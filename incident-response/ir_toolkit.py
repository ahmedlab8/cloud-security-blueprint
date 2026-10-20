#!/usr/bin/env python3
"""Kubernetes incident-response toolkit (NIST SP 800-61 containment / evidence / reporting).

Subcommands
  isolate   Quarantine a pod: deny-all NetworkPolicy + labels, detach from its controller/Service
  logs      Capture current + previous container logs, describe output and events
  collect   Collect forensic artifacts (pod/node specs, images, events) with SHA-256 manifest
  notify    Send a Slack and/or Microsoft Teams notification (webhooks from env vars only)
  report    Render a markdown incident report from the evidence directory
  respond   Full playbook: isolate -> logs -> collect -> report -> notify

Every command supports --dry-run, which prints the kubectl calls / payloads and changes nothing.
Webhook URLs come only from SLACK_WEBHOOK_URL / TEAMS_WEBHOOK_URL and are never logged.

Examples
  ./ir_toolkit.py respond -n secure-app -p secure-app-7d9c-abcde --reason "Falco: shell in container"
  ./ir_toolkit.py respond --falco-event event.json --dry-run
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

LOG = logging.getLogger("ir")

QUARANTINE_LABEL = "security.csb.io/quarantine"
INCIDENT_ANNOTATION = "security.csb.io/incident-id"
DNS_1123 = re.compile(r"^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$")
ALLOWED_WEBHOOK_HOSTS = (
    "hooks.slack.com",
    ".webhook.office.com",
    ".logic.azure.com",
    ".environment.api.powerplatform.com",
)


class IRError(RuntimeError):
    """Raised for invalid input or failed response actions."""


# --------------------------------------------------------------------------- #
# Plumbing
# --------------------------------------------------------------------------- #
def utcnow() -> str:
    return dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def validate_name(value: str, what: str) -> str:
    if not value or not DNS_1123.match(value):
        raise IRError(f"invalid {what}: {value!r}")
    return value


@dataclass
class Incident:
    incident_id: str
    namespace: str
    pod: str
    reason: str
    severity: str = "high"
    rule: str = ""
    source: str = "manual"
    started_at: str = field(default_factory=utcnow)
    timeline: list[dict[str, str]] = field(default_factory=list)
    artifacts: dict[str, str] = field(default_factory=dict)

    def log(self, action: str, detail: str = "") -> None:
        self.timeline.append({"time": utcnow(), "action": action, "detail": detail})
        LOG.info("%s %s", action, detail)


class Kubectl:
    """Thin kubectl wrapper. In dry-run mode commands are recorded, not executed."""

    def __init__(self, dry_run: bool = False, binary: str = "kubectl", runner: Callable[..., Any] | None = None) -> None:
        self.dry_run = dry_run
        self.binary = binary
        self.calls: list[list[str]] = []
        self._runner = runner or subprocess.run

    def __call__(self, *args: str, stdin: str | None = None, check: bool = True, mutating: bool = False) -> str:
        cmd = [self.binary, *args]
        self.calls.append(cmd)
        if self.dry_run and mutating:
            print("[dry-run] " + " ".join(cmd))
            return ""
        if self.dry_run and shutil.which(self.binary) is None:
            print("[dry-run] " + " ".join(cmd))
            return ""
        res = self._runner(cmd, input=stdin, capture_output=True, text=True, timeout=120, check=False)
        if check and res.returncode != 0:
            raise IRError(f"{' '.join(cmd)} failed: {res.stderr.strip()}")
        return res.stdout


def new_incident_id(pod: str) -> str:
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%d-%H%M%S")
    return f"IR-{stamp}-{hashlib.sha256(pod.encode()).hexdigest()[:6]}"


def evidence_dir(base: Path, inc: Incident) -> Path:
    d = base / inc.incident_id
    d.mkdir(parents=True, exist_ok=True)
    # Owner-only (rwx------): evidence may contain sensitive data. Exec bit is required to traverse a directory.
    os.chmod(d, 0o700)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
    return d


def write_artifact(inc: Incident, d: Path, name: str, content: str) -> None:
    path = d / name
    path.write_text(content, encoding="utf-8")
    os.chmod(path, 0o600)
    inc.artifacts[name] = hashlib.sha256(content.encode()).hexdigest()


# --------------------------------------------------------------------------- #
# Containment
# --------------------------------------------------------------------------- #
def quarantine_policy(namespace: str) -> dict[str, Any]:
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": "quarantine-deny-all", "namespace": namespace, "labels": {"app.kubernetes.io/managed-by": "ir-toolkit"}},
        "spec": {"podSelector": {"matchLabels": {QUARANTINE_LABEL: "true"}}, "policyTypes": ["Ingress", "Egress"]},
    }


def isolate(k: Kubectl, inc: Incident, detach: bool = True, cordon_node: bool = False) -> None:
    ns, pod = inc.namespace, inc.pod
    k("apply", "-f", "-", stdin=json.dumps(quarantine_policy(ns)), mutating=True)
    inc.log("network-isolated", f"deny-all NetworkPolicy quarantine-deny-all applied in {ns}")

    k("label", "pod", pod, "-n", ns, f"{QUARANTINE_LABEL}=true", "--overwrite", mutating=True)
    k("annotate", "pod", pod, "-n", ns, f"{INCIDENT_ANNOTATION}={inc.incident_id}", "--overwrite", mutating=True)
    inc.log("pod-labelled", f"{QUARANTINE_LABEL}=true, {INCIDENT_ANNOTATION}={inc.incident_id}")

    if detach:
        # Removing the selector label orphans the pod from its ReplicaSet (a clean replacement is
        # scheduled) and from Service endpoints, while the compromised pod is preserved for forensics.
        k("label", "pod", pod, "-n", ns, "app.kubernetes.io/name-", mutating=True)
        inc.log("pod-detached", "removed app.kubernetes.io/name so the controller and Service release it")

    if cordon_node:
        node = k("get", "pod", pod, "-n", ns, "-o", "jsonpath={.spec.nodeName}").strip()
        if node:
            k("cordon", node, mutating=True)
            inc.log("node-cordoned", node)


# --------------------------------------------------------------------------- #
# Evidence
# --------------------------------------------------------------------------- #
def capture_logs(k: Kubectl, inc: Incident, d: Path) -> None:
    ns, pod = inc.namespace, inc.pod
    write_artifact(inc, d, "logs-current.txt", k("logs", pod, "-n", ns, "--all-containers", "--timestamps", "--prefix", check=False))
    write_artifact(
        inc, d, "logs-previous.txt", k("logs", pod, "-n", ns, "--all-containers", "--timestamps", "--prefix", "--previous", check=False)
    )
    write_artifact(inc, d, "describe-pod.txt", k("describe", "pod", pod, "-n", ns, check=False))
    write_artifact(
        inc, d, "events.txt", k("get", "events", "-n", ns, "--field-selector", f"involvedObject.name={pod}", "-o", "wide", check=False)
    )
    inc.log("logs-captured", f"{len(inc.artifacts)} files in {d}")


def collect_artifacts(k: Kubectl, inc: Incident, d: Path) -> Path:
    ns, pod = inc.namespace, inc.pod
    pod_json = k("get", "pod", pod, "-n", ns, "-o", "json", check=False)
    write_artifact(inc, d, "pod.json", pod_json)
    node = ""
    try:
        spec = json.loads(pod_json) if pod_json else {}
        node = spec.get("spec", {}).get("nodeName", "")
        images = [
            {"container": s.get("name"), "image": s.get("image"), "imageID": s.get("imageID")}
            for s in spec.get("status", {}).get("containerStatuses", [])
        ]
        write_artifact(inc, d, "images.json", json.dumps(images, indent=2))
    except json.JSONDecodeError:
        LOG.warning("pod JSON could not be parsed; continuing")
    if node:
        write_artifact(inc, d, "node.json", k("get", "node", node, "-o", "json", check=False))
    write_artifact(inc, d, "networkpolicies.yaml", k("get", "networkpolicy", "-n", ns, "-o", "yaml", check=False))
    write_artifact(inc, d, "rolebindings.yaml", k("get", "rolebinding", "-n", ns, "-o", "yaml", check=False))
    write_artifact(inc, d, "namespace-pods.txt", k("get", "pods", "-n", ns, "-o", "wide", "--show-labels", check=False))

    manifest = {"incident_id": inc.incident_id, "collected_at": utcnow(), "sha256": dict(sorted(inc.artifacts.items()))}
    (d / "MANIFEST.json").write_text(json.dumps(manifest, indent=2))
    bundle = d.parent / f"{inc.incident_id}-evidence.tar.gz"
    with tarfile.open(bundle, "w:gz") as tar:
        tar.add(d, arcname=inc.incident_id)
    os.chmod(bundle, 0o600)
    inc.log("artifacts-collected", f"bundle {bundle.name} sha256={sha256_file(bundle)}")
    return bundle


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# --------------------------------------------------------------------------- #
# Notification
# --------------------------------------------------------------------------- #
def validate_webhook(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https":
        raise IRError("webhook URL must use https")
    if not any(host == h or (h.startswith(".") and host.endswith(h)) for h in ALLOWED_WEBHOOK_HOSTS):
        raise IRError(f"webhook host {host!r} is not in the allowlist")
    return url


def slack_payload(inc: Incident) -> dict[str, Any]:
    text = f":rotating_light: *{inc.severity.upper()}* incident `{inc.incident_id}`"
    fields = [
        f"*Namespace:* {inc.namespace}",
        f"*Pod:* {inc.pod}",
        f"*Reason:* {inc.reason}",
        f"*Detected by:* {inc.source}{' / ' + inc.rule if inc.rule else ''}",
        f"*Actions:* {', '.join(t['action'] for t in inc.timeline) or 'none yet'}",
    ]
    return {
        "text": f"{inc.severity.upper()} incident {inc.incident_id}: {inc.reason}",
        "blocks": [
            {"type": "section", "text": {"type": "mrkdwn", "text": text}},
            {"type": "section", "fields": [{"type": "mrkdwn", "text": f} for f in fields]},
        ],
    }


def teams_payload(inc: Incident) -> dict[str, Any]:
    facts = [
        {"title": "Namespace", "value": inc.namespace},
        {"title": "Pod", "value": inc.pod},
        {"title": "Reason", "value": inc.reason},
        {"title": "Detected by", "value": f"{inc.source} {inc.rule}".strip()},
        {"title": "Actions", "value": ", ".join(t["action"] for t in inc.timeline) or "none yet"},
    ]
    card = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "body": [
            {
                "type": "TextBlock",
                "size": "Large",
                "weight": "Bolder",
                "color": "Attention",
                "text": f"{inc.severity.upper()} incident {inc.incident_id}",
            },
            {"type": "FactSet", "facts": facts},
        ],
    }
    return {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}]}


def post_json(url: str, payload: dict[str, Any]) -> int:
    # validate_webhook() enforces https and an allowlisted host, so file:// and SSRF are not possible.
    req = urllib.request.Request(  # noqa: S310
        validate_webhook(url), data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310  # nosec B310  # nosemgrep
        return resp.status


def notify(inc: Incident, dry_run: bool = False, poster: Callable[[str, dict[str, Any]], int] = post_json) -> list[str]:
    sent = []
    for env, builder, name in (("SLACK_WEBHOOK_URL", slack_payload, "slack"), ("TEAMS_WEBHOOK_URL", teams_payload, "teams")):
        url = os.environ.get(env, "")
        if not url:
            continue
        payload = builder(inc)
        if dry_run:
            validate_webhook(url)
            print(f"[dry-run] would POST to {name} ({env}):\n{json.dumps(payload, indent=2)}")
        else:
            poster(url, payload)
        sent.append(name)
    if not sent:
        LOG.warning("no SLACK_WEBHOOK_URL / TEAMS_WEBHOOK_URL set - notification skipped")
    else:
        inc.log("notified", ", ".join(sent))
    return sent


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
def render_report(inc: Incident) -> str:
    rows = "\n".join(f"| {t['time']} | {t['action']} | {t['detail']} |" for t in inc.timeline) or "| - | - | - |"
    arts = "\n".join(f"| `{n}` | `{h}` |" for n, h in sorted(inc.artifacts.items())) or "| - | - |"
    return f"""# Incident Report - {inc.incident_id}

| Field | Value |
|---|---|
| Severity | **{inc.severity.upper()}** |
| Status | Contained - under investigation |
| Detected | {inc.started_at} |
| Detection source | {inc.source}{" - " + inc.rule if inc.rule else ""} |
| Affected workload | `{inc.namespace}/{inc.pod}` |
| Reason | {inc.reason} |

## 1. Summary
Automated containment was performed on `{inc.namespace}/{inc.pod}` following: *{inc.reason}*.
The pod was network-isolated with a deny-all NetworkPolicy and preserved for forensic analysis.

## 2. Timeline (UTC)
| Time | Action | Detail |
|---|---|---|
{rows}

## 3. Evidence (chain of custody)
| Artifact | SHA-256 |
|---|---|
{arts}

## 4. Containment checklist
- [x] Pod network-isolated (`quarantine-deny-all`)
- [x] Pod labelled `{QUARANTINE_LABEL}=true` and annotated with the incident ID
- [ ] Rotate credentials reachable from the pod (IRSA / workload identity, Key Vault / Secrets Manager secrets)
- [ ] Review cloud audit logs (CloudTrail / Entra sign-in + Activity Log) for the workload identity
- [ ] Check other pods using the same image digest

## 5. Eradication and recovery
- [ ] Identify root cause (vulnerable dependency, leaked credential, misconfiguration)
- [ ] Patch, rebuild, re-scan (Trivy) and redeploy via the pipeline
- [ ] Delete the quarantined pod after evidence sign-off

## 6. Lessons learned
- [ ] Detection gap analysis (Falco rules, alerts)
- [ ] Policy improvements (Gatekeeper constraints, NetworkPolicies)
- [ ] Post-incident review scheduled within 5 business days

_Generated by `incident-response/ir_toolkit.py` at {utcnow()}._
"""


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def incident_from_args(args: argparse.Namespace) -> Incident:
    ns, pod, reason, rule, source, severity = args.namespace, args.pod, args.reason, "", "manual", args.severity
    if getattr(args, "falco_event", None):
        ev = json.loads(Path(args.falco_event).read_text())
        f = ev.get("output_fields", {})
        ns = ns or f.get("k8s.ns.name", "")
        pod = pod or f.get("k8s.pod.name", "")
        rule = ev.get("rule", "")
        reason = reason or ev.get("output", rule)
        source = "falco"
        severity = {"Emergency": "critical", "Alert": "critical", "Critical": "critical", "Error": "high"}.get(
            ev.get("priority", ""), severity
        )
    validate_name(ns, "namespace")
    validate_name(pod, "pod name")
    inc = Incident(
        incident_id=args.incident_id or new_incident_id(pod),
        namespace=ns,
        pod=pod,
        reason=reason or "unspecified",
        severity=severity,
        rule=rule,
        source=source,
    )
    return inc


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-n", "--namespace", default="")
    common.add_argument("-p", "--pod", default="")
    common.add_argument("--reason", default="")
    common.add_argument("--severity", default="high", choices=["low", "medium", "high", "critical"])
    common.add_argument("--incident-id", default="")
    common.add_argument("--falco-event", help="Falco JSON event file to populate namespace/pod/rule")
    common.add_argument("--evidence-dir", default=os.environ.get("IR_EVIDENCE_DIR", "./evidence"))
    common.add_argument("--dry-run", action="store_true", help="print actions without changing anything")

    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="command", required=True)
    iso = sub.add_parser("isolate", parents=[common])
    iso.add_argument("--no-detach", action="store_true")
    iso.add_argument("--cordon-node", action="store_true")
    for name in ("logs", "collect", "notify", "report"):
        sub.add_parser(name, parents=[common])
    r = sub.add_parser("respond", parents=[common])
    r.add_argument("--no-detach", action="store_true")
    r.add_argument("--cordon-node", action="store_true")
    r.add_argument("--no-notify", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    args = build_parser().parse_args(argv)
    try:
        inc = incident_from_args(args)
        k = Kubectl(dry_run=args.dry_run)
        d = evidence_dir(Path(args.evidence_dir), inc)
        if args.command in ("isolate", "respond"):
            isolate(k, inc, detach=not args.no_detach, cordon_node=args.cordon_node)
        if args.command in ("logs", "respond"):
            capture_logs(k, inc, d)
        if args.command in ("collect", "respond"):
            collect_artifacts(k, inc, d)
        if args.command == "notify" or (args.command == "respond" and not args.no_notify):
            notify(inc, dry_run=args.dry_run)
        if args.command in ("report", "respond"):
            report = render_report(inc)
            (d / "incident-report.md").write_text(report)
            (d / "incident.json").write_text(json.dumps(asdict(inc), indent=2))
            print(f"report: {d / 'incident-report.md'}")
    except IRError as exc:
        LOG.error("%s", exc)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
