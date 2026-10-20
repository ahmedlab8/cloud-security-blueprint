import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import ir_toolkit as ir

HERE = Path(__file__).resolve().parents[1]


class FakeRunner:
    """Records kubectl invocations and returns canned output."""

    def __init__(self, outputs=None):
        self.calls = []
        self.outputs = outputs or {}

    def __call__(self, cmd, **kwargs):
        self.calls.append((cmd, kwargs.get("input")))
        key = " ".join(cmd[1:3])
        return SimpleNamespace(returncode=0, stdout=self.outputs.get(key, ""), stderr="")


def make_incident():
    return ir.Incident(incident_id="IR-TEST-1", namespace="secure-app", pod="secure-app-abc", reason="unit test")


def test_validate_name_rejects_injection():
    with pytest.raises(ir.IRError):
        ir.validate_name("pod; rm -rf /", "pod name")
    assert ir.validate_name("secure-app-7d9c", "pod") == "secure-app-7d9c"


def test_isolate_applies_policy_and_labels():
    runner = FakeRunner()
    k = ir.Kubectl(runner=runner)
    inc = make_incident()
    ir.isolate(k, inc)
    cmds = [" ".join(c) for c, _ in runner.calls]
    assert cmds[0] == "kubectl apply -f -"
    policy = json.loads(runner.calls[0][1])
    assert policy["spec"]["policyTypes"] == ["Ingress", "Egress"]
    assert policy["spec"]["podSelector"]["matchLabels"] == {ir.QUARANTINE_LABEL: "true"}
    assert any(f"{ir.QUARANTINE_LABEL}=true" in c for c in cmds)
    assert any("app.kubernetes.io/name-" in c for c in cmds)
    assert [t["action"] for t in inc.timeline] == ["network-isolated", "pod-labelled", "pod-detached"]


def test_dry_run_does_not_execute_mutations(capsys):
    runner = FakeRunner()
    k = ir.Kubectl(dry_run=True, runner=runner)
    ir.isolate(k, make_incident())
    assert all(c[1] not in ("apply", "label", "annotate", "cordon") for c, _ in runner.calls)
    assert "[dry-run] kubectl apply -f -" in capsys.readouterr().out


def test_collect_writes_manifest_and_bundle(tmp_path):
    pod = {"spec": {"nodeName": "node-1"}, "status": {"containerStatuses": [{"name": "app", "image": "img:1", "imageID": "sha256:abc"}]}}
    runner = FakeRunner({"get pod": json.dumps(pod)})
    k = ir.Kubectl(runner=runner)
    inc = make_incident()
    d = ir.evidence_dir(tmp_path, inc)
    ir.capture_logs(k, inc, d)
    bundle = ir.collect_artifacts(k, inc, d)
    manifest = json.loads((d / "MANIFEST.json").read_text())
    assert "pod.json" in manifest["sha256"] and "logs-current.txt" in manifest["sha256"]
    assert "images.json" in manifest["sha256"] and "node.json" in manifest["sha256"]
    assert bundle.exists() and oct(bundle.stat().st_mode)[-3:] == "600"


def test_webhook_validation():
    assert ir.validate_webhook("https://hooks.slack.com/services/T000/B000/XXXX")
    assert ir.validate_webhook("https://contoso.webhook.office.com/webhookb2/abc")
    for bad in ("http://hooks.slack.com/x", "https://evil.example.com/hook", "https://hooks.slack.com.evil.io/x"):
        with pytest.raises(ir.IRError):
            ir.validate_webhook(bad)


def test_notify_uses_env_and_both_channels(monkeypatch):
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/T000/B000/XXXX")
    monkeypatch.setenv("TEAMS_WEBHOOK_URL", "https://contoso.webhook.office.com/webhookb2/abc")
    posted = []
    sent = ir.notify(make_incident(), poster=lambda url, payload: posted.append((url, payload)) or 200)
    assert sent == ["slack", "teams"]
    assert posted[0][1]["blocks"][0]["type"] == "section"
    assert posted[1][1]["attachments"][0]["content"]["type"] == "AdaptiveCard"


def test_notify_skips_without_env(monkeypatch):
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("TEAMS_WEBHOOK_URL", raising=False)
    assert ir.notify(make_incident(), poster=lambda *_: pytest.fail("should not post")) == []


def test_report_contains_key_sections():
    inc = make_incident()
    inc.log("network-isolated", "x")
    inc.artifacts["pod.json"] = "deadbeef"
    md = ir.render_report(inc)
    for s in ("# Incident Report - IR-TEST-1", "## 2. Timeline", "`pod.json`", "deadbeef", "Containment checklist"):
        assert s in md


def test_falco_event_populates_incident():
    args = ir.build_parser().parse_args(["respond", "--falco-event", str(HERE / "templates" / "falco-event.example.json"), "--dry-run"])
    inc = ir.incident_from_args(args)
    assert inc.namespace == "secure-app"
    assert inc.pod == "secure-app-6f7d9c5b8-x2k4q"
    assert inc.source == "falco" and inc.rule == "CSB Shell Spawned in Container"


def test_cli_respond_dry_run_end_to_end(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", "/nonexistent")  # no kubectl -> pure dry-run
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("TEAMS_WEBHOOK_URL", raising=False)
    rc = ir.main(
        [
            "respond",
            "-n",
            "secure-app",
            "-p",
            "secure-app-abc",
            "--reason",
            "test",
            "--incident-id",
            "IR-CLI-1",
            "--evidence-dir",
            str(tmp_path),
            "--dry-run",
        ]
    )
    assert rc == 0
    assert (tmp_path / "IR-CLI-1" / "incident-report.md").exists()


@pytest.mark.parametrize("script", ["isolate-pod.sh", "capture-logs.sh", "collect-artifacts.sh"])
def test_bash_scripts_dry_run(script, tmp_path):
    res = subprocess.run(
        ["bash", str(HERE / script), "-n", "secure-app", "-p", "secure-app-abc", "--dry-run"],
        check=False,
        capture_output=True,
        text=True,
        cwd=tmp_path,
        env={**os.environ, "PATH": os.environ["PATH"]},
    )
    assert res.returncode == 0, res.stderr
    assert "[dry-run]" in res.stdout


def test_bash_isolate_rejects_bad_names(tmp_path):
    res = subprocess.run(
        ["bash", str(HERE / "isolate-pod.sh"), "-n", "Bad;NS", "-p", "x", "--dry-run"],
        check=False,
        capture_output=True,
        text=True,
        cwd=tmp_path,
    )
    assert res.returncode == 2
