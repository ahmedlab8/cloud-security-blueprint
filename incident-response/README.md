# Incident response automation

Python toolkit and Bash scripts for containment, evidence collection, notification, and
reporting, following the NIST SP 800-61 phases.

| Tool | What it does |
|---|---|
| `ir_toolkit.py isolate` | Applies `quarantine-deny-all`, labels the pod `security.csb.io/quarantine=true`, adds the incident-ID annotation, and removes the selector label so the ReplicaSet replaces the pod and the Service drops it. The compromised pod is **kept** for forensics. `--cordon-node` is optional. |
| `ir_toolkit.py logs` | Current and previous logs for all containers, `describe` output, events |
| `ir_toolkit.py collect` | Pod/node specs, image digests, NetworkPolicies, RoleBindings, a SHA-256 `MANIFEST.json`, and a `.tar.gz` bundle (0600) |
| `ir_toolkit.py notify` | Slack (Block Kit) and/or Teams (Adaptive Card). URLs come **only** from `SLACK_WEBHOOK_URL` / `TEAMS_WEBHOOK_URL`, must be https, and must match a host allowlist |
| `ir_toolkit.py report` | Markdown incident report: timeline, evidence hashes, containment / eradication / lessons-learned checklists |
| `ir_toolkit.py respond` | Runs the whole playbook: isolate, logs, collect, report, notify |
| `isolate-pod.sh`, `capture-logs.sh`, `collect-artifacts.sh`, `notify.sh` | Bash equivalents for jump hosts where Python isn't available |

Every command takes `--dry-run`, which prints the mutating kubectl calls and webhook payloads
and changes nothing. Pod and namespace names are validated as DNS-1123 to block injection.

## Usage

```bash
export SLACK_WEBHOOK_URL=...   # from your secret manager, never hard-coded
./incident-response/ir_toolkit.py respond -n secure-app -p secure-app-6f7d9c5b8-x2k4q \
  --reason "Falco: shell spawned in container" --severity critical

# Driven directly by a Falco JSON event (namespace, pod, and rule are filled in automatically):
./incident-response/ir_toolkit.py respond --falco-event incident-response/templates/falco-event.example.json --dry-run
```

Output goes to `./evidence/<incident-id>/` (gitignored), and the `.tar.gz` bundle sits next to it.

## RBAC

Run the toolkit as a member of `security-incident-responders`, which is bound to the
`incident-responder` Role in `kubernetes/secure-cluster/rbac.yaml` (patch pods, create
NetworkPolicies, read logs and events). Node cordoning needs a separate ClusterRole and is opt-in.

## Tests

```bash
pytest -q incident-response/tests     # 14 tests: kubectl calls mocked, dry-run end-to-end, bash scripts
shellcheck incident-response/*.sh
```
