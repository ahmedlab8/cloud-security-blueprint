# Falco runtime threat detection

| Rule | Detects | Priority | MITRE |
|---|---|---|---|
| CSB Shell Spawned in Container | Any shell in a container (images are distroless, so none is expected) | WARNING | T1059 |
| CSB Privilege Escalation Binary Executed | `sudo`, `su`, `pkexec`, `doas` in a container | CRITICAL | T1548 |
| CSB Setuid or Setgid Bit Set | `chmod u+s`/`g+s` inside a container | CRITICAL | T1548.001 |
| CSB Non-root Process Became Root | `setuid(0)` from a non-root process | CRITICAL | T1068 |
| CSB Container Escape Tooling Executed | `nsenter`, `unshare`, `chroot`, `capsh` | CRITICAL | T1611 |
| CSB Crypto Miner Process | Known miner binaries and `stratum+tcp://` command lines | CRITICAL | T1496 |
| CSB Outbound Connection to Mining Pool Port | Connections to common pool ports | WARNING | T1496 |
| CSB Sensitive File Read in Container | `/etc/shadow`, SSH/cloud creds, Kubernetes PKI | ERROR | T1552 |
| CSB Service Account Token Read by Unexpected Process | SA token read in `secure-app` (token isn't mounted there) | WARNING | T1528 |

## Deploy

```bash
kubectl apply -f kubernetes/pod-security/namespaces-pss.yaml   # creates the falco namespace (privileged PSS)
kubectl -n falco create secret generic falcosidekick-webhooks \
  --from-literal=SLACK_WEBHOOKURL="$SLACK_WEBHOOK_URL" \
  --from-literal=TEAMS_WEBHOOKURL="$TEAMS_WEBHOOK_URL"
helm repo add falcosecurity https://falcosecurity.github.io/charts && helm repo update
helm upgrade --install falco falcosecurity/falco -n falco \
  -f security-tools/falco/values.yaml \
  --set-file 'customRules.csb-rules\.yaml=security-tools/falco/custom-rules.yaml'
```

## Validate rules locally

```bash
docker run --rm -v "$PWD/security-tools/falco:/rules:ro" falcosecurity/falco:<version> \
  falco -c /etc/falco/falco.yaml -V /rules/custom-rules.yaml
```

## Test a detection (in a non-production cluster)

```bash
kubectl run shell-test --rm -it --image=busybox:1.36 --restart=Never -- sh -c 'cat /etc/shadow'
# Expect: "Shell Spawned in Container" + "Sensitive File Read in Container" in Falco logs / Slack
```

Falco alerts go to Falcosidekick, which forwards them to Slack/Teams and exposes Prometheus
metrics (`falcosecurity_falcosidekick_falco_events_total`). Those metrics feed the
*Security Alerts* Grafana dashboard and the `FalcoCriticalEvent` alert. The playbook in
`incident-response/` takes over from there.
