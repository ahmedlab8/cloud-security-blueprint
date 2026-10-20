# Security design decisions

Short architecture decision records (ADRs): what was decided, why, and the trade-off.

### SDD-01: Private control planes by default
**Decision:** EKS `endpoint_public_access=false`. AKS `private_cluster_enabled=true` with no public FQDN.
**Why:** The Kubernetes API is the highest-value target in the cluster, and taking it off the
internet removes most of the attack surface.
**Trade-off:** Operators need SSM, VPN, or in-VNet runners. `eks_admin_cidrs` is an explicit,
allowlisted escape hatch.

### SDD-02: Workload identity instead of static credentials
**Decision:** IRSA on EKS and Entra workload identity on AKS. Service accounts do not auto-mount
tokens, and the app's IAM policy is limited to one S3 prefix plus KMS via S3.
**Why:** No secrets to leak or rotate, and every credential is short-lived and auditable.
**Trade-off:** Some setup complexity (OIDC provider, federated credentials).

### SDD-03: One customer-managed key per data domain
**Decision:** Separate KMS keys for EKS secrets, S3, logs, and EBS, rotated every 90 days.
Azure uses an HSM-backed key with a rotation policy for disk encryption.
**Why:** Smaller blast radius, per-domain key policies, and crypto-shredding is possible.
**Trade-off:** KMS cost (about $1 per key per month) and more key policies to maintain.

### SDD-04: Defence in depth at admission
**Decision:** Pod Security Admission (`restricted`) plus Gatekeeper, with the same Rego enforced
in CI through conftest.
**Why:** PSA is built in and can't be bypassed. Gatekeeper covers what PSA can't (tags,
limits, LB exposure). Running the policies in CI gives feedback in the PR instead of at deploy time.
**Trade-off:** Two policy systems. Gatekeeper exemptions are limited to system namespaces.
**Rollout:** New constraints start with `enforcementAction: dryrun`, then `warn`, then `deny`.

### SDD-05: Rego is the source of truth, templates are generated
**Decision:** Rego lives in `.rego` files with unit tests, and `generate.py` embeds it into ConstraintTemplates. CI fails if they drift.
**Why:** What gets tested is exactly what gets deployed.

### SDD-06: Distroless, non-root, read-only containers
**Decision:** Multi-stage build on `gcr.io/distroless/python3-debian13:nonroot`, UID 65532,
read-only root filesystem, all capabilities dropped, seccomp `RuntimeDefault`.
**Why:** With no shell or package manager, most post-exploitation tooling can't run, and a
shell appearing at all is a high-confidence Falco signal. The Trivy evidence shows 0 CRITICAL,
compared with 21 on a full base image.
**Trade-off:** You can't `kubectl exec` in to debug. Use `kubectl debug` with an ephemeral container instead (still policy-checked).

### SDD-07: Zero-trust pod networking
**Decision:** Default deny on ingress and egress, with explicit allows for DNS, the ingress
controller, Prometheus, and HTTPS egress. The IMDS addresses are blocked.
**Why:** Limits lateral movement and stops pods from stealing node credentials.
**Trade-off:** Every new dependency needs a policy, which also gives you an inventory of flows.

### SDD-08: Secrets as mounted files from a cloud KMS-backed store
**Decision:** Secrets Store CSI driver mounting from Secrets Manager or Key Vault, read-only.
The app reads `*_FILE`.
**Why:** Secrets stay out of Git, image layers, and environment variables (which leak through
`/proc` and crash dumps), and rotation needs no redeploy.

### SDD-09: Pipeline gates and thresholds
| Gate | Fails on | Rationale |
|---|---|---|
| terraform fmt/validate | any error | Basic correctness |
| tfsec | HIGH or CRITICAL | Repo is clean at HIGH, so it is held there |
| Checkov | any failed check | Accepted risks must be skipped inline, with a reason |
| Trivy image | fixable CRITICAL | Unfixable OS CVEs are tracked, not blocked. The weekly schedule catches new fixes |
| Trivy fs / config | HIGH or CRITICAL | Dependencies and misconfigurations are fully under our control |
| gitleaks | any finding, full history | A leaked secret is an incident even after it's deleted |
| Semgrep | ERROR | WARNINGs are triaged in review |
| ZAP baseline | rules marked FAIL in `rules.tsv` | Passive scan with an explicit, versioned risk acceptance |
**Supply chain:** Third-party actions are pinned to full commit SHAs. `GITHUB_TOKEN` is read-only,
checkout uses `persist-credentials: false`, and tool versions are pinned.
**Note:** CodeQL / GitHub code scanning (SARIF upload) needs GitHub Advanced Security on private
repos, so reports go out as artifacts instead. Making the repo public enables SARIF upload.

### SDD-10: Detection mapped to MITRE ATT&CK
**Decision:** Self-contained Falco rules tagged with technique IDs. Falcosidekick feeds them to
Slack/Teams and Prometheus.
**Why:** Detections can be tested and versioned, and alerts link straight to the IR playbook.

### SDD-11: Evidence-preserving containment
**Decision:** Isolate the pod with a NetworkPolicy and detach it from its controller instead of deleting it.
**Why:** It keeps memory, filesystem, and process state available for forensics while a clean
replica restores service. Every artifact is SHA-256 hashed for chain of custody.

### SDD-12: Accepted risks
These are documented in `docs/remediation-guide.md` under "Accepted findings". Each has an
inline justification in the code and is reviewed every quarter.
