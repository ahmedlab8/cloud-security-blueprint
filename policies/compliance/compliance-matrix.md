# Compliance control matrix

_Generated from `control-mapping.csv` by `build_matrix.py`. Edit the CSV, not this file._

This maps every security control in the repo to **NIST SP 800-53 Rev. 5**, **CIS Benchmarks**
(AWS Foundations v3.0, Azure Foundations v2.x, Kubernetes v1.9, EKS/AKS, Docker, CIS Controls v8),
**SOC 2 Trust Services Criteria (2017, rev. 2022)** and **ISO/IEC 27001:2022 Annex A**.

> Mappings are engineering guidance meant to support an audit, not an attestation. CIS
> recommendation numbers change between benchmark versions, so check them against the
> version your auditor uses.

| ID | Control / implementation | Evidence | NIST 800-53 | CIS | SOC 2 | ISO 27001 |
|---|---|---|---|---|---|---|
| CSB-01 | **Least-privilege workload identity (no static cloud keys)**<br>EKS IRSA role scoped to one S3 prefix + KMS via S3; AKS Entra workload identity with Key Vault Secrets User on one vault | `terraform/aws/iam.tf`<br>`terraform/azure/identity.tf` | AC-2, AC-6, IA-5 | CIS K8s 5.1.6; CIS AWS 1.16 | CC6.1, CC6.3 | 5.15, 5.18, 8.2 |
| CSB-02 | **Cluster access via IdP + RBAC only**<br>EKS access entries (API auth mode, no aws-auth); AKS local accounts disabled + Azure RBAC | `terraform/aws/eks.tf`<br>`terraform/azure/aks.tf` | AC-2, AC-3, IA-2 | CIS EKS 3.1; CIS AKS 5.1 | CC6.1, CC6.2 | 5.16, 8.5 |
| CSB-03 | **Namespace-scoped Kubernetes RBAC bound to groups**<br>Viewer / deployer / incident-responder Roles; no wildcards, no secrets or exec | `kubernetes/secure-cluster/rbac.yaml` | AC-3, AC-6 | CIS K8s 5.1.1; 5.1.3 | CC6.3 | 5.15, 8.2 |
| CSB-04 | **Encryption at rest with customer-managed keys**<br>KMS keys with 90-day rotation for EKS secrets, S3, logs, EBS; Key Vault HSM key + disk encryption set for AKS | `terraform/aws/kms.tf`<br>`terraform/azure/keyvault.tf` | SC-12, SC-13, SC-28 | CIS AWS 3.6; CIS Azure 8.x | CC6.1, C1.1 | 8.24 |
| CSB-05 | **Encryption in transit enforced**<br>S3 bucket policy denies non-TLS and TLS < 1.2; HSTS on app | `terraform/aws/modules/secure-s3-bucket/main.tf`<br>`app/src/app.py` | SC-8, SC-13 | CIS AWS 2.1.1 | CC6.7 | 8.24 |
| CSB-06 | **No public storage**<br>S3 Block Public Access (all four), BucketOwnerEnforced; Key Vault public network access disabled + private endpoint | `terraform/aws/modules/secure-s3-bucket/main.tf`<br>`terraform/azure/keyvault.tf` | AC-3, SC-7 | CIS AWS 2.1.4; CIS Azure 8.7 | CC6.1, CC6.6 | 8.3, 8.12 |
| CSB-07 | **Versioning and recoverability**<br>S3 versioning + lifecycle; Key Vault soft delete 90d + purge protection | `terraform/aws/modules/secure-s3-bucket/main.tf`<br>`terraform/azure/keyvault.tf` | CP-9, SI-12 | CIS Azure 8.5 | A1.2, CC6.1 | 8.13 |
| CSB-08 | **Secrets never in Git or env vars**<br>Secrets Store CSI driver (AWS Secrets Manager / Azure Key Vault) mounted read-only as files; gitleaks on full history in CI | `kubernetes/secure-cluster/secretproviderclass-*.yaml`<br>`.github/workflows/devsecops.yml` | IA-5, SC-28 | CIS K8s 5.4.1; 5.4.2 | CC6.1 | 5.17, 8.4 |
| CSB-09 | **Private control planes**<br>EKS private endpoint by default; AKS private cluster without public FQDN | `terraform/aws/eks.tf`<br>`terraform/azure/aks.tf` | SC-7, AC-17 | CIS EKS 5.4.2; CIS AKS 5.4 | CC6.6 | 8.20, 8.22 |
| CSB-10 | **Segmented networks with default-deny**<br>Private subnets for nodes, locked default SG, NSGs deny-all inbound, no default outbound access | `terraform/aws/vpc.tf`<br>`terraform/azure/network.tf` | SC-7, AC-4 | CIS AWS 5.4; CIS Azure 6.x | CC6.6 | 8.20, 8.22 |
| CSB-11 | **Zero-trust pod networking**<br>Default deny ingress+egress, explicit DNS / ingress / Prometheus / HTTPS allows, IMDS blocked | `kubernetes/network-policies/` | SC-7, AC-4 | CIS K8s 5.3.2 | CC6.6 | 8.20, 8.22 |
| CSB-12 | **No internet-facing load balancers**<br>Gatekeeper K8sBlockPublicLoadBalancer + ResourceQuota services.loadbalancers=0 | `policies/opa/gatekeeper/`<br>`kubernetes/secure-cluster/quotas.yaml` | SC-7, CM-7 | CIS K8s 5.3 | CC6.6 | 8.20 |
| CSB-13 | **Pod Security Standards restricted**<br>PSA enforce=restricted on app namespaces; non-root UID 65532, drop ALL caps, seccomp RuntimeDefault, no privilege escalation | `kubernetes/secure-cluster/namespace.yaml`<br>`kubernetes/pod-security/` | CM-6, AC-6, SC-39 | CIS K8s 5.2.2-5.2.9; 5.7.2 | CC6.8, CC7.1 | 8.9 |
| CSB-14 | **Read-only root filesystem and resource limits**<br>readOnlyRootFilesystem + CPU/memory/ephemeral limits; LimitRange + ResourceQuota | `kubernetes/secure-cluster/deployment.yaml`<br>`quotas.yaml` | CM-6, SC-5 | CIS K8s 5.7.3 | CC7.1 | 8.6, 8.9 |
| CSB-15 | **Admission control (policy-as-code)**<br>Gatekeeper blocks root, privileged, :latest, missing limits, public LBs; same Rego tested with opa test and enforced in CI with conftest | `policies/opa/` | CM-6, CM-7, SI-7 | CIS K8s 5.2; 5.7 | CC7.1, CC8.1 | 8.9, 8.32 |
| CSB-16 | **Hardened nodes**<br>IMDSv2 only (hop limit 1), encrypted gp3 volumes, SSM instead of SSH; AKS host encryption, ephemeral OS disks, automatic patch channel | `terraform/aws/eks.tf`<br>`terraform/azure/aks.tf` | CM-6, SI-2 | CIS AWS 5.6; CIS EKS 3.2 | CC6.8, CC7.1 | 8.8, 8.9 |
| CSB-17 | **Minimal distroless image + SBOM**<br>Multi-stage build, distroless non-root runtime (no shell / package manager), pinned deps, CycloneDX SBOM per build | `app/Dockerfile`<br>`.github/workflows/devsecops.yml` | CM-7, SR-3, SA-10 | CIS Docker 4.1; 4.6 | CC8.1 | 8.25, 8.30 |
| CSB-18 | **IaC scanning gate**<br>tfsec (fail HIGH+) and Checkov (fail any) on every push/PR; accepted findings documented inline | `.github/workflows/devsecops.yml`<br>`security-tools/reports/` | RA-5, CA-7, SA-11 | CIS Controls v8 16.12 | CC7.1, CC8.1 | 8.8, 8.29 |
| CSB-19 | **Container and dependency scanning**<br>Trivy image (fail fixable CRITICAL), Trivy fs SCA and config scan (fail HIGH+), weekly scheduled re-scan | `.github/workflows/devsecops.yml` | RA-5, SI-2 | CIS Controls v8 7.5; 16.4 | CC7.1 | 8.8 |
| CSB-20 | **SAST + DAST + secret scanning**<br>Semgrep (fail ERROR), OWASP ZAP baseline (fail on FAIL rules), gitleaks (any leak fails) | `.github/workflows/devsecops.yml`<br>`security-tools/zap/rules.tsv` | SA-11, RA-5, IA-5 | CIS Controls v8 16.12 | CC7.1, CC8.1 | 8.25, 8.28, 8.29 |
| CSB-21 | **Pipeline hardening**<br>Actions pinned to commit SHAs, read-only GITHUB_TOKEN, no persisted credentials, CODEOWNERS review | `.github/workflows/devsecops.yml`<br>`.github/CODEOWNERS` | CM-3, SA-10, SR-3 | CIS Software Supply Chain 1.x | CC8.1 | 8.4, 8.32 |
| CSB-22 | **Audit logging with retention**<br>EKS all control-plane log types, VPC flow logs, S3 access logs (KMS, 365d); AKS kube-audit-admin + Key Vault audit to Log Analytics (365d) | `terraform/aws/eks.tf`<br>`vpc.tf`<br>`terraform/azure/aks.tf`<br>`keyvault.tf` | AU-2, AU-9, AU-11, AU-12 | CIS AWS 3.7; CIS EKS 2.1.1 | CC7.2 | 8.15 |
| CSB-23 | **Runtime threat detection**<br>Falco rules for shell in container, privilege escalation, container escape, crypto mining, sensitive file and token access (MITRE-tagged) | `security-tools/falco/` | SI-4, SI-3, AU-6 | CIS Controls v8 13.1 | CC7.2, CC7.3 | 8.7, 8.16 |
| CSB-24 | **Security monitoring and alerting**<br>Prometheus alerts (Falco critical, brute force, Gatekeeper violations, restarts, CPU/mem) routed to Slack/Teams; Grafana dashboards | `monitoring/` | SI-4, AU-6, IR-5 | CIS Controls v8 8.11 | CC7.2, CC7.3 | 8.16 |
| CSB-25 | **Automated containment and evidence handling**<br>ir_toolkit.py: quarantine NetworkPolicy, detach pod, capture logs, SHA-256 evidence manifest, Slack/Teams notify, markdown report | `incident-response/` | IR-4, IR-5, IR-6, AU-9 | CIS Controls v8 17.x | CC7.4, CC7.5 | 5.24, 5.25, 5.26, 5.28 |
| CSB-26 | **Threat model and documented design decisions**<br>STRIDE threat model; security design decisions with trade-offs | `docs/threat-model.md`<br>`docs/security-design-decisions.md` | RA-3, PL-8, SA-8 | CIS Controls v8 16.10 | CC3.2, CC5.2 | 5.8, 8.27 |

## NIST 800-53 Rev. 5 → repo controls

| Framework control | Repo controls |
|---|---|
| AC-17 | CSB-09 |
| AC-2 | CSB-01, CSB-02 |
| AC-3 | CSB-02, CSB-03, CSB-06 |
| AC-4 | CSB-10, CSB-11 |
| AC-6 | CSB-01, CSB-03, CSB-13 |
| AU-11 | CSB-22 |
| AU-12 | CSB-22 |
| AU-2 | CSB-22 |
| AU-6 | CSB-23, CSB-24 |
| AU-9 | CSB-22, CSB-25 |
| CA-7 | CSB-18 |
| CM-3 | CSB-21 |
| CM-6 | CSB-13, CSB-14, CSB-15, CSB-16 |
| CM-7 | CSB-12, CSB-15, CSB-17 |
| CP-9 | CSB-07 |
| IA-2 | CSB-02 |
| IA-5 | CSB-01, CSB-08, CSB-20 |
| IR-4 | CSB-25 |
| IR-5 | CSB-24, CSB-25 |
| IR-6 | CSB-25 |
| PL-8 | CSB-26 |
| RA-3 | CSB-26 |
| RA-5 | CSB-18, CSB-19, CSB-20 |
| SA-10 | CSB-17, CSB-21 |
| SA-11 | CSB-18, CSB-20 |
| SA-8 | CSB-26 |
| SC-12 | CSB-04 |
| SC-13 | CSB-04, CSB-05 |
| SC-28 | CSB-04, CSB-08 |
| SC-39 | CSB-13 |
| SC-5 | CSB-14 |
| SC-7 | CSB-06, CSB-09, CSB-10, CSB-11, CSB-12 |
| SC-8 | CSB-05 |
| SI-12 | CSB-07 |
| SI-2 | CSB-16, CSB-19 |
| SI-3 | CSB-23 |
| SI-4 | CSB-23, CSB-24 |
| SI-7 | CSB-15 |
| SR-3 | CSB-17, CSB-21 |

## SOC 2 TSC → repo controls

| Framework control | Repo controls |
|---|---|
| A1.2 | CSB-07 |
| C1.1 | CSB-04 |
| CC3.2 | CSB-26 |
| CC5.2 | CSB-26 |
| CC6.1 | CSB-01, CSB-02, CSB-04, CSB-06, CSB-07, CSB-08 |
| CC6.2 | CSB-02 |
| CC6.3 | CSB-01, CSB-03 |
| CC6.6 | CSB-06, CSB-09, CSB-10, CSB-11, CSB-12 |
| CC6.7 | CSB-05 |
| CC6.8 | CSB-13, CSB-16 |
| CC7.1 | CSB-13, CSB-14, CSB-15, CSB-16, CSB-18, CSB-19, CSB-20 |
| CC7.2 | CSB-22, CSB-23, CSB-24 |
| CC7.3 | CSB-23, CSB-24 |
| CC7.4 | CSB-25 |
| CC7.5 | CSB-25 |
| CC8.1 | CSB-15, CSB-17, CSB-18, CSB-20, CSB-21 |

## ISO 27001:2022 Annex A → repo controls

| Framework control | Repo controls |
|---|---|
| 5.8 | CSB-26 |
| 5.15 | CSB-01, CSB-03 |
| 5.16 | CSB-02 |
| 5.17 | CSB-08 |
| 5.18 | CSB-01 |
| 5.24 | CSB-25 |
| 5.25 | CSB-25 |
| 5.26 | CSB-25 |
| 5.28 | CSB-25 |
| 8.2 | CSB-01, CSB-03 |
| 8.3 | CSB-06 |
| 8.4 | CSB-08, CSB-21 |
| 8.5 | CSB-02 |
| 8.6 | CSB-14 |
| 8.7 | CSB-23 |
| 8.8 | CSB-16, CSB-18, CSB-19 |
| 8.9 | CSB-13, CSB-14, CSB-15, CSB-16 |
| 8.12 | CSB-06 |
| 8.13 | CSB-07 |
| 8.15 | CSB-22 |
| 8.16 | CSB-23, CSB-24 |
| 8.20 | CSB-09, CSB-10, CSB-11, CSB-12 |
| 8.22 | CSB-09, CSB-10, CSB-11 |
| 8.24 | CSB-04, CSB-05 |
| 8.25 | CSB-17, CSB-20 |
| 8.27 | CSB-26 |
| 8.28 | CSB-20 |
| 8.29 | CSB-18, CSB-20 |
| 8.30 | CSB-17 |
| 8.32 | CSB-15, CSB-21 |
