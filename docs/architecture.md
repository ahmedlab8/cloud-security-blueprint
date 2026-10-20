# Architecture

## High-level view

```mermaid
flowchart LR
  dev[Developer] -->|PR| gh[GitHub]
  subgraph CI["GitHub Actions - DevSecOps pipeline"]
    direction TB
    tf[terraform fmt / validate] --> iac[tfsec + Checkov]
    pol[OPA tests + conftest + kubeconform]
    code[gitleaks + Semgrep + unit tests]
    img[docker build -> Trivy image/fs/config + SBOM] --> dast[OWASP ZAP baseline]
    iac & pol & code & dast --> gate{Security gate}
  end
  gh --> CI
  gate -->|pass| reg[(Container registry)]
  gate -->|fail| block[Merge blocked]

  subgraph AWS["AWS account"]
    direction TB
    subgraph VPC["VPC 10.20.0.0/16 (flow logs -> KMS CloudWatch)"]
      pub[Public subnets: NAT / LB only]
      subgraph PRIV["Private subnets"]
        eks[EKS - private API, KMS secrets, audit logs]
        ng[Managed nodes - IMDSv2, encrypted EBS]
      end
    end
    kms[(KMS CMKs: eks / s3 / logs / ebs)]
    s3[(S3 data + access-log buckets: SSE-KMS, BPA, TLS-only)]
    irsa[IRSA role: one S3 prefix]
  end

  subgraph Azure["Azure subscription"]
    direction TB
    subgraph VNET["VNet 10.30.0.0/16 + NSGs (deny-all inbound)"]
      aks[AKS - private, Entra RBAC, Azure Policy, Defender]
      pe[Private endpoint]
    end
    kv[(Key Vault premium - RBAC, purge protection, no public access)]
    mi[Managed identities + workload identity]
    law[(Log Analytics)]
  end

  reg --> eks & aks
  eks --- irsa --- s3
  aks --- mi --- kv
  pe --- kv
  aks --> law
```

## Kubernetes runtime layers

```mermaid
flowchart TB
  req[kubectl / CD pipeline] --> authn[IdP auth: IAM Identity Center / Entra ID]
  authn --> rbac[RBAC: namespace Roles bound to groups]
  rbac --> psa[Pod Security Admission: restricted]
  psa --> gk[Gatekeeper: no root / privileged / :latest / missing limits / public LB]
  gk --> pod[Pod: distroless, UID 65532, RO rootfs, drop ALL, seccomp]
  pod --> np[NetworkPolicies: default deny + explicit allows, IMDS blocked]
  pod --> csi[Secrets Store CSI: KMS-backed secrets as files]
  pod -.syscalls.-> falco[Falco eBPF rules]
  falco --> sidekick[Falcosidekick] --> slack[Slack / Teams]
  sidekick --> prom[Prometheus] --> graf[Grafana dashboards]
  prom --> am[Alertmanager] --> slack
  am --> ir[incident-response/ir_toolkit.py: isolate, collect, report]
```

## Incident-response flow

```mermaid
sequenceDiagram
  participant F as Falco
  participant S as Falcosidekick / Alertmanager
  participant O as On-call engineer
  participant T as ir_toolkit.py
  participant K as Kubernetes API
  F->>S: CRITICAL "Shell Spawned in Container"
  S->>O: Slack / Teams alert with pod + rule
  O->>T: respond --falco-event event.json
  T->>K: apply quarantine-deny-all NetworkPolicy
  T->>K: label quarantine=true, detach from ReplicaSet/Service
  T->>K: logs, describe, events, pod/node specs
  T->>T: SHA-256 manifest + evidence tarball
  T->>S: Slack / Teams notification (actions taken)
  T->>O: incident-report.md
```

## Repository map

| Path | Purpose |
|---|---|
| `terraform/aws` | VPC, subnets, NAT, flow logs, KMS, S3 module, IAM (cluster, node, IRSA), EKS |
| `terraform/azure` | RG, VNet, NSGs, NAT, Key Vault + private endpoint, managed identities, AKS, Log Analytics |
| `kubernetes/secure-cluster` | Namespace (PSS), ServiceAccount, Deployment, Service, Role/RoleBinding, quotas, SecretProviderClass |
| `kubernetes/network-policies` | Default deny, DNS, ingress controller, Prometheus, HTTPS egress, quarantine |
| `kubernetes/pod-security` | PSS namespace tiers and the PSA admission configuration |
| `policies/opa` | Gatekeeper Rego (tested), generated ConstraintTemplates, Constraints, conftest wrapper |
| `policies/compliance` | Control mapping CSV and generated matrix (NIST / CIS / SOC 2 / ISO) |
| `app/` | Sample Flask service, distroless Dockerfile, tests |
| `security-tools/` | Falco, ZAP rules, scan reports, insecure training example |
| `monitoring/` | Prometheus config + alert rules (with tests), Alertmanager, Grafana dashboards |
| `incident-response/` | Python toolkit + Bash scripts with dry-run and tests |
| `.github/workflows` (copy in `cicd/`) | DevSecOps pipeline |
