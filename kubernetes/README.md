# Kubernetes manifests

| Folder | Manifests |
|---|---|
| `secure-cluster/` | `namespace.yaml` (PSS restricted), `serviceaccount.yaml` (no token automount, IRSA / workload-identity annotations), `deployment.yaml`, `service.yaml` (ClusterIP), `rbac.yaml` (viewer, deployer, and incident-responder Roles + RoleBindings), `quotas.yaml` (ResourceQuota, LimitRange, PDB), `secretproviderclass-{aws,azure}.yaml` |
| `network-policies/` | default deny (ingress + egress), DNS, ingress controller, Prometheus scrape, HTTPS egress with IMDS blocked, quarantine |
| `pod-security/` | Namespace PSS tiers and the PSA `AdmissionConfiguration` |

Deployment hardening: UID/GID 65532, `runAsNonRoot`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`,
`capabilities.drop: [ALL]`, seccomp `RuntimeDefault`, CPU/memory/ephemeral-storage requests and limits,
liveness and readiness probes, a memory-backed `/tmp`, secrets mounted read-only through the CSI driver,
topology spread, and `maxUnavailable: 0` rollouts.

```bash
kubectl apply -k kubernetes/secure-cluster      # includes network-policies
make policy                                     # kubeconform + conftest against the Gatekeeper policies
```
