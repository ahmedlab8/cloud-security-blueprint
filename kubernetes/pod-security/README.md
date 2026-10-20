# Pod Security Standards

| Namespace tier | Enforce | Why |
|---|---|---|
| `secure-app` and all workload namespaces | `restricted` | Non-root, no privilege escalation, seccomp `RuntimeDefault`, all capabilities dropped |
| `ingress-nginx`, `monitoring` | `baseline` (warn/audit `restricted`) | Platform add-ons; tracked toward `restricted` |
| `falco` | `privileged` | Kernel/eBPF access needed for runtime detection; isolated namespace, no human RBAC |

Pod Security Admission is the built-in first layer. Gatekeeper (`policies/opa/`) is the
second layer and adds rules PSA cannot express (image tags, resource limits, public load
balancers). `admission-configuration.yaml` sets cluster-wide defaults for self-managed API
servers. On EKS/AKS, apply `namespaces-pss.yaml` and the labels in
`../secure-cluster/namespace.yaml`.
