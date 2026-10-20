# Policies

## `opa/`: Gatekeeper admission control (policy as code)

| Constraint | Blocks |
|---|---|
| `K8sBlockRootContainers` | Containers without `runAsNonRoot: true` or a non-zero `runAsUser`, and explicit UID 0 |
| `K8sBlockPrivilegedContainers` | `privileged: true`, missing `allowPrivilegeEscalation: false`, `hostPID` / `hostIPC` / `hostNetwork` |
| `K8sDisallowLatestTag` | `:latest` and untagged images (digests are allowed, and registry ports are handled correctly) |
| `K8sRequireResourceLimits` | Missing CPU or memory requests or limits |
| `K8sBlockPublicLoadBalancer` | `type: LoadBalancer` without an internal-LB annotation (AWS, Azure, GCP) |

```
opa/gatekeeper/rego/         source of truth (Rego v1 syntax, shared lib via Gatekeeper `libs`)
opa/gatekeeper/templates/    GENERATED ConstraintTemplates (python3 generate.py)
opa/gatekeeper/constraints/  Constraints with system-namespace exemptions
opa/tests/                   20 opa unit tests and a negative fixture
opa/conftest/                wrapper that runs the same policies against raw manifests in CI
```

Policies check Pods **and** workload controllers (Deployment, StatefulSet, DaemonSet, Job,
CronJob, and so on), so violations show up when the Deployment is applied rather than later
as failed ReplicaSet events.

## `compliance/`: control mapping

`control-mapping.csv` maps 26 controls to NIST 800-53 r5, CIS, SOC 2, and ISO 27001:2022.
`compliance-matrix.md` is generated from it with reverse indexes per framework.
