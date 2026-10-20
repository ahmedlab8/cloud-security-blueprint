# Security scan reports

Each dated folder holds raw output from **real scanner runs**. Nothing is hand-written or
invented. CI also uploads fresh reports as workflow artifacts on every run (`tfsec-report`,
`checkov-report`, `trivy-report` with SBOM, `semgrep-report`, `gitleaks-report`, `zap-report`).

## 2026-10-20 baseline

Tool versions: Terraform 1.9.8, tfsec 1.28.11, Checkov 3.3.30, Trivy 0.76.0, gitleaks 8.30.1,
Semgrep 1.181.0, OWASP ZAP (stable image), OPA 1.21.3, conftest 0.71.1, kubeconform 0.8.0, Falco 0.45.1.

### Hardened blueprint (what CI gates on)

| Scanner | Target | Result | Files |
|---|---|---|---|
| tfsec | `terraform/aws` | 53 passed, **0 findings**, 2 ignored with inline justification | `tfsec-aws.{txt,json}` |
| tfsec | `terraform/azure` | 16 passed, **0 findings** | `tfsec-azure.{txt,json}` |
| Checkov | `terraform/aws` | 248 passed, **0 failed**, 7 skipped with inline justification | `checkov-terraform-aws.{txt,json}` |
| Checkov | `terraform/azure` | 42 passed, **0 failed** | `checkov-terraform-azure.{txt,json}` |
| Checkov | `kubernetes/` | 124 passed, **0 failed**, 1 skipped (image digest set at deploy time) | `checkov-kubernetes.txt` |
| Checkov | `app/Dockerfile` | 36 passed, **0 failed** | `checkov-dockerfile.txt` |
| Checkov | `.github/workflows` | 256 passed, **0 failed** | `checkov-github-actions.txt` |
| Trivy image | `secure-app` (distroless Debian 13.7) | **0 CRITICAL**, 26 HIGH, 87 MEDIUM, 49 LOW, all OS packages with **no upstream fix**; Python packages: 0 | `trivy-image-secure-app.{txt,json}`, `sbom-secure-app.cdx.json` |
| Trivy fs (SCA) | `app/requirements.txt` | **0** vulnerabilities | `trivy-fs-app.txt` |
| Trivy config | Dockerfile, K8s, Terraform | **0** HIGH/CRITICAL misconfigurations (1 accepted in `.trivyignore.yaml`) | `trivy-config.txt` |
| gitleaks | working tree | **no leaks found** | `gitleaks.{txt,json}` |
| Semgrep | `p/python p/flask p/dockerfile p/github-actions p/secrets` | **0** findings after triage (see below) | `semgrep.json` |
| OWASP ZAP baseline | running container | **0 FAIL, 0 WARN**, 66 PASS, 1 IGNORE (10049, intentional `no-store`) | `zap-baseline.{md,json}` |
| Validation | fmt/validate, OPA, conftest, kubeconform, pytest, promtool, Falco | all passed | `validation.txt` |

**Semgrep triage:** the first run flagged 2 WARNING-level findings, and both were handled before
the run recorded here:
1. `python-logger-credential-disclosure` in `app/src/app.py`. The log line named the secret
   variable (not its value). Fixed by rewording the message.
2. `insecure-file-permissions` in `incident-response/ir_toolkit.py`. `chmod 0o700` on the
   evidence *directory* is owner-only, and the exec bit is needed to traverse it. Accepted with
   an inline `nosemgrep` and a justification.

**Container image:** `trivy-base-image-comparison.md` shows why the runtime base is
`gcr.io/distroless/python3-debian13:nonroot`. It goes from 21 CRITICAL / 586 HIGH on
`python:3.11-bookworm` down to 0 CRITICAL / 26 HIGH, with none of those fixable yet. The CI gate
fails on any *fixable* CRITICAL, and the weekly scheduled run catches fixes as Debian ships them.

### Intentionally insecure example (training baseline)

`security-tools/examples/insecure-terraform/` reproduces common misconfigurations. CI never
gates on it.

| Scanner | Result | Files |
|---|---|---|
| tfsec | **27 findings**: 4 CRITICAL, 12 HIGH, 8 MEDIUM, 3 LOW (2 passed) | `tfsec-insecure-example.{txt,json}` |
| Checkov | **35 failed**, 11 passed | `checkov-insecure-example.{txt,json}` |

`docs/remediation-guide.md` maps every one of these findings to the fix used in `terraform/aws`.

## Regenerating

```bash
make iac-scan sast secrets       # gates
make image                       # Trivy image gate (needs docker)
```
