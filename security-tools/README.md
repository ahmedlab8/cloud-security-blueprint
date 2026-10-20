# Security tools

| Tool | Where | How it's used |
|---|---|---|
| tfsec | CI `tfsec` job, `make iac-scan` | Terraform misconfigurations. Inline `#tfsec:ignore:<id>` comments carry justifications |
| Checkov | CI `checkov` job | Terraform, Kubernetes, Dockerfile, GitHub Actions. Inline `#checkov:skip=<id>:<reason>` |
| Trivy | CI `container` job | Image CVEs, SCA (`requirements.txt`), config scanning, SBOM. Accepted items go in `/.trivyignore.yaml` |
| gitleaks | CI `secret-scan` job | Full git history |
| Semgrep | CI `sast` job | SAST rule packs |
| OWASP ZAP | CI `dast` job, `zap/rules.tsv` | Baseline passive DAST. `FAIL` rules break the build |
| OPA / Gatekeeper / conftest | `policies/opa` | Admission control, plus the same policies in CI |
| Falco | `falco/` | Runtime detection rules and Helm values |

- `reports/`: dated **real** scan output and the summary table
- `examples/insecure-terraform/`: **intentionally insecure** training baseline (never deployed, excluded from gates)
