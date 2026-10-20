# Contributing

Thanks for helping improve **cloud-security-blueprint**.

## Workflow

1. Fork the repo or create a branch: `feat/<topic>`, `fix/<topic>`, `sec/<topic>`.
2. Make your change and run the local gates:
   ```bash
   make fmt        # terraform fmt, opa fmt, ruff format
   make generate   # if you changed Rego, dashboards, compliance CSV or alert rules
   make all        # validate + tfsec/Checkov + Semgrep + gitleaks
   make image      # optional: build and Trivy-scan the sample image (needs docker)
   ```
3. Open a PR. **Security gate** must be green, and CODEOWNERS approval is required.

## Conventions

- **Commits:** [Conventional Commits](https://www.conventionalcommits.org/), e.g. `feat(terraform): add GuardDuty`, `fix(policy): handle initContainers`.
- **Terraform:** `terraform fmt`, typed and described variables with validation where useful, no hard-coded IDs or regions in resources, provider versions pinned, lock files committed.
- **Kubernetes:** must pass PSS `restricted`, Gatekeeper/conftest, Checkov, and kubeconform.
- **Rego:** v1 syntax. Edit `policies/opa/gatekeeper/rego/*.rego` and add tests in `policies/opa/tests/`, then run `generate.py`. Never edit the generated templates by hand.
- **Python:** ruff-clean, type hints, tests for new behaviour. **Bash:** `set -euo pipefail`, shellcheck-clean, `--dry-run` for anything that mutates state.
- **Accepting a finding:** use an inline skip with a justification (`#checkov:skip=ID:reason`, `#tfsec:ignore:id`, `.trivyignore.yaml` with a `statement`, or `# nosemgrep: rule-id`), and add a row to *Accepted findings* in `docs/remediation-guide.md`.
- **Secrets:** never commit any. Use placeholders like `<ACCOUNT_ID>`. gitleaks scans the full history.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Please don't open public issues for vulnerabilities.
