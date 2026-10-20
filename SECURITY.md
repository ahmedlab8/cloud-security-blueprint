# Security policy

## Supported versions

| Version | Supported |
|---|---|
| `main` | Yes |
| anything else | No |

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Use GitHub's **private vulnerability reporting** (*Security* tab → *Report a vulnerability*),
or contact the maintainer [@ahmedlab8](https://github.com/ahmedlab8) directly. Please include:

- the affected file or component, and the commit SHA
- reproduction steps or a proof of concept
- impact as you understand it

| Step | Target |
|---|---|
| Acknowledge the report | 3 business days |
| Triage and severity (CVSS v3.1) | 7 days |
| Fix for Critical / High | 14 / 30 days |
| Coordinated disclosure | after the fix, or 90 days |

## Scope

This repository is a **reference blueprint**. In scope: insecure defaults in Terraform,
manifests, policies, the sample app, the pipeline, or the IR scripts. Out of scope: findings
in `security-tools/examples/insecure-terraform/`, which is **intentionally insecure**
training material, and issues in upstream tools.

## Security controls in this repo

Every change goes through the DevSecOps pipeline (`.github/workflows/devsecops.yml`): tfsec,
Checkov, Trivy, gitleaks, Semgrep, OWASP ZAP, OPA policy tests, and a blocking security gate.
See `docs/security-design-decisions.md` and `docs/threat-model.md`.

## Secrets

No real credentials, account IDs, subscription IDs, or webhook URLs belong in this repo.
Placeholders look like `<ACCOUNT_ID>`. If you find a real secret, report it privately and it
will be rotated immediately, then purged from history.
