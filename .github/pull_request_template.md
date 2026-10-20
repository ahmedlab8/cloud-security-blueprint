## What & why

## Security checklist
- [ ] `make all` passes locally (or CI security gate is green)
- [ ] No secrets, account IDs or real endpoints added
- [ ] New/changed accepted findings have inline justification + entry in `docs/remediation-guide.md`
- [ ] Threat model / design decisions updated if the architecture changed
- [ ] Generated files refreshed (`make generate`) if Rego, dashboards, compliance CSV or alert rules changed
