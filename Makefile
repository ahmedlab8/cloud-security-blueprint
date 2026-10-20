# Local equivalents of the CI gates. Requires: terraform, tfsec, checkov, trivy, gitleaks,
# semgrep, opa, conftest, kubeconform, shellcheck, ruff, pytest, docker (optional).
SHELL := /bin/bash
.DEFAULT_GOAL := help
K8S_YAML := $(shell find kubernetes -name '*.yaml' ! -name kustomization.yaml ! -name admission-configuration.yaml)
CRD_SCHEMAS := https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json

help: ## Show targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-16s %s\n", $$1, $$2}'

fmt: ## Format Terraform, Rego and Python
	terraform fmt -recursive terraform
	opa fmt -w policies/opa
	ruff format .

terraform: ## terraform fmt -check + init -backend=false + validate (aws, azure)
	terraform fmt -check -recursive terraform
	@for c in aws azure; do (cd terraform/$$c && terraform init -backend=false -input=false >/dev/null && terraform validate) || exit 1; done

iac-scan: ## tfsec + Checkov
	tfsec terraform --minimum-severity HIGH --concise-output
	checkov -d terraform -d kubernetes -d app -d .github --framework terraform kubernetes dockerfile github_actions --skip-path security-tools/examples --compact --quiet

policy: ## OPA unit tests, template sync, conftest, kubeconform
	opa test policies/opa/gatekeeper/rego policies/opa/tests
	python3 policies/opa/gatekeeper/generate.py --check
	conftest test -p policies/opa/gatekeeper/rego -p policies/opa/conftest $(K8S_YAML)
	! conftest test -p policies/opa/gatekeeper/rego -p policies/opa/conftest policies/opa/tests/fixtures/bad-workload.yaml >/dev/null
	kubeconform -strict -summary -kubernetes-version 1.31.0 -schema-location default -schema-location '$(CRD_SCHEMAS)' \
	  -skip Kustomization,AdmissionConfiguration,K8sBlockRootContainers,K8sBlockPrivilegedContainers,K8sDisallowLatestTag,K8sRequireResourceLimits,K8sBlockPublicLoadBalancer $(shell find kubernetes policies/opa/gatekeeper -name '*.yaml' ! -name kustomization.yaml)

code: ## ruff, shellcheck, pytest
	ruff check . && ruff format --check .
	shellcheck incident-response/*.sh
	pytest -q app/tests incident-response/tests

secrets: ## gitleaks over git history
	gitleaks git --redact --verbose .

sast: ## Semgrep
	semgrep scan --config p/python --config p/flask --config p/dockerfile --config p/github-actions --config p/secrets \
	  --exclude security-tools/examples --severity ERROR --error --metrics off

image: ## Build image and Trivy-scan it (fail on fixable CRITICAL)
	docker build -t secure-app:local app
	trivy image --severity CRITICAL --ignore-unfixed --exit-code 1 secure-app:local

monitoring: ## promtool + amtool checks
	promtool check rules monitoring/prometheus/rules/security-alerts.yml
	cd monitoring/prometheus/rules && promtool test rules security-alerts.test.yml
	amtool check-config monitoring/alertmanager/alertmanager.yml

generate: ## Regenerate Gatekeeper templates, Grafana dashboards, compliance matrix
	python3 policies/opa/gatekeeper/generate.py
	python3 monitoring/grafana/build_dashboards.py
	python3 policies/compliance/build_matrix.py
	python3 monitoring/prometheus/build_prometheusrule.py

validate: terraform policy code monitoring ## All offline validation
all: validate iac-scan sast secrets ## Everything except the image build

.PHONY: help fmt terraform iac-scan policy code secrets sast image monitoring generate validate all
