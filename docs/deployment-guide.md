# Deployment guide

> This repository has been validated (`terraform validate`, scanners, policy tests) but has
> **never been applied to a real cloud account**. Treat it as a reference blueprint: review
> sizing, CIDRs, and costs (NAT gateways, EKS/AKS control planes, premium Key Vault) first.

## 0. Prerequisites

| Tool | Version used | Purpose |
|---|---|---|
| Terraform | >= 1.6 (tested with 1.9.8) | IaC |
| AWS CLI v2 / Azure CLI | latest | Auth |
| kubectl, Helm | >= 1.29 / >= 3.14 | Cluster add-ons |
| tfsec, Checkov, Trivy, gitleaks, Semgrep, OPA, conftest | see `security-tools/reports/README.md` | Local gates (`make all`) |

Authenticate with **short-lived credentials**: AWS IAM Identity Center (`aws sso login`) and
Azure `az login`, or GitHub OIDC federation in CD. Never use long-lived access keys.

## 1. Remote state

Create the state backends once, out of band (bootstrap stack or console):

- **AWS:** an S3 bucket (versioning, SSE-KMS, Block Public Access) and a DynamoDB lock table
- **Azure:** a Storage account with `allow_blob_public_access=false`, Entra ID auth only, and a `tfstate` container

Copy `backend.hcl.example` to `backend.hcl` (this file is gitignored) and fill it in.

## 2. AWS

```bash
cd terraform/aws
cp terraform.tfvars.example terraform.tfvars        # adjust, never commit
terraform init -backend-config=backend.hcl
terraform plan -out tfplan
tfsec . && checkov -d .                             # re-scan before apply
terraform apply tfplan
```

The API endpoint is private by default. Reach it from inside the VPC (SSM port forwarding,
VPN, or a CI runner in the VPC), or temporarily set `eks_admin_cidrs` to your egress IP.
Set `cluster_admin_role_arn` to your SSO admin role so you can authenticate.

```bash
aws eks update-kubeconfig --name "$(terraform output -raw eks_cluster_name)" --region us-east-1
```

## 3. Azure

```bash
cd terraform/azure
export TF_VAR_subscription_id="<subscription-guid>"   # not committed
cp terraform.tfvars.example terraform.tfvars
terraform init -backend-config=backend.hcl
terraform plan -out tfplan && terraform apply tfplan
az aks get-credentials -g "$(terraform output -raw resource_group_name)" -n "$(terraform output -raw aks_name)"
kubelogin convert-kubeconfig -l azurecli
```

The deploying identity needs `Owner`, or `Contributor` plus `User Access Administrator`, on
the subscription to create role assignments. Key Vault is private-only, so run Terraform from a
network that can resolve and reach the private endpoint (a self-hosted runner in the VNet),
or temporarily add your IP to `network_acls`.

## 4. Cluster baseline (both clouds)

```bash
# Namespaces with Pod Security Standards
kubectl apply -f kubernetes/pod-security/namespaces-pss.yaml

# Gatekeeper, then templates, then constraints
helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts
helm upgrade --install gatekeeper gatekeeper/gatekeeper -n gatekeeper-system --create-namespace
kubectl apply -f policies/opa/gatekeeper/templates/
kubectl wait --for=condition=established crd -l gatekeeper.sh/constraint=yes --timeout=60s || sleep 20
kubectl apply -f policies/opa/gatekeeper/constraints/

# Secrets Store CSI driver + provider (AWS: secrets-store-csi-driver-provider-aws; AKS: enabled by Terraform)
helm repo add secrets-store-csi-driver https://kubernetes-sigs.github.io/secrets-store-csi-driver/charts
helm upgrade --install csi secrets-store-csi-driver/secrets-store-csi-driver -n kube-system

# Falco (see security-tools/falco/README.md)
# Monitoring (see monitoring/README.md)
```

## 5. Application

1. Fill in the placeholders in `kubernetes/secure-cluster/serviceaccount.yaml` with the
   Terraform outputs (`app_irsa_role_arn` or `app_identity_client_id`).
2. Create the secret in AWS Secrets Manager (`csb/dev/secure-app/demo-password`) or Key Vault (`demo-password`).
3. On AKS, swap `secretproviderclass-aws.yaml` for `secretproviderclass-azure.yaml` in `kustomization.yaml`.
4. Pin the image digest and deploy:

```bash
cd kubernetes/secure-cluster
kustomize edit set image ghcr.io/ahmedlab8/secure-app=ghcr.io/ahmedlab8/secure-app@sha256:<digest>
kubectl apply -k .
```

## 6. Verify the controls

```bash
# Should be DENIED by Gatekeeper/PSA:
kubectl -n secure-app run bad --image=nginx:latest
kubectl -n secure-app create service loadbalancer public --tcp=80:80

# Should raise Falco alerts (use a throwaway namespace):
kubectl create ns falco-test
kubectl -n falco-test run t --image=busybox:1.36 --restart=Never -- sh -c 'cat /etc/shadow; sleep 5'

# Incident response dry-run:
./incident-response/ir_toolkit.py respond -n secure-app -p <pod> --reason "drill" --dry-run
```

## 7. Teardown

`terraform destroy` in each stack. Key Vault purge protection keeps the vault in a
soft-deleted state for 90 days by design, and KMS keys have a 30-day deletion window.
