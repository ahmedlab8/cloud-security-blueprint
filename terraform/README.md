# Terraform

| Stack | Resources |
|---|---|
| [`aws/`](aws) | VPC (3 AZs, public/private subnets, NAT per AZ, locked default SG, S3 gateway endpoint, flow logs to KMS-encrypted CloudWatch), 4 KMS CMKs with 90-day rotation, hardened S3 module (data + access logs), IAM (EKS cluster, node, VPC-CNI IRSA, least-privilege app IRSA), EKS (private API, KMS secrets encryption, all log types, access entries, IMDSv2 launch template, managed add-ons) |
| [`azure/`](azure) | Resource group, Log Analytics, VNet + subnets (no default outbound access), NSGs (deny-all inbound), NAT gateway, Key Vault Premium (RBAC, purge protection, private endpoint + DNS, diagnostics), HSM CMK + disk encryption set, user-assigned identities + federated workload identity, private AKS (Entra RBAC, local accounts off, Azure CNI + network policy, Azure Policy, Defender, CSI secrets provider, host encryption) |

```bash
make terraform     # fmt -check + init -backend=false + validate for both stacks
```

Provider lock files (`.terraform.lock.hcl`) are committed for reproducible builds. The
backend blocks are intentionally empty, so pass `-backend-config=backend.hcl`. **Nothing here
has been applied to a real account.**
