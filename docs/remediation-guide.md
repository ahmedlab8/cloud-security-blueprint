# Remediation guide: from findings to fixes

These findings come from the real tfsec and Checkov runs against
`security-tools/examples/insecure-terraform/` (reports in `security-tools/reports/2026-10-20/`).
Each row shows the fix and where the hardened blueprint implements it.

## Network

| Finding (tool ID) | Severity | Risk | Fix | Where in blueprint |
|---|---|---|---|---|
| `aws-ec2-no-public-ingress-sgr` (tfsec), CKV_AWS_24/25/260 | CRITICAL | All ports including SSH/RDP open to the internet | Allow only the required port from known CIDRs or SGs, and use SSM Session Manager instead of SSH | `terraform/aws/eks.tf` (`aws_vpc_security_group_ingress_rule` from the VPC CIDR only) |
| `aws-ec2-no-public-egress-sgr`, CKV_AWS_382 | CRITICAL | Unrestricted exfiltration path | Scope egress to the VPC or required endpoints, add VPC endpoints, and use NAT for the rest | `terraform/aws/eks.tf`, `vpc.tf` (S3 gateway endpoint) |
| `aws-ec2-add-description-to-security-group-rule`, CKV_AWS_23 | LOW | Rules can't be audited | Add a description to every rule | all SG rules |
| CKV2_AWS_5 | - | Orphaned SG | Attach the SG or delete it | n/a |
| CKV_AWS_88 | - | Instance gets a public IP | Private subnets only, `map_public_ip_on_launch = false` | `terraform/aws/vpc.tf` |

## Identity

| Finding | Severity | Risk | Fix | Where |
|---|---|---|---|---|
| `aws-iam-no-policy-wildcards`, CKV_AWS_62/63/355, CKV2_AWS_40 | HIGH | `*:*` means full account takeover | Name the specific actions on specific ARNs, and add conditions (`kms:ViaService`, `s3:prefix`) | `terraform/aws/iam.tf` (`app` policy) |
| CKV_AWS_286/287/288/289/290 | - | Privilege escalation, credential exposure, data exfiltration | Same as above. Never grant `iam:*`, `sts:*`, or unscoped write | `terraform/aws/iam.tf` |
| CKV2_AWS_41 | - | Instance without a role means static keys on disk | Use an instance profile, or IRSA for pods | `terraform/aws/iam.tf` (IRSA) |

## Kubernetes control plane (EKS)

| Finding | Severity | Risk | Fix | Where |
|---|---|---|---|---|
| `aws-eks-no-public-cluster-access`, CKV_AWS_39 | CRITICAL | API server reachable from the internet | `endpoint_public_access = false` (the default here) | `terraform/aws/eks.tf` |
| `aws-eks-no-public-cluster-access-to-cidr`, CKV_AWS_38 | CRITICAL | 0.0.0.0/0 API access | If public access is needed, allowlist `eks_admin_cidrs` | `terraform/aws/eks.tf` |
| `aws-eks-encrypt-secrets`, CKV_AWS_58 | HIGH | Secrets in etcd protected only by AWS-managed encryption | `encryption_config` with a customer-managed KMS key | `terraform/aws/eks.tf`, `kms.tf` |
| `aws-eks-enable-control-plane-logging` (x5), CKV_AWS_37 | MEDIUM | No audit trail of API activity | Enable api, audit, authenticator, controllerManager, scheduler; pre-create a KMS-encrypted log group with retention | `terraform/aws/eks.tf` |

## Compute

| Finding | Severity | Risk | Fix | Where |
|---|---|---|---|---|
| `aws-ec2-enforce-http-token-imds`, CKV_AWS_79 | HIGH | SSRF leads to stolen instance credentials (IMDSv1) | `http_tokens = "required"`, `http_put_response_hop_limit = 1` | `terraform/aws/eks.tf` (launch template) |
| `aws-ec2-enable-at-rest-encryption`, CKV_AWS_8 | HIGH | Unencrypted root volume | `encrypted = true` with a customer-managed KMS key | `terraform/aws/eks.tf` (launch template) |
| CKV_AWS_126 / CKV_AWS_135 | - | No detailed monitoring / not EBS-optimised | `monitoring { enabled = true }`, current-generation instances | `terraform/aws/eks.tf` |

## Storage (S3)

| Finding | Severity | Risk | Fix | Where |
|---|---|---|---|---|
| `aws-s3-no-public-access-with-acl`, CKV_AWS_20 | HIGH | `public-read` ACL exposes the data | Remove ACLs and set `BucketOwnerEnforced` | `modules/secure-s3-bucket` |
| `aws-s3-block-public-acls/policy`, `ignore-public-acls`, `no-public-buckets`, `specify-public-access-block`, CKV2_AWS_6 | HIGH/LOW | Bucket can be made public | Turn on all four Block Public Access settings | `modules/secure-s3-bucket` |
| `aws-s3-enable-bucket-encryption`, `aws-s3-encryption-customer-key`, CKV_AWS_145 | HIGH | No encryption, or AWS-managed key only | SSE-KMS with a customer-managed key, bucket key enabled | `modules/secure-s3-bucket` |
| `aws-s3-enable-versioning`, CKV_AWS_21 | MEDIUM | Ransomware or accidental deletion | Versioning plus noncurrent version lifecycle | `modules/secure-s3-bucket` |
| `aws-s3-enable-bucket-logging`, CKV_AWS_18 | MEDIUM | No access audit | Server access logs to a dedicated log bucket | `modules/secure-s3-bucket`, `s3.tf` |
| CKV2_AWS_61 | - | Unbounded storage and retention | Lifecycle rules | `modules/secure-s3-bucket` |
| CKV_AWS_144, CKV2_AWS_62 | - | No cross-region replication / event notifications | **Accepted** with inline `checkov:skip` and a justification (environment-level DR decision) | `modules/secure-s3-bucket` |

## Key management

| Finding | Severity | Risk | Fix | Where |
|---|---|---|---|---|
| `aws-kms-auto-rotate-keys`, CKV_AWS_7 | MEDIUM | Long-lived key material | `enable_key_rotation = true`, `rotation_period_in_days = 90` | `terraform/aws/kms.tf` |
| CKV2_AWS_64 | - | Implicit default key policy | Explicit key policy | `terraform/aws/kms.tf` |

## Accepted findings in the hardened code (with justification)

| Tool | ID | Location | Justification |
|---|---|---|---|
| tfsec | `aws-iam-no-policy-wildcards` | `iam.tf` app policy | `/<namespace>/*` is the narrowest possible S3 object scope for one workload |
| tfsec | `aws-iam-no-policy-wildcards` | `vpc.tf` flow logs | `<log-group-arn>:*` addresses streams inside a single log group, as CloudWatch requires |
| Checkov | CKV_AWS_109, CKV_AWS_111, CKV_AWS_356 | `kms.tf` | The KMS key-policy root statement and `"*"` resource are the AWS-documented baseline. Without them the key can become unmanageable |
| Checkov | CKV_AWS_144, CKV2_AWS_62 | S3 module | DR replication and event notifications are per-environment decisions |
| Checkov | CKV_K8S_43 | `deployment.yaml` | The image digest is pinned by the release pipeline. Source manifests carry an immutable semver tag |
| Trivy | KSV-0056 | `rbac.yaml` | The IR role must create the quarantine NetworkPolicy and the deployer must patch the Service. Both are namespace-scoped and group-bound |
| Semgrep | insecure-file-permissions | `ir_toolkit.py` | `0700` on a directory is owner-only, and the exec bit is needed to traverse it |
| ZAP | 10049 (IGNORE) | `rules.tsv` | `Cache-Control: no-store` is deliberate for API responses |

## Container image remediation

| Finding | Fix | Evidence |
|---|---|---|
| 21 CRITICAL / 586 HIGH OS CVEs on `python:3.11-bookworm` | Multi-stage build with a distroless Debian 13 runtime: no shell, no package manager, far fewer packages | `trivy-base-image-comparison.md` |
| Fixable HIGH CVEs on `distroless/python3-debian12` (43) | Move to `python3-debian13`: 0 fixable | same |
| Running as root (CKV_DOCKER_3 / CIS Docker 4.1) | `USER 65532:65532` plus `runAsNonRoot` in K8s, enforced by Gatekeeper | `app/Dockerfile` |
| Missing HEALTHCHECK (CKV_DOCKER_2) | Python-based HEALTHCHECK, since there is no curl in distroless | `app/Dockerfile` |
| Server banner disclosure (ZAP 10036) | `gunicorn.SERVER = "undisclosed"` | `app/src/gunicorn.conf.py` |
| CSP without `form-action` (ZAP 10055) | Added `form-action 'none'; base-uri 'none'` | `app/src/app.py` |
