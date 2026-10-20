output "vpc_id" {
  description = "ID of the VPC."
  value       = aws_vpc.this.id
}

output "private_subnet_ids" {
  description = "Private subnet IDs (EKS nodes)."
  value       = aws_subnet.private[*].id
}

output "eks_cluster_name" {
  description = "EKS cluster name."
  value       = aws_eks_cluster.this.name
}

output "eks_oidc_provider_arn" {
  description = "OIDC provider ARN for IRSA."
  value       = aws_iam_openid_connect_provider.eks.arn
}

output "app_irsa_role_arn" {
  description = "Annotate the app service account with this role ARN (eks.amazonaws.com/role-arn)."
  value       = aws_iam_role.app.arn
}

output "data_bucket" {
  description = "Encrypted application data bucket."
  value       = module.s3_app_data.id
}

output "kms_key_arns" {
  description = "Customer-managed KMS key ARNs by purpose."
  value       = { for k, v in aws_kms_key.this : k => v.arn }
}
