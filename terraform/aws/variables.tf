variable "project" {
  description = "Short project name used as a prefix for all resources."
  type        = string
  default     = "csb"

  validation {
    condition     = can(regex("^[a-z0-9-]{2,12}$", var.project))
    error_message = "project must be 2-12 chars of lowercase letters, digits or dashes."
  }
}

variable "environment" {
  description = "Deployment environment (dev, staging, prod)."
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be one of dev, staging, prod."
  }
}

variable "region" {
  description = "AWS region."
  type        = string
  default     = "us-east-1"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC."
  type        = string
  default     = "10.20.0.0/16"
}

variable "az_count" {
  description = "Number of availability zones to spread subnets across."
  type        = number
  default     = 3

  validation {
    condition     = var.az_count >= 2 && var.az_count <= 4
    error_message = "az_count must be between 2 and 4 for high availability."
  }
}

variable "eks_version" {
  description = "Kubernetes version for EKS."
  type        = string
  default     = "1.31"
}

variable "eks_admin_cidrs" {
  description = "CIDRs allowed to reach the EKS API server. Empty list = private endpoint only (recommended)."
  type        = list(string)
  default     = []
}

variable "node_instance_types" {
  description = "Instance types for the managed node group."
  type        = list(string)
  default     = ["m6i.large"]
}

variable "node_desired_size" {
  description = "Desired node count."
  type        = number
  default     = 3
}

variable "app_namespace" {
  description = "Kubernetes namespace of the workload that receives the IRSA role."
  type        = string
  default     = "secure-app"
}

variable "app_service_account" {
  description = "Kubernetes service account bound to the least-privilege IRSA role."
  type        = string
  default     = "secure-app"
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days (>= 365 for compliance)."
  type        = number
  default     = 365
}

variable "cluster_admin_role_arn" {
  description = "IAM role ARN (e.g. an SSO break-glass role) granted EKS cluster-admin via access entries. Empty = none."
  type        = string
  default     = ""
}
