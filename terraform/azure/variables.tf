variable "subscription_id" {
  description = "Target Azure subscription ID (supply via TF_VAR_subscription_id; never commit it)."
  type        = string
  default     = null
}

variable "project" {
  description = "Short project name used as a prefix for all resources."
  type        = string
  default     = "csb"

  validation {
    condition     = can(regex("^[a-z0-9]{2,8}$", var.project))
    error_message = "project must be 2-8 lowercase alphanumerics (Key Vault names are length-limited)."
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

variable "location" {
  description = "Azure region."
  type        = string
  default     = "eastus2"
}

variable "vnet_cidr" {
  description = "Address space of the spoke VNet."
  type        = string
  default     = "10.30.0.0/16"
}

variable "kubernetes_version" {
  description = "AKS Kubernetes version (null = latest GA default)."
  type        = string
  default     = null
}

variable "admin_group_object_ids" {
  description = "Entra ID group object IDs granted AKS RBAC cluster admin."
  type        = list(string)
  default     = []
}


variable "app_namespace" {
  description = "Namespace of the workload that receives the workload identity."
  type        = string
  default     = "secure-app"
}

variable "app_service_account" {
  description = "Service account federated with the workload managed identity."
  type        = string
  default     = "secure-app"
}

variable "log_retention_days" {
  description = "Log Analytics retention (days)."
  type        = number
  default     = 365
}
