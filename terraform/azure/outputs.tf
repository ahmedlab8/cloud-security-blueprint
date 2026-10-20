output "resource_group_name" {
  description = "Resource group name."
  value       = azurerm_resource_group.this.name
}

output "aks_name" {
  description = "AKS cluster name."
  value       = azurerm_kubernetes_cluster.this.name
}

output "aks_oidc_issuer_url" {
  description = "OIDC issuer for workload identity federation."
  value       = azurerm_kubernetes_cluster.this.oidc_issuer_url
}

output "key_vault_uri" {
  description = "Key Vault URI (private endpoint only)."
  value       = azurerm_key_vault.this.vault_uri
}

output "app_identity_client_id" {
  description = "Annotate the app service account with azure.workload.identity/client-id = this value."
  value       = azurerm_user_assigned_identity.app.client_id
}
