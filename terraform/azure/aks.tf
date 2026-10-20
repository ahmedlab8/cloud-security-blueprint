# Private AKS cluster: Entra ID + Azure RBAC only (local accounts disabled), Azure CNI with
# network policy, CMK disk encryption, host encryption, Azure Policy, Defender, and
# workload identity.

resource "azurerm_kubernetes_cluster" "this" {
  name                = "aks-${local.name}"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  dns_prefix          = "aks-${local.name}"
  kubernetes_version  = var.kubernetes_version
  sku_tier            = "Standard"

  private_cluster_enabled             = true
  private_cluster_public_fqdn_enabled = false
  local_account_disabled              = true
  role_based_access_control_enabled   = true
  azure_policy_enabled                = true
  oidc_issuer_enabled                 = true
  workload_identity_enabled           = true
  automatic_upgrade_channel           = "patch"
  node_os_upgrade_channel             = "NodeImage"
  disk_encryption_set_id              = azurerm_disk_encryption_set.aks.id
  image_cleaner_enabled               = true
  image_cleaner_interval_hours        = 48

  default_node_pool {
    name                         = "system"
    vm_size                      = "Standard_D4s_v5"
    vnet_subnet_id               = azurerm_subnet.aks.id
    auto_scaling_enabled         = true
    min_count                    = 2
    max_count                    = 5
    max_pods                     = 50
    os_disk_type                 = "Ephemeral"
    os_disk_size_gb              = 100
    host_encryption_enabled      = true
    only_critical_addons_enabled = true
    zones                        = ["1", "2", "3"]

    upgrade_settings {
      max_surge = "33%"
    }
  }

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.aks_control_plane.id]
  }

  kubelet_identity {
    client_id                 = azurerm_user_assigned_identity.aks_kubelet.client_id
    object_id                 = azurerm_user_assigned_identity.aks_kubelet.principal_id
    user_assigned_identity_id = azurerm_user_assigned_identity.aks_kubelet.id
  }

  azure_active_directory_role_based_access_control {
    tenant_id              = data.azurerm_client_config.current.tenant_id
    admin_group_object_ids = var.admin_group_object_ids
    azure_rbac_enabled     = true
  }

  network_profile {
    network_plugin    = "azure"
    network_policy    = "azure"
    load_balancer_sku = "standard"
    outbound_type     = "userAssignedNATGateway"
  }

  key_vault_secrets_provider {
    secret_rotation_enabled  = true
    secret_rotation_interval = "2m"
  }

  oms_agent {
    log_analytics_workspace_id      = azurerm_log_analytics_workspace.this.id
    msi_auth_for_monitoring_enabled = true
  }

  microsoft_defender {
    log_analytics_workspace_id = azurerm_log_analytics_workspace.this.id
  }

  tags = local.tags

  depends_on = [
    azurerm_role_assignment.aks_cp_network,
    azurerm_role_assignment.aks_cp_kubelet_operator,
    azurerm_role_assignment.des_kv_crypto_user,
    azurerm_subnet_nat_gateway_association.aks,
  ]
}

# Workload pool kept separate from system pool (critical add-ons only on system).
resource "azurerm_kubernetes_cluster_node_pool" "workload" {
  name                    = "workload"
  kubernetes_cluster_id   = azurerm_kubernetes_cluster.this.id
  vm_size                 = "Standard_D4s_v5"
  vnet_subnet_id          = azurerm_subnet.aks.id
  auto_scaling_enabled    = true
  min_count               = 2
  max_count               = 10
  max_pods                = 50
  os_disk_type            = "Ephemeral"
  os_disk_size_gb         = 100
  host_encryption_enabled = true
  zones                   = ["1", "2", "3"]
  tags                    = local.tags

  upgrade_settings {
    max_surge = "33%"
  }
}

resource "azurerm_monitor_diagnostic_setting" "aks" {
  name                       = "diag-${local.name}-aks"
  target_resource_id         = azurerm_kubernetes_cluster.this.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.this.id

  enabled_log {
    category = "kube-audit-admin"
  }

  enabled_log {
    category = "guard"
  }

  enabled_log {
    category = "kube-apiserver"
  }

  enabled_metric {
    category = "AllMetrics"
  }
}
