data "azurerm_client_config" "current" {}

locals {
  name = "${var.project}-${var.environment}"
  # Key Vault names: 3-24 chars, globally unique.
  kv_name = substr("kv${var.project}${var.environment}${substr(md5(data.azurerm_client_config.current.subscription_id), 0, 6)}", 0, 24)

  tags = {
    project     = var.project
    environment = var.environment
    managed_by  = "terraform"
    repository  = "cloud-security-blueprint"
  }
}

resource "azurerm_resource_group" "this" {
  name     = "rg-${local.name}"
  location = var.location
  tags     = local.tags
}

resource "azurerm_log_analytics_workspace" "this" {
  name                = "log-${local.name}"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  sku                 = "PerGB2018"
  retention_in_days   = var.log_retention_days
  tags                = local.tags
}
