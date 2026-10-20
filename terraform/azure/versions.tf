terraform {
  required_version = ">= 1.6.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.10"
    }
  }

  # Remote state in an Azure Storage account with Entra ID auth. See backend.hcl.example.
  backend "azurerm" {}
}
