terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.69"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }

  # Remote state is configured per environment. See backend.hcl.example.
  # Run `terraform init -backend-config=backend.hcl` for real deployments.
  backend "s3" {}
}
