data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

# Allowlist zones explicitly so the subnet layout never shifts when AWS adds an AZ.
data "aws_availability_zones" "available" {
  state = "available"

  filter {
    name   = "zone-name"
    values = [for s in slice(["a", "b", "c", "d"], 0, var.az_count) : "${var.region}${s}"]
  }
}

locals {
  name       = "${var.project}-${var.environment}"
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  azs        = slice(data.aws_availability_zones.available.names, 0, var.az_count)

  common_tags = {
    Project     = var.project
    Environment = var.environment
    ManagedBy   = "terraform"
    Repository  = "cloud-security-blueprint"
    DataClass   = "internal"
  }
}
