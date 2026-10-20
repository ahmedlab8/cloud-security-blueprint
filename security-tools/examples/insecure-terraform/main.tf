# =============================================================================
# INTENTIONALLY INSECURE - TRAINING / BASELINE EXAMPLE ONLY. DO NOT DEPLOY.
#
# This file reproduces common real-world misconfigurations so tfsec and Checkov
# have something to find. The reports in security-tools/reports/*-insecure-*
# were generated from it, and docs/remediation-guide.md maps every finding to the
# hardened equivalent in terraform/aws. CI excludes this directory from gates.
# =============================================================================

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.80"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# No encryption, no versioning, no logging, no public access block.
resource "aws_s3_bucket" "insecure" {
  bucket = "example-insecure-bucket-do-not-deploy"
}

resource "aws_s3_bucket_acl" "insecure" {
  bucket = aws_s3_bucket.insecure.id
  acl    = "public-read"
}

# SSH and all ports open to the internet.
resource "aws_security_group" "wide_open" {
  name        = "wide-open"
  description = "Allows everything"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Admin-everything IAM policy.
resource "aws_iam_policy" "admin" {
  name = "too-much-power"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

# Public EKS endpoint, no secrets encryption, no control-plane logging.
resource "aws_eks_cluster" "insecure" {
  name     = "insecure"
  role_arn = "arn:aws:iam::000000000000:role/placeholder"

  vpc_config {
    subnet_ids             = ["subnet-00000000000000000"]
    endpoint_public_access = true
  }
}

# IMDSv1 allowed, unencrypted root volume, public IP.
resource "aws_instance" "insecure" {
  ami                         = "ami-00000000000000000"
  instance_type               = "t3.micro"
  associate_public_ip_address = true

  root_block_device {
    encrypted = false
  }
}

# KMS key without rotation.
resource "aws_kms_key" "no_rotation" {
  description = "no rotation"
}
