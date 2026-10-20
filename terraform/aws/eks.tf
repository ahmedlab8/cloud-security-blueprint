# ---------------------------------------------------------------------------
# Amazon EKS: private API endpoint, envelope-encrypted secrets, full audit logging,
# IMDSv2-only nodes with encrypted volumes in private subnets.
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "eks" {
  # EKS writes to this exact name; creating it first lets us enforce retention + KMS.
  name              = "/aws/eks/${local.name}-eks/cluster"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.this["logs"].arn
}

resource "aws_security_group" "eks_cluster" {
  name        = "${local.name}-eks-cluster"
  description = "Additional security group for the EKS control plane ENIs"
  vpc_id      = aws_vpc.this.id

  tags = { Name = "${local.name}-eks-cluster" }
}

resource "aws_vpc_security_group_ingress_rule" "eks_api_from_vpc" {
  security_group_id = aws_security_group.eks_cluster.id
  description       = "HTTPS to the Kubernetes API from inside the VPC only"
  cidr_ipv4         = var.vpc_cidr
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "eks_to_vpc" {
  security_group_id = aws_security_group.eks_cluster.id
  description       = "Control plane to nodes/kubelets inside the VPC"
  cidr_ipv4         = var.vpc_cidr
  ip_protocol       = "-1"
}

resource "aws_eks_cluster" "this" {
  name     = "${local.name}-eks"
  version  = var.eks_version
  role_arn = aws_iam_role.eks_cluster.arn

  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  access_config {
    authentication_mode                         = "API"
    bootstrap_cluster_creator_admin_permissions = false
  }

  vpc_config {
    subnet_ids              = aws_subnet.private[*].id
    security_group_ids      = [aws_security_group.eks_cluster.id]
    endpoint_private_access = true
    #tfsec:ignore:aws-eks-no-public-cluster-access - only enabled when eks_admin_cidrs is explicitly set; default is private-only
    endpoint_public_access = length(var.eks_admin_cidrs) > 0
    #tfsec:ignore:aws-eks-no-public-cluster-access-to-cidr - restricted to eks_admin_cidrs, never 0.0.0.0/0 (see validation in docs)
    public_access_cidrs = length(var.eks_admin_cidrs) > 0 ? var.eks_admin_cidrs : ["0.0.0.0/32"]
  }

  encryption_config {
    resources = ["secrets"]
    provider {
      key_arn = aws_kms_key.this["eks"].arn
    }
  }

  depends_on = [
    aws_iam_role_policy_attachment.eks_cluster,
    aws_cloudwatch_log_group.eks,
  ]
}

data "tls_certificate" "eks" {
  url = aws_eks_cluster.this.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "eks" {
  url             = aws_eks_cluster.this.identity[0].oidc[0].issuer
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.eks.certificates[0].sha1_fingerprint]
}

resource "aws_launch_template" "nodes" {
  name_prefix = "${local.name}-nodes-"
  description = "Hardened launch template for EKS managed nodes"

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2 only
    http_put_response_hop_limit = 1          # pods cannot reach node IMDS credentials
    instance_metadata_tags      = "disabled"
  }

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size           = 50
      volume_type           = "gp3"
      encrypted             = true
      kms_key_id            = aws_kms_key.this["ebs"].arn
      delete_on_termination = true
    }
  }

  monitoring {
    enabled = true
  }

  tag_specifications {
    resource_type = "instance"
    tags          = merge(local.common_tags, { Name = "${local.name}-eks-node" })
  }
}

resource "aws_eks_node_group" "default" {
  cluster_name    = aws_eks_cluster.this.name
  node_group_name = "${local.name}-default"
  node_role_arn   = aws_iam_role.eks_node.arn
  subnet_ids      = aws_subnet.private[*].id
  instance_types  = var.node_instance_types
  ami_type        = "AL2023_x86_64_STANDARD"
  capacity_type   = "ON_DEMAND"

  scaling_config {
    desired_size = var.node_desired_size
    min_size     = 2
    max_size     = 6
  }

  update_config {
    max_unavailable = 1
  }

  launch_template {
    id      = aws_launch_template.nodes.id
    version = aws_launch_template.nodes.latest_version
  }

  depends_on = [aws_iam_role_policy_attachment.eks_node]
}

resource "aws_eks_addon" "this" {
  for_each = {
    "vpc-cni"                = aws_iam_role.vpc_cni.arn
    "coredns"                = null
    "kube-proxy"             = null
    "eks-pod-identity-agent" = null
  }

  cluster_name                = aws_eks_cluster.this.name
  addon_name                  = each.key
  service_account_role_arn    = each.value
  resolve_conflicts_on_update = "OVERWRITE"

  depends_on = [aws_eks_node_group.default]
}

# Grant cluster admin to an explicit IAM role via EKS access entries (no aws-auth ConfigMap).
resource "aws_eks_access_entry" "admin" {
  count = var.cluster_admin_role_arn == "" ? 0 : 1

  cluster_name  = aws_eks_cluster.this.name
  principal_arn = var.cluster_admin_role_arn
}

resource "aws_eks_access_policy_association" "admin" {
  count = var.cluster_admin_role_arn == "" ? 0 : 1

  cluster_name  = aws_eks_cluster.this.name
  principal_arn = var.cluster_admin_role_arn
  policy_arn    = "arn:${local.partition}:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"

  access_scope {
    type = "cluster"
  }
}
