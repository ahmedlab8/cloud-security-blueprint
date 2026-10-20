# Customer-managed KMS keys, one per data domain, with automatic rotation.
# Separate keys limit blast radius and allow per-domain key policies (NIST SC-12, SC-28).

data "aws_iam_policy_document" "kms_base" {
  #checkov:skip=CKV_AWS_109:Root principal statement is required by AWS so the key never becomes unmanageable; access is still governed by IAM.
  #checkov:skip=CKV_AWS_111:Same as above - the account root statement is the AWS-documented default key policy.
  #checkov:skip=CKV_AWS_356:KMS key policies must use "*" as resource (it refers to the key itself).
  statement {
    sid       = "EnableRootAccountAdministration"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
  }

  statement {
    sid    = "AllowCloudWatchLogs"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:Describe*",
    ]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["logs.${var.region}.amazonaws.com"]
    }

    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:${local.partition}:logs:${var.region}:${local.account_id}:*"]
    }
  }
}

resource "aws_kms_key" "this" {
  for_each = toset(["eks", "s3", "logs", "ebs"])

  description             = "${local.name} ${each.key} encryption key"
  enable_key_rotation     = true
  rotation_period_in_days = 90
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.kms_base.json

  tags = {
    Name    = "${local.name}-${each.key}"
    Purpose = each.key
  }
}

resource "aws_kms_alias" "this" {
  for_each = aws_kms_key.this

  name          = "alias/${local.name}-${each.key}"
  target_key_id = each.value.key_id
}
