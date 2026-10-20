# Access-log sink + application data bucket, both built from the hardened module.

module "s3_access_logs" {
  source = "./modules/secure-s3-bucket"

  bucket_name       = "${local.name}-access-logs-${local.account_id}"
  kms_key_arn       = aws_kms_key.this["s3"].arn
  access_log_prefix = "s3/self/" # the log sink audits access to itself
  is_log_sink       = true
}

module "s3_app_data" {
  source = "./modules/secure-s3-bucket"

  bucket_name       = "${local.name}-app-data-${local.account_id}"
  kms_key_arn       = aws_kms_key.this["s3"].arn
  access_log_bucket = module.s3_access_logs.id
  access_log_prefix = "s3/app-data/"
}
