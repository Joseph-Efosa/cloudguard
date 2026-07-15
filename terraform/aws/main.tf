################################################################################
# CloudGuard — AWS Test Environment
# Provisions compliant resources; the misconfigured variant is toggled via
# the `misconfigured` variable (true = introduce GDPR violations).
################################################################################

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  default = "eu-west-1"
}

variable "misconfigured" {
  description = "Set to true to introduce deliberate GDPR violations for evaluation."
  type        = bool
  default     = false
}

variable "prefix" {
  default = "cloudguard-test"
}

################################################################################
# C-01 / C-02 / C-08 — S3 bucket
################################################################################

resource "aws_s3_bucket" "test" {
  bucket        = "${var.prefix}-bucket-${random_id.suffix.hex}"
  force_destroy = true
}

resource "random_id" "suffix" {
  byte_length = 4
}

# C-01: SSE encryption (disabled when misconfigured)
resource "aws_s3_bucket_server_side_encryption_configuration" "test" {
  count  = var.misconfigured ? 0 : 1
  bucket = aws_s3_bucket.test.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

# C-02: Block public access (all 4 flags off when misconfigured)
resource "aws_s3_bucket_public_access_block" "test" {
  bucket                  = aws_s3_bucket.test.id
  block_public_acls       = !var.misconfigured
  ignore_public_acls      = !var.misconfigured
  block_public_policy     = !var.misconfigured
  restrict_public_buckets = !var.misconfigured
}

# C-08: Versioning (disabled when misconfigured)
resource "aws_s3_bucket_versioning" "test" {
  bucket = aws_s3_bucket.test.id
  versioning_configuration {
    status = var.misconfigured ? "Suspended" : "Enabled"
  }
}

################################################################################
# C-03 / C-04 — CloudTrail
################################################################################

resource "aws_s3_bucket" "trail" {
  bucket        = "${var.prefix}-trail-${random_id.suffix.hex}"
  force_destroy = true
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.trail.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.trail.arn}/AWSLogs/*"
        Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" } }
      }
    ]
  })
}

resource "aws_cloudtrail" "test" {
  name                          = "${var.prefix}-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  is_multi_region_trail         = !var.misconfigured  # C-03
  enable_log_file_validation    = !var.misconfigured  # C-04
  include_global_service_events = true
  depends_on                    = [aws_s3_bucket_policy.trail]
}

################################################################################
# C-05 — RDS instance (db.t3.micro, no personal data)
################################################################################

resource "aws_db_instance" "test" {
  identifier          = "${var.prefix}-rds"
  engine              = "mysql"
  engine_version      = "8.0"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  db_name             = "testdb"
  username            = "admin"
  password            = "CloudGuard2026!"   # synthetic test env only
  skip_final_snapshot = true
  storage_encrypted   = !var.misconfigured   # C-05
  depends_on          = []
}

################################################################################
# C-06 — KMS CMK with/without rotation
################################################################################

resource "aws_kms_key" "test" {
  description             = "CloudGuard test CMK"
  deletion_window_in_days = 7
  enable_key_rotation     = !var.misconfigured  # C-06
}

################################################################################
# C-09 — EBS default encryption (account-level)
################################################################################

resource "aws_ebs_encryption_by_default" "test" {
  enabled = !var.misconfigured
}

################################################################################
# C-10 — AWS Config recorder
################################################################################

resource "aws_config_configuration_recorder" "test" {
  name     = "${var.prefix}-recorder"
  role_arn = aws_iam_role.config.arn
  recording_group {
    all_supported = true
  }
}

resource "aws_iam_role" "config" {
  name = "${var.prefix}-config-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "config" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_s3_bucket" "config" {
  bucket        = "${var.prefix}-config-${random_id.suffix.hex}"
  force_destroy = true
}

resource "aws_s3_bucket_versioning" "config" {
  bucket = aws_s3_bucket.config.id
  versioning_configuration {
    status = var.misconfigured ? "Suspended" : "Enabled"
  }
}

resource "aws_s3_bucket_versioning" "trail" {
  bucket = aws_s3_bucket.trail.id
  versioning_configuration {
    status = var.misconfigured ? "Suspended" : "Enabled"
  }
}

# Config service needs explicit permission to write to this bucket
resource "aws_s3_bucket_policy" "config" {
  bucket = aws_s3_bucket.config.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSConfigBucketPermissionsCheck"
        Effect = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.config.arn
      },
      {
        Sid    = "AWSConfigBucketDelivery"
        Effect = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.config.arn}/AWSLogs/*/Config/*"
        Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" } }
      }
    ]
  })
}

resource "aws_config_delivery_channel" "test" {
  name           = "${var.prefix}-channel"
  s3_bucket_name = aws_s3_bucket.config.bucket
  depends_on     = [aws_config_configuration_recorder.test, aws_s3_bucket_policy.config]
}

resource "aws_config_configuration_recorder_status" "test" {
  name       = aws_config_configuration_recorder.test.name
  is_enabled = !var.misconfigured   # C-10
  depends_on = [aws_config_delivery_channel.test]
}

################################################################################
# Outputs
################################################################################

output "s3_bucket_name" { value = aws_s3_bucket.test.bucket }
output "cloudtrail_name" { value = aws_cloudtrail.test.name }
output "rds_identifier"  { value = aws_db_instance.test.identifier }
output "kms_key_id"      { value = aws_kms_key.test.key_id }
output "misconfigured"   { value = var.misconfigured }
