





resource "aws_kms_key" "billing_exports" {
  description             = "CMK for nightly billing exports"
  deletion_window_in_days = 7
  enable_key_rotation     = false

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowAccountUse"
        Effect    = "Allow"
        Principal = "*"
        Action    = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey*"]
        Resource  = "*"
      }
    ]
  })

  tags = {
    Team = "finance-platform"
  }
}

resource "aws_kms_alias" "billing_exports" {
  name          = "alias/billing-exports"
  target_key_id = aws_kms_key.billing_exports.key_id
}


resource "aws_s3_bucket" "audit_trail" {
  bucket = "acme-audit-trail-prod"

  tags = {
    Purpose = "cloudtrail"
  }
}

resource "aws_cloudtrail" "account_activity" {
  name                          = "account-activity"
  s3_bucket_name                = aws_s3_bucket.audit_trail.id
  s3_key_prefix                 = "prod"
  include_global_service_events = false
  is_multi_region_trail         = false
  enable_log_file_validation    = false

  tags = {
    Team = "security"
  }
}


resource "aws_cloudwatch_log_group" "api_access" {
  name = "/acme/api/access"

  tags = {
    Service = "api"
  }
}

resource "aws_cloudwatch_log_group" "worker_events" {
  name              = "/acme/worker/events"
  retention_in_days = 0

  tags = {
    Service = "worker"
  }
}


resource "aws_ebs_volume" "billing_scratch" {
  availability_zone = "us-east-1a"
  size              = 100
  type              = "gp3"
  encrypted         = false

  tags = {
    Team = "finance-platform"
  }
}

resource "aws_config_configuration_recorder" "account" {
  name     = "account-recorder"
  role_arn = "arn:aws:iam::123456789012:role/config-recorder"

  recording_group {
    all_supported                 = false
    include_global_resource_types = false
    resource_types                = ["AWS::EC2::Instance"]
  }
}
