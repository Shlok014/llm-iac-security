########################################################
# Log encryption key and application log group for the
# reporting service.
########################################################

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60"
    }
  }
}

resource "aws_kms_key" "logs" {
  description             = "Customer-managed key for reporting-api log encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowAccountAdministration"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::111122223333:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowCloudWatchLogsUse"
        Effect    = "Allow"
        Principal = { Service = "logs.eu-west-1.amazonaws.com" }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:Describe*",
        ]
        Resource = "*"
      },
    ]
  })

  tags = {
    Name        = "reporting-api-logs"
    Environment = "prod"
  }
}

resource "aws_kms_alias" "logs" {
  name          = "alias/reporting-api-logs"
  target_key_id = aws_kms_key.logs.key_id
}

resource "aws_cloudwatch_log_group" "app" {
  name              = "/northwind/reporting-api"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.logs.arn

  tags = {
    Name        = "reporting-api"
    Environment = "prod"
  }
}
