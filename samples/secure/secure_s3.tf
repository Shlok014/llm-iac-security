########################################################
# Reporting data bucket, plus the access-log bucket it
# writes to.
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

########################################################
# Customer-managed encryption key
########################################################

resource "aws_kms_key" "reports" {
  description             = "Customer-managed key for the reporting data and log buckets"
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
        Sid       = "AllowS3ServiceUse"
        Effect    = "Allow"
        Principal = { Service = "s3.amazonaws.com" }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
        ]
        Resource = "*"
      },
    ]
  })

  tags = {
    Name        = "reporting-data"
    Environment = "prod"
  }
}

resource "aws_kms_alias" "reports" {
  name          = "alias/reporting-data"
  target_key_id = aws_kms_key.reports.key_id
}

########################################################
# Replication role. The destination buckets and their
# replica key live in eu-central-1 and are managed by the
# disaster-recovery stack, so they are referenced by ARN.
########################################################

locals {
  dr_reports_bucket_arn = "arn:aws:s3:::northwind-reporting-data-dr"
  dr_logs_bucket_arn    = "arn:aws:s3:::northwind-reporting-access-logs-dr"
  dr_kms_key_arn        = "arn:aws:kms:eu-central-1:111122223333:key/8b1f0c02-6b0f-4a3f-9a6d-2f5f1c0f7c11"
}

resource "aws_iam_role" "replication" {
  name = "northwind-reporting-s3-replication"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "s3.amazonaws.com" }
        Action    = "sts:AssumeRole"
      },
    ]
  })

  tags = {
    Name        = "reporting-s3-replication"
    Environment = "prod"
  }
}

resource "aws_iam_role_policy" "replication" {
  name = "northwind-reporting-s3-replication"
  role = aws_iam_role.replication.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadSourceBuckets"
        Effect = "Allow"
        Action = [
          "s3:GetReplicationConfiguration",
          "s3:ListBucket",
        ]
        Resource = [
          aws_s3_bucket.reports.arn,
          aws_s3_bucket.logs.arn,
        ]
      },
      {
        Sid    = "ReadSourceObjectVersions"
        Effect = "Allow"
        Action = [
          "s3:GetObjectVersionForReplication",
          "s3:GetObjectVersionAcl",
          "s3:GetObjectVersionTagging",
        ]
        Resource = [
          "${aws_s3_bucket.reports.arn}/*",
          "${aws_s3_bucket.logs.arn}/*",
        ]
      },
      {
        Sid    = "WriteReplicas"
        Effect = "Allow"
        Action = [
          "s3:ReplicateObject",
          "s3:ReplicateDelete",
          "s3:ReplicateTags",
        ]
        Resource = [
          "${local.dr_reports_bucket_arn}/*",
          "${local.dr_logs_bucket_arn}/*",
        ]
      },
      {
        Sid      = "DecryptSourceObjects"
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = [aws_kms_key.reports.arn]
      },
      {
        Sid    = "EncryptReplicas"
        Effect = "Allow"
        Action = [
          "kms:Encrypt",
          "kms:GenerateDataKey",
        ]
        Resource = [local.dr_kms_key_arn]
      },
    ]
  })
}

########################################################
# Access-log bucket
########################################################

resource "aws_s3_bucket" "logs" {
  bucket = "northwind-reporting-access-logs"

  tags = {
    Name        = "reporting-access-logs"
    Environment = "prod"
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket = aws_s3_bucket.logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.reports.arn
      sse_algorithm     = "aws:kms"
    }

    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_logging" "logs" {
  bucket = aws_s3_bucket.logs.id

  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "self-access-logs/"
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    id     = "abort-incomplete-multipart-uploads"
    status = "Enabled"

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  rule {
    id     = "expire-access-logs"
    status = "Enabled"

    filter {
      prefix = ""
    }

    expiration {
      days = 400
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

resource "aws_s3_bucket_notification" "logs" {
  bucket      = aws_s3_bucket.logs.id
  eventbridge = true
}

resource "aws_s3_bucket_replication_configuration" "logs" {
  depends_on = [aws_s3_bucket_versioning.logs]

  bucket = aws_s3_bucket.logs.id
  role   = aws_iam_role.replication.arn

  rule {
    id       = "replicate-access-logs-to-dr"
    status   = "Enabled"
    priority = 10

    filter {}

    delete_marker_replication {
      status = "Enabled"
    }

    source_selection_criteria {
      sse_kms_encrypted_objects {
        status = "Enabled"
      }
    }

    destination {
      bucket        = local.dr_logs_bucket_arn
      storage_class = "STANDARD_IA"

      encryption_configuration {
        replica_kms_key_id = local.dr_kms_key_arn
      }
    }
  }
}

resource "aws_s3_bucket_policy" "logs" {
  bucket = aws_s3_bucket.logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyUnencryptedTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.logs.arn,
          "${aws_s3_bucket.logs.arn}/*",
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      },
    ]
  })
}

########################################################
# Reporting data bucket
########################################################

resource "aws_s3_bucket" "reports" {
  bucket = "northwind-reporting-data"

  tags = {
    Name        = "reporting-data"
    Environment = "prod"
  }
}

resource "aws_s3_bucket_public_access_block" "reports" {
  bucket = aws_s3_bucket.reports.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "reports" {
  bucket = aws_s3_bucket.reports.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "reports" {
  bucket = aws_s3_bucket.reports.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.reports.arn
      sse_algorithm     = "aws:kms"
    }

    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_logging" "reports" {
  bucket = aws_s3_bucket.reports.id

  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "reporting-data/"
}

resource "aws_s3_bucket_lifecycle_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id

  rule {
    id     = "abort-incomplete-multipart-uploads"
    status = "Enabled"

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  rule {
    id     = "archive-then-expire"
    status = "Enabled"

    filter {
      prefix = ""
    }

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }

    expiration {
      days = 2555
    }

    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}

resource "aws_s3_bucket_notification" "reports" {
  bucket      = aws_s3_bucket.reports.id
  eventbridge = true
}

resource "aws_s3_bucket_replication_configuration" "reports" {
  depends_on = [aws_s3_bucket_versioning.reports]

  bucket = aws_s3_bucket.reports.id
  role   = aws_iam_role.replication.arn

  rule {
    id       = "replicate-reporting-data-to-dr"
    status   = "Enabled"
    priority = 10

    filter {}

    delete_marker_replication {
      status = "Enabled"
    }

    source_selection_criteria {
      sse_kms_encrypted_objects {
        status = "Enabled"
      }
    }

    destination {
      bucket        = local.dr_reports_bucket_arn
      storage_class = "STANDARD_IA"

      encryption_configuration {
        replica_kms_key_id = local.dr_kms_key_arn
      }
    }
  }
}

resource "aws_s3_bucket_policy" "reports" {
  bucket = aws_s3_bucket.reports.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyUnencryptedTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.reports.arn,
          "${aws_s3_bucket.reports.arn}/*",
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      },
    ]
  })
}
