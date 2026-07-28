########################################################
# Core VPC for the reporting platform: private subnets,
# flow logs, and the application security group.
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

locals {
  region   = "eu-west-1"
  vpc_cidr = "10.20.0.0/16"
}

########################################################
# VPC and subnets
########################################################

resource "aws_vpc" "core" {
  cidr_block           = local.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name        = "core"
    Environment = "prod"
  }
}

resource "aws_default_security_group" "core" {
  vpc_id = aws_vpc.core.id

  tags = {
    Name        = "core-default-deny-all"
    Environment = "prod"
  }
}

resource "aws_subnet" "private_a" {
  vpc_id                  = aws_vpc.core.id
  cidr_block              = "10.20.1.0/24"
  availability_zone       = "${local.region}a"
  map_public_ip_on_launch = false

  tags = {
    Name        = "core-private-a"
    Environment = "prod"
  }
}

resource "aws_subnet" "private_b" {
  vpc_id                  = aws_vpc.core.id
  cidr_block              = "10.20.2.0/24"
  availability_zone       = "${local.region}b"
  map_public_ip_on_launch = false

  tags = {
    Name        = "core-private-b"
    Environment = "prod"
  }
}

########################################################
# Flow logs
########################################################

resource "aws_kms_key" "flow_logs" {
  description             = "Customer-managed key for VPC flow log encryption"
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
        Principal = { Service = "logs.${local.region}.amazonaws.com" }
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
    Name        = "core-flow-logs"
    Environment = "prod"
  }
}

resource "aws_kms_alias" "flow_logs" {
  name          = "alias/core-flow-logs"
  target_key_id = aws_kms_key.flow_logs.key_id
}

resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/aws/vpc/core/flow-logs"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.flow_logs.arn

  tags = {
    Name        = "core-flow-logs"
    Environment = "prod"
  }
}

resource "aws_iam_role" "flow_logs" {
  name = "core-vpc-flow-logs"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "vpc-flow-logs.amazonaws.com" }
        Action    = "sts:AssumeRole"
      },
    ]
  })

  tags = {
    Name        = "core-vpc-flow-logs"
    Environment = "prod"
  }
}

resource "aws_iam_role_policy" "flow_logs" {
  name = "core-vpc-flow-logs"
  role = aws_iam_role.flow_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "WriteFlowLogsToOneLogGroup"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams",
        ]
        Resource = [
          aws_cloudwatch_log_group.flow_logs.arn,
          "${aws_cloudwatch_log_group.flow_logs.arn}:*",
        ]
      },
    ]
  })
}

resource "aws_flow_log" "core" {
  vpc_id                   = aws_vpc.core.id
  traffic_type             = "ALL"
  iam_role_arn             = aws_iam_role.flow_logs.arn
  log_destination_type     = "cloud-watch-logs"
  log_destination          = aws_cloudwatch_log_group.flow_logs.arn
  max_aggregation_interval = 60

  tags = {
    Name        = "core-flow-logs"
    Environment = "prod"
  }
}

########################################################
# Application security group
########################################################

resource "aws_security_group" "app" {
  name        = "core-app"
  description = "Reporting API: HTTPS from inside the VPC only"
  vpc_id      = aws_vpc.core.id

  tags = {
    Name        = "core-app"
    Environment = "prod"
  }
}

resource "aws_vpc_security_group_ingress_rule" "app_https_from_vpc" {
  security_group_id = aws_security_group.app.id
  description       = "HTTPS from workloads inside the VPC"

  cidr_ipv4   = local.vpc_cidr
  from_port   = 443
  ip_protocol = "tcp"
  to_port     = 443
}

resource "aws_vpc_security_group_egress_rule" "app_https_to_vpc" {
  security_group_id = aws_security_group.app.id
  description       = "HTTPS to the database and cache tiers inside the VPC"

  cidr_ipv4   = local.vpc_cidr
  from_port   = 443
  ip_protocol = "tcp"
  to_port     = 443
}

resource "aws_vpc_security_group_egress_rule" "app_postgres_to_data_subnet" {
  security_group_id = aws_security_group.app.id
  description       = "PostgreSQL to the data subnet"

  cidr_ipv4   = "10.20.2.0/24"
  from_port   = 5432
  ip_protocol = "tcp"
  to_port     = 5432
}

resource "aws_network_interface" "app" {
  subnet_id       = aws_subnet.private_a.id
  security_groups = [aws_security_group.app.id]
  description     = "Reporting API service ENI"

  tags = {
    Name        = "core-app"
    Environment = "prod"
  }
}

########################################################
# Network ACL
########################################################

resource "aws_network_acl" "private" {
  vpc_id     = aws_vpc.core.id
  subnet_ids = [aws_subnet.private_a.id, aws_subnet.private_b.id]

  ingress {
    rule_no    = 100
    action     = "allow"
    protocol   = "tcp"
    cidr_block = local.vpc_cidr
    from_port  = 443
    to_port    = 443
  }

  egress {
    rule_no    = 100
    action     = "allow"
    protocol   = "tcp"
    cidr_block = local.vpc_cidr
    from_port  = 1024
    to_port    = 65535
  }

  tags = {
    Name        = "core-private"
    Environment = "prod"
  }
}
