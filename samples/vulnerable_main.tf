############################################################
# vulnerable_main.tf
# Purpose: intentionally insecure Terraform for testing
############################################################

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
  required_version = ">= 1.0"
}

provider "aws" {
  region = "us-east-1"
}

####################
# 1) Public S3 bucket (public-read ACL + public policy)
####################
resource "aws_s3_bucket" "public_bucket" {
  bucket = "company-demo-public-bucket-123"
  acl    = "public-read"        # <- public-read is insecure
  tags = {
    Name = "public-s3"
  }
}

resource "aws_s3_bucket_policy" "public_policy" {
  bucket = aws_s3_bucket.public_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowPublicRead"
        Effect    = "Allow"
        Principal = "*"
        Action    = ["s3:GetObject"]
        Resource  = ["${aws_s3_bucket.public_bucket.arn}/*"]
      }
    ]
  })
}

####################
# 2) Security group open to the world (SSH + wide egress)
####################
resource "aws_security_group" "insecure_sg" {
  name        = "insecure-sg"
  description = "Allow SSH from anywhere and wide egress"
  vpc_id      = "vpc-0example"  # placeholder

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]   # <- insecure: SSH open to world
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]   # <- wide egress allowed (noticeable risk)
  }
}

####################
# 3) EC2 Instance with user_data that includes a hardcoded secret
#    and unencrypted root block device
####################
resource "aws_instance" "bad_instance" {
  ami           = "ami-0abcdef1234567890"  # placeholder AMI (maybe outdated)
  instance_type = "t2.micro"
  subnet_id     = "subnet-0example"
  vpc_security_group_ids = [aws_security_group.insecure_sg.id]

  user_data = <<-EOF
              #!/bin/bash
              echo "DB_PASSWORD=SuperInsecurePassword123!" > /etc/myapp_creds
              # This writes a plaintext secret file inside the instance
              EOF

  root_block_device {
    volume_size = 8
    volume_type = "gp2"
    encrypted   = false    # <- unencrypted root volume
  }

  tags = {
    Name = "insecure-ec2"
  }
}

####################
# 4) RDS instance publicly accessible with hardcoded credentials
####################
resource "aws_db_instance" "bad_rds" {
  identifier = "insecure-rds-instance"
  engine     = "mysql"
  instance_class = "db.t3.micro"
  allocated_storage = 20
  username = "admin"
  password = "Password123!"   # <- hardcoded secret
  publicly_accessible = true  # <- RDS publicly accessible (dangerous)
  skip_final_snapshot = true
}

####################
# 5) Overly-permissive IAM policy attached to a user (wildcard *)
####################
resource "aws_iam_user" "danger_user" {
  name = "danger-user"
}

resource "aws_iam_policy" "over_permissive_policy" {
  name        = "admin-all-policy"
  description = "Policy with * actions (insecure)"
  policy      = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = ["*"],
        Effect   = "Allow",
        Resource = ["*"]
      }
    ]
  })
}

resource "aws_iam_user_policy_attachment" "attach_danger" {
  user       = aws_iam_user.danger_user.name
  policy_arn = aws_iam_policy.over_permissive_policy.arn
}

####################
# 6) Hardcoded sensitive data via Terraform variables (bad example)
####################
variable "api_key" {
  type    = string
  default = "AKIA_FAKE_KEY_DO_NOT_USE"   # <- secret in code (bad)
}

# Output the API key (shows secret exposure)
output "exposed_api_key" {
  value = var.api_key
  sensitive = false   # intentionally exposed; insecure
}