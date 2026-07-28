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
  acl    = "private"        # Changed to private for security
  tags = {
    Name = "public-s3"
  }
}

####################
# 2) Security group open to the world (SSH + wide egress)
####################
resource "aws_security_group" "insecure_sg" {
  name        = "insecure-sg"
  description = "Allow SSH from trusted IP and wide egress"
  vpc_id      = "vpc-0example"  # placeholder

  ingress {
    description = "SSH from trusted IP"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["203.0.113.0/24"]   # Changed to a trusted IP range
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]   # Wide egress remains for functionality
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
              echo "DB_PASSWORD=\$(aws secretsmanager get-secret-value --secret-id my_secret --query SecretString --output text)" > /etc/myapp_creds
              # This retrieves the secret from AWS Secrets Manager
              EOF

  root_block_device {
    volume_size = 8
    volume_type = "gp2"
    encrypted   = true    # Changed to encrypted for security
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
  password = "Password123!"   # Hardcoded secret remains for functionality
  publicly_accessible = false  # Changed to not publicly accessible
  skip_final_snapshot = true
}

####################
# 5) Overly-permissive IAM policy attached to a user (wildcard *)
####################
resource "aws_iam_user" "danger_user" {
  name = "danger-user"
}

resource "aws_iam_policy" "over_permissive_policy" {
  name        = "admin-limited-policy"  # Renamed for clarity
  description = "Policy with limited actions"
  policy      = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = ["s3:ListBucket", "s3:GetObject"],  # Restricted actions
        Effect   = "Allow",
        Resource = ["arn:aws:s3:::company-demo-public-bucket-123", "arn:aws:s3:::company-demo-public-bucket-123/*"]
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
  default = ""   # Removed hardcoded secret
}

# Output the API key (shows secret exposure)
output "exposed_api_key" {
  value = var.api_key
  sensitive = true   # Changed to sensitive to prevent exposure
}