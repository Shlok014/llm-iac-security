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

resource "aws_s3_bucket" "public_bucket" {
  bucket = "company-demo-public-bucket-123"
  acl    = "private"
  tags = {
    Name = "public-s3"
  }
}

resource "aws_security_group" "insecure_sg" {
  name        = "insecure-sg"
  description = "Allow SSH from specific IP and wide egress"
  vpc_id      = "vpc-0example"

  ingress {
    description = "SSH from specific IP"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["YOUR_IP_ADDRESS/32"]  # Replace with your specific IP address
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "bad_instance" {
  ami                    = "ami-0abcdef1234567890"
  instance_type         = "t2.micro"
  subnet_id             = "subnet-0example"
  vpc_security_group_ids = [aws_security_group.insecure_sg.id]

  user_data = <<-EOF
              #!/bin/bash
              echo "DB_PASSWORD=\$(aws secretsmanager get-secret-value --secret-id myapp/DB_PASSWORD --query SecretString --output text)" > /etc/myapp_creds
              # This retrieves the secret from AWS Secrets Manager
              EOF

  root_block_device {
    volume_size = 8
    volume_type = "gp2"
    encrypted   = true
  }

  tags = {
    Name = "insecure-ec2"
  }
}

resource "aws_db_instance" "bad_rds" {
  identifier         = "insecure-rds-instance"
  engine             = "mysql"
  instance_class     = "db.t3.micro"
  allocated_storage   = 20
  username           = "admin"
  password           = "Password123!"
  publicly_accessible = false
  skip_final_snapshot = true
}

resource "aws_iam_user" "danger_user" {
  name = "danger-user"
}

resource "aws_iam_policy" "over_permissive_policy" {
  name        = "admin-limited-policy"
  description = "Policy with limited actions"
  policy      = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = ["s3:ListBucket", "s3:GetObject"],  # Limit actions to necessary ones
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

variable "api_key" {
  type = string
  default = ""  # Remove hardcoded API key
}

output "exposed_api_key" {
  value     = var.api_key
  sensitive = true  # Mark as sensitive to prevent exposure
}