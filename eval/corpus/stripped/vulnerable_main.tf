




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
  acl    = "public-read"
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




resource "aws_security_group" "insecure_sg" {
  name        = "insecure-sg"
  description = "Allow SSH from anywhere and wide egress"
  vpc_id      = "vpc-0example"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}





resource "aws_instance" "bad_instance" {
  ami           = "ami-0abcdef1234567890"
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
    encrypted   = false
  }

  tags = {
    Name = "insecure-ec2"
  }
}




resource "aws_db_instance" "bad_rds" {
  identifier = "insecure-rds-instance"
  engine     = "mysql"
  instance_class = "db.t3.micro"
  allocated_storage = 20
  username = "admin"
  password = "Password123!"
  publicly_accessible = true
  skip_final_snapshot = true
}




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




variable "api_key" {
  type    = string
  default = "AKIA_FAKE_KEY_DO_NOT_USE"
}


output "exposed_api_key" {
  value = var.api_key
  sensitive = false
}