
provider "aws" {
  region = "us-east-1"
}

resource "aws_security_group" "vulnerable_sg" {
  name        = "vulnerable-web-server-sg"
  description = "A security group with SSH open to the world"

  ingress {
    from_port   = 22             # Port 22 is for SSH (Secure Shell)
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # This allows traffic from ANY IP address
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "vulnerable-sg"
  }
}

resource "aws_instance" "web_server" {
  ami           = "ami-0c55b159cbfafe1f0" # Example: Amazon Linux 2 AMI
  instance_type = "t2.micro"
  
  vpc_security_group_ids = [aws_security_group.vulnerable_sg.id]

  tags = {
    Name = "Vulnerable-Server"
  }
}