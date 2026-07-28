provider "aws" {
  region = "us-east-1"
}

resource "aws_security_group" "vulnerable_sg" {
  name        = "vulnerable-web-server-sg"
  description = "A security group with SSH open to the world"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["YOUR_IP_ADDRESS/32"]  # Replace YOUR_IP_ADDRESS with your actual IP address
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/8"]  # Example: Allow egress to private IP range, adjust as necessary
  }

  tags = {
    Name = "vulnerable-sg"
  }
}

resource "aws_instance" "web_server" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"

  vpc_security_group_ids = [aws_security_group.vulnerable_sg.id]

  tags = {
    Name = "Vulnerable-Server"
  }
}