########################################################
# vulnerable_network.tf
########################################################

resource "aws_vpc" "test_vpc" {
  cidr_block = "10.0.0.0/16"
  tags = {
    Name = "test-vpc"
  }
}

resource "aws_subnet" "test_subnet" {
  vpc_id            = aws_vpc.test_vpc.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-east-1a"
  map_public_ip_on_launch = false  # changed to prevent automatic public IP assignment
}

resource "aws_security_group" "open_http" {
  name        = "allow-http"
  description = "Allow HTTP from a specific IP range"
  vpc_id      = aws_vpc.test_vpc.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["192.0.2.0/24"]  # restricted to a specific IP range instead of '0.0.0.0/0'
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]  # consider restricting this further based on application needs
  }
}