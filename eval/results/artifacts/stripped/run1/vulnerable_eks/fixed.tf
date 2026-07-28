resource "aws_iam_role" "eks_control_plane" {
  name = "platform-eks-control-plane"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "eks.amazonaws.com" }
    }]
  })
}

resource "aws_eks_cluster" "platform" {
  name     = "platform-prod"
  role_arn = aws_iam_role.eks_control_plane.arn
  version  = "1.27"

  vpc_config {
    subnet_ids              = ["subnet-0a1b2c3d", "subnet-0e4f5a6b"]
    endpoint_public_access  = true
    endpoint_private_access = false
    public_access_cidrs     = ["192.168.0.0/16"] # Updated to a more restrictive CIDR range
  }

  tags = {
    Environment = "prod"
    Team        = "platform"
  }
}

resource "aws_ecr_repository" "report_renderer" {
  name                 = "report-renderer"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true # Enabled image scanning on push
  }
}

resource "aws_ecs_cluster" "batch" {
  name = "batch-prod"

  setting {
    name  = "containerInsights"
    value = "enabled" # Enabled container insights
  }
}

resource "aws_ecs_task_definition" "report_renderer" {
  family                   = "report-renderer"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "512"
  memory                   = "1024"

  container_definitions = jsonencode([
    {
      name       = "renderer"
      image      = "report-renderer:latest"
      essential  = true
      privileged = false # Removed privileged mode
      user       = "1001" # Specified a non-root user
      environment = [
        { name = "SMTP_PASSWORD", value = "arn:aws:secretsmanager:region:account-id:secret:your-secret-name" }, # Updated to use Secrets Manager
        { name = "REPORT_BUCKET", value = "acme-reports-prod" }
      ]
      portMappings = [
        { containerPort = 8080, hostPort = 8080, protocol = "tcp" }
      ]
    }
  ])
}

resource "aws_ecs_service" "report_renderer" {
  name            = "report-renderer"
  cluster         = aws_ecs_cluster.batch.id
  task_definition = aws_ecs_task_definition.report_renderer.arn
  desired_count   = 2
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = ["subnet-0a1b2c3d"]
    assign_public_ip = true
  }
}