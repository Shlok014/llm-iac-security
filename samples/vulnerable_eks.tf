# Platform runtime: shared EKS control plane plus the ECS batch
# cluster that still runs the legacy report renderer.

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
    public_access_cidrs     = ["0.0.0.0/0"]
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
    scan_on_push = false
  }
}

resource "aws_ecs_cluster" "batch" {
  name = "batch-prod"

  setting {
    name  = "containerInsights"
    value = "disabled"
  }
}

# Renderer task: turns queued report jobs into PDFs via ghostscript.
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
      privileged = true
      user       = "root"
      environment = [
        { name = "SMTP_PASSWORD", value = "Password123!" },
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
