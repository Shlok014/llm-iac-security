resource "aws_api_gateway_rest_api" "notifications" {
  name = "notifications-api"
}

resource "aws_api_gateway_resource" "events" {
  rest_api_id = aws_api_gateway_rest_api.notifications.id
  parent_id   = aws_api_gateway_rest_api.notifications.root_resource_id
  path_part   = "events"
}

resource "aws_api_gateway_method" "post_event" {
  rest_api_id      = aws_api_gateway_rest_api.notifications.id
  resource_id      = aws_api_gateway_resource.events.id
  http_method      = "POST"
  authorization    = "AWS_IAM"  # Updated to restrict access
  api_key_required = false
}

resource "aws_api_gateway_deployment" "notifications" {
  rest_api_id = aws_api_gateway_rest_api.notifications.id
  depends_on  = [aws_api_gateway_method.post_event]
}

resource "aws_api_gateway_stage" "prod" {
  stage_name            = "prod"
  rest_api_id           = aws_api_gateway_rest_api.notifications.id
  deployment_id         = aws_api_gateway_deployment.notifications.id
  xray_tracing_enabled  = false
  cache_cluster_enabled = true
  cache_cluster_size    = "0.5"

  tags = {
    Service = "notifications"
  }
}

resource "aws_api_gateway_method_settings" "prod_all" {
  rest_api_id = aws_api_gateway_rest_api.notifications.id
  stage_name  = aws_api_gateway_stage.prod.stage_name
  method_path = "*/*"

  settings {
    metrics_enabled      = true
    logging_level        = "ERROR"
    cache_data_encrypted = true  # Updated to ensure cached data is encrypted
  }
}

resource "aws_sns_topic" "delivery_events" {
  name = "delivery-events"
}

resource "aws_sns_topic_policy" "delivery_events" {
  arn = aws_sns_topic.delivery_events.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowSubscribe"
      Effect    = "Allow"
      Principal = {
        "AWS": [
          "arn:aws:iam::123456789012:role/YourSpecificRole"  # Restrict to specific role
        ]
      }
      Action    = ["SNS:Subscribe", "SNS:Receive", "SNS:Publish"]
      Resource  = aws_sns_topic.delivery_events.arn
    }]
  })
}

resource "aws_sqs_queue" "delivery_retry" {
  name                       = "delivery-retry"
  visibility_timeout_seconds = 60
}

resource "aws_sqs_queue_policy" "delivery_retry" {
  queue_url = aws_sqs_queue.delivery_retry.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = {
        "AWS": [
          "arn:aws:iam::123456789012:role/YourSpecificRole"  # Restrict to specific role
        ]
      }
      Action    = [
        "sqs:SendMessage",  # Limit to necessary permissions
        "sqs:ReceiveMessage",
        "sqs:DeleteMessage"
      ]
      Resource  = aws_sqs_queue.delivery_retry.arn
    }]
  })
}