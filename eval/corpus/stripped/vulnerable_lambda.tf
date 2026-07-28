


resource "aws_iam_role" "order_worker" {
  name = "order-worker-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}



resource "aws_iam_role_policy" "order_worker_runtime" {
  name = "order-worker-runtime"
  role = aws_iam_role.order_worker.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:*", "dynamodb:*", "secretsmanager:*", "logs:*"]
      Resource = "*"
    }]
  })
}

resource "aws_lambda_function" "order_processor" {
  function_name = "order-processor"
  role          = aws_iam_role.order_worker.arn
  handler       = "app.handler"
  runtime       = "python3.9"
  filename      = "build/order-processor.zip"
  memory_size   = 512
  timeout       = 30

  environment {
    variables = {
      STRIPE_SECRET_KEY = "sk_live_FAKE_PLACEHOLDER_00000000"
      DB_PASSWORD       = "Password123!"
      ORDERS_TABLE      = aws_dynamodb_table.orders.name
      LOG_LEVEL         = "INFO"
    }
  }

  tags = {
    Service = "orders"
    Tier    = "prod"
  }
}


resource "aws_lambda_function_url" "checkout_callback" {
  function_name      = aws_lambda_function.order_processor.function_name
  authorization_type = "NONE"

  cors {
    allow_origins = ["*"]
    allow_methods = ["*"]
  }
}

resource "aws_lambda_permission" "storefront_invoke" {
  statement_id  = "AllowStorefrontInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.order_processor.function_name
  principal     = "*"
}

resource "aws_dynamodb_table" "orders" {
  name         = "orders-prod"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "order_id"

  attribute {
    name = "order_id"
    type = "S"
  }

  point_in_time_recovery {
    enabled = false
  }

  tags = {
    Service = "orders"
  }
}
