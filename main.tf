terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "eu-central-1"
}

# -----------------------------------------------------------------------------
# VARIABLES - Define your students and their passwords here
# -----------------------------------------------------------------------------
variable "students" {
  description = "A map of student fruits to their passwords. The fruit name MUST be capitalized."
  type        = map(string)
  default = {
    "Apple" = "insecure_password_123"
    "Grape" = "another_bad_pass_456"
    "Berry" = "super_secret_789"
  }
}

locals {
  aws_account_id = data.aws_caller_identity.current.account_id
}

data "aws_caller_identity" "current" {}


# -----------------------------------------------------------------------------
# STUDENT IAM ROLES AND POLICIES
# -----------------------------------------------------------------------------

resource "aws_iam_policy" "student_terraform_policy" {
  for_each = var.students
  name     = "Student-${each.key}-TerraformPolicy"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "AllowTerraformToManageStudentResources",
        Effect = "Allow",
        Action = [
          "apigateway:*", "lambda:*", "s3:*", "iam:PassRole",
          "iam:CreateRole", "iam:PutRolePolicy", "iam:GetRole",
          "iam:DeleteRole", "iam:DeleteRolePolicy", "iam:TagRole"
        ],
        Resource = [
          "arn:aws:apigateway:eu-central-1::/restapis/*",
          "arn:aws:lambda:eu-central-1:${local.aws_account_id}:function:student-${lower(each.key)}-*",
          "arn:aws:s3:::student-${lower(each.key)}-*",
          "arn:aws:iam::${local.aws_account_id}:role/student-${lower(each.key)}-*"
        ]
      },
      {
        Sid    = "AllowProwlerToDiscoverS3Buckets",
        Effect = "Allow",
        Action = "s3:ListAllMyBuckets",
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role" "student_role" {
  for_each           = var.students
  name               = "StudentRole-${each.key}"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = {
        AWS = aws_iam_role.credential_dispenser_lambda_role.arn
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "student_policy_attachment" {
  for_each   = var.students
  role       = aws_iam_role.student_role[each.key].name
  policy_arn = aws_iam_policy.student_terraform_policy[each.key].arn
}


# -----------------------------------------------------------------------------
# VULNERABLE S3 BUCKET
# -----------------------------------------------------------------------------
resource "aws_s3_bucket" "vulnerable_bucket" {
  bucket = "company-legacy-data-${local.aws_account_id}"
}

resource "aws_s3_bucket_ownership_controls" "vulnerable_bucket_ownership" {
  bucket = aws_s3_bucket.vulnerable_bucket.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_policy" "vulnerable_bucket_policy" {
  bucket = aws_s3_bucket.vulnerable_bucket.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = { AWS = "arn:aws:iam::${local.aws_account_id}:root" },
      Action    = ["s3:GetObject", "s3:ListBucket"],
      Resource = [
        aws_s3_bucket.vulnerable_bucket.arn,
        "${aws_s3_bucket.vulnerable_bucket.arn}/*"
      ]
    }]
  })
}

resource "aws_s3_object" "secret_file" {
  bucket       = aws_s3_bucket.vulnerable_bucket.id
  key          = "confidential-financials.txt"
  content      = "Q3 Profits: $5 Million. Q4 Projections: $7 Million."
  content_type = "text/plain"
}


# -----------------------------------------------------------------------------
# CREDENTIAL DISPENSER LAMBDA & API GATEWAY
# -----------------------------------------------------------------------------

resource "aws_iam_role" "credential_dispenser_lambda_role" {
  name = "CredentialDispenserLambdaRole"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_policy" "credential_dispenser_lambda_policy" {
  name   = "CredentialDispenserLambdaPolicy"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow",
        Action   = "sts:AssumeRole",
        Resource = "arn:aws:iam::${local.aws_account_id}:role/StudentRole-*"
      },
      {
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        Effect   = "Allow",
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "credential_dispenser_attachment" {
  role       = aws_iam_role.credential_dispenser_lambda_role.name
  policy_arn = aws_iam_policy.credential_dispenser_lambda_policy.arn
}

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/src/credential_dispenser.py"
  output_path = "${path.module}/dist/credential_dispenser.zip"
}

resource "aws_lambda_function" "credential_dispenser" {
  function_name    = "credential-dispenser"
  role             = aws_iam_role.credential_dispenser_lambda_role.arn
  handler          = "credential_dispenser.lambda_handler"
  runtime          = "python3.11"
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      STUDENT_PASSWORDS_JSON = jsonencode(var.students)
    }
  }
}

resource "aws_apigatewayv2_api" "dispenser_api" {
  name          = "StudentCredentialDispenserAPI"
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.dispenser_api.id
  name        = "$default"
  auto_deploy = true
}

resource "aws_apigatewayv2_integration" "lambda_integration" {
  api_id           = aws_apigatewayv2_api.dispenser_api.id
  integration_type = "AWS_PROXY"
  integration_uri  = aws_lambda_function.credential_dispenser.invoke_arn
}

resource "aws_apigatewayv2_route" "get_credentials" {
  api_id    = aws_apigatewayv2_api.dispenser_api.id
  route_key = "GET /{fruit}"
  target    = "integrations/${aws_apigatewayv2_integration.lambda_integration.id}"
}

resource "aws_lambda_permission" "api_gateway_invoke" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.credential_dispenser.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.dispenser_api.execution_arn}/*/*"
}

# -----------------------------------------------------------------------------
# OUTPUTS
# -----------------------------------------------------------------------------
output "api_invoke_url" {
  description = "The invoke URL for the credential dispenser API."
  value       = aws_apigatewayv2_api.dispenser_api.api_endpoint
}