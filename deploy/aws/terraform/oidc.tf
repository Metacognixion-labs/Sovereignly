# ─────────────────────────────────────────────────────────────────────────────
# GitHub Actions OIDC — Keyless AWS authentication
#
# No AWS access keys stored in GitHub. Actions assume a role via OIDC.
# Set AWS_DEPLOY_ROLE_ARN secret in GitHub to the role ARN output below.
# ─────────────────────────────────────────────────────────────────────────────

data "aws_iam_openid_connect_provider" "github" {
  count = var.github_org != "" ? 0 : 0  # Set to [1] after manual OIDC provider creation
  url   = "https://token.actions.githubusercontent.com"
}

variable "github_org" {
  description = "GitHub org/user for OIDC (e.g., Metacognixion-labs)"
  type        = string
  default     = ""
}

variable "github_repo" {
  description = "GitHub repo name (e.g., Sovereignly)"
  type        = string
  default     = ""
}

# OIDC Identity Provider (create once per AWS account)
resource "aws_iam_openid_connect_provider" "github" {
  count           = var.github_org != "" ? 1 : 0
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]

  tags = { Name = "github-actions" }
}

# Deploy role — GitHub Actions assumes this
resource "aws_iam_role" "github_deploy" {
  count = var.github_org != "" ? 1 : 0
  name  = "${local.name}-github-deploy"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = aws_iam_openid_connect_provider.github[0].arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        }
        StringLike = {
          "token.actions.githubusercontent.com:sub" = "repo:${var.github_org}/${var.github_repo}:*"
        }
      }
    }]
  })

  tags = { Name = "${local.name}-github-deploy" }
}

# Permissions for CI/CD: ECR push, ECS deploy, CloudFront invalidation
resource "aws_iam_role_policy" "github_deploy" {
  count = var.github_org != "" ? 1 : 0
  name  = "${local.name}-deploy-policy"
  role  = aws_iam_role.github_deploy[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:PutImage",
          "ecr:InitiateLayerUpload",
          "ecr:UploadLayerPart",
          "ecr:CompleteLayerUpload"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ecs:DescribeTaskDefinition",
          "ecs:RegisterTaskDefinition",
          "ecs:UpdateService",
          "ecs:DescribeServices",
          "ecs:ListTasks",
          "ecs:DescribeTasks"
        ]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = "iam:PassRole"
        Resource = [
          aws_iam_role.ecs_execution.arn,
          aws_iam_role.ecs_task.arn
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "cloudfront:CreateInvalidation",
          "cloudfront:ListDistributions"
        ]
        Resource = "*"
      }
    ]
  })
}

output "github_deploy_role_arn" {
  description = "Set this as AWS_DEPLOY_ROLE_ARN in GitHub repo secrets"
  value       = var.github_org != "" ? aws_iam_role.github_deploy[0].arn : "Set github_org and github_repo variables first"
}
