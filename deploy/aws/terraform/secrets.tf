# ─────────────────────────────────────────────────────────────────────────────
# Secrets Manager — Application secrets
#
# Each secret costs $0.40/mo + $0.05/10K API calls.
# Bundled as a single JSON secret to minimize cost.
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_secretsmanager_secret" "app" {
  name                    = "sovereignly/${var.environment}/app"
  description             = "Sovereignly application secrets"
  recovery_window_in_days = var.environment == "prod" ? 30 : 0

  tags = { Name = "${local.name}-secrets" }
}

# Placeholder — populate via CLI before first deploy:
#   aws secretsmanager put-secret-value --secret-id sovereignly/prod/app \
#     --secret-string '{"SOVEREIGN_SERVER_KEY":"...","JWT_SECRET":"...","ADMIN_TOKEN":"..."}'
resource "aws_secretsmanager_secret_version" "app_initial" {
  secret_id = aws_secretsmanager_secret.app.id
  secret_string = jsonencode({
    SOVEREIGN_SERVER_KEY = "CHANGE_ME"
    JWT_SECRET           = "CHANGE_ME"
    ADMIN_TOKEN          = "CHANGE_ME"
  })

  lifecycle {
    ignore_changes = [secret_string] # Managed via CLI after creation
  }
}

# Individual secret references for ECS task definition
# Use these ARNs in var.secret_arns or reference directly
output "secret_arn" {
  value       = aws_secretsmanager_secret.app.arn
  description = "Secrets Manager ARN for app secrets"
}
