# ─────────────────────────────────────────────────────────────────────────────
# Outputs
# ─────────────────────────────────────────────────────────────────────────────

output "alb_dns_name" {
  description = "ALB DNS name (use if no custom domain)"
  value       = aws_lb.main.dns_name
}

output "cloudfront_domain" {
  description = "CloudFront distribution domain"
  value       = aws_cloudfront_distribution.main.domain_name
}

output "cloudfront_distribution_id" {
  description = "CloudFront distribution ID (for cache invalidation)"
  value       = aws_cloudfront_distribution.main.id
}

output "ecr_repository_url" {
  description = "ECR repository URL for docker push"
  value       = aws_ecr_repository.app.repository_url
}

output "ecs_cluster_name" {
  description = "ECS cluster name"
  value       = aws_ecs_cluster.main.name
}

output "ecs_service_name" {
  description = "ECS service name"
  value       = aws_ecs_service.app.name
}

output "s3_backup_bucket" {
  description = "S3 bucket for Litestream backups"
  value       = aws_s3_bucket.litestream.id
}

output "efs_file_system_id" {
  description = "EFS file system ID"
  value       = aws_efs_file_system.data.id
}

output "app_url" {
  description = "Application URL"
  value       = var.domain_name != "" ? "https://${var.domain_name}" : "https://${aws_cloudfront_distribution.main.domain_name}"
}

output "acm_validation_records" {
  description = "DNS records to add for ACM certificate validation"
  value = var.domain_name != "" ? {
    for opt in aws_acm_certificate.main[0].domain_validation_options : opt.domain_name => {
      type  = opt.resource_record_type
      name  = opt.resource_record_name
      value = opt.resource_record_value
    }
  } : {}
}

# ── Quickstart Commands ───────────────────────────────────────────────────────

output "deploy_commands" {
  description = "Commands to deploy after terraform apply"
  value       = <<-EOT

    # 1. Set secrets (one-time):
    aws secretsmanager put-secret-value \
      --secret-id sovereignly/${var.environment}/app \
      --secret-string '{"SOVEREIGN_SERVER_KEY":"$(openssl rand -hex 32)","JWT_SECRET":"$(openssl rand -hex 32)","ADMIN_TOKEN":"$(openssl rand -hex 16)"}'

    # 2. Build & push (or use GitHub Actions):
    aws ecr get-login-password --region ${local.region} | docker login --username AWS --password-stdin ${aws_ecr_repository.app.repository_url}
    docker buildx build --platform linux/arm64 -f apps/cloud/Dockerfile -t ${aws_ecr_repository.app.repository_url}:latest --push .

    # 3. Force new deployment:
    aws ecs update-service --cluster ${aws_ecs_cluster.main.name} --service ${aws_ecs_service.app.name} --force-new-deployment

    # 4. SSH into container (like fly ssh console):
    aws ecs execute-command --cluster ${aws_ecs_cluster.main.name} --task <TASK_ID> --container sovereignly --interactive --command "/bin/sh"

    # 5. View logs:
    aws logs tail /ecs/${local.name} --follow

  EOT
}
