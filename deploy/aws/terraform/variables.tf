# ─────────────────────────────────────────────────────────────────────────────
# Variables
# ─────────────────────────────────────────────────────────────────────────────

variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name (prod, staging)"
  type        = string
  default     = "prod"
}

variable "domain_name" {
  description = "Primary domain (e.g., sovereignly.io). Leave empty to use ALB DNS."
  type        = string
  default     = ""
}

# ── Compute ───────────────────────────────────────────────────────────────────

variable "cpu" {
  description = "Fargate task CPU units (256 = 0.25 vCPU, 512, 1024, 2048, 4096)"
  type        = number
  default     = 512
}

variable "memory" {
  description = "Fargate task memory (MB). Must be compatible with CPU."
  type        = number
  default     = 1024
}

variable "desired_count" {
  description = "Number of ECS tasks to run"
  type        = number
  default     = 1
}

variable "min_capacity" {
  description = "Minimum number of ECS tasks (auto-scaling)"
  type        = number
  default     = 1
}

variable "max_capacity" {
  description = "Maximum number of ECS tasks (auto-scaling)"
  type        = number
  default     = 4
}

variable "enable_fargate_spot" {
  description = "Use Fargate Spot for ~70% cost savings (tasks may be interrupted)"
  type        = bool
  default     = false
}

# ── Application ───────────────────────────────────────────────────────────────

variable "container_port" {
  description = "Port the application listens on"
  type        = number
  default     = 8787
}

variable "app_env_vars" {
  description = "Non-secret environment variables for the container"
  type        = map(string)
  default = {
    NODE_ENV         = "production"
    WORKER_POOL_SIZE = "2"
    LOG_LEVEL        = "minimal"
    ANCHOR_TIER      = "starter"
    NODE_ROLE        = "cluster"
    CLUSTER_ID       = "us-east"
    NODE_REGION      = "us-east"
  }
}

variable "secret_arns" {
  description = "Map of secret name → Secrets Manager ARN for sensitive env vars"
  type        = map(string)
  default     = {}
}

# ── Networking ────────────────────────────────────────────────────────────────

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "availability_zones" {
  description = "AZs to use (minimum 2 for ALB)"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]
}

# ── Monitoring ────────────────────────────────────────────────────────────────

variable "alarm_email" {
  description = "Email for CloudWatch alarm notifications. Leave empty to skip."
  type        = string
  default     = ""
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 30
}
