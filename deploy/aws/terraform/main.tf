# ─────────────────────────────────────────────────────────────────────────────
# Sovereignly — AWS Infrastructure (Terraform)
#
# Architecture: ECS Fargate (Graviton/ARM64) + EFS + S3 + CloudFront + ALB
# Cost target: ~$25-40/mo base (scales with traffic)
# ─────────────────────────────────────────────────────────────────────────────

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Remote state — uncomment and configure for team use
  # backend "s3" {
  #   bucket         = "sovereignly-terraform-state"
  #   key            = "prod/terraform.tfstate"
  #   region         = "us-east-1"
  #   dynamodb_table = "terraform-locks"
  #   encrypt        = true
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "sovereignly"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

# For CloudFront ACM certificate (must be us-east-1)
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"

  default_tags {
    tags = {
      Project     = "sovereignly"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

# ── Data Sources ──────────────────────────────────────────────────────────────

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  name       = "sovereignly-${var.environment}"
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
}
