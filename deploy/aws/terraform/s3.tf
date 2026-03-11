# ─────────────────────────────────────────────────────────────────────────────
# S3 — Litestream backup bucket
#
# Intelligent-Tiering automatically moves data to cheaper storage classes.
# Cost: ~$0.023/GB/mo (Standard), drops to $0.004/GB/mo after 90 days.
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_s3_bucket" "litestream" {
  bucket = "${local.name}-litestream-${local.account_id}"

  tags = { Name = "${local.name}-litestream" }
}

resource "aws_s3_bucket_versioning" "litestream" {
  bucket = aws_s3_bucket.litestream.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "litestream" {
  bucket = aws_s3_bucket.litestream.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_intelligent_tiering_configuration" "litestream" {
  bucket = aws_s3_bucket.litestream.id
  name   = "archive-old-wal"

  tiering {
    access_tier = "ARCHIVE_ACCESS"
    days        = 90
  }

  tiering {
    access_tier = "DEEP_ARCHIVE_ACCESS"
    days        = 180
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "litestream" {
  bucket = aws_s3_bucket.litestream.id

  rule {
    id     = "cleanup-old-wal"
    status = "Enabled"

    filter {
      prefix = "sovereign/"
    }

    # Move to Intelligent-Tiering after 30 days
    transition {
      days          = 30
      storage_class = "INTELLIGENT_TIERING"
    }

    # Delete WAL fragments older than 1 year
    expiration {
      days = 365
    }

    # Clean up incomplete multipart uploads
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

resource "aws_s3_bucket_public_access_block" "litestream" {
  bucket = aws_s3_bucket.litestream.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
