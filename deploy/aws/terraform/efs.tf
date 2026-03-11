# ─────────────────────────────────────────────────────────────────────────────
# EFS — Persistent storage for SQLite databases
#
# Uses bursting throughput (free up to burst credits) — no provisioned IOPS.
# Cost: ~$0.30/GB/mo for Standard, first 5GB free on new accounts.
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_efs_file_system" "data" {
  creation_token = "${local.name}-data"
  encrypted      = true

  throughput_mode = "bursting"

  lifecycle_policy {
    transition_to_ia = "AFTER_30_DAYS"
  }

  lifecycle_policy {
    transition_to_primary_storage_class = "AFTER_1_ACCESS"
  }

  tags = { Name = "${local.name}-data" }
}

resource "aws_efs_mount_target" "data" {
  count           = length(aws_subnet.public)
  file_system_id  = aws_efs_file_system.data.id
  subnet_id       = aws_subnet.public[count.index].id
  security_groups = [aws_security_group.efs.id]
}

# Access point — enforces POSIX user (matches Docker USER sovereign = UID 100)
resource "aws_efs_access_point" "app" {
  file_system_id = aws_efs_file_system.data.id

  posix_user {
    uid = 100 # sovereign user in Alpine
    gid = 101 # sovereign group
  }

  root_directory {
    path = "/sovereignly"
    creation_info {
      owner_uid   = 100
      owner_gid   = 101
      permissions = "0755"
    }
  }

  tags = { Name = "${local.name}-app" }
}

# ── EFS Backup ────────────────────────────────────────────────────────────────
# AWS Backup for EFS — daily snapshots, 7-day retention (~$0.05/GB/mo)

resource "aws_backup_vault" "main" {
  name = "${local.name}-vault"
}

resource "aws_backup_plan" "daily" {
  name = "${local.name}-daily"

  rule {
    rule_name         = "daily-backup"
    target_vault_name = aws_backup_vault.main.name
    schedule          = "cron(0 5 * * ? *)" # 5 AM UTC daily

    lifecycle {
      delete_after = 7
    }
  }
}

resource "aws_iam_role" "backup" {
  name = "${local.name}-backup-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "backup.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "backup" {
  role       = aws_iam_role.backup.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
}

resource "aws_backup_selection" "efs" {
  name         = "${local.name}-efs"
  plan_id      = aws_backup_plan.daily.id
  iam_role_arn = aws_iam_role.backup.arn

  resources = [aws_efs_file_system.data.arn]
}
