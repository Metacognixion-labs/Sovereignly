#!/bin/sh
# Sovereignly v3.0.1 — Container Entrypoint
#
# If LITESTREAM_BUCKET is set → Litestream wraps Bun (continuous backup)
# Otherwise → plain Bun (local dev / no backup)
#
# Litestream restore: on first boot, restores any existing DB from S3/R2
# before starting the application. This handles Fly machine restarts.

set -e

if [ -n "$LITESTREAM_BUCKET" ] && [ -n "$LITESTREAM_ACCESS_KEY_ID" ]; then
  echo "[entrypoint] Litestream backup enabled → $LITESTREAM_BUCKET"

  # Restore databases if they don't exist yet (fresh machine / volume wipe)
  for db in /data/platform/chain.db /data/global/tenants.db; do
    if [ ! -f "$db" ]; then
      echo "[entrypoint] Restoring $db from replica..."
      litestream restore -config /etc/litestream.yml -if-replica-exists "$db" || true
    fi
  done

  # Start Litestream with Bun as the subprocess
  # Litestream will replicate all DBs listed in litestream.yml
  exec litestream replicate -exec "bun src/server.ts" -config /etc/litestream.yml
else
  echo "[entrypoint] No backup configured — running plain Bun"
  exec bun src/server.ts
fi
