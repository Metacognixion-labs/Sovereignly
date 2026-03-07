#!/usr/bin/env pwsh
# ═══════════════════════════════════════════════════════════════════════════════
# SOVEREIGNLY v3.0.1 — PUSH TO GITHUB
#
# This zip IS the repo. Unzip it and push.
#
# STEPS:
#   1. Unzip Sovereignly-v3.0.1-final.zip into an empty folder
#   2. Run this script from inside that folder
#   3. Done
# ═══════════════════════════════════════════════════════════════════════════════

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "⬡  SOVEREIGNLY v3.0.1 — Push to GitHub" -ForegroundColor Cyan
Write-Host ""

# Verify we're in the right place
if (-not (Test-Path "apps/oss/src/server.ts")) {
    Write-Host "  ✗ Run this from inside the unzipped Sovereignly folder." -ForegroundColor Red
    exit 1
}

# Init git
if (-not (Test-Path ".git")) {
    git init
    git branch -M main
}

# Set remote
$remote = git remote get-url origin 2>$null
if (-not $remote) {
    git remote add origin https://github.com/Metacognixion-labs/Sovereignly.git
}

Write-Host "  Remote: https://github.com/Metacognixion-labs/Sovereignly.git" -ForegroundColor Gray
Write-Host ""

# Stage everything
git add -A

# Show what's being pushed
$count = (git status --short | Measure-Object).Count
Write-Host "  Files: $count" -ForegroundColor White

# Commit
git commit -m "Sovereignly v3.0.1 — open-core monorepo

MIT open-source:
  apps/oss/        Single-tenant server (chain, auth, gateway, runtime)
  packages/core/   Shared types
  packages/sdk/    @metacognixion/chain-sdk
  contracts/       AuditAnchor.sol

BSL 1.1 premium:
  apps/cloud/      Multi-tenant SaaS (tenants, billing, compliance, webhooks)

75 files · 3 dependencies · 73 endpoints · $0.63/yr COGS per tenant"

Write-Host ""
Write-Host "  ✓ Committed" -ForegroundColor Green

# Push
Write-Host "  Pushing..." -ForegroundColor Gray
git push -u origin main --force
Write-Host "  ✓ Pushed" -ForegroundColor Green

# Tag
Write-Host ""
$tag = Read-Host "  Tag v3.0.1? (y/n)"
if ($tag -eq "y") {
    git tag v3.0.1
    git push origin v3.0.1
    Write-Host "  ✓ Tagged — release pipeline triggered" -ForegroundColor Green
}

Write-Host ""
Write-Host "  Done: https://github.com/Metacognixion-labs/Sovereignly" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Next:" -ForegroundColor White
Write-Host "    bun install && bun run dev        ← OSS edition" -ForegroundColor Gray
Write-Host "    bun install && bun run dev:cloud   ← Cloud edition" -ForegroundColor Gray
Write-Host "    fly deploy                         ← Deploy to Fly.io" -ForegroundColor Gray
Write-Host ""
