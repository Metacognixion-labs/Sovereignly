#!/usr/bin/env pwsh
# ═══════════════════════════════════════════════════════════════════════════════
# SOVEREIGNLY v3.0.1 — PRODUCTION DEPLOY
# Deploys to Fly.io with Litestream backup to Cloudflare R2
#
# USAGE:
#   .\deploy\DEPLOY.ps1                   Full interactive deploy
#   .\deploy\DEPLOY.ps1 -SkipSecrets      Deploy only (secrets already set)
#   .\deploy\DEPLOY.ps1 -Verify           Post-deploy verification only
# ═══════════════════════════════════════════════════════════════════════════════

param(
    [switch]$SkipSecrets,
    [switch]$Verify
)

$ErrorActionPreference = "Stop"
$BASE_URL = ""

Write-Host ""
Write-Host "⬡  SOVEREIGNLY — PRODUCTION DEPLOY" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor DarkCyan
Write-Host ""

# ─── Pre-flight ───────────────────────────────────────────────────────────────

if (-not $Verify) {
    Write-Host "[1/6] Pre-flight checks..." -ForegroundColor Yellow

    # Check flyctl
    $flyVersion = fly version 2>$null
    if (-not $flyVersion) {
        Write-Host "  ✗ flyctl not found. Install: winget install --id Fly.io.flyctl" -ForegroundColor Red
        exit 1
    }
    Write-Host "  ✓ flyctl: $flyVersion" -ForegroundColor Green

    # Check logged in
    $flyAuth = fly auth whoami 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  ⚠ Not logged in. Running: fly auth login" -ForegroundColor Yellow
        fly auth login
    }
    Write-Host "  ✓ Fly.io authenticated" -ForegroundColor Green

    # Check app exists
    $appInfo = fly apps list 2>$null | Select-String "sovereignly"
    if (-not $appInfo) {
        Write-Host "  Creating Fly app..." -ForegroundColor Gray
        fly launch --name sovereignly --region iad --no-deploy
    }
    Write-Host "  ✓ App: sovereignly" -ForegroundColor Green
}

# ─── Secrets ──────────────────────────────────────────────────────────────────

if (-not $SkipSecrets -and -not $Verify) {
    Write-Host ""
    Write-Host "[2/6] Setting production secrets..." -ForegroundColor Yellow

    # Generate secrets if not provided
    $serverKey = Read-Host -Prompt "  SOVEREIGN_SERVER_KEY (or Enter to generate)"
    if (-not $serverKey) { $serverKey = -join ((1..32) | ForEach-Object { '{0:x2}' -f (Get-Random -Max 256) }) }

    $jwtSecret = Read-Host -Prompt "  JWT_SECRET (or Enter to generate)"
    if (-not $jwtSecret) { $jwtSecret = -join ((1..32) | ForEach-Object { '{0:x2}' -f (Get-Random -Max 256) }) }

    $adminToken = Read-Host -Prompt "  ADMIN_TOKEN (or Enter to generate)"
    if (-not $adminToken) { $adminToken = -join ((1..16) | ForEach-Object { '{0:x2}' -f (Get-Random -Max 256) }) }

    Write-Host "  Setting core secrets..." -ForegroundColor Gray
    fly secrets set `
        SOVEREIGN_SERVER_KEY=$serverKey `
        JWT_SECRET=$jwtSecret `
        ADMIN_TOKEN=$adminToken `
        --stage

    # EAS attestation
    $easKey = Read-Host -Prompt "  EAS_SIGNER_KEY (0x... EVM private key, or Enter to skip)"
    if ($easKey) {
        fly secrets set `
            EAS_SIGNER_KEY=$easKey `
            EAS_SCHEMA_UID=0xa3518350e4a3857be49837596827c326dad06d71a9ed18cd883774118c1e90dc `
            --stage
    }

    # Litestream / R2 backup
    Write-Host ""
    Write-Host "  Cloudflare R2 backup (recommended):" -ForegroundColor White
    $r2Bucket = Read-Host -Prompt "  LITESTREAM_BUCKET (R2 bucket name, or Enter to skip)"
    if ($r2Bucket) {
        $r2Key = Read-Host -Prompt "  LITESTREAM_ACCESS_KEY_ID"
        $r2Secret = Read-Host -Prompt "  LITESTREAM_SECRET_ACCESS_KEY"
        $r2Endpoint = Read-Host -Prompt "  LITESTREAM_ENDPOINT (https://<account_id>.r2.cloudflarestorage.com)"

        fly secrets set `
            LITESTREAM_BUCKET=$r2Bucket `
            LITESTREAM_ACCESS_KEY_ID=$r2Key `
            LITESTREAM_SECRET_ACCESS_KEY=$r2Secret `
            LITESTREAM_ENDPOINT=$r2Endpoint `
            LITESTREAM_REGION=auto `
            LITESTREAM_PATH_STYLE=true `
            --stage
    }

    # Domain
    $domain = Read-Host -Prompt "  SOVEREIGN_DOMAIN (e.g. sovereignly.io, or Enter to skip)"
    if ($domain) {
        fly secrets set SOVEREIGN_DOMAIN=$domain --stage
    }

    # Stripe
    $stripeKey = Read-Host -Prompt "  STRIPE_SECRET_KEY (or Enter to skip billing)"
    if ($stripeKey) {
        $stripeWebhook = Read-Host -Prompt "  STRIPE_WEBHOOK_SECRET"
        $stripeStarter = Read-Host -Prompt "  STRIPE_PRICE_STARTER"
        $stripeGrowth = Read-Host -Prompt "  STRIPE_PRICE_GROWTH"
        fly secrets set `
            STRIPE_SECRET_KEY=$stripeKey `
            STRIPE_WEBHOOK_SECRET=$stripeWebhook `
            STRIPE_PRICE_STARTER=$stripeStarter `
            STRIPE_PRICE_GROWTH=$stripeGrowth `
            --stage
    }

    # Deploy staged secrets
    Write-Host "  Deploying secrets..." -ForegroundColor Gray
    fly secrets deploy
    Write-Host "  ✓ All secrets set" -ForegroundColor Green

    # Save ADMIN_TOKEN locally for verification
    $script:ADMIN_TOKEN = $adminToken
}

# ─── Deploy ───────────────────────────────────────────────────────────────────

if (-not $Verify) {
    Write-Host ""
    Write-Host "[3/6] Deploying to Fly.io..." -ForegroundColor Yellow
    fly deploy --wait-timeout 120
    Write-Host "  ✓ Deployed" -ForegroundColor Green

    # Get app URL
    $BASE_URL = (fly info 2>$null | Select-String "Hostname" | ForEach-Object { $_.Line -replace '.*=\s*', '' }).Trim()
    if (-not $BASE_URL) { $BASE_URL = "https://sovereignly.fly.dev" }
    if (-not $BASE_URL.StartsWith("https://")) { $BASE_URL = "https://$BASE_URL" }
}

# ─── Custom Domain ────────────────────────────────────────────────────────────

if (-not $Verify -and $domain) {
    Write-Host ""
    Write-Host "[4/6] Setting up custom domain..." -ForegroundColor Yellow
    fly certs add $domain 2>$null
    Write-Host "  ✓ Certificate requested for $domain" -ForegroundColor Green
    Write-Host "  → Add a CNAME record: $domain → sovereignly.fly.dev" -ForegroundColor Gray
    $BASE_URL = "https://$domain"
}

# ─── Post-Deploy Verification ─────────────────────────────────────────────────

Write-Host ""
Write-Host "[5/6] Post-deploy verification..." -ForegroundColor Yellow

if (-not $BASE_URL) {
    $BASE_URL = Read-Host -Prompt "  Base URL (e.g. https://sovereignly.fly.dev)"
}
if (-not $script:ADMIN_TOKEN) {
    $script:ADMIN_TOKEN = Read-Host -Prompt "  Admin token"
}

$TOKEN = $script:ADMIN_TOKEN
$pass = 0
$fail = 0

function Test-Endpoint {
    param($Name, $Url, $Headers, $Check)
    try {
        $resp = Invoke-RestMethod -Uri $Url -Headers $Headers -TimeoutSec 10 -ErrorAction Stop
        $ok = & $Check $resp
        if ($ok) {
            Write-Host "  ✓ $Name" -ForegroundColor Green
            $script:pass++
        } else {
            Write-Host "  ✗ $Name — unexpected response" -ForegroundColor Red
            $script:fail++
        }
    } catch {
        Write-Host "  ✗ $Name — $($_.Exception.Message)" -ForegroundColor Red
        $script:fail++
    }
}

$authHeader = @{ "x-sovereign-token" = "Bearer $TOKEN" }

Test-Endpoint "Health" "$BASE_URL/_sovereign/health" @{} {
    param($r) $r.version -eq "3.0.1" -and $r.ok -eq $true
}

Test-Endpoint "Chain stats" "$BASE_URL/_sovereign/chain/stats" $authHeader {
    param($r) $r.blocks -ge 1
}

Test-Endpoint "Chain integrity" "$BASE_URL/_sovereign/chain/verify" $authHeader {
    param($r) $r.valid -eq $true
}

Test-Endpoint "SOC2 report" "$BASE_URL/_sovereign/compliance/soc2" $authHeader {
    param($r) $r.overallScore -ge 0
}

Test-Endpoint "Metrics" "$BASE_URL/_sovereign/metrics" @{} {
    param($r) $true  # Just needs to not error
}

# ─── Summary ──────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "[6/6] Summary" -ForegroundColor Yellow
Write-Host ""
Write-Host "  URL:     $BASE_URL" -ForegroundColor White
Write-Host "  Health:  $BASE_URL/_sovereign/health" -ForegroundColor Gray
Write-Host "  Dash:    $BASE_URL/_sovereign/dashboard" -ForegroundColor Gray
Write-Host "  Metrics: $BASE_URL/_sovereign/metrics" -ForegroundColor Gray
Write-Host "  Tests:   $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { "Green" } else { "Red" })
Write-Host ""

if ($fail -gt 0) {
    Write-Host "  ⚠ Some checks failed. Run: fly logs" -ForegroundColor Yellow
} else {
    Write-Host "  ✓ All checks passed. Sovereignly is live." -ForegroundColor Green
    Write-Host ""
    Write-Host "  Next: Tag the release" -ForegroundColor White
    Write-Host "    git tag v3.0.1" -ForegroundColor Gray
    Write-Host "    git push origin v3.0.1" -ForegroundColor Gray
    Write-Host "    (triggers Docker image build + GitHub Release)" -ForegroundColor Gray
}

Write-Host ""
Write-Host "⬡  Sovereignly v3.0.1 — MetaCognixion" -ForegroundColor DarkCyan
