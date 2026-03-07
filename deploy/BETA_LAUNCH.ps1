#!/usr/bin/env pwsh
# ═══════════════════════════════════════════════════════════════════════════════
# SOVEREIGNLY v3.0.1 — BETA LAUNCH
#
# Provisions 5 Growth-tier beta tenants, issues API keys, runs SDK test.
#
# USAGE:
#   .\deploy\BETA_LAUNCH.ps1 -BaseUrl https://sovereignly.fly.dev -AdminToken <token>
# ═══════════════════════════════════════════════════════════════════════════════

param(
    [string]$BaseUrl,
    [string]$AdminToken,
    [string]$OwnerEmail = "jp@metacognixion.com"
)

$ErrorActionPreference = "Stop"

if (-not $BaseUrl)   { $BaseUrl   = Read-Host "Base URL" }
if (-not $AdminToken) { $AdminToken = Read-Host "Admin token" }
$BaseUrl = $BaseUrl.TrimEnd("/")

Write-Host ""
Write-Host "⬡  SOVEREIGNLY — BETA LAUNCH" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor DarkCyan
Write-Host ""

# ── Beta tenant definitions ───────────────────────────────────────────────────

$betaTenants = @(
    @{ name = "MetaCognixion Internal"; plan = "enterprise"; domain = "internal.metacognixion.com" },
    @{ name = "Beta Alpha";             plan = "growth";     domain = $null },
    @{ name = "Beta Bravo";             plan = "growth";     domain = $null },
    @{ name = "Beta Charlie";           plan = "growth";     domain = $null },
    @{ name = "Beta Delta";             plan = "starter";    domain = $null }
)

$results = @()

# ── Provision each tenant ─────────────────────────────────────────────────────

Write-Host "[1/4] Provisioning $($betaTenants.Count) beta tenants..." -ForegroundColor Yellow
Write-Host ""

foreach ($t in $betaTenants) {
    Write-Host "  Creating: $($t.name) ($($t.plan))..." -ForegroundColor Gray -NoNewline

    $body = @{
        name    = $t.name
        plan    = $t.plan
        ownerId = $OwnerEmail
    }
    if ($t.domain) { $body.domain = $t.domain }

    try {
        $r = Invoke-RestMethod -Uri "$BaseUrl/_sovereign/tenants" -Method POST `
            -Headers @{ "x-sovereign-token" = "Bearer $AdminToken"; "Content-Type" = "application/json" } `
            -Body ($body | ConvertTo-Json) -TimeoutSec 15

        $tenantId = $r.tenant.id

        # Issue a 90-day owner JWT for this tenant
        $tokenBody = @{ sub = $OwnerEmail; role = "deployer"; ttl = (90 * 86400) }
        $tokenR = Invoke-RestMethod -Uri "$BaseUrl/_sovereign/auth/token" -Method POST `
            -Headers @{ "x-sovereign-token" = "Bearer $AdminToken"; "Content-Type" = "application/json" } `
            -Body ($tokenBody | ConvertTo-Json) -TimeoutSec 10

        $results += @{
            name     = $t.name
            id       = $tenantId
            plan     = $t.plan
            apiKey   = $tokenR.token
            domain   = $t.domain ?? "—"
        }

        Write-Host " ✓ $tenantId" -ForegroundColor Green
    } catch {
        Write-Host " ✗ $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ── SDK connectivity test ─────────────────────────────────────────────────────

Write-Host ""
Write-Host "[2/4] Testing SDK event ingest..." -ForegroundColor Yellow

$firstTenant = $results[0]
if ($firstTenant) {
    try {
        $sdkR = Invoke-RestMethod -Uri "$BaseUrl/_sovereign/sdk/events" -Method POST `
            -Headers @{
                "Content-Type"  = "application/json"
                "x-org-id"     = $firstTenant.id
                "Authorization" = "Bearer $($firstTenant.apiKey)"
            } `
            -Body (@{
                events = @(
                    @{ type = "AUTH_SUCCESS";  payload = @{ userId = "beta_test"; method = "passkey" };  severity = "LOW" }
                    @{ type = "FUNCTION_DEPLOY"; payload = @{ fnId = "fn_hello"; route = "/hello" };   severity = "LOW" }
                    @{ type = "CONFIG_CHANGE";  payload = @{ key = "beta_launch"; value = "true" };     severity = "LOW" }
                )
            } | ConvertTo-Json -Depth 5) -TimeoutSec 15

        Write-Host "  ✓ $($sdkR.results.Count) events ingested for $($firstTenant.name)" -ForegroundColor Green
    } catch {
        Write-Host "  ✗ SDK test failed: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "  ⚠ No tenants provisioned — skipping SDK test" -ForegroundColor Yellow
}

# ── Generate credentials file ─────────────────────────────────────────────────

Write-Host ""
Write-Host "[3/4] Generating credentials..." -ForegroundColor Yellow

$credLines = @(
    "# ═══════════════════════════════════════════════════════════════════════════════"
    "# SOVEREIGNLY BETA — Tenant Credentials"
    "# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')"
    "# Base URL: $BaseUrl"
    "# ═══════════════════════════════════════════════════════════════════════════════"
    "# ⚠  KEEP THIS FILE SECURE — contains live API keys"
    ""
)

foreach ($r in $results) {
    $credLines += "# ── $($r.name) ──"
    $credLines += "# Plan: $($r.plan)  |  Domain: $($r.domain)"
    $credLines += "$($r.name.Replace(' ','_').ToUpper())_TENANT_ID=$($r.id)"
    $credLines += "$($r.name.Replace(' ','_').ToUpper())_API_KEY=$($r.apiKey)"
    $credLines += ""

    $credLines += "# SDK usage:"
    $credLines += "#   import { SovereignChain } from '@metacognixion/chain-sdk';"
    $credLines += "#   const chain = new SovereignChain({"
    $credLines += "#     endpoint: '$BaseUrl',"
    $credLines += "#     orgId:    '$($r.id)',"
    $credLines += "#     apiKey:   '<API_KEY above>',"
    $credLines += "#   });"
    $credLines += "#   await chain.emit('USER_LOGIN', { userId: 'u1', method: 'passkey' });"
    $credLines += ""
}

$credPath = Join-Path (Get-Location) "BETA_CREDENTIALS.env"
$credLines | Out-File -FilePath $credPath -Encoding UTF8
Write-Host "  ✓ Saved: $credPath" -ForegroundColor Green

# ── Summary ───────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "[4/4] Summary" -ForegroundColor Yellow
Write-Host ""

Write-Host "  ┌─────────────────────────────────────┬──────────┬────────────┐" -ForegroundColor DarkCyan
Write-Host "  │ Tenant                               │ Plan     │ ID         │" -ForegroundColor DarkCyan
Write-Host "  ├─────────────────────────────────────┼──────────┼────────────┤" -ForegroundColor DarkCyan
foreach ($r in $results) {
    $n = $r.name.PadRight(37)
    $p = $r.plan.PadRight(8)
    $i = $r.id.Substring(0, [Math]::Min(10, $r.id.Length))
    Write-Host "  │ $n │ $p │ $($i)… │" -ForegroundColor White
}
Write-Host "  └─────────────────────────────────────┴──────────┴────────────┘" -ForegroundColor DarkCyan

$totalMRR = ($results | ForEach-Object { switch ($_.plan) { "starter" { 49 } "growth" { 149 } "enterprise" { 2000 } default { 0 } } } | Measure-Object -Sum).Sum

Write-Host ""
Write-Host "  Tenants:     $($results.Count)" -ForegroundColor White
Write-Host "  Beta MRR:    `$$totalMRR" -ForegroundColor White
Write-Host "  Credentials: $credPath" -ForegroundColor White
Write-Host ""
Write-Host "  ─── Beta checklist ───" -ForegroundColor Gray
Write-Host "  [$(if ($results.Count -ge 5) {'✓'} else {'·'})] 5 tenants provisioned" -ForegroundColor $(if ($results.Count -ge 5) {"Green"} else {"Gray"})
Write-Host "  [·] EAS schema registered: node deploy/register-eas-schema.mjs" -ForegroundColor Gray
Write-Host "  [·] Smoke test passed: .\deploy\SMOKE_TEST.ps1" -ForegroundColor Gray
Write-Host "  [·] Litestream backup verified: check R2 bucket" -ForegroundColor Gray
Write-Host "  [·] Release tagged: git tag v3.0.1 && git push origin v3.0.1" -ForegroundColor Gray
Write-Host "  [·] SDK published: cd packages/chain-sdk && npm publish" -ForegroundColor Gray
Write-Host ""
Write-Host "⬡  Sovereignly v3.0.1 — Beta is live." -ForegroundColor Cyan
