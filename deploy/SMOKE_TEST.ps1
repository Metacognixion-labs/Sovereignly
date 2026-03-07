#!/usr/bin/env pwsh
# ═══════════════════════════════════════════════════════════════════════════════
# SOVEREIGNLY v3.0.1 — PRODUCTION SMOKE TEST
#
# Runs 20 end-to-end checks against a live deployment.
# Tests the full revenue pipeline: health → signup → emit → chain → compliance.
#
# USAGE:
#   .\deploy\SMOKE_TEST.ps1 -BaseUrl https://sovereignly.fly.dev -AdminToken <token>
#   .\deploy\SMOKE_TEST.ps1   # prompts for URL and token
# ═══════════════════════════════════════════════════════════════════════════════

param(
    [string]$BaseUrl,
    [string]$AdminToken
)

$ErrorActionPreference = "Continue"
$pass = 0; $fail = 0; $skip = 0
$startTime = Get-Date

if (-not $BaseUrl)   { $BaseUrl   = Read-Host "Base URL (e.g. https://sovereignly.fly.dev)" }
if (-not $AdminToken) { $AdminToken = Read-Host "Admin token" }
$BaseUrl = $BaseUrl.TrimEnd("/")

Write-Host ""
Write-Host "⬡  SOVEREIGNLY — PRODUCTION SMOKE TEST" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor DarkCyan
Write-Host "  Target: $BaseUrl" -ForegroundColor Gray
Write-Host ""

# ── Helpers ───────────────────────────────────────────────────────────────────

function Test($Name, $Block) {
    try {
        $result = & $Block
        if ($result) {
            Write-Host "  ✓ $Name" -ForegroundColor Green
            $script:pass++
        } else {
            Write-Host "  ✗ $Name" -ForegroundColor Red
            $script:fail++
        }
    } catch {
        Write-Host "  ✗ $Name — $($_.Exception.Message)" -ForegroundColor Red
        $script:fail++
    }
}

function Api($Path, $Method = "GET", $Body = $null, $Headers = @{}) {
    $h = @{ "Content-Type" = "application/json" } + $Headers
    $params = @{ Uri = "$BaseUrl$Path"; Method = $Method; Headers = $h; TimeoutSec = 15; ErrorAction = "Stop" }
    if ($Body) { $params.Body = ($Body | ConvertTo-Json -Depth 5) }
    Invoke-RestMethod @params
}

$adminHeaders = @{ "x-sovereign-token" = "Bearer $AdminToken" }

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 1: Infrastructure
# ═══════════════════════════════════════════════════════════════════════════════

Write-Host "── Infrastructure ──" -ForegroundColor Yellow

Test "1. Health returns 3.0.1" {
    $r = Api "/_sovereign/health"
    $r.version -eq "3.0.1" -and $r.ok -eq $true
}

Test "2. Chain has blocks" {
    $r = Api "/_sovereign/chain/stats" -Headers $adminHeaders
    $r.blocks -ge 1
}

Test "3. Chain integrity valid" {
    $r = Api "/_sovereign/chain/verify" -Headers $adminHeaders
    $r.valid -eq $true
}

Test "4. Metrics endpoint responds" {
    $r = Api "/_sovereign/metrics"
    $null -ne $r.requests
}

Test "5. SOC2 report generates" {
    $r = Api "/_sovereign/compliance/soc2" -Headers $adminHeaders
    $r.overallScore -ge 0
}

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 2: Self-Service Pipeline
# ═══════════════════════════════════════════════════════════════════════════════

Write-Host ""
Write-Host "── Self-Service Pipeline ──" -ForegroundColor Yellow

$testEmail = "smoketest-$(Get-Random)@test.sovereignly.io"
$tenantToken = $null
$tenantId = $null

Test "6. Public signup creates tenant" {
    $r = Api "/_sovereign/signup" "POST" @{ name = "Smoke Test Corp"; email = $testEmail }
    $script:tenantToken = $r.token
    $script:tenantId = $r.tenant.id
    $r.ok -eq $true -and $r.tenant.plan -eq "free" -and $r.token.Length -gt 10
}

Test "7. JWT returns user context" {
    $r = Api "/_sovereign/me" -Headers @{ Authorization = "Bearer $tenantToken" }
    $r.tenant.id -eq $tenantId -and $r.user.role -eq "owner"
}

Test "8. Pricing endpoint returns plans" {
    $r = Api "/_sovereign/pricing"
    $r.plans.Count -eq 4 -and ($r.plans | Where-Object { $_.name -eq "Growth" }).price -eq 149
}

Test "9. Tenant detail accessible" {
    $r = Api "/_sovereign/tenants/$tenantId" -Headers @{ Authorization = "Bearer $tenantToken" }
    $r.name -eq "Smoke Test Corp" -and $r.plan -eq "free"
}

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 3: Chain Operations
# ═══════════════════════════════════════════════════════════════════════════════

Write-Host ""
Write-Host "── Chain Operations ──" -ForegroundColor Yellow

Test "10. SDK event ingest" {
    $r = Api "/_sovereign/sdk/events" "POST" @{
        events = @(
            @{ type = "AUTH_SUCCESS"; payload = @{ userId = "smoke_user"; method = "passkey" }; severity = "LOW" }
            @{ type = "DATA_ACCESS"; payload = @{ resource = "/api/users"; action = "read" }; severity = "LOW" }
            @{ type = "CONFIG_CHANGE"; payload = @{ key = "theme"; value = "dark" }; severity = "LOW" }
        )
    } @{ "x-org-id" = $tenantId; Authorization = "Bearer $tenantToken" }
    $r.results.Count -eq 3
}

Test "11. Tenant chain events visible" {
    $r = Api "/_sovereign/tenants/$tenantId/chain/events?limit=10" -Headers @{ Authorization = "Bearer $tenantToken" }
    $r.count -ge 1
}

Test "12. Tenant stats updated" {
    $r = Api "/_sovereign/tenants/$tenantId/stats" -Headers @{ Authorization = "Bearer $tenantToken" }
    $r.chain.events -ge 1
}

Test "13. Compliance report for tenant" {
    # Free tier should get blocked (402) or generate report depending on implementation
    try {
        $r = Api "/_sovereign/tenants/$tenantId/chain/report" -Headers @{ Authorization = "Bearer $tenantToken" }
        $true # If it returns, it worked
    } catch {
        # 402 = expected for free tier (compliance requires Starter+)
        $_.Exception.Response.StatusCode.value__ -eq 402
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 4: Admin Operations
# ═══════════════════════════════════════════════════════════════════════════════

Write-Host ""
Write-Host "── Admin Operations ──" -ForegroundColor Yellow

Test "14. Admin tenant list" {
    $r = Api "/_sovereign/tenants" -Headers $adminHeaders
    $r.count -ge 1 -and $null -ne $r.mrr
}

Test "15. Platform stats" {
    $r = Api "/_sovereign/platform/stats" -Headers $adminHeaders
    $null -ne $r.tenants.total -and $null -ne $r.tenants.mrr
}

Test "16. Ops endpoint" {
    $r = Api "/_sovereign/ops" -Headers $adminHeaders
    $null -ne $r.version -and $r.version -eq "3.0.1" -and $null -ne $r.webhooks
}

Test "17. Chain export" {
    $r = Api "/_sovereign/tenants/$tenantId/chain/export" "POST" @{} @{ Authorization = "Bearer $tenantToken" }
    $r.exportVersion -eq "3.0.1" -and $r.events.Count -ge 0
}

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 5: Security
# ═══════════════════════════════════════════════════════════════════════════════

Write-Host ""
Write-Host "── Security ──" -ForegroundColor Yellow

Test "18. Rejects bad auth" {
    try {
        Api "/_sovereign/tenants" -Headers @{ "x-sovereign-token" = "Bearer wrong-token" }
        $false
    } catch {
        $_.Exception.Response.StatusCode.value__ -eq 403
    }
}

Test "19. Rate limit headers present" {
    $uri = "$BaseUrl/_sovereign/sdk/events"
    $r = Invoke-WebRequest -Uri $uri -Method POST -Headers @{
        "Content-Type" = "application/json"; "x-org-id" = $tenantId; Authorization = "Bearer $tenantToken"
    } -Body '{"events":[{"type":"TEST","payload":{},"severity":"LOW"}]}' -TimeoutSec 10 -ErrorAction Stop
    $r.Headers["x-ratelimit-limit"] -ne $null
}

Test "20. Landing page serves HTML" {
    $r = Invoke-WebRequest -Uri "$BaseUrl/" -TimeoutSec 10 -ErrorAction Stop
    $r.StatusCode -eq 200 -and $r.Content.Contains("</html>")
}

# ═══════════════════════════════════════════════════════════════════════════════
# CLEANUP: Suspend smoke test tenant
# ═══════════════════════════════════════════════════════════════════════════════

try {
    Api "/_sovereign/tenants/$tenantId" "DELETE" @{ reason = "smoke test cleanup" } $adminHeaders | Out-Null
} catch {}

# ═══════════════════════════════════════════════════════════════════════════════
# RESULTS
# ═══════════════════════════════════════════════════════════════════════════════

$duration = ((Get-Date) - $startTime).TotalSeconds

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Results: $pass passed, $fail failed, $skip skipped" -ForegroundColor $(if ($fail -eq 0) { "Green" } else { "Red" })
Write-Host "  Duration: $([math]::Round($duration, 1))s" -ForegroundColor Gray
Write-Host "  Target: $BaseUrl" -ForegroundColor Gray
Write-Host ""

if ($fail -eq 0) {
    Write-Host "  ✓ ALL CHECKS PASSED — Sovereignly is production-ready." -ForegroundColor Green
    Write-Host ""
    Write-Host "  Next:" -ForegroundColor White
    Write-Host "    1. Provision beta tenants:  .\deploy\BETA_LAUNCH.ps1" -ForegroundColor Gray
    Write-Host "    2. Tag release:             git tag v3.0.1 && git push origin v3.0.1" -ForegroundColor Gray
    Write-Host "    3. Register EAS schema:     EAS_SIGNER_KEY=0x... node deploy/register-eas-schema.mjs" -ForegroundColor Gray
} else {
    Write-Host "  ⚠ $fail checks failed. Review errors above and fix before launch." -ForegroundColor Yellow
    Write-Host "  Debug: fly logs -a sovereignly" -ForegroundColor Gray
}

Write-Host ""
Write-Host "⬡  Sovereignly v3.0.1 — MetaCognixion" -ForegroundColor DarkCyan
exit $fail
