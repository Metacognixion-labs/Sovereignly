#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════╗
# ║  Sovereignly v3 — Launch Script                                  ║
# ║  MetaCognixion Protocol Stack                                       ║
# ║                                                                     ║
# ║  Usage:                                                             ║
# ║    ./deploy/launch.sh                    Interactive setup          ║
# ║    ./deploy/launch.sh --quick            Skip prompts, use .env     ║
# ║    ./deploy/launch.sh --reset            Wipe data, fresh start     ║
# ║    ./deploy/launch.sh --check            Pre-flight checks only     ║
# ╚══════════════════════════════════════════════════════════════════════╝

set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────────────
GOLD="\033[38;5;178m"
GREEN="\033[32m"
RED="\033[31m"
DIM="\033[2m"
BOLD="\033[1m"
RESET="\033[0m"

# ── Flags ─────────────────────────────────────────────────────────────────────
QUICK=false
RESET_DATA=false
CHECK_ONLY=false
for arg in "$@"; do
  case $arg in
    --quick)  QUICK=true ;;
    --reset)  RESET_DATA=true ;;
    --check)  CHECK_ONLY=true ;;
  esac
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT/.env"

echo -e "
${GOLD}╔══════════════════════════════════════════════════════════════╗
║    ⬡  METACOGNIXION PROTOCOL STACK — LAUNCH                  ║
╚══════════════════════════════════════════════════════════════╝${RESET}
  ${DIM}$ROOT${RESET}
"

# ── Pre-flight checks ─────────────────────────────────────────────────────────
echo -e "${BOLD}[1/5] Pre-flight checks${RESET}"

check() {
  local cmd=$1; local name=$2; local install_hint=$3
  if command -v "$cmd" >/dev/null 2>&1; then
    echo -e "  ${GREEN}✓${RESET}  $name"
    return 0
  else
    echo -e "  ${RED}✗${RESET}  $name not found — $install_hint"
    return 1
  fi
}

PASS=true
check docker     "Docker"          "https://docs.docker.com/install"         || PASS=false
check "docker" "Docker Compose v2"  "docker compose (v2 is built into Docker)" || true
check openssl    "OpenSSL"          "brew install openssl"                    || true

# Check docker compose version
if docker compose version >/dev/null 2>&1; then
  echo -e "  ${GREEN}✓${RESET}  Docker Compose v2 ($(docker compose version --short))"
else
  echo -e "  ${RED}✗${RESET}  docker compose v2 not found — update Docker"
  PASS=false
fi

if [ "$PASS" = false ]; then
  echo -e "\n  ${RED}Fix the above issues and re-run.${RESET}"
  exit 1
fi

[ "$CHECK_ONLY" = true ] && echo -e "\n${GREEN}Pre-flight checks passed.${RESET}" && exit 0

# ── .env setup ────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[2/5] Environment configuration${RESET}"

if [ ! -f "$ENV_FILE" ]; then
  echo -e "  ${DIM}Creating .env from .env.example...${RESET}"
  cp "$ROOT/.env.example" "$ENV_FILE"
fi

# Auto-generate missing required secrets
needs_update=false

check_or_generate() {
  local var=$1; local label=$2
  local current=$(grep "^${var}=" "$ENV_FILE" 2>/dev/null | cut -d= -f2-)
  if [ -z "$current" ] || [ "$current" = "" ]; then
    local new_val=$(openssl rand -hex 32)
    # Replace or append
    if grep -q "^${var}=" "$ENV_FILE"; then
      sed -i.bak "s|^${var}=.*|${var}=${new_val}|" "$ENV_FILE"
    else
      echo "${var}=${new_val}" >> "$ENV_FILE"
    fi
    echo -e "  ${GREEN}✓${RESET}  ${label}: auto-generated"
    needs_update=true
  else
    echo -e "  ${GREEN}✓${RESET}  ${label}: already set"
  fi
}

check_or_generate SOVEREIGN_SERVER_KEY "SOVEREIGN_SERVER_KEY (master encryption key)"
check_or_generate JWT_SECRET           "JWT_SECRET"
check_or_generate ADMIN_TOKEN          "ADMIN_TOKEN"

if [ "$needs_update" = true ]; then
  echo -e "\n  ${GOLD}⚠  Auto-generated secrets written to .env${RESET}"
  echo -e "  ${DIM}Back up .env — these keys encrypt all tenant data!${RESET}"
fi

# Print ADMIN_TOKEN so operator can access the API
ADMIN_TOKEN_VAL=$(grep "^ADMIN_TOKEN=" "$ENV_FILE" | cut -d= -f2-)
echo -e "\n  Admin token: ${GOLD}${ADMIN_TOKEN_VAL:0:16}...${RESET} (see .env for full value)"

# ── Optional config prompts ────────────────────────────────────────────────────
if [ "$QUICK" = false ]; then
  echo -e "\n${BOLD}[3/5] Optional configuration${RESET}"

  DOMAIN=$(grep "^SOVEREIGN_DOMAIN=" "$ENV_FILE" 2>/dev/null | cut -d= -f2- || echo "")
  if [ -z "$DOMAIN" ]; then
    echo -e "  ${DIM}SOVEREIGN_DOMAIN not set. Caddy will serve on localhost (HTTP).${RESET}"
    echo -e "  Set SOVEREIGN_DOMAIN=yourdomain.com in .env for auto-TLS."
  else
    echo -e "  ${GREEN}✓${RESET}  Domain: $DOMAIN"
  fi

  EAS_KEY=$(grep "^EAS_SIGNER_KEY=" "$ENV_FILE" 2>/dev/null | cut -d= -f2- || echo "")
  if [ -z "$EAS_KEY" ]; then
    echo -e "  ${DIM}EAS_SIGNER_KEY not set — set it to enable omnichain attestation.${RESET}"
    echo -e "  ${DIM}EAS/Base uses public RPC (no API key needed). Schema UID is precomputed.${RESET}"
    echo -e "  ${DIM}Annual cost at growth tier: \$0.63/yr (EAS/Base + Arbitrum + Solana)${RESET}"
  else
    ANCHOR_TIER_VAL=$(grep "^ANCHOR_TIER=" "$ENV_FILE" 2>/dev/null | cut -d= -f2- || echo "starter")
    echo -e "  ${GREEN}✓${RESET}  Omnichain anchor configured — tier=${ANCHOR_TIER_VAL:-starter}"
    echo -e "  ${DIM}    Chains: EAS/Base + EAS/Arbitrum + Sign Protocol + Solana${RESET}"
  fi

  STRIPE_KEY=$(grep "^STRIPE_SECRET_KEY=" "$ENV_FILE" 2>/dev/null | cut -d= -f2- || echo "")
  if [ -z "$STRIPE_KEY" ]; then
    echo -e "  ${DIM}STRIPE_SECRET_KEY not set — billing disabled.${RESET}"
  else
    echo -e "  ${GREEN}✓${RESET}  Stripe billing configured"
  fi
else
  echo -e "\n${BOLD}[3/5] Optional configuration${RESET} ${DIM}(skipped with --quick)${RESET}"
fi

# ── Data reset ────────────────────────────────────────────────────────────────
if [ "$RESET_DATA" = true ]; then
  echo -e "\n${RED}[!] Resetting all data volumes...${RESET}"
  docker compose -f "$ROOT/docker-compose.yml" down -v 2>/dev/null || true
  echo -e "  ${GREEN}✓${RESET}  Volumes cleared"
fi

# ── Pull images ────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[4/5] Building and pulling images${RESET}"
cd "$ROOT"

# Build the sovereign image
echo -e "  Building metacognixion/sovereignly:3.0..."
docker build -t metacognixion/sovereignly:3.0 . --quiet && \
  echo -e "  ${GREEN}✓${RESET}  Built metacognixion/sovereignly:3.0" || \
  echo -e "  ${RED}✗${RESET}  Build failed — check Dockerfile"

# Pull external images
echo -e "  Pulling Caddy, Prometheus, Grafana..."
docker compose pull caddy prometheus grafana 2>/dev/null | grep -v "^#" || true
echo -e "  ${GREEN}✓${RESET}  Images ready"

# ── Launch ─────────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[5/5] Launching${RESET}"
docker compose up -d --remove-orphans

# Wait for health
echo -e "\n  Waiting for sovereign node to be healthy..."
attempts=0
until docker compose exec -T sovereign \
    bun -e "fetch('http://localhost:8787/_sovereign/health').then(r=>process.exit(r.ok?0:1))" \
    2>/dev/null; do
  attempts=$((attempts + 1))
  if [ $attempts -ge 20 ]; then
    echo -e "\n  ${RED}✗${RESET}  Node not healthy after 20 attempts."
    echo -e "  Check logs: docker compose logs sovereign"
    exit 1
  fi
  printf "."
  sleep 2
done

echo -e "\n\n  ${GREEN}✓${RESET}  Sovereignly is up"

# ── Summary ────────────────────────────────────────────────────────────────────
DOMAIN_VAL=$(grep "^SOVEREIGN_DOMAIN=" "$ENV_FILE" 2>/dev/null | cut -d= -f2- || echo "")
BASE_URL="http://localhost:8787"
[ -n "$DOMAIN_VAL" ] && BASE_URL="https://$DOMAIN_VAL"

echo -e "
${GOLD}╔══════════════════════════════════════════════════════════════╗
║  ✓  Sovereignly v3.0 is running                              ║
╚══════════════════════════════════════════════════════════════╝${RESET}

  ${BOLD}Endpoints:${RESET}
    ${BASE_URL}/_sovereign/chain/stats
    ${BASE_URL}/_sovereign/auth
    ${BASE_URL}/_sovereign/platform/stats   ${DIM}(admin token required)${RESET}

  ${BOLD}Dashboard:${RESET}
    Open sovereign-os-dashboard.html in your browser

  ${BOLD}Admin token:${RESET}
    ${GOLD}${ADMIN_TOKEN_VAL}${RESET}
    ${DIM}# Usage: curl -H 'x-sovereign-token: TOKEN' ${BASE_URL}/_sovereign/platform/stats${RESET}

  ${BOLD}Next steps:${RESET}
    ${DIM}# Register EAS schema (one-time, ~\$0.001):${RESET}
    EAS_SIGNER_KEY=0x<key> node deploy/register-eas-schema.mjs

    ${DIM}# Publish chain-sdk to npm:${RESET}
    cd packages/chain-sdk && npm publish

    ${DIM}# View logs:${RESET}
    docker compose logs -f sovereign

    ${DIM}# Scale out (add a replica node):${RESET}
    docker compose --profile scale up -d

    ${DIM}# Enable monitoring (Prometheus + Grafana):${RESET}
    docker compose --profile monitoring up -d
    ${DIM}# Grafana: http://localhost:3001 — admin/sovereign${RESET}
"
