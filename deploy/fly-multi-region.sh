#!/usr/bin/env bash
# Sovereignly Multi-Region Deployment Script
# Deploys the full global network on Fly.io
#
# Prerequisites:
#   - flyctl installed and authenticated
#   - Fly.io organization configured
#
# Usage: bash deploy/fly-multi-region.sh

set -euo pipefail

echo "=== Sovereignly v4.0 Multi-Region Deployment ==="
echo ""

# ── 1. Deploy Control Plane ──
echo "[1/3] Deploying Control Plane..."
cd apps/control-plane
fly deploy --config fly.toml \
  --region iad \
  --env ADMIN_TOKEN="$(fly secrets list | grep ADMIN_TOKEN || echo 'set via fly secrets set')"
echo "  Control Plane deployed to iad (Virginia)"

# Add Frankfurt as backup control plane
fly scale count 1 --region fra
echo "  Backup control plane added to fra (Frankfurt)"
cd ../..

# ── 2. Deploy Cluster Nodes ──
echo ""
echo "[2/3] Deploying Cluster Nodes..."

# US-East cluster
fly deploy --config fly.toml \
  --region iad \
  --env CLUSTER_ID=us-east \
  --env NODE_REGION=us-east \
  --env NODE_ROLE=cluster
echo "  Cluster us-east deployed to iad"

# Add more regions for the cluster app
fly scale count 1 --region sjc   # US-West
fly scale count 1 --region cdg   # Europe
fly scale count 1 --region nrt   # Asia
echo "  Clusters scaled to: iad, sjc, cdg, nrt"

# ── 3. Deploy Edge Nodes ──
echo ""
echo "[3/3] Deploying Edge Nodes..."
cd apps/edge
fly deploy --config fly.toml
# Scale to multiple PoPs
fly scale count 1 --region iad
fly scale count 1 --region sjc
fly scale count 1 --region cdg
fly scale count 1 --region lhr
fly scale count 1 --region nrt
fly scale count 1 --region sin
fly scale count 1 --region syd
fly scale count 1 --region gru
echo "  Edge nodes deployed to 8 regions"
cd ../..

echo ""
echo "=== Deployment Complete ==="
echo ""
echo "Topology:"
echo "  Control Plane:  iad, fra"
echo "  Clusters:       iad, sjc, cdg, nrt"
echo "  Edge Nodes:     iad, sjc, cdg, lhr, nrt, sin, syd, gru"
echo ""
echo "Verify:"
echo "  fly status -a sovereignly-control-plane"
echo "  fly status -a sovereignly"
echo "  fly status -a sovereignly-edge"
