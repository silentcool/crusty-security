#!/usr/bin/env bash
# Crusty Security — One-command setup
# Usage: bash setup.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}🦀 Crusty Security — Setup${NC}"
echo ""

# 1. Check Python 3
if command -v python3 &>/dev/null; then
  echo -e "  ✅ Python 3 found ($(python3 --version 2>&1 | awk '{print $2}'))"
else
  echo -e "  ${RED}❌ Python 3 not found. Install it first.${NC}"
  exit 1
fi

# 2. Check/install ClamAV
if command -v clamscan &>/dev/null || command -v clamdscan &>/dev/null; then
  echo -e "  ✅ ClamAV already installed"
else
  echo -e "  ${YELLOW}📦 Installing ClamAV...${NC}"
  bash "$SCRIPT_DIR/scripts/install_clamav.sh"
  echo -e "  ✅ ClamAV installed"
fi

# 2b. Fix freshclam config on macOS (Homebrew leaves example config that blocks freshclam)
if [[ "$(uname)" == "Darwin" ]]; then
  for prefix in /opt/homebrew /usr/local; do
    SAMPLE="$prefix/etc/clamav/freshclam.conf.sample"
    CONF="$prefix/etc/clamav/freshclam.conf"
    if [[ -f "$SAMPLE" && ! -f "$CONF" ]]; then
      cp "$SAMPLE" "$CONF"
      sed -i '' 's/^Example/#Example/' "$CONF" 2>/dev/null || true
      echo -e "  ✅ freshclam.conf configured ($prefix)"
    elif [[ -f "$CONF" ]] && grep -q "^Example" "$CONF" 2>/dev/null; then
      sed -i '' 's/^Example/#Example/' "$CONF" 2>/dev/null || true
      echo -e "  ✅ freshclam.conf fixed ($prefix)"
    fi
  done
fi

# 3. Ensure scripts are executable
chmod +x "$SCRIPT_DIR"/scripts/*.sh "$SCRIPT_DIR"/scripts/*.py 2>/dev/null || true
echo -e "  ✅ Scripts ready"

# 4. Create data directories
mkdir -p /tmp/clawguard_logs /tmp/clawguard_quarantine /tmp/clawguard_data 2>/dev/null || true
echo -e "  ✅ Data directories created"

# 5. Quick verification scan
echo ""
echo -e "  ${YELLOW}🔍 Running verification scan...${NC}"
RESULT=$(bash "$SCRIPT_DIR/scripts/scan_file.sh" "$SCRIPT_DIR/SKILL.md" 2>/dev/null || echo '{"status":"error"}')
if echo "$RESULT" | grep -q '"clean"'; then
  echo -e "  ✅ Scanner working — verification scan clean"
else
  echo -e "  ${YELLOW}⚠️  Scanner returned unexpected result (ClamAV may still be updating signatures)${NC}"
fi

# 6. Dashboard integration — auto-register on first install
if [[ -n "${CRUSTY_API_KEY:-}" ]]; then
  CLAWGUARD_DASHBOARD_URL="${CLAWGUARD_DASHBOARD_URL:-https://crustysecurity.com}"
  export CRUSTY_API_KEY CLAWGUARD_DASHBOARD_URL CLAWGUARD_API_KEY="${CRUSTY_API_KEY}"
  echo -e "  ${YELLOW}📡 Dashboard integration detected — registering agent...${NC}"

  # Send initial heartbeat (populates hostname, OS, architecture, OpenClaw version)
  if bash "$SCRIPT_DIR/scripts/dashboard.sh" heartbeat >/dev/null 2>&1; then
    echo -e "  ✅ Heartbeat sent — agent registered in dashboard"
  else
    echo -e "  ${YELLOW}⚠️  Heartbeat failed (dashboard may be unreachable)${NC}"
  fi

  # Run initial host audit (populates posture score + first scan)
  echo -e "  ${YELLOW}🔍 Running initial host security audit...${NC}"
  if bash "$SCRIPT_DIR/scripts/host_audit.sh" >/dev/null 2>&1; then
    echo -e "  ✅ Host audit complete — results pushed to dashboard"
  else
    echo -e "  ${YELLOW}⚠️  Host audit completed with warnings${NC}"
  fi

  # Run initial workspace scan (populates scan history)
  echo -e "  ${YELLOW}🔍 Running initial workspace scan...${NC}"
  if bash "$SCRIPT_DIR/scripts/scan_file.sh" -r "${CLAWGUARD_SCAN_DIR:-/data/workspace}" >/dev/null 2>&1; then
    echo -e "  ✅ Workspace scan complete — results pushed to dashboard"
  else
    echo -e "  ${YELLOW}⚠️  Workspace scan completed with warnings${NC}"
  fi

  echo ""
  echo -e "  ${GREEN}📊 Dashboard: ${CLAWGUARD_DASHBOARD_URL}/dashboard${NC}"
else
  echo ""
  echo -e "  ${YELLOW}ℹ️  No CRUSTY_API_KEY set — running in local-only mode${NC}"
  echo "  To connect to the dashboard: export CRUSTY_API_KEY=cg_live_..."
fi

echo ""
echo -e "${GREEN}🦀 Crusty Security is ready.${NC}"
echo ""
echo "  Scan a file:     bash scripts/scan_file.sh /path/to/file"
echo "  Scan workspace:  bash scripts/scan_file.sh -r /data/workspace"
echo "  Audit a skill:   bash scripts/audit_skill.sh /path/to/skill/"
echo "  Host audit:      bash scripts/host_audit.sh"
echo ""
