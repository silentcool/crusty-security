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

echo ""
echo -e "${GREEN}🦀 Crusty Security is ready.${NC}"
echo ""
echo "  Scan a file:     bash scripts/scan_file.sh /path/to/file"
echo "  Scan workspace:  bash scripts/scan_file.sh -r /data/workspace"
echo "  Audit a skill:   bash scripts/audit_skill.sh /path/to/skill/"
echo "  Host audit:      bash scripts/host_audit.sh"
echo ""
echo "  Optional: Set CRUSTY_API_KEY and CRUSTY_DASHBOARD_URL for dashboard integration."
echo ""
