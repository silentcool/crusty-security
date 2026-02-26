#!/usr/bin/env bash
# Crusty Security — Auto-install cron jobs via OpenClaw CLI
# Usage: bash install_crons.sh [--force]
# Idempotent: skips jobs that already exist (matched by name prefix "crusty-")
# Pass --force to recreate all jobs (removes existing crusty-* jobs first)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SKILL_DIR="$(dirname "$SCRIPT_DIR")"
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

FORCE=false
[[ "${1:-}" == "--force" ]] && FORCE=true

echo -e "${GREEN}🦀 Crusty Security — Installing cron jobs${NC}"
echo ""

# Check openclaw CLI exists
if ! command -v openclaw &>/dev/null; then
  echo -e "${RED}❌ openclaw CLI not found. Cannot install cron jobs.${NC}"
  exit 1
fi

# Get existing crusty-* jobs
EXISTING=$(openclaw cron list --json 2>/dev/null | python3 -c "
import sys, json
try:
    jobs = json.load(sys.stdin).get('jobs', [])
    for j in jobs:
        name = j.get('name', '')
        if name.lower().startswith('crusty-'):
            print(f\"{j['id']}|{name}\")
except: pass
" 2>/dev/null || true)

if [[ "$FORCE" == "true" && -n "$EXISTING" ]]; then
  echo -e "${YELLOW}🗑  --force: removing existing crusty-* jobs${NC}"
  while IFS='|' read -r job_id job_name; do
    openclaw cron rm "$job_id" 2>/dev/null && echo "  Removed: $job_name" || true
  done <<< "$EXISTING"
  EXISTING=""
fi

# Helper: check if a job name already exists
job_exists() {
  echo "$EXISTING" | grep -qi "|$1$" 2>/dev/null
}

# Helper: create a cron job
create_job() {
  local name="$1" cron_expr="$2" session="$3" payload_flag="$4" payload="$5" timeout="${6:-30000}"
  if job_exists "$name"; then
    echo -e "  ⏭  ${name} — already exists, skipping"
    return 0
  fi
  if openclaw cron add \
    --name "$name" \
    --cron "$cron_expr" \
    --session "$session" \
    $payload_flag "$payload" \
    --timeout "$timeout" \
    2>/dev/null; then
    echo -e "  ✅ ${name} — created"
  else
    echo -e "  ${RED}❌ ${name} — failed to create${NC}"
    return 1
  fi
}

SCAN_DIR="${CLAWGUARD_WORKSPACE:-/data/workspace}"
ERRORS=0

# 1. Heartbeat (every hour) — sends agent status to the Crusty Security dashboard
create_job \
  "crusty-heartbeat" \
  "0 * * * *" \
  "main" \
  "--system-event" \
  "You have Crusty Security installed at ${SKILL_DIR}. Use your bash/exec tool to run: bash ${SKILL_DIR}/scripts/dashboard.sh heartbeat. Summarize the JSON output briefly. If it fails, report the error. No user interaction needed. This is an automated scan." \
  "30000" || ((ERRORS++))

# 2. Daily scan (3 AM UTC) — incremental workspace scan + agent monitor
create_job \
  "crusty-daily-scan" \
  "0 3 * * *" \
  "main" \
  "--system-event" \
  "You have Crusty Security installed at ${SKILL_DIR}. Use your bash/exec tool to run: bash ${SKILL_DIR}/scripts/scan_file.sh --incremental -r ${SCAN_DIR} && bash ${SKILL_DIR}/scripts/monitor_agent.sh. Summarize the JSON output briefly. If it fails, report the error. No user interaction needed. This is an automated scan." \
  "120000" || ((ERRORS++))

# 3. Weekly full scan (Sunday 3 AM UTC) — full scan + host audit + report
create_job \
  "crusty-weekly-full" \
  "0 3 * * 0" \
  "main" \
  "--system-event" \
  "You have Crusty Security installed at ${SKILL_DIR}. Use your bash/exec tool to run: bash ${SKILL_DIR}/scripts/scan_file.sh -r ${SCAN_DIR} && bash ${SKILL_DIR}/scripts/host_audit.sh && bash ${SKILL_DIR}/scripts/generate_report.sh --output /tmp/clawguard_logs/weekly_report.md. Summarize the JSON output briefly. If it fails, report the error. No user interaction needed. This is an automated scan." \
  "300000" || ((ERRORS++))

# 4. Monthly deep audit (1st of month, 4 AM UTC)
create_job \
  "crusty-monthly-deep" \
  "0 4 1 * *" \
  "main" \
  "--system-event" \
  "You have Crusty Security installed at ${SKILL_DIR}. Use your bash/exec tool to run: bash ${SKILL_DIR}/scripts/host_audit.sh --deep. Summarize the JSON output briefly. If it fails, report the error. No user interaction needed. This is an automated scan." \
  "300000" || ((ERRORS++))

echo ""
if [[ $ERRORS -eq 0 ]]; then
  echo -e "${GREEN}🦀 All cron jobs installed. No questions asked.${NC}"
else
  echo -e "${YELLOW}⚠️  Installed with $ERRORS error(s). Check above.${NC}"
fi
