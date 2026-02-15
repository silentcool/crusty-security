---
name: clawguard
version: 1.0.0
description: >
  Security and threat scanning skill for OpenClaw agents. Scans files, URLs, and
  skills for malware. Monitors agent behavior for compromise indicators. Audits host
  security posture. Triggers on: "scan this file", "check this URL", "is this safe",
  "virus scan", "malware check", "security scan", "scan for threats", "check this
  download", "quarantine", "scan my system", "threat report", "scheduled scan",
  "audit host security", "audit this skill", "check agent integrity",
  "security report", "monitor agent".
homepage: https://crustysecurity.com
metadata: {"openclaw":{"requires":{"bins":["bash","python3"]}}}
---

# Crusty Security — Security & Threat Scanning

## Overview

Crusty Security protects OpenClaw agents against real threats: malware in downloaded files, malicious URLs, compromised skills from ClawHub, data exfiltration, prompt injection payloads, and host-level compromise. It uses layered scanning (ClamAV → VirusTotal) and AI-agent-specific static analysis.

**Threat model:** The agent itself is the attack surface. Prompt injection can lead to code execution. Malicious skills run with agent privileges. Crusty Security protects both the host AND the agent's integrity.

## Quick Reference

| Task | Command |
|------|---------|
| Install ClamAV | `bash scripts/install_clamav.sh` |
| Scan a file | `bash scripts/scan_file.sh /path/to/file` |
| Scan a directory | `bash scripts/scan_file.sh -r /path/to/dir` |
| Scan a URL | `python3 scripts/scan_url.py "https://example.com"` |
| Check file on VirusTotal | `python3 scripts/scan_vt.py /path/to/file` |
| Audit a skill | `bash scripts/audit_skill.sh /path/to/skill/` |
| Host security audit | `bash scripts/host_audit.sh` |
| Monitor agent integrity | `bash scripts/monitor_agent.sh` |
| Generate security report | `bash scripts/generate_report.sh` |

All scripts output JSON. All scripts support `--help`. All paths are relative to this skill directory.

## Setup (First Run)

Run `bash setup.sh` — that's it. ClamAV installs automatically if missing, including on first scan.

Optional environment variables for cloud scanning:
- `VIRUSTOTAL_API_KEY` — free at virustotal.com (4 req/min, 500/day)
- `GOOGLE_SAFE_BROWSING_KEY` — free via Google Cloud Console

See `references/setup.md` for detailed configuration.

## Scanning Workflows

### File Scanning

**Triggers:** "scan this file", "is this safe", "check this download", "virus scan"

1. Run `bash scripts/scan_file.sh <path>` for ClamAV local scan
2. If ClamAV flags something OR user wants extra confidence, escalate:
   `python3 scripts/scan_vt.py <path>` (hash lookup only — no file upload by default)
3. Report results:
   - ✅ Clean — "No threats detected. Scanned with ClamAV, signatures from [date]."
   - ⚠️ Suspicious — "Low-confidence detection by ClamAV. Cross-checking with VirusTotal..."
   - 🚨 Malicious — "Threat detected: [name]. Recommend quarantine. Options: quarantine, delete, or ignore."

**For directories:**
```bash
bash scripts/scan_file.sh -r /data/workspace      # Full recursive scan
bash scripts/scan_file.sh -r --incremental /data/workspace  # Skip unchanged files
```

**Quarantine workflow:**
```bash
bash scripts/scan_file.sh --quarantine /path/to/file   # Move to quarantine
# Quarantine location: $CLAWGUARD_QUARANTINE (default: /tmp/clawguard_quarantine)
# Manifest: /tmp/clawguard_quarantine/manifest.json
```

**Important notes:**
- ClamAV prefers clamdscan (daemon) when available, falls back to clamscan
- Max file size default: 200M (configurable via `CLAWGUARD_MAX_FILE_SIZE`)
- Encrypted archives: flagged as "unscanned" — cannot inspect contents
- Large archives: ClamAV handles zip, rar, 7z, tar, gz natively

### URL Scanning

**Triggers:** "is this URL safe", "check this link", "scan this URL"

1. Run `python3 scripts/scan_url.py "<url>"`
2. Checks VirusTotal (70+ engines) and Google Safe Browsing
3. Automatically resolves shortened URLs (bit.ly, t.co, etc.) — checks each URL in the redirect chain
4. Batch mode: `python3 scripts/scan_url.py url1 url2 url3`

**Graceful degradation:**
- No API keys → warns user, suggests manual check
- Only one key → uses available service
- Rate limited → reports rate limit, suggests retry

**Report format:**
- ✅ Clean — "URL is clean across [N] engines."
- ⚠️ Suspicious — "[N] engines flagged this URL. Proceed with caution."
- 🚨 Malicious — "URL is flagged as malicious. Threats: [types]. Do NOT visit."

### VirusTotal File Scanning

**Triggers:** "deep scan", "check on VirusTotal", "is this really safe"

`python3 scripts/scan_vt.py /path/to/file`

**Privacy-first approach:**
1. Computes SHA256 hash locally
2. Looks up hash on VirusTotal (file never leaves the machine)
3. If hash unknown: reports "not found" — offers upload only with explicit user consent (`--upload`)
4. **⚠️ NEVER auto-upload files.** VirusTotal shares uploads with 70+ security vendors.

**Severity classification:**
- Clean: 0 detections
- Low: <10% detection rate (likely false positive)
- Medium: 10-30% detection rate
- High: 30-60% detection rate
- Critical: >60% detection rate

**Rate limiting:** Built-in rate limiter for free tier (4 req/min). Waits automatically when hitting limits.

### Skill Auditing (Supply Chain Security)

**Triggers:** "audit this skill", "is this skill safe", "check skill security", "scan skill"

`bash scripts/audit_skill.sh /path/to/skill/directory/`

**What it checks:**
- 🔴 **Critical:** curl/wget piped to shell, reverse shell patterns, crypto mining indicators
- 🟠 **High:** eval/exec with dynamic input, base64 decode patterns, data exfiltration endpoints (webhook.site, ngrok, etc.), credential harvesting, binary executables, agent config modification
- 🟡 **Medium:** hidden files, system file access, hardcoded IPs, obfuscated code, persistence mechanisms (cron, systemd)
- 🔵 **Low/Info:** large skill size, credential references in docs

**Output:** Risk score (low/medium/high/critical) + detailed findings with evidence.

**When to use:**
- Before installing any skill from ClawHub
- When reviewing third-party skill contributions
- Periodically on all installed skills: `for d in /data/workspace/skills/*/; do bash scripts/audit_skill.sh "$d"; done`

### Host Security Audit

**Triggers:** "audit host", "security audit", "check host security"

`bash scripts/host_audit.sh` or `bash scripts/host_audit.sh --deep`

**Checks:**
- Suspicious cron jobs (curl piping, base64, reverse shells)
- Unexpected listening ports
- Recently modified system files (deep mode)
- SSH key audit (excessive keys, no-comment keys, root login)
- Sensitive file permissions (world-writable /etc/passwd, etc.)
- ClamAV signature freshness
- `openclaw security audit` (if available)

**Output:** Posture score (0-100) + findings. Score deductions: critical (-25), high (-15), medium (-10), low (-5).

### Agent Behavior Monitoring

**Triggers:** "check agent integrity", "monitor agent", "is the agent compromised"

`bash scripts/monitor_agent.sh`

**What it checks:**
- Recent modifications to AGENTS.md, SOUL.md, MEMORY.md, TOOLS.md, USER.md
- Memory file churn (>10 files modified = suspicious)
- Unexpected cron jobs (anything not clawguard/freshclam/standard maintenance)
- Suspicious outbound connections (IRC ports, backdoor ports, Tor)
- Files created outside workspace (/tmp executables, home directory changes)
- Suspicious processes (xmrig, nc -l, ncat, socat, chisel)
- High CPU processes (>80% — potential miners)
- Sensitive file exposure (.env files, world-readable SSH keys)

**Output:** Status (healthy / warnings_present / compromised_indicators) + findings.

### Security Report Generation

**Triggers:** "security report", "threat report", "posture report"

`bash scripts/generate_report.sh` or `bash scripts/generate_report.sh --days 30 --output report.md`

Compiles all recent scan results into a markdown security posture report with:
- Scan summary (total, clean, threats, errors)
- Threat details with file paths and actions taken
- Security posture score with emoji indicators
- Recommendations (missing tools, API keys, scan schedules)

## Scheduled Scanning

Set up recurring scans using OpenClaw cron:

| Schedule | What | Command |
|----------|------|---------|
| Daily 3am | Workspace scan (incremental) | `bash scripts/scan_file.sh --incremental -r /data/workspace` |
| Weekly Sunday 3am | Full workspace scan | `bash scripts/scan_file.sh -r /data/workspace` |
| Daily | Agent integrity check | `bash scripts/monitor_agent.sh` |
| Weekly | Host audit | `bash scripts/host_audit.sh` |
| Monthly | Deep host audit | `bash scripts/host_audit.sh --deep` |
| Weekly | All skills audit | `for d in skills/*/; do bash scripts/audit_skill.sh "$d"; done` |
| Weekly | Security report | `bash scripts/generate_report.sh --output /tmp/clawguard_logs/weekly_report.md` |

## False Positive Handling

ClamAV has moderate false positive rates. Strategy:

1. **Single ClamAV detection, VT clean → Likely false positive.** Log and skip.
2. **ClamAV + VT 1-3 engines → Probably false positive.** Quarantine, monitor.
3. **ClamAV + VT 5+ engines → Real threat.** Quarantine immediately.
4. **VT 15+ engines → Confirmed malicious.** Quarantine + incident response.

**To whitelist a false positive:**
- Verify via VirusTotal hash lookup
- Submit to ClamAV: https://www.clamav.net/reports/fp
- Document in scan logs for future reference

## Quarantine Procedures

**Location:** `$CLAWGUARD_QUARANTINE` (default: `/tmp/clawguard_quarantine`)
**Manifest:** `manifest.json` in quarantine directory tracks original paths and timestamps.

```bash
# View quarantined files
cat /tmp/clawguard_quarantine/manifest.json | python3 -m json.tool

# Restore a false positive
mv /tmp/clawguard_quarantine/<file> /original/path/

# Permanently delete
rm -rf /tmp/clawguard_quarantine/*
```

**Never use `clamscan --remove`.** Always quarantine first, verify, then delete.

## Offline Mode

ClawGuard works fully offline with reduced capability:
- ✅ ClamAV scanning (local signatures)
- ✅ Skill auditing (static analysis, no network needed)
- ✅ Host auditing (local checks)
- ✅ Agent monitoring (local checks)
- ❌ VirusTotal lookups (queued for later)
- ❌ Google Safe Browsing (degraded)
- ⚠️ ClamAV signatures may be stale (check freshness in host audit)

## Resource-Constrained Environments (Raspberry Pi)

For hosts with <2GB RAM:
- `install_clamav.sh` auto-detects low RAM and skips daemon mode
- Use `clamscan` (on-demand) instead of `clamd` (daemon)
- Use incremental scanning (`--incremental`) to reduce scan time
- Rely more on VirusTotal hash lookups than local scanning
- Skill auditing and agent monitoring have minimal resource requirements

For hosts with <1GB RAM:
- Consider skipping ClamAV entirely
- Use skill auditing + VirusTotal hash lookups + agent monitoring only
- These tools are shell/Python with negligible memory usage

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VIRUSTOTAL_API_KEY` | (none) | VirusTotal API key |
| `GOOGLE_SAFE_BROWSING_KEY` | (none) | Google Safe Browsing key |
| `CLAWGUARD_QUARANTINE` | `/tmp/clawguard_quarantine` | Quarantine directory |
| `CLAWGUARD_LOG_DIR` | `/tmp/clawguard_logs` | Scan log directory |
| `CLAWGUARD_MAX_FILE_SIZE` | `200M` | Max file size to scan |
| `CLAWGUARD_WORKSPACE` | `/data/workspace` | Agent workspace path |

## Incident Response

When a real threat is confirmed, see `references/remediation.md` for the full checklist. Quick summary:

1. **Quarantine** the file immediately
2. **Assess scope** — was it executed? Did it modify other files?
3. **Check persistence** — cron jobs, SSH keys, shell profiles, systemd services
4. **Check exfiltration** — outbound connections, DNS queries, API key usage
5. **Rotate credentials** if any were potentially exposed
6. **Full scan** — `bash scripts/scan_file.sh -r /`
7. **Document** the incident
