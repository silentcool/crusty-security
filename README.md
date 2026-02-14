# ClawGuard Security 🛡️

**On-host security monitoring for OpenClaw AI agents.** Scans files, URLs, and skills for malware. Monitors agent behavior for compromise indicators. Audits host security posture.

[![ClawHub](https://img.shields.io/badge/ClawHub-clawguard--security-emerald)](https://clawhub.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE.txt)

---

## Why Your Agent Needs This

AI agents download files, install skills, and execute code — all with your system privileges. A single prompt injection can lead to:

- 🦠 **Malware execution** via downloaded files or malicious skill scripts
- 🔗 **Data exfiltration** through hidden webhook calls or reverse shells
- 🧬 **Supply chain attacks** from compromised ClawHub skills
- 🔑 **Credential theft** from exposed `.env` files and API keys
- 🧠 **Agent hijacking** via modified SOUL.md, AGENTS.md, or MEMORY.md

ClawGuard is the first security skill built specifically for the OpenClaw agent threat model.

## Features

| Feature | Description |
|---------|-------------|
| **File Scanning** | ClamAV local scan → VirusTotal escalation (70+ engines) |
| **URL Scanning** | VirusTotal + Google Safe Browsing, auto-resolves shortened URLs |
| **Skill Auditing** | Static analysis for reverse shells, crypto miners, data exfiltration, obfuscation |
| **Host Audit** | Cron jobs, open ports, SSH keys, file permissions, posture scoring (0-100) |
| **Agent Monitoring** | Detects modified config files, suspicious processes, unexpected outbound connections |
| **ClawHub Sync** | Tracks installed skill versions against ClawHub catalog, blocklist checking |
| **Quarantine** | Isolate threats with manifest tracking, never auto-deletes |
| **Reports** | Markdown security posture reports with recommendations |

## Quick Start

### 1. Install

```bash
# Via ClawHub (recommended)
clawhub install clawguard-security

# Or clone directly
git clone https://github.com/silentcool/clawguard-security.git skills/clawguard
```

### 2. Set Up ClamAV

```bash
bash scripts/install_clamav.sh
```

This auto-detects your environment (Docker, Raspberry Pi, standard Linux) and installs + configures ClamAV appropriately. Takes ~2 minutes.

### 3. Start Scanning

```bash
# Scan a file
bash scripts/scan_file.sh /path/to/suspicious-file.pdf

# Scan your entire workspace
bash scripts/scan_file.sh -r /data/workspace

# Check a URL before visiting
python3 scripts/scan_url.py "https://sketchy-download.com/agent-skill.tar.gz"

# Audit a skill before installing
bash scripts/audit_skill.sh /path/to/skill/

# Full host security audit
bash scripts/host_audit.sh
```

That's it. ClawGuard works immediately with ClamAV alone — no API keys required.

## Optional: Cloud Scanning

For deeper analysis, add these environment variables:

```bash
# VirusTotal — free at virustotal.com (4 req/min, 500/day)
export VIRUSTOTAL_API_KEY="your-key-here"

# Google Safe Browsing — free via Google Cloud Console
export GOOGLE_SAFE_BROWSING_KEY="your-key-here"
```

**Privacy note:** ClawGuard never uploads files to VirusTotal — it only sends SHA256 hashes for lookup. File upload requires explicit `--upload` flag.

## Optional: Dashboard

Connect to [ClawGuard Dashboard](https://getclawguard.com) for centralized monitoring across multiple agents:

```bash
export CLAWGUARD_API_KEY="cg_live_xxxxx"
export CLAWGUARD_DASHBOARD_URL="https://getclawguard.com"
```

The dashboard provides:
- Real-time agent status and health monitoring
- Scan history and threat timelines
- Installed skills inventory with ClawHub version tracking
- Alert management (email + Slack notifications)
- Multi-agent fleet overview

The skill is **fully functional without the dashboard** — it's optional for users who want centralized visibility.

## All Commands

| Command | Description |
|---------|-------------|
| `bash scripts/install_clamav.sh` | Install and configure ClamAV |
| `bash scripts/scan_file.sh <path>` | Scan a file with ClamAV |
| `bash scripts/scan_file.sh -r <dir>` | Recursive directory scan |
| `bash scripts/scan_file.sh --incremental -r <dir>` | Skip unchanged files |
| `bash scripts/scan_file.sh --quarantine <path>` | Quarantine a file |
| `python3 scripts/scan_url.py "<url>"` | Check URL safety |
| `python3 scripts/scan_url.py url1 url2 url3` | Batch URL scan |
| `python3 scripts/scan_vt.py <path>` | VirusTotal hash lookup |
| `python3 scripts/scan_vt.py --upload <path>` | Upload to VT (explicit only) |
| `bash scripts/audit_skill.sh <dir>` | Audit a skill for threats |
| `bash scripts/host_audit.sh` | Host security audit |
| `bash scripts/host_audit.sh --deep` | Deep host audit (includes file modifications) |
| `bash scripts/monitor_agent.sh` | Agent behavior integrity check |
| `bash scripts/generate_report.sh` | Generate security posture report |
| `python3 scripts/clawhub_sync.py` | Sync installed skills against ClawHub catalog |

All commands output JSON. All support `--help`.

## Scanning Stack

```
                    ┌──────────────────┐
   File arrives →   │  ClamAV (local)  │  ← Free, instant, 90% coverage
                    └────────┬─────────┘
                             │ flagged or escalation requested
                    ┌────────▼─────────┐
                    │ VirusTotal (hash) │  ← 70+ engines, hash only
                    └────────┬─────────┘
                             │ hash unknown + user consents
                    ┌────────▼─────────┐
                    │ VirusTotal (file) │  ← Full analysis, explicit opt-in
                    └──────────────────┘
```

For URLs:
```
   URL arrives → VirusTotal (70+ engines) + Google Safe Browsing
                 ↳ auto-resolves shortened URLs (bit.ly, t.co, etc.)
```

## Skill Auditing — What It Catches

Static analysis specifically tuned for the OpenClaw threat model:

| Severity | Pattern |
|----------|---------|
| 🔴 Critical | `curl \| sh`, reverse shell patterns, crypto mining indicators |
| 🟠 High | `eval`/`exec` with dynamic input, base64 decode chains, webhook.site/ngrok exfil, credential harvesting, binaries in skill dirs |
| 🟡 Medium | Hidden files, system file access, hardcoded IPs, obfuscated code, persistence mechanisms (cron, systemd) |
| 🔵 Info | Large skill size, credential references in docs |

## Host Audit Scoring

The host audit produces a posture score from 0-100:

| Score | Rating | Meaning |
|-------|--------|---------|
| 90-100 | 🟢 Excellent | Minimal risk |
| 70-89 | 🟡 Good | Minor issues to address |
| 50-69 | 🟠 Fair | Several findings, take action |
| 0-49 | 🔴 Poor | Significant security issues |

Deductions: Critical (-25), High (-15), Medium (-10), Low (-5).

## Agent Behavior Monitoring

Detects indicators of agent compromise:

- Modified `AGENTS.md`, `SOUL.md`, `MEMORY.md`, `TOOLS.md` (config tampering)
- Unexpected cron jobs or scheduled tasks
- Suspicious outbound connections (IRC, Tor, backdoor ports)
- Files created outside workspace (`/tmp` executables, home directory changes)
- Suspicious processes (crypto miners, netcat listeners, tunneling tools)
- Exposed credentials (world-readable `.env` files, SSH keys)

## ClawHub Supply Chain Monitoring

The `clawhub_sync.py` script protects against malicious or compromised skills:

- Fetches the full ClawHub catalog (400+ skills)
- Compares installed skill versions against latest
- Checks against a blocklist of known-bad skills
- Flags skills not found on ClawHub (potential forks or custom builds)
- Detects version drift across multiple agents
- Pushes results to the dashboard (if configured)

```bash
# One-time sync
python3 scripts/clawhub_sync.py

# JSON output (for automation)
python3 scripts/clawhub_sync.py --json

# With dashboard push
python3 scripts/clawhub_sync.py --push
```

## Recommended Scan Schedule

| Frequency | Scan | Purpose |
|-----------|------|---------|
| Every 5 min | Heartbeat | Dashboard agent status |
| Daily | `scan_file.sh --incremental -r /data/workspace` | Catch new threats |
| Daily | `monitor_agent.sh` | Detect behavior changes |
| Weekly | `scan_file.sh -r /data/workspace` | Full scan |
| Weekly | `host_audit.sh` | Host posture check |
| Weekly | Audit all skills | Supply chain monitoring |
| 12 hours | `clawhub_sync.py --push` | ClawHub catalog sync |
| Monthly | `host_audit.sh --deep` | Deep system audit |

## Requirements

- **OS:** Linux (tested on Debian/Ubuntu, works in Docker)
- **Python:** 3.8+
- **ClamAV:** Installed via `install_clamav.sh` or manually
- **Optional:** VirusTotal API key, Google Safe Browsing API key
- **Disk:** ~300MB for ClamAV signatures

### Raspberry Pi / Low Memory

- `<2GB RAM`: Runs in on-demand mode (no ClamAV daemon)
- `<1GB RAM`: Skip ClamAV, use VirusTotal hash lookups + skill auditing + agent monitoring
- All non-ClamAV tools are lightweight shell/Python scripts

## Environment Variables

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `VIRUSTOTAL_API_KEY` | — | No | VirusTotal API key for deep scanning |
| `GOOGLE_SAFE_BROWSING_KEY` | — | No | Google Safe Browsing API key |
| `CLAWGUARD_API_KEY` | — | No | Dashboard API key (from getclawguard.com) |
| `CLAWGUARD_DASHBOARD_URL` | — | No | Dashboard URL |
| `CLAWGUARD_QUARANTINE` | `/tmp/clawguard_quarantine` | No | Quarantine directory |
| `CLAWGUARD_LOG_DIR` | `/tmp/clawguard_logs` | No | Scan log directory |
| `CLAWGUARD_MAX_FILE_SIZE` | `200M` | No | Max file size for scanning |
| `CLAWGUARD_WORKSPACE` | `/data/workspace` | No | Agent workspace path |

## File Structure

```
clawguard/
├── SKILL.md              # Agent instructions (OpenClaw reads this)
├── README.md             # Human documentation (you're reading it)
├── LICENSE.txt           # MIT License
├── CHANGELOG.md          # Version history
├── scripts/
│   ├── install_clamav.sh     # ClamAV installer
│   ├── scan_file.sh          # File/directory scanner
│   ├── scan_url.py           # URL safety checker
│   ├── scan_vt.py            # VirusTotal integration
│   ├── audit_skill.sh        # Skill static analysis
│   ├── host_audit.sh         # Host security audit
│   ├── monitor_agent.sh      # Agent behavior monitoring
│   ├── generate_report.sh    # Security report generator
│   ├── clawhub_sync.py       # ClawHub catalog sync
│   └── dashboard.sh          # Dashboard integration library
└── references/
    ├── setup.md              # Detailed setup guide
    ├── threat-patterns.md    # Threat pattern database
    └── remediation.md        # Incident response procedures
```

## Offline Mode

ClawGuard works fully offline with reduced capability:

| Feature | Offline | Online |
|---------|---------|--------|
| ClamAV file scanning | ✅ (local signatures) | ✅ (fresh signatures) |
| Skill auditing | ✅ (static analysis) | ✅ |
| Host auditing | ✅ | ✅ |
| Agent monitoring | ✅ | ✅ |
| VirusTotal | ❌ queued | ✅ |
| Safe Browsing | ❌ | ✅ |
| ClawHub sync | ❌ | ✅ |

## Contributing

Issues and PRs welcome at [github.com/silentcool/clawguard-security](https://github.com/silentcool/clawguard-security).

## License

MIT — see [LICENSE.txt](LICENSE.txt).

## Links

- 🌐 **Dashboard:** [getclawguard.com](https://getclawguard.com)
- 📦 **ClawHub:** [clawhub.com](https://clawhub.com) (search "clawguard-security")
- 🐙 **GitHub:** [github.com/silentcool/clawguard-security](https://github.com/silentcool/clawguard-security)
- 🦀 **Built by:** [Black Matter VC](https://blackmatter.vc)
