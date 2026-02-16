# Changelog

## [1.2.0] — 2026-02-16

### Added
- Full macOS compatibility for host_audit.sh, scan_file.sh, audit_skill.sh
- macOS security checks: SIP, Gatekeeper, FileVault, Application Firewall, Remote Login
- LaunchAgent/LaunchDaemon persistence scanning (replaces Linux-only cron spool checks on macOS)
- Port scanning via `lsof` on macOS (fixes broken `netstat -tlnp` on Darwin)

### Fixed
- Cross-platform millisecond timestamps (`date +%s%3N` doesn't work on macOS)
- SSH key audit now checks `/Users/*` on macOS instead of `/home/*`
- Permissions check skips `/etc/shadow` on macOS (uses Directory Services)
- All platform-specific code degrades gracefully — no crashes if commands unavailable

## [1.1.1] — 2026-02-16

### Changed
- Removed scan_url.py and scan_vt.py from repo (VirusTotal/Safe Browsing are deferred features)
- Removed all VirusTotal/Safe Browsing references from docs, setup.sh, and generate_report.sh
- Fixed setup.md to lead with `bash setup.sh` (ClamAV installs automatically)
- Fixed ClawHub slug to `crusty-security`
- Added dashboard connection docs, comparison table, and architecture diagram to README
- Simplified scanning stack documentation to ClamAV-only

## [1.1.0] — 2026-02-16

### Changed
- Scanning stack simplified to ClamAV local scanning only
- Updated all documentation, environment variables, and command tables

## [1.0.0] — 2026-02-14

### Added
- File scanning with ClamAV (local)
- Skill auditing — static analysis for supply chain attacks (reverse shells, crypto miners, data exfiltration, obfuscation)
- Host security audit with posture scoring (0-100)
- Agent behavior monitoring (config tampering, suspicious processes, outbound connections)
- ClawHub catalog sync with blocklist checking and version drift detection
- Quarantine system with manifest tracking
- Security posture report generation
- Dashboard integration (optional — push scan results to crustysecurity.com)
- ClamAV auto-installer with environment detection (Docker, Raspberry Pi, standard Linux)
- Incremental scanning support for large workspaces
- Offline mode with graceful degradation
- Low-memory mode for Raspberry Pi / constrained environments
