# Changelog

## [1.0.0] — 2026-02-14

### Added
- File scanning with ClamAV (local) + VirusTotal (hash lookup + optional upload)
- URL scanning with VirusTotal + Google Safe Browsing
- Skill auditing — static analysis for supply chain attacks (reverse shells, crypto miners, data exfiltration, obfuscation)
- Host security audit with posture scoring (0-100)
- Agent behavior monitoring (config tampering, suspicious processes, outbound connections)
- ClawHub catalog sync with blocklist checking and version drift detection
- Quarantine system with manifest tracking
- Security posture report generation
- Dashboard integration (optional — push scan results to getclawguard.com)
- ClamAV auto-installer with environment detection (Docker, Raspberry Pi, standard Linux)
- Incremental scanning support for large workspaces
- Offline mode with graceful degradation
- Low-memory mode for Raspberry Pi / constrained environments
