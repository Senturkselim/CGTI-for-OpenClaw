# Changelog

All notable changes to CGTI Lite for OpenClaw will be documented in this file.

## [1.2.1] — 2026-03-29

### Fixed
- **Autostart IPS mode not working on Linux**: System's `suricata.service` starts Suricata in IDS mode before `cgti-lite.service` runs — CGTI now detects this, stops the IDS instance, and restarts Suricata in full IPS mode (NFQUEUE + iptables + drop rules)
- **Autostart Enhanced Autoblock not activating on Linux**: When system Suricata was already running, `cmd_start --silent` exited silently without spawning the autoblock daemon — now correctly spawns the daemon in IDS mode
- **Autostart systemd `Type=forking` incorrect**: Changed to `Type=oneshot` + `RemainAfterExit=yes` — Python script starts Suricata and exits cleanly, systemd tracks the service as active
- **Autostart macOS launchd restart loop**: Removed `KeepAlive > SuccessfulExit: false` which caused launchd to endlessly restart the script after clean exit
- **Autostart interface hardcoded in service files**: Interface is now read from config at runtime — changing the interface no longer requires re-running `autostart enable`
- **Autoblock daemon wrote to `/usr/local/bin/`**: Wrapper script moved to `/tmp/cgti-autoblock.sh`; replaced `os.system("nohup ... &")` with proper `subprocess.Popen` + `os.setpgrp` for clean process detachment
- **Windows VBS launcher quoting**: Simplified command string by removing hardcoded interface parameter
- **`install.sh` failing on Ubuntu without `python3-venv`**: Installer now auto-detects the package manager (apt/dnf/yum/pacman) and installs the missing venv package automatically, with `--without-pip` + `get-pip.py` as final fallback

### Changed
- Autostart service files no longer contain `-i <interface>` — interface is always read from `config.json` at boot time
- Autostart enable output now shows `Interface: ens192 (read from config at boot)` to clarify runtime resolution
- Version bumped to 1.2.1

## [1.2.0] — 2026-03-17

### Added
- **Enhanced Autoblock** — rebranded autoblock system with intelligent blocking
  - DNS domain-based blocking: extracts domain from alert signature, resolves it via system DNS, and blocks the real IP (not the DNS server)
  - Bidirectional firewall rules: blocks both inbound and outbound traffic for blocked IPs (C2/exfiltration prevention)
  - Severity threshold: configurable via `cgti config set cgti.autoblock_min_severity` (1-4, default 3 = Critical+High+Medium)
  - Private IP protection: RFC1918/CGNAT addresses are never auto-blocked as destination
  - DNS server protection: port 53 traffic destinations are never auto-blocked
  - Non-blockable IP guard: loopback, broadcast, multicast, link-local addresses protected
  - Auto-whitelist configured DNS servers from `suricata.dns_servers` config
  - Blocked IP counter shown in live monitoring summary
- Autoblock severity row in `cgti status` output
- Enhanced Autoblock configuration section in `cgti -h` help text
- `.gitignore` for repository
- `CHANGELOG.md`

### Fixed
- **Windows autostart console window**: Suricata now starts with `CREATE_NO_WINDOW` flag in silent/autostart mode — no more empty cmd.exe window on boot
- **`cgti logs` showing "No alerts found"**: Progressive search depth (20x → 80x → 200x) ensures alerts buried under stats/flow events are always found
- **`blocked remove` not working on Windows**: Fixed netsh delete syntax (was passing extra parameters); added backward compatibility with old `CGTI_BLOCK_` rule name format
- **SYN-only Suricata warnings**: Added `flow:to_server;` to 4 rules (SID 9202911, 9200804, 9200821, 9202035) that caused "SYN-only w/o direction specified" warnings
- **`cgti status` hint text**: Changed `Start: cgti start -i` to `Start: cgti start`
- **Eve.json log rotation**: Live monitoring detects file rotation and reopens the log automatically

### Changed
- "Autoblock" rebranded to "Enhanced Autoblock" across all UI text
- `cgti status` Mode field now shows `IDS + Enhanced Autoblock` or `IPS + Enhanced Autoblock` when active
- Firewall rules are now bidirectional on all platforms (Linux iptables, macOS pf, Windows netsh)
- Version bumped to 1.2.0

## [1.1.0] — 2026-03-16

### Added
- Autostart CLI wiring (`cgti autostart enable/disable/status`)
- Silent mode (`--silent` flag) for autostart — no interactive prompts
- Windows silent autostart via VBS wrapper + Task Scheduler
- Autoblock preference persistence in config (`cgti.autoblock`)
- FUNDING.yml for GitHub Sponsors + Open Collective
- False positive optimizations (6 rules across 2 files)

### Fixed
- Format consistency: DNS and TLS rule files converted to single-line format
- Date fix: 2025 → 2026 in DNS and TLS rule file headers
- README.md complete rewrite with correct SID ranges (493 lines)
- Autostart triggered interactive mode prompt (fixed with `--silent`)

## [1.0.0] — 2026-03-15

### Added
- Initial release: 648 rules across 13 categories
- Single-file Python application (`cgti_lite.py`, ~3000 lines)
- Cross-platform support: Windows, macOS, Linux
- Suricata IDS/IPS management with install wizard
- Live alert monitoring (`cgti live`)
- IP blocking with firewall integration (`cgti blocked`)
- Rule management (`cgti rules`)
- 33 unit tests (`test_cgti.py`)
- Platform-specific installers (`install.sh`, `install.bat`)
