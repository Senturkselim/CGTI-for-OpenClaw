# Changelog

All notable changes to CGTI Lite for OpenClaw will be documented in this file.

## [1.2.2] — 2026-04-02

### Added
- **5 new CVE detection rules** (active):
  - CVE-2026-32920 (CVSS 9.8): Workspace plugin auto-discovery RCE — `.openclaw/extensions/` archive delivery detection (SID:9203013)
  - CVE-2026-29607: `allow-always` wrapper persistence bypass — `allow-always` + `system.run` approval pattern (SID:9203018)
  - CVE-2026-28460: Shell line-continuation allowlist bypass — `$\` in `system.run` detection (SID:9203019)
  - CVE-2026-34503 (CVSS 8.1): WebSocket session expiration failure — `device.token.rotate` monitoring + external `config.patch` (SID:9200907–9200908)
  - CVE-2026-33577: Node pairing scope escalation — `pair` + `approve` + `operator.admin` detection (SID:9202092–9202093)
- **CertiK sandbox bypass pattern** — Telegram-triggered `system.run` skill invocation, `sandbox.mode=off` API write, `tools.exec.host=gateway` (SID:9203140–9203142)
- **MS Teams authorization bypass** — `feedback` + `msteams` sender allowlist bypass (SID:9202095)
- **macOS Dashboard token leak** (GHSA-rchv-x836-w7xp) — auth token in URL parameter + Referrer header leak (SID:9204420–9204421)
- **Git executable hijack** and **IPv6 SSRF guard bypass** documented as pending CVEs in README

### Fixed
- **Telegram Bot API false positives**: SID:9200070 (sendDocument) had **no threshold** — fired on every single API call. Disabled as duplicate; canonical rule SID:9201520 in `oc-data-exfiltration.rules` has proper `threshold:type both, track by_src, count 5, seconds 60`
- **Vidar t.me false positives**: SID:9200040 now has `threshold:type both, track by_src, count 3, seconds 300` — single non-browser access to t.me no longer triggers; requires 3+ in 5 minutes
- **17 duplicate rules eliminated**: Cross-file SID duplicates between `oc-infostealer-c2.rules` and `oc-data-exfiltration.rules` disabled with `#DISABLED-DUPE#` — each references the canonical SID. Zero cross-file duplicates remain.
- **7 high-FP-risk rules disabled by default**: New rules that fire on legitimate operations (gateway outbound TLS, Teams messages, `/usr/bin/env` commands, `$()` substitution, nohup/timeout, system.run volume) — all marked `#DISABLED-FP#`

### Changed
- `oc-infostealer-c2.rules`: 67 → 50 active (17 DISABLED-DUPE)
- `oc-exploit-cve.rules`: 37 → 40 active (5 DISABLED-FP), SID range extended to 9203020
- `oc-exploit-detection.rules`: 89 → 92 active, SID range extended to 9203142
- `oc-gateway-exposure.rules`: 42 → 45 active (1 DISABLED-FP), SID range extended to 9202095
- `oc-websocket-attack.rules`: 43 → 45 active (1 DISABLED-FP), SID range extended to 9200908
- `oc-tls-certificate-anomaly.rules`: 20 → 22 active, SID range extended to 9204421
- Total: 642 active + 23 disabled-FP + 17 disabled-DUPE = 682 rules (was 662)
- Version bumped to 1.2.2

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
