# 🛡 CGTI Lite for OpenClaw — Community Edition

[![License: AGPL-3.0-only](https://img.shields.io/badge/License-AGPL--3.0--only-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-brightgreen.svg)](https://www.python.org)
[![Suricata 6.0+](https://img.shields.io/badge/Suricata-6.0%2B-orange.svg)](https://suricata.io)
[![Rules](https://img.shields.io/badge/Detection_Rules-646_active-red.svg)](#rule-files)
[![CVEs](https://img.shields.io/badge/CVEs_Covered-25-critical.svg)](#cves-covered)

> **Purpose-built Suricata IDS/IPS management tool** that protects [OpenClaw](https://openclaw.ai) AI agent users from known threat campaigns, zero-day exploits, and supply-chain attacks.
>
> **Windows · macOS · Linux** — Install and run in minutes.
>
> **662 total rules** — 646 active + 16 disabled by default (high false-positive risk rules, [see details](#disabled-rules)).

---

## Why CGTI Lite?

Between January and March 2026, the OpenClaw ecosystem faced an unprecedented security crisis:

- **ClawHavoc Campaign** — 1,184+ malicious skills discovered on ClawHub, distributing AMOS, Vidar, and GhostSocks infostealers
- **GhostClaw/GhostLoader** — RAT distributed via typosquatted npm packages (`@openclaw-ai/openclawai`), exfiltrating data to GoFile.io via trackpipe.dev C2
- **CVE-2026-25253** (CVSS 8.8) — 1-click RCE allowing complete token theft and remote code execution
- **135,000+ exposed instances** found on the public internet, many with no authentication
- **AMOS Stealer** — macOS infostealer harvesting `openclaw.json`, API keys, crypto wallets, and SSH credentials

CGTI Lite provides 646 curated Suricata rules covering every stage of these attack chains, wrapped in a cross-platform management console that handles installation, configuration, live monitoring, and active blocking.

---

## Table of Contents

- [Why CGTI Lite?](#why-cgti-lite)
- [Key Features](#key-features)
- [Threat Coverage](#threat-coverage)
- [Rule Files](#rule-files)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Command Reference](#command-reference)
- [IDS vs IPS Mode](#ids-vs-ips-mode)
- [False Positive Management](#false-positive-management)
- [Suricata Configuration](#suricata-configuration)
- [Config File Locations](#config-file-locations)
- [Firewall Integration](#firewall-integration)
- [Requirements](#requirements)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgments](#acknowledgments)

---

## Key Features

| Feature | Description |
|---|---|
| **Cross-Platform** | Full support for Windows, macOS, and Linux with platform-specific installers |
| **646 Detection Rules** | Purpose-built rules across 13 specialized files — zero SID conflicts, validated namespace |
| **IDS + IPS Modes** | Monitor-only (IDS) or active blocking (IPS) with automatic `alert → drop` rule generation |
| **Live Alert Feed** | Real-time `eve.json` monitoring with color-coded severity display |
| **Auto-Blocking** | Enhanced Autoblock mode automatically adds OS-native firewall rules for detected threats — bidirectional, DNS-aware, severity-filtered |
| **Firewall Integration** | iptables (Linux) / pfctl (macOS) / netsh advfirewall (Windows) |
| **Autostart** | Boot-time activation via systemd (Linux), launchd (macOS), Task Scheduler (Windows) — supports IDS, IPS, and Enhanced Autoblock modes |
| **IP Block Management** | Track, add, remove, and clear blocked IPs with reason logging |
| **Rule Management** | Enable/disable individual rules by SID, add custom rules, hot-reload |
| **Config Validation** | Schema-validated JSON configuration with safe defaults |
| **Log Rotation** | Automatic CGTI log rotation at 5 MB threshold |
| **Memory-Safe Reads** | Tail-based log reading in 1 MB chunks — never loads entire files into memory |

---

## Threat Coverage

### Campaigns & Malware Families

| Threat | Description | Detection Method |
|---|---|---|
| **ClawHavoc** | 1,184+ malicious ClawHub skills distributing infostealers | C2 IPs, domains, skill download patterns, DNS queries |
| **AMOS Stealer** | macOS infostealer targeting crypto wallets, openclaw.json, SSH keys | TLS C2 (91.92.242.0/24), HTTP exfil (out.zip), BuildID header |
| **Vidar 2.0** | Infostealer targeting `~/.openclaw/` credential store | JA3 fingerprint, TLS cert (C=XX,ST=NY,O=StaticIP) |
| **GhostClaw/GhostLoader** | RAT distributed via typosquatted npm packages (`@openclaw-ai/openclawai`), exfils to GoFile.io | TLS/HTTP C2 to trackpipe.dev, bootstrap payload URI, npm package detection, DNS queries |
| **GhostSocks** | Proxy malware turning compromised hosts into SOCKS proxies | Default cert CN, Stealth Packer indicators |
| **DigitStealer** | Cryptocurrency-focused stealer distributed via ClawHavoc | HTTP C2 patterns, wallet extension targeting |
| **AuthTool Backdoor** | Fake authentication skill with reverse shell to 54.91.154.110 | C2 IP, port 13338 connection patterns |

### CVEs Covered

CGTI Lite includes detection rules for **25 unique CVEs** targeting OpenClaw components:

| CVE | CVSS | Description |
|---|---|---|
| CVE-2026-25253 | 8.8 | 1-click RCE via `gatewayUrl` token exfiltration (5-phase kill chain) |
| CVE-2026-28446 | 9.8 | Voice extension pre-auth RCE via transcription pipeline |
| CVE-2026-28363 | 9.9 | `safeBins` bypass via GNU long-option abbreviations |
| CVE-2026-28484 | 9.8 | Git pre-commit hook option injection |
| CVE-2026-32059 | HIGH | Remote code execution via crafted skill metadata |
| CVE-2026-25593 | HIGH | Unauthenticated `config.apply` cliPath command injection |
| CVE-2026-27487 | HIGH | macOS keychain OAuth token command injection |
| CVE-2026-24763 | HIGH | Docker PATH environment variable command injection |
| CVE-2026-25157 | HIGH | `sshNodeCommand` / `parseSSHTarget` OS command injection |
| CVE-2026-26329 | HIGH | Path traversal via workspace configuration |
| CVE-2026-26322 | 7.6 | SSRF via gateway tool `gatewayUrl` parameter |
| CVE-2026-26319 | 7.5 | Telnyx/Twilio webhook authentication fail-open bypass |
| CVE-2026-22708 | MED | CSS hidden prompt injection in web UI |
| + 12 more | — | See `openclaw-exploit-detection.rules` and `oc-exploit-cve.rules` |

### Detection Layers

Rules are organized in three detection confidence layers:

- **Layer 1** — High confidence (priority 1): Known C2 IPs, CVE exploit signatures, TLS/JA3 fingerprints
- **Layer 2** — Medium confidence (priority 2): Behavioral patterns, protocol anomalies, threshold-based detection
- **Layer 3** — Low confidence (priority 3): Generic heuristics, scanner detection, broad pattern matching

---

## Rule Files

**13 files · 646 active rules (662 total) · SID range 9200001–9204419 · zero conflicts**

| # | File | SID Range | Active | Coverage |
|---|---|---|---|---|
| 01 | `oc-infostealer-c2.rules` | 9200001–9200128 | 67 | AMOS/Vidar/GhostClaw C2, credential theft, stealer panels |
| 02 | `oc-reverse-shell.rules` | 9200500–9200651 | 59 | Reverse shells (bash, netcat, Python, Node.js, PowerShell, Go, Java) |
| 03 | `oc-websocket-attack.rules` | 9200800–9200905 | 43 | WebSocket gateway attacks (CVE-2026-25253, ClawJacked, log poisoning) |
| 04 | `oc-malicious-skill-download.rules` | 9201000–9201113 | 50 | Malicious skill install, typosquatting, supply-chain |
| 05 | `oc-data-exfiltration.rules` | 9201500–9201631 | 57 | Credential exfil (Telegram, Discord, Slack, cloud storage, paste sites) |
| 06 | `oc-gateway-exposure.rules` | 9202000–9202091 | 42 | Exposed gateway, Moltbook, scanner detection, lateral movement |
| 07 | `oc-cryptostealer-activity.rules` | 9202300–9202381 | 41 | Crypto wallet theft, mining, seed phrases, exchange API keys, drainers |
| 08 | `oc-mcp-security.rules` | 9202600–9202662 | 24 | MCP endpoint security, SSRF, tool injection, credential exfil |
| 09 | `oc-exploit-cve.rules` | 9202900–9203012 | 37 | CVE-specific exploit signatures (base set) |
| 10 | `oc-exploit-detection.rules` | 9203050–9203139 | 89 | Extended CVE coverage (25 CVEs, full kill-chain, 35 sections) |
| 11 | `oc-threat-intel-ioc.rules` | 9203400–9203483 | 83 | Threat intel IOCs, malicious publishers, supply-chain attacks |
| 12 | `oc-dns-threat-detection.rules` | 9203900–9203942 | 34 | DNS C2, rebinding, typosquatting, mDNS recon, Enhanced Autoblock |
| 13 | `oc-tls-certificate-anomaly.rules` | 9204400–9204419 | 20 | TLS/cert MITM, TOFU attacks, JA3, Anthropic API protection |

All rule files are self-contained and can be loaded simultaneously with no additional configuration.

---

## Installation

### Linux / macOS

```bash
git clone https://github.com/Senturkselim/CGTI-for-OpenClaw.git
cd CGTI-for-OpenClaw
chmod +x install.sh
./install.sh
```

Then run the setup wizard:

```bash
cgti install
```

### Windows

1. Clone or download the repository
2. Right-click `install.bat` → **Run as administrator**
3. Open a **new** Administrator CMD window:

```cmd
cgti install
```

### Manual (Any OS)

```bash
pip install rich
python cgti_lite.py install
```

---

## Quick Start

```bash
# 1. Install and configure (first run only)
cgti install

# 2. Start Suricata monitoring
sudo cgti start                  # Interactive — select interface from list
sudo cgti start -i eth0          # Linux (direct)
cgti start -i "Wi-Fi"            # Windows (direct)
sudo cgti start -i en0           # macOS (direct)

# 3. Watch live alerts
cgti live

# 4. Enable auto-blocking (blocks attacking IPs via OS firewall)
sudo cgti live --autoblock
```

---

## Command Reference

### Core Commands

| Command | Description |
|---|---|
| `cgti install` | First-time setup wizard — detects/installs Suricata, configures rules |
| `cgti status` | System status, Suricata version, rule stats |
| `cgti start [-i INTERFACE]` | Start Suricata on specified network interface |
| `cgti stop` | Stop Suricata |
| `cgti live` | Live alert feed with color-coded severity |
| `cgti live --autoblock` | Live feed + automatic IP blocking for detected threats |

### Rule Management

| Command | Description |
|---|---|
| `cgti rules list` | List all rules (paginated) |
| `cgti rules list --filter "AMOS"` | Filter rules by text pattern |
| `cgti rules enable <SID>` | Enable a specific rule by SID |
| `cgti rules disable <SID>` | Disable a specific rule by SID |
| `cgti rules add "<rule>"` | Add a custom Suricata rule |
| `cgti rules reload` | Hot-reload rules without restarting Suricata |
| `cgti rules files` | List all rule files with stats |

### IP Blocking

| Command | Description |
|---|---|
| `cgti blocked list` | Show all blocked IPs with reasons and timestamps |
| `cgti blocked add <IP> -r "reason"` | Block an IP (applies OS firewall rule) |
| `cgti blocked remove <IP>` | Unblock an IP |
| `cgti blocked clear` | Clear all blocked IPs |

### Log Analysis

| Command | Description |
|---|---|
| `cgti logs` | Show recent alerts |
| `cgti logs -n 100` | Show last 100 alerts |
| `cgti logs --severity 1` | Show only critical (priority 1) alerts |
| `cgti logs --ip 1.2.3.4` | Filter alerts by source/destination IP |

### Configuration

| Command | Description |
|---|---|
| `cgti config show` | Display current configuration |
| `cgti config set suricata.mode IPS` | Switch to IPS mode |
| `cgti config set suricata.interface eth0` | Set default interface |
| `cgti config set suricata.dns_servers "9.9.9.9,149.112.112.112"` | Set custom DNS servers (live-applies to suricata.yaml) |
| `cgti config reset` | Reset configuration to defaults |
| `cgti config path` | Show config, rules, and log file paths |

### Autostart

CGTI Lite can start Suricata automatically on boot using the OS-native service manager:

| Command | Description |
|---|---|
| `cgti autostart enable` | Enable autostart on boot |
| `cgti autostart disable` | Disable autostart |
| `cgti autostart status` | Show current autostart status |

The implementation is platform-specific:

| OS | Method | Service Name |
|---|---|---|
| Linux | systemd unit | `cgti-lite.service` |
| macOS | launchd plist | `com.cgti-lite.daemon` |
| Windows | Task Scheduler | `CGTI-Lite-Autostart` |

> **Prerequisite:** An interface must be configured before enabling autostart. Run `cgti install` or `cgti config set suricata.interface <IFACE>` first.
>
> **How it works at boot:** The interface is read from `config.json` at runtime — changing the interface does not require re-running `autostart enable`. On Linux, if the system's own `suricata.service` starts Suricata in IDS mode but IPS is configured, CGTI automatically stops the IDS instance and restarts in full IPS/NFQUEUE mode. Enhanced Autoblock is also automatically activated at boot when enabled (`cgti config set cgti.autoblock true`).

---

## IDS vs IPS Mode

### IDS Mode (Default)

- **Monitors** network traffic and generates alerts
- Does **not** block or modify traffic
- Rules use `alert` action
- Works on all platforms

### IPS Mode

- **Actively blocks** malicious traffic by dropping packets
- Automatically converts existing `alert` rules to `drop` in-place (reverts on stop)
- Linux: Uses `iptables` NFQUEUE for inline packet processing
- Configures `suricata.yaml` with `nfq:` section automatically

```bash
# Enable IPS mode
cgti config set suricata.mode IPS

# Start with IPS (Linux — requires root)
sudo cgti start -i eth0
```

> **Note:** IPS mode with NFQUEUE is currently supported on **Linux only**. On macOS and Windows, CGTI operates in IDS mode with auto-blocking available as an alternative via `cgti live --autoblock`.

---

## False Positive Management

CGTI Lite rules were designed with a strict FP-prevention methodology: every rule requires at least two independent indicators, port/direction scoping where applicable, and threshold protection on behavioral rules. Despite this, some rules may trigger alerts in specific OpenClaw usage patterns. This section helps you tune the ruleset for your environment.

### Disabled Rules

16 rules are **disabled by default** because they fire on normal OpenClaw operations. Each disabled rule has a `# DISABLED-FP:` comment explaining the reason. You can re-enable them if your deployment does not use the affected feature.

| SID | File | Reason | Re-enable if... |
|---|---|---|---|
| 9200835 | websocket-attack | `device.register` fires on every legitimate device pairing | You never pair new devices |
| 9200836 | websocket-attack | `node.list` fires on every node enumeration | You have a static node setup |
| 9200837 | websocket-attack | `config.get` fires on every config read | You never read config via WebSocket |
| 9200838 | websocket-attack | `skill.install` fires on every skill installation | You have a locked skill set |
| 9200839 | websocket-attack | `log.read` fires on every log access | You never read logs via WebSocket |
| 9200872 | websocket-attack | Python REPL detection — REPL is a core OpenClaw feature | You don't use the Python REPL |
| 9202012 | gateway-exposure | Python REPL detection (gateway context) — same as above | Same as above |
| 9202071 | gateway-exposure | `HOME_NET → HOME_NET [22,3306,5432,6379,27017]` — no OpenClaw-specific content, fires on all internal DB/SSH traffic | You want to monitor ALL east-west traffic |
| 9202610 | mcp-security | `tools/call + exec` — matches legitimate MCP tools like `execute_query`, `exec_sql` | You don't use any MCP tool with "exec" in its name |
| 9202614 | mcp-security | `tools/call + read_file` — standard filesystem MCP tool | You don't use the filesystem MCP server |
| 9202615 | mcp-security | `tools/call + write_file` — standard filesystem MCP tool | You don't use the filesystem MCP server |
| 9202662 | mcp-security | Hardcoded `database_query` tool name — poor detection quality | N/A — detection logic is flawed |
| 9201070 | skill-download | `registry.npmjs.org` DNS — fires on every `npm install` command | Your OpenClaw host never runs npm |
| 9200513 | reverse-shell | Port 8888 + TLS handshake — fires on Jupyter Notebook, MAMP, dev servers | No dev tools run on port 8888 |
| 9203124 | exploit-detection | `[SYSTEM]+exec` in ALL HTTP responses — fires on tech docs and blog pages | You want aggressive prompt injection detection |
| 9203482 | threat-intel-ioc | Duplicate of SID:9203124 | Same as above |

To re-enable a disabled rule:

```bash
cgti rules enable <SID>
```

### Tuning Guide by Use Case

**If you use Discord/Slack/Teams integrations:**

SIDs 9201523–9201527 detect webhook POST requests to these platforms. They already have threshold protection (5 requests/60 seconds) and lowered priority (3). If you still see too many alerts, increase the threshold in your local rule override:

```bash
# Example: raise Discord webhook threshold to 10/60s
cgti rules disable 9201524
cgti rules add 'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"LOCAL - Discord Webhook POST (Tuned)"; flow:established,to_server; http.method; content:"POST"; http.host; content:"discord.com"; http.uri; content:"/api/webhooks/"; threshold:type both, track by_src, count 10, seconds 60; classtype:trojan-activity; priority:3; sid:9900001; rev:1;)'
```

**If you use Telegram Bot API:**

SIDs 9201520–9201522 and 9200070–9200071 detect Telegram Bot API calls. They have threshold protection (3–15 requests per 60 seconds). If your bot makes frequent API calls, consider raising the threshold or lowering the priority.

**If you run crypto trading bots:**

SID:9202333 (exchange withdrawal API call) is already set to priority:3 with `false_positive High` metadata. It detects POST requests to exchange APIs (Binance, Coinbase, etc.) with `withdraw/transfer/send` in the URI. If you run automated trading, this rule will generate informational alerts. You can disable it:

```bash
cgti rules disable 9202333
```

**If you run MCP servers (filesystem, database, custom tools):**

Four MCP rules are already disabled by default (9202610, 9202614, 9202615, 9202662). The remaining 24 MCP rules are scoped to detect external access, SSRF, and credential leaks — they should not fire on normal local MCP usage.

**If you use glot.io, file.io, or other code/file sharing services:**

These services are used by attackers but also by legitimate developers. The rules use threshold protection and lowered priority:
- glot.io HTTP (SID:9201000): priority 2
- glot.io DNS (SID:9203908): threshold 3 queries in 60 seconds
- file.io (SID:9201544): priority 2
- gofile.io (SID:9201547): priority 3

If you regularly use these services, you can raise thresholds or disable individual SIDs.

**If you access your gateway remotely (Tailscale, Cloudflare Tunnel, LAN):**

Rules in `oc-gateway-exposure.rules` and `oc-websocket-attack.rules` are designed to detect external access to port 18789. If you intentionally expose your gateway via a VPN or tunnel, these rules will fire. This is by design — the rules alert on the exposure itself as a policy violation. You can:
- Lower priority for gateway exposure rules: `cgti rules disable 9202000` then re-add with priority:3
- Or add your tunnel IP range to `$HOME_NET` in `suricata.yaml` so it is treated as internal

### Known False Positive Scenarios

These are documented scenarios where active rules may generate alerts during legitimate use. All have been evaluated and accepted at their current priority/threshold levels:

| Scenario | Rule(s) | Priority | Why it's acceptable |
|---|---|---|---|
| `curl \| bash` install scripts (Homebrew, nvm, etc.) | SID:9201021 | 2 | Specific combo: curl UA + `#!/bin/` shebang in response body. Common in dev setups but also the exact ClawHavoc delivery technique. |
| GitHub raw `.sh` script download via curl | SID:9201041 | 2 | Matches `raw.githubusercontent.com` + curl UA + `.sh` extension. FP metadata set to Medium. |
| Mach-O binary download (Homebrew, legitimate macOS apps) | SID:9200023 | 2 | Matches `\|ca fe ba be\|` magic bytes in HTTP response. Fires on any universal Mach-O binary download. |
| `.dmg` download via curl (legitimate macOS installers) | SID:9200021, 9200029, 9200030 | 2 | Specific to `.dmg` extension + curl UA. Ledger/Trezor rules additionally check for non-official domain. |
| IP geolocation lookups (ipinfo.io, ip-api.com) | SID:9200090–92, 9201620–23 | 3 | Non-browser UA + IP lookup service. Priority 3 (informational). Many legitimate scripts check public IP. |
| GitHub Gist creation | SID:9201551 | 3 | `api.github.com/gists` POST. Priority 3, FP:Medium. Developers creating Gists trigger this. |
| Pastebin API paste creation | SID:9201550 | 1 | Specific `api_option=paste` in POST body. Very low FP — most users don't POST to Pastebin API programmatically. |
| Self-signed TLS cert on gateway port 18789 | SID:9204415 | 2 | Fires on non-localhost connections with self-signed cert. Expected in dev/test environments using `wss://`. |

### Reporting False Positives

If you encounter a false positive not listed above, please report it so we can improve the ruleset for everyone:

1. **Identify the SID** — check the alert details in `cgti logs` or `cgti live`
2. **Temporarily disable** — `cgti rules disable <SID>` to stop the alert
3. **Open a GitHub Issue** with:
   - The SID number and full alert message
   - What legitimate activity triggered it
   - Your OpenClaw version and platform
   - Whether you use integrations (Discord, Telegram, MCP, crypto trading, etc.)

All FP reports are reviewed and may result in threshold adjustments, priority changes, or rule disabling in the next release.

---

## Suricata Configuration

All 13 rule files work out of the box with a standard Suricata installation. Two optional configurations enhance coverage:

### JA3 Fingerprinting (Recommended)

Required for Vidar infostealer JA3 detection (SID 9204416). Add to `suricata.yaml`:

```yaml
app-layer:
  protocols:
    tls:
      ja3-fingerprints: yes
```

### DNS Server Variable

Required for unauthorized DNS resolver detection (SID 9203923). Automatically configured during `cgti install` with public resolvers:

```yaml
vars:
  address-groups:
    DNS_SERVERS: "[8.8.8.8, 8.8.4.4, 1.1.1.1, 1.0.0.1]"
```

To use your own DNS servers, use the `config set` command — this updates both the CGTI config **and** `suricata.yaml` immediately:

```bash
cgti config set suricata.dns_servers "9.9.9.9,149.112.112.112"
```

### Standard Variables

All rules use standard Suricata variables (defined by default):

```yaml
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12]"
    EXTERNAL_NET: "!$HOME_NET"
```

---

## Config File Locations

| OS | Config Path |
|---|---|
| Linux | `/etc/cgti-lite/config.json` |
| macOS | `~/Library/Application Support/cgti-lite/config.json` |
| Windows | `%APPDATA%\cgti-lite\config.json` |

---

## Firewall Integration

`cgti blocked add` applies OS-native firewall rules:

| OS | Method |
|---|---|
| Linux | `iptables -I INPUT -s <IP> -j DROP` + `iptables -I OUTPUT -d <IP> -j DROP` |
| macOS | `pfctl` table with persistent file (`/etc/cgti_blocked_ips`) |
| Windows | `netsh advfirewall firewall` rule |

All firewall operations include IP validation to prevent injection attacks. IPS mode on Linux uses `iptables` NFQUEUE with automatic rollback on failure.

---

## Requirements

- **Python 3.8+**
- **[rich](https://github.com/Textualize/rich) ≥ 13.0.0** — auto-installed on first run
- **Suricata 6.0+** — IDS/IPS engine

### Installing Suricata

| OS | Command |
|---|---|
| Ubuntu/Debian | `sudo apt install suricata` |
| CentOS/RHEL | `sudo yum install suricata` |
| Arch Linux | `sudo pacman -S suricata` |
| macOS | `brew install suricata` |
| Windows | [Download MSI](https://suricata.io/download/) or run `cgti install` |

> **Windows:** [Npcap](https://npcap.com) is also required for packet capture. The `install.bat` script handles this automatically.

---

## Testing

```bash
python -m pytest test_cgti.py -v
```

The test suite includes 33 tests covering IP validation, memory-safe log reading, rule toggle integrity, config validation, IPS drop rule generation, NFQ configuration, and log rotation.

---

## Debug Mode

```bash
CGTI_DEBUG=1 cgti status
```

---

## Contributing

Contributions are welcome. Areas of interest:

- **New detection rules** — Follow the SID allocation scheme below
- **Platform testing** — Additional Linux distributions, macOS versions, Windows configurations
- **IoC updates** — Monitor the sources listed in each rule file header for new indicators
- **Bug reports** — Open an issue with `cgti status` output and relevant logs

### SID Allocation

When adding new rules, use SIDs within the allocated range for each category:

| Category | SID Range | Current Max |
|---|---|---|
| Infostealer C2 | 9200001–9200499 | 9200123 |
| Reverse Shell | 9200500–9200799 | 9200651 |
| WebSocket Attack | 9200800–9200999 | 9200905 |
| Malicious Skill Download | 9201000–9201499 | 9201113 |
| Data Exfiltration | 9201500–9201999 | 9201631 |
| Gateway Exposure | 9202000–9202299 | 9202091 |
| Cryptostealer Activity | 9202300–9202599 | 9202381 |
| MCP Security | 9202600–9202899 | 9202662 |
| Exploit CVE (base) | 9202900–9203049 | 9203012 |
| Exploit Detection (extended) | 9203050–9203399 | 9203139 |
| Threat Intel IOC | 9203400–9203899 | 9203483 |
| DNS Threat Detection | 9203900–9204399 | 9203924 |
| TLS/Certificate Anomaly | 9204400–9204999 | 9204419 |

### Rule Metadata Standard

Every rule must include the following metadata fields:

```
msg:"CGTI-OC <description>";
classtype:<suricata-classtype>;
priority:<1|2|3>;
reference:<type>,<value>;
metadata:<key value pairs>;
sid:<SID>; rev:<N>;
```

---

## License

This project is licensed under the **GNU Affero General Public License v3.0 only (AGPL-3.0-only)**.

```
Copyright (C) 2026  Selim Şentürk

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, version 3.
```

See [LICENSE.txt](LICENSE.txt) for the full license text.

---

## Acknowledgments

### Threat Intelligence Sources

The detection rules are built upon research and indicators from:

- [Koi Security](https://koi.ai) — ClawHavoc campaign discovery (1,184+ malicious skills)
- [Huntress](https://huntress.com) — AMOS stealer via ChatGPT/Grok analysis, GhostSocks/OpenClaw campaign
- [Bitdefender Labs](https://businessinsights.bitdefender.com) — AMOS technical advisory for enterprise networks
- [Darktrace](https://darktrace.com) — Atomic Stealer investigation across 24 countries
- [Trend Micro](https://trendmicro.com) — AMOS distribution analysis, Vidar 2.0 research
- [Ontinue](https://ontinue.com) — Vidar Stealer 2.0 reverse engineering
- [DepthFirst Security](https://depthfirst.com) — CVE-2026-25253 original discovery and kill-chain analysis
- [Oasis Security](https://oasis.security) — ClawJacked vulnerability disclosure
- [Bitsight TRACE](https://bitsight.com) — Exposed MCP servers research, OpenClaw instance scanning
- [Corelight](https://corelight.com) — React2Shell Suricata detection patterns
- [Endor Labs](https://endorlabs.com) — Multiple OpenClaw CVE discoveries
- [SentinelOne VDB](https://sentinelone.com) — Vulnerability database entries
- [VulnCheck](https://vulncheck.com) — Advisory publications
- [Hunt.io](https://hunt.io) — Certificate analysis of 17,470+ exposed instances
- [Hudson Rock](https://hudsonrock.com) — OpenClaw credential exposure research
- [Moonlock Lab](https://moonlock.com) — AMOS backdoor macOS analysis
- [JFrog Security Research](https://research.jfrog.com) — GhostClaw/GhostLoader RAT campaign discovery and analysis
- [abuse.ch SSLBL](https://sslbl.abuse.ch) — JA3 fingerprint database
- [adibirzu/openclaw-security-monitor](https://github.com/adibirzu/openclaw-security-monitor) — Curated IoC database
- [MITRE ATT&CK](https://attack.mitre.org) — Technique classification framework

---

<p align="center">
  <strong>CGTI Lite for OpenClaw</strong> — Community Edition<br>
  <em>Part of the <a href="https://github.com/Senturkselim">CloudGo Threat Intelligence</a> project</em>
</p>
