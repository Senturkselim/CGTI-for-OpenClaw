#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026  Selim Şentürk
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
"""
╔══════════════════════════════════════════════════════╗
║        CGTI Lite for OpenClaw  —  v1.2.2                             ║
║        Suricata IDS/IPS Cross-Platform Manager                       ║
║        Windows · macOS · Linux                                       ║
╚══════════════════════════════════════════════════════╝
Usage:
    python cgti_lite.py install      ← first run
    python cgti_lite.py start
    python cgti_lite.py --help
"""

import argparse
import json
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import types
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Optional

# ─── Auto-install rich ───────────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.prompt import Confirm
    from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
    from rich.syntax import Syntax
    from rich.align import Align
    from rich.rule import Rule
    from rich import box
except ImportError:
    print("[CGTI] Installing required dependency: rich …")
    # Try multiple strategies — macOS Homebrew Python 3.12+ blocks bare pip (PEP 668)
    _install_ok = False
    _strategies = [
        [sys.executable, "-m", "pip", "install", "--quiet", "rich"],
        [sys.executable, "-m", "pip", "install", "--quiet", "--user", "rich"],
        [sys.executable, "-m", "pip", "install", "--quiet", "--break-system-packages", "rich"],
    ]
    for _cmd in _strategies:
        try:
            subprocess.check_call(_cmd, stderr=subprocess.DEVNULL)
            _install_ok = True
            break
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue
    if not _install_ok:
        print(
            "[CGTI] ERROR: Could not install 'rich' package.\n"
            "  On macOS, run install.sh first (creates a virtual environment),\n"
            "  or install manually:  pip install --user rich\n"
            "  or:  brew install python-rich"
        )
        sys.exit(1)
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.prompt import Confirm
    from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
    from rich.syntax import Syntax
    from rich.align import Align
    from rich.rule import Rule
    from rich import box

# ─── Constants ───────────────────────────────────────────────────────────────

VERSION = "1.2.2"
OS      = platform.system()   # Windows | Linux | Darwin

NPCAP_VERSION   = "1.79"
NPCAP_URL       = f"https://npcap.com/dist/npcap-{NPCAP_VERSION}.exe"

SURICATA_WIN_VER = "8.0.3"
SURICATA_WIN_URL = (
    "https://www.openinfosecfoundation.org/download/windows/"
    f"Suricata-{SURICATA_WIN_VER}-1-64bit.msi"
)

if OS == "Windows":
    CONFIG_DIR = Path(os.environ.get("APPDATA", "C:/ProgramData")) / "cgti-lite"
elif OS == "Darwin":
    # Use system-wide path so root LaunchDaemon can access config
    CONFIG_DIR = Path("/usr/local/etc/cgti-lite")
else:
    CONFIG_DIR = Path("/etc/cgti-lite")

# ── macOS: migrate config from old user-specific location ──
if OS == "Darwin":
    _OLD_CONFIG_DIR = Path.home() / "Library" / "Application Support" / "cgti-lite"
    if _OLD_CONFIG_DIR.exists() and not CONFIG_DIR.exists():
        try:
            import shutil
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            for f in _OLD_CONFIG_DIR.iterdir():
                dest = CONFIG_DIR / f.name
                if not dest.exists():
                    shutil.copy2(str(f), str(dest))
        except (PermissionError, OSError):
            pass  # Will be handled when user runs with sudo

CONFIG_FILE      = CONFIG_DIR / "config.json"
RULES_DIR        = CONFIG_DIR / "rules"
BLOCKED_FILE     = CONFIG_DIR / "blocked_ips.json"
LOG_FILE         = CONFIG_DIR / "cgti.log"
SURICATA_RUN_LOG = CONFIG_DIR / "suricata_run.log"

SURICATA_BINS = {
    "Linux":   ["/usr/bin/suricata", "/usr/local/bin/suricata"],
    "Darwin":  ["/usr/local/bin/suricata", "/opt/homebrew/bin/suricata"],
    "Windows": [
        "C:\\Program Files\\Suricata\\suricata.exe",
        "C:\\Suricata\\suricata.exe",
        str(Path(os.environ.get("ProgramFiles", "C:\\Program Files"))
            / "Suricata" / "suricata.exe"),
    ],
}

SURICATA_CFGS = {
    "Linux":   "/etc/suricata/suricata.yaml",
    "Darwin":  "/opt/homebrew/etc/suricata/suricata.yaml",
    "Windows": "C:\\Program Files\\Suricata\\suricata.yaml",
}

SURICATA_LOGS = {
    "Linux":   ["/var/log/suricata/eve.json"],
    "Darwin":  ["/opt/homebrew/var/log/suricata/eve.json",
                "/usr/local/var/log/suricata/eve.json"],
    "Windows": [
        "C:\\Program Files\\Suricata\\log\\eve.json",
        "C:\\Suricata\\log\\eve.json",
    ],
}

_local_ips_cache: set = set()

LOG_MAX_BYTES = 5 * 1024 * 1024   # 5 MB — log rotation threshold

_IP_RE = re.compile(
    r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$"         # IPv4
    r"|^([0-9a-fA-F:]{2,39})$"                           # IPv6
)


def _validate_ip(ip: str) -> bool:
    """Return True if *ip* looks like a valid IPv4 or IPv6 address."""
    if not ip or not isinstance(ip, str):
        return False
    ip = ip.strip()
    if not _IP_RE.match(ip):
        return False
    # Extra IPv4 octet range check
    if "." in ip:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        return all(0 <= int(p) <= 255 for p in parts)
    return True


def _is_non_blockable_ip(ip: str) -> bool:
    """Return True for IPs that should never be auto-blocked."""
    if not ip:
        return True
    try:
        if "." in ip:
            parts = [int(p) for p in ip.split(".")]
            if len(parts) != 4:
                return True
            # Loopback 127.x.x.x
            if parts[0] == 127:
                return True
            # Broadcast
            if parts == [255, 255, 255, 255]:
                return True
            # Multicast 224-239.x.x.x
            if 224 <= parts[0] <= 239:
                return True
            # 0.0.0.0
            if parts == [0, 0, 0, 0]:
                return True
            # Link-local 169.254.x.x
            if parts[0] == 169 and parts[1] == 254:
                return True
        elif ":" in ip:
            # IPv6 loopback ::1, unspecified ::
            stripped = ip.strip().lower()
            if stripped in ("::1", "::", "0::0", "0::1"):
                return True
            # IPv6 multicast ff00::/8
            if stripped.startswith("ff"):
                return True
    except Exception:
        return True
    return False


def _is_private_ip(ip: str) -> bool:
    """Return True for RFC1918 private, CGNAT, and link-local IPs."""
    if not ip or ":" in ip:
        return False  # IPv6 handled separately
    try:
        parts = [int(p) for p in ip.split(".")]
        if len(parts) != 4:
            return False
        # 10.0.0.0/8
        if parts[0] == 10:
            return True
        # 172.16.0.0/12
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        # 192.168.0.0/16
        if parts[0] == 192 and parts[1] == 168:
            return True
        # 100.64.0.0/10 (CGNAT)
        if parts[0] == 100 and 64 <= parts[1] <= 127:
            return True
    except Exception:
        pass
    return False


def _tail_lines(filepath: str, max_lines: int = 2000) -> list:
    """Read last *max_lines* from a file without loading entire file into memory."""
    result: list = []
    try:
        with open(filepath, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            if size == 0:
                return result
            # Read in chunks from the end
            chunk_size = min(size, 1024 * 1024)  # 1 MB chunks
            pos = size
            leftover = b""
            while pos > 0 and len(result) < max_lines:
                read_size = min(chunk_size, pos)
                pos -= read_size
                f.seek(pos)
                chunk = f.read(read_size) + leftover
                lines = chunk.split(b"\n")
                leftover = lines[0]  # May be partial line
                for line in reversed(lines[1:]):
                    decoded = line.decode("utf-8", errors="ignore").strip()
                    if decoded:
                        result.append(decoded)
                    if len(result) >= max_lines:
                        break
            # Handle the very first line
            if leftover and len(result) < max_lines:
                decoded = leftover.decode("utf-8", errors="ignore").strip()
                if decoded:
                    result.append(decoded)
    except Exception as e:
        _log(f"_tail_lines error ({filepath}): {e}", "ERROR")
    return result


def _get_local_ips() -> set:
    ips = {"127.0.0.1", "::1", "0.0.0.0"}
    try:
        import socket
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ips.add(info[4][0])
    except Exception as e:
        _log(f"_get_local_ips socket error: {e}", "WARN")
    try:
        if OS == "Windows":
            r = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 "Get-NetIPAddress -AddressFamily IPv4 | Select-Object -ExpandProperty IPAddress"],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=5,
            )
            for line in r.stdout.splitlines():
                ip = line.strip()
                if ip:
                    ips.add(ip)
        else:
            r = subprocess.run(["ip", "-o", "-4", "addr", "show"],
                               capture_output=True, text=True, timeout=5)
            for m in re.finditer(r"inet (\S+)/", r.stdout):
                ips.add(m.group(1))
    except Exception as e:
        _log(f"_get_local_ips subprocess error: {e}", "WARN")
    return ips


def _setup_linux_ips(interface: str, queue_num: int = 0) -> tuple:
    """Setup iptables NFQUEUE rules for Suricata IPS mode on Linux.

    Fixes applied:
    - Explicit --queue-num for Suricata queue matching
    - Interface filter (-i / -o) to avoid affecting other interfaces
    - Return code checking for each iptables command
    - No --queue-bypass: fail-closed for security (configurable)
    """
    if OS != "Linux":
        return False, "IPS mode is only supported on Linux."
    if not shutil.which("iptables"):
        return False, "iptables not found. Run with sudo."
    try:
        cmds = [
            ["iptables", "-I", "INPUT",   "-i", interface,
             "-j", "NFQUEUE", "--queue-num", str(queue_num)],
            ["iptables", "-I", "OUTPUT",  "-o", interface,
             "-j", "NFQUEUE", "--queue-num", str(queue_num)],
            ["iptables", "-I", "FORWARD", "-i", interface,
             "-j", "NFQUEUE", "--queue-num", str(queue_num)],
        ]
        for cmd in cmds:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if r.returncode != 0:
                err_msg = r.stderr.strip() or f"exit code {r.returncode}"
                _log(f"IPS iptables error: {' '.join(cmd)} → {err_msg}", "ERROR")
                # Rollback: remove added rules
                _teardown_linux_ips(interface, queue_num)
                return False, f"iptables rule could not be added: {err_msg}"
        _log(f"IPS: iptables NFQUEUE rules added (iface={interface}, queue={queue_num})")
        return True, ""
    except FileNotFoundError:
        return False, "iptables not found. Run with sudo."
    except subprocess.TimeoutExpired:
        return False, "iptables timed out — system is not responding."
    except Exception as e:
        return False, str(e)


def _teardown_linux_ips(interface: str = "", queue_num: int = 0):
    """Remove iptables NFQUEUE rules. Silently ignores missing rules."""
    try:
        # If interface is empty, clear all NFQUEUE rules
        if interface:
            cmds = [
                ["iptables", "-D", "INPUT",   "-i", interface,
                 "-j", "NFQUEUE", "--queue-num", str(queue_num)],
                ["iptables", "-D", "OUTPUT",  "-o", interface,
                 "-j", "NFQUEUE", "--queue-num", str(queue_num)],
                ["iptables", "-D", "FORWARD", "-i", interface,
                 "-j", "NFQUEUE", "--queue-num", str(queue_num)],
            ]
        else:
            # Fallback: legacy style (backwards compatibility)
            cmds = [
                ["iptables", "-D", "FORWARD", "-j", "NFQUEUE", "--queue-bypass"],
                ["iptables", "-D", "INPUT",   "-j", "NFQUEUE", "--queue-bypass"],
                ["iptables", "-D", "OUTPUT",  "-j", "NFQUEUE", "--queue-bypass"],
            ]
        for cmd in cmds:
            subprocess.run(cmd, capture_output=True, timeout=10)
        _log(f"IPS: iptables NFQUEUE rules removed (iface={interface or 'all'})")
    except Exception as e:
        _log(f"iptables teardown error: {e}")


def _generate_drop_rules(rules_dir: Path) -> tuple:
    """Generate IPS drop rule copies from existing alert rules.

    Creates *-ips.rules files where 'alert' action is replaced with 'drop'.
    Original rule files are NOT modified.
    Returns: (list of generated filenames, error string)
    """
    generated = []
    try:
        rules_dir.mkdir(parents=True, exist_ok=True)
        for rule_file in sorted(rules_dir.glob("*.rules")):
            # Skip already generated IPS files
            if rule_file.name.endswith("-ips.rules"):
                continue
            try:
                text = rule_file.read_text(encoding="utf-8", errors="replace")
                lines = text.splitlines(keepends=True)
                ips_lines = []
                has_changes = False
                for line in lines:
                    stripped = line.lstrip()
                    # Active alert rule → drop
                    if stripped.startswith("alert "):
                        ips_lines.append(line.replace("alert ", "drop ", 1))
                        has_changes = True
                    # Commented alert rule → commented drop (preserve state)
                    elif stripped.startswith("# alert "):
                        ips_lines.append(line.replace("# alert ", "# drop ", 1))
                        has_changes = True
                    else:
                        ips_lines.append(line)
                if has_changes:
                    ips_name = rule_file.stem + "-ips.rules"
                    ips_path = rules_dir / ips_name
                    header = (
                        f"# AUTO-GENERATED by CGTI Lite IPS Mode\n"
                        f"# Source: {rule_file.name}\n"
                        f"# Action: alert → drop\n"
                        f"# Date: {datetime.now():%Y-%m-%d %H:%M}\n"
                        f"# DO NOT EDIT — regenerated on each IPS start\n\n"
                    )
                    ips_path.write_text(header + "".join(ips_lines), encoding="utf-8")
                    generated.append(ips_name)
                    _log(f"IPS drop rules generated: {ips_name}")
            except Exception as e:
                _log(f"IPS rule generation error ({rule_file.name}): {e}", "ERROR")
        return generated, ""
    except Exception as e:
        return [], str(e)


def _cleanup_drop_rules(rules_dir: Path):
    """Remove auto-generated *-ips.rules files."""
    try:
        for f in rules_dir.glob("*-ips.rules"):
            f.unlink()
            _log(f"IPS drop rules removed: {f.name}")
    except Exception as e:
        _log(f"IPS cleanup error: {e}")


def _configure_suricata_nfq(yaml_path: str, queue_num: int = 0) -> bool:
    """Configure suricata.yaml for NFQ (IPS) mode.

    Adds/updates nfq section. Drop action is handled by in-place rule
    modification (alert → drop) — no separate -ips.rules files needed.
    Also enables drop event logging in eve-log for IPS visibility.
    """
    try:
        text = Path(yaml_path).read_text(encoding="utf-8", errors="replace")
        modified = False

        # Add/update nfq section
        nfq_section = (
            f"\nnfq:\n"
            f"  mode: accept\n"
            f"  repeat-mark: 0\n"
            f"  repeat-mask: 0\n"
            f"  bypass-mark: 0\n"
            f"  bypass-mask: 0\n"
            f"  batchcount: 20\n"
            f"  fail-open: yes\n"
        )
        if "nfq:" not in text:
            text += nfq_section
            modified = True
            _log("suricata.yaml: nfq section added")
        else:
            # Make sure fail-open: yes is set
            if "fail-open:" not in text:
                text = text.replace("nfq:", "nfq:\n  fail-open: yes", 1)
                modified = True

        # Enable drop event logging in eve-log (IPS visibility)
        # Suricata only logs drop events if "- drop" is in eve-log types
        if "- drop" not in text:
            # Find the eve-log types section and add "- drop" after "- alert"
            drop_added = re.sub(
                r"(^\s*- alert\b[^\n]*\n)",
                r"\1      - drop:\n          alerts: yes\n          flows: all\n",
                text, count=1, flags=re.MULTILINE,
            )
            if drop_added != text:
                text = drop_added
                modified = True
                _log("suricata.yaml: drop event logging enabled for IPS")

        if modified:
            Path(yaml_path).write_text(text, encoding="utf-8")
        return True
    except Exception as e:
        _log(f"suricata.yaml NFQ config error: {e}", "ERROR")
        return False


def _revert_suricata_nfq(yaml_path: str):
    """Remove IPS-specific entries from suricata.yaml (IPS rule refs)."""
    try:
        text = Path(yaml_path).read_text(encoding="utf-8", errors="replace")
        # Remove -ips.rules entries
        new_text = re.sub(r"^\s*-\s+\S+-ips\.rules\n", "", text, flags=re.MULTILINE)
        if new_text != text:
            Path(yaml_path).write_text(new_text, encoding="utf-8")
            _log("suricata.yaml: IPS rule entries removed")
    except Exception as e:
        _log(f"suricata.yaml revert error: {e}")


def _configure_suricata_enhancements(yaml_path: str,
                                      dns_servers: str = "") -> list:
    """Enable JA3 fingerprinting and define $DNS_SERVERS in suricata.yaml.

    These are optional but recommended settings that enable specific
    OpenClaw detection rules:
      - ja3-fingerprints: yes  → enables rule 9203150 (Vidar JA3)
      - DNS_SERVERS variable   → enables rule 9100031 (rogue DNS)

    Returns a list of human-readable strings describing changes made.
    """
    changes = []
    try:
        text = Path(yaml_path).read_text(encoding="utf-8", errors="replace")
        modified = False

        # ── 1) Enable JA3 fingerprinting ─────────────────────────────────
        # Look for existing ja3-fingerprints setting
        ja3_re = re.compile(
            r"^(\s*)ja3-fingerprints:\s*(no|false)",
            re.MULTILINE | re.IGNORECASE,
        )
        m_ja3 = ja3_re.search(text)
        if m_ja3:
            # Change 'no' to 'yes'
            indent = m_ja3.group(1)
            text = text[:m_ja3.start()] + f"{indent}ja3-fingerprints: yes" + text[m_ja3.end():]
            modified = True
            changes.append("JA3 fingerprints enabled (was disabled)")
            _log("suricata.yaml: ja3-fingerprints changed to yes")
        elif "ja3-fingerprints" not in text:
            # Not present at all — insert under tls protocol section
            tls_re = re.compile(
                r"(^(\s+)tls:\s*\n)",
                re.MULTILINE,
            )
            m_tls = tls_re.search(text)
            if m_tls:
                indent = m_tls.group(2)
                ja3_line = f"{indent}  ja3-fingerprints: yes\n"
                text = text[:m_tls.end()] + ja3_line + text[m_tls.end():]
                modified = True
                changes.append("JA3 fingerprints enabled")
                _log("suricata.yaml: ja3-fingerprints: yes added under tls")
            else:
                _log("suricata.yaml: tls section not found, skipping JA3")
        else:
            # ja3-fingerprints already set to yes
            _log("suricata.yaml: ja3-fingerprints already enabled")

        # ── 2) Define DNS_SERVERS variable ────────────────────────────────
        dns_var_re = re.compile(
            r"^\s+DNS_SERVERS:\s",
            re.MULTILINE,
        )
        if not dns_var_re.search(text):
            # Find address-groups section and add DNS_SERVERS
            ag_re = re.compile(
                r"(^(\s+)address-groups:\s*\n)",
                re.MULTILINE,
            )
            m_ag = ag_re.search(text)
            if m_ag:
                indent = m_ag.group(2)
                # Use custom DNS servers if provided, else defaults
                if dns_servers:
                    servers = ", ".join(
                        s.strip() for s in dns_servers.replace(";", ",").split(",")
                        if s.strip()
                    )
                else:
                    servers = "8.8.8.8, 8.8.4.4, 1.1.1.1, 1.0.0.1"
                dns_line = (
                    f'{indent}  DNS_SERVERS: "[{servers}]"\n'
                )
                # Find the last existing variable in address-groups
                # and insert after it
                after_ag = text[m_ag.end():]
                # Scan forward through indented lines to find insertion point
                insert_pos = m_ag.end()
                for line in after_ag.splitlines(keepends=True):
                    stripped = line.strip()
                    if stripped == "" or line.startswith(indent + "  "):
                        insert_pos += len(line)
                    else:
                        break
                text = text[:insert_pos] + dns_line + text[insert_pos:]
                modified = True
                changes.append(f"DNS_SERVERS defined ({servers})")
                _log("suricata.yaml: DNS_SERVERS variable added")
            else:
                _log("suricata.yaml: address-groups not found, skipping DNS_SERVERS")
        elif dns_servers:
            # DNS_SERVERS exists but user wants to update it
            new_servers = ", ".join(
                s.strip() for s in dns_servers.replace(";", ",").split(",")
                if s.strip()
            )
            dns_update_re = re.compile(
                r"(^\s+DNS_SERVERS:\s*)\"[^\"]*\"",
                re.MULTILINE,
            )
            m_dns = dns_update_re.search(text)
            if m_dns:
                new_val = f'{m_dns.group(1)}"[{new_servers}]"'
                text = text[:m_dns.start()] + new_val + text[m_dns.end():]
                modified = True
                changes.append(f"DNS_SERVERS updated ({new_servers})")
                _log(f"suricata.yaml: DNS_SERVERS updated to {new_servers}")
        else:
            _log("suricata.yaml: DNS_SERVERS already defined")

        if modified:
            Path(yaml_path).write_text(text, encoding="utf-8")

    except PermissionError:
        _log("suricata.yaml enhancements: Permission denied", "ERROR")
        changes.append("Permission denied — run as Administrator")
    except Exception as e:
        _log(f"suricata.yaml enhancements error: {e}", "ERROR")

    return changes



console = Console(highlight=False)

# ─── Banner ──────────────────────────────────────────────────────────────────

BANNER = r"""
  ██████╗ ██████╗ ████████╗██╗    ██╗     ██╗████████╗███████╗
 ██╔════╝██╔════╝ ╚══██╔══╝██║    ██║     ██║╚══██╔══╝██╔════╝
 ██║     ██║  ███╗   ██║   ██║    ██║     ██║   ██║   █████╗
 ██║     ██║   ██║   ██║   ██║    ██║     ██║   ██║   ██╔══╝
 ╚██████╗╚██████╔╝   ██║   ██║    ███████╗██║   ██║   ███████╗
  ╚═════╝ ╚═════╝    ╚═╝   ╚═╝    ╚══════╝╚═╝   ╚═╝   ╚══════╝
"""

def print_banner():
    console.print(f"[bold cyan]{BANNER}[/bold cyan]")
    console.print(Align.center(
        f"[bold white]CGTI Lite[/bold white] [dim]for OpenClaw[/dim]"
        f"   [bold green]v{VERSION}[/bold green]"
        f"   [dim]│  Suricata IDS/IPS Manager  │[/dim]"
        f"   [dim cyan]{OS}[/dim cyan]"
    ))
    console.print(Rule(style="dim cyan"))
    console.print()


# ─── Config ──────────────────────────────────────────────────────────────────

class ConfigManager:
    DEFAULT = {
        "suricata": {
            "binary": "", "config": "", "interface": "",
            "mode": "IDS", "eve_log": "", "fast_log": "",
            "ips_severity_threshold": 0,
            "ips_queue_num": 0,
            "dns_servers": "",
        },
        "cgti":    {"rules_dir": str(RULES_DIR), "openclaw_ruleset": True,
                    "autoblock_min_severity": 3},
        "network": {"monitored_interfaces": [], "exclude_ips": [], "whitelist_ips": []},
    }

    # Allowed keys and their accepted values (None = any value accepted)
    VALID_KEYS = {
        "suricata.binary": None,
        "suricata.config": None,
        "suricata.interface": None,
        "suricata.mode": ["IDS", "IPS"],
        "suricata.eve_log": None,
        "suricata.fast_log": None,
        "suricata.dns_servers": None,
        "cgti.rules_dir": None,
        "cgti.openclaw_ruleset": [True, False],
        "cgti.autoblock": [True, False],
        "cgti.autoblock_min_severity": [1, 2, 3, 4],
        "network.monitored_interfaces": None,
        "network.exclude_ips": None,
        "network.whitelist_ips": None,
    }

    def __init__(self):
        self.data: dict = {}
        self.load()

    def load(self):
        if CONFIG_FILE.exists():
            try:
                self.data = json.loads(CONFIG_FILE.read_text())
                return
            except Exception as e:
                _log(f"Config load error, using defaults: {e}", "WARN")
        import copy
        self.data = copy.deepcopy(self.DEFAULT)

    def save(self):
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        CONFIG_FILE.write_text(json.dumps(self.data, indent=2))

    def get(self, *keys, default=None):
        d = self.data
        for k in keys:
            if isinstance(d, dict) and k in d:
                d = d[k]
            else:
                return default
        return d

    def set(self, *keys_and_value):
        *keys, value = keys_and_value
        d = self.data
        for k in keys[:-1]:
            d = d.setdefault(k, {})
        d[keys[-1]] = value
        self.save()


# ─── Suricata Manager ────────────────────────────────────────────────────────

class SuricataManager:
    def __init__(self, config: ConfigManager):
        self.config = config

    # ── Discovery ─────────────────────────────────────────────────────────────

    def find_binary(self) -> Optional[str]:
        stored = self.config.get("suricata", "binary")
        if stored and Path(stored).exists():
            return stored
        for p in SURICATA_BINS.get(OS, []):
            if Path(p).exists():
                return p
        return shutil.which("suricata")

    def is_installed(self) -> bool:
        return self.find_binary() is not None

    def find_config(self) -> Optional[str]:
        stored = self.config.get("suricata", "config", default="")
        if stored and Path(stored).exists():
            return stored
        candidates = list(SURICATA_CFGS.values()) + [
            "/etc/suricata/suricata.yaml",
            "/usr/local/etc/suricata/suricata.yaml",
            "/opt/homebrew/etc/suricata/suricata.yaml",
            "C:\\Program Files\\Suricata\\suricata.yaml",
            "C:\\Suricata\\suricata.yaml",
        ]
        return next((p for p in candidates if Path(p).exists()), None)

    def get_version(self) -> str:
        binary = self.find_binary()
        if not binary:
            return "Not found"
        try:
            r = subprocess.run([binary, "--version"], capture_output=True,
                               text=True, encoding="utf-8", errors="replace", timeout=5)
            for line in (r.stdout + r.stderr).splitlines():
                if "suricata" in line.lower():
                    for part in reversed(line.strip().split()):
                        if part and part[0].isdigit():
                            return part
        except Exception:
            pass
        return "Unknown"

    # ── State ─────────────────────────────────────────────────────────────────

    def is_running(self) -> bool:
        try:
            if OS == "Windows":
                r = subprocess.run(
                    ["tasklist", "/FI", "IMAGENAME eq suricata.exe", "/NH"],
                    capture_output=True, text=True,
                    encoding="utf-8", errors="replace", timeout=5,
                )
                return "suricata.exe" in r.stdout.lower()
            else:
                # Method 1: Check PID file
                for pid_f in ["/var/run/suricata.pid", "/run/suricata.pid"]:
                    try:
                        pid = int(Path(pid_f).read_text().strip())
                        if Path(f"/proc/{pid}/status").exists():
                            return True
                    except Exception:
                        continue
                # Method 2: pgrep -x (exact process name, not -f which matches args)
                r = subprocess.run(
                    ["pgrep", "-x", "suricata"],
                    capture_output=True, timeout=5,
                )
                return r.returncode == 0
        except Exception:
            return False
    def get_stats(self) -> dict:
        stats = {"packets": 0, "alerts": 0, "dropped": 0}
        eve = self.config.get("suricata", "eve_log") or _auto_eve()
        if not eve or not Path(eve).exists():
            return stats
        try:
            for line in _tail_lines(eve, max_lines=2000):
                try:
                    e = json.loads(line)
                    if e.get("event_type") == "stats":
                        s = e.get("stats", {})
                        cap = s.get("capture", {})
                        det = s.get("detect", {})
                        dec = s.get("decoder", {})
                        ips = s.get("ips", {})

                        # Packets: IPS uses decoder.pkts, IDS uses capture.kernel_packets
                        stats["packets"] = dec.get("pkts", 0) or cap.get("kernel_packets", 0)

                        # Alerts: same path in both modes
                        stats["alerts"] = det.get("alert", 0)

                        # Drops: IPS uses ips.blocked, IDS uses capture.kernel_drops
                        stats["dropped"] = ips.get("blocked", 0) or cap.get("kernel_drops", 0)

                        break
                except Exception:
                    continue
        except Exception as e:
            _log(f"get_stats error: {e}", "ERROR")
        return stats

    def _read_run_log(self, last_n: int = 15) -> str:
        try:
            return "\n".join(SURICATA_RUN_LOG.read_text(errors="ignore").splitlines()[-last_n:])
        except Exception:
            return ""

    # ── Start ─────────────────────────────────────────────────────────────────

    def start(self, interface: str, silent: bool = False) -> tuple:
        if OS == "Windows":
            return self._start_windows(interface, silent=silent)
        return self._start_unix(interface)

    def _start_windows(self, interface: str, silent: bool = False) -> tuple:
        binary = self.find_binary()
        if not binary:
            return False, "Suricata not found. Run first: cgti install"

        cfg_path = self.find_config()
        if not cfg_path:
            return False, "suricata.yaml not found. Set: cgti config set suricata.config <path>"
        self.config.set("suricata", "config", cfg_path)

        # Start with IP — Suricata maps the IP to NPF device itself
        iface_arg = self._get_interface_ip(interface) or interface
        if not silent:
            console.print(
                f"  [dim]Interface: [cyan]{interface}[/cyan]"
                + (f" → IP: [green]{iface_arg}[/green]" if iface_arg != interface else "")
                + "[/dim]"
            )

        # Create missing rule/config files
        _ensure_suricata_ready(cfg_path)

        # Log directory
        log_dir = Path(binary).parent / "log"
        try:
            log_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            log_dir = CONFIG_DIR

        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        run_log = open(str(SURICATA_RUN_LOG), "w", encoding="utf-8")

        # Start directly as a process.
        # DETACHED_PROCESS is not used — that flag causes Suricata to think
        # it's running as a service ("Running as service: yes").
        cmd = [binary, "-i", iface_arg, "-l", str(log_dir)]
        _log(f"Cmd: {' '.join(cmd)}")
        if not silent:
            console.print(f"  [dim]Command: [cyan]{' '.join(cmd)}[/cyan][/dim]")

        try:
            # In silent/autostart mode, hide Suricata's console window completely
            cflags = subprocess.CREATE_NEW_PROCESS_GROUP
            if silent:
                cflags |= subprocess.CREATE_NO_WINDOW
            proc = subprocess.Popen(
                cmd,
                stdout=run_log,
                stderr=subprocess.STDOUT,
                cwd=str(Path(binary).parent),
                creationflags=cflags,
            )
        except PermissionError:
            return False, "Access denied. Run CMD as Administrator."
        except Exception as e:
            return False, f"Suricata could not be started: {e}"

        # Wait for Suricata to start
        if silent:
            # Silent mode: simple wait loop, no progress bar
            for tick in range(12):
                time.sleep(1)
                if proc.poll() is not None:
                    run_log.flush()
                    try:
                        detail = SURICATA_RUN_LOG.read_text(
                            encoding="utf-8", errors="replace"
                        ).strip()[-1500:]
                    except Exception:
                        detail = "(could not read log)"
                    return False, (
                        f"Suricata exited at second {tick + 1} (exit {proc.returncode}).\n\n"
                        f"Output:\n{detail or '(empty)'}\n\nFull log: {SURICATA_RUN_LOG}"
                    )
                r = subprocess.run(
                    ["tasklist", "/FI", "IMAGENAME eq suricata.exe", "/NH"],
                    capture_output=True, text=True, encoding="utf-8", errors="replace",
                )
                if "suricata.exe" in r.stdout.lower():
                    _log(f"Suricata running pid={proc.pid} iface={iface_arg}")
                    return True, "OK"
        else:
            # Interactive mode: show progress bar
            from rich.progress import BarColumn, TaskProgressColumn
            with Progress(
                SpinnerColumn(),
                TextColumn("[cyan]{task.description}[/cyan]"),
                BarColumn(bar_width=28),
                TaskProgressColumn(),
                TimeElapsedColumn(),
                console=console,
                transient=True,
            ) as prog:
                task = prog.add_task("Starting Suricata…", total=12)
                for tick in range(12):
                    time.sleep(1)
                    prog.advance(task)
                    if proc.poll() is not None:
                        run_log.flush()
                        try:
                            detail = SURICATA_RUN_LOG.read_text(
                                encoding="utf-8", errors="replace"
                            ).strip()[-1500:]
                        except Exception:
                            detail = "(could not read log)"
                        return False, (
                            f"Suricata exited at second {tick + 1} (exit {proc.returncode}).\n\n"
                            f"Output:\n{detail or '(empty)'}\n\nFull log: {SURICATA_RUN_LOG}"
                        )
                    r = subprocess.run(
                        ["tasklist", "/FI", "IMAGENAME eq suricata.exe", "/NH"],
                        capture_output=True, text=True, encoding="utf-8", errors="replace",
                    )
                    if "suricata.exe" in r.stdout.lower():
                        prog.update(task, description="[green]Suricata running ✓[/green]", completed=12)
                        _log(f"Suricata running pid={proc.pid} iface={iface_arg}")
                        return True, "OK"

        if self.is_running():
            return True, "OK"

        try:
            detail = SURICATA_RUN_LOG.read_text(encoding="utf-8", errors="replace").strip()[-800:]
        except Exception:
            detail = "(could not read log)"
        return False, (
            f"Suricata did not start within 12 seconds.\n\n"
            f"Last log:\n{detail or '(empty)'}\n\nFull log: {SURICATA_RUN_LOG}"
        )

    def _start_unix(self, interface: str) -> tuple:
        binary = self.find_binary()
        if not binary:
            return False, "Suricata not found. Run first: cgti install"
        cfg_path = self.find_config()
        if not cfg_path:
            return False, "suricata.yaml not found."
        self.config.set("suricata", "config", cfg_path)
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)

        mode = self.config.get("suricata", "mode", default="IDS")
        queue_num = self.config.get("suricata", "ips_queue_num", default=0)
        rules_dir = Path(self.config.get("cgti", "rules_dir", default=str(RULES_DIR)))

        # IPS mode preparations
        if mode == "IPS":
            if OS != "Linux":
                return False, (
                    "IPS mode requires Linux (NFQUEUE + iptables).\n"
                    "On macOS, use IDS + Enhanced Autoblock instead:\n"
                    "  cgti config set suricata.mode IDS\n"
                    "  cgti config set cgti.autoblock true"
                )

            # 1) Force-kill any lingering Suricata to free NFQ queue
            console.print("  [cyan]IPS:[/cyan] Ensuring clean state…")
            subprocess.run(["systemctl", "stop", "suricata"], capture_output=True, timeout=15)
            subprocess.run(["pkill", "-9", "suricata"], capture_output=True)
            time.sleep(1)
            for pid_f in ["/var/run/suricata.pid", "/run/suricata.pid"]:
                try:
                    Path(pid_f).unlink(missing_ok=True)
                except Exception:
                    pass
            # Kill anything still holding our NFQ queue
            try:
                nfq_info = Path("/proc/net/netfilter/nfnetlink_queue")
                if nfq_info.exists():
                    for line in nfq_info.read_text().splitlines():
                        parts = line.split()
                        if parts and parts[0] == str(queue_num):
                            try:
                                subprocess.run(["kill", "-9", parts[1]],
                                               capture_output=True, timeout=3)
                                time.sleep(1)
                            except Exception:
                                pass
            except Exception:
                pass

            # 2) Convert alert → drop directly in Suricata's rule files
            #    No separate -ips.rules = no SID conflicts
            drp = re.search(r"^\s*default-rule-path:\s*(.+)$",
                            Path(cfg_path).read_text(errors="replace"), re.MULTILINE)
            sur_rules = Path(
                drp.group(1).strip().strip('"').strip("'")
            ) if drp else Path(cfg_path).parent / "rules"
            console.print("  [cyan]IPS:[/cyan] Converting rules to drop mode…")
            for rf in sorted(sur_rules.glob("oc-*.rules")):
                try:
                    text = rf.read_text(encoding="utf-8", errors="replace")
                    new_text = re.sub(r"^alert ", "drop ", text, flags=re.MULTILINE)
                    if new_text != text:
                        rf.write_text(new_text, encoding="utf-8")
                except Exception as e:
                    _log(f"IPS rule convert error ({rf.name}): {e}", "WARN")
            console.print("  [green]✓[/green] Rules converted to drop mode")

            # 3) Ensure nfq section exists in suricata.yaml
            console.print("  [cyan]IPS:[/cyan] Configuring suricata.yaml NFQ…")
            _configure_suricata_nfq(cfg_path, queue_num)

            # 4) iptables NFQUEUE rules
            console.print(f"  [cyan]IPS:[/cyan] Setting up iptables NFQUEUE (iface={interface})…")
            ok_ips, err_ips = _setup_linux_ips(interface, queue_num)
            if not ok_ips:
                # Revert drop→alert
                for rf in sur_rules.glob("oc-*.rules"):
                    try:
                        t = rf.read_text(encoding="utf-8", errors="replace")
                        rf.write_text(re.sub(r"^drop ", "alert ", t, flags=re.MULTILINE), encoding="utf-8")
                    except Exception:
                        pass
                return False, f"IPS setup failed: {err_ips}"
            console.print("  [green]✓[/green] iptables NFQUEUE rules added")

        # Update af-packet interface in suricata.yaml
        try:
            yaml_text = Path(cfg_path).read_text(encoding="utf-8", errors="replace")
            new_yaml = re.sub(
                r"(- interface:) (?!default)\S+",
                lambda m: f"{m.group(1)} {interface}",
                yaml_text, count=1,
            )
            if new_yaml != yaml_text:
                Path(cfg_path).write_text(new_yaml, encoding="utf-8")
                _log(f"suricata.yaml interface updated: {interface}")
        except Exception as e:
            _log(f"yaml update warning: {e}")

        # Stop any previous instance
        if self.is_running():
            self.stop()
            time.sleep(1)

        # Start Suricata
        if mode == "IPS" and OS == "Linux":
            # IPS: Start Suricata in NFQUEUE mode as background process
            # Using Popen (not -D daemon) to avoid fork race condition with NFQ binding
            console.print(f"  [cyan]IPS:[/cyan] Starting Suricata in NFQUEUE mode (queue={queue_num})…")
            log_dir = Path("/var/log/suricata")
            log_dir.mkdir(parents=True, exist_ok=True)
            ips_log = open(str(log_dir / "suricata-ips.log"), "w")
            cmd = [binary, "-q", str(queue_num), "-c", cfg_path,
                   "-l", str(log_dir), "--pidfile", "/var/run/suricata.pid"]
            _log(f"IPS Cmd: {' '.join(cmd)}")
            try:
                proc = subprocess.Popen(
                    cmd, stdout=ips_log, stderr=subprocess.STDOUT,
                    preexec_fn=os.setpgrp,
                )
            except Exception as e:
                _teardown_linux_ips(interface, queue_num)
                return False, f"Could not start Suricata: {e}"

            # Wait for NFQ binding (up to 15 seconds)
            for tick in range(15):
                time.sleep(1)
                if proc.poll() is not None:
                    ips_log.flush()
                    try:
                        crash = (log_dir / "suricata-ips.log").read_text(errors="ignore")[-1200:]
                    except Exception:
                        crash = "(could not read log)"
                    _teardown_linux_ips(interface, queue_num)
                    return False, (
                        f"Suricata IPS exited at second {tick+1}.\n\n"
                        f"Log:\n{crash}\n\n"
                        f"Manual test: sudo suricata -q {queue_num} -c {cfg_path} -v"
                    )
                # Check if NFQ queue is bound
                try:
                    nfq = Path("/proc/net/netfilter/nfnetlink_queue")
                    if nfq.exists() and str(queue_num) in nfq.read_text():
                        console.print(f"  [green]✓[/green] NFQUEUE bound (pid={proc.pid})")
                        _log(f"Suricata IPS running: pid={proc.pid} iface={interface} queue={queue_num}")
                        return True, "OK"
                except Exception:
                    pass

            # Still running after 15s but no NFQ confirm — probably still loading rules
            if proc.poll() is None:
                _log(f"Suricata IPS running (slow start): pid={proc.pid}")
                return True, "OK"

            ips_log.flush()
            try:
                crash = (log_dir / "suricata-ips.log").read_text(errors="ignore")[-1200:]
            except Exception:
                crash = ""
            _teardown_linux_ips(interface, queue_num)
            return False, (
                f"Suricata IPS failed to start.\n\n"
                f"Log:\n{crash}\n\n"
                f"Manual test: sudo suricata -q {queue_num} -c {cfg_path} -v"
            )
        elif OS == "Darwin":
            # macOS: no systemctl — start Suricata directly as a background process
            _ensure_suricata_ready(cfg_path)
            # Use default-log-dir from suricata.yaml if set, else fallback
            log_dir = Path("/usr/local/var/log/suricata")
            try:
                _yaml = Path(cfg_path).read_text(errors="replace")
                _m = re.search(r"^\s*default-log-dir:\s*(.+)$", _yaml, re.MULTILINE)
                if _m:
                    _parsed = _m.group(1).strip().strip('"').strip("'")
                    if _parsed:
                        log_dir = Path(_parsed)
            except Exception:
                pass
            log_dir.mkdir(parents=True, exist_ok=True)
            run_log = open(str(SURICATA_RUN_LOG), "w", encoding="utf-8")
            cmd = [binary, "-c", cfg_path, "-i", interface,
                   "-l", str(log_dir), "--pidfile", "/var/run/suricata.pid"]
            _log(f"macOS Cmd: {' '.join(cmd)}")
            try:
                proc = subprocess.Popen(
                    cmd, stdout=run_log, stderr=subprocess.STDOUT,
                    preexec_fn=os.setpgrp,
                )
            except PermissionError:
                return False, "Permission denied — run with sudo."
            except Exception as e:
                return False, f"Suricata could not be started: {e}"

            # Wait for Suricata to start (up to 15 seconds)
            for tick in range(15):
                time.sleep(1)
                if proc.poll() is not None:
                    run_log.flush()
                    try:
                        detail = SURICATA_RUN_LOG.read_text(
                            encoding="utf-8", errors="replace"
                        ).strip()[-1500:]
                    except Exception:
                        detail = "(could not read log)"
                    return False, (
                        f"Suricata exited at second {tick + 1} (exit {proc.returncode}).\n\n"
                        f"Output:\n{detail or '(empty)'}\n\nFull log: {SURICATA_RUN_LOG}"
                    )
                if self.is_running():
                    _log(f"Suricata running: pid={proc.pid} iface={interface} ({mode})")
                    self.config.set("suricata", "eve_log", str(log_dir / "eve.json"))
                    self.config.set("suricata", "fast_log", str(log_dir / "fast.log"))
                    return True, "OK"

            # Still running but is_running didn't confirm yet
            if proc.poll() is None:
                _log(f"Suricata running (slow start): pid={proc.pid}")
                self.config.set("suricata", "eve_log", str(log_dir / "eve.json"))
                self.config.set("suricata", "fast_log", str(log_dir / "fast.log"))
                return True, "OK"

            try:
                detail = SURICATA_RUN_LOG.read_text(
                    encoding="utf-8", errors="replace"
                ).strip()[-800:]
            except Exception:
                detail = "(could not read log)"
            return False, (
                f"Suricata did not start within 15 seconds.\n\n"
                f"Last log:\n{detail or '(empty)'}\n\nFull log: {SURICATA_RUN_LOG}"
            )
        else:
            # Linux IDS: systemctl start
            r = subprocess.run(
                ["systemctl", "start", "suricata"],
                capture_output=True, text=True, timeout=30,
            )
            if r.returncode != 0:
                jlog = subprocess.run(
                    ["journalctl", "-u", "suricata", "-n", "20", "--no-pager", "-o", "cat"],
                    capture_output=True, text=True, timeout=5,
                )
                err = jlog.stdout.strip()[-600:] or r.stderr.strip()
                return False, f"Suricata could not be started:\n{err}"
            _log(f"Suricata started: {interface} ({mode})")

        return True, "OK"
    # ── Stop / Reload ─────────────────────────────────────────────────────────

    def stop(self) -> bool:
        try:
            if OS == "Windows":
                r = subprocess.run(
                    ["taskkill", "/F", "/IM", "suricata.exe"],
                    capture_output=True, text=True,
                    encoding="utf-8", errors="replace",
                )
                return r.returncode == 0
            else:
                # 1) Kill via PID file first (most reliable)
                for pid_f in ["/var/run/suricata.pid", "/run/suricata.pid"]:
                    try:
                        pid = int(Path(pid_f).read_text().strip())
                        os.kill(pid, 9)
                        _log(f"Killed Suricata pid={pid} from {pid_f}")
                    except Exception:
                        pass
                # 2) systemctl stop (Linux only)
                if OS == "Linux":
                    subprocess.run(["systemctl", "stop", "suricata"],
                                   capture_output=True, timeout=15)
                time.sleep(1)
                # 3) Kill any remaining process with pkill -x (exact name)
                subprocess.run(["pkill", "-9", "-x", "suricata"],
                               capture_output=True)
                time.sleep(1)
                # 3) Clean PID files
                for pid_f in ["/var/run/suricata.pid", "/run/suricata.pid"]:
                    try:
                        Path(pid_f).unlink(missing_ok=True)
                    except Exception:
                        pass
                # 4) IPS cleanup
                if OS == "Linux":
                    if self.config.get("suricata", "mode", default="IDS") == "IPS":
                        iface = self.config.get("suricata", "interface", default="")
                        queue_num = self.config.get("suricata", "ips_queue_num", default=0)
                        _teardown_linux_ips(iface, queue_num)
                        # Revert drop→alert in Suricata's rule files
                        cfg = self.config.get("suricata", "config", default="")
                        if cfg:
                            _revert_suricata_nfq(cfg)
                            try:
                                yt = Path(cfg).read_text(errors="replace")
                                drp = re.search(r"^\s*default-rule-path:\s*(.+)$", yt, re.MULTILINE)
                                sr = Path(drp.group(1).strip().strip('"').strip("'")) if drp \
                                     else Path(cfg).parent / "rules"
                                for rf in sr.glob("oc-*.rules"):
                                    text = rf.read_text(encoding="utf-8", errors="replace")
                                    new_text = re.sub(r"^drop ", "alert ", text, flags=re.MULTILINE)
                                    if new_text != text:
                                        rf.write_text(new_text, encoding="utf-8")
                                _log("IPS stop: rules reverted to alert mode")
                            except Exception as e:
                                _log(f"IPS rule revert error: {e}", "WARN")
                return True
        except Exception:
            return False
    def reload_rules(self) -> bool:
        if OS == "Windows":
            iface = self.config.get("suricata", "interface", default="Ethernet")
            if self.stop():
                time.sleep(1.5)
                ok, _ = self._start_windows(iface)
                return ok
            return False
        return subprocess.run(["pkill", "-USR2", "suricata"],
                              capture_output=True).returncode == 0

    # ── Windows helpers ───────────────────────────────────────────────────────

    def get_active_interfaces(self) -> list:
        if OS == "Windows":
            return self._get_ifaces_windows()
        if OS == "Darwin":
            return self._get_ifaces_macos()
        return self._get_ifaces_unix()

    def _get_ifaces_macos(self) -> list:
        """List network interfaces on macOS using networksetup / ifconfig."""
        SKIP = ("lo", "utun", "gif", "stf", "XHC", "ap", "p2p",
                "awdl", "llw", "bridge", "vmnet", "vboxnet")
        out = []
        seen = set()
        # Method 1: networksetup -listallhardwareports
        try:
            r = subprocess.run(["networksetup", "-listallhardwareports"],
                               capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=8)
            current_label = ""
            for line in r.stdout.splitlines():
                if line.strip().startswith("Hardware Port:"):
                    current_label = line.split(":", 1)[1].strip()
                elif line.strip().startswith("Device:"):
                    dev = line.split(":", 1)[1].strip()
                    if dev and not any(dev.startswith(p) for p in SKIP) and dev not in seen:
                        seen.add(dev)
                        # Check if interface is active via ifconfig
                        try:
                            chk = subprocess.run(["ifconfig", dev],
                                                 capture_output=True, text=True, timeout=4)
                            status = "Up" if "status: active" in chk.stdout.lower() else "Down"
                        except Exception:
                            status = "Unknown"
                        out.append({"name": dev, "npf": "", "status": status,
                                    "label": current_label})
            if out:
                return out
        except Exception:
            pass
        # Method 2: ifconfig -u (up interfaces)
        try:
            r = subprocess.run(["ifconfig", "-u"], capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=6)
            for dev in re.findall(r"^(\S+):", r.stdout, re.MULTILINE):
                if not any(dev.startswith(p) for p in SKIP) and dev not in seen:
                    seen.add(dev)
                    out.append({"name": dev, "npf": "", "status": "Up"})
        except Exception:
            pass
        return out

    def _get_ifaces_windows(self) -> list:
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 "Get-NetAdapter | Select-Object Name,DeviceID,Status | ConvertTo-Json"],
                capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=10,
            )
            data = json.loads(r.stdout)
            if isinstance(data, dict):
                data = [data]
            out = []
            for a in data:
                name   = a.get("Name", "")
                guid   = str(a.get("DeviceID", "")).strip("{}")
                status = str(a.get("Status", ""))
                npf    = "\\Device\\NPF_{" + guid + "}" if guid else ""
                out.append({"name": name, "npf": npf, "status": status})
            return out
        except Exception as e:
            _log(f"get_ifaces_windows: {e}")
            return []

    def _get_ifaces_unix(self) -> list:
        out = []
        try:
            r = subprocess.run(["ip", "-o", "link", "show"],
                               capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                parts = line.split()
                if len(parts) < 2:
                    continue
                name = parts[1].rstrip(":")
                if name in ("lo", ""):
                    continue
                status = "Up" if "UP" in line else "Down"
                out.append({"name": name, "npf": "", "status": status})
        except Exception:
            import os as _os
            try:
                for name in _os.listdir("/sys/class/net"):
                    if name == "lo":
                        continue
                    try:
                        op = open(f"/sys/class/net/{name}/operstate").read().strip()
                        status = "Up" if op == "up" else "Down"
                    except Exception:
                        status = "Unknown"
                    out.append({"name": name, "npf": "", "status": status})
            except Exception as e:
                _log(f"get_ifaces_unix: {e}")
        return out
    def _get_interface_ip(self, friendly_name: str) -> Optional[str]:
        """Return IPv4 of a named Windows interface. Tries PowerShell then ipconfig."""
        # Method 1: PowerShell
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 f"(Get-NetIPAddress -InterfaceAlias '{friendly_name}' "
                 f"-AddressFamily IPv4 -ErrorAction Stop).IPAddress"],
                capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=8,
            )
            ip = (r.stdout.strip().splitlines() or [""])[0].strip()
            if ip and re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                _log(f"IP (PS): {friendly_name} -> {ip}")
                return ip
        except Exception as e:
            _log(f"_get_interface_ip PS: {e}")

        # Method 2: ipconfig
        try:
            r = subprocess.run(["ipconfig"], capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=8)
            in_section = False
            for line in r.stdout.splitlines():
                if friendly_name.lower() in line.lower():
                    in_section = True
                elif in_section:
                    m = re.search(r"IPv4[^:]*:\s*([\d.]+)", line)
                    if m:
                        _log(f"IP (ipconfig): {friendly_name} -> {m.group(1)}")
                        return m.group(1).strip()
                    if not line.strip():
                        in_section = False
        except Exception as e:
            _log(f"_get_interface_ip ipconfig: {e}")

        _log(f"_get_interface_ip: no IP for '{friendly_name}'")
        return None


# ─── Dependency Installer ────────────────────────────────────────────────────

class DepInstaller:

    def npcap_present(self) -> bool:
        if OS != "Windows":
            return True
        # Service check
        try:
            r = subprocess.run(["sc", "query", "npcap"], capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=5)
            if "RUNNING" in r.stdout or "STOPPED" in r.stdout:
                return True
        except Exception:
            pass
        # DLL check
        sys32 = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32"
        if (sys32 / "Npcap" / "wpcap.dll").exists() or (sys32 / "wpcap.dll").exists():
            return True
        # Registry check
        try:
            import winreg  # type: ignore
            winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Npcap", 0, winreg.KEY_READ)
            return True
        except Exception:
            pass
        return False

    def install_npcap(self) -> tuple:
        dest = Path(tempfile.gettempdir()) / f"npcap-{NPCAP_VERSION}.exe"
        if not self._download(NPCAP_URL, dest, f"Npcap v{NPCAP_VERSION}"):
            return False, f"Download failed: {NPCAP_URL}"
        try:
            console.print("  [yellow]The Npcap installer window will open.[/yellow]")
            console.print("  [dim]Complete the installation steps, then continue.[/dim]")
            r = subprocess.run([str(dest)], timeout=300)
            ok = r.returncode in (0, 3010)
            return ok, "" if ok else f"Installer exited {r.returncode}"
        except Exception as e:
            return False, str(e)

    def suricata_present(self) -> bool:
        return SuricataManager(ConfigManager()).is_installed()

    def install_suricata(self) -> tuple:
        if OS == "Windows": return self._install_win()
        if OS == "Darwin":  return self._install_mac()
        return self._install_linux()

    def _install_win(self) -> tuple:
        dest = Path(tempfile.gettempdir()) / f"Suricata-{SURICATA_WIN_VER}.msi"
        if not self._download(SURICATA_WIN_URL, dest, f"Suricata v{SURICATA_WIN_VER}"):
            return False, f"Download failed: {SURICATA_WIN_URL}"
        try:
            console.print("  [dim]Running Suricata MSI installer (silent)…[/dim]")
            r = subprocess.run(
                ["msiexec", "/i", str(dest), "/quiet", "/norestart", "ADDLOCAL=ALL"],
                timeout=300,
            )
            ok = r.returncode in (0, 3010)
            return ok, "" if ok else f"MSI exited {r.returncode}"
        except Exception as e:
            return False, str(e)

    def _install_mac(self) -> tuple:
        brew = self._find_brew()

        # On macOS, Homebrew REFUSES to run as root. If we're root (sudo cgti install),
        # we must drop to the real user via sudo -u $SUDO_USER for all brew commands.
        real_user = os.environ.get("SUDO_USER", "")
        is_root = os.geteuid() == 0

        # ── Step 1: Install Homebrew if not found ──
        if not brew:
            console.print("\n  [yellow]Homebrew not found — installing automatically…[/yellow]")
            if is_root and not real_user:
                return False, (
                    "Running as root but $SUDO_USER is not set.\n"
                    "  Run with sudo (not su): sudo cgti install\n"
                    "  Or install Homebrew as your normal user first."
                )
            try:
                # Download installer first (curl runs fine as root)
                dl = subprocess.run(
                    ["curl", "-fsSL",
                     "https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh",
                     "-o", "/tmp/_brew_install.sh"],
                    timeout=60,
                )
                if dl.returncode != 0:
                    return False, "Failed to download Homebrew installer."

                # Run installer — if root, drop to real user with env passthrough
                if is_root and real_user:
                    install_cmd = ["sudo", "-u", real_user, "--",
                                   "env", "NONINTERACTIVE=1",
                                   "/bin/bash", "/tmp/_brew_install.sh"]
                else:
                    env = os.environ.copy()
                    env["NONINTERACTIVE"] = "1"
                    install_cmd = ["/bin/bash", "/tmp/_brew_install.sh"]

                console.print(f"  [dim]{' '.join(install_cmd)}[/dim]\n")
                r = subprocess.run(install_cmd, timeout=900,
                                   env=env if not (is_root and real_user) else None)
                if r.returncode != 0:
                    return False, (
                        f"Homebrew installation failed (exit {r.returncode}).\n"
                        "  Try manually as your normal user (not sudo):\n"
                        '  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/'
                        'Homebrew/install/HEAD/install.sh)"'
                    )
            except subprocess.TimeoutExpired:
                return False, "Homebrew installation timed out (>15 min)."
            except Exception as e:
                return False, f"Homebrew installation error: {e}"

            brew = self._find_brew()
            if not brew:
                return False, (
                    "Homebrew installed but brew binary not found.\n"
                    "  Expected: /opt/homebrew/bin/brew (Apple Silicon)\n"
                    "         or /usr/local/bin/brew (Intel Mac)\n"
                    "  Try: open a new terminal → cgti install"
                )
            console.print(f"  [green]✓ Homebrew installed:[/green] {brew}\n")

        # ── Step 2: Install Suricata via Homebrew ──
        if is_root and real_user:
            install_cmd = ["sudo", "-u", real_user, "--", brew, "install", "suricata"]
        else:
            install_cmd = [brew, "install", "suricata"]
        console.print(f"  [dim]{' '.join(install_cmd)}[/dim]")
        console.print("  [dim]This may take a few minutes…[/dim]\n")
        try:
            r = subprocess.run(install_cmd, timeout=900)
            if r.returncode == 0:
                return True, ""
            return False, (
                f"brew install suricata failed (exit {r.returncode}).\n"
                "  Try manually: brew install suricata"
            )
        except subprocess.TimeoutExpired:
            return False, "brew install suricata timed out (>15 min). Try manually."
        except Exception as e:
            return False, f"brew install suricata error: {e}"

    @staticmethod
    def _find_brew() -> Optional[str]:
        """Find Homebrew binary — checks PATH then known install locations."""
        found = shutil.which("brew")
        if found:
            return found
        # Apple Silicon (M1/M2/M3/M4) default location
        if Path("/opt/homebrew/bin/brew").exists():
            return "/opt/homebrew/bin/brew"
        # Intel Mac default location
        if Path("/usr/local/bin/brew").exists():
            return "/usr/local/bin/brew"
        return None

    def _install_linux(self) -> tuple:
        if shutil.which("apt-get"):
            return self._install_linux_apt()
        for mgr, cmd in [
            ("dnf",    ["dnf",    "install", "-y", "suricata"]),
            ("yum",    ["yum",    "install", "-y", "suricata"]),
            ("pacman", ["pacman", "-S", "--noconfirm", "suricata"]),
            ("zypper", ["zypper", "install", "-y", "suricata"]),
        ]:
            if shutil.which(mgr):
                console.print(f"  [dim]{' '.join(cmd)}[/dim]")
                r = subprocess.run(cmd, timeout=300)
                return (r.returncode == 0), ("" if r.returncode == 0 else f"{mgr} failed")
        return False, "No supported package manager found (apt/dnf/yum/pacman/zypper)"

    def _install_linux_apt(self) -> tuple:
        """Ubuntu/Debian: once try direct apt, then fallback to OISF PPA."""
        # Try directly first
        console.print("  [dim]apt-get install -y suricata[/dim]")
        r = subprocess.run(["apt-get", "install", "-y", "suricata"],
                           timeout=300, capture_output=True, text=True)
        if r.returncode == 0:
            return True, ""

        # If package not found, add OISF PPA (Ubuntu 18.04 - 22.04)
        console.print("  [yellow]Suricata not in official repo, adding OISF PPA...[/yellow]")
        steps = [
            ["apt-get", "install", "-y", "software-properties-common"],
            ["add-apt-repository", "-y", "ppa:oisf/suricata-stable"],
            ["apt-get", "update", "-y"],
            ["apt-get", "install", "-y", "suricata"],
        ]
        for cmd in steps:
            console.print(f"  [dim]{' '.join(cmd)}[/dim]")
            r = subprocess.run(cmd, timeout=300,
                               capture_output=True, text=True)
            if r.returncode != 0:
                # add-apt-repository yoksa dene
                if "add-apt-repository" in cmd[0] and r.returncode != 0:
                    subprocess.run(["apt-get", "install", "-y",
                                    "software-properties-common"], timeout=60)
                    r = subprocess.run(cmd, timeout=300)
                    if r.returncode != 0:
                        return False, f"Could not add PPA: {r.stderr.strip()[:200]}"
                elif "suricata" in cmd:
                    return False, f"apt-get failed: {r.stderr.strip()[:200]}"
        return True, ""

    def _download(self, url: str, dest: Path, label: str) -> bool:
        console.print(f"  [cyan]↓[/cyan] Downloading {label}…  [dim]{url}[/dim]")
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": f"CGTI-Lite/{VERSION} (Windows NT)"},
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                total = int(resp.headers.get("Content-Length", 0))
                downloaded = 0
                chunk = 65536
                with open(dest, "wb") as f:
                    while True:
                        data = resp.read(chunk)
                        if not data:
                            break
                        f.write(data)
                        downloaded += len(data)
                        if total > 0:
                            pct = min(100, int(downloaded * 100 / total))
                            bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
                            print(f"\r  [{bar}] {pct}%  ", end="", flush=True)
            print()
            return True
        except Exception as e:
            print()
            console.print(f"  [red]Download error: {e}[/red]")
            return False


# ─── Rule Manager ────────────────────────────────────────────────────────────

class RuleManager:
    def __init__(self, config: ConfigManager):
        self.rules_dir = Path(config.get("cgti", "rules_dir", default=str(RULES_DIR)))
        # Fallback: if CGTI rules dir is empty, try Suricata's rules directory
        cfg_path = config.get("suricata", "config", default="")
        self._suricata_rules_dir = None
        if cfg_path and Path(cfg_path).exists():
            try:
                yt = Path(cfg_path).read_text(errors="replace")
                drp = re.search(r"^\s*default-rule-path:\s*(.+)$", yt, re.MULTILINE)
                if drp:
                    self._suricata_rules_dir = Path(drp.group(1).strip().strip('"').strip("'"))
            except Exception:
                pass

    def _effective_rules_dir(self) -> Path:
        """Return the directory that actually contains oc-*.rules files."""
        if self.rules_dir.exists() and list(self.rules_dir.glob("oc-*.rules")):
            return self.rules_dir
        if self._suricata_rules_dir and self._suricata_rules_dir.exists() \
           and list(self._suricata_rules_dir.glob("oc-*.rules")):
            return self._suricata_rules_dir
        # Hardcoded fallback: common Suricata rules directories
        for fallback in ["/var/lib/suricata/rules", "/etc/suricata/rules",
                         "/usr/local/etc/suricata/rules"]:
            p = Path(fallback)
            if p.exists() and list(p.glob("oc-*.rules")):
                return p
        return self.rules_dir

    def rule_files(self) -> list:
        d = self._effective_rules_dir()
        return sorted(d.glob("oc-*.rules")) if d.exists() else []

    def list_rules(self, filename: str = None) -> list:
        rules = []
        d = self._effective_rules_dir()
        files = [d / filename] if filename else self.rule_files()
        for f in files:
            f = Path(f)
            if not f.exists():
                continue
            try:
                for i, line in enumerate(f.read_text(errors="ignore").splitlines(), 1):
                    line = line.strip()
                    if not line:
                        continue
                    enabled = not line.startswith("#")
                    clean   = line.lstrip("# ").strip()
                    parts   = clean.split()
                    if not parts or parts[0] not in (
                        "alert", "drop", "pass", "reject", "rejectsrc", "rejectdst"
                    ):
                        continue
                    sid = clean.split("sid:")[1].split(";")[0].strip() if "sid:" in clean else "N/A"
                    msg = clean.split('msg:"')[1].split('"')[0] if 'msg:"' in clean else "N/A"
                    rules.append({
                        "file": f.name, "line": i, "sid": sid,
                        "action": parts[0], "msg": msg,
                        "enabled": enabled, "raw": clean,
                    })
            except Exception:
                continue
        return rules

    def toggle_rule(self, sid: str, enable: bool) -> bool:
        for f in self.rule_files():
            try:
                lines = Path(f).read_text(errors="ignore").splitlines(keepends=True)
                new_lines, changed = [], False
                for line in lines:
                    # Use regex to strip only leading "# " comment markers
                    stripped = re.sub(r"^#\s*", "", line.strip())
                    if f"sid:{sid};" in stripped or f"sid:{sid} " in stripped:
                        new_lines.append((stripped if enable else f"# {stripped}") + "\n")
                        changed = True
                    else:
                        new_lines.append(line)
                if changed:
                    Path(f).write_text("".join(new_lines))
                    return True
            except Exception as e:
                _log(f"toggle_rule error in {f}: {e}", "ERROR")
                continue
        return False

    def add_rule(self, rule_text: str, filename: str = "openclaw-custom.rules") -> bool:
        target = self.rules_dir / filename
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        try:
            with open(target, "a") as fp:
                fp.write(f"\n{rule_text.strip()}\n")
            return True
        except Exception:
            return False


# ─── IP Block Manager ────────────────────────────────────────────────────────

class IPBlockManager:
    def __init__(self):
        self.data: dict = {"blocked": []}
        if BLOCKED_FILE.exists():
            try:
                self.data = json.loads(BLOCKED_FILE.read_text())
            except Exception as e:
                _log(f"blocked_ips.json load error: {e}", "WARN")

    def _save(self):
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        BLOCKED_FILE.write_text(json.dumps(self.data, indent=2))

    def list(self) -> list:
        return self.data.get("blocked", [])

    def block(self, ip: str, reason: str = "Manual") -> bool:
        if not _validate_ip(ip):
            _log(f"IP block rejected (invalid format): {ip!r}", "WARN")
            return False
        if any(e["ip"] == ip for e in self.data["blocked"]):
            return False
        self.data["blocked"].append({
            "ip": ip, "reason": reason,
            "timestamp": datetime.now().isoformat(), "active": True,
        })
        self._save()
        self._fw(ip, block=True)
        return True

    def unblock(self, ip: str) -> bool:
        before = len(self.data["blocked"])
        self.data["blocked"] = [e for e in self.data["blocked"] if e["ip"] != ip]
        if len(self.data["blocked"]) < before:
            self._save()
            self._fw(ip, block=False)
            return True
        return False

    def clear_all(self):
        for e in self.data["blocked"]:
            self._fw(e["ip"], block=False)
        self.data["blocked"] = []
        self._save()

    _PF_TABLE_FILE = Path("/etc/cgti_blocked_ips")
    _PF_TABLE_NAME = "cgti_blocked"

    def _ensure_pf_rules(self):
        """Ensure pf.conf has CGTI table + block rules (no anchors, direct rules)."""
        pf_conf = Path("/etc/pf.conf")
        marker = "# CGTI-LITE-BLOCK-START"
        try:
            if not pf_conf.exists():
                return
            content = pf_conf.read_text(errors="replace")
            if marker in content:
                return  # already configured

            # Create empty table file if it doesn't exist
            if not self._PF_TABLE_FILE.exists():
                self._PF_TABLE_FILE.write_text("", encoding="utf-8")

            # Back up original pf.conf
            backup = Path("/etc/pf.conf.cgti_backup")
            if not backup.exists():
                backup.write_text(content, encoding="utf-8")
                _log(f"Backed up pf.conf → {backup}")

            # Add table + block rules directly to pf.conf (before anchor lines)
            cgti_block = (
                f"\n{marker}\n"
                f"table <{self._PF_TABLE_NAME}> persist file \"{self._PF_TABLE_FILE}\"\n"
                f"block in quick from <{self._PF_TABLE_NAME}> to any\n"
                f"block out quick from any to <{self._PF_TABLE_NAME}>\n"
                f"# CGTI-LITE-BLOCK-END\n"
            )

            # Insert BEFORE the first anchor line so block rules are evaluated first
            lines = content.split("\n")
            insert_idx = None
            for i, line in enumerate(lines):
                if line.strip().startswith("anchor ") or line.strip().startswith("load anchor"):
                    insert_idx = i
                    break

            if insert_idx is not None:
                lines.insert(insert_idx, cgti_block)
                new_content = "\n".join(lines)
            else:
                new_content = content + cgti_block

            pf_conf.write_text(new_content, encoding="utf-8")

            # Reload pf with new rules
            r = subprocess.run(["pfctl", "-f", "/etc/pf.conf"],
                               capture_output=True, text=True)
            subprocess.run(["pfctl", "-e"], capture_output=True)
            _log(f"pf.conf updated with CGTI block rules: {r.stderr.strip()}")
        except PermissionError:
            _log("Cannot modify /etc/pf.conf — run with sudo for IP blocking", "WARN")
        except Exception as e:
            _log(f"_ensure_pf_rules error: {e}", "ERROR")

    def _fw(self, ip: str, block: bool):
        if not _validate_ip(ip):
            _log(f"_fw rejected invalid IP: {ip!r}", "WARN")
            return
        try:
            if OS == "Linux":
                # -I (insert at top) ensures block rules are evaluated BEFORE
                # any NFQUEUE rules that IPS mode may add
                flag = "-I" if block else "-D"
                subprocess.run(["iptables", flag, "INPUT", "-s", ip, "-j", "DROP"],
                               capture_output=True)
                # Outbound block (C2/exfiltration prevention)
                subprocess.run(["iptables", flag, "OUTPUT", "-d", ip, "-j", "DROP"],
                               capture_output=True)
            elif OS == "Darwin":
                # macOS: use pf table file — no anchors, direct rules in pf.conf
                self._ensure_pf_rules()
                table = self._PF_TABLE_NAME
                if block:
                    # Add to running pf table
                    r = subprocess.run(
                        ["pfctl", "-t", table, "-T", "add", ip],
                        capture_output=True, text=True)
                    # Also persist to file so it survives reboot
                    try:
                        existing = set()
                        if self._PF_TABLE_FILE.exists():
                            existing = {l.strip() for l in self._PF_TABLE_FILE.read_text().splitlines() if l.strip()}
                        if ip not in existing:
                            existing.add(ip)
                            self._PF_TABLE_FILE.write_text("\n".join(sorted(existing)) + "\n")
                    except Exception as fe:
                        _log(f"Table file write error: {fe}", "WARN")
                    # Ensure pf is enabled
                    subprocess.run(["pfctl", "-e"], capture_output=True)
                    _log(f"pf block {ip}: {r.stderr.strip()}")
                else:
                    # Remove from running pf table
                    r = subprocess.run(
                        ["pfctl", "-t", table, "-T", "delete", ip],
                        capture_output=True, text=True)
                    # Remove from persistent file
                    try:
                        if self._PF_TABLE_FILE.exists():
                            lines = {l.strip() for l in self._PF_TABLE_FILE.read_text().splitlines() if l.strip()}
                            lines.discard(ip)
                            self._PF_TABLE_FILE.write_text("\n".join(sorted(lines)) + "\n" if lines else "")
                    except Exception as fe:
                        _log(f"Table file remove error: {fe}", "WARN")
                    _log(f"pf unblock {ip}: {r.stderr.strip()}")
            elif OS == "Windows":
                rule_in   = f"CGTI_BLOCK_IN_{ip.replace('.', '_')}"
                rule_out  = f"CGTI_BLOCK_OUT_{ip.replace('.', '_')}"
                rule_old  = f"CGTI_BLOCK_{ip.replace('.', '_')}"
                if block:
                    # Inbound block
                    subprocess.run(
                        ["netsh", "advfirewall", "firewall", "add", "rule",
                         f"name={rule_in}", "dir=in", "action=block", f"remoteip={ip}"],
                        capture_output=True)
                    # Outbound block (C2/exfiltration prevention)
                    subprocess.run(
                        ["netsh", "advfirewall", "firewall", "add", "rule",
                         f"name={rule_out}", "dir=out", "action=block", f"remoteip={ip}"],
                        capture_output=True)
                else:
                    # Delete new-format rules (IN + OUT)
                    subprocess.run(
                        ["netsh", "advfirewall", "firewall", "delete", "rule",
                         f"name={rule_in}"],
                        capture_output=True)
                    subprocess.run(
                        ["netsh", "advfirewall", "firewall", "delete", "rule",
                         f"name={rule_out}"],
                        capture_output=True)
                    # Delete legacy rule format (backward compat v1.1.0)
                    subprocess.run(
                        ["netsh", "advfirewall", "firewall", "delete", "rule",
                         f"name={rule_old}"],
                        capture_output=True)
        except Exception as e:
            _log(f"Firewall rule error ({ip}, block={block}): {e}", "ERROR")


# ─── Log Viewer ──────────────────────────────────────────────────────────────

class LogViewer:
    def __init__(self, config: ConfigManager):
        self.eve_log = config.get("suricata", "eve_log") or _auto_eve()

    def alerts(self, limit: int = 50, severity: int = None) -> list:
        if not self.eve_log or not Path(self.eve_log).exists():
            return []
        result = []
        # Progressive search: start with a reasonable window, expand if no alerts found
        # This prevents "No alerts found" when stats/flow events push alerts out of range
        search_depths = [limit * 20, limit * 80, limit * 200]
        for max_lines in search_depths:
            try:
                for line in _tail_lines(self.eve_log, max_lines=max_lines):
                    try:
                        e = json.loads(line)
                        if e.get("event_type") != "alert":
                            continue
                        a   = e.get("alert", {})
                        sev = a.get("severity", 0)
                        if severity and sev != severity:
                            continue
                        result.append({
                            "timestamp": e.get("timestamp", "")[:19].replace("T", " "),
                            "src_ip":    e.get("src_ip", ""),
                            "dest_ip":   e.get("dest_ip", ""),
                            "proto":     e.get("proto", ""),
                            "msg":       a.get("signature", ""),
                            "severity":  sev,
                            "sid":       a.get("signature_id", ""),
                        })
                    except Exception:
                        continue
            except Exception as e:
                _log(f"LogViewer.alerts error: {e}", "ERROR")
            if result:
                break  # Found alerts, no need to search deeper
        return result[:limit]


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _apply_openclaw_rules(yaml_path: str, our_rules_dir: Path) -> tuple:
    """
    Comments out all rules in the rule-files section of suricata.yaml,
    adds the .rules files from our_rules_dir as active entries, and
    copies them to Suricata's rules/ directory.
    """
    try:
        our_files = sorted(our_rules_dir.glob("*.rules"))
        if not our_files:
            return [], "No .rules files found in the rules/ directory"

        text = Path(yaml_path).read_text(encoding="utf-8", errors="replace")

        # Find and update the rule-files: section
        section_re = re.compile(
            r"(^rule-files:\n)((?:[ \t]*.*\n)*?)(?=^\S|\Z)",
            re.MULTILINE,
        )
        m = section_re.search(text)
        if not m:
            return [], "No 'rule-files:' section found in suricata.yaml"

        header   = m.group(1)
        old_body = m.group(2)

        # Comment out existing lines
        commented = []
        for line in old_body.splitlines(keepends=True):
            stripped = line.lstrip()
            if stripped.startswith("#") or stripped.strip() == "":
                commented.append(line)
            else:
                commented.append("  #" + line.lstrip())

        # Add our files
        new_lines = [f"  - {f.name}\n" for f in our_files]
        new_body  = "".join(commented) + "".join(new_lines)

        new_text = text[:m.start(2)] + new_body + text[m.end(2):]
        Path(yaml_path).write_text(new_text, encoding="utf-8")

        # Copy to Suricata rules directory
        drp = re.search(r"^\s*default-rule-path:\s*(.+)$", new_text, re.MULTILINE)
        sur_rules = Path(
            drp.group(1).strip().strip('"').strip("'")
        ) if drp else Path(yaml_path).parent / "rules"
        sur_rules.mkdir(parents=True, exist_ok=True)

        copied = []
        for f in our_files:
            dest = sur_rules / f.name
            shutil.copy2(str(f), str(dest))
            copied.append(f.name)
            _log(f"Rule copied: {f} -> {dest}")

        return copied, ""

    except PermissionError:
        return [], "Permission error — run as Administrator."
    except Exception as e:
        return [], str(e)


def _ensure_suricata_ready(yaml_path: str):
    """Create any missing .rules files and threshold.config listed in suricata.yaml."""
    try:
        text = Path(yaml_path).read_text(encoding="utf-8", errors="replace")
        ydir = Path(yaml_path).parent

        drp       = re.search(r"^\s*default-rule-path:\s*(.+)$", text, re.MULTILINE)
        rules_dir = Path(drp.group(1).strip().strip('"').strip("'")) if drp else ydir / "rules"

        for m in re.finditer(r"^\s*-\s+(\S+\.rules)", text, re.MULTILINE):
            fname = m.group(1).strip()
            fpath = Path(fname) if Path(fname).is_absolute() else rules_dir / fname
            if fpath.exists():
                continue
            try:
                fpath.parent.mkdir(parents=True, exist_ok=True)
                fpath.write_text("# Auto-created by CGTI Lite\n", encoding="utf-8")
                console.print(f"  [green]✓[/green] Rule file created: [dim]{fpath}[/dim]")
                _log(f"Created rule file: {fpath}")
            except Exception as e:
                _log(f"Could not create {fpath}: {e}")

        for m in re.finditer(r"threshold-file:\s*['\"]?([^'\"#\n]+)['\"]?", text):
            raw   = m.group(1).strip().replace("\\\\", "\\")
            tpath = Path(raw) if Path(raw).is_absolute() else ydir / raw
            if not tpath.exists():
                try:
                    tpath.parent.mkdir(parents=True, exist_ok=True)
                    tpath.write_text("# threshold.config — auto-created\n", encoding="utf-8")
                    _log(f"Created threshold.config: {tpath}")
                except Exception as e:
                    _log(f"Could not create threshold.config: {e}")

    except Exception as e:
        _log(f"_ensure_suricata_ready: {e}")


def _auto_eve() -> Optional[str]:
    return next((p for p in SURICATA_LOGS.get(OS, []) if Path(p).exists()), None)

def _sev_color(sev: int) -> str:
    return {1: "bold red", 2: "red", 3: "yellow", 4: "cyan"}.get(sev, "white")


# Regex to extract domain-like patterns from Suricata alert signatures
_DOMAIN_IN_SIG_RE = re.compile(
    r"(?:DNS[^a-z]*(?:Query|Lookup|Resolve)[^a-z]*(?:for\s+|to\s+|-\s*)?)"
    r"([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*"
    r"\.[a-zA-Z]{2,})",
    re.IGNORECASE,
)
# Fallback: extract any FQDN-like pattern from signature text
_DOMAIN_FALLBACK_RE = re.compile(
    r"\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*"
    r"\.[a-zA-Z]{2,15})\b",
    re.IGNORECASE,
)
# TLDs/patterns to EXCLUDE from domain extraction (common false positives)
_NOT_DOMAINS = {"rev", "1", "2", "3", "4", "in-addr.arpa"}

def _extract_domain_from_sig(signature: str) -> str:
    """Extract a domain name from a Suricata alert signature string."""
    if not signature:
        return ""
    m = _DOMAIN_IN_SIG_RE.search(signature)
    if m:
        d = m.group(1).lower().rstrip(".")
        if "." in d and d.split(".")[-1] not in _NOT_DOMAINS:
            return d
    # Fallback: find any FQDN in the signature
    for m in _DOMAIN_FALLBACK_RE.finditer(signature):
        d = m.group(1).lower().rstrip(".")
        if "." in d and d.split(".")[-1] not in _NOT_DOMAINS \
           and not d.endswith(".arpa") and len(d.split(".")) >= 2:
            return d
    return ""


# Cache resolved domains to avoid repeated DNS lookups in the same session
_dns_resolve_cache: dict = {}

def _resolve_domain(domain: str) -> list:
    """Resolve a domain to IP addresses using system DNS. Returns list of IPs."""
    if domain in _dns_resolve_cache:
        return _dns_resolve_cache[domain]
    ips = []
    try:
        import socket
        results = socket.getaddrinfo(domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for res in results:
            ip = res[4][0]
            if ip and _validate_ip(ip) and ip not in ips:
                ips.append(ip)
    except Exception as e:
        _log(f"DNS resolve failed for {domain}: {e}", "WARN")
    _dns_resolve_cache[domain] = ips
    return ips

def _running_badge(ok: bool) -> str:
    return "[bold green]● RUNNING[/bold green]" if ok else "[bold red]● STOPPED[/bold red]"

def _action_color(a: str) -> str:
    return {"alert": "yellow", "drop": "red", "pass": "green", "reject": "red"}.get(a, "white")

def _is_admin() -> bool:
    if OS != "Windows":
        return True
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def _log(msg: str, level: str = "INFO"):
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        # Log rotation — rename to .bak if exceeds LOG_MAX_BYTES
        if LOG_FILE.exists() and LOG_FILE.stat().st_size > LOG_MAX_BYTES:
            bak = LOG_FILE.with_suffix(".log.bak")
            try:
                if bak.exists():
                    bak.unlink()
                LOG_FILE.rename(bak)
            except Exception:
                pass
        with open(LOG_FILE, "a") as f:
            f.write(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] [{level}] {msg}\n")
    except Exception:
        pass


# ─── Install Wizard ──────────────────────────────────────────────────────────

class InstallWizard:
    def __init__(self):
        self.cfg      = ConfigManager()
        self.sur      = SuricataManager(self.cfg)
        self.dep      = DepInstaller()
        self.results: list  = []
        self.warnings: list = []

    def _ok(self, label, value):
        self.results.append(("[green]✓[/green]", label, str(value)))

    def _warn(self, label, value, hint=""):
        self.results.append(("[yellow]![/yellow]", label, f"[yellow]{value}[/yellow]"))
        if hint:
            self.warnings.append(hint)

    def _info(self, label, value):
        self.results.append(("[dim]–[/dim]", label, f"[dim]{value}[/dim]"))

    def run(self):
        print_banner()
        console.print(Panel.fit(
            "[bold cyan]🛡  CGTI Lite — Auto Setup[/bold cyan]\n"
            "[dim]Detecting environment, installing missing components…[/dim]",
            border_style="cyan",
        ))
        console.print()

        steps = [
            ("System",       self._step_system),
            ("Dependencies", self._step_deps),
            ("Suricata",     self._step_suricata),
            ("Network",      self._step_interface),
            ("Log paths",    self._step_logs),
            ("Finalizing",   self._step_finalize),
        ]
        with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}[/cyan]"),
                      TimeElapsedColumn(), console=console, transient=True) as prog:
            task = prog.add_task("Starting…", total=None)
            for name, fn in steps:
                prog.update(task, description=f"{name}…")
                fn()

        t = Table(show_header=False, box=box.SIMPLE_HEAD, padding=(0, 1), border_style="dim")
        t.add_column("", width=3, justify="center")
        t.add_column("", style="dim", width=26)
        t.add_column("", style="white")
        for row in self.results:
            t.add_row(*row)
        console.print(t)

        if self.warnings:
            console.print()
            for w in self.warnings:
                console.print(f"  [yellow]⚠  {w}[/yellow]")

        console.print()
        console.print(Panel.fit(
            "[bold green]✅  Setup complete![/bold green]\n\n"
            "  [cyan]cgti status[/cyan]               — Verify everything\n"
            "  [cyan]cgti start[/cyan]                — Start Suricata\n"
            "  [cyan]cgti live[/cyan]                 — Watch live alerts\n"
            "  [cyan]cgti live --autoblock[/cyan]     — Monitor + Enhanced Autoblock\n"
            "  [cyan]cgti --help[/cyan]               — All commands",
            title="[bold green]🎉 Ready[/bold green]",
            border_style="green",
        ))

    def _step_system(self):
        self._ok("OS",     f"{OS} {platform.machine()}")
        self._ok("Python", platform.python_version())

    def _step_deps(self):
        if OS == "Windows":
            if self.dep.npcap_present():
                self._ok("Npcap", "Already installed ✓")
            else:
                ok, err = self.dep.install_npcap()
                if ok:
                    self._ok("Npcap", f"Installed v{NPCAP_VERSION} ✓")
                else:
                    self._warn("Npcap", f"Install failed: {err}",
                               f"Manual: https://npcap.com/#download  (v{NPCAP_VERSION}+)")
        elif OS == "Linux":
            self._check_linux_lib(["libpcap.so", "libpcap-"], "libpcap",
                                  "sudo apt install libpcap0.8")
            nfq  = self._linux_lib_present(["libnetfilter_queue.so", "libnetfilter_queue-"])
            mode = self.cfg.get("suricata", "mode", default="IDS")
            if nfq:
                self._ok("libnetfilter-queue", "Installed ✓")
            elif mode == "IPS":
                self._warn("libnetfilter-queue", "Not found — required for IPS mode",
                           "sudo apt install libnetfilter-queue1")
            else:
                self._info("libnetfilter-queue", "Not installed (only needed for IPS mode)")
        else:
            candidates = ["/usr/lib/libpcap.dylib", "/usr/lib/libpcap.A.dylib",
                          "/usr/local/lib/libpcap.dylib", "/opt/homebrew/lib/libpcap.dylib"]
            found = next((p for p in candidates if Path(p).exists()), None)
            if found:
                self._ok("libpcap", f"Found ✓  {found}")
            else:
                self._warn("libpcap", "Not found",
                           "brew install libpcap  or reinstall Xcode Command Line Tools")

    def _check_linux_lib(self, names, label, hint):
        if self._linux_lib_present(names):
            self._ok(label, "Installed ✓")
        else:
            self._warn(label, "Not found", hint)

    def _linux_lib_present(self, names) -> bool:
        try:
            r = subprocess.run(["ldconfig", "-p"], capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=5)
            if any(n in r.stdout for n in names):
                return True
        except Exception:
            pass
        for d in ["/usr/lib", "/usr/lib64", "/usr/local/lib", "/lib", "/lib64",
                  "/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu"]:
            if any(list(Path(d).glob(n + "*")) for n in names if Path(d).exists()):
                return True
        return False

    def _step_suricata(self):
        if self.dep.suricata_present():
            binary = self.sur.find_binary()
            ver    = self.sur.get_version()
            self._ok("Suricata", f"Installed ✓  {binary}  [dim](v{ver})[/dim]")
        else:
            ok, err = self.dep.install_suricata()
            if ok:
                self._ok("Suricata", f"Installed ✓  {self.sur.find_binary() or ''}")
            else:
                self._warn("Suricata", f"Could not install — {err}",
                           "Manual: https://suricata.io/download/")

        self.cfg.set("suricata", "binary", self.sur.find_binary() or "")

        cfg_path = self.sur.find_config()
        if cfg_path:
            self.cfg.set("suricata", "config", cfg_path)
            self._ok("suricata.yaml", cfg_path)
        else:
            default = SURICATA_CFGS.get(OS, "")
            self.cfg.set("suricata", "config", default)
            self._warn("suricata.yaml", f"Not found — default: {default}",
                       "Set: cgti config set suricata.config <path>")

        self.cfg.set("suricata", "mode", "IDS")
        self._info("Mode", "IDS  (change: cgti config set suricata.mode IPS)")

    def _step_interface(self):
        ifaces = self._detect_interfaces()
        best   = self._pick_best(ifaces)
        if best:
            self.cfg.set("suricata", "interface", best)
            self.cfg.set("network", "monitored_interfaces", ifaces)
            others = [i for i in ifaces if i != best]
            extra  = f"  [dim](also: {', '.join(others)})[/dim]" if others else ""
            self._ok("Interface", f"[bold]{best}[/bold]{extra}")
        else:
            fallback = "eth0" if OS != "Windows" else "Ethernet"
            self.cfg.set("suricata", "interface", fallback)
            self._warn("Interface", f"Not detected — set to '{fallback}'",
                       "Override: cgti config set suricata.interface <name>")

    def _step_logs(self):
        all_candidates = [p for paths in SURICATA_LOGS.values() for p in paths]
        eve  = next((p for p in all_candidates if Path(p).exists()), None) \
               or SURICATA_LOGS.get(OS, ["/var/log/suricata/eve.json"])[0]
        fast = eve.replace("eve.json", "fast.log")
        self.cfg.set("suricata", "eve_log",  eve)
        self.cfg.set("suricata", "fast_log", fast)
        self._ok("EVE log", eve) if Path(eve).exists() else self._info("EVE log", f"{eve}  (after first run)")
        self._info("fast.log", fast)

    def _step_finalize(self):
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        RULES_DIR.mkdir(parents=True, exist_ok=True)
        self.cfg.save()
        _log(f"Installed on {OS} v{VERSION}")
        self._ok("Config",    str(CONFIG_FILE))
        self._ok("Rules dir", str(RULES_DIR))

        # Apply OpenClaw rules
        yaml_path = self.cfg.get("suricata", "config", default="")
        if yaml_path and Path(yaml_path).exists():
            self._apply_rules_step(yaml_path)
            # Configure optional enhancements (JA3, DNS_SERVERS)
            custom_dns = self.cfg.get("suricata", "dns_servers", default="")
            enhancements = _configure_suricata_enhancements(
                yaml_path, dns_servers=custom_dns
            )
            if enhancements:
                for change in enhancements:
                    self._ok("suricata.yaml", change)
            else:
                self._info("suricata.yaml", "JA3 + DNS_SERVERS already configured")
        else:
            self._warn("OpenClaw Rules", "suricata.yaml not found")

    def _apply_rules_step(self, yaml_path: str):
        """Automatically locates the rules/ directory in the same directory as install.bat/.sh."""
        candidates = [Path.cwd() / "rules"]
        try:
            candidates.insert(0, Path(__file__).parent / "rules")
        except Exception:
            pass
        if OS == "Windows":
            appdata = os.environ.get("APPDATA", "")
            if appdata:
                candidates.append(Path(appdata) / "cgti-lite" / "rules")

        our_rules_dir = next(
            (c for c in candidates if c.exists() and list(c.glob("*.rules"))),
            None,
        )

        if not our_rules_dir:
            self._warn("OpenClaw Rules",
                       "rules/ directory not found or empty",
                       "Create a rules/ directory in the same location as install.bat")
            return

        copied, err = _apply_openclaw_rules(yaml_path, our_rules_dir)
        if err:
            self._warn("OpenClaw Rules", f"Error: {err}")
        else:
            self._ok("OpenClaw Rules",
                     f"{len(copied)} files active: {chr(44).join(copied)}")
            self._info("Other rules", "All disabled")

    def _detect_interfaces(self) -> list:
        if OS == "Windows":  return self._ifaces_windows()
        if OS == "Darwin":   return self._ifaces_macos()
        return self._ifaces_linux()

    def _ifaces_windows(self) -> list:
        ifaces = []
        try:
            r = subprocess.run(["netsh", "interface", "show", "interface"],
                               capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=8)
            for line in r.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 4 and parts[0].lower() == "enabled":
                    name = " ".join(parts[3:]).strip()
                    if name and name not in ifaces:
                        ifaces.append(name)
            if ifaces:
                return ifaces
        except Exception:
            pass
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | "
                 "Select-Object -ExpandProperty Name"],
                capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=10)
            for line in r.stdout.splitlines():
                if line.strip() and line.strip() not in ifaces:
                    ifaces.append(line.strip())
        except Exception:
            pass
        return ifaces

    def _ifaces_macos(self) -> list:
        SKIP   = ("lo", "utun", "gif", "stf", "XHC", "ap", "p2p",
                  "awdl", "llw", "bridge", "vmnet", "vboxnet")
        ifaces = []
        try:
            r = subprocess.run(["networksetup", "-listallhardwareports"],
                               capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=8)
            for line in r.stdout.splitlines():
                if line.strip().startswith("Device:"):
                    dev = line.split(":", 1)[1].strip()
                    if dev and not any(dev.startswith(p) for p in SKIP) and dev not in ifaces:
                        ifaces.append(dev)
            if ifaces:
                return ifaces
        except Exception:
            pass
        try:
            r = subprocess.run(["ifconfig", "-u"], capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=6)
            for dev in re.findall(r"^(\S+):", r.stdout, re.MULTILINE):
                if not any(dev.startswith(p) for p in SKIP) and dev not in ifaces:
                    ifaces.append(dev)
        except Exception:
            pass
        return ifaces

    def _ifaces_linux(self) -> list:
        SKIP = ("lo", "docker", "veth", "virbr", "vmnet", "br-",
                "tun", "tap", "dummy", "bond", "flannel", "cali")
        _skip = lambda n: any(n.startswith(p) for p in SKIP)
        ifaces = []
        try:
            for dp in sorted(Path("/sys/class/net").iterdir()):
                dev = dp.name
                if _skip(dev):
                    continue
                sf    = dp / "operstate"
                state = sf.read_text().strip() if sf.exists() else "unknown"
                if state in ("up", "unknown"):
                    ifaces.append(dev)
            if ifaces:
                return ifaces
        except Exception:
            pass
        try:
            r = subprocess.run(["ip", "-j", "link", "show", "up"],
                               capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=6)
            for entry in json.loads(r.stdout):
                dev = entry.get("ifname", "")
                if dev and not _skip(dev) and dev not in ifaces:
                    ifaces.append(dev)
            if ifaces:
                return ifaces
        except Exception:
            pass
        try:
            r = subprocess.run(["ip", "-o", "link", "show", "up"],
                               capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=6)
            for dev in re.findall(r"^\d+: (\S+?)[@:]", r.stdout, re.MULTILINE):
                if not _skip(dev) and dev not in ifaces:
                    ifaces.append(dev)
        except Exception:
            pass
        return ifaces

    def _pick_best(self, ifaces: list) -> Optional[str]:
        if not ifaces:
            return None
        def _score(name: str) -> int:
            s, n = 0, name.lower()
            if re.match(r"^(eth\d|ens\d|enp\d|eno\d|em\d|en\d)", n): s += 40
            if "ethernet" in n:                                        s += 35
            if re.match(r"^(wlan\d|wlp|wls)", n):                     s += 25
            if "wi-fi" in n or "wifi" in n or "wireless" in n:        s += 20
            if n == "en0":                                             s += 38
            if n == "en1":                                             s += 30
            for bad in ("virtual", "vmware", "hyper-v", "loopback", "vbox", "npcap"):
                if bad in n:                                           s -= 50
            return s
        return max(ifaces, key=_score)


# ─── Commands ────────────────────────────────────────────────────────────────

def cmd_install(args):
    InstallWizard().run()


def cmd_status(args):
    cfg     = ConfigManager()
    sur     = SuricataManager(cfg)
    ipm     = IPBlockManager()
    rm      = RuleManager(cfg)
    running = sur.is_running()
    stats   = sur.get_stats()
    rules   = rm.list_rules()
    enabled = sum(1 for r in rules if r["enabled"])
    mode    = cfg.get("suricata", "mode",      default="IDS")
    iface   = cfg.get("suricata", "interface", default="N/A")
    binary  = sur.find_binary() or "Not found"
    ver     = sur.get_version()
    autoblock = cfg.get("cgti", "autoblock", default=False)

    # Build display mode string
    if autoblock:
        display_mode = f"{mode} + Enhanced Autoblock"
        mode_color = "red" if mode == "IPS" else "yellow"
    else:
        display_mode = mode
        mode_color = "red" if mode == "IPS" else "yellow"

    print_banner()
    console.print(Panel(
        f"\n  [dim]Suricata:[/dim]    {_running_badge(running)}\n"
        f"  [dim]Mode:[/dim]        [bold {mode_color}]{display_mode}"
        f"[/bold {mode_color}]\n"
        f"  [dim]Interface:[/dim]   [cyan]{iface}[/cyan]\n"
        f"  [dim]Binary:[/dim]      [dim]{binary}[/dim]\n"
        f"  [dim]Version:[/dim]     [dim]{ver}[/dim]\n"
        f"  [dim]Config:[/dim]      [dim]{CONFIG_FILE}[/dim]\n",
        title="[bold cyan]🛡  CGTI Lite — System Status[/bold cyan]",
        border_style="cyan",
    ))
    t = Table(box=box.ROUNDED, border_style="dim", title="📊 Statistics", title_style="bold")
    t.add_column("Metric",  style="cyan",       width=25)
    t.add_column("Value",   style="bold white",  justify="right")
    t.add_row("Packets Captured", f"{stats['packets']:,}")
    t.add_row("Alerts Generated", f"{stats['alerts']:,}")
    t.add_row("Packets Dropped",  f"{stats['dropped']:,}")
    t.add_row("Blocked IPs",      f"[red]{len(ipm.list())}[/red]" if ipm.list() else "[dim]0[/dim]")
    t.add_row("Total Rules",      str(len(rules)))
    t.add_row("Enabled Rules",    f"[green]{enabled}[/green]")
    t.add_row("Disabled Rules",   f"[dim]{len(rules) - enabled}[/dim]")
    if autoblock:
        sev_val = int(cfg.get("cgti", "autoblock_min_severity", default=3))
        sev_names = {1: "Critical only", 2: "Critical+High", 3: "Critical+High+Medium", 4: "All"}
        t.add_row("Autoblock Severity", f"≤{sev_val} ({sev_names.get(sev_val, '?')})")
    console.print(t)
    console.print()
    if not running:
        if SURICATA_RUN_LOG.exists():
            last = SURICATA_RUN_LOG.read_text(errors="ignore").splitlines()
            if last:
                console.print("[dim]Last Suricata output:[/dim]")
                for line in last[-6:]:
                    console.print(f"  [dim red]{line}[/dim red]")
                console.print()
        console.print(f"[dim]Start:[/dim] [bold cyan]cgti start[/bold cyan]")


def cmd_start(args):
    cfg = ConfigManager()
    sur = SuricataManager(cfg)
    silent = getattr(args, "silent", False)

    if sur.is_running():
        if silent:
            mode = cfg.get("suricata", "mode", default="IDS")
            if mode == "IPS" and OS == "Linux":
                # System's suricata.service started Suricata in IDS (af-packet)
                # mode, but we need IPS (NFQUEUE). Must stop and restart.
                _log("Autostart: Suricata running in IDS mode, IPS configured — stopping system instance...")
                sur.stop()
                time.sleep(2)
                # Fall through to normal silent start flow below which does
                # full IPS setup (iptables NFQUEUE + drop rules + restart)
            else:
                # IDS mode: Suricata already running, just spawn autoblock
                _log("Autostart: Suricata already running (started by system)")
                autoblock = cfg.get("cgti", "autoblock", default=False)
                if autoblock:
                    _log("Autostart: launching autoblock daemon")
                    try:
                        _spawn_autoblock_daemon()
                    except Exception as e:
                        _log(f"Autostart: autoblock error: {e}", "ERROR")
                return
        else:
            console.print("[yellow]⚠  Suricata is already running.[/yellow]")
            return
    if not sur.is_installed():
        if not silent:
            console.print("[red]✗  Suricata not found. Run [bold]cgti install[/bold][/red]")
        return
    if OS == "Windows" and not _is_admin():
        if not silent:
            console.print(
                "[bold red]✗  Administrator privileges required.[/bold red]\n"
                "   Right-click CMD and select [bold]'Run as administrator'[/bold]."
            )
        return

    iface = getattr(args, "interface", None)
    mode  = cfg.get("suricata", "mode", default="IDS")

    # ── Silent mode: use saved config, no prompts ────────────────────────
    if silent:
        if not iface:
            iface = cfg.get("suricata", "interface", default="")
        if not iface:
            _log("Autostart failed: no interface configured")
            return
        ok, msg = sur.start(iface, silent=True)
        if ok:
            _log(f"Autostart: Suricata started on {iface} ({mode})")
            # Auto-apply saved monitoring preference
            autoblock = cfg.get("cgti", "autoblock", default=False)
            if autoblock:
                _log("Autostart: launching live monitoring with autoblock")
                try:
                    _spawn_autoblock_daemon()
                except Exception as e:
                    _log(f"Autostart: autoblock error: {e}", "ERROR")
        else:
            _log(f"Autostart: Suricata failed — {msg}")
        return

    # ── Interactive mode (normal CLI usage) ───────────────────────────────
    if not iface:
        ifaces  = sur.get_active_interfaces()
        choices = [i for i in ifaces if i["status"] == "Up"] or ifaces
        if choices:
            t = Table(title="📡 Select Network Interface",
                      box=box.ROUNDED, border_style="cyan")
            t.add_column("#",          style="cyan",       width=4, justify="right")
            t.add_column("Name",       style="bold white")
            t.add_column("Status",     width=14)
            if OS == "Windows":
                t.add_column("NPF Device", style="dim")
            elif OS == "Darwin":
                t.add_column("Type", style="dim")
            for idx, i in enumerate(choices, 1):
                sfmt = "[green]Up[/green]" if i["status"] == "Up" else f"[dim]{i['status']}[/dim]"
                if OS == "Windows":
                    t.add_row(str(idx), i["name"], sfmt, i["npf"])
                elif OS == "Darwin":
                    t.add_row(str(idx), i["name"], sfmt, i.get("label", ""))
                else:
                    t.add_row(str(idx), i["name"], sfmt)
            console.print(t)
            console.print()
            raw = console.input("[cyan]Number or name: [/cyan]").strip()
            if raw.isdigit() and 1 <= int(raw) <= len(choices):
                chosen = choices[int(raw) - 1]
            else:
                chosen = next((i for i in choices if i["name"].lower() == raw.lower()), None)
            if not chosen:
                console.print("[red]✗  Invalid selection.[/red]")
                return
            iface = chosen["name"]
            cfg.set("suricata", "interface", iface)
            if OS == "Windows":
                console.print(f"[dim]Selected: [bold]{iface}[/bold] → {chosen['npf']}[/dim]")
            else:
                console.print(f"[dim]Selected: [bold]{iface}[/bold][/dim]")
            console.print()
        else:
            iface = cfg.get("suricata", "interface", default="eth0" if OS != "Windows" else "Ethernet")

    if not iface:
        iface = cfg.get("suricata", "interface", default="eth0")

    with console.status(
        f"[cyan]Starting Suricata[/cyan] [bold cyan]{mode}[/bold cyan] "
        f"[dim]on[/dim] [cyan]{iface}[/cyan]…",
        spinner="dots",
    ):
        ok, msg = sur.start(iface)

    if ok:
        console.print(
            f"[bold green]✓  Suricata started[/bold green]"
            f"  │  Interface: [cyan]{iface}[/cyan]  │  Mode: [bold]{mode}[/bold]"
        )
        _log(f"Suricata started on {iface} ({mode})")
        if OS == "Windows":
            console.print(f"[dim]  Log: {SURICATA_RUN_LOG}[/dim]")
        _prompt_post_start_mode(cfg, iface)
    else:
        console.print(f"[red]✗  Failed:[/red]\n{msg}")
        console.print(f"[dim]Check: [bold]{SURICATA_RUN_LOG}[/bold][/dim]")


def cmd_stop(args):
    cfg = ConfigManager()
    sur = SuricataManager(cfg)
    was_running = sur.is_running()
    if not was_running:
        console.print("[yellow]⚠  Suricata may not be running — forcing cleanup…[/yellow]")
    with console.status("[cyan]Stopping…[/cyan]"):
        ok = sur.stop()
        time.sleep(1)
    if was_running:
        console.print("[green]✓  Stopped.[/green]" if ok else "[red]✗  Could not stop.[/red]")
    else:
        console.print("[green]✓  Cleanup complete.[/green]")
    _log("Suricata stopped")


def cmd_rules(args):
    cfg = ConfigManager()
    rm  = RuleManager(cfg)
    sur = SuricataManager(cfg)
    sub = getattr(args, "rules_cmd", None)

    if sub in ("list", None):
        rules = rm.list_rules(getattr(args, "file", None))
        flt   = getattr(args, "filter", None)
        if flt:
            rules = [r for r in rules if flt.lower() in r["msg"].lower() or flt == r["sid"]]
        if not rules:
            console.print("[yellow]No rules found.[/yellow]")
            console.print(f"[dim]Rules dir: {rm.rules_dir}[/dim]")
            return
        page  = max(1, getattr(args, "page", 1) or 1)
        per   = 30
        total = max(1, (len(rules) + per - 1) // per)
        page  = min(page, total)
        shown = rules[(page - 1) * per : page * per]
        t = Table(title=f"📋 Rules — {len(rules)} total  │  Page {page}/{total}",
                  box=box.ROUNDED, border_style="dim")
        t.add_column("",          width=4,  justify="center")
        t.add_column("SID",       style="cyan dim", width=12)
        t.add_column("Action",    width=9)
        t.add_column("Signature", style="white")
        t.add_column("File",      style="dim", width=22)
        for r in shown:
            badge = "[green]ON [/green]" if r["enabled"] else "[dim]OFF[/dim]"
            ac    = _action_color(r["action"])
            t.add_row(badge, r["sid"], f"[{ac}]{r['action']}[/{ac}]",
                      r["msg"][:58] + ("…" if len(r["msg"]) > 58 else ""), r["file"])
        console.print(t)
        if total > 1:
            console.print(f"[dim]Next: [/dim][cyan]cgti rules list --page {page + 1}[/cyan]")

    elif sub == "enable":
        if rm.toggle_rule(args.sid, True):
            console.print(f"[green]✓  SID {args.sid} enabled.[/green]")
            if not getattr(args, "no_reload", False):
                sur.reload_rules()
        else:
            console.print(f"[red]✗  SID {args.sid} not found.[/red]")

    elif sub == "disable":
        if rm.toggle_rule(args.sid, False):
            console.print(f"[yellow]⊘  SID {args.sid} disabled.[/yellow]")
            if not getattr(args, "no_reload", False):
                sur.reload_rules()
        else:
            console.print(f"[red]✗  SID {args.sid} not found.[/red]")

    elif sub == "add":
        fname = getattr(args, "file", "openclaw-custom.rules")
        if rm.add_rule(args.rule, fname):
            console.print(f"[green]✓  Rule added to {fname}[/green]")
        else:
            console.print("[red]✗  Failed.[/red]")

    elif sub == "reload":
        with console.status("[cyan]Reloading…[/cyan]"):
            ok = sur.reload_rules()
        console.print("[green]✓  Reloaded.[/green]" if ok
                      else "[red]✗  Failed (Suricata not running?)[/red]")

    elif sub == "files":
        files = rm.rule_files()
        if not files:
            console.print("[yellow]No .rules files found.[/yellow]")
            return
        t = Table(title="📁 Rule Files", box=box.SIMPLE)
        t.add_column("File",  style="cyan")
        t.add_column("Rules", justify="right")
        t.add_column("Size",  justify="right", style="dim")
        for f in files:
            t.add_row(f.name, str(len(rm.list_rules(f.name))), f"{f.stat().st_size:,} B")
        console.print(t)

    elif sub == "apply":
        src_dir   = Path(getattr(args, "dir", None) or Path.cwd() / "rules")
        yaml_path = cfg.get("suricata", "config", default="")
        if not yaml_path or not Path(yaml_path).exists():
            console.print("[red]✗  suricata.yaml not found.[/red]")
            console.print("[dim]Set: cgti config set suricata.config <path>[/dim]")
            return
        if not src_dir.exists():
            console.print(f"[red]✗  Directory not found: {src_dir}[/red]")
            return
        copied, err = _apply_openclaw_rules(yaml_path, src_dir)
        if err:
            console.print(f"[red]✗  {err}[/red]")
        else:
            console.print(f"[green]✓  {len(copied)} rules applied: {chr(44).join(copied)}[/green]")
            console.print("[dim]  Other rules disabled.[/dim]")
            console.print("[dim]  Restart: cgti stop && cgti start[/dim]")

    elif sub == "validate":
        binary = sur.find_binary()
        yaml_path = cfg.get("suricata", "config", default="") or sur.find_config()
        if not binary:
            console.print("[red]✗  Suricata not found.[/red]")
            return
        if not yaml_path:
            console.print("[red]✗  suricata.yaml not found.[/red]")
            return
        # Find rules directory
        try:
            yt = Path(yaml_path).read_text(errors="replace")
            drp = re.search(r"^\s*default-rule-path:\s*(.+)$", yt, re.MULTILINE)
            rules_path = Path(drp.group(1).strip().strip('"').strip("'")) if drp \
                         else Path(yaml_path).parent / "rules"
        except Exception:
            rules_path = rm.rules_dir

        console.print(f"[cyan]Validating rules with Suricata…[/cyan]")
        console.print(f"[dim]  Binary: {binary}[/dim]")
        console.print(f"[dim]  Config: {yaml_path}[/dim]")
        console.print(f"[dim]  Rules:  {rules_path}[/dim]")
        console.print()

        total_disabled = 0
        for iteration in range(15):
            r = subprocess.run(
                [binary, "-T", "-c", yaml_path],
                capture_output=True, text=True, timeout=120,
            )
            output = r.stderr + "\n" + r.stdout
            failing_sids = set()
            for line in output.splitlines():
                line = line.strip()
                if line.startswith("E:") and "sid:" in line:
                    m = re.search(r"sid:(\d+)", line)
                    if m:
                        failing_sids.add(m.group(1))
            if not failing_sids or "Loading signatures failed" not in output:
                break
            for rules_file in sorted(rules_path.glob("*.rules")):
                text = rules_file.read_text(encoding="utf-8", errors="replace")
                new_text = text
                for sid in failing_sids:
                    new_text = re.sub(
                        rf"^(alert |drop )(.*sid:{sid};.*)",
                        r"#DISABLED-PARSE# \1\2",
                        new_text, flags=re.MULTILINE,
                    )
                if new_text != text:
                    rules_file.write_text(new_text, encoding="utf-8")
            total_disabled += len(failing_sids)
            console.print(f"  [yellow]Pass {iteration + 1}:[/yellow] disabled {len(failing_sids)} broken rules")

        # Final check
        r = subprocess.run([binary, "-T", "-c", yaml_path],
                           capture_output=True, text=True, timeout=120)
        if "Loading signatures failed" not in (r.stderr + r.stdout):
            active = 0
            for rf in rules_path.glob("*.rules"):
                active += sum(1 for l in rf.read_text(errors="replace").splitlines()
                              if l.strip().startswith(("alert ", "drop ")))
            console.print()
            console.print(
                f"[bold green]✅  Validation complete[/bold green]\n"
                f"  Active rules: [green]{active}[/green]\n"
                f"  Disabled (parse errors): [yellow]{total_disabled}[/yellow]\n"
                f"  [dim]Disabled rules marked with #DISABLED-PARSE#[/dim]"
            )
        else:
            console.print("[red]✗  Some rules still fail. Run again or check manually.[/red]")


def cmd_blocked(args):
    ipm = IPBlockManager()
    sub = getattr(args, "blocked_cmd", None)

    if sub in ("list", None):
        blocked = ipm.list()
        if not blocked:
            console.print("[dim]No IPs blocked.[/dim]")
            return
        t = Table(title=f"🚫 Blocked IPs — {len(blocked)} total",
                  box=box.ROUNDED, border_style="red")
        t.add_column("#",         style="dim",      width=4, justify="right")
        t.add_column("IP",        style="bold red", width=18)
        t.add_column("Reason",    style="yellow")
        t.add_column("Timestamp", style="dim",      width=20)
        for i, e in enumerate(blocked, 1):
            t.add_row(str(i), e["ip"], e.get("reason", ""),
                      e.get("timestamp", "")[:19].replace("T", " "))
        console.print(t)

    elif sub == "add":
        reason = getattr(args, "reason", "Manual block")
        if ipm.block(args.ip, reason):
            console.print(f"[red]🚫  {args.ip} blocked.[/red]  [dim]{reason}[/dim]")
            _log(f"Blocked {args.ip} — {reason}")
        else:
            console.print(f"[yellow]⚠  {args.ip} already blocked.[/yellow]")

    elif sub == "remove":
        if ipm.unblock(args.ip):
            console.print(f"[green]✓  {args.ip} unblocked.[/green]")
        else:
            console.print(f"[yellow]⚠  {args.ip} not in list.[/yellow]")

    elif sub == "clear":
        blocked = ipm.list()
        if not blocked:
            console.print("[dim]Nothing to clear.[/dim]")
            return
        if Confirm.ask(f"[red]Clear all {len(blocked)} blocked IPs?[/red]", default=False):
            ipm.clear_all()
            console.print("[green]✓  All cleared.[/green]")


def cmd_logs(args):
    cfg      = ConfigManager()
    lv       = LogViewer(cfg)
    limit    = getattr(args, "limit", 50)
    severity = getattr(args, "severity", None)
    fip      = getattr(args, "ip", None)
    alerts   = lv.alerts(limit=limit * 3, severity=severity)
    if fip:
        alerts = [a for a in alerts if a["src_ip"] == fip or a["dest_ip"] == fip]
    alerts = alerts[:limit]
    if not alerts:
        console.print("[yellow]No alerts found.[/yellow]")
        console.print(f"[dim]EVE log: {lv.eve_log or 'Not configured'}[/dim]")
        return
    t = Table(title=f"📋 Alerts — {len(alerts)} shown",
              box=box.ROUNDED, border_style="yellow")
    t.add_column("Timestamp", style="dim",       width=19)
    t.add_column("Sev",                          width=4, justify="center")
    t.add_column("Src IP",    style="bold red",  width=17)
    t.add_column("Dst IP",    style="cyan",      width=17)
    t.add_column("Proto",     style="dim",       width=7)
    t.add_column("Signature", style="yellow")
    t.add_column("SID",       style="dim",       width=10)
    for a in alerts:
        sc = _sev_color(a["severity"])
        t.add_row(a["timestamp"], f"[{sc}]{a['severity']}[/{sc}]",
                  a["src_ip"], a["dest_ip"], a["proto"].upper(),
                  a["msg"][:52] + ("…" if len(a["msg"]) > 52 else ""), str(a["sid"]))
    console.print(t)
    if getattr(args, "cgti_log", False) and LOG_FILE.exists():
        console.print(Rule("[dim]CGTI Internal Log[/dim]"))
        for line in LOG_FILE.read_text(errors="ignore").splitlines()[-20:]:
            console.print(f"[dim]{line}[/dim]")


def _prompt_post_start_mode(cfg, iface: str):
    sur = SuricataManager(cfg)
    # ── Auto-apply saved preference (no prompt) ─────────────────────────
    # If user previously selected a monitoring mode, reuse it silently.
    # This also handles autostart scenarios where --silent may be lost.
    saved_mode = cfg.get("suricata", "mode", default="IDS")
    saved_autoblock = cfg.get("cgti", "autoblock", default=None)

    if saved_autoblock is not None:
        # User has previously made a choice — auto-apply
        label = saved_mode
        if saved_autoblock:
            label += " + Enhanced Autoblock"
        console.print()
        console.print(
            f"  [cyan]Monitoring:[/cyan] [bold]{label}[/bold]"
            f"  [dim](saved preference — change with cgti config set)[/dim]"
        )
        if saved_autoblock:
            console.print(
                "[yellow]Starting Enhanced Autoblock…  Press Ctrl+C to switch to background mode[/yellow]"
            )
            console.print("[dim]Suricata continues running in the background.[/dim]")
            console.print()
            cmd_live(types.SimpleNamespace(autoblock=True, verbose=False))
        elif saved_mode == "IPS" and OS == "Linux":
            console.print("[cyan]Switching to IPS mode — restarting Suricata…[/cyan]")
            sur.stop()
            time.sleep(1)
            ok, msg = sur.start(iface)
            if not ok:
                console.print(f"[red]✗  {msg}[/red]")
            else:
                console.print("[green]✓  IPS mode active.[/green]")
        return

    # ── First run: show interactive mode selector ────────────────────────
    console.print()
    console.print(Rule("[dim]Select Monitoring Mode[/dim]", style="dim"))
    console.print()
    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    t.add_column("", width=4, justify="right", style="cyan bold")
    t.add_column("", style="bold white", min_width=35)
    t.add_column("", style="dim")
    t.add_row("1", "IDS  — Monitor Only",
              "Generate alerts, no blocking")
    t.add_row("2", "IDS + Enhanced Autoblock  — Monitor + Auto-Block",
              "Add source IP to firewall on alert  (all platforms)")
    if OS == "Linux":
        t.add_row("3", "IPS  — Inline Blocking",
                  "drop rules block instantly  [Linux NFQUEUE]")
        t.add_row("4", "IPS + Enhanced Autoblock  — Full Protection",
                  "drop + IP permanently added to firewall on alert  [Linux]")
    else:
        t.add_row("[dim]3[/dim]", "[dim]IPS  — Inline Blocking[/dim]",
                  "[dim]Linux only[/dim]")
        t.add_row("[dim]4[/dim]", "[dim]IPS + Enhanced Autoblock[/dim]",
                  "[dim]Linux only[/dim]")
    t.add_row("5", "Not Now", "Later: cgti live")
    console.print(t)
    console.print()
    raw = console.input("[cyan]Your choice [1-5]: [/cyan]").strip()
    if raw == "1":
        cfg.set("suricata", "mode", "IDS")
        cfg.set("cgti", "autoblock", False)
        console.print("[cyan]IDS mode.[/cyan]  To monitor: [bold]cgti live[/bold]")
    elif raw == "2":
        cfg.set("suricata", "mode", "IDS")
        cfg.set("cgti", "autoblock", True)
        console.print("[yellow]Starting Enhanced Autoblock…  Press Ctrl+C to switch to background mode[/yellow]")
        console.print("[dim]Suricata continues running in the background.[/dim]")
        console.print()
        cmd_live(types.SimpleNamespace(autoblock=True, verbose=False))
    elif raw == "3":
        if OS != "Linux":
            console.print("[red]IPS mode is not supported on this platform.[/red]")
            console.print("[dim]We recommend using Enhanced Autoblock (2).[/dim]")
        else:
            cfg.set("suricata", "mode", "IPS")
            console.print("[cyan]Switching to IPS mode — restarting Suricata…[/cyan]")
            sur.stop()
            time.sleep(1)
            ok, msg = sur.start(iface)
            if ok:
                console.print("[green]✓  IPS mode active.[/green]")
                console.print("[dim]  To monitor: cgti live[/dim]")
            else:
                console.print(f"[red]IPS setup failed: {msg}[/red]")
    elif raw == "4":
        if OS != "Linux":
            console.print("[red]IPS + Enhanced Autoblock is not supported on this platform.[/red]")
            console.print("[dim]We recommend using Enhanced Autoblock (2).[/dim]")
        else:
            cfg.set("suricata", "mode", "IPS")
            cfg.set("cgti", "autoblock", True)
            console.print("[cyan]Switching to IPS + Enhanced Autoblock — restarting Suricata…[/cyan]")
            sur.stop()
            time.sleep(1)
            ok, msg = sur.start(iface)
            if ok:
                console.print("[green]✓  IPS + Enhanced Autoblock active.[/green]  Highest protection level.")
                console.print("[yellow]Starting Enhanced Autoblock…  Press Ctrl+C to switch to background mode[/yellow]")
                console.print("[dim]Suricata continues running in the background.[/dim]")
                console.print()
                cmd_live(types.SimpleNamespace(autoblock=True, verbose=False))
            else:
                console.print(f"[red]IPS setup failed: {msg}[/red]")
    else:
        console.print("[dim]To start: cgti live[/dim]")

def _spawn_autoblock_daemon():
    """Spawn autoblock daemon using a bash shell wrapper script.

    Shell scripts work perfectly in the background on macOS (Python doesn't).
    The wrapper script manages the Python process lifecycle with automatic
    restart on crash and logging.
    """
    try:
        script = str(Path(__file__).resolve())
    except Exception:
        script = str(Path(sys.argv[0]).resolve())

    if OS == "Windows":
        try:
            cmd = [sys.executable, script, "live", "--autoblock", "--daemon"]
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP,
            )
            _log(f"Autoblock daemon spawned: pid={proc.pid}")
            return True
        except Exception as e:
            _log(f"Failed to spawn autoblock daemon: {e}", "ERROR")
            return False

    # Unix (macOS / Linux): create and run a bash wrapper script
    try:
        import shlex
        wrapper_path = "/tmp/cgti-autoblock.sh"
        log_path = "/tmp/cgti-autoblock.log"
        python_exe = sys.executable or "/usr/bin/python3"

        wrapper_content = (
            "#!/bin/bash\n"
            "# CGTI Enhanced Autoblock Daemon — managed by bash\n"
            f"LOG=\"{log_path}\"\n"
            f"PYTHON={shlex.quote(python_exe)}\n"
            f"SCRIPT={shlex.quote(script)}\n"
            "echo \"$(date): autoblock daemon starting (pid $$)\" >> \"$LOG\"\n"
            "while true; do\n"
            "    \"$PYTHON\" \"$SCRIPT\" live --autoblock --daemon >> \"$LOG\" 2>&1\n"
            "    RC=$?\n"
            "    echo \"$(date): python exited ($RC), restarting in 5s...\" >> \"$LOG\"\n"
            "    sleep 5\n"
            "done\n"
        )

        Path(wrapper_path).write_text(wrapper_content, encoding="utf-8")
        os.chmod(wrapper_path, 0o755)

        # Properly detach the bash wrapper using Popen + double-fork semantics
        subprocess.Popen(
            ["/bin/bash", wrapper_path],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setpgrp,  # detach from parent process group
        )
        _log(f"Autoblock daemon started via bash wrapper (log: {log_path})")
        return True
    except Exception as e:
        _log(f"Failed to spawn autoblock daemon: {e}", "ERROR")
        return False


def cmd_live(args):
    cfg        = ConfigManager()
    ipm        = IPBlockManager()
    auto_block = getattr(args, "autoblock", False)
    verbose    = getattr(args, "verbose", False)
    silent     = getattr(args, "silent", False)
    daemon     = getattr(args, "daemon", False)

    # Daemon mode = silent mode (no output, runs in background)
    if daemon:
        silent = True

    # In daemon/autostart mode, ignore signals so autoblock loop survives
    _original_sigint = None
    if silent and hasattr(signal, 'SIGINT'):
        _original_sigint = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        # Also ignore SIGHUP (terminal close) and SIGTERM on Unix
        if hasattr(signal, 'SIGHUP'):
            signal.signal(signal.SIGHUP, signal.SIG_IGN)
        if hasattr(signal, 'SIGTERM'):
            signal.signal(signal.SIGTERM, signal.SIG_IGN)

    global _local_ips_cache
    _local_ips_cache = _get_local_ips()
    whitelist  = set(cfg.get("network", "whitelist_ips", default=[]) or [])
    # Auto-whitelist configured DNS servers (never block DNS infrastructure)
    dns_cfg = cfg.get("suricata", "dns_servers", default="")
    if dns_cfg:
        for ds in dns_cfg.replace(";", ",").split(","):
            ds = ds.strip()
            if ds and _validate_ip(ds):
                whitelist.add(ds)
    eve_log    = cfg.get("suricata", "eve_log") or _auto_eve()
    # Severity threshold for autoblock: block alerts with severity <= this value
    # Suricata severity: 1=Critical, 2=High, 3=Medium, 4=Low
    # Default 3 = block Critical+High+Medium, skip Low/Informational
    autoblock_max_sev = int(cfg.get("cgti", "autoblock_min_severity", default=3))

    # ── Wait for EVE log to appear (especially important for autostart) ──
    if not eve_log or not Path(eve_log).exists():
        if silent:
            # In daemon/autostart context, wait up to 60 seconds for Suricata
            # to create the EVE log file after boot
            _log("Waiting for EVE log to appear…")
            for _w in range(60):
                time.sleep(1)
                eve_log = cfg.get("suricata", "eve_log") or _auto_eve()
                if eve_log and Path(eve_log).exists():
                    _log(f"EVE log found: {eve_log}")
                    break
            else:
                _log("EVE log not found after 60s wait — retrying...", "ERROR")
                raise FileNotFoundError("EVE log not found after 60s wait")
        else:
            print_banner()
            console.print("[red]✗  EVE JSON log not found.[/red]")
            console.print("[dim]Run: cgti install   or   cgti config set suricata.eve_log <path>[/dim]")
            return

    if not silent:
        print_banner()
        mode       = cfg.get("suricata", "mode", default="IDS")
        if auto_block and mode == "IPS":
            mode_badge = "[red]IPS+ENHANCED AUTOBLOCK[/red]"
        elif auto_block:
            mode_badge = "[yellow]IDS+ENHANCED AUTOBLOCK[/yellow]"
        else:
            mode_badge = f"[cyan]{mode} MONITOR[/cyan]"
        sev_names = {1: "Critical", 2: "High", 3: "Medium", 4: "Low"}
        sev_info = f"  Blocking severity ≤ {autoblock_max_sev} ({sev_names.get(autoblock_max_sev, '?')})" if auto_block else ""
        console.print(Panel.fit(
            f"[bold green]📡 Live Alert Feed[/bold green]   {mode_badge}\n"
            f"[dim]{eve_log}[/dim]{sev_info}\n"
            f"[dim]Press Ctrl+C to stop monitoring (Suricata keeps running)[/dim]",
            border_style="green",
        ))
        console.print()
        console.print(
            f"[dim]{'TIMESTAMP':<20} {'TYPE':<8} {'SRC IP':<18} {'DST IP':<18} {'PROTO':<6} SIGNATURE[/dim]"
        )
        console.print(Rule(style="dim"))

    try:
        fh = open(eve_log, errors="ignore")
        fh.seek(0, 2)  # EOF
    except Exception as e:
        if not silent:
            console.print(f"[red]Cannot open log: {e}[/red]")
        else:
            _log(f"Cannot open EVE log: {e}", "ERROR")
        return

    if daemon:
        _log(f"Daemon: monitoring {eve_log}, auto_block={auto_block}, max_sev={autoblock_max_sev}")

    alert_count = drop_count = block_count = 0
    line_buffer = ""
    _rotation_check_counter = 0
    try:
        while True:
            try:
                # Detect eve.json log rotation every ~5 seconds
                _rotation_check_counter += 1
                if _rotation_check_counter >= 50:  # 50 × 0.1s = 5s
                    _rotation_check_counter = 0
                    try:
                        current_size = Path(eve_log).stat().st_size
                        current_pos = fh.tell()
                        if current_size < current_pos:
                            # File was rotated — reopen
                            _log("Live: eve.json rotated, reopening")
                            fh.close()
                            fh = open(eve_log, errors="ignore")
                            line_buffer = ""
                    except Exception:
                        pass

                chunk = fh.read()
                if chunk:
                    line_buffer += chunk
                    lines = line_buffer.split("\n")
                    # Last element may be an incomplete line — keep in buffer
                    line_buffer = lines[-1]
                    for raw_line in lines[:-1]:
                        raw_line = raw_line.strip()
                        if not raw_line:
                            continue
                        try:
                            e     = json.loads(raw_line)
                            etype = e.get("event_type", "")
                            ts    = e.get("timestamp", "")[:19].replace("T", " ")
                            src   = e.get("src_ip", "")
                            dst   = e.get("dest_ip", "")
                            proto = e.get("proto", "").upper()
                            dst_port = e.get("dest_port", 0)
                            src_port = e.get("src_port", 0)
                            if etype == "alert":
                                a   = e.get("alert", {})
                                msg = a.get("signature", "")[:55]
                                sev = a.get("severity", 0)
                                sid = a.get("signature_id", "")
                                action = a.get("action", "allowed")
                                sc  = _sev_color(sev)
                                alert_count += 1
                                if daemon and alert_count % 10 == 1:
                                    _log(f"Daemon: alert #{alert_count} src={src} dst={dst} sev={sev} '{msg}'")

                                # IPS drop detection: alert with action "drop"
                                is_drop = (action == "drop")
                                if is_drop:
                                    drop_count += 1

                                label = f"[bold red]DROP[/bold red]" if is_drop else f"[{sc}]ALERT[/{sc}]"
                                if not silent:
                                    console.print(
                                        f"[dim]{ts}[/dim]  {label}   "
                                        f"[red]{src:<17}[/red]  [cyan]{dst:<17}[/cyan]  "
                                        f"[dim]{proto:<6}[/dim]  [{sc}]{msg}[/{sc}]  [dim]SID:{sid}[/dim]"
                                    )
                                if auto_block and (src or dst):
                                    # ── Source IP blocking (inbound threats) ──
                                    if src and src not in _local_ips_cache and src not in whitelist and not _is_non_blockable_ip(src):
                                        if sev > autoblock_max_sev:
                                            pass  # severity too low
                                        elif ipm.block(src, f"Auto sev:{sev} src ({msg[:35]})"):
                                            block_count += 1
                                            if not silent:
                                                console.print(f"  [red]↳ ENHANCED-BLOCKED src {src}[/red]  [dim](severity {sev})[/dim]")
                                            _log(f"Auto-blocked src {src}: sev={sev} {msg}")
                                        elif daemon:
                                            _log(f"Daemon: ipm.block({src}) returned False (already blocked or failed)")

                                    # ── Destination IP blocking (outbound C2/exfil) ──
                                    is_dns_traffic = (dst_port == 53 or src_port == 53)
                                    if is_dns_traffic and sev <= autoblock_max_sev:
                                        # DNS alert: dst is DNS server (private IP) — never block it.
                                        # Instead, extract domain from signature and resolve to real IP.
                                        _domain = _extract_domain_from_sig(a.get("signature", ""))
                                        if _domain:
                                            resolved = _resolve_domain(_domain)
                                            for rip in resolved:
                                                if rip not in _local_ips_cache \
                                                   and rip not in whitelist \
                                                   and not _is_non_blockable_ip(rip) \
                                                   and not _is_private_ip(rip):
                                                    if ipm.block(rip, f"DNS sev:{sev} ({_domain})"):
                                                        block_count += 1
                                                        if not silent:
                                                            console.print(
                                                                f"  [red]↳ ENHANCED-BLOCKED {rip}[/red]  "
                                                                f"[dim](DNS → {_domain})[/dim]"
                                                            )
                                                        _log(f"DNS-blocked {rip} ({_domain} SID:{sid})")
                                    elif dst and not is_dns_traffic \
                                       and dst not in _local_ips_cache \
                                       and dst not in whitelist \
                                       and not _is_non_blockable_ip(dst) \
                                       and not _is_private_ip(dst):
                                        if sev > autoblock_max_sev:
                                            pass
                                        elif ipm.block(dst, f"Auto sev:{sev} dst ({msg[:35]})"):
                                            block_count += 1
                                            if not silent:
                                                console.print(f"  [red]↳ ENHANCED-BLOCKED dst {dst}[/red]  [dim](severity {sev})[/dim]")
                                            _log(f"Auto-blocked dst {dst}: sev={sev} {msg}")
                            elif etype == "drop":
                                drop_count += 1
                                if not silent:
                                    console.print(
                                        f"[dim]{ts}[/dim]  [bold red]DROP[/bold red]    "
                                        f"[red]{src:<17}[/red]  [cyan]{dst:<17}[/cyan]  [dim]{proto}[/dim]"
                                    )
                            elif etype == "dns" and verbose and not silent:
                                dns_d = e.get("dns", {})
                                if not silent:
                                    console.print(
                                        f"[dim]{ts}  DNS     {src:<17}  {dst:<17}  {dns_d.get('rrname', '')}[/dim]"
                                    )
                        except json.JSONDecodeError:
                            _log(f"Live: JSON parse error: {raw_line[:80]}")
                            continue
                        except Exception:
                            continue
            except Exception:
                pass
            time.sleep(0.1)
    except KeyboardInterrupt:
        console.print()
        console.print(Rule(style="dim"))
        console.print(
            f"[dim]Monitoring stopped — Alerts: [yellow]{alert_count}[/yellow]  "
            f"Drops: [red]{drop_count}[/red]  "
            f"Blocked: [red]{block_count}[/red][/dim]"
        )
        # If autoblock was active in interactive mode, spawn background daemon
        if auto_block and not silent:
            if _spawn_autoblock_daemon():
                console.print(
                    "[green]✓  Enhanced Autoblock continues in the background.[/green]\n"
                    "[dim]  To stop autoblock: [cyan]cgti blocked clear[/cyan] or kill the daemon process[/dim]"
                )
            else:
                console.print(
                    "[yellow]⚠  Could not start background autoblock daemon.[/yellow]\n"
                    "[dim]  Restart manually: [cyan]cgti live --autoblock[/cyan][/dim]"
                )
        else:
            console.print("[dim]Suricata continues running in the background. To stop: [cyan]cgti stop[/cyan][/dim]")
    finally:
        # Restore original SIGINT handler if it was changed
        if _original_sigint is not None:
            try:
                signal.signal(signal.SIGINT, _original_sigint)
            except Exception:
                pass
        try:
            fh.close()
        except Exception:
            pass


def cmd_config(args):
    cfg = ConfigManager()
    sub = getattr(args, "config_cmd", None)
    if sub in ("show", None):
        console.print(Panel(
            Syntax(json.dumps(cfg.data, indent=2), "json", theme="monokai"),
            title=f"[cyan]⚙  Config — {CONFIG_FILE}[/cyan]", border_style="cyan",
        ))
    elif sub == "set":
        keys  = args.key.split(".")
        value = args.value
        if value.lower() in ("true", "false"):
            value = value.lower() == "true"
        elif value.isdigit():
            value = int(value)
        # Validate key and value
        flat_key = args.key
        if flat_key in ConfigManager.VALID_KEYS:
            allowed = ConfigManager.VALID_KEYS[flat_key]
            if allowed is not None and value not in allowed:
                console.print(
                    f"[red]✗  Invalid value:[/red] [white]{value}[/white]\n"
                    f"[dim]  Allowed: {allowed}[/dim]"
                )
                return
        else:
            console.print(
                f"[yellow]⚠  Unknown key:[/yellow] [white]{flat_key}[/white]\n"
                f"[dim]  Known keys: {', '.join(sorted(ConfigManager.VALID_KEYS))}[/dim]"
            )
            if not Confirm.ask("[yellow]Set anyway?[/yellow]", default=False):
                return
        cfg.set(*keys, value)
        console.print(f"[green]\u2713[/green]  [cyan]{args.key}[/cyan] = [white]{value}[/white]")
        # Live-apply DNS servers to suricata.yaml
        if flat_key == "suricata.dns_servers" and isinstance(value, str) and value:
            yaml_path = cfg.get("suricata", "config", default="")
            if yaml_path and Path(yaml_path).exists():
                changes = _configure_suricata_enhancements(
                    yaml_path, dns_servers=value
                )
                for c in changes:
                    console.print(f"  [green]\u2713[/green]  [dim]suricata.yaml:[/dim] {c}")
            else:
                console.print(
                    "  [yellow]\u26a0[/yellow]  [dim]suricata.yaml not found — "
                    "DNS servers saved to config, will apply on next install[/dim]"
                )
    elif sub == "reset":
        if Confirm.ask("[red]Reset config to defaults?[/red]", default=False):
            import copy
            cfg.data = copy.deepcopy(ConfigManager.DEFAULT)
            cfg.save()
            console.print("[green]✓  Config reset.[/green]")
    elif sub == "path":
        console.print(f"[dim]Config:[/dim] [cyan]{CONFIG_FILE}[/cyan]")
        console.print(f"[dim]Rules: [/dim] [cyan]{RULES_DIR}[/cyan]")
        console.print(f"[dim]Log:   [/dim] [cyan]{LOG_FILE}[/cyan]")


def cmd_uninstall(args):
    """Remove CGTI Lite files, config, and PATH entry."""
    print_banner()
    console.print(Panel.fit(
        "[bold red]🗑  CGTI Lite — Uninstall[/bold red]\n"
        f"[dim]Config: {CONFIG_DIR}[/dim]",
        border_style="red",
    ))
    console.print()

    items = []
    if CONFIG_DIR.exists():
        items.append(f"Config directory: {CONFIG_DIR}")
    if OS == "Windows":
        launcher = Path(os.environ.get("APPDATA", "")) / "cgti-lite" / "bin" / "cgti.cmd"
        if launcher.exists():
            items.append(f"Launcher: {launcher}")
    else:
        for p in ["/usr/local/bin/cgti", str(Path.home() / ".local" / "bin" / "cgti")]:
            if Path(p).exists():
                items.append(f"Launcher: {p}")
        for p in ["/usr/local/lib/cgti-lite", str(Path.home() / ".local" / "lib" / "cgti-lite")]:
            if Path(p).exists():
                items.append(f"Lib: {p}")

    if not items:
        console.print("[yellow]Nothing to remove.[/yellow]")
        return

    for item in items:
        console.print(f"  [dim]•[/dim] {item}")
    console.print()

    if not Confirm.ask("[red]Delete all files?[/red]", default=False):
        console.print("[dim]Cancelled.[/dim]")
        return

    # Stop Suricata if running
    cfg = ConfigManager()
    sur = SuricataManager(cfg)
    if sur.is_running():
        console.print("[yellow]Stopping Suricata…[/yellow]")
        sur.stop()

    # Remove config directory
    if CONFIG_DIR.exists():
        shutil.rmtree(str(CONFIG_DIR), ignore_errors=True)
        console.print(f"[green]✓[/green]  Config deleted: {CONFIG_DIR}")

    # Remove launchers
    if OS == "Windows":
        launcher = Path(os.environ.get("APPDATA", "")) / "cgti-lite" / "bin" / "cgti.cmd"
        if launcher.exists():
            launcher.unlink()
            console.print(f"[green]✓[/green]  Launcher deleted: {launcher}")
        # Remove from user PATH
        try:
            scripts_dir = str(launcher.parent)
            subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 f"$p = [System.Environment]::GetEnvironmentVariable('PATH','User');"
                 f"$new = ($p -split ';' | Where-Object {{ $_ -ne '{scripts_dir}' }}) -join ';';"
                 f"[System.Environment]::SetEnvironmentVariable('PATH',$new,'User')"],
                capture_output=True, timeout=10)
            console.print("[green]✓[/green]  PATH cleaned.")
        except Exception:
            pass
    else:
        for p in ["/usr/local/bin/cgti", str(Path.home() / ".local" / "bin" / "cgti")]:
            if Path(p).exists():
                try:
                    Path(p).unlink()
                    console.print(f"[green]✓[/green]  Launcher deleted: {p}")
                except PermissionError:
                    console.print(f"[yellow]⚠  Launcher could not be deleted (sudo required): {p}[/yellow]")
        for p in ["/usr/local/lib/cgti-lite", str(Path.home() / ".local" / "lib" / "cgti-lite")]:
            if Path(p).exists():
                shutil.rmtree(p, ignore_errors=True)
                console.print(f"[green]✓[/green]  Lib deleted: {p}")

    console.print()
    console.print("[bold green]✅  CGTI Lite removed.[/bold green]")


# ─── Autostart ────────────────────────────────────────────────────────────────

_SYSTEMD_UNIT = "cgti-lite.service"
_SYSTEMD_PATH = Path("/etc/systemd/system") / _SYSTEMD_UNIT

_LAUNCHD_LABEL = "com.cgti-lite.daemon"
_LAUNCHD_PLIST = Path("/Library/LaunchDaemons") / f"{_LAUNCHD_LABEL}.plist"
_LAUNCHD_OLD   = Path.home() / "Library" / "LaunchAgents" / "com.cgti-lite.agent.plist"

_SCHTASK_NAME = "CGTI-Lite-Autostart"


def _autostart_enable_linux(script: str) -> tuple:
    """Create and enable a systemd service for CGTI Lite.

    Uses Type=oneshot + RemainAfterExit so systemd tracks the service as
    'active' after the start command exits (Suricata runs independently).
    Interface is read from config at runtime, not baked into the unit file.
    """
    unit = (
        "[Unit]\n"
        "Description=CGTI Lite for OpenClaw — Suricata IDS/IPS\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        "RemainAfterExit=yes\n"
        f"ExecStart={sys.executable} {script} start --silent\n"
        f"ExecStop={sys.executable} {script} stop\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )
    try:
        _SYSTEMD_PATH.write_text(unit, encoding="utf-8")
        subprocess.run(["systemctl", "daemon-reload"],
                       capture_output=True, timeout=10)
        r = subprocess.run(["systemctl", "enable", _SYSTEMD_UNIT],
                           capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            return False, r.stderr.strip() or "systemctl enable failed"
        _log(f"Autostart enabled: {_SYSTEMD_PATH}")
        return True, str(_SYSTEMD_PATH)
    except PermissionError:
        return False, "Permission denied — run with sudo"
    except Exception as e:
        return False, str(e)


def _autostart_disable_linux() -> tuple:
    try:
        subprocess.run(["systemctl", "disable", _SYSTEMD_UNIT],
                       capture_output=True, timeout=10)
        if _SYSTEMD_PATH.exists():
            _SYSTEMD_PATH.unlink()
        subprocess.run(["systemctl", "daemon-reload"],
                       capture_output=True, timeout=10)
        _log("Autostart disabled (systemd)")
        return True, ""
    except PermissionError:
        return False, "Permission denied — run with sudo"
    except Exception as e:
        return False, str(e)


def _autostart_status_linux() -> str:
    if not _SYSTEMD_PATH.exists():
        return "disabled"
    try:
        r = subprocess.run(["systemctl", "is-enabled", _SYSTEMD_UNIT],
                           capture_output=True, text=True, timeout=5)
        return r.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def _autostart_enable_macos(script: str) -> tuple:
    """Create and load a launchd LaunchDaemon plist for CGTI Lite (runs at boot as root).

    No KeepAlive — the script starts Suricata and exits cleanly.
    Interface is read from config at runtime, not baked into the plist.
    """
    # Clean up old LaunchAgent if it exists
    if _LAUNCHD_OLD.exists():
        try:
            subprocess.run(["launchctl", "unload", "-w", str(_LAUNCHD_OLD)],
                           capture_output=True, timeout=10)
            _LAUNCHD_OLD.unlink(missing_ok=True)
            _log("Removed old LaunchAgent plist")
        except Exception:
            pass
    plist = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
        '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        '<plist version="1.0">\n'
        '<dict>\n'
        f'  <key>Label</key>\n  <string>{_LAUNCHD_LABEL}</string>\n'
        '  <key>ProgramArguments</key>\n'
        '  <array>\n'
        f'    <string>{sys.executable}</string>\n'
        f'    <string>{script}</string>\n'
        '    <string>start</string>\n'
        '    <string>--silent</string>\n'
        '  </array>\n'
        '  <key>UserName</key>\n  <string>root</string>\n'
        '  <key>RunAtLoad</key>\n  <true/>\n'
        '  <key>StandardErrorPath</key>\n'
        '  <string>/tmp/cgti-lite.err</string>\n'
        '  <key>StandardOutPath</key>\n'
        '  <string>/tmp/cgti-lite.out</string>\n'
        '</dict>\n'
        '</plist>\n'
    )
    try:
        _LAUNCHD_PLIST.parent.mkdir(parents=True, exist_ok=True)
        _LAUNCHD_PLIST.write_text(plist, encoding="utf-8")
        # Set correct ownership and permissions for LaunchDaemon
        subprocess.run(["chown", "root:wheel", str(_LAUNCHD_PLIST)],
                       capture_output=True)
        subprocess.run(["chmod", "644", str(_LAUNCHD_PLIST)],
                       capture_output=True)
        r = subprocess.run(["launchctl", "load", "-w", str(_LAUNCHD_PLIST)],
                           capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            return False, r.stderr.strip() or "launchctl load failed"
        _log(f"Autostart enabled (LaunchDaemon): {_LAUNCHD_PLIST}")
        return True, str(_LAUNCHD_PLIST)
    except PermissionError:
        return False, "Permission denied — run with sudo"
    except Exception as e:
        return False, str(e)


def _autostart_disable_macos() -> tuple:
    try:
        if _LAUNCHD_PLIST.exists():
            subprocess.run(["launchctl", "unload", "-w", str(_LAUNCHD_PLIST)],
                           capture_output=True, timeout=10)
            _LAUNCHD_PLIST.unlink(missing_ok=True)
        # Also clean up old LaunchAgent if it exists
        if _LAUNCHD_OLD.exists():
            subprocess.run(["launchctl", "unload", "-w", str(_LAUNCHD_OLD)],
                           capture_output=True, timeout=10)
            _LAUNCHD_OLD.unlink(missing_ok=True)
        # Also kill any leftover autoblock wrapper processes
        try:
            subprocess.run(["pkill", "-f", "cgti-autoblock.sh"],
                           capture_output=True, timeout=5)
        except Exception:
            pass
        _log("Autostart disabled (launchd)")
        return True, ""
    except Exception as e:
        return False, str(e)


def _autostart_status_macos() -> str:
    if not _LAUNCHD_PLIST.exists():
        # Check old location too
        if _LAUNCHD_OLD.exists():
            return "enabled (old location — re-run 'cgti autostart enable')"
        return "disabled"
    try:
        r = subprocess.run(["launchctl", "list", _LAUNCHD_LABEL],
                           capture_output=True, text=True, timeout=5)
        return "enabled" if r.returncode == 0 else "loaded (not running)"
    except Exception:
        return "enabled (plist exists)"


def _autostart_enable_windows(script: str) -> tuple:
    """Create a Windows Task Scheduler task for CGTI Lite (silent, no console).

    Interface is read from config at runtime, not baked into the task.
    Uses a VBS wrapper to suppress any console window flash.
    """
    try:
        # Remove existing task first
        subprocess.run(
            ["schtasks", "/Delete", "/TN", _SCHTASK_NAME, "/F"],
            capture_output=True, timeout=10,
        )

        # Prefer pythonw.exe (no console window) over python.exe
        pythonw = sys.executable.replace("python.exe", "pythonw.exe")
        py_exe = pythonw if Path(pythonw).exists() else sys.executable

        # Create a VBS silent launcher to suppress any console flash
        # WshShell.Run with window style 0 = completely hidden
        vbs_dir = Path(os.environ.get("APPDATA", "")) / "cgti-lite"
        vbs_dir.mkdir(parents=True, exist_ok=True)
        vbs_path = vbs_dir / "cgti-autostart.vbs"
        # VBS double-quote escaping: "" inside a string literal = one "
        vbs_content = (
            'Set WshShell = CreateObject("WScript.Shell")\n'
            f'WshShell.Run """{py_exe}"" ""{script}"" start --silent", 0, False\n'
        )
        vbs_path.write_text(vbs_content, encoding="utf-8")

        cmd_line = f'wscript.exe "{vbs_path}"'
        r = subprocess.run(
            ["schtasks", "/Create",
             "/TN", _SCHTASK_NAME,
             "/TR", cmd_line,
             "/SC", "ONLOGON",
             "/RL", "HIGHEST",
             "/F"],
            capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=15,
        )
        if r.returncode != 0:
            return False, r.stderr.strip() or r.stdout.strip() or "schtasks failed"
        _log(f"Autostart enabled: Task Scheduler '{_SCHTASK_NAME}' (silent VBS)")
        return True, _SCHTASK_NAME
    except Exception as e:
        return False, str(e)


def _autostart_disable_windows() -> tuple:
    try:
        r = subprocess.run(
            ["schtasks", "/Delete", "/TN", _SCHTASK_NAME, "/F"],
            capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=10,
        )
        if r.returncode != 0 and "not found" not in (r.stderr + r.stdout).lower():
            return False, r.stderr.strip() or r.stdout.strip()
        _log("Autostart disabled (schtasks)")
        return True, ""
    except Exception as e:
        return False, str(e)


def _autostart_status_windows() -> str:
    try:
        r = subprocess.run(
            ["schtasks", "/Query", "/TN", _SCHTASK_NAME, "/FO", "LIST"],
            capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=10,
        )
        if r.returncode != 0:
            return "disabled"
        for line in r.stdout.splitlines():
            if "Status:" in line:
                return f"enabled ({line.split(':', 1)[1].strip().lower()})"
        return "enabled"
    except Exception:
        return "unknown"


def cmd_autostart(args):
    """Enable, disable, or check autostart status."""
    sub = getattr(args, "autostart_cmd", None)
    cfg = ConfigManager()

    if sub == "status" or sub is None:
        if OS == "Linux":
            status = _autostart_status_linux()
        elif OS == "Darwin":
            status = _autostart_status_macos()
        else:
            status = _autostart_status_windows()
        color = "green" if "enabled" in status or status == "enabled" else "yellow"
        console.print(f"  [bold]Autostart:[/bold] [{color}]{status}[/{color}]")
        return

    # Resolve script path
    try:
        script = str(Path(__file__).resolve())
    except Exception:
        script = str(Path(sys.argv[0]).resolve())

    # Validate interface is configured (it's read from config at runtime,
    # not baked into the service file — but must exist for start --silent)
    interface = cfg.get("suricata", "interface", default="")
    if not interface:
        console.print(
            "[red]✗  No interface configured.[/red]\n"
            "   Run [bold]cgti install[/bold] first, or set manually:\n"
            "   [dim]cgti config set suricata.interface eth0[/dim]"
        )
        return

    if sub == "enable":
        console.print(
            f"  [cyan]Enabling autostart…[/cyan]\n"
            f"  [dim]Script:    {script}[/dim]\n"
            f"  [dim]Interface: {interface} (read from config at boot)[/dim]\n"
            f"  [dim]OS:        {OS}[/dim]"
        )
        if OS == "Linux":
            ok, info = _autostart_enable_linux(script)
        elif OS == "Darwin":
            ok, info = _autostart_enable_macos(script)
        else:
            ok, info = _autostart_enable_windows(script)

        if ok:
            cfg.set("cgti", "autostart", True)
            console.print(f"  [green]✓  Autostart enabled[/green]  [dim]{info}[/dim]")
        else:
            console.print(f"  [red]✗  Failed: {info}[/red]")

    elif sub == "disable":
        if OS == "Linux":
            ok, err = _autostart_disable_linux()
        elif OS == "Darwin":
            ok, err = _autostart_disable_macos()
        else:
            ok, err = _autostart_disable_windows()

        if ok:
            cfg.set("cgti", "autostart", False)
            console.print("  [green]✓  Autostart disabled[/green]")
        else:
            console.print(f"  [red]✗  Failed: {err}[/red]")


# ─── CLI ─────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cgti",
        description=f"CGTI Lite for OpenClaw v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  install                         Auto-detect & install everything
  status                          System status & stats
  start  [-i IFACE]               Start Suricata
  stop                            Stop Suricata
  live   [--autoblock] [-v]       Live alert feed (Enhanced Autoblock)

  rules list  [-f FILE] [--filter TEXT] [--page N]
  rules enable  <SID>
  rules disable <SID>
  rules add "<rule>" [-f FILE]
  rules reload
  rules files
  rules validate                   Auto-fix Suricata-incompatible rules

  blocked list
  blocked add    <IP> [-r REASON]
  blocked remove <IP>
  blocked clear

  logs  [-n N] [--severity 1-4] [--ip ADDR] [--cgti-log]

  config show
  config set <key.sub> <value>
  config reset
  config path

  uninstall                       Remove CGTI Lite

  autostart enable                Enable boot-time autostart
  autostart disable               Disable autostart
  autostart status                Show autostart status

Enhanced Autoblock Configuration:
  cgti config set cgti.autoblock true           Enable Enhanced Autoblock
  cgti config set cgti.autoblock false          Disable Enhanced Autoblock
  cgti config set cgti.autoblock_min_severity 2 Severity threshold (1-4)
    1 = Critical only
    2 = Critical + High
    3 = Critical + High + Medium  (default)
    4 = All severities
        """,
    )
    sub = p.add_subparsers(dest="command", metavar="COMMAND")

    sub.add_parser("install")
    sub.add_parser("status")

    p_st = sub.add_parser("start")
    p_st.add_argument("-i", "--interface", metavar="IFACE")
    p_st.add_argument("--silent", action="store_true",
                       help="Skip interactive prompts (used by autostart)")

    sub.add_parser("stop")

    p_lv = sub.add_parser("live")
    p_lv.add_argument("--autoblock", action="store_true")
    p_lv.add_argument("-v", "--verbose", action="store_true")
    p_lv.add_argument("--daemon", action="store_true", help=argparse.SUPPRESS)

    # rules
    p_r = sub.add_parser("rules")
    rs  = p_r.add_subparsers(dest="rules_cmd", metavar="ACTION")
    rl  = rs.add_parser("list");    rl.add_argument("-f", "--file"); rl.add_argument("--filter"); rl.add_argument("--page", type=int, default=1)
    re_ = rs.add_parser("enable");  re_.add_argument("sid"); re_.add_argument("--no-reload", action="store_true")
    rd  = rs.add_parser("disable"); rd.add_argument("sid");  rd.add_argument("--no-reload", action="store_true")
    ra  = rs.add_parser("add");     ra.add_argument("rule"); ra.add_argument("-f", "--file", default="openclaw-custom.rules")
    rs.add_parser("reload")
    rs.add_parser("files")
    rs.add_parser("validate", help="Auto-detect & disable Suricata-incompatible rules")
    p_ap = rs.add_parser("apply", help="Apply .rules files from a directory (disable others)")
    p_ap.add_argument("--dir", help="rules directory (default: ./rules)")

    # blocked
    p_b = sub.add_parser("blocked")
    bs  = p_b.add_subparsers(dest="blocked_cmd", metavar="ACTION")
    bs.add_parser("list")
    ba  = bs.add_parser("add");    ba.add_argument("ip"); ba.add_argument("-r", "--reason", default="Manual block")
    bm  = bs.add_parser("remove"); bm.add_argument("ip")
    bs.add_parser("clear")

    # logs
    p_lg = sub.add_parser("logs")
    p_lg.add_argument("-n", "--limit",   type=int, default=50)
    p_lg.add_argument("--severity",      type=int, choices=[1, 2, 3, 4])
    p_lg.add_argument("--ip",            metavar="ADDR")
    p_lg.add_argument("--cgti-log",      action="store_true", dest="cgti_log")

    # config
    p_c = sub.add_parser("config")
    cs  = p_c.add_subparsers(dest="config_cmd", metavar="ACTION")
    cs.add_parser("show"); cs.add_parser("reset"); cs.add_parser("path")
    p_cs = cs.add_parser("set"); p_cs.add_argument("key"); p_cs.add_argument("value")

    # uninstall
    sub.add_parser("uninstall", help="Remove CGTI Lite files")

    # autostart
    p_as = sub.add_parser("autostart", help="Manage boot-time autostart")
    as_sub = p_as.add_subparsers(dest="autostart_cmd")
    as_sub.add_parser("enable",  help="Enable autostart on boot")
    as_sub.add_parser("disable", help="Disable autostart")
    as_sub.add_parser("status",  help="Show autostart status")

    return p


HANDLERS = {
    "install":   cmd_install,  "status":    cmd_status,
    "start":     cmd_start,    "stop":      cmd_stop,
    "live":      cmd_live,     "rules":     cmd_rules,
    "blocked":   cmd_blocked,  "logs":      cmd_logs,
    "config":    cmd_config,   "uninstall": cmd_uninstall,
    "autostart": cmd_autostart,
}

def main():
    parser = build_parser()
    args   = parser.parse_args()
    if not args.command:
        print_banner()
        parser.print_help()
        return
    handler = HANDLERS.get(args.command)
    if not handler:
        parser.print_help()
        return
    try:
        handler(args)
    except KeyboardInterrupt:
        console.print("\n[dim]Interrupted.[/dim]")
    except PermissionError:
        console.print(
            "[red]✗  Permission denied.[/red] "
            "Run as [bold]Administrator[/bold] (Windows) or [bold]sudo[/bold] (Linux/macOS)."
        )
    except Exception as e:
        console.print(f"[red]✗  Error: {e}[/red]")
        if os.environ.get("CGTI_DEBUG"):
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    main()
