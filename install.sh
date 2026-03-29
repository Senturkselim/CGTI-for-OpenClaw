#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Selim Şentürk
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
# ─────────────────────────────────────────────────────────────────────────────
#  CGTI Lite for OpenClaw — Linux/macOS Installer
# ─────────────────────────────────────────────────────────────────────────────

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info() { echo -e "${CYAN}[INFO]${RESET}  $*"; }
ok()   { echo -e "${GREEN}[  OK]${RESET}  $*"; }
warn() { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
err()  { echo -e "${RED}[FAIL]${RESET}  $*"; exit 1; }

echo ""
echo -e "${BOLD}${CYAN}"
echo "  ╔══════════════════════════════════════════╗"
echo "  ║     CGTI Lite for OpenClaw — Installer   ║"
echo "  ╚══════════════════════════════════════════╝"
echo -e "${RESET}"

# ── Detect OS ────────────────────────────────────────────────────────────────
OS_TYPE="$(uname -s)"
INSTALL_DIR="/usr/local/lib/cgti-lite"
BIN_PATH="/usr/local/bin/cgti"

if [[ "$OS_TYPE" == "Darwin" ]]; then
    info "Detected: macOS"
    if [[ "$(id -u)" -ne 0 ]]; then
        INSTALL_DIR="$HOME/.local/lib/cgti-lite"
        BIN_PATH="$HOME/.local/bin/cgti"
        mkdir -p "$HOME/.local/bin"
    fi
else
    info "Detected: Linux"
    if [[ "$(id -u)" -ne 0 ]]; then
        warn "Not root. Installing to user directory."
        INSTALL_DIR="$HOME/.local/lib/cgti-lite"
        BIN_PATH="$HOME/.local/bin/cgti"
        mkdir -p "$HOME/.local/bin"
    fi
fi

# ── Python check ─────────────────────────────────────────────────────────────
info "Checking for Python 3..."
if command -v python3 &>/dev/null; then
    PY=$(python3 --version 2>&1 | awk '{print $2}')
    ok "Python $PY found."
    PYTHON=python3
elif command -v python &>/dev/null; then
    PY=$(python --version 2>&1 | awk '{print $2}')
    [[ "${PY:0:1}" == "3" ]] && { ok "Python $PY found."; PYTHON=python; } || err "Python 3.8+ required."
else
    err "Python 3 not found. https://www.python.org/downloads/"
fi

# ── Virtual environment + dependencies ────────────────────────────────────
VENV_DIR="$INSTALL_DIR/.venv"
info "Creating virtual environment at: $VENV_DIR"
$PYTHON -m venv "$VENV_DIR" 2>/dev/null || {
    # Fallback: some minimal Pythons lack ensurepip
    if [[ "$OS_TYPE" == "Darwin" ]]; then
        warn "venv creation failed, trying with --without-pip..."
        $PYTHON -m venv --without-pip "$VENV_DIR"
        curl -sSL https://bootstrap.pypa.io/get-pip.py | "$VENV_DIR/bin/python"
    else
        # Auto-install python3-venv on Debian/Ubuntu if apt-get is available
        if command -v apt-get &>/dev/null; then
            # Detect the Python minor version for the correct package name
            PY_MINOR=$($PYTHON -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
            warn "venv module missing — installing python${PY_MINOR}-venv..."
            apt-get update -qq 2>/dev/null
            apt-get install -y -qq "python${PY_MINOR}-venv" 2>/dev/null || \
                apt-get install -y -qq python3-venv 2>/dev/null || true
            # Retry venv creation
            $PYTHON -m venv "$VENV_DIR" 2>/dev/null || {
                warn "Still failed, trying --without-pip..."
                $PYTHON -m venv --without-pip "$VENV_DIR"
                curl -sSL https://bootstrap.pypa.io/get-pip.py | "$VENV_DIR/bin/python"
            }
        elif command -v dnf &>/dev/null; then
            warn "venv module missing — installing python3-libs..."
            dnf install -y -q python3-libs 2>/dev/null || true
            $PYTHON -m venv "$VENV_DIR" 2>/dev/null || \
                err "python3 -m venv failed. Install manually: sudo dnf install python3-libs"
        elif command -v yum &>/dev/null; then
            warn "venv module missing — installing python3-libs..."
            yum install -y -q python3-libs 2>/dev/null || true
            $PYTHON -m venv "$VENV_DIR" 2>/dev/null || \
                err "python3 -m venv failed. Install manually: sudo yum install python3-libs"
        elif command -v pacman &>/dev/null; then
            # Arch includes venv in base python package; try --without-pip
            warn "venv creation failed, trying --without-pip..."
            $PYTHON -m venv --without-pip "$VENV_DIR"
            curl -sSL https://bootstrap.pypa.io/get-pip.py | "$VENV_DIR/bin/python"
        else
            err "python3 -m venv failed. Install your distro's python3-venv package."
        fi
    fi
}
ok "Virtual environment created."

info "Installing dependencies (rich)..."
"$VENV_DIR/bin/pip" install --quiet --upgrade rich
ok "rich installed."

# The launcher will use the venv Python so all imports work
PYTHON_EXEC="$VENV_DIR/bin/python"

# ── Suricata ─────────────────────────────────────────────────────────────────
if ! command -v suricata &>/dev/null; then
    echo ""
    warn "Suricata not found."
    if command -v apt-get &>/dev/null; then
        echo -e "  Install: ${CYAN}sudo apt install suricata${RESET}"
    elif command -v yum &>/dev/null; then
        echo -e "  Install: ${CYAN}sudo yum install suricata${RESET}"
    elif command -v pacman &>/dev/null; then
        echo -e "  Install: ${CYAN}sudo pacman -S suricata${RESET}"
    elif [[ "$OS_TYPE" == "Darwin" ]]; then
        echo -e "  Install: ${CYAN}brew install suricata${RESET}"
    fi
    echo -e "  or run: ${CYAN}cgti install${RESET} to install automatically."
    echo ""
else
    ok "Suricata found: $(which suricata)"
fi

# ── Copy files ───────────────────────────────────────────────────────────────
info "Installing CGTI Lite to: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cp "$SCRIPT_DIR/cgti_lite.py" "$INSTALL_DIR/cgti_lite.py"

# ── Copy rules directory ─────────────────────────────────────────────────────
if [[ -d "$SCRIPT_DIR/rules" ]] && ls "$SCRIPT_DIR/rules/"*.rules &>/dev/null 2>&1; then
    mkdir -p "$INSTALL_DIR/rules"
    cp "$SCRIPT_DIR/rules/"*.rules "$INSTALL_DIR/rules/"
    ok "Rules copied to: $INSTALL_DIR/rules/"
else
    warn "rules/ directory not found. It must be in the same directory as install.sh."
fi

# ── Launcher ─────────────────────────────────────────────────────────────────
info "Creating launcher: $BIN_PATH"
cat > "$BIN_PATH" <<WRAPPER
#!/usr/bin/env bash
exec $PYTHON_EXEC "$INSTALL_DIR/cgti_lite.py" "\$@"
WRAPPER
chmod +x "$BIN_PATH"

# Also place in /usr/local/bin for sudo use (so sudo cgti works)
if [[ "$(id -u)" -ne 0 ]] && command -v sudo &>/dev/null; then
    SYSTEM_BIN="/usr/local/bin/cgti"
    sudo bash -c "cat > $SYSTEM_BIN <<SWRAP
#!/usr/bin/env bash
exec $PYTHON_EXEC \"$INSTALL_DIR/cgti_lite.py\" \"\\\$@\"
SWRAP
chmod +x $SYSTEM_BIN" 2>/dev/null && ok "sudo cgti enabled: $SYSTEM_BIN" || warn "System launcher could not be installed (not critical)"
fi

# ── PATH check ───────────────────────────────────────────────────────────────
BIN_DIR="$(dirname $BIN_PATH)"
if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    EXPORT_LINE="export PATH=\"\$PATH:$BIN_DIR\""
    # .bashrc
    if [[ -f "$HOME/.bashrc" ]] && ! grep -q "$BIN_DIR" "$HOME/.bashrc"; then
        echo "" >> "$HOME/.bashrc"
        echo "# CGTI Lite" >> "$HOME/.bashrc"
        echo "$EXPORT_LINE" >> "$HOME/.bashrc"
        ok "PATH updated: ~/.bashrc"
    fi
    # .zshrc
    if [[ -f "$HOME/.zshrc" ]] && ! grep -q "$BIN_DIR" "$HOME/.zshrc"; then
        echo "" >> "$HOME/.zshrc"
        echo "# CGTI Lite" >> "$HOME/.zshrc"
        echo "$EXPORT_LINE" >> "$HOME/.zshrc"
        ok "PATH updated: ~/.zshrc"
    fi
    export PATH="$PATH:$BIN_DIR"
    warn "Will be active automatically in new terminals. For now: source ~/.bashrc"
fi

echo ""
echo -e "${GREEN}${BOLD}✅  CGTI Lite installed!${RESET}"
echo ""
echo -e "  ${CYAN}cgti install${RESET}   — Configure Suricata"
echo -e "  ${CYAN}cgti start${RESET}     — Start Suricata"
echo -e "  ${CYAN}cgti --help${RESET}    — All commands"
echo ""
