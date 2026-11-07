#!/usr/bin/env bash
# ==============================================================================
# DeadDrop - Single-Command Installer for Linux & Kali Linux
# ==============================================================================

set -e

# Terminal colors
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${CYAN}"
cat << 'EOF'
 ██████╗ ███████╗ █████╗ ██████╗ ██████╗ ██████╗  ██████╗ ██████╗ 
 ██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔═══██╗██╔══██╗
 ██║  ██║█████╗  ███████║██║  ██║██║  ██║██████╔╝██║   ██║██████╔╝
 ██║  ██║██╔══╝  ██╔══██║██║  ██║██║  ██║██╔══██╗██║   ██║██╔═══╝ 
 ██████╔╝███████╗██║  ██║██████╔╝██████╔╝██║  ██║╚██████╔╝██║     
 ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝     
   ✦ DeadDrop Automated Single-Command Installer [Kali Linux / Desktop] ✦
EOF
echo -e "${NC}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 1. Check Python 3
echo -e "${CYAN}[1/5] Checking Python environment...${NC}"
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}[!] Error: Python 3 is required but not installed.${NC}"
    echo "    Install with: sudo apt update && sudo apt install -y python3 python3-venv python3-pip"
    exit 1
fi

PY_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo -e "${GREEN}[✔] Detected Python ${PY_VERSION}${NC}"

# Check for apt dependencies if on Debian/Kali and root or sudo
if command -v apt-get &>/dev/null; then
    echo -e "${CYAN}[2/5] Checking system GUI libraries (libxcb, venv)...${NC}"
    MISSING_PKGS=()
    dpkg -s python3-venv &>/dev/null || MISSING_PKGS+=("python3-venv")
    dpkg -s libxcb-cursor0 &>/dev/null || MISSING_PKGS+=("libxcb-cursor0")
    if [ ${#MISSING_PKGS[@]} -gt 0 ]; then
        echo -e "${YELLOW}[*] Installing system dependencies: ${MISSING_PKGS[*]} ...${NC}"
        if [ "$EUID" -eq 0 ]; then
            apt-get update -qq && apt-get install -y "${MISSING_PKGS[@]}"
        elif command -v sudo &>/dev/null; then
            sudo apt-get update -qq && sudo apt-get install -y "${MISSING_PKGS[@]}"
        fi
    else
        echo -e "${GREEN}[✔] System libraries satisfied.${NC}"
    fi
else
    echo -e "${CYAN}[2/5] Skipping apt check (non-Debian system).${NC}"
fi

# 3. Setup Virtual Environment
echo -e "${CYAN}[3/5] Setting up virtual environment (.venv)...${NC}"
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
    echo -e "${GREEN}[✔] Created virtual environment at .venv${NC}"
else
    echo -e "${GREEN}[✔] Existing virtual environment found at .venv${NC}"
fi

source .venv/bin/activate

# 4. Install Dependencies & Package Entrypoint
echo -e "${CYAN}[4/5] Installing DeadDrop dependencies and CLI tools...${NC}"
pip install --upgrade pip -q
pip install -e . -q
pip install pytest pytest-asyncio -q
echo -e "${GREEN}[✔] Dependencies installed successfully.${NC}"

# 5. Global Command Symlink & Desktop Launcher
echo -e "${CYAN}[5/5] Configuring system-wide 'deaddrop' command...${NC}"

# Target binary directory
INSTALL_BIN_DIR="$HOME/.local/bin"
mkdir -p "$INSTALL_BIN_DIR"

WRAPPER="$INSTALL_BIN_DIR/deaddrop"
cat << WRAPPER_EOF > "$WRAPPER"
#!/usr/bin/env bash
exec "$SCRIPT_DIR/.venv/bin/deaddrop" "\$@"
WRAPPER_EOF
chmod +x "$WRAPPER"

# Also try /usr/local/bin if running as root
if [ "$EUID" -eq 0 ]; then
    ln -sf "$WRAPPER" /usr/local/bin/deaddrop
    echo -e "${GREEN}[✔] Linked /usr/local/bin/deaddrop${NC}"
fi

# Make root wrapper executable
chmod +x deaddrop.sh deaddrop-cli 2>/dev/null || true

# Add ~/.local/bin to PATH in current bashrc if not present
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    if [ -f "$HOME/.bashrc" ] && ! grep -q 'export PATH="$HOME/.local/bin:$PATH"' "$HOME/.bashrc"; then
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
    fi
    if [ -f "$HOME/.zshrc" ] && ! grep -q 'export PATH="$HOME/.local/bin:$PATH"' "$HOME/.zshrc"; then
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.zshrc"
    fi
    export PATH="$HOME/.local/bin:$PATH"
fi

# Create Desktop Application Entry for Kali Linux menu
DESKTOP_DIR="$HOME/.local/share/applications"
mkdir -p "$DESKTOP_DIR"
cat << DESKTOP_EOF > "$DESKTOP_DIR/deaddrop.desktop"
[Desktop Entry]
Name=DeadDrop
Comment=Zero-Knowledge 2FA Secure File Exchange
Exec=$SCRIPT_DIR/.venv/bin/python $SCRIPT_DIR/run_app.py
Terminal=false
Type=Application
Categories=Utility;Security;
DESKTOP_EOF

echo ""
echo -e "${GREEN}====================================================================${NC}"
echo -e "${GREEN}       ✦ DEADDROP INSTALLATION COMPLETED SUCCESSFULLY! ✦            ${NC}"
echo -e "${GREEN}====================================================================${NC}"
echo -e "You can now run DeadDrop from anywhere:"
echo ""
echo -e "  ${CYAN}deaddrop send <file>${NC}      - Encrypt and upload a file via CLI"
echo -e "  ${CYAN}deaddrop receive <code>${NC}   - Unlock and download a file via CLI"
echo -e "  ${CYAN}deaddrop list${NC}             - List active drops"
echo -e "  ${CYAN}deaddrop burn <id>${NC}        - Shred a drop"
echo -e "  ${CYAN}deaddrop server${NC}           - Start relay server"
echo -e "  ${CYAN}deaddrop gui${NC}              - Launch PySide6 Desktop GUI"
echo -e "  ${CYAN}deaddrop lab${NC}              - Run security lab attack simulations"
echo ""
echo -e "Or launch directly:"
echo -e "  ${YELLOW}./run_app.py${NC}              - Launch Desktop GUI"
echo -e "  ${YELLOW}./run_server.py${NC}           - Launch Cloud Relay Server"
echo -e "${GREEN}====================================================================${NC}"
