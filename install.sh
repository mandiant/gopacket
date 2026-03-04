#!/bin/bash
#
# gopacket installer
# Builds all tools and installs them as gopacket-<toolname> on your PATH
#

set -e

# Default install directory
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
BUILD_DIR="./bin"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --prefix DIR    Install to DIR (default: /usr/local/bin)"
    echo "  --build-only    Build but don't install"
    echo "  --uninstall     Remove installed gopacket tools"
    echo "  -h, --help      Show this help"
    echo ""
    echo "Environment:"
    echo "  INSTALL_DIR     Same as --prefix (default: /usr/local/bin)"
}

build_only=false
uninstall=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix)
            INSTALL_DIR="$2"
            shift 2
            ;;
        --build-only)
            build_only=true
            shift
            ;;
        --uninstall)
            uninstall=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Uninstall mode
if $uninstall; then
    echo "Removing gopacket tools from ${INSTALL_DIR}..."
    count=0
    for f in "${INSTALL_DIR}"/gopacket-*; do
        if [ -f "$f" ]; then
            echo "  removing $(basename "$f")"
            rm -f "$f"
            ((count++))
        fi
    done
    if [ $count -eq 0 ]; then
        echo "No gopacket tools found in ${INSTALL_DIR}"
    else
        echo -e "${GREEN}Removed ${count} tools${NC}"
    fi
    exit 0
fi

# Check dependencies
if ! command -v go &>/dev/null; then
    echo -e "${RED}Error: go is not installed or not in PATH${NC}"
    echo "Install Go from https://go.dev/dl/"
    exit 1
fi

if ! command -v gcc &>/dev/null; then
    echo -e "${RED}Error: gcc is not installed${NC}"
    echo "Install with: apt install build-essential (Debian/Ubuntu) or yum install gcc (RHEL/CentOS)"
    exit 1
fi

# Determine script directory (where go.mod lives)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -f go.mod ]; then
    echo -e "${RED}Error: go.mod not found. Run this script from the gopacket directory.${NC}"
    exit 1
fi

# Discover tools
tools=($(ls tools/))
total=${#tools[@]}

echo "gopacket installer"
echo "  Tools:   ${total}"
echo "  Build:   ${BUILD_DIR}/"
if ! $build_only; then
    echo "  Install: ${INSTALL_DIR}/"
fi
echo ""

# Build
echo "Building ${total} tools..."
mkdir -p "${BUILD_DIR}"

failed=0
for tool in "${tools[@]}"; do
    echo -n "  ${tool}... "
    if CGO_ENABLED=1 go build -o "${BUILD_DIR}/${tool}" \
        -ldflags '-linkmode external -extldflags "-static-libgcc"' \
        "./tools/${tool}" 2>/dev/null; then
        echo -e "${GREEN}ok${NC}"
    else
        echo -e "${RED}failed${NC}"
        ((failed++))
    fi
done

if [ $failed -gt 0 ]; then
    echo -e "\n${RED}${failed} tool(s) failed to build${NC}"
    exit 1
fi

echo -e "\n${GREEN}All ${total} tools built successfully${NC}"

if $build_only; then
    echo "Binaries are in ${BUILD_DIR}/"
    exit 0
fi

# Install
echo ""
echo "Installing to ${INSTALL_DIR}/ as gopacket-<toolname>..."

# Check write permissions
if [ ! -w "${INSTALL_DIR}" ]; then
    echo -e "${YELLOW}Note: ${INSTALL_DIR} requires elevated permissions${NC}"
    echo "Re-running install step with sudo..."
    SUDO="sudo"
else
    SUDO=""
fi

for tool in "${tools[@]}"; do
    # Normalize tool name: lowercase, replace special chars with hyphens
    normalized=$(echo "$tool" | tr '[:upper:]' '[:lower:]' | tr '_' '-')
    dest="${INSTALL_DIR}/gopacket-${normalized}"
    $SUDO cp "${BUILD_DIR}/${tool}" "$dest"
    $SUDO chmod +x "$dest"
done

echo -e "${GREEN}Installed ${total} tools to ${INSTALL_DIR}/${NC}"
echo ""
echo "Tools are available as:"
echo "  gopacket-secretsdump, gopacket-smbclient, gopacket-psexec, etc."
echo ""
echo "Run 'gopacket-<tool> -h' for help on any tool."
echo "To uninstall: $0 --uninstall"
