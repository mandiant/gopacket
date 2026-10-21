#!/bin/bash
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
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
    cat <<'EOF'
Usage: ./install.sh [OPTIONS]

Build and install gopacket tools. Run with no flags to get an interactive
prompt explaining the build targets.

Options:
  --target NAME   Build target. One of:
                    native    (default) Linux/macOS cgo, installs to
                              /usr/local/bin. All 63 tools; proxychains
                              and -proxy both work. Needs GCC + libpcap-dev.
                    portable  Static host-OS binaries, no system libs.
                              sniff/split stubbed; use -proxy (proxychains
                              won't hook). Output: ./dist/portable/
                    windows   Windows amd64 cross-compile. sniff/split/
                              sniffer stubbed; -proxy only (no LD_PRELOAD
                              on Windows). Output: ./dist/windows/
                    all       Build every target.

  --prefix DIR    For the native target, install to DIR instead of
                  /usr/local/bin. Has no effect on cross-compile targets.
  --build-only    Build but don't install (native target only).
  --uninstall     Remove previously installed gopacket-* binaries from
                  $INSTALL_DIR. Affects native installs only.
  -h, --help      Show this help.

Environment:
  INSTALL_DIR     Same as --prefix.

Examples:
  ./install.sh                          Interactive, prompts for target
  ./install.sh --target native          Today's default (build + install)
  ./install.sh --target windows         Cross-compile Windows .exe files
  ./install.sh --target all             Build every target in one run
EOF
}

target=""
build_only=false
uninstall=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)
            target="$2"
            shift 2
            ;;
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

# Determine script directory (where go.mod lives)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -f go.mod ]; then
    echo -e "${RED}Error: go.mod not found. Run this script from the gopacket directory.${NC}"
    exit 1
fi

# Interactive prompt if no --target given and stdin is a terminal.
if [ -z "$target" ]; then
    if [ -t 0 ]; then
        cat <<'EOF'
gopacket installer

Pick a build target. If unsure, pick (1).

  (1) native
      Linux/macOS cgo, installs to /usr/local/bin. All 63 tools; supports
      both proxychains (LD_PRELOAD) and the -proxy SOCKS5 flag.
      Needs GCC + libpcap-dev installed.

  (2) portable
      Static single-file binaries for your host OS, no system libs needed.
      sniff/split are stubs (they need libpcap). proxychains can't hook a
      cgo-off Go binary, so use -proxy instead. Output: ./dist/portable/

  (3) windows
      Windows amd64 .exe cross-compile. sniff/split/sniffer are stubs.
      No LD_PRELOAD on Windows, so -proxy is the only proxy path.
      Output: ./dist/windows/

  (4) all
      Build every target.

EOF
        read -r -p "Choice [1-4, default 1]: " choice
        choice="${choice:-1}"
        case "$choice" in
            1) target="native" ;;
            2) target="portable" ;;
            3) target="windows" ;;
            4) target="all" ;;
            *) echo -e "${RED}Invalid choice: $choice${NC}"; exit 1 ;;
        esac
        echo ""
    else
        # Non-TTY (piped, CI). Default to native without prompting.
        target="native"
    fi
fi

# Validate target
case "$target" in
    native|portable|windows|all) ;;
    *)
        echo -e "${RED}Error: unknown target '$target'${NC}"
        echo "Valid targets: native, portable, windows, all"
        exit 1
        ;;
esac

# Check the Go toolchain is present (all targets need this).
if ! command -v go &>/dev/null; then
    echo -e "${RED}Error: go is not installed or not in PATH${NC}"
    echo "Install Go from https://go.dev/dl/"
    exit 1
fi

# build_target runs the build for one of: native, portable, windows.
# Sets the right GOOS/CGO_ENABLED, picks an output directory, and iterates
# over every tool in tools/. Stubs defined in the tools handle the cases
# where a tool cannot be built for the target.
build_target() {
    local t="$1"
    local goos goarch cgo outdir exe_suffix pcap_check label
    case "$t" in
        native)
            goos=""
            goarch=""
            cgo=1
            outdir="$BUILD_DIR"
            exe_suffix=""
            pcap_check=true
            label="native (host OS, cgo on)"
            ;;
        portable)
            goos=""   # inherit host OS
            goarch="" # inherit host arch
            cgo=0
            outdir="./dist/portable"
            exe_suffix=""
            pcap_check=false
            label="portable (host OS, cgo off, sniff/split stubbed)"
            ;;
        windows)
            goos="windows"
            goarch="amd64"
            cgo=0
            outdir="./dist/windows"
            exe_suffix=".exe"
            pcap_check=false
            label="windows (GOOS=windows amd64, sniff/split/sniffer stubbed)"
            ;;
    esac

    echo ""
    echo -e "${GREEN}=== Building ${label} ===${NC}"

    # Native target needs GCC for cgo and benefits from libpcap to get real
    # sniff/split. Cross-compile targets use stubs and need neither.
    if [ "$t" = "native" ]; then
        if ! command -v gcc &>/dev/null; then
            echo -e "${RED}Error: gcc is required for the native target (cgo)${NC}"
            echo "Install with: apt install build-essential (Debian/Ubuntu), yum install gcc (RHEL/CentOS), or xcode-select --install (macOS)"
            return 1
        fi
    fi

    local has_libpcap=true
    if $pcap_check; then
        local sdk_pcap=""
        if command -v xcrun &>/dev/null; then
            sdk_pcap="$(xcrun --show-sdk-path 2>/dev/null)/usr/include/pcap.h"
        fi
        if ! [ -f /usr/include/pcap.h ] \
           && ! [ -f /usr/include/pcap/pcap.h ] \
           && ! [ -f /usr/local/include/pcap.h ] \
           && ! [ -f /opt/homebrew/include/pcap.h ] \
           && ! [ -f /opt/homebrew/opt/libpcap/include/pcap.h ] \
           && ! [ -f /usr/local/opt/libpcap/include/pcap.h ] \
           && ! { [ -n "$sdk_pcap" ] && [ -f "$sdk_pcap" ]; } \
           && ! pkg-config --exists libpcap 2>/dev/null; then
            has_libpcap=false
            echo -e "${YELLOW}Warning: libpcap development headers not found${NC}"
            echo "  sniff and split will be skipped in this target."
            echo "  Install with: apt install libpcap-dev (Debian/Ubuntu/Kali)"
            echo "             or yum install libpcap-devel (RHEL/CentOS)"
            echo "             or brew install libpcap (macOS)"
            echo ""
        fi
    fi

    local tools
    tools=($(ls tools/))
    local total=${#tools[@]}

    mkdir -p "$outdir"

    local failed=0 skipped=0
    for tool in "${tools[@]}"; do
        # On native without libpcap, skip sniff/split entirely (same as the
        # old behavior). On other targets, stubs handle the skip automatically.
        if [ "$t" = "native" ] && ! $has_libpcap && { [ "$tool" = "sniff" ] || [ "$tool" = "split" ]; }; then
            echo -e "  ${tool}... ${YELLOW}skipped (libpcap-dev not installed)${NC}"
            skipped=$((skipped + 1))
            continue
        fi
        echo -n "  ${tool}... "
        # Cross-compile outputs get the same gopacket- prefix as the native
        # install, so users copying a .exe to a Windows host don't end up with
        # ping.exe / net.exe / reg.exe shadowing built-ins of the same name.
        # Native stays as the raw name here; install_native prefixes when it
        # copies to INSTALL_DIR.
        local out_name
        if [ "$t" = "native" ]; then
            out_name="$tool"
        else
            local normalized
            normalized=$(echo "$tool" | tr '[:upper:]' '[:lower:]' | tr '_' '-')
            out_name="gopacket-${normalized}"
        fi
        local out_path="${outdir}/${out_name}${exe_suffix}"
        local build_cmd=(go build -o "$out_path")
        if [ "$t" = "native" ] && [ "$(uname -s)" = "Linux" ]; then
            # Static-link libgcc on Linux so binaries run on minimally-versioned
            # hosts. Apple's clang linker on macOS does not support -static-libgcc.
            build_cmd+=(-ldflags '-linkmode external -extldflags "-static-libgcc"')
        fi
        build_cmd+=("./tools/${tool}")
        if err=$(GOOS="$goos" GOARCH="$goarch" CGO_ENABLED="$cgo" "${build_cmd[@]}" 2>&1); then
            echo -e "${GREEN}ok${NC}"
        else
            echo -e "${RED}failed${NC}"
            echo "$err" | sed 's/^/      /'
            failed=$((failed + 1))
        fi
    done

    if [ $failed -gt 0 ]; then
        echo -e "\n${RED}${failed} tool(s) failed to build for ${t}${NC}"
        return 1
    fi

    local built=$((total - skipped))
    echo -e "\n${GREEN}Built ${built}/${total} tools for ${t} in ${outdir}/${NC}"
    if [ $skipped -gt 0 ]; then
        echo -e "${YELLOW}Skipped ${skipped} tool(s), install libpcap-dev to enable them${NC}"
    fi
    return 0
}

# Install is only meaningful for the native target. Cross-compile outputs
# live in ./dist/ for the user to copy to the right host.
install_native() {
    echo ""
    echo "Installing to ${INSTALL_DIR}/ as gopacket-<toolname>..."

    local SUDO=""
    mkdir -p "${INSTALL_DIR}" 2>/dev/null || true
    if [ ! -w "${INSTALL_DIR}" ]; then
        echo -e "${YELLOW}Note: ${INSTALL_DIR} requires elevated permissions${NC}"
        echo "Re-running install step with sudo..."
        SUDO="sudo"
        $SUDO mkdir -p "${INSTALL_DIR}"
    fi

    local tools
    tools=($(ls tools/))
    local installed=0
    for tool in "${tools[@]}"; do
        if [ ! -f "${BUILD_DIR}/${tool}" ]; then
            continue
        fi
        local normalized
        normalized=$(echo "$tool" | tr '[:upper:]' '[:lower:]' | tr '_' '-')
        local dest="${INSTALL_DIR}/gopacket-${normalized}"
        $SUDO cp "${BUILD_DIR}/${tool}" "$dest"
        $SUDO chmod +x "$dest"
        installed=$((installed + 1))
    done

    echo -e "${GREEN}Installed ${installed} tools to ${INSTALL_DIR}/${NC}"
    echo ""
    echo "Tools are available as:"
    echo "  gopacket-secretsdump, gopacket-smbclient, gopacket-psexec, etc."
    echo ""
    echo "Run 'gopacket-<tool> -h' for help on any tool."
    echo "To uninstall: $0 --uninstall"
}

# Run the requested target(s).
if [ "$target" = "all" ]; then
    build_target native || exit 1
    build_target portable || exit 1
    build_target windows || exit 1
    if ! $build_only; then
        install_native
    fi
    echo ""
    echo -e "${GREEN}All targets built.${NC}"
    echo "  native   -> ${BUILD_DIR}/"
    echo "  portable -> ./dist/portable/"
    echo "  windows  -> ./dist/windows/"
    exit 0
fi

build_target "$target" || exit 1

if [ "$target" = "native" ] && ! $build_only; then
    install_native
elif [ "$target" = "native" ] && $build_only; then
    echo ""
    echo "Binaries are in ${BUILD_DIR}/"
else
    echo ""
    echo "Binaries are in $([ "$target" = "portable" ] && echo ./dist/portable/ || echo ./dist/windows/)"
    echo "Copy them to the target host and run."
fi
