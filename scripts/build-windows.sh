#!/bin/bash
# scripts/build-windows.sh
# Cross-compile EPN Windows client on Linux using MinGW-w64
#
# Requirements:
#   apt install mingw-w64
#   (libsodium is cross-compiled automatically on first run)
#
# Output: build-windows/apps/epn-win-client/epn-win-client.exe

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$SCRIPT_DIR/.."
BUILD_DIR="$ROOT/build-windows"

GREEN='\033[0;32m'; CYAN='\033[0;36m'; RED='\033[0;31m'; NC='\033[0m'

echo -e "${CYAN}══════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  EPN Windows Cross-Compilation (MinGW-w64)       ${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════${NC}"
echo ""

# ── Check dependencies ────────────────────────────────────────────────────────
check_tool() {
    which "$1" > /dev/null 2>&1 || { echo -e "${RED}Missing: $1${NC}"; echo "  apt install mingw-w64"; exit 1; }
}
check_tool x86_64-w64-mingw32-g++-posix
check_tool x86_64-w64-mingw32-windres
echo -e "Compiler: $(x86_64-w64-mingw32-g++-posix --version | head -1)"

# ── Build libsodium for Windows if not present ────────────────────────────────
SODIUM_WIN="/usr/x86_64-w64-mingw32/lib/libsodium.a"
if [[ ! -f "$SODIUM_WIN" ]]; then
    echo ""
    echo "Building libsodium for Windows/MinGW..."
    SODIUM_SRC="/tmp/libsodium-src"
    if [[ ! -d "$SODIUM_SRC" ]]; then
        git clone --depth=1 -q https://github.com/jedisct1/libsodium.git "$SODIUM_SRC"
    fi
    cd "$SODIUM_SRC"
    [[ ! -f configure ]] && autoreconf -fi -q
    ./configure \
        --host=x86_64-w64-mingw32 \
        --prefix=/usr/x86_64-w64-mingw32 \
        --disable-shared --enable-static \
        CFLAGS="-O2" -q
    make -j"$(nproc)" -s
    make install -s
    cd -
    echo -e "${GREEN}  ✓ libsodium Windows built${NC}"
else
    echo -e "${GREEN}  ✓ libsodium Windows: already built${NC}"
fi

# ── Run CMake for Windows ──────────────────────────────────────────────────────
echo ""
echo "Configuring CMake for Windows (MinGW cross-compilation)..."
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

cmake "$ROOT" \
    -DCMAKE_TOOLCHAIN_FILE="$ROOT/cmake/MinGWToolchain.cmake" \
    -DCMAKE_BUILD_TYPE=Release \
    -DEPN_BUILD_TESTS=OFF \
    -DEPN_ENABLE_PQ_CRYPTO=OFF \
    2>&1 | tail -8

echo ""
echo "Building epn-win-client.exe..."
make -j"$(nproc)" epn-win-client 2>&1 | tail -6

EXE="$BUILD_DIR/apps/epn-win-client/epn-win-client.exe"
if [[ -f "$EXE" ]]; then
    SIZE=$(du -sh "$EXE" | cut -f1)
    echo ""
    echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  ✓ Build successful!                             ${NC}"
    echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
    echo ""
    echo "  Output:  $EXE"
    echo "  Size:    $SIZE"
    echo "  Type:    $(file "$EXE" | cut -d: -f2)"
    echo ""
    echo "Usage on Windows:"
    echo "  epn-win-client.exe socks    --disc-host <server> --disc-port 8000"
    echo "  epn-win-client.exe sysproxy --disc-host <server> --disc-port 8000"
    echo "  epn-win-client.exe wintun   --disc-host <server> --disc-port 8000 --gateway <gw>"
    echo "  epn-win-client.exe status"
else
    echo -e "${RED}Build failed — check output above${NC}"
    exit 1
fi
