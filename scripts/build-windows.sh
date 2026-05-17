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
BUILD_DIR="${BUILD_DIR:-$ROOT/build-windows}"
DEPS_DIR="$ROOT/.deps/windows"
SODIUM_PREFIX="$DEPS_DIR/x86_64-w64-mingw32"
SODIUM_VERSION="${SODIUM_VERSION:-1.0.20}"

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
check_tool curl
check_tool tar
echo -e "Compiler: $(x86_64-w64-mingw32-g++-posix --version | head -1)"

# ── Build libsodium for Windows if not present ────────────────────────────────
SODIUM_WIN="$SODIUM_PREFIX/lib/libsodium.a"
if [[ ! -f "$SODIUM_WIN" ]]; then
    echo ""
    echo "Building libsodium $SODIUM_VERSION for Windows/MinGW..."
    mkdir -p "$SODIUM_PREFIX"
    SODIUM_SRC="/tmp/libsodium-$SODIUM_VERSION"
    SODIUM_TARBALL="/tmp/libsodium-$SODIUM_VERSION.tar.gz"
    if [[ ! -d "$SODIUM_SRC" ]]; then
        curl -fL --retry 5 --retry-delay 3 \
            "https://download.libsodium.org/libsodium/releases/libsodium-$SODIUM_VERSION.tar.gz" \
            -o "$SODIUM_TARBALL"
        tar -xzf "$SODIUM_TARBALL" -C /tmp
    fi
    cd "$SODIUM_SRC"
    [[ ! -f configure ]] && autoreconf -fi
    ./configure \
        --host=x86_64-w64-mingw32 \
        --prefix="$SODIUM_PREFIX" \
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
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

cmake "$ROOT" \
    -DCMAKE_TOOLCHAIN_FILE="$ROOT/cmake/MinGWToolchain.cmake" \
    -DCMAKE_BUILD_TYPE=Release \
    -DEPN_BUILD_TESTS=OFF \
    -DEPN_ENABLE_PQ_CRYPTO=OFF \
    -DSODIUM_INCLUDE_DIR="$SODIUM_PREFIX/include" \
    -DSODIUM_LIB_PATH="$SODIUM_WIN" \
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
    echo "  epn-win-client.exe cleanup"
else
    echo -e "${RED}Build failed — check output above${NC}"
    exit 1
fi
