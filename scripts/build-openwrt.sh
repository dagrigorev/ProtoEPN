#!/usr/bin/env bash
# Build EPN OpenWrt packages with the official OpenWrt SDK.

set -euo pipefail

OPENWRT_VERSION="${OPENWRT_VERSION:-24.10.6}"
OPENWRT_TARGET="${OPENWRT_TARGET:-mediatek/filogic}"
OPENWRT_ARCH="${OPENWRT_ARCH:-aarch64_cortex-a53}"
BUILD_ROOT="${BUILD_ROOT:-${TMPDIR:-/tmp}/epn-openwrt-sdk}"
REPO_ROOT="$(pwd)"
PACKAGE_VERSION="${EPN_PACKAGE_VERSION:-${GITHUB_REF_NAME:-0.1.0}}"
PACKAGE_VERSION="${PACKAGE_VERSION#v}"

TARGET_DASH="${OPENWRT_TARGET//\//-}"
TARGET_URL="https://downloads.openwrt.org/releases/${OPENWRT_VERSION}/targets/${OPENWRT_TARGET}/"

have() { command -v "$1" >/dev/null 2>&1; }

if ! have curl || ! have tar || ! have make; then
  echo "curl, tar and make are required" >&2
  exit 1
fi

mkdir -p "${BUILD_ROOT}"

echo "Discovering OpenWrt SDK from ${TARGET_URL}"
SDK_NAME="$(
  curl -fsSL "${TARGET_URL}" |
    grep -o "openwrt-sdk-${OPENWRT_VERSION}-${TARGET_DASH}[^\"<> ]*Linux-x86_64\\.tar\\.zst" |
    head -n1 || true
)"

if [[ -z "${SDK_NAME}" ]]; then
  echo "Could not find OpenWrt SDK for ${OPENWRT_VERSION}/${OPENWRT_TARGET}" >&2
  exit 1
fi

SDK_ARCHIVE="${BUILD_ROOT}/${SDK_NAME}"
SDK_DIR="${BUILD_ROOT}/${SDK_NAME%.tar.zst}"

if [[ ! -f "${SDK_ARCHIVE}" ]]; then
  echo "Downloading ${SDK_NAME}"
  curl -fL "${TARGET_URL}${SDK_NAME}" -o "${SDK_ARCHIVE}"
fi

rm -rf "${SDK_DIR}"
tar -C "${BUILD_ROOT}" -xf "${SDK_ARCHIVE}"

if [[ ! -d "${SDK_DIR}" ]]; then
  SDK_DIR="$(find "${BUILD_ROOT}" -maxdepth 1 -type d -name "openwrt-sdk-${OPENWRT_VERSION}-${TARGET_DASH}*" | head -n1)"
fi

if [[ -z "${SDK_DIR}" || ! -d "${SDK_DIR}" ]]; then
  echo "OpenWrt SDK extraction failed" >&2
  exit 1
fi

rm -rf "${SDK_DIR}/package/epn"
mkdir -p "${SDK_DIR}/package/epn"
cp -a openwrt/package/epn/. "${SDK_DIR}/package/epn/"
sed -i "s/^PKG_VERSION:=.*/PKG_VERSION:=${PACKAGE_VERSION}/" "${SDK_DIR}/package/epn/Makefile"

(
  cd "${SDK_DIR}"
  ./scripts/feeds update packages
  ./scripts/feeds install libsodium
  make defconfig
  make package/epn/clean EPN_SOURCE_DIR="${REPO_ROOT}" V=s
  make package/epn/compile EPN_SOURCE_DIR="${REPO_ROOT}" V=s
)

DIST_DIR="${REPO_ROOT}/dist/epn-openwrt-${OPENWRT_ARCH}"
rm -rf "${DIST_DIR}"
mkdir -p "${DIST_DIR}"

find "${SDK_DIR}/bin/packages/${OPENWRT_ARCH}" \
  \( -name "epn_*.ipk" -o -name "luci-app-epn_*.ipk" \) \
  -exec cp {} "${DIST_DIR}/" \;

cp "${REPO_ROOT}/openwrt/README.md" "${DIST_DIR}/README-OPENWRT.md"

if ! find "${DIST_DIR}" -name "*.ipk" | grep -q .; then
  echo "OpenWrt packages were not produced" >&2
  exit 1
fi

tar -C "${REPO_ROOT}/dist" -czf "${REPO_ROOT}/epn-openwrt-${OPENWRT_ARCH}-${GITHUB_REF_NAME:-v${PACKAGE_VERSION}}.tar.gz" "epn-openwrt-${OPENWRT_ARCH}"
