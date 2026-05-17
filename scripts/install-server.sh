#!/usr/bin/env bash
# Install and run EPN server-side infrastructure on a Linux VPS.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/<owner>/<repo>/main/scripts/install-server.sh | sudo bash
#
# Optional environment:
#   EPN_REPO=dagrigorev/ProtoEPN
#   EPN_VERSION=v0.1.0        # release tag; default: latest release
#   EPN_DOMAIN=epn.example.com
#   EPN_DISC_PORT=8000
#   EPN_RELAY_PORTS="9001 9002 9003"
#   EPN_TUN_PORT=9200
#   EPN_BUILD_FROM_SOURCE=1   # force source build instead of release asset

set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "This installer must run as root. Re-run with sudo." >&2
  exit 1
fi

EPN_REPO="${EPN_REPO:-}"
EPN_VERSION="${EPN_VERSION:-latest}"
EPN_DOMAIN="${EPN_DOMAIN:-}"
EPN_DISC_PORT="${EPN_DISC_PORT:-8000}"
EPN_RELAY_PORTS="${EPN_RELAY_PORTS:-9001 9002 9003}"
EPN_TUN_PORT="${EPN_TUN_PORT:-9200}"
EPN_HOME="${EPN_HOME:-/opt/epn}"
EPN_USER="${EPN_USER:-epn}"
EPN_BUILD_FROM_SOURCE="${EPN_BUILD_FROM_SOURCE:-0}"

have() { command -v "$1" >/dev/null 2>&1; }

detect_repo() {
  if [[ -n "${EPN_REPO}" ]]; then return; fi
  if [[ "${BASH_SOURCE[0]}" =~ githubusercontent\.com/([^/]+/[^/]+)/ ]]; then
    EPN_REPO="${BASH_REMATCH[1]}"
    return
  fi
  EPN_REPO="dagrigorev/ProtoEPN"
}

install_deps() {
  if have apt-get; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
      ca-certificates curl tar unzip cmake g++ make git pkg-config libsodium-dev
  elif have dnf; then
    dnf install -y ca-certificates curl tar unzip cmake gcc-c++ make git pkgconf-pkg-config libsodium-devel
  elif have yum; then
    yum install -y ca-certificates curl tar unzip cmake gcc-c++ make git pkgconfig libsodium-devel
  else
    echo "Unsupported distro: install curl, tar, cmake, g++, make, git, pkg-config, libsodium-dev manually." >&2
    exit 1
  fi
}

public_host() {
  if [[ -n "${EPN_DOMAIN}" ]]; then
    echo "${EPN_DOMAIN}"
    return
  fi
  curl -fsS --max-time 5 https://api.ipify.org || hostname -I | awk '{print $1}'
}

latest_tag() {
  curl -fsS "https://api.github.com/repos/${EPN_REPO}/releases/latest" |
    sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' |
    head -n1
}

download_release() {
  local tag="$1"
  local asset="epn-server-linux-x86_64-${tag}.tar.gz"
  local url="https://github.com/${EPN_REPO}/releases/download/${tag}/${asset}"

  mkdir -p "${EPN_HOME}"
  echo "Downloading ${url}"
  curl -fL "${url}" -o "/tmp/${asset}"
  tar -xzf "/tmp/${asset}" -C /tmp
  install -d "${EPN_HOME}/bin" "${EPN_HOME}/scripts"
  install -m 0755 /tmp/epn-server-linux-x86_64/bin/* "${EPN_HOME}/bin/"
  if [[ -d /tmp/epn-server-linux-x86_64/scripts ]]; then
    install -m 0755 /tmp/epn-server-linux-x86_64/scripts/* "${EPN_HOME}/scripts/" || true
  fi
}

build_from_source() {
  local tag="$1"
  local src="/tmp/epn-src"
  rm -rf "${src}"
  git clone "https://github.com/${EPN_REPO}.git" "${src}"
  if [[ "${tag}" != "latest" && -n "${tag}" ]]; then
    git -C "${src}" checkout "${tag}"
  fi
  cmake -S "${src}" -B "${src}/build" -DCMAKE_BUILD_TYPE=Release -DEPN_BUILD_TESTS=OFF
  cmake --build "${src}/build" --parallel

  install -d "${EPN_HOME}/bin" "${EPN_HOME}/scripts"
  install -m 0755 "${src}/build/apps/epn-discovery/epn-discovery" "${EPN_HOME}/bin/"
  install -m 0755 "${src}/build/apps/epn-relay/epn-relay" "${EPN_HOME}/bin/"
  install -m 0755 "${src}/build/apps/epn-tun-server/epn-tun-server" "${EPN_HOME}/bin/"
  install -m 0755 "${src}/scripts/"*.sh "${EPN_HOME}/scripts/" || true
}

validate_installed_binaries() {
  local bins=(epn-discovery epn-relay epn-tun-server)
  local bin
  for bin in "${bins[@]}"; do
    if ! "${EPN_HOME}/bin/${bin}" --help >/dev/null 2>&1; then
      echo "Installed ${bin} cannot run on this host." >&2
      return 1
    fi
  done
}

write_service() {
  local name="$1"
  local exec_line="$2"
  cat >"/etc/systemd/system/${name}.service" <<EOF
[Unit]
Description=${name}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${EPN_USER}
Group=${EPN_USER}
ExecStart=${exec_line}
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=${EPN_HOME}

[Install]
WantedBy=multi-user.target
EOF
}

configure_systemd() {
  local host="$1"

  if ! id -u "${EPN_USER}" >/dev/null 2>&1; then
    useradd --system --home "${EPN_HOME}" --shell /usr/sbin/nologin "${EPN_USER}"
  fi
  chown -R "${EPN_USER}:${EPN_USER}" "${EPN_HOME}"

  write_service "epn-discovery" \
    "${EPN_HOME}/bin/epn-discovery --port ${EPN_DISC_PORT}"

  local idx=1
  for port in ${EPN_RELAY_PORTS}; do
    write_service "epn-relay-${idx}" \
      "${EPN_HOME}/bin/epn-relay --port ${port} --disc-host 127.0.0.1 --disc-port ${EPN_DISC_PORT} --bind ${host}"
    idx=$((idx + 1))
  done

  write_service "epn-tun-server" \
    "${EPN_HOME}/bin/epn-tun-server --port ${EPN_TUN_PORT} --disc-host 127.0.0.1 --disc-port ${EPN_DISC_PORT} --bind ${host}"

  systemctl daemon-reload
  systemctl enable --now epn-discovery
  sleep 1
  idx=1
  for _port in ${EPN_RELAY_PORTS}; do
    systemctl enable --now "epn-relay-${idx}"
    idx=$((idx + 1))
  done
  systemctl enable --now epn-tun-server
}

check_services() {
  local services=(epn-discovery)
  local idx=1
  for _port in ${EPN_RELAY_PORTS}; do
    services+=("epn-relay-${idx}")
    idx=$((idx + 1))
  done
  services+=(epn-tun-server)

  sleep 3
  local failed=()
  for service in "${services[@]}"; do
    if ! systemctl is-active --quiet "${service}"; then
      failed+=("${service}")
    fi
  done

  if [[ "${#failed[@]}" -gt 0 ]]; then
    echo "EPN service startup failed: ${failed[*]}" >&2
    echo "" >&2
    systemctl status "${failed[@]}" --no-pager >&2 || true
    echo "" >&2
    journalctl -u "${failed[@]}" -n 80 --no-pager >&2 || true
    exit 1
  fi
}

print_summary() {
  local host="$1"
  local tag="$2"
  local linux_client_asset="epn-client-linux-x86_64-${tag}.tar.gz"
  local linux_client_url="https://github.com/${EPN_REPO}/releases/download/${tag}/${linux_client_asset}"
  local win_asset="epn-windows-gui-x86_64-${tag}.zip"
  local win_url="https://github.com/${EPN_REPO}/releases/download/${tag}/${win_asset}"
  local openwrt_asset="epn-openwrt-aarch64_cortex-a53-${tag}.tar.gz"
  local openwrt_url="https://github.com/${EPN_REPO}/releases/download/${tag}/${openwrt_asset}"

  cat <<EOF

EPN server is running.

Public endpoint:
  Discovery: ${host}:${EPN_DISC_PORT}
  Relays:    $(for p in ${EPN_RELAY_PORTS}; do printf "%s:%s " "${host}" "${p}"; done)
  Exit:      ${host}:${EPN_TUN_PORT}

Linux client example:
  Download: ${linux_client_url}
  epn-tun-client --disc-host ${host} --disc-port ${EPN_DISC_PORT} --socks-port 1080
  curl --socks5 127.0.0.1:1080 https://example.com

Windows client:
  Download: ${win_url}
  Run:      epn-windows-gui.exe

OpenWrt client:
  Download: ${openwrt_url}
  Configure discovery endpoint: ${host}:${EPN_DISC_PORT}

Firewall ports to allow inbound TCP:
  ${EPN_DISC_PORT} ${EPN_RELAY_PORTS} ${EPN_TUN_PORT}

Services:
  systemctl status epn-discovery
  systemctl status epn-relay-1 epn-relay-2 epn-relay-3
  systemctl status epn-tun-server

EOF
}

main() {
  detect_repo
  install_deps

  local tag="${EPN_VERSION}"
  if [[ "${tag}" == "latest" ]]; then
    tag="$(latest_tag || true)"
  fi

  if [[ -z "${tag}" ]]; then
    echo "No release tag found; falling back to source build from main."
    tag="main"
    EPN_BUILD_FROM_SOURCE=1
  fi

  if [[ "${EPN_BUILD_FROM_SOURCE}" == "1" || "${tag}" == "main" ]]; then
    build_from_source "${tag}"
  else
    if ! download_release "${tag}" || ! validate_installed_binaries; then
      echo "Release asset is unavailable or incompatible with this host; building from source instead."
      build_from_source "${tag}"
    fi
  fi

  local host
  host="$(public_host)"
  configure_systemd "${host}"
  check_services
  print_summary "${host}" "${tag}"
}

main "$@"
