# OpenWrt package

This directory contains an OpenWrt package feed for the EPN router client and a
minimal LuCI configuration page.

The target architecture requested for router builds is `aarch64_cortex-a53`.
Use the matching OpenWrt SDK for your device target. For example, if your
firmware target is `mediatek/filogic`, download the `aarch64_cortex-a53` SDK
for the same OpenWrt release as the router firmware.

## Build with OpenWrt SDK

```sh
cd openwrt-sdk-*
mkdir -p package/epn
cp -a /path/to/ProtoEPN/openwrt/package/epn/* package/epn/
./scripts/feeds update packages
./scripts/feeds install libsodium
make package/epn/clean V=s
make package/epn/compile V=s
```

For local development without cloning from GitHub during the SDK build:

```sh
make package/epn/clean EPN_SOURCE_DIR=/path/to/ProtoEPN V=s
make package/epn/compile EPN_SOURCE_DIR=/path/to/ProtoEPN V=s
```

The resulting packages are written under `bin/packages/aarch64_cortex-a53/`.

## Install on router

```sh
opkg update
opkg install luci-base rpcd rpcd-mod-file
opkg install epn_*.ipk luci-app-epn_*.ipk
/etc/init.d/rpcd restart
/etc/init.d/uhttpd restart
```

Then open LuCI: `Services -> EPN`.

Minimal CLI configuration:

```sh
uci set epn.main.enabled='1'
uci set epn.main.disc_host='YOUR_SERVER_IP'
uci set epn.main.disc_port='8000'
uci set epn.main.socks_bind='0.0.0.0'
uci set epn.main.socks_port='1080'
uci commit epn
/etc/init.d/epn enable
/etc/init.d/epn restart
```

Test from a LAN client:

```sh
curl --socks5-hostname ROUTER_LAN_IP:1080 https://api.ipify.org
```

The LuCI page can also ping the configured discovery endpoint.
