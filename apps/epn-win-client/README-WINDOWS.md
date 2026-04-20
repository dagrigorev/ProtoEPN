# EPN Windows Client

`epn-win-client.exe` — single statically-linked executable, no installer required.

## System Requirements

- Windows 10 / Windows 11 (x86-64)
- No .NET, no VC++ redistributables
- Required DLLs (all pre-installed on every Windows system):
  `ADVAPI32.dll`, `KERNEL32.dll`, `MSWSOCK.dll`, `USER32.dll`, `WS2_32.dll`, `msvcrt.dll`, `ole32.dll`

---

## Modes

### Mode 1 — SOCKS5 (no admin rights required)

Starts a local SOCKS5 proxy. Configure your applications manually.

```
epn-win-client.exe socks --disc-host SERVER_IP --disc-port 8000
```

Then configure apps:

| App | Setting |
|-----|---------|
| **Chrome** | `chrome.exe --proxy-server="socks5://127.0.0.1:1080"` |
| **Firefox** | Settings → Network → Manual proxy → SOCKS5: `127.0.0.1:1080` |
| **curl** | `curl --socks5 127.0.0.1:1080 https://example.com` |
| **Git** | `git config --global http.proxy socks5://127.0.0.1:1080` |
| **PowerShell** | `$env:ALL_PROXY="socks5://127.0.0.1:1080"` |
| **Python** | `requests.get(url, proxies={"https":"socks5://127.0.0.1:1080"})` |

---

### Mode 2 — System Proxy (no admin rights required)

Sets the Windows-wide SOCKS5 proxy in the registry. All applications that respect
the Windows system proxy are tunneled automatically — **browsers, WinHTTP, curl, PowerShell,
Windows Update, Store apps, etc.**

```
epn-win-client.exe sysproxy --disc-host SERVER_IP --disc-port 8000
```

On exit (Ctrl+C), the system proxy is automatically restored.

What gets tunneled:
- ✅ Chrome, Edge, Internet Explorer
- ✅ Firefox (uses system proxy by default)
- ✅ curl (Windows build)
- ✅ PowerShell `Invoke-WebRequest` / `Invoke-RestMethod`
- ✅ Windows Update (via WinHTTP)
- ✅ Any app using WinHTTP or WinInet

Bypassed (always direct):
- `localhost`, `127.*`, `10.*`, `172.16-31.*`, `192.168.*`, `<local>`

---

### Mode 3 — WinTun Full VPN (requires Administrator + wintun.dll)

Creates a virtual TUN network adapter. **All TCP traffic is transparently tunneled**
through EPN — no per-application configuration at all.

**Setup:**

1. Download `wintun.dll` from [wintun.net](https://www.wintun.net/) (free, MIT license)
2. Place `wintun.dll` next to `epn-win-client.exe`
3. Run as Administrator:

```
epn-win-client.exe wintun ^
    --disc-host SERVER_IP ^
    --disc-port 8000 ^
    --gateway YOUR_DEFAULT_GATEWAY_IP ^
    --relay-ip RELAY1_IP ^
    --relay-ip RELAY2_IP ^
    --relay-ip RELAY3_IP
```

Replace `YOUR_DEFAULT_GATEWAY_IP` with your router's IP (e.g. `192.168.1.1`).
The `--relay-ip` entries prevent the EPN tunnel's own traffic from being re-intercepted.

To find your gateway:
```
ipconfig | findstr "Default Gateway"
```

What gets tunneled in WinTun mode:
- ✅ **All TCP traffic** from all applications — no configuration needed
- ❌ UDP is NOT tunneled (DNS, QUIC, etc.)
- ❌ ICMP (ping) is NOT tunneled

DNS leak prevention: set a custom DNS server (e.g. `1.1.1.1`) to prevent DNS leaks
via your ISP's resolver while using WinTun mode.

---

### Status

Show current proxy configuration:

```
epn-win-client.exe status
```

---

## Server-Side Setup

The server infrastructure runs on Linux. Start in this order:

```bash
# Discovery server (can be on a public VPS)
./epn-discovery --port 8000

# Relay nodes (can be on same or different machines)
./epn-relay --port 9001 --disc-port 8000 --bind 0.0.0.0
./epn-relay --port 9002 --disc-port 8000 --bind 0.0.0.0
./epn-relay --port 9003 --disc-port 8000 --bind 0.0.0.0

# Tunnel exit node (TCP proxy to real internet)
./epn-tun-server --port 9200 --disc-port 8000 --bind 0.0.0.0
```

All nodes should have `--bind 0.0.0.0` for external accessibility.
Firewall: open ports 8000, 9001-9003, 9200 (TCP inbound).

---

## Quick Start

```
# On server (Linux):
./epn-discovery --port 8000 &
./epn-relay --port 9001 --disc-port 8000 --bind 0.0.0.0 &
./epn-relay --port 9002 --disc-port 8000 --bind 0.0.0.0 &
./epn-relay --port 9003 --disc-port 8000 --bind 0.0.0.0 &
./epn-tun-server --port 9200 --disc-port 8000 --bind 0.0.0.0 &

# On Windows client:
epn-win-client.exe sysproxy --disc-host YOUR.SERVER.IP --disc-port 8000
```

---

## Security Notes

- Relay nodes see only encrypted ciphertext — they do not know the source or destination
- All traffic is end-to-end encrypted with ChaCha20-Poly1305 + X25519 key exchange
- Fresh ephemeral keys are generated per session — no long-term encryption keys
- The tunnel server (`epn-tun-server`) can see the destination of your connections
  (it acts as the TCP proxy), but not your identity
- For maximum anonymity, run your own relay nodes and tunnel server

---

## Troubleshooting

**"Cannot establish EPN tunnel"**
- Verify the discovery server is reachable: `curl http://SERVER_IP:8000`
- Check Windows Firewall is not blocking outbound connections
- Try `--relays 2` if only 2 relay nodes are running

**System proxy not working after restart**
- Run with `sysproxy` mode again — the proxy setting is removed on clean exit
- Or manually set in: Settings → Network → Proxy

**WinTun mode: "wintun.dll not found"**
- Download from wintun.net and place in the same folder as the .exe

**WinTun mode: "Cannot create WinTun adapter"**
- Run as Administrator (right-click → Run as administrator)
