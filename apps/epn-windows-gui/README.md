# EPN Windows GUI

Minimal WPF shell for `epn-win-client.exe`.

## Usage

1. Put `epn-windows-gui.exe` and `epn-win-client.exe` in the same directory.
2. Start `epn-windows-gui.exe`.
3. Enter an endpoint URL, for example `epn://127.0.0.1:8000`.
4. Click **Connect**.

The GUI starts `epn-win-client.exe socks`, waits until the tunnel is ready, and
then enables the Windows system SOCKS proxy. **Disconnect** disables the proxy.
Closing the window hides it to the tray; use the tray menu to reopen, disconnect,
or exit.

## Icon

The app icon is the Icons8 VPN icon:

https://icons8.com/icon/13059/vpn

Free Icons8 assets require attribution. Keep the bundled attribution file when
redistributing the app.
