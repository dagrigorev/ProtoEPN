using System.Runtime.InteropServices;
using System.IO;
using Microsoft.Win32;

namespace Epn.WindowsGui.Services;

public static class SystemProxy
{
    private const string InternetSettingsKey = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    private const int InternetOptionSettingsChanged = 39;
    private const int InternetOptionRefresh = 37;
    private static readonly string PacPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "EPN",
        "epn-proxy.pac");

    public static void EnableSocks(string host, int port)
    {
        EnablePac(host, port, allowDirectFallback: false);
    }

    public static void EnablePac(string host, int port, bool allowDirectFallback)
    {
        using var key = Registry.CurrentUser.OpenSubKey(InternetSettingsKey, writable: true)
            ?? throw new InvalidOperationException("Cannot open Windows Internet Settings registry key.");

        Directory.CreateDirectory(Path.GetDirectoryName(PacPath)!);
        File.WriteAllText(PacPath, BuildPac(host, port, allowDirectFallback));

        key.SetValue("ProxyEnable", 0, RegistryValueKind.DWord);
        key.DeleteValue("ProxyServer", throwOnMissingValue: false);
        key.DeleteValue("ProxyOverride", throwOnMissingValue: false);
        key.SetValue("AutoConfigURL", new Uri(PacPath).AbsoluteUri, RegistryValueKind.String);
        Refresh();
    }

    public static void Disable()
    {
        using var key = Registry.CurrentUser.OpenSubKey(InternetSettingsKey, writable: true);
        if (key is null)
        {
            return;
        }

        key.SetValue("ProxyEnable", 0, RegistryValueKind.DWord);
        key.DeleteValue("ProxyServer", throwOnMissingValue: false);
        key.DeleteValue("ProxyOverride", throwOnMissingValue: false);
        key.DeleteValue("AutoConfigURL", throwOnMissingValue: false);
        TryDeletePac();
        Refresh();
    }

    private static string BuildPac(string host, int port, bool allowDirectFallback)
    {
        var fallback = allowDirectFallback ? "; DIRECT" : string.Empty;
        return $$"""
function FindProxyForURL(url, host) {
  if (isPlainHostName(host) ||
      dnsDomainIs(host, ".local") ||
      shExpMatch(host, "localhost") ||
      shExpMatch(host, "127.*") ||
      shExpMatch(host, "10.*") ||
      shExpMatch(host, "192.168.*") ||
      shExpMatch(host, "172.16.*") ||
      shExpMatch(host, "172.17.*") ||
      shExpMatch(host, "172.18.*") ||
      shExpMatch(host, "172.19.*") ||
      shExpMatch(host, "172.20.*") ||
      shExpMatch(host, "172.21.*") ||
      shExpMatch(host, "172.22.*") ||
      shExpMatch(host, "172.23.*") ||
      shExpMatch(host, "172.24.*") ||
      shExpMatch(host, "172.25.*") ||
      shExpMatch(host, "172.26.*") ||
      shExpMatch(host, "172.27.*") ||
      shExpMatch(host, "172.28.*") ||
      shExpMatch(host, "172.29.*") ||
      shExpMatch(host, "172.30.*") ||
      shExpMatch(host, "172.31.*")) {
    return "DIRECT";
  }
  return "SOCKS5 {{host}}:{{port}}{{fallback}}";
}
""";
    }

    private static void TryDeletePac()
    {
        try
        {
            if (File.Exists(PacPath))
            {
                File.Delete(PacPath);
            }
        }
        catch
        {
            // The PAC file is disposable cache; leave it if another process is reading it.
        }
    }

    private static void Refresh()
    {
        InternetSetOption(IntPtr.Zero, InternetOptionSettingsChanged, IntPtr.Zero, 0);
        InternetSetOption(IntPtr.Zero, InternetOptionRefresh, IntPtr.Zero, 0);
    }

    [DllImport("wininet.dll", SetLastError = true)]
    private static extern bool InternetSetOption(IntPtr internet, int option, IntPtr buffer, int bufferLength);
}
