#pragma once
// win_utils.hpp — Windows-specific EPN utilities

#ifndef _WIN32
#  error "This header is Windows-only"
#endif

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winreg.h>
#include <shellapi.h>

#include <cstdint>
#include <functional>
#include <string>
#include <memory>

// ─── Winsock RAII ─────────────────────────────────────────────────────────────
struct WinsockInit {
    bool ok{false};
    WinsockInit() {
        WSADATA d;
        ok = (WSAStartup(MAKEWORD(2,2), &d) == 0);
    }
    ~WinsockInit() { if (ok) WSACleanup(); }
};

// ─── System SOCKS5 proxy (Internet Settings registry) ─────────────────────────
namespace win_proxy {

constexpr LPCSTR REG_KEY =
    "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";

inline bool enable(const std::string& host, uint16_t port) {
    HKEY key;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, REG_KEY, 0, KEY_SET_VALUE, &key) != ERROR_SUCCESS)
        return false;
    std::string proxy = "socks=" + host + ":" + std::to_string(port);
    constexpr LPCSTR overrides =
        "localhost;127.*;10.*;172.16.*;192.168.*;<local>";
    DWORD enabled = 1;
    RegSetValueExA(key, "ProxyServer",   0, REG_SZ,
        reinterpret_cast<const BYTE*>(proxy.c_str()),
        static_cast<DWORD>(proxy.size() + 1));
    RegSetValueExA(key, "ProxyEnable",   0, REG_DWORD,
        reinterpret_cast<const BYTE*>(&enabled), sizeof(DWORD));
    RegSetValueExA(key, "ProxyOverride", 0, REG_SZ,
        reinterpret_cast<const BYTE*>(overrides),
        static_cast<DWORD>(strlen(overrides) + 1));
    RegCloseKey(key);
    DWORD_PTR result = 0;
    SendMessageTimeoutA(HWND_BROADCAST, WM_SETTINGCHANGE, 0,
        reinterpret_cast<LPARAM>("Internet Settings"),
        SMTO_ABORTIFHUNG, 2000, &result);
    return true;
}

inline bool disable() {
    HKEY key;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, REG_KEY, 0, KEY_SET_VALUE, &key) != ERROR_SUCCESS)
        return false;
    DWORD disabled = 0;
    RegSetValueExA(key, "ProxyEnable", 0, REG_DWORD,
        reinterpret_cast<const BYTE*>(&disabled), sizeof(DWORD));
    RegCloseKey(key);
    DWORD_PTR result = 0;
    SendMessageTimeoutA(HWND_BROADCAST, WM_SETTINGCHANGE, 0,
        reinterpret_cast<LPARAM>("Internet Settings"),
        SMTO_ABORTIFHUNG, 2000, &result);
    return true;
}

inline std::string current() {
    HKEY key;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, REG_KEY, 0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS)
        return "(registry error)";
    char buf[512] = {};
    DWORD len = sizeof(buf), type = 0;
    DWORD enabled = 0, elen = sizeof(DWORD), etype = REG_DWORD;
    RegQueryValueExA(key, "ProxyEnable", nullptr, &etype,
        reinterpret_cast<LPBYTE>(&enabled), &elen);
    RegQueryValueExA(key, "ProxyServer", nullptr, &type,
        reinterpret_cast<LPBYTE>(buf), &len);
    RegCloseKey(key);
    if (enabled && buf[0]) return std::string("ENABLED — ") + buf;
    return "DISABLED";
}

} // namespace win_proxy

// ─── WinTun virtual adapter ───────────────────────────────────────────────────
// Dynamic loading of wintun.dll at runtime.
// wintun.dll must be placed next to the executable.
// Download: https://www.wintun.net/
namespace wintun {

using WINTUN_ADAPTER_HANDLE = void*;
using WINTUN_SESSION_HANDLE  = void*;

// Function pointer types matching WinTun API
// Names match exactly: Fn + WinTun API function name (without "Wintun" prefix)
using FnCreateAdapter        = WINTUN_ADAPTER_HANDLE (WINAPI*)(LPCWSTR, LPCWSTR, const GUID*);
using FnOpenAdapter          = WINTUN_ADAPTER_HANDLE (WINAPI*)(LPCWSTR);
using FnCloseAdapter         = void                  (WINAPI*)(WINTUN_ADAPTER_HANDLE);
using FnDeleteAdapter        = BOOL                  (WINAPI*)(WINTUN_ADAPTER_HANDLE);
using FnGetAdapterLUID       = void                  (WINAPI*)(WINTUN_ADAPTER_HANDLE, LUID*);
using FnStartSession         = WINTUN_SESSION_HANDLE (WINAPI*)(WINTUN_ADAPTER_HANDLE, DWORD);
using FnEndSession           = void                  (WINAPI*)(WINTUN_SESSION_HANDLE);
using FnReceivePacket        = BYTE*                 (WINAPI*)(WINTUN_SESSION_HANDLE, DWORD*);
using FnReleaseReceivePacket = void                  (WINAPI*)(WINTUN_SESSION_HANDLE, BYTE*);
using FnAllocateSendPacket   = BYTE*                 (WINAPI*)(WINTUN_SESSION_HANDLE, DWORD);
using FnSendPacket           = void                  (WINAPI*)(WINTUN_SESSION_HANDLE, BYTE*);
using FnGetReadWaitEvent     = HANDLE                (WINAPI*)(WINTUN_SESSION_HANDLE);

struct WinTunApi {
    HMODULE               dll{nullptr};
    FnCreateAdapter       CreateAdapter{};
    FnOpenAdapter         OpenAdapter{};
    FnCloseAdapter        CloseAdapter{};
    FnDeleteAdapter       DeleteAdapter{};
    FnGetAdapterLUID      GetAdapterLUID{};
    FnStartSession        StartSession{};
    FnEndSession          EndSession{};
    FnReceivePacket       ReceivePacket{};
    FnReleaseReceivePacket ReleaseReceivePacket{};
    FnAllocateSendPacket  AllocateSendPacket{};
    FnSendPacket          SendPacket{};
    FnGetReadWaitEvent    GetReadWaitEvent{};
    bool loaded{false};

    bool load(LPCWSTR path = L"wintun.dll") {
        dll = LoadLibraryExW(path, nullptr,
            LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!dll) return false;
        // LOAD macro: FnXxx member = GetProcAddress(dll, "WintunXxx")
        #define WINTUN_LOAD(name) \
            name = reinterpret_cast<Fn##name>(GetProcAddress(dll, "Wintun" #name)); \
            if (!name) { FreeLibrary(dll); dll=nullptr; return false; }
        WINTUN_LOAD(CreateAdapter)  WINTUN_LOAD(OpenAdapter)
        WINTUN_LOAD(CloseAdapter)   WINTUN_LOAD(DeleteAdapter)
        WINTUN_LOAD(GetAdapterLUID) WINTUN_LOAD(StartSession)
        WINTUN_LOAD(EndSession)     WINTUN_LOAD(ReceivePacket)
        WINTUN_LOAD(ReleaseReceivePacket) WINTUN_LOAD(AllocateSendPacket)
        WINTUN_LOAD(SendPacket)     WINTUN_LOAD(GetReadWaitEvent)
        #undef WINTUN_LOAD
        loaded = true;
        return true;
    }

    ~WinTunApi() { if (dll) FreeLibrary(dll); }
};

inline WinTunApi& api() { static WinTunApi inst; return inst; }

inline bool set_adapter_ip(const std::wstring& name, const std::string& ip,
                            const std::string& mask = "255.255.255.0")
{
    char narrow[256];
    WideCharToMultiByte(CP_ACP, 0, name.c_str(), -1, narrow, sizeof(narrow), nullptr, nullptr);
    std::string cmd = "netsh interface ip set address \"" +
                      std::string(narrow) + "\" static " + ip + " " + mask;
    return system(cmd.c_str()) == 0;
}

inline bool add_bypass_route(const std::string& ip, const std::string& gw) {
    return system(("route add " + ip + "/32 " + gw).c_str()) == 0;
}
inline bool del_bypass_route(const std::string& ip) {
    return system(("route delete " + ip + "/32").c_str()) == 0;
}
inline bool set_default_route(const std::string& tun_ip) {
    return system(("route add 0.0.0.0 mask 0.0.0.0 " + tun_ip + " metric 1").c_str()) == 0;
}

} // namespace wintun

// ─── Ctrl+C handler ───────────────────────────────────────────────────────────
namespace win_ctrl {

static std::function<void()> g_shutdown_fn;

inline BOOL WINAPI ctrl_handler(DWORD ev) {
    if (ev == CTRL_C_EVENT || ev == CTRL_CLOSE_EVENT || ev == CTRL_SHUTDOWN_EVENT) {
        if (g_shutdown_fn) g_shutdown_fn();
        return TRUE;
    }
    return FALSE;
}

inline void install(std::function<void()> fn) {
    g_shutdown_fn = std::move(fn);
    SetConsoleCtrlHandler(ctrl_handler, TRUE);
}

} // namespace win_ctrl

// ─── Console colours ─────────────────────────────────────────────────────────
namespace win_con {
enum Color { DEFAULT=7, GREEN=10, CYAN=11, RED=12, YELLOW=14, WHITE=15 };

inline void set_color(Color c) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), static_cast<WORD>(c));
}
struct Colored {
    Color c;
    explicit Colored(Color col) : c(col) { set_color(col); }
    ~Colored() { set_color(DEFAULT); }
};
} // namespace win_con
