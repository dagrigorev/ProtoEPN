cmake_minimum_required(VERSION 3.20)

# ─── Windows resource file ────────────────────────────────────────────────────
if(WIN32)
    set(WIN_RESOURCES epn-win.rc)
    enable_language(RC)
endif()

add_executable(epn-win-client
    main.cpp
    ${WIN_RESOURCES}
)

# ─── Include paths ────────────────────────────────────────────────────────────
target_include_directories(epn-win-client PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# ─── Compile definitions ─────────────────────────────────────────────────────
target_compile_definitions(epn-win-client PRIVATE
    _WIN32_WINNT=0x0A00    # Windows 10+
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    ASIO_STANDALONE
    ASIO_NO_DEPRECATED
    _WINSOCK_DEPRECATED_NO_WARNINGS
)

# ─── EPN library dependencies ─────────────────────────────────────────────────
target_link_libraries(epn-win-client PRIVATE
    epn-core
    epn-crypto
    epn-protocol
    epn-tunnel
    epn-discovery
    epn-routing
    epn-observability
    asio
    spdlog::spdlog
    nlohmann_json::nlohmann_json
    CLI11::CLI11
)

# ─── Windows-specific system libraries ───────────────────────────────────────
if(WIN32)
    target_link_libraries(epn-win-client PRIVATE
        ws2_32      # Winsock2
        iphlpapi    # IP Helper API (routing table)
        advapi32    # Registry functions
        user32      # SendMessageTimeout (proxy broadcast)
        ole32       # CoCreateGuid (WinTun GUID)
        shell32     # ShellAPI
        mswsock     # AcceptEx, ConnectEx (Winsock extensions)
    )
endif()

# ─── libsodium ────────────────────────────────────────────────────────────────
if(CMAKE_CROSSCOMPILING AND CMAKE_SYSTEM_NAME STREQUAL "Windows")
    # Use cross-compiled libsodium for Windows/MinGW
    find_library(SODIUM_WIN_LIB
        NAMES sodium
        PATHS /usr/x86_64-w64-mingw32/lib
        NO_DEFAULT_PATH
    )
    if(SODIUM_WIN_LIB)
        target_link_libraries(epn-win-client PRIVATE ${SODIUM_WIN_LIB})
        target_include_directories(epn-win-client PRIVATE /usr/x86_64-w64-mingw32/include)
    else()
        message(FATAL_ERROR "libsodium for Windows/MinGW not found at /usr/x86_64-w64-mingw32/lib")
    endif()
else()
    # Native Windows build — use system libsodium or vcpkg
    target_link_libraries(epn-win-client PRIVATE sodium)
endif()

# ─── Static linking for Windows (single .exe, no DLL dependencies) ────────────
if(MINGW OR CMAKE_CROSSCOMPILING)
    target_link_options(epn-win-client PRIVATE
        -static-libgcc
        -static-libstdc++
        -static
        -Wl,--subsystem,console
    )
    # Strip release builds
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        target_link_options(epn-win-client PRIVATE -s)
    endif()
endif()

# ─── Output name ─────────────────────────────────────────────────────────────
set_target_properties(epn-win-client PROPERTIES
    OUTPUT_NAME "epn-win-client"
)

target_compile_features(epn-win-client PRIVATE cxx_std_20)
