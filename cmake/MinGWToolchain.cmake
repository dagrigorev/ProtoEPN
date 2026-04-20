# MinGW-w64 cross-compilation toolchain: Linux → Windows x86_64

set(CMAKE_SYSTEM_NAME     Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

set(MINGW_PREFIX "x86_64-w64-mingw32")
set(MINGW_SYSROOT "/usr/${MINGW_PREFIX}")

set(CMAKE_C_COMPILER   "${MINGW_PREFIX}-gcc-posix")
set(CMAKE_CXX_COMPILER "${MINGW_PREFIX}-g++-posix")
set(CMAKE_RC_COMPILER  "${MINGW_PREFIX}-windres")
set(CMAKE_AR           "${MINGW_PREFIX}-ar")
set(CMAKE_RANLIB       "${MINGW_PREFIX}-ranlib")
set(CMAKE_STRIP        "${MINGW_PREFIX}-strip")

# Sysroot: ONLY use MinGW headers, never Linux system headers
set(CMAKE_SYSROOT ${MINGW_SYSROOT})
set(CMAKE_FIND_ROOT_PATH ${MINGW_SYSROOT})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# Force compiler to NOT look in Linux include dirs
set(CMAKE_C_IMPLICIT_INCLUDE_DIRECTORIES   "")
set(CMAKE_CXX_IMPLICIT_INCLUDE_DIRECTORIES "")

# Windows compile flags
set(CMAKE_C_FLAGS_INIT
    "--sysroot=${MINGW_SYSROOT} -D_WIN32_WINNT=0x0A00 -DWIN32_LEAN_AND_MEAN -DNOMINMAX")
set(CMAKE_CXX_FLAGS_INIT
    "--sysroot=${MINGW_SYSROOT} -D_WIN32_WINNT=0x0A00 -DWIN32_LEAN_AND_MEAN -DNOMINMAX")

# Static link everything into one .exe
set(CMAKE_EXE_LINKER_FLAGS_INIT
    "-static -static-libgcc -static-libstdc++ -Wl,--subsystem,console")

set(CMAKE_EXECUTABLE_SUFFIX ".exe")

# Use cross-pkg-config so sodium resolves to MinGW version
set(ENV{PKG_CONFIG_PATH} "/usr/x86_64-w64-mingw32/lib/pkgconfig")
set(ENV{PKG_CONFIG_LIBDIR} "/usr/x86_64-w64-mingw32/lib/pkgconfig")
set(ENV{PKG_CONFIG_SYSROOT_DIR} "/usr/x86_64-w64-mingw32")
set(PKG_CONFIG_EXECUTABLE /usr/local/bin/x86_64-w64-mingw32-pkg-config)
