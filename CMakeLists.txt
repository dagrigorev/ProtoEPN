cmake_minimum_required(VERSION 3.20)
project(EPN VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Build type
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

option(EPN_ENABLE_PQ_CRYPTO "Enable post-quantum hybrid crypto (requires liboqs)" OFF)
option(EPN_BUILD_TESTS "Build tests" ON)
option(EPN_SANITIZE "Enable address/undefined sanitizers" OFF)

include(cmake/Dependencies.cmake)
include(cmake/CompilerOptions.cmake)

# Libraries
add_subdirectory(libs/epn-core)
add_subdirectory(libs/epn-observability)
add_subdirectory(libs/epn-crypto)
add_subdirectory(libs/epn-protocol)
add_subdirectory(libs/epn-transport)
add_subdirectory(libs/epn-discovery)
add_subdirectory(libs/epn-routing)
add_subdirectory(libs/epn-tunnel)

# Applications
add_subdirectory(apps/epn-discovery)
add_subdirectory(apps/epn-relay)
add_subdirectory(apps/epn-server)
add_subdirectory(apps/epn-client)
add_subdirectory(apps/epn-tun-server)
add_subdirectory(apps/epn-tun-client)
add_subdirectory(apps/epn-tun-dev)

# Windows cross-compiled client
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  add_subdirectory(apps/epn-win-client)
endif()

# Tests
if(EPN_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
