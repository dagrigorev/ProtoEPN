include(FetchContent)
set(FETCHCONTENT_QUIET ON)

# ─── libsodium (system) ──────────────────────────────────────────────────────
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

# Use find_library to get the actual .so path — avoids circular target ref
find_library(SODIUM_LIB_PATH NAMES sodium REQUIRED)

add_library(sodium INTERFACE)
target_include_directories(sodium INTERFACE ${SODIUM_INCLUDE_DIRS})
target_link_libraries(sodium INTERFACE ${SODIUM_LIB_PATH})

# ─── Standalone Asio (header-only) ───────────────────────────────────────────
FetchContent_Declare(
  asio
  GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
  GIT_TAG        asio-1-28-2
  GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(asio)

add_library(asio INTERFACE)
target_include_directories(asio INTERFACE ${asio_SOURCE_DIR}/asio/include)
target_compile_definitions(asio INTERFACE
  ASIO_STANDALONE
  ASIO_NO_DEPRECATED
)
target_link_libraries(asio INTERFACE pthread)

# ─── spdlog ──────────────────────────────────────────────────────────────────
FetchContent_Declare(
  spdlog
  GIT_REPOSITORY https://github.com/gabime/spdlog.git
  GIT_TAG        v1.13.0
  GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(spdlog)

# ─── nlohmann/json ───────────────────────────────────────────────────────────
FetchContent_Declare(
  nlohmann_json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG        v3.11.3
  GIT_SHALLOW    TRUE
)
set(JSON_BuildTests OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(nlohmann_json)

# ─── CLI11 ───────────────────────────────────────────────────────────────────
FetchContent_Declare(
  CLI11
  GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
  GIT_TAG        v2.4.1
  GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(CLI11)

# ─── GoogleTest ──────────────────────────────────────────────────────────────
if(EPN_BUILD_TESTS)
  FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.14.0
    GIT_SHALLOW    TRUE
  )
  set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(googletest)
endif()

# ─── liboqs (post-quantum, optional) ─────────────────────────────────────────
if(EPN_ENABLE_PQ_CRYPTO)
  find_library(OQS_LIBRARY oqs)
  find_path(OQS_INCLUDE_DIR oqs/oqs.h)
  if(OQS_LIBRARY AND OQS_INCLUDE_DIR)
    add_library(liboqs INTERFACE)
    target_include_directories(liboqs INTERFACE ${OQS_INCLUDE_DIR})
    target_link_libraries(liboqs INTERFACE ${OQS_LIBRARY})
    add_compile_definitions(EPN_ENABLE_PQ_CRYPTO)
    message(STATUS "Post-quantum crypto: enabled (liboqs found)")
  else()
    message(WARNING "EPN_ENABLE_PQ_CRYPTO requested but liboqs not found. Disabling.")
    set(EPN_ENABLE_PQ_CRYPTO OFF)
  endif()
endif()
