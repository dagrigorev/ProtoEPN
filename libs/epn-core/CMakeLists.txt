add_library(epn-core INTERFACE)
target_include_directories(epn-core INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_compile_features(epn-core INTERFACE cxx_std_20)
