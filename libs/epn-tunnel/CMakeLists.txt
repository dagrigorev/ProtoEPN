add_library(epn-tunnel INTERFACE)

target_include_directories(epn-tunnel INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(epn-tunnel INTERFACE epn-core epn-crypto)
