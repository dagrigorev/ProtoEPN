add_library(epn-observability INTERFACE)

target_include_directories(epn-observability INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(epn-observability INTERFACE
    epn-core spdlog::spdlog
)
