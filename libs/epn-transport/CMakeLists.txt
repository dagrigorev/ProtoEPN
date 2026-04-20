add_library(epn-transport STATIC
    src/connection.cpp
)

target_include_directories(epn-transport
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(epn-transport
    PUBLIC  epn-core epn-protocol epn-observability asio
)

target_compile_features(epn-transport PUBLIC cxx_std_20)
epn_set_compiler_options(epn-transport)
