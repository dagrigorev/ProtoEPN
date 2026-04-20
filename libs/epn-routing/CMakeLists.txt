add_library(epn-routing STATIC
    src/route.cpp
)

target_include_directories(epn-routing
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(epn-routing
    PUBLIC
        epn-core
        epn-crypto
        epn-protocol
        epn-discovery
        epn-observability
)

target_compile_features(epn-routing PUBLIC cxx_std_20)
epn_set_compiler_options(epn-routing)
