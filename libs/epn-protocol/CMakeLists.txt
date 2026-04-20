add_library(epn-protocol STATIC
    src/framing.cpp
    src/onion.cpp
)

target_include_directories(epn-protocol
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(epn-protocol
    PUBLIC  epn-core epn-crypto
    PRIVATE sodium
)

target_compile_features(epn-protocol PUBLIC cxx_std_20)
epn_set_compiler_options(epn-protocol)
