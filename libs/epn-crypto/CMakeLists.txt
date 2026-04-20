add_library(epn-crypto STATIC
    src/keys.cpp
    src/kdf.cpp
    src/aead.cpp
    src/signing.cpp
)

target_include_directories(epn-crypto
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(epn-crypto
    PUBLIC  epn-core
    PRIVATE sodium
)

target_compile_features(epn-crypto PUBLIC cxx_std_20)
epn_set_compiler_options(epn-crypto)

if(EPN_ENABLE_PQ_CRYPTO)
    target_link_libraries(epn-crypto PRIVATE liboqs)
endif()
