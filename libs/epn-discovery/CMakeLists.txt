add_library(epn-discovery STATIC
    src/announcement.cpp
    src/client.cpp
)

target_include_directories(epn-discovery
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(epn-discovery
    PUBLIC
        epn-core
        epn-crypto
        epn-transport
        epn-observability
        nlohmann_json::nlohmann_json
        asio
    PRIVATE
        sodium
)

target_compile_features(epn-discovery PUBLIC cxx_std_20)
epn_set_compiler_options(epn-discovery)
