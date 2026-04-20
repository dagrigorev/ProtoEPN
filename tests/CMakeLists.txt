add_executable(epn-tests
    test_crypto.cpp
    test_protocol.cpp
    test_routing.cpp
)

target_link_libraries(epn-tests PRIVATE
    epn-core epn-crypto epn-protocol
    epn-discovery epn-observability
    spdlog::spdlog
    nlohmann_json::nlohmann_json
    sodium
    GTest::gtest
    GTest::gtest_main
)

target_compile_features(epn-tests PRIVATE cxx_std_20)
epn_set_compiler_options(epn-tests)

include(GoogleTest)
gtest_discover_tests(epn-tests)
