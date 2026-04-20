add_executable(epn-client main.cpp)

target_link_libraries(epn-client PRIVATE
    epn-core epn-crypto epn-protocol
    epn-transport epn-discovery epn-routing epn-observability
    asio spdlog::spdlog nlohmann_json::nlohmann_json
    CLI11::CLI11 sodium
)

epn_set_compiler_options(epn-client)
