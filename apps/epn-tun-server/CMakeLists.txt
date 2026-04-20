add_executable(epn-tun-server main.cpp)

target_link_libraries(epn-tun-server PRIVATE
    epn-core epn-crypto epn-protocol
    epn-transport epn-tunnel epn-discovery epn-observability
    asio spdlog::spdlog nlohmann_json::nlohmann_json
    CLI11::CLI11 sodium
)

epn_set_compiler_options(epn-tun-server)
