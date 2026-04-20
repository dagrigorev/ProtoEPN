add_executable(epn-tun-dev main.cpp)

target_link_libraries(epn-tun-dev PRIVATE
    epn-core epn-observability
    asio spdlog::spdlog
    CLI11::CLI11
)

epn_set_compiler_options(epn-tun-dev)
