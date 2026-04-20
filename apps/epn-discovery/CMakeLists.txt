add_executable(epn-discovery-app main.cpp)
set_target_properties(epn-discovery-app PROPERTIES OUTPUT_NAME epn-discovery)

target_link_libraries(epn-discovery-app PRIVATE
    epn-core
    epn-crypto
    epn-discovery
    epn-observability
    asio
    spdlog::spdlog
    nlohmann_json::nlohmann_json
    CLI11::CLI11
    sodium
)

epn_set_compiler_options(epn-discovery-app)
