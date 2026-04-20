#include <epn/discovery/announcement.hpp>
#include <epn/observability/log.hpp>
#include <asio.hpp>
#include <nlohmann/json.hpp>
#include <CLI/CLI.hpp>
#include <cstring>
#include <atomic>
#include <thread>
#include <vector>
#include <csignal>

using namespace epn;
using namespace epn::core;
using namespace epn::discovery;
using asio::ip::tcp;
using json = nlohmann::json;

// Global registry
static AnnouncementRegistry g_registry;
static std::atomic<bool>    g_running{true};

// ─── Handle one discovery connection ─────────────────────────────────────────
static void handle_connection(tcp::socket sock) {
    try {
        sock.set_option(tcp::no_delay(true));
        LOG_DEBUG("Discovery: accepted connection from {}",
                  sock.remote_endpoint().address().to_string());

        // Read framed request
        std::array<uint8_t, 5> hdr{};
        asio::read(sock, asio::buffer(hdr));
        uint32_t len     = read_be32(hdr.data());
        uint8_t  msg_type = hdr[4];

        if (len > 256 * 1024) {
            LOG_WARN("Discovery: request too large ({})", len);
            return;
        }

        std::vector<uint8_t> body(len);
        if (len > 0) asio::read(sock, asio::buffer(body));

        json req = json::parse(body.begin(), body.end());
        std::string req_type = req.value("type", "");

        json resp;

        if (req_type == "register" || msg_type == 0x10) {
            auto ann_res = NodeAnnouncement::from_json(req);
            if (ann_res.is_err()) {
                resp = {{"status", "error"}, {"message", ann_res.error()}};
            } else {
                auto upsert_res = g_registry.upsert(std::move(ann_res.value()));
                if (upsert_res.is_err()) {
                    resp = {{"status", "error"}, {"message", upsert_res.error()}};
                } else {
                    resp = {{"status", "ok"}, {"registry_size", g_registry.size()}};
                    LOG_INFO("Discovery: registered node {} (total: {})",
                             req.value("node_id", "?"), g_registry.size());
                }
            }

        } else if (req_type == "query" || msg_type == 0x11) {
            NodeRole role = static_cast<NodeRole>(req.value("role", 1));
            auto nodes = g_registry.query(role);
            json node_arr = json::array();
            for (auto& n : nodes) node_arr.push_back(n.to_json());
            resp = {{"status", "ok"}, {"nodes", node_arr}};
            LOG_DEBUG("Discovery: query role={} returned {} nodes",
                      static_cast<int>(role), nodes.size());

        } else {
            resp = {{"status", "error"}, {"message", "Unknown request type"}};
        }

        // Send framed response
        std::string resp_str = resp.dump();
        std::vector<uint8_t> wire(5 + resp_str.size());
        write_be32(wire.data(), static_cast<uint32_t>(resp_str.size()));
        wire[4] = 0x12; // DISC_RESPONSE
        std::memcpy(wire.data() + 5, resp_str.data(), resp_str.size());
        asio::write(sock, asio::buffer(wire));

    } catch (const std::exception& e) {
        LOG_DEBUG("Discovery: connection handler exception: {}", e.what());
    }
}

int main(int argc, char** argv) {
    CLI::App app{"EPN Discovery Server"};
    uint16_t port      = 8000;
    bool     debug     = false;
    std::string log_file;

    app.add_option("-p,--port",     port,     "Listen port")->default_val(8000);
    app.add_flag  ("-d,--debug",    debug,    "Enable debug logging");
    app.add_option("-l,--log-file", log_file, "Log file path (optional)");
    CLI11_PARSE(app, argc, argv);

    observability::init_logger("epn-discovery", debug, log_file);
    if (sodium_init() < 0) { LOG_CRITICAL("libsodium init failed"); return 1; }

    LOG_INFO("EPN Discovery Server starting on port {}", port);

    // Signal handling
    std::signal(SIGINT,  [](int) { g_running = false; });
    std::signal(SIGTERM, [](int) { g_running = false; });

    asio::io_context ioc;
    tcp::acceptor    acceptor(ioc, tcp::endpoint(tcp::v4(), port));
    acceptor.set_option(asio::socket_base::reuse_address(true));

    LOG_INFO("Discovery: listening on 0.0.0.0:{}", port);

    // Periodic sweep timer (60s)
    asio::steady_timer sweep_timer(ioc);
    std::function<void()> schedule_sweep = [&]() {
        sweep_timer.expires_after(std::chrono::seconds(60));
        sweep_timer.async_wait([&](std::error_code ec) {
            if (ec) return;
            size_t removed = g_registry.sweep_expired();
            if (removed > 0)
                LOG_INFO("Discovery: swept {} expired announcements", removed);
            schedule_sweep();
        });
    };
    schedule_sweep();

    // Accept loop (each connection handled in a detached thread)
    auto do_accept = [&]() {
        std::function<void()> accept_fn = [&]() {
            acceptor.async_accept([&](std::error_code ec, tcp::socket sock) {
                if (!ec && g_running) {
                    std::thread([s = std::move(sock)]() mutable {
                        handle_connection(std::move(s));
                    }).detach();
                }
                if (g_running) accept_fn();
            });
        };
        accept_fn();
    };
    do_accept();

    // Run until signal
    while (g_running) {
        ioc.run_for(std::chrono::milliseconds(100));
        ioc.restart();
    }

    LOG_INFO("Discovery: shutting down");
    return 0;
}
