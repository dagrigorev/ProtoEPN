#include <epn/crypto/keys.hpp>
#include <epn/crypto/aead.hpp>
#include <epn/crypto/kdf.hpp>
#include <epn/protocol/framing.hpp>
#include <epn/protocol/onion.hpp>
#include <epn/discovery/client.hpp>
#include <epn/routing/route.hpp>
#include <epn/observability/log.hpp>

#include <asio.hpp>
#include <CLI/CLI.hpp>
#include <sodium.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <functional>

using namespace epn;
using namespace epn::core;
using namespace epn::crypto;
using namespace epn::protocol;
using namespace epn::routing;
using asio::ip::tcp;

// ─── One-shot framed read/write on a raw socket ───────────────────────────────
static void read_frame_raw(
    std::shared_ptr<tcp::socket> sock,
    std::function<void(std::error_code, Frame)> cb)
{
    auto hdr = std::make_shared<std::array<uint8_t, 5>>();
    asio::async_read(*sock, asio::buffer(*hdr),
        [sock, hdr, cb = std::move(cb)](std::error_code ec, size_t) mutable {
            if (ec) { cb(ec, {}); return; }
            uint32_t plen = read_be32(hdr->data());
            auto     type = static_cast<MsgType>((*hdr)[4]);
            if (plen > MAX_FRAME_SIZE) { cb(asio::error::message_size, {}); return; }
            auto p = std::make_shared<Bytes>(plen);
            if (plen == 0) { cb({}, Frame{type, {}}); return; }
            asio::async_read(*sock, asio::buffer(*p),
                [type, p, cb = std::move(cb)](std::error_code ec2, size_t) mutable {
                    cb(ec2, ec2 ? Frame{} : Frame{type, *p});
                });
        });
}

static void write_frame_raw(
    std::shared_ptr<tcp::socket> sock,
    Frame f,
    std::function<void(std::error_code)> cb = {})
{
    auto wire = std::make_shared<Bytes>(encode_frame(f));
    asio::async_write(*sock, asio::buffer(*wire),
        [wire, cb = std::move(cb)](std::error_code ec, size_t) {
            if (cb) cb(ec);
        });
}

// ─── Continuous frame reader loop ─────────────────────────────────────────────
static void read_frames_loop(
    std::shared_ptr<tcp::socket> sock,
    std::function<void(Frame)>   on_frame,
    std::function<void()>        on_close)
{
    read_frame_raw(sock,
        [sock, on_frame = std::move(on_frame), on_close = std::move(on_close)]
        (std::error_code ec, Frame f) mutable {
            if (ec) { on_close(); return; }
            on_frame(f);
            read_frames_loop(sock, on_frame, on_close);
        });
}

// ─── EpnClient ───────────────────────────────────────────────────────────────
class EpnClient {
public:
    EpnClient(asio::io_context& ioc, const std::string& disc_host, uint16_t disc_port)
        : ioc_(ioc), disc_(disc_host, disc_port), planner_(disc_)
        , fwd_nonce_(NONCE_DIRECTION_FORWARD)
        , bwd_nonce_(NONCE_DIRECTION_BACKWARD)
    {}

    // Send message through EPN route, block until response or timeout
    Result<std::string> send(const std::string& message, size_t num_relays) {
        LOG_INFO("Client: building {}-hop route", num_relays);
        Bytes payload(message.begin(), message.end());

        // Build onion route — returns wire bytes + E2E session key with server
        auto route_res = planner_.build_route({payload.data(), payload.size()}, num_relays);
        if (route_res.is_err())
            return Result<std::string>::err("Route: " + route_res.error());

        auto& route = route_res.value();
        session_id_ = route.session_id;

        // Store the E2E session key (derived from X25519 DH with server during build_onion)
        // forward  = client → server encryption key
        // backward = server → client encryption key (what we decrypt responses with)
        key_fwd_ = route.server_session_key.forward;
        key_bwd_ = route.server_session_key.backward;

        LOG_INFO("Client: route built — entry {}:{}, {} hops, sid={}",
                 route.entry_point.addr, route.entry_point.port,
                 route.hops.size(),
                 to_hex({session_id_.data.data(), 8}));

        // Synchronization primitives for async → sync bridge
        std::mutex              mu;
        std::condition_variable cv;
        bool                    done     = false;
        std::string             response;
        std::error_code         async_ec;

        // Connect to relay1 (entry point)
        std::error_code connect_ec;
        std::shared_ptr<tcp::socket> sock;
        {
            std::mutex              conn_mu;
            std::condition_variable conn_cv;
            bool                    conn_done = false;

            auto resolver = std::make_shared<tcp::resolver>(ioc_);
            resolver->async_resolve(
                route.entry_point.addr, std::to_string(route.entry_point.port),
                [&, resolver](std::error_code ec, tcp::resolver::results_type eps) mutable {
                    if (ec) {
                        std::lock_guard lk(conn_mu);
                        connect_ec = ec; conn_done = true; conn_cv.notify_all(); return;
                    }
                    auto s = std::make_shared<tcp::socket>(ioc_);
                    asio::async_connect(*s, eps,
                        [&, s](std::error_code ec2, const tcp::endpoint&) mutable {
                            std::lock_guard lk(conn_mu);
                            connect_ec = ec2;
                            if (!ec2) { std::error_code oe; s->set_option(tcp::no_delay(true), oe); sock = s; }
                            conn_done  = true;
                            conn_cv.notify_all();
                        });
                });

            std::unique_lock lk(conn_mu);
            conn_cv.wait_for(lk, std::chrono::seconds(5), [&]{ return conn_done; });
        }

        if (connect_ec || !sock)
            return Result<std::string>::err("Connect to relay1: " +
                (connect_ec ? connect_ec.message() : "timeout"));

        LOG_INFO("Client: connected to relay1 {}:{}", route.entry_point.addr,
                 route.entry_point.port);

        // Start continuous frame reader — handles ROUTE_READY + SESSION_DATA
        bool route_ready = false;
        read_frames_loop(sock,
            [&, sock_ref = sock](Frame f) mutable {
                handle_frame(f, sock_ref, mu, cv, done, route_ready, response);
            },
            [&] {
                std::lock_guard lk(mu);
                if (!done) { done = true; cv.notify_all(); }
            });

        // Send ONION_FORWARD to relay1
        write_frame_raw(sock, Frame{MsgType::ONION_FORWARD, std::move(route.onion_packet)});
        LOG_INFO("Client: sent ONION_FORWARD");

        // Wait for response (15s timeout)
        std::unique_lock lk(mu);
        bool timed_out = !cv.wait_for(lk, std::chrono::seconds(15), [&]{ return done; });
        if (timed_out) return Result<std::string>::err("Timeout waiting for response");
        if (response.empty() && async_ec)
            return Result<std::string>::err("Async error: " + async_ec.message());

        // Clean teardown — cancel pending async ops, then close
        write_frame_raw(sock, make_teardown(session_id_));
        std::error_code ec;
        sock->cancel(ec);
        sock->close(ec);

        LOG_INFO("Client: session complete");
        return Result<std::string>::ok(std::move(response));
    }

private:
    void handle_frame(const Frame& f,
                      std::shared_ptr<tcp::socket> sock,
                      std::mutex& mu, std::condition_variable& cv,
                      bool& done, bool& route_ready, std::string& response)
    {
        switch (f.type) {

        case MsgType::ROUTE_READY:
            if (f.payload.size() >= 32) {
                LOG_INFO("Client: ROUTE_READY — route confirmed, session active");
                route_ready = true;
            }
            break;

        case MsgType::SESSION_DATA: {
            // Wire: [32 session_id][12 nonce][ciphertext]
            if (f.payload.size() < SESSION_HEADER_SIZE) {
                LOG_WARN("Client: SESSION_DATA too short ({}B)", f.payload.size()); break;
            }
            RawNonce nonce;
            std::memcpy(nonce.data(), f.payload.data() + 32, 12);
            ByteSpan ct(f.payload.data() + SESSION_HEADER_SIZE,
                        f.payload.size() - SESSION_HEADER_SIZE);

            // Decrypt with backward key (server→client)
            auto pt_res = aead_decrypt(key_bwd_, nonce, ct);
            if (pt_res.is_err()) {
                LOG_WARN("Client: SESSION_DATA decrypt failed: {}", pt_res.error());
                break;
            }
            response = std::string(pt_res.value().begin(), pt_res.value().end());
            LOG_INFO("Client: response: \"{}\"", response);
            ioc_.stop();   // Stop io_context - we have our response
            std::lock_guard lk(mu);
            done = true;
            cv.notify_all();
            break;
        }

        case MsgType::KEEPALIVE:
            write_frame_raw(sock, make_keepalive());
            break;

        case MsgType::ERROR_MSG:
            LOG_ERROR("Client: server error");
            { std::lock_guard lk(mu); done = true; cv.notify_all(); }
            break;

        default:
            LOG_WARN("Client: unexpected frame 0x{:02x}", (int)f.type);
            break;
        }
    }

    asio::io_context&          ioc_;
    discovery::DiscoveryClient disc_;
    RoutePlanner               planner_;
    SessionId                  session_id_;
    RawSessionKey              key_fwd_{};
    RawSessionKey              key_bwd_{};
    NonceCounter               fwd_nonce_;
    NonceCounter               bwd_nonce_;
};

// ─── main ─────────────────────────────────────────────────────────────────────
int main(int argc, char** argv) {
    CLI::App app{"EPN Client"};
    std::string disc_host  = "127.0.0.1";
    int         disc_port  = 8000;
    std::string message    = "Hello, EPN!";
    size_t      num_relays = MIN_HOPS;
    bool        debug      = false;

    app.add_option("--disc-host",  disc_host,  "Discovery host")->default_val("127.0.0.1");
    app.add_option("--disc-port",  disc_port,  "Discovery port")->default_val(8000);
    app.add_option("-m,--message", message,    "Message to send");
    app.add_option("-r,--relays",  num_relays, "Relay hops (≥3)")->default_val(3);
    app.add_flag  ("-d,--debug",   debug,      "Debug logging");
    CLI11_PARSE(app, argc, argv);

    if (num_relays < MIN_HOPS) {
        std::cerr << "Error: minimum " << MIN_HOPS << " hops required\n"; return 1;
    }

    observability::init_logger("epn-client", debug);
    if (sodium_init() < 0) { LOG_CRITICAL("libsodium init"); return 1; }

    LOG_INFO("EPN Client | discovery={}:{} | relays={} | msg=\"{}\"",
             disc_host, disc_port, num_relays, message);

    asio::io_context ioc;
    auto work = asio::make_work_guard(ioc);
    std::thread io_thread([&]{ ioc.run(); });

    EpnClient client(ioc, disc_host, disc_port);
    auto result = client.send(message, num_relays);

    work.reset();
    ioc.stop();    // cancel any pending async ops (the looping frame reader)
    io_thread.join();

    if (result.is_err()) {
        LOG_ERROR("Failed: {}", result.error());
        std::cerr << "\n[FAIL] " << result.error() << "\n";
        return 1;
    }

    std::cout << "\n";
    std::cout << "┌─────────────────────────────────────────────────┐\n";
    std::cout << "│           EPN Session Complete ✓                │\n";
    std::cout << "├─────────────────────────────────────────────────┤\n";
    std::cout << "│ Sent:     " << message                          << "\n";
    std::cout << "│ Received: " << result.value()                   << "\n";
    std::cout << "│ Hops:     " << num_relays << " relay + server"  << "\n";
    std::cout << "└─────────────────────────────────────────────────┘\n\n";

    return 0;
}
