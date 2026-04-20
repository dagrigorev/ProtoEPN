#include <epn/crypto/keys.hpp>
#include <epn/protocol/framing.hpp>
#include <epn/protocol/onion.hpp>
#include <epn/discovery/announcement.hpp>
#include <epn/discovery/client.hpp>
#include <epn/observability/log.hpp>

#include <asio.hpp>
#include <CLI/CLI.hpp>
#include <sodium.h>

#include <atomic>
#include <csignal>
#include <memory>
#include <vector>
#include <thread>
#include <functional>

using namespace epn;
using namespace epn::core;
using namespace epn::crypto;
using namespace epn::protocol;
using asio::ip::tcp;

static std::atomic<bool> g_running{true};

// ─── Raw bidirectional byte-copy between two sockets ──────────────────────────
// After onion peeling, relay becomes a transparent TCP proxy.
// No framing involved — raw bytes are forwarded as-is.

static void proxy_copy(
    std::shared_ptr<tcp::socket> src,
    std::shared_ptr<tcp::socket> dst,
    std::shared_ptr<std::vector<uint8_t>> buf)
{
    src->async_read_some(
        asio::buffer(*buf),
        [src, dst, buf](std::error_code ec, size_t n) {
            if (ec || n == 0) {
                std::error_code ignored;
                dst->shutdown(tcp::socket::shutdown_send, ignored);
                return;
            }
            asio::async_write(*dst, asio::buffer(buf->data(), n),
                [src, dst, buf](std::error_code ec2, size_t) {
                    if (!ec2) proxy_copy(src, dst, buf);
                    else {
                        std::error_code ignored;
                        src->shutdown(tcp::socket::shutdown_receive, ignored);
                    }
                });
        });
}

static void start_bidirectional_proxy(
    std::shared_ptr<tcp::socket> a,
    std::shared_ptr<tcp::socket> b)
{
    // a → b
    proxy_copy(a, b, std::make_shared<std::vector<uint8_t>>(65536));
    // b → a
    proxy_copy(b, a, std::make_shared<std::vector<uint8_t>>(65536));
}

// ─── Read exactly one framed message from a raw socket (sync-style async) ────
// Header = [4-byte payload_len][1-byte type]
// Returns the Frame via callback; called once per relay setup.
static void read_one_frame(
    std::shared_ptr<tcp::socket> sock,
    std::function<void(std::error_code, Frame)> cb)
{
    auto hdr = std::make_shared<std::array<uint8_t, 5>>();
    asio::async_read(*sock, asio::buffer(*hdr),
        [sock, hdr, cb = std::move(cb)](std::error_code ec, size_t) mutable {
            if (ec) { cb(ec, {}); return; }
            uint32_t plen = read_be32(hdr->data());
            auto     type = static_cast<MsgType>((*hdr)[4]);
            if (plen > MAX_FRAME_SIZE) {
                cb(asio::error::message_size, {}); return;
            }
            auto payload = std::make_shared<Bytes>(plen);
            if (plen == 0) { cb({}, Frame{type, {}}); return; }
            asio::async_read(*sock, asio::buffer(*payload),
                [type, payload, cb = std::move(cb)](std::error_code ec2, size_t) mutable {
                    if (ec2) { cb(ec2, {}); return; }
                    cb({}, Frame{type, *payload});
                });
        });
}

// ─── Write one framed message to a raw socket ─────────────────────────────────
static void write_one_frame(
    std::shared_ptr<tcp::socket> sock,
    Frame f,
    std::function<void(std::error_code)> cb)
{
    auto wire = std::make_shared<Bytes>(encode_frame(f));
    asio::async_write(*sock, asio::buffer(*wire),
        [wire, cb = std::move(cb)](std::error_code ec, size_t) {
            cb(ec);
        });
}

// ─── RelaySession ─────────────────────────────────────────────────────────────
class RelaySession : public std::enable_shared_from_this<RelaySession> {
public:
    RelaySession(tcp::socket inbound, asio::io_context& ioc,
                 const RawPrivateKey& privkey, EphemeralKeyTracker& tracker)
        : inbound_(std::make_shared<tcp::socket>(std::move(inbound)))
        , ioc_(ioc), privkey_(privkey), tracker_(tracker) {}

    void start() {
        auto self = shared_from_this();
        // Step 1: read exactly one ONION_FORWARD frame from inbound
        read_one_frame(inbound_,
            [self](std::error_code ec, Frame f) {
                if (ec) { LOG_DEBUG("Relay: inbound read error: {}", ec.message()); return; }
                if (f.type != MsgType::ONION_FORWARD) {
                    LOG_WARN("Relay: expected ONION_FORWARD, got 0x{:02x}", (int)f.type);
                    return;
                }
                self->handle_onion(std::move(f.payload));
            });
    }

private:
    void handle_onion(Bytes wire) {
        // Anti-replay: check ephemeral pubkey
        if (wire.size() < 32) {
            LOG_WARN("Relay: onion too short"); return;
        }
        RawPublicKey epk;
        std::memcpy(epk.data(), wire.data(), 32);
        if (!tracker_.check_and_insert(epk)) {
            LOG_WARN("Relay: replay detected — dropping");
            return;
        }

        // Peel one layer
        auto res = peel_onion(privkey_, {wire.data(), wire.size()});
        if (res.is_err()) {
            LOG_WARN("Relay: peel failed: {}", res.error()); return;
        }
        auto& peeled = res.value();

        if (peeled.hop_type != HopType::RELAY) {
            LOG_WARN("Relay: unexpected hop_type {}", (int)peeled.hop_type); return;
        }

        LOG_DEBUG("Relay: forwarding to {}:{}", peeled.next_addr, peeled.next_port);
        connect_and_proxy(peeled.next_addr, peeled.next_port, std::move(peeled.inner));
    }

    void connect_and_proxy(std::string addr, uint16_t port, Bytes inner) {
        auto self     = shared_from_this();
        auto resolver = std::make_shared<tcp::resolver>(ioc_);
        resolver->async_resolve(addr, std::to_string(port),
            [self, resolver, inner = std::move(inner)]
            (std::error_code ec, tcp::resolver::results_type eps) mutable {
                if (ec) {
                    LOG_ERROR("Relay: resolve error: {}", ec.message()); return;
                }
                auto outbound = std::make_shared<tcp::socket>(self->ioc_);
                asio::async_connect(*outbound, eps,
                    [self, outbound, inner = std::move(inner)]
                    (std::error_code ec2, const tcp::endpoint&) mutable {
                        if (ec2) {
                            LOG_ERROR("Relay: connect error: {}", ec2.message()); return;
                        }
                        std::error_code opt_ec;
                        outbound->set_option(tcp::no_delay(true), opt_ec);

                        // Step 2: forward inner onion to next hop
                        write_one_frame(outbound,
                            Frame{MsgType::ONION_FORWARD, std::move(inner)},
                            [self, outbound](std::error_code ec3) mutable {
                                if (ec3) {
                                    LOG_ERROR("Relay: forward write error: {}", ec3.message());
                                    return;
                                }
                                // Step 3: enter raw bidirectional proxy
                                LOG_DEBUG("Relay: proxy mode active");
                                start_bidirectional_proxy(self->inbound_, outbound);
                            });
                    });
            });
    }

    std::shared_ptr<tcp::socket> inbound_;
    asio::io_context&            ioc_;
    const RawPrivateKey&         privkey_;
    EphemeralKeyTracker&         tracker_;
};

// ─── main ─────────────────────────────────────────────────────────────────────
int main(int argc, char** argv) {
    CLI::App app{"EPN Relay Node"};
    int         port      = 9001;
    std::string disc_host = "127.0.0.1";
    int         disc_port = 8000;
    std::string bind_addr = "127.0.0.1";
    bool        debug     = false;

    app.add_option("-p,--port",     port,      "Listen port")->default_val(9001);
    app.add_option("--disc-host",   disc_host, "Discovery host")->default_val("127.0.0.1");
    app.add_option("--disc-port",   disc_port, "Discovery port")->default_val(8000);
    app.add_option("--bind",        bind_addr, "Bind address")->default_val("127.0.0.1");
    app.add_flag  ("-d,--debug",    debug,     "Debug logging");
    CLI11_PARSE(app, argc, argv);

    observability::init_logger("epn-relay", debug);
    if (sodium_init() < 0) { LOG_CRITICAL("libsodium init failed"); return 1; }

    LOG_INFO("EPN Relay starting on {}:{}", bind_addr, port);

    auto kp_res = generate_x25519_keypair();
    if (kp_res.is_err()) { LOG_CRITICAL("Keypair gen failed"); return 1; }
    auto& kp = kp_res.value();

    auto sign_kp_res = generate_signing_keypair();
    if (sign_kp_res.is_err()) { LOG_CRITICAL("Sign keypair gen failed"); return 1; }
    auto& sign_kp = sign_kp_res.value();

    NodeId node_id = pubkey_to_node_id(kp.pubkey);
    LOG_INFO("node_id: {}", to_hex({node_id.data.data(), 8}));

    // Register with discovery
    discovery::DiscoveryClient disc(disc_host, disc_port);
    discovery::NodeAnnouncement ann;
    ann.node_id_hex = to_hex({node_id.data.data(), 32});
    ann.role        = NodeRole::Relay;
    ann.addr        = bind_addr;
    ann.port        = port;
    ann.dh_pubkey   = kp.pubkey;
    ann.sign_pubkey = sign_kp.pubkey;
    ann.timestamp   = now_unix();
    ann.ttl         = DISCOVERY_TTL_SECS;

    auto reg = disc.register_node(ann, sign_kp);
    if (reg.is_err()) LOG_WARN("Discovery registration failed: {}", reg.error());
    else              LOG_INFO("Registered with discovery at {}:{}", disc_host, disc_port);

    EphemeralKeyTracker epk_tracker(120);

    const int threads = static_cast<int>(std::max(2u, std::thread::hardware_concurrency()));
    asio::io_context ioc(threads);

    // Periodic re-registration
    asio::steady_timer reg_timer(ioc);
    std::function<void()> rereg = [&]() {
        reg_timer.expires_after(std::chrono::seconds(DISCOVERY_TTL_SECS / 2));
        reg_timer.async_wait([&](std::error_code ec) {
            if (ec) return;
            ann.timestamp = now_unix();
            auto r = disc.register_node(ann, sign_kp);
            if (r.is_err()) LOG_WARN("Re-reg failed: {}", r.error());
            rereg();
        });
    };
    rereg();

    // Accept loop
    tcp::acceptor acceptor(ioc, tcp::endpoint(tcp::v4(), port));
    acceptor.set_option(asio::socket_base::reuse_address(true));
    LOG_INFO("Relay: listening for onion packets");

    std::function<void()> do_accept = [&]() {
        acceptor.async_accept(
            [&](std::error_code ec, tcp::socket sock) {
                if (ec) {
                    if (ec != asio::error::operation_aborted)
                        LOG_ERROR("Accept error: {}", ec.message());
                    return;
                }
                std::error_code opt_ec;
                sock.set_option(tcp::no_delay(true), opt_ec);
                LOG_DEBUG("Relay: inbound connection");
                auto session = std::make_shared<RelaySession>(
                    std::move(sock), ioc, kp.privkey, epk_tracker);
                session->start();
                do_accept();
            });
    };
    do_accept();

    asio::signal_set sigs(ioc, SIGINT, SIGTERM);
    sigs.async_wait([&](std::error_code, int s) {
        LOG_INFO("Relay: signal {}, shutting down", s);
        g_running = false;
        acceptor.close();
        ioc.stop();
    });

    std::vector<std::thread> pool;
    for (int i = 0; i < threads - 1; ++i)
        pool.emplace_back([&ioc] { ioc.run(); });
    ioc.run();
    for (auto& t : pool) t.join();

    LOG_INFO("Relay: stopped");
    sodium_memzero(const_cast<uint8_t*>(kp.privkey.data()), 32);
    return 0;
}
