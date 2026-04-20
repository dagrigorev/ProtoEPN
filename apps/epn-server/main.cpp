#include <epn/crypto/keys.hpp>
#include <epn/crypto/aead.hpp>
#include <epn/crypto/kdf.hpp>
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
#include <mutex>
#include <thread>
#include <vector>
#include <functional>
#include <cstring>

using namespace epn;
using namespace epn::core;
using namespace epn::crypto;
using namespace epn::protocol;
using asio::ip::tcp;

static std::atomic<bool> g_running{true};

// ─── Read one framed message from raw socket ──────────────────────────────────
static void read_one_frame_raw(
    std::shared_ptr<tcp::socket> sock,
    std::function<void(std::error_code, Frame)> cb)
{
    auto hdr = std::make_shared<std::array<uint8_t, 5>>();
    asio::async_read(*sock, asio::buffer(*hdr),
        [sock, hdr, cb = std::move(cb)](std::error_code ec, size_t) mutable {
            if (ec) { cb(ec, {}); return; }
            uint32_t plen = read_be32(hdr->data());
            auto     type = static_cast<MsgType>((*hdr)[4]);
            if (plen > MAX_FRAME_SIZE || plen > 1024*1024) {
                cb(asio::error::message_size, {}); return;
            }
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

// ─── ServerSession ─────────────────────────────────────────────────────────────
struct ServerSession {
    SessionId  id;
    int64_t    created_at;
    std::shared_ptr<tcp::socket> sock; // connection back through relay chain
    RawSessionKey key_fwd{};
    RawSessionKey key_bwd{};
    NonceCounter  bwd_nonce{NONCE_DIRECTION_BACKWARD};

    ~ServerSession() {
        sodium_memzero(key_fwd.data(), 32);
        sodium_memzero(key_bwd.data(), 32);
    }
};

// ─── EpnServer ───────────────────────────────────────────────────────────────
class EpnServer {
public:
    EpnServer(asio::io_context& ioc,
              const RawPrivateKey& privkey,
              const RawPublicKey&  pubkey)
        : ioc_(ioc), privkey_(privkey), pubkey_(pubkey), epk_tracker_(120) {}

    void handle_connection(std::shared_ptr<tcp::socket> sock) {
        LOG_DEBUG("Server: new connection");
        read_frames(sock);
    }

private:
    void read_frames(std::shared_ptr<tcp::socket> sock) {
        auto self = this;
        read_one_frame_raw(sock,
            [this, sock](std::error_code ec, Frame f) {
                if (ec) {
                    LOG_DEBUG("Server: connection closed: {}", ec.message());
                    return;
                }
                on_frame(sock, std::move(f));
                // Continue reading
                read_frames(sock);
            });
    }

    void on_frame(std::shared_ptr<tcp::socket> sock, Frame f) {
        switch (f.type) {
        case MsgType::ONION_FORWARD:  handle_onion(sock, std::move(f.payload)); break;
        case MsgType::SESSION_DATA:   handle_data(sock, std::move(f.payload));  break;
        case MsgType::TEARDOWN:       handle_teardown(sock, std::move(f.payload)); break;
        case MsgType::KEEPALIVE:      write_frame_raw(sock, make_keepalive());   break;
        default:
            LOG_WARN("Server: unknown frame 0x{:02x}", (int)f.type); break;
        }
    }

    void handle_onion(std::shared_ptr<tcp::socket> sock, Bytes wire) {
        if (wire.size() < 32) return;
        RawPublicKey epk;
        std::memcpy(epk.data(), wire.data(), 32);
        if (!epk_tracker_.check_and_insert(epk)) {
            LOG_WARN("Server: replay detected");
            write_frame_raw(sock, make_error(EpnError::REPLAY_DETECTED));
            return;
        }

        auto res = peel_onion(privkey_, {wire.data(), wire.size()});
        if (res.is_err()) {
            LOG_WARN("Server: peel failed: {}", res.error());
            write_frame_raw(sock, make_error(EpnError::AUTH_FAILED));
            return;
        }
        auto& peeled = res.value();
        if (peeled.hop_type != HopType::FINAL) {
            write_frame_raw(sock, make_error(EpnError::INVALID_HOP_TYPE));
            return;
        }

        const SessionId& sid = peeled.session_id;
        LOG_INFO("Server: new session sid={}", to_hex({sid.data.data(), 4}));

        // Derive session keys from DH with the ephemeral pubkey in this onion layer
        auto dh_res = x25519_dh(privkey_, epk);
        auto session = std::make_shared<ServerSession>();
        session->id         = sid;
        session->created_at = now_unix();
        session->sock       = sock;

        if (dh_res.is_ok()) {
            auto sk_res = derive_session_keys(dh_res.value(), epk, pubkey_);
            if (sk_res.is_ok()) {
                session->key_fwd = sk_res.value().forward;
                session->key_bwd = sk_res.value().backward;
            }
        }

        {
            std::lock_guard lk(mu_);
            sessions_[std::string(sid.data.begin(), sid.data.end())] = session;
        }

        // Log the received payload
        auto& payload = peeled.inner;
        std::string msg(payload.begin(), payload.end());
        LOG_INFO("Server: payload: \"{}\"", msg);

        // Send ROUTE_READY back through relay chain
        write_frame_raw(sock, make_route_ready(sid));
        LOG_DEBUG("Server: sent ROUTE_READY");

        // Send echo response
        send_echo(session, payload);
    }

    void handle_data(std::shared_ptr<tcp::socket> sock, Bytes payload) {
        if (payload.size() < SESSION_HEADER_SIZE) return;
        std::string sid_key(reinterpret_cast<const char*>(payload.data()), 32);

        std::shared_ptr<ServerSession> session;
        {
            std::lock_guard lk(mu_);
            auto it = sessions_.find(sid_key);
            if (it == sessions_.end()) { LOG_WARN("Server: unknown session"); return; }
            session = it->second;
        }

        if ((now_unix() - session->created_at) > SESSION_TTL_SECS) {
            write_frame_raw(sock, make_error(EpnError::SESSION_EXPIRED));
            cleanup(sid_key);
            return;
        }

        RawNonce nonce;
        std::memcpy(nonce.data(), payload.data() + 32, 12);
        ByteSpan ct(payload.data() + SESSION_HEADER_SIZE,
                    payload.size() - SESSION_HEADER_SIZE);

        auto pt_res = aead_decrypt(session->key_fwd, nonce, ct);
        if (pt_res.is_err()) { LOG_WARN("Server: SESSION_DATA decrypt failed"); return; }

        LOG_INFO("Server: data ({}B): \"{}\"",
                 pt_res.value().size(),
                 std::string(pt_res.value().begin(), pt_res.value().end()));

        send_echo(session, pt_res.value());
    }

    void handle_teardown(std::shared_ptr<tcp::socket> sock, Bytes payload) {
        if (payload.size() < 32) return;
        std::string sid_key(reinterpret_cast<const char*>(payload.data()), 32);
        cleanup(sid_key);
        std::error_code ec;
        sock->shutdown(tcp::socket::shutdown_both, ec);
    }

    void send_echo(std::shared_ptr<ServerSession> session, const Bytes& data) {
        std::string echo = "ECHO: " + std::string(data.begin(), data.end());
        Bytes resp(echo.begin(), echo.end());

        auto nonce  = session->bwd_nonce.next();
        auto ct_res = aead_encrypt_with_nonce(session->key_bwd, nonce,
                                               {resp.data(), resp.size()});
        if (ct_res.is_err()) { LOG_ERROR("Server: encrypt failed"); return; }

        Bytes frame_payload(32 + 12 + ct_res.value().ciphertext.size());
        std::memcpy(frame_payload.data(),      session->id.data.data(), 32);
        std::memcpy(frame_payload.data() + 32, nonce.data(), 12);
        std::memcpy(frame_payload.data() + 44,
                    ct_res.value().ciphertext.data(),
                    ct_res.value().ciphertext.size());

        write_frame_raw(session->sock,
                        Frame{MsgType::SESSION_DATA, std::move(frame_payload)});
        LOG_DEBUG("Server: sent echo response");
    }

    void cleanup(const std::string& sid_key) {
        std::lock_guard lk(mu_);
        sessions_.erase(sid_key);
        LOG_INFO("Server: session cleaned up (active: {})", sessions_.size());
    }

    asio::io_context&    ioc_;
    const RawPrivateKey& privkey_;
    const RawPublicKey&  pubkey_;
    EphemeralKeyTracker  epk_tracker_;
    std::mutex           mu_;
    std::unordered_map<std::string, std::shared_ptr<ServerSession>> sessions_;
};

// ─── main ─────────────────────────────────────────────────────────────────────
int main(int argc, char** argv) {
    CLI::App app{"EPN Server Node"};
    int         port      = 9100;
    std::string disc_host = "127.0.0.1";
    int         disc_port = 8000;
    std::string bind_addr = "127.0.0.1";
    bool        debug     = false;

    app.add_option("-p,--port",     port,      "Server port")->default_val(9100);
    app.add_option("--disc-host",   disc_host, "Discovery host")->default_val("127.0.0.1");
    app.add_option("--disc-port",   disc_port, "Discovery port")->default_val(8000);
    app.add_option("--bind",        bind_addr, "Bind address")->default_val("127.0.0.1");
    app.add_flag  ("-d,--debug",    debug,     "Debug logging");
    CLI11_PARSE(app, argc, argv);

    observability::init_logger("epn-server", debug);
    if (sodium_init() < 0) { LOG_CRITICAL("libsodium init failed"); return 1; }

    LOG_INFO("EPN Server starting on {}:{}", bind_addr, port);

    auto kp_res = generate_x25519_keypair();
    if (kp_res.is_err()) { LOG_CRITICAL("Keypair gen failed"); return 1; }
    auto& kp = kp_res.value();

    auto sign_kp_res = generate_signing_keypair();
    if (sign_kp_res.is_err()) { LOG_CRITICAL("Sign keypair gen failed"); return 1; }
    auto& sign_kp = sign_kp_res.value();

    NodeId node_id = pubkey_to_node_id(kp.pubkey);
    LOG_INFO("node_id:   {}", to_hex({node_id.data.data(), 8}));
    LOG_INFO("dh_pubkey: {}", to_hex({kp.pubkey.data(), 16}));

    discovery::DiscoveryClient disc(disc_host, disc_port);
    discovery::NodeAnnouncement ann;
    ann.node_id_hex = to_hex({node_id.data.data(), 32});
    ann.role        = NodeRole::Server;
    ann.addr        = bind_addr;
    ann.port        = port;
    ann.dh_pubkey   = kp.pubkey;
    ann.sign_pubkey = sign_kp.pubkey;
    ann.timestamp   = now_unix();
    ann.ttl         = DISCOVERY_TTL_SECS;

    auto reg = disc.register_node(ann, sign_kp);
    if (reg.is_err()) LOG_WARN("Discovery reg failed: {}", reg.error());
    else              LOG_INFO("Registered with discovery");

    const int threads = static_cast<int>(std::max(2u, std::thread::hardware_concurrency()));
    asio::io_context ioc(threads);

    EpnServer server(ioc, kp.privkey, kp.pubkey);

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

    tcp::acceptor acceptor(ioc, tcp::endpoint(tcp::v4(), port));
    acceptor.set_option(asio::socket_base::reuse_address(true));
    LOG_INFO("Server: ready and listening");

    std::function<void()> do_accept = [&]() {
        acceptor.async_accept([&](std::error_code ec, tcp::socket sock) {
            if (ec) {
                if (ec != asio::error::operation_aborted)
                    LOG_ERROR("Accept: {}", ec.message());
                return;
            }
            std::error_code opt_ec;
            sock.set_option(tcp::no_delay(true), opt_ec);
            auto sp = std::make_shared<tcp::socket>(std::move(sock));
            server.handle_connection(sp);
            do_accept();
        });
    };
    do_accept();

    asio::signal_set sigs(ioc, SIGINT, SIGTERM);
    sigs.async_wait([&](std::error_code, int s) {
        LOG_INFO("Server: signal {}, shutting down", s);
        acceptor.close();
        ioc.stop();
    });

    std::vector<std::thread> pool;
    for (int i = 0; i < threads - 1; ++i)
        pool.emplace_back([&ioc] { ioc.run(); });
    ioc.run();
    for (auto& t : pool) t.join();

    LOG_INFO("Server: stopped");
    sodium_memzero(const_cast<uint8_t*>(kp.privkey.data()), 32);
    return 0;
}
