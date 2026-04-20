// epn-tun-server: EPN tunnel endpoint
//
// Architecture:
//   EPN client (encrypted) → relay chain → THIS SERVER
//   For each STREAM_OPEN: connect to real target, bidirectional proxy
//   Multiple streams multiplexed over one EPN session (one TCP connection)
//
// Session_DATA wire: [32B sid][12B nonce][AEAD(tunnel_frame)]
// Tunnel frame:      [4B stream_id][1B cmd][2B len][data]

#include <epn/crypto/keys.hpp>
#include <epn/crypto/aead.hpp>
#include <epn/crypto/kdf.hpp>
#include <epn/protocol/framing.hpp>
#include <epn/protocol/onion.hpp>
#include <epn/tunnel/protocol.hpp>
#include <epn/discovery/announcement.hpp>
#include <epn/discovery/client.hpp>
#include <epn/observability/log.hpp>

#include <asio.hpp>
#include <CLI/CLI.hpp>
#include <sodium.h>

#include <atomic>
#include <csignal>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>

using namespace epn;
using namespace epn::core;
using namespace epn::crypto;
using namespace epn::protocol;
using namespace epn::tunnel;
using asio::ip::tcp;

// ─── Read one framed message ──────────────────────────────────────────────────
static void read_one_frame(
    std::shared_ptr<tcp::socket> sock,
    std::function<void(std::error_code, Frame)> cb)
{
    auto hdr = std::make_shared<std::array<uint8_t,5>>();
    asio::async_read(*sock, asio::buffer(*hdr),
        [sock, hdr, cb=std::move(cb)](std::error_code ec, size_t) mutable {
            if (ec) { cb(ec,{}); return; }
            uint32_t plen = read_be32(hdr->data());
            auto type = static_cast<MsgType>((*hdr)[4]);
            if (plen > MAX_FRAME_SIZE) { cb(asio::error::message_size,{}); return; }
            auto p = std::make_shared<Bytes>(plen);
            if (plen == 0) { cb({},Frame{type,{}}); return; }
            asio::async_read(*sock, asio::buffer(*p),
                [type,p,cb=std::move(cb)](std::error_code ec2, size_t) mutable {
                    cb(ec2, ec2 ? Frame{} : Frame{type,*p});
                });
        });
}

static void write_frame(
    std::shared_ptr<tcp::socket> sock,
    Frame f,
    std::function<void(std::error_code)> cb = {})
{
    auto wire = std::make_shared<Bytes>(encode_frame(f));
    asio::async_write(*sock, asio::buffer(*wire),
        [wire, cb=std::move(cb)](std::error_code ec, size_t) { if(cb) cb(ec); });
}

// ─── Remote TCP stream managed by this session ────────────────────────────────
struct RemoteStream {
    uint32_t id;
    tcp::socket sock;
    std::array<uint8_t, 65536> buf{};

    explicit RemoteStream(asio::io_context& ioc, uint32_t i)
        : id(i), sock(ioc) {}
};

// ─── TunnelServerSession ──────────────────────────────────────────────────────
// Manages one EPN session from a client. Contains N multiplexed TCP streams.
class TunnelServerSession : public std::enable_shared_from_this<TunnelServerSession> {
public:
    TunnelServerSession(
        asio::io_context&     ioc,
        std::shared_ptr<tcp::socket> epn_sock,
        const SessionId&      session_id,
        const RawSessionKey&  key_fwd,
        const RawSessionKey&  key_bwd)
        : ioc_(ioc)
        , epn_sock_(std::move(epn_sock))
        , session_id_(session_id)
        , bwd_nonce_(NONCE_DIRECTION_BACKWARD)
    {
        std::memcpy(key_fwd_.data(), key_fwd.data(), 32);
        std::memcpy(key_bwd_.data(), key_bwd.data(), 32);
    }

    ~TunnelServerSession() {
        sodium_memzero(key_fwd_.data(), 32);
        sodium_memzero(key_bwd_.data(), 32);
    }

    void start() { recv_loop(); }

private:
    // ── Receive SESSION_DATA frames from client, dispatch tunnel commands ──────
    void recv_loop() {
        auto self = shared_from_this();
        read_one_frame(epn_sock_,
            [self](std::error_code ec, Frame f) {
                if (ec) {
                    LOG_INFO("TunServer: session closed ({})", ec.message());
                    self->close_all_streams();
                    return;
                }
                switch (f.type) {
                case MsgType::SESSION_DATA: self->on_session_data(std::move(f.payload)); break;
                case MsgType::TEARDOWN:     self->close_all_streams(); return;
                case MsgType::KEEPALIVE:    write_frame(self->epn_sock_, make_keepalive()); break;
                default: break;
                }
                self->recv_loop();
            });
    }

    void on_session_data(Bytes payload) {
        // Wire: [32B session_id][12B nonce][ciphertext]
        if (payload.size() < SESSION_HEADER_SIZE) return;
        RawNonce nonce;
        std::memcpy(nonce.data(), payload.data() + 32, 12);
        ByteSpan ct(payload.data() + SESSION_HEADER_SIZE,
                    payload.size() - SESSION_HEADER_SIZE);

        auto pt_res = aead_decrypt(key_fwd_, nonce, ct);
        if (pt_res.is_err()) {
            LOG_WARN("TunServer: decrypt failed: {}", pt_res.error()); return;
        }

        auto frame_res = decode_tunnel_frame({pt_res.value().data(), pt_res.value().size()});
        if (frame_res.is_err()) {
            LOG_WARN("TunServer: bad tunnel frame: {}", frame_res.error()); return;
        }
        auto& tf = frame_res.value();

        switch (tf.cmd) {
        case TunnelCmd::STREAM_OPEN:  on_stream_open(tf.stream_id, std::move(tf.data));  break;
        case TunnelCmd::STREAM_DATA:  on_stream_data(tf.stream_id, std::move(tf.data));  break;
        case TunnelCmd::STREAM_CLOSE: on_stream_close(tf.stream_id); break;
        default: break;
        }
    }

    // ── STREAM_OPEN: resolve and connect to target ────────────────────────────
    void on_stream_open(uint32_t sid, Bytes payload) {
        auto target = parse_open_payload({payload.data(), payload.size()});
        if (target.is_err()) {
            send_ack(sid, OpenResult::GENERAL_ERROR); return;
        }
        auto& [host, port] = target.value();
        LOG_INFO("TunServer: stream {} → {}:{}", sid, host, port);

        auto self  = shared_from_this();
        auto stream = std::make_shared<RemoteStream>(ioc_, sid);
        {
            std::lock_guard lk(streams_mu_);
            streams_[sid] = stream;
        }

        auto resolver = std::make_shared<tcp::resolver>(ioc_);
        resolver->async_resolve(host, std::to_string(port),
            [self, sid, stream, resolver](std::error_code ec, tcp::resolver::results_type eps) {
                if (ec) {
                    LOG_WARN("TunServer: resolve {} failed: {}", sid, ec.message());
                    self->send_ack(sid, OpenResult::UNREACHABLE);
                    self->remove_stream(sid);
                    return;
                }
                asio::async_connect(stream->sock, eps,
                    [self, sid, stream](std::error_code ec2, const tcp::endpoint& ep) {
                        if (ec2) {
                            LOG_WARN("TunServer: connect {} failed: {}", sid, ec2.message());
                            OpenResult r = (ec2 == asio::error::connection_refused)
                                ? OpenResult::REFUSED : OpenResult::UNREACHABLE;
                            self->send_ack(sid, r);
                            self->remove_stream(sid);
                            return;
                        }
                        std::error_code oe;
                        stream->sock.set_option(tcp::no_delay(true), oe);
                        LOG_DEBUG("TunServer: stream {} connected to {}", sid, ep.address().to_string());
                        self->send_ack(sid, OpenResult::OK);
                        self->pump_from_remote(stream);
                    });
            });
    }

    // ── STREAM_DATA: forward to remote TCP connection ─────────────────────────
    void on_stream_data(uint32_t sid, Bytes data) {
        std::shared_ptr<RemoteStream> stream;
        {
            std::lock_guard lk(streams_mu_);
            auto it = streams_.find(sid);
            if (it == streams_.end()) return;
            stream = it->second;
        }
        if (data.empty()) return;
        auto buf = std::make_shared<Bytes>(std::move(data));
        asio::async_write(stream->sock, asio::buffer(*buf),
            [buf, sid](std::error_code ec, size_t) {
                if (ec) LOG_DEBUG("TunServer: write to remote {} failed: {}", sid, ec.message());
            });
    }

    // ── STREAM_CLOSE: close the remote TCP connection ─────────────────────────
    void on_stream_close(uint32_t sid) {
        LOG_DEBUG("TunServer: stream {} CLOSE received", sid);
        remove_stream(sid);
    }

    // ── Pump data from remote TCP → client (via EPN) ──────────────────────────
    void pump_from_remote(std::shared_ptr<RemoteStream> stream) {
        auto self = shared_from_this();
        stream->sock.async_read_some(asio::buffer(stream->buf),
            [self, stream](std::error_code ec, size_t n) {
                if (ec || n == 0) {
                    LOG_DEBUG("TunServer: remote stream {} closed", stream->id);
                    self->send_tunnel_frame(stream->id, TunnelCmd::STREAM_CLOSE, {});
                    self->remove_stream(stream->id);
                    return;
                }
                self->send_tunnel_frame(stream->id, TunnelCmd::STREAM_DATA,
                    {stream->buf.data(), n});
                self->pump_from_remote(stream);
            });
    }

    // ── Send a tunnel frame to the client (encrypted SESSION_DATA) ────────────
    void send_tunnel_frame(uint32_t sid, TunnelCmd cmd, ByteSpan data) {
        Bytes tf = encode_tunnel_frame(sid, cmd, data);
        send_session_data({tf.data(), tf.size()});
    }

    void send_ack(uint32_t sid, OpenResult result) {
        uint8_t r = static_cast<uint8_t>(result);
        send_tunnel_frame(sid, TunnelCmd::STREAM_OPEN_ACK, {&r, 1});
    }

    void send_session_data(ByteSpan plaintext) {
        auto nonce = bwd_nonce_.next();
        auto ct_res = aead_encrypt_with_nonce(key_bwd_, nonce, plaintext);
        if (ct_res.is_err()) return;

        Bytes payload(32 + 12 + ct_res.value().ciphertext.size());
        std::memcpy(payload.data(),      session_id_.data.data(), 32);
        std::memcpy(payload.data() + 32, nonce.data(), 12);
        std::memcpy(payload.data() + 44,
                    ct_res.value().ciphertext.data(),
                    ct_res.value().ciphertext.size());

        // Serialise writes — use a shared mutex-protected queue
        {
            std::lock_guard lk(send_mu_);
            send_queue_.push_back(std::move(payload));
            if (!sending_) { sending_ = true; do_send(); }
        }
    }

    void do_send() {
        // Must be called with send_mu_ held
        if (send_queue_.empty()) { sending_ = false; return; }
        auto wire = std::make_shared<Bytes>(5 + send_queue_.front().size());
        write_be32(wire->data(), static_cast<uint32_t>(send_queue_.front().size()));
        (*wire)[4] = static_cast<uint8_t>(MsgType::SESSION_DATA);
        std::memcpy(wire->data() + 5,
                    send_queue_.front().data(),
                    send_queue_.front().size());
        send_queue_.pop_front();

        auto self = shared_from_this();
        asio::async_write(*epn_sock_, asio::buffer(*wire),
            [self, wire](std::error_code, size_t) {
                std::lock_guard lk(self->send_mu_);
                self->do_send();
            });
    }

    void remove_stream(uint32_t sid) {
        std::lock_guard lk(streams_mu_);
        auto it = streams_.find(sid);
        if (it != streams_.end()) {
            std::error_code ec;
            it->second->sock.shutdown(tcp::socket::shutdown_both, ec);
            it->second->sock.close(ec);
            streams_.erase(it);
        }
    }

    void close_all_streams() {
        std::lock_guard lk(streams_mu_);
        for (auto& [id, s] : streams_) {
            std::error_code ec;
            s->sock.shutdown(tcp::socket::shutdown_both, ec);
            s->sock.close(ec);
        }
        streams_.clear();
        std::error_code ec;
        epn_sock_->cancel(ec);
    }

    asio::io_context&            ioc_;
    std::shared_ptr<tcp::socket> epn_sock_;
    SessionId                    session_id_;
    RawSessionKey                key_fwd_{};
    RawSessionKey                key_bwd_{};
    NonceCounter                 bwd_nonce_;

    std::mutex                   streams_mu_;
    std::unordered_map<uint32_t, std::shared_ptr<RemoteStream>> streams_;

    std::mutex                   send_mu_;
    std::deque<Bytes>            send_queue_;
    bool                         sending_{false};
};

// ─── main ─────────────────────────────────────────────────────────────────────
int main(int argc, char** argv) {
    CLI::App app{"EPN Tunnel Server"};
    int         port      = 9200;
    int         disc_port = 8000;
    std::string disc_host = "127.0.0.1";
    std::string bind_addr = "127.0.0.1";
    bool        debug     = false;

    app.add_option("-p,--port",     port,      "Listen port")->default_val(9200);
    app.add_option("--disc-host",   disc_host, "Discovery host")->default_val("127.0.0.1");
    app.add_option("--disc-port",   disc_port, "Discovery port")->default_val(8000);
    app.add_option("--bind",        bind_addr, "Bind address")->default_val("127.0.0.1");
    app.add_flag  ("-d,--debug",    debug,     "Debug logging");
    CLI11_PARSE(app, argc, argv);

    observability::init_logger("epn-tun-server", debug);
    if (sodium_init() < 0) { LOG_CRITICAL("libsodium init failed"); return 1; }

    LOG_INFO("EPN Tunnel Server starting on {}:{}", bind_addr, port);

    auto kp_res = generate_x25519_keypair();
    auto sign_kp_res = generate_signing_keypair();
    if (kp_res.is_err() || sign_kp_res.is_err()) {
        LOG_CRITICAL("Key generation failed"); return 1;
    }
    auto& kp      = kp_res.value();
    auto& sign_kp = sign_kp_res.value();

    NodeId node_id = pubkey_to_node_id(kp.pubkey);
    LOG_INFO("node_id:   {}", to_hex({node_id.data.data(), 8}));
    LOG_INFO("dh_pubkey: {}", to_hex({kp.pubkey.data(), 16}));

    // Register with discovery
    discovery::DiscoveryClient disc(disc_host, static_cast<uint16_t>(disc_port));
    discovery::NodeAnnouncement ann;
    ann.node_id_hex = to_hex({node_id.data.data(), 32});
    ann.role        = NodeRole::TunnelServer;
    ann.addr        = bind_addr;
    ann.port        = static_cast<uint16_t>(port);
    ann.dh_pubkey   = kp.pubkey;
    ann.sign_pubkey = sign_kp.pubkey;
    ann.timestamp   = now_unix();
    ann.ttl         = DISCOVERY_TTL_SECS;

    auto reg = disc.register_node(ann, sign_kp);
    if (reg.is_err()) LOG_WARN("Discovery reg failed: {} — continuing", reg.error());
    else              LOG_INFO("Registered with discovery");

    const int threads = static_cast<int>(std::max(2u, std::thread::hardware_concurrency()));
    asio::io_context ioc(threads);

    EphemeralKeyTracker epk_tracker(120);

    // Periodic re-registration
    asio::steady_timer reg_timer(ioc);
    std::function<void()> rereg = [&]() {
        reg_timer.expires_after(std::chrono::seconds(DISCOVERY_TTL_SECS / 2));
        reg_timer.async_wait([&](std::error_code ec) {
            if (ec) return;
            ann.timestamp = now_unix();
            disc.register_node(ann, sign_kp);
            rereg();
        });
    };
    rereg();

    // Accept EPN connections
    tcp::acceptor acceptor(ioc, tcp::endpoint(tcp::v4(), static_cast<uint16_t>(port)));
    acceptor.set_option(asio::socket_base::reuse_address(true));
    LOG_INFO("Tunnel server: listening for EPN connections");

    std::function<void()> do_accept = [&]() {
        acceptor.async_accept([&](std::error_code ec, tcp::socket raw_sock) {
            if (ec) {
                if (ec != asio::error::operation_aborted)
                    LOG_ERROR("Accept: {}", ec.message());
                return;
            }
            std::error_code oe;
            raw_sock.set_option(tcp::no_delay(true), oe);
            auto sock = std::make_shared<tcp::socket>(std::move(raw_sock));

            // Read onion setup frame
            read_one_frame(sock, [&ioc, &kp, &epk_tracker, sock]
                (std::error_code ec, Frame f) mutable {
                    if (ec || f.type != MsgType::ONION_FORWARD) {
                        LOG_DEBUG("TunServer: bad setup frame"); return;
                    }
                    auto& wire = f.payload;
                    if (wire.size() < 32) return;

                    RawPublicKey epk;
                    std::memcpy(epk.data(), wire.data(), 32);
                    if (!epk_tracker.check_and_insert(epk)) {
                        LOG_WARN("TunServer: replay detected"); return;
                    }

                    auto peel_res = peel_onion(kp.privkey, {wire.data(), wire.size()});
                    if (peel_res.is_err() || peel_res.value().hop_type != HopType::FINAL) {
                        LOG_WARN("TunServer: onion peel failed"); return;
                    }
                    auto& peeled = peel_res.value();

                    // Derive E2E session keys
                    auto dh_res = x25519_dh(kp.privkey, epk);
                    if (dh_res.is_err()) return;
                    auto sk_res = derive_session_keys(dh_res.value(), epk, kp.pubkey);
                    if (sk_res.is_err()) return;
                    auto& sk = sk_res.value();

                    LOG_INFO("TunServer: tunnel session established sid={}",
                             to_hex({peeled.session_id.data.data(), 4}));

                    // Send ROUTE_READY
                    write_frame(sock, make_route_ready(peeled.session_id));

                    auto session = std::make_shared<TunnelServerSession>(
                        ioc, sock,
                        peeled.session_id,
                        sk.forward, sk.backward);
                    session->start();
                });
            do_accept();
        });
    };
    do_accept();

    asio::signal_set sigs(ioc, SIGINT, SIGTERM);
    sigs.async_wait([&](std::error_code, int s) {
        LOG_INFO("TunServer: signal {}, shutting down", s);
        acceptor.close();
        ioc.stop();
    });

    std::vector<std::thread> pool;
    for (int i = 0; i < threads - 1; ++i)
        pool.emplace_back([&ioc] { ioc.run(); });
    ioc.run();
    for (auto& t : pool) t.join();

    LOG_INFO("Tunnel server: stopped");
    sodium_memzero(const_cast<uint8_t*>(kp.privkey.data()), 32);
    return 0;
}
