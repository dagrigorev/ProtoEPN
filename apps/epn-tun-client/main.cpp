// epn-tun-client: SOCKS5 proxy + EPN transparent tunnel
//
// Usage:
//   ./epn-tun-client --disc-port 8000 --socks-port 1080
//
// Configure any SOCKS5-aware client (curl, browser, etc.):
//   curl --socks5 127.0.0.1:1080 https://example.com
//
// Architecture:
//   SOCKS5 client → localhost:1080 (this process)
//     → STREAM_OPEN (via EPN onion route, encrypted E2E)
//       → epn-tun-server → TCP → real server
//         → STREAM_DATA back → SOCKS5 client
//
// Single persistent EPN session handles all SOCKS5 connections (multiplexed).

#include <epn/crypto/keys.hpp>
#include <epn/crypto/aead.hpp>
#include <epn/crypto/kdf.hpp>
#include <epn/protocol/framing.hpp>
#include <epn/protocol/onion.hpp>
#include <epn/tunnel/protocol.hpp>
#include <epn/discovery/client.hpp>
#include <epn/routing/route.hpp>
#include <epn/observability/log.hpp>

#include <asio.hpp>
#include <CLI/CLI.hpp>
#include <sodium.h>

#include <atomic>
#include <condition_variable>
#include <csignal>
#include <cstring>
#include <functional>
#include <random>
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
using namespace epn::routing;
using asio::ip::tcp;

static std::atomic<bool> g_running{true};

// ─── Async write helpers ──────────────────────────────────────────────────────
static void async_write_buf(
    std::shared_ptr<tcp::socket> sock,
    Bytes data,
    std::function<void(std::error_code)> cb = {})
{
    auto buf = std::make_shared<Bytes>(std::move(data));
    asio::async_write(*sock, asio::buffer(*buf),
        [buf, cb=std::move(cb)](std::error_code ec, size_t) { if (cb) cb(ec); });
}

// ─── LocalStream: one SOCKS5 client connection ────────────────────────────────
struct LocalStream {
    uint32_t id;
    std::shared_ptr<tcp::socket> sock;   // SOCKS5 client connection
    std::array<uint8_t, 65536> buf{};

    // Open ACK synchronization
    std::mutex              ack_mu;
    std::condition_variable ack_cv;
    bool                    ack_received{false};
    OpenResult              ack_result{OpenResult::GENERAL_ERROR};

    LocalStream(uint32_t i, std::shared_ptr<tcp::socket> s)
        : id(i), sock(std::move(s)) {}
};

// ─── EpnTunnel: manages persistent EPN session + all local streams ─────────────
class EpnTunnel : public std::enable_shared_from_this<EpnTunnel> {
public:
    EpnTunnel(asio::io_context& ioc,
              const std::string& disc_host, int disc_port)
        : ioc_(ioc)
        , disc_(disc_host, static_cast<uint16_t>(disc_port))
        , planner_(disc_)
        , fwd_nonce_(NONCE_DIRECTION_FORWARD)
        , next_stream_id_(1)   // odd = client-initiated
    {}

    // Establish EPN route to tunnel server. Blocks until ready or error.
    bool connect(int num_relays = 3) {
        LOG_INFO("EpnTunnel: discovering route ({} relays)...", num_relays);

        // Dummy payload for route setup (tunnel servers ignore initial payload)
        Bytes dummy = {'E','P','N','-','T','U','N','N','E','L'};
        // Query TunnelServer nodes specifically (not echo/application servers)
        auto servers_res = disc_.query_nodes(NodeRole::TunnelServer);
        if (servers_res.is_err() || servers_res.value().empty()) {
            LOG_WARN("EpnTunnel: no TunnelServer found, trying Server role");
            servers_res = disc_.query_nodes(NodeRole::Server);
        }
        if (servers_res.is_err() || servers_res.value().empty()) {
            LOG_ERROR("EpnTunnel: no server nodes found in discovery");
            return false;
        }
        std::mt19937_64 _rng(std::random_device{}());
        std::uniform_int_distribution<size_t> _pick(0, servers_res.value().size()-1);
        const auto& _srv = servers_res.value()[_pick(_rng)];
        auto route_res = planner_.build_route_to(_srv.node_id_hex,
                                                  {dummy.data(), dummy.size()},
                                                  static_cast<size_t>(num_relays));
        if (route_res.is_err()) {
            LOG_ERROR("EpnTunnel: route build failed: {}", route_res.error());
            return false;
        }
        auto& route = route_res.value();
        session_id_ = route.session_id;
        std::memcpy(key_fwd_.data(), route.server_session_key.forward.data(), 32);
        std::memcpy(key_bwd_.data(), route.server_session_key.backward.data(), 32);

        LOG_INFO("EpnTunnel: route built — sid={}, entry={}:{}",
                 to_hex({session_id_.data.data(), 8}),
                 route.entry_point.addr, route.entry_point.port);

        // Connect to relay1
        std::error_code connect_ec;
        {
            std::mutex m; std::condition_variable cv; bool done = false;
            auto resolver = std::make_shared<tcp::resolver>(ioc_);
            resolver->async_resolve(route.entry_point.addr,
                std::to_string(route.entry_point.port),
                [&, resolver](std::error_code ec, tcp::resolver::results_type eps) mutable {
                    if (ec) {
                        connect_ec = ec;
                        std::lock_guard lk(m); done = true; cv.notify_all(); return;
                    }
                    auto s = std::make_shared<tcp::socket>(ioc_);
                    asio::async_connect(*s, eps,
                        [&, s](std::error_code ec2, const tcp::endpoint&) mutable {
                            if (!ec2) {
                                std::error_code oe;
                                s->set_option(tcp::no_delay(true), oe);
                                epn_sock_ = s;
                            }
                            connect_ec = ec2;
                            std::lock_guard lk(m); done = true; cv.notify_all();
                        });
                });
            std::unique_lock lk(m);
            cv.wait_for(lk, std::chrono::seconds(5), [&]{ return done; });
        }

        if (connect_ec || !epn_sock_) {
            LOG_ERROR("EpnTunnel: connect failed: {}", connect_ec.message());
            return false;
        }

        // Send onion packet
        async_write_buf(epn_sock_,
            encode_frame(Frame{MsgType::ONION_FORWARD, std::move(route.onion_packet)}));

        // Wait for ROUTE_READY
        {
            std::mutex m; std::condition_variable cv;
            bool ready = false; bool failed = false;
            read_one_raw_frame(epn_sock_,
                [&](std::error_code ec, Frame f) {
                    std::lock_guard lk(m);
                    if (!ec && f.type == MsgType::ROUTE_READY) ready = true;
                    else failed = true;
                    cv.notify_all();
                });
            std::unique_lock lk(m);
            if (!cv.wait_for(lk, std::chrono::seconds(10), [&]{ return ready || failed; })) {
                LOG_ERROR("EpnTunnel: ROUTE_READY timeout");
                return false;
            }
            if (failed) {
                LOG_ERROR("EpnTunnel: ROUTE_READY failed");
                return false;
            }
        }

        LOG_INFO("EpnTunnel: tunnel established ✓");
        return true;
    }

    // Start receive loop (must be called after connect())
    void start_recv() { recv_loop(); }

    // Open a stream to target host:port through the EPN tunnel.
    // Returns stream_id on success, 0 on failure.
    uint32_t open_stream(const std::string& host, uint16_t port,
                         std::shared_ptr<tcp::socket> local_sock)
    {
        uint32_t sid = next_stream_id_.fetch_add(2); // odd IDs
        auto stream = std::make_shared<LocalStream>(sid, std::move(local_sock));
        {
            std::lock_guard lk(streams_mu_);
            streams_[sid] = stream;
        }

        // Send STREAM_OPEN
        Bytes open_payload = make_open_payload(host, port);
        send_tunnel(sid, TunnelCmd::STREAM_OPEN, {open_payload.data(), open_payload.size()});
        LOG_DEBUG("EpnTunnel: STREAM_OPEN {} → {}:{}", sid, host, port);

        // Wait for ACK (5s)
        {
            std::unique_lock lk(stream->ack_mu);
            if (!stream->ack_cv.wait_for(lk, std::chrono::seconds(10),
                                          [&]{ return stream->ack_received; })) {
                LOG_WARN("EpnTunnel: stream {} open timeout", sid);
                remove_stream(sid);
                return 0;
            }
        }

        if (stream->ack_result != OpenResult::OK) {
            LOG_WARN("EpnTunnel: stream {} refused ({})", sid,
                     static_cast<int>(stream->ack_result));
            remove_stream(sid);
            return 0;
        }

        LOG_INFO("EpnTunnel: stream {} open OK → {}:{}", sid, host, port);
        return sid;
    }

    // Pump data from local SOCKS5 socket to EPN tunnel (call after open_stream succeeds)
    void pump_from_local(uint32_t sid) {
        std::shared_ptr<LocalStream> stream;
        {
            std::lock_guard lk(streams_mu_);
            auto it = streams_.find(sid);
            if (it == streams_.end()) return;
            stream = it->second;
        }
        auto self = shared_from_this();
        stream->sock->async_read_some(asio::buffer(stream->buf),
            [self, stream, sid](std::error_code ec, size_t n) {
                if (ec || n == 0) {
                    LOG_DEBUG("EpnTunnel: local stream {} closed", sid);
                    self->send_tunnel(sid, TunnelCmd::STREAM_CLOSE, {});
                    self->remove_stream(sid);
                    return;
                }
                self->send_tunnel(sid, TunnelCmd::STREAM_DATA,
                    {stream->buf.data(), n});
                self->pump_from_local(sid);
            });
    }

    void close_stream(uint32_t sid) {
        send_tunnel(sid, TunnelCmd::STREAM_CLOSE, {});
        remove_stream(sid);
    }

    bool is_connected() const { return epn_sock_ && epn_sock_->is_open(); }

private:
    // ── One-shot async frame read (used for ROUTE_READY) ─────────────────────
    void read_one_raw_frame(
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

    // ── Continuous receive loop: SESSION_DATA → dispatch to local streams ─────
    void recv_loop() {
        auto self = shared_from_this();
        read_one_raw_frame(epn_sock_,
            [self](std::error_code ec, Frame f) {
                if (ec) {
                    if (g_running) LOG_WARN("EpnTunnel: recv error: {}", ec.message());
                    return;
                }
                if (f.type == MsgType::SESSION_DATA) self->on_session_data(std::move(f.payload));
                else if (f.type == MsgType::KEEPALIVE) {
                    // echo back
                    async_write_buf(self->epn_sock_,
                        encode_frame(make_keepalive()));
                }
                self->recv_loop();
            });
    }

    void on_session_data(Bytes payload) {
        if (payload.size() < SESSION_HEADER_SIZE) return;
        RawNonce nonce;
        std::memcpy(nonce.data(), payload.data() + 32, 12);
        ByteSpan ct(payload.data() + SESSION_HEADER_SIZE,
                    payload.size() - SESSION_HEADER_SIZE);

        auto pt_res = aead_decrypt(key_bwd_, nonce, ct);
        if (pt_res.is_err()) {
            LOG_WARN("EpnTunnel: decrypt failed: {}", pt_res.error()); return;
        }

        auto tf_res = decode_tunnel_frame({pt_res.value().data(), pt_res.value().size()});
        if (tf_res.is_err()) { LOG_WARN("EpnTunnel: bad frame"); return; }
        auto& tf = tf_res.value();

        switch (tf.cmd) {
        case TunnelCmd::STREAM_OPEN_ACK: on_open_ack(tf.stream_id, tf.data); break;
        case TunnelCmd::STREAM_DATA:     on_data(tf.stream_id, std::move(tf.data)); break;
        case TunnelCmd::STREAM_CLOSE:    on_close(tf.stream_id); break;
        default: break;
        }
    }

    void on_open_ack(uint32_t sid, const Bytes& data) {
        std::shared_ptr<LocalStream> stream;
        {
            std::lock_guard lk(streams_mu_);
            auto it = streams_.find(sid);
            if (it == streams_.end()) return;
            stream = it->second;
        }
        std::lock_guard lk(stream->ack_mu);
        stream->ack_result   = data.empty() ? OpenResult::GENERAL_ERROR
                                             : static_cast<OpenResult>(data[0]);
        stream->ack_received = true;
        stream->ack_cv.notify_all();
    }

    void on_data(uint32_t sid, Bytes data) {
        std::shared_ptr<LocalStream> stream;
        {
            std::lock_guard lk(streams_mu_);
            auto it = streams_.find(sid);
            if (it == streams_.end()) return;
            stream = it->second;
        }
        async_write_buf(stream->sock, std::move(data));
    }

    void on_close(uint32_t sid) {
        LOG_DEBUG("EpnTunnel: stream {} closed by server", sid);
        std::shared_ptr<LocalStream> stream;
        {
            std::lock_guard lk(streams_mu_);
            auto it = streams_.find(sid);
            if (it == streams_.end()) return;
            stream = it->second;
        }
        std::error_code ec;
        stream->sock->shutdown(tcp::socket::shutdown_both, ec);
        stream->sock->close(ec);
        remove_stream(sid);
    }

    // ── Send encrypted tunnel frame to server ─────────────────────────────────
    void send_tunnel(uint32_t sid, TunnelCmd cmd, ByteSpan data) {
        Bytes tf = encode_tunnel_frame(sid, cmd, data);
        auto nonce = fwd_nonce_.next();
        auto ct_res = aead_encrypt_with_nonce(key_fwd_, nonce,
                                               {tf.data(), tf.size()});
        if (ct_res.is_err()) return;

        Bytes payload(32 + 12 + ct_res.value().ciphertext.size());
        std::memcpy(payload.data(),      session_id_.data.data(), 32);
        std::memcpy(payload.data() + 32, nonce.data(), 12);
        std::memcpy(payload.data() + 44,
                    ct_res.value().ciphertext.data(),
                    ct_res.value().ciphertext.size());

        std::lock_guard lk(send_mu_);
        send_queue_.push_back(std::move(payload));
        if (!sending_) { sending_ = true; do_send_locked(); }
    }

    void do_send_locked() {
        if (send_queue_.empty()) { sending_ = false; return; }
        Bytes& front = send_queue_.front();
        auto wire = std::make_shared<Bytes>(5 + front.size());
        write_be32(wire->data(), static_cast<uint32_t>(front.size()));
        (*wire)[4] = static_cast<uint8_t>(MsgType::SESSION_DATA);
        std::memcpy(wire->data() + 5, front.data(), front.size());
        send_queue_.pop_front();

        auto self = shared_from_this();
        asio::async_write(*epn_sock_, asio::buffer(*wire),
            [self, wire](std::error_code, size_t) {
                std::lock_guard lk(self->send_mu_);
                self->do_send_locked();
            });
    }

    void remove_stream(uint32_t sid) {
        std::lock_guard lk(streams_mu_);
        streams_.erase(sid);
    }

    asio::io_context&            ioc_;
    discovery::DiscoveryClient   disc_;
    RoutePlanner                 planner_;
    std::shared_ptr<tcp::socket> epn_sock_;
    SessionId                    session_id_;
    RawSessionKey                key_fwd_{};
    RawSessionKey                key_bwd_{};
    NonceCounter                 fwd_nonce_;
    std::atomic<uint32_t>        next_stream_id_;

    std::mutex                   streams_mu_;
    std::unordered_map<uint32_t, std::shared_ptr<LocalStream>> streams_;

    std::mutex                   send_mu_;
    std::deque<Bytes>            send_queue_;
    bool                         sending_{false};
};

// ─── SOCKS5 handshake ────────────────────────────────────────────────────────
// Returns {host, port} of the CONNECT target or error.
// RFC 1928 compliant.
static Result<std::pair<std::string, uint16_t>>
socks5_handshake(std::shared_ptr<tcp::socket> sock)
{
    // 1. Read greeting
    std::array<uint8_t, 2> greeting{};
    std::error_code ec;
    asio::read(*sock, asio::buffer(greeting), ec);
    if (ec) return Result<std::pair<std::string, uint16_t>>::err("greeting read: " + ec.message());
    if (greeting[0] != 0x05)
        return Result<std::pair<std::string, uint16_t>>::err("not SOCKS5");

    // Skip method bytes
    uint8_t nmethods = greeting[1];
    std::vector<uint8_t> methods(nmethods);
    if (nmethods > 0) asio::read(*sock, asio::buffer(methods), ec);

    // Reply: no authentication required
    uint8_t reply[2] = {0x05, 0x00};
    asio::write(*sock, asio::buffer(reply), ec);
    if (ec) return Result<std::pair<std::string, uint16_t>>::err("reply write");

    // 2. Read CONNECT request
    std::array<uint8_t, 4> req_hdr{};
    asio::read(*sock, asio::buffer(req_hdr), ec);
    if (ec) return Result<std::pair<std::string, uint16_t>>::err("req read");
    if (req_hdr[0] != 0x05 || req_hdr[1] != 0x01)
        return Result<std::pair<std::string, uint16_t>>::err("only CONNECT supported");

    uint8_t atype = req_hdr[3];
    std::string host;
    uint16_t port = 0;

    if (atype == 0x01) { // IPv4
        std::array<uint8_t, 6> addr_port{};
        asio::read(*sock, asio::buffer(addr_port), ec);
        if (ec) return Result<std::pair<std::string, uint16_t>>::err("ipv4 read");
        host = std::to_string(addr_port[0]) + "." + std::to_string(addr_port[1]) +
               "." + std::to_string(addr_port[2]) + "." + std::to_string(addr_port[3]);
        port = static_cast<uint16_t>((addr_port[4] << 8) | addr_port[5]);

    } else if (atype == 0x03) { // Domain
        uint8_t len = 0;
        asio::read(*sock, asio::buffer(&len, 1), ec);
        std::vector<uint8_t> domain(len + 2);
        asio::read(*sock, asio::buffer(domain), ec);
        if (ec) return Result<std::pair<std::string, uint16_t>>::err("domain read");
        host = std::string(reinterpret_cast<char*>(domain.data()), len);
        port = static_cast<uint16_t>((domain[len] << 8) | domain[len+1]);

    } else if (atype == 0x04) { // IPv6
        std::array<uint8_t, 18> addr_port{};
        asio::read(*sock, asio::buffer(addr_port), ec);
        if (ec) return Result<std::pair<std::string, uint16_t>>::err("ipv6 read");
        char buf[64];
        snprintf(buf, sizeof(buf),
            "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
            "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
            addr_port[0],addr_port[1],addr_port[2],addr_port[3],
            addr_port[4],addr_port[5],addr_port[6],addr_port[7],
            addr_port[8],addr_port[9],addr_port[10],addr_port[11],
            addr_port[12],addr_port[13],addr_port[14],addr_port[15]);
        host = buf;
        port = static_cast<uint16_t>((addr_port[16] << 8) | addr_port[17]);
    } else {
        // Unsupported address type
        uint8_t err_reply[10] = {0x05,0x08,0x00,0x01,0,0,0,0,0,0};
        asio::write(*sock, asio::buffer(err_reply), ec);
        return Result<std::pair<std::string, uint16_t>>::err("unsupported atype");
    }

    return Result<std::pair<std::string, uint16_t>>::ok({host, port});
}

// Send SOCKS5 reply
static void socks5_reply(std::shared_ptr<tcp::socket> sock, bool success) {
    // REP: 0x00=success, 0x05=connection refused
    uint8_t reply[10] = {0x05, success ? 0x00u : 0x05u, 0x00,
                         0x01, 0,0,0,0, 0,0};
    std::error_code ec;
    asio::write(*sock, asio::buffer(reply), ec);
}

// ─── Handle one SOCKS5 client connection ─────────────────────────────────────
static void handle_socks5_client(
    std::shared_ptr<tcp::socket> client_sock,
    std::shared_ptr<EpnTunnel>   tunnel,
    asio::io_context&            ioc)
{
    // Run SOCKS5 handshake synchronously (short, bounded operations)
    auto target = socks5_handshake(client_sock);
    if (target.is_err()) {
        LOG_WARN("SOCKS5: handshake failed: {}", target.error());
        return;
    }
    auto& [host, port] = target.value();
    LOG_INFO("SOCKS5: CONNECT {}:{}", host, port);

    // Open stream through EPN tunnel (blocks until ACK)
    uint32_t sid = tunnel->open_stream(host, port, client_sock);
    if (sid == 0) {
        socks5_reply(client_sock, false);
        return;
    }

    // Inform SOCKS5 client: connection established
    socks5_reply(client_sock, true);

    // Start pumping: local_sock → EPN → remote server
    tunnel->pump_from_local(sid);
    // Reverse direction (remote → EPN → local_sock) handled inside EpnTunnel::on_data
}

// ═══════════════════════════════════════════════════════════════════════════════
// TRANSPARENT PROXY LISTENER
// ═══════════════════════════════════════════════════════════════════════════════
// When iptables redirects all TCP OUTPUT traffic to this port, we use
// SO_ORIGINAL_DST to recover the original destination and route via EPN.
//
// This is automatically included in epn-tun-client's main() when
// --transparent is passed. The function below replaces the SOCKS5 accept loop.

#include <linux/netfilter_ipv4.h>  // SO_ORIGINAL_DST
#include <netinet/in.h>
#include <arpa/inet.h>

static std::pair<std::string, uint16_t>
get_original_dst(int fd) {
    struct sockaddr_in orig{};
    socklen_t len = sizeof(orig);
    if (getsockopt(fd, SOL_IP, SO_ORIGINAL_DST,
                   &orig, &len) < 0) {
        return {"", 0};
    }
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &orig.sin_addr, ip, sizeof(ip));
    return {ip, ntohs(orig.sin_port)};
}

void run_transparent_proxy(
    asio::io_context&          ioc,
    std::shared_ptr<EpnTunnel> tunnel,
    const std::string&         bind_addr,
    uint16_t                   tproxy_port)
{
    tcp::acceptor acceptor(
        ioc,
        tcp::endpoint(asio::ip::make_address(bind_addr), tproxy_port));
    acceptor.set_option(asio::socket_base::reuse_address(true));

    LOG_INFO("Transparent proxy: listening on {}:{}", bind_addr, tproxy_port);
    LOG_INFO("All iptables-redirected TCP will be tunneled via EPN");

    auto do_accept = [&acceptor, tunnel, &ioc]() {
        std::function<void()> accept_fn;
        accept_fn = [&acceptor, tunnel, &ioc, &accept_fn]() {
            acceptor.async_accept([&, tunnel](std::error_code ec, tcp::socket sock) {
                if (ec) return;
                std::error_code oe;
                sock.set_option(tcp::no_delay(true), oe);

                auto client = std::make_shared<tcp::socket>(std::move(sock));
                int  fd     = static_cast<int>(client->native_handle());

                // Recover original destination from iptables REDIRECT
                auto [host, port] = get_original_dst(fd);
                if (host.empty() || port == 0) {
                    LOG_WARN("Transparent: cannot get SO_ORIGINAL_DST");
                    accept_fn();
                    return;
                }

                LOG_INFO("Transparent: intercepted TCP → {}:{}", host, port);

                std::thread([client, tunnel, host, port, &ioc]() mutable {
                    uint32_t sid = tunnel->open_stream(host, port, client);
                    if (sid == 0) {
                        // Send RST to indicate connection failed
                        std::error_code ec2;
                        client->shutdown(tcp::socket::shutdown_both, ec2);
                        return;
                    }
                    tunnel->pump_from_local(sid);
                }).detach();

                accept_fn();
            });
        };
        accept_fn();
    };
    do_accept();
}

// ─── main ─────────────────────────────────────────────────────────────────────
int main(int argc, char** argv) {
    CLI::App app{"EPN Tunnel Client (SOCKS5 proxy)"};
    std::string disc_host  = "127.0.0.1";
    int         disc_port  = 8000;
    std::string socks_bind = "127.0.0.1";
    int         socks_port = 1080;
    int         num_relays = 3;
    bool        debug      = false;

    bool        transparent = false;
    int         tproxy_port = 1081;

    app.add_option("--disc-host",   disc_host,  "Discovery host")->default_val("127.0.0.1");
    app.add_option("--disc-port",   disc_port,  "Discovery port")->default_val(8000);
    app.add_option("--socks-bind",  socks_bind, "SOCKS5 bind address")->default_val("127.0.0.1");
    app.add_option("--socks-port",  socks_port, "SOCKS5 listen port")->default_val(1080);
    app.add_option("-r,--relays",   num_relays, "Relay hops (≥3)")->default_val(3);
    app.add_flag  ("--transparent", transparent,
        "Transparent proxy mode (requires iptables REDIRECT setup via epn-tun-dev)");
    app.add_option("--tproxy-port", tproxy_port,
        "Transparent proxy listen port")->default_val(1081);
    app.add_flag  ("-d,--debug",    debug,      "Debug logging");
    CLI11_PARSE(app, argc, argv);

    observability::init_logger("epn-tun-client", debug);
    if (sodium_init() < 0) { LOG_CRITICAL("libsodium init failed"); return 1; }

    LOG_INFO("EPN Tunnel Client starting");
    LOG_INFO("  SOCKS5: {}:{}", socks_bind, socks_port);
    LOG_INFO("  Discovery: {}:{}", disc_host, disc_port);
    LOG_INFO("  Relays: {}", num_relays);

    const int threads = static_cast<int>(std::max(2u, std::thread::hardware_concurrency()));
    asio::io_context ioc(threads);

    // Start io_context thread pool FIRST — connect() uses async ops
    auto work = asio::make_work_guard(ioc);
    std::vector<std::thread> pool;
    for (int i = 0; i < threads; ++i)
        pool.emplace_back([&ioc] { ioc.run(); });

    // Build EPN tunnel (io_context now running in background)
    auto tunnel = std::make_shared<EpnTunnel>(ioc, disc_host, disc_port);
    if (!tunnel->connect(num_relays)) {
        LOG_CRITICAL("Failed to establish EPN tunnel");
        ioc.stop();
        for (auto& t : pool) t.join();
        return 1;
    }
    tunnel->start_recv();

    // SOCKS5 listener
    tcp::acceptor socks_acceptor(
        ioc, tcp::endpoint(
            asio::ip::make_address(socks_bind),
            static_cast<uint16_t>(socks_port)));
    socks_acceptor.set_option(asio::socket_base::reuse_address(true));

    if (transparent) {
        LOG_INFO("Transparent proxy mode — port {}", tproxy_port);
        LOG_INFO("Setup iptables with: sudo epn-tun-dev setup --tproxy-port {}", tproxy_port);
        run_transparent_proxy(ioc, tunnel, socks_bind, static_cast<uint16_t>(tproxy_port));
    } else {
        LOG_INFO("SOCKS5 proxy ready — configure clients to use {}:{}", socks_bind, socks_port);
        LOG_INFO("Example: curl --socks5 {}:{} https://example.com", socks_bind, socks_port);
    }

    std::function<void()> do_accept = [&]() {
        if (transparent) { return; } // Transparent mode has its own acceptor
        socks_acceptor.async_accept([&](std::error_code ec, tcp::socket sock) {
            if (ec) {
                if (ec != asio::error::operation_aborted)
                    LOG_ERROR("SOCKS5 accept: {}", ec.message());
                return;
            }
            std::error_code oe;
            sock.set_option(tcp::no_delay(true), oe);
            auto client = std::make_shared<tcp::socket>(std::move(sock));

            // Handle each SOCKS5 client in a detached thread
            // (handshake is sync, then async pump takes over)
            std::thread([client, tunnel, &ioc]() mutable {
                handle_socks5_client(client, tunnel, ioc);
            }).detach();

            do_accept();
        });
    };
    do_accept();

    asio::signal_set sigs(ioc, SIGINT, SIGTERM);
    sigs.async_wait([&](std::error_code, int s) {
        LOG_INFO("EPN Tunnel: signal {}, shutting down", s);
        g_running = false;
        socks_acceptor.close();
        work.reset();
        ioc.stop();
    });

    // Main thread also contributes to the io_context
    ioc.run();
    for (auto& t : pool) t.join();

    LOG_INFO("EPN Tunnel Client: stopped");
    return 0;
}

