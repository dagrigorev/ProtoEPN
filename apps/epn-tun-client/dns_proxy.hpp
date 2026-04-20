#pragma once
// DNS Proxy: runs alongside SOCKS5/transparent mode
// Intercepts UDP port 53 and tunnels DNS queries via EPN TCP streams
// Prevents DNS leaks in transparent proxy mode

#include <epn/tunnel/protocol.hpp>
#include <epn/observability/log.hpp>

#include <asio.hpp>
#include <memory>
#include <functional>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <cstring>

using namespace epn;
using namespace epn::core;
using namespace epn::tunnel;
using asio::ip::udp;
using asio::ip::tcp;

// Forward declaration
class EpnTunnel;

// ─── DNS-over-TCP proxy ───────────────────────────────────────────────────────
// Listens on UDP :5353 (or :53 with root)
// Each DNS query → EPN STREAM_OPEN upstream:53 → TCP DNS → response → UDP reply
class DnsProxy {
public:
    DnsProxy(asio::io_context& ioc,
             std::shared_ptr<EpnTunnel> tunnel,
             const std::string& upstream = "1.1.1.1",
             uint16_t listen_port = 5353)
        : ioc_(ioc)
        , tunnel_(std::move(tunnel))
        , upstream_(upstream)
        , socket_(ioc, udp::endpoint(udp::v4(), listen_port))
    {
        socket_.set_option(asio::socket_base::reuse_address(true));
        LOG_INFO("DNS proxy: UDP :{} → {} via EPN", listen_port, upstream);
    }

    void start() { recv_loop(); }

    // Called when STREAM_DATA arrives for a DNS stream_id
    void on_stream_data(uint32_t sid, const Bytes& data) {
        std::lock_guard lk(mu_);
        auto it = pending_.find(sid);
        if (it == pending_.end()) return;

        auto& buf = it->second.tcp_buf;
        buf.insert(buf.end(), data.begin(), data.end());

        // DNS-over-TCP: first 2 bytes = message length
        if (buf.size() < 2) return;
        uint16_t msg_len = static_cast<uint16_t>((buf[0] << 8) | buf[1]);
        if (buf.size() < static_cast<size_t>(2 + msg_len)) return;

        // Complete DNS response received
        Bytes dns_response(buf.begin() + 2, buf.begin() + 2 + msg_len);
        udp::endpoint src = it->second.src;
        pending_.erase(it);

        LOG_DEBUG("DNS: response {} bytes → {}:{}", dns_response.size(),
                  src.address().to_string(), src.port());

        // Send UDP response back to original querier
        auto resp = std::make_shared<Bytes>(std::move(dns_response));
        socket_.async_send_to(asio::buffer(*resp), src,
            [resp](std::error_code, size_t) {});
    }

    void on_stream_close(uint32_t sid) {
        std::lock_guard lk(mu_);
        pending_.erase(sid);
    }

private:
    struct PendingDns {
        udp::endpoint src;
        Bytes         tcp_buf;
    };

    void recv_loop() {
        auto src  = std::make_shared<udp::endpoint>();
        auto buf  = std::make_shared<std::array<uint8_t, 512>>();
        socket_.async_receive_from(asio::buffer(*buf), *src,
            [this, src, buf](std::error_code ec, size_t n) {
                if (!ec && n > 0) {
                    handle_query({buf->data(), n}, *src);
                }
                recv_loop();
            });
    }

    void handle_query(ByteSpan query, udp::endpoint src) {
        if (query.size() < 12) return; // Minimum DNS header

        LOG_DEBUG("DNS query {} bytes from {}:{}", query.size(),
                  src.address().to_string(), src.port());

        // Open EPN stream to upstream DNS resolver via TCP
        auto query_copy = std::make_shared<Bytes>(query.begin(), query.end());
        auto self = this;

        // STREAM_OPEN is blocking in current EpnTunnel implementation
        // Post to thread to avoid blocking the io_context
        std::thread([this, query_copy, src]() {
            uint32_t sid = open_dns_stream();
            if (sid == 0) {
                LOG_WARN("DNS: could not open EPN stream to {}", upstream_);
                return;
            }
            {
                std::lock_guard lk(mu_);
                pending_[sid].src = src;
            }

            // Wrap DNS query in TCP framing (2-byte length prefix)
            Bytes tcp_frame(2 + query_copy->size());
            tcp_frame[0] = static_cast<uint8_t>((query_copy->size() >> 8) & 0xFF);
            tcp_frame[1] = static_cast<uint8_t>( query_copy->size()        & 0xFF);
            std::memcpy(tcp_frame.data() + 2, query_copy->data(), query_copy->size());

            send_to_stream_(sid, {tcp_frame.data(), tcp_frame.size()});
        }).detach();
    }

    uint32_t open_dns_stream();  // Implemented in tun-client main.cpp after EpnTunnel def

    asio::io_context&           ioc_;
    std::shared_ptr<EpnTunnel>  tunnel_;
    std::string                 upstream_;
    udp::socket                 socket_;
    std::mutex                  mu_;
    std::unordered_map<uint32_t, PendingDns> pending_;

public:
    // Set by main after tunnel is established
    std::function<uint32_t(const std::string&, uint16_t)> open_stream_fn_;
    std::function<void(uint32_t, ByteSpan)>               send_to_stream_;
};
