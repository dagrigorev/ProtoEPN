#pragma once

#include <epn/core/types.hpp>
#include <epn/core/result.hpp>
#include <epn/protocol/framing.hpp>
#include <epn/protocol/messages.hpp>

#include <asio.hpp>
#include <functional>
#include <memory>
#include <atomic>
#include <mutex>
#include <deque>

namespace epn::transport {

using namespace epn::core;
using namespace epn::protocol;
using asio::ip::tcp;

// ─── Frame callbacks ──────────────────────────────────────────────────────────
using FrameHandler  = std::function<void(Frame)>;
using ErrorHandler  = std::function<void(std::error_code)>;
using ConnectHandler = std::function<void(std::error_code)>;

// ─── TcpConnection ────────────────────────────────────────────────────────────
// Wraps a TCP socket with:
//   - Length-prefixed frame reads (async, non-blocking)
//   - Queued frame writes (serialised via strand)
//   - Graceful close
class TcpConnection : public std::enable_shared_from_this<TcpConnection> {
public:
    explicit TcpConnection(asio::io_context& ioc)
        : socket_(ioc), strand_(asio::make_strand(ioc)) {}

    // Takes ownership of an already-connected socket
    explicit TcpConnection(tcp::socket sock)
        : socket_(std::move(sock))
        , strand_(asio::make_strand(socket_.get_executor())) {}

    tcp::socket& socket() { return socket_; }

    // Start async read loop. Calls on_frame for each complete frame received.
    // Calls on_error on disconnect or protocol error.
    void start_reading(FrameHandler on_frame, ErrorHandler on_error);

    // Write a frame asynchronously (queued; thread-safe)
    void write_frame(Frame f);
    void write_frame(Frame f, std::function<void(std::error_code)> on_done);

    // Write raw bytes (used for proxy mode — no framing overhead)
    void write_raw(Bytes data);

    // Start raw bidirectional proxy to another connection
    // Once started, no frame callbacks are invoked — bytes are forwarded directly
    void start_raw_proxy(std::shared_ptr<TcpConnection> peer);

    void close();
    bool is_open() const { return socket_.is_open(); }

    std::string remote_address() const {
        if (!socket_.is_open()) return "closed";
        try {
            auto ep = socket_.remote_endpoint();
            return ep.address().to_string() + ":" + std::to_string(ep.port());
        } catch (...) { return "unknown"; }
    }

private:
    void do_read_header();
    void do_read_payload(uint32_t payload_len, MsgType type);
    void do_write_next();

    // Raw proxy helpers
    void proxy_read_from_self(std::shared_ptr<TcpConnection> peer);
    void proxy_read_from_peer(std::shared_ptr<TcpConnection> peer);

    tcp::socket               socket_;
    asio::strand<asio::any_io_executor> strand_;

    // Read state
    std::array<uint8_t, 5>   header_buf_{};
    Bytes                     read_buf_;
    FrameHandler              on_frame_;
    ErrorHandler              on_error_;

    // Write queue (protected by strand)
    std::deque<Bytes>         write_queue_;
    bool                      writing_{false};

    // Proxy mode buffers
    static constexpr size_t   PROXY_BUF_SIZE = 65536;
    std::vector<uint8_t>      proxy_self_buf_;
    std::vector<uint8_t>      proxy_peer_buf_;
};

// ─── TcpServer ────────────────────────────────────────────────────────────────
class TcpServer {
public:
    using AcceptHandler = std::function<void(std::shared_ptr<TcpConnection>)>;

    TcpServer(asio::io_context& ioc, uint16_t port)
        : ioc_(ioc)
        , acceptor_(ioc, tcp::endpoint(tcp::v4(), port)) {
        acceptor_.set_option(asio::socket_base::reuse_address(true));
    }

    void start(AcceptHandler on_accept) {
        on_accept_ = std::move(on_accept);
        do_accept();
    }

    uint16_t port() const {
        return acceptor_.local_endpoint().port();
    }

    void stop() { acceptor_.close(); }

private:
    void do_accept();

    asio::io_context& ioc_;
    tcp::acceptor     acceptor_;
    AcceptHandler     on_accept_;
};

// ─── Async connect helper ─────────────────────────────────────────────────────
// Creates a new TcpConnection and connects to addr:port
void async_connect(
    asio::io_context&            ioc,
    const std::string&           addr,
    uint16_t                     port,
    std::function<void(std::error_code, std::shared_ptr<TcpConnection>)> on_done
);

} // namespace epn::transport
