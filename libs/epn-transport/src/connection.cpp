#include <epn/transport/connection.hpp>
#include <epn/observability/log.hpp>
#include <cstring>

namespace epn::transport {

// ─── TcpConnection ────────────────────────────────────────────────────────────

void TcpConnection::start_reading(FrameHandler on_frame, ErrorHandler on_error) {
    on_frame_ = std::move(on_frame);
    on_error_ = std::move(on_error);
    do_read_header();
}

void TcpConnection::do_read_header() {
    auto self = shared_from_this();
    asio::async_read(
        socket_,
        asio::buffer(header_buf_),
        asio::bind_executor(strand_,
            [this, self](std::error_code ec, size_t) {
                if (ec) { if (on_error_) on_error_(ec); return; }
                uint32_t plen = core::read_be32(header_buf_.data());
                auto     type = static_cast<MsgType>(header_buf_[4]);
                if (plen > MAX_FRAME_SIZE) {
                    LOG_WARN("Frame too large: {} bytes", plen);
                    if (on_error_) on_error_(asio::error::message_size);
                    return;
                }
                do_read_payload(plen, type);
            }));
}

void TcpConnection::do_read_payload(uint32_t plen, MsgType type) {
    auto self = shared_from_this();
    if (plen == 0) {
        if (on_frame_) on_frame_(Frame{type, {}});
        do_read_header();
        return;
    }
    read_buf_.resize(plen);
    asio::async_read(
        socket_,
        asio::buffer(read_buf_),
        asio::bind_executor(strand_,
            [this, self, type](std::error_code ec, size_t) {
                if (ec) { if (on_error_) on_error_(ec); return; }
                if (on_frame_) on_frame_(Frame{type, read_buf_});
                do_read_header();
            }));
}

void TcpConnection::write_frame(Frame f) {
    auto wire = std::make_shared<Bytes>(encode_frame(f));
    auto self = shared_from_this();
    asio::post(strand_, [this, self, wire]() mutable {
        write_queue_.push_back(std::move(*wire));
        if (!writing_) do_write_next();
    });
}

void TcpConnection::write_frame(Frame f, std::function<void(std::error_code)> /*on_done*/) {
    write_frame(std::move(f));
}

void TcpConnection::write_raw(Bytes data) {
    auto wire = std::make_shared<Bytes>(std::move(data));
    auto self = shared_from_this();
    asio::post(strand_, [this, self, wire]() mutable {
        write_queue_.push_back(std::move(*wire));
        if (!writing_) do_write_next();
    });
}

void TcpConnection::do_write_next() {
    if (write_queue_.empty()) { writing_ = false; return; }
    writing_ = true;
    auto self = shared_from_this();
    asio::async_write(
        socket_,
        asio::buffer(write_queue_.front()),
        asio::bind_executor(strand_,
            [this, self](std::error_code ec, size_t) {
                write_queue_.pop_front();
                if (ec) { if (on_error_) on_error_(ec); return; }
                do_write_next();
            }));
}

void TcpConnection::start_raw_proxy(std::shared_ptr<TcpConnection> peer) {
    proxy_self_buf_.resize(PROXY_BUF_SIZE);
    proxy_peer_buf_.resize(PROXY_BUF_SIZE);
    proxy_read_from_self(peer);
    proxy_read_from_peer(peer);
}

void TcpConnection::proxy_read_from_self(std::shared_ptr<TcpConnection> peer) {
    auto self = shared_from_this();
    socket_.async_read_some(
        asio::buffer(proxy_self_buf_),
        [this, self, peer](std::error_code ec, size_t n) {
            if (ec || n == 0) { peer->close(); return; }
            Bytes d(proxy_self_buf_.begin(),
                    proxy_self_buf_.begin() + static_cast<ptrdiff_t>(n));
            peer->write_raw(std::move(d));
            proxy_read_from_self(peer);
        });
}

void TcpConnection::proxy_read_from_peer(std::shared_ptr<TcpConnection> peer) {
    auto self = shared_from_this();
    peer->socket_.async_read_some(
        asio::buffer(proxy_peer_buf_),
        [this, self, peer](std::error_code ec, size_t n) {
            if (ec || n == 0) { close(); return; }
            Bytes d(proxy_peer_buf_.begin(),
                    proxy_peer_buf_.begin() + static_cast<ptrdiff_t>(n));
            write_raw(std::move(d));
            proxy_read_from_peer(peer);
        });
}

void TcpConnection::close() {
    asio::post(strand_, [self = shared_from_this()]() {
        if (self->socket_.is_open()) {
            std::error_code ec;
            self->socket_.shutdown(tcp::socket::shutdown_both, ec);
            self->socket_.close(ec);
        }
    });
}

// ─── TcpServer ────────────────────────────────────────────────────────────────

void TcpServer::do_accept() {
    acceptor_.async_accept([this](std::error_code ec, tcp::socket sock) {
        if (ec) {
            if (ec != asio::error::operation_aborted)
                LOG_ERROR("Accept error: {}", ec.message());
            return;
        }
        sock.set_option(tcp::no_delay(true));
        auto conn = std::make_shared<TcpConnection>(std::move(sock));
        if (on_accept_) on_accept_(std::move(conn));
        do_accept();
    });
}

// ─── async_connect ────────────────────────────────────────────────────────────

void async_connect(
    asio::io_context&  ioc,
    const std::string& addr,
    uint16_t           port,
    std::function<void(std::error_code, std::shared_ptr<TcpConnection>)> on_done)
{
    auto resolver = std::make_shared<tcp::resolver>(ioc);
    resolver->async_resolve(addr, std::to_string(port),
        [&ioc, on_done = std::move(on_done), resolver]
        (std::error_code ec, tcp::resolver::results_type results) mutable {
            if (ec) { on_done(ec, nullptr); return; }
            auto conn = std::make_shared<TcpConnection>(ioc);
            asio::async_connect(conn->socket(), results,
                [on_done = std::move(on_done), conn]
                (std::error_code ec2, const tcp::endpoint&) mutable {
                    if (!ec2) {
                        std::error_code opt_ec;
                        conn->socket().set_option(tcp::no_delay(true), opt_ec);
                    }
                    on_done(ec2, ec2 ? nullptr : conn);
                });
        });
}

} // namespace epn::transport
