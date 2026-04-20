#pragma once
// epn-dns: DNS leak prevention via EPN tunnel
//
// Runs a local DNS resolver on 127.0.0.1:5353 (or 53 with root).
// All DNS queries are forwarded to a configurable upstream resolver
// THROUGH the EPN tunnel (using STREAM_OPEN to port 53 on the upstream).
//
// Flow:
//   App → getaddrinfo() → OS → 127.0.0.1:5353 (this server)
//   → STREAM_OPEN tcp 1.1.1.1:53 via EPN → real DNS answer → App
//
// DNS-over-TCP (RFC 1035 §4.2.2): length-prefixed DNS messages.
// We also support DNS-over-HTTPS (DoH) as an alternative upstream.
//
// Usage:
//   On Linux:  change /etc/resolv.conf: nameserver 127.0.0.1
//   On Windows: change DNS to 127.0.0.1 in network adapter settings
//   Or use systemd-resolved: resolvectl dns lo 127.0.0.1

#include <epn/core/types.hpp>
#include <epn/core/result.hpp>
#include <functional>
#include <string>
#include <cstdint>

namespace epn::dns {

using namespace epn::core;

// ─── DNS upstream configuration ──────────────────────────────────────────────
struct DnsUpstream {
    std::string  host;       // Upstream resolver IP (e.g. "1.1.1.1", "8.8.8.8")
    uint16_t     port{53};   // Default TCP DNS port
    bool         use_doh{false}; // Use DNS-over-HTTPS instead of plain TCP
    std::string  doh_path{"/dns-query"}; // DoH path (RFC 8484)
};

// ─── DNS message (wire format, length-prefixed for TCP) ───────────────────────
// DNS over TCP: [2B length BE][DNS message]
// DNS over UDP: [DNS message] (no length prefix)

inline Bytes make_dns_tcp_frame(ByteSpan dns_message) {
    if (dns_message.size() > 65535) return {};
    Bytes frame(2 + dns_message.size());
    write_be16(frame.data(), static_cast<uint16_t>(dns_message.size()));
    std::memcpy(frame.data() + 2, dns_message.data(), dns_message.size());
    return frame;
}

// ─── DnsProxy interface ───────────────────────────────────────────────────────
// Forwards DNS queries through the EPN tunnel.
// Caller provides an open_stream_fn that opens an EPN stream to (host, port).

using OpenStreamFn = std::function<
    uint32_t(const std::string& host, uint16_t port)  // returns stream_id or 0 on fail
>;

using SendDataFn = std::function<
    void(uint32_t stream_id, ByteSpan data)
>;

// ─── DNS forwarder state machine ──────────────────────────────────────────────
// Lifecycle per DNS query:
//   1. Receive UDP DNS query from local app (via UDP socket on :5353)
//   2. STREAM_OPEN upstream_resolver:53 via EPN
//   3. Send DNS query as TCP (length-prefixed)
//   4. Receive TCP DNS response (length-prefixed)
//   5. Send DNS response back to local app via UDP
//   6. STREAM_CLOSE

// Query ID → source endpoint mapping (UDP is stateless, we correlate by DNS query ID)
struct PendingQuery {
    uint16_t    query_id;      // DNS message ID (bytes 0-1)
    std::string src_addr;      // Originating IP
    uint16_t    src_port;      // Originating port
    uint32_t    stream_id;     // EPN stream for this query
    int64_t     created_ms;    // For timeout tracking
};

} // namespace epn::dns
