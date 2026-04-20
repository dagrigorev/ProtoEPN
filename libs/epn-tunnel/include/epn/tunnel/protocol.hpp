#pragma once

#include <epn/core/types.hpp>
#include <epn/core/result.hpp>
#include <cstring>
#include <string>

namespace epn::tunnel {

using namespace epn::core;

// ─── Wire format (inside AEAD-encrypted SESSION_DATA payload) ─────────────────
//
//   [4B stream_id BE]  — client-assigned; odd = client-initiated
//   [1B cmd]
//   [2B data_len BE]
//   [data_len bytes]
//
// A SESSION_DATA frame contains exactly one tunnel frame.
// E2E encryption: ChaCha20-Poly1305 (existing session keys).
// Relay nodes see only ciphertext as part of the raw TCP proxy stream.

inline constexpr size_t TUNNEL_FRAME_HEADER = 4 + 1 + 2; // stream_id + cmd + len

enum class TunnelCmd : uint8_t {
    STREAM_OPEN     = 0x01,  // client→server: open TCP to target
    STREAM_DATA     = 0x02,  // bidirectional: raw TCP bytes
    STREAM_CLOSE    = 0x03,  // either direction: stream done
    STREAM_OPEN_ACK = 0x04,  // server→client: connection result
};

// STREAM_OPEN payload: [1B addr_type][addr][2B port BE]
//   addr_type 0x01 = IPv4 (4 bytes)
//   addr_type 0x03 = domain (1B len prefix + N bytes)
//   addr_type 0x04 = IPv6 (16 bytes)
// STREAM_OPEN_ACK payload: [1B result]
//   0x00 = connected OK
//   0x01 = connection refused
//   0x02 = host unreachable / resolve failed
//   0x03 = general error
// STREAM_DATA payload: raw bytes (any length)
// STREAM_CLOSE payload: empty

enum class OpenResult : uint8_t {
    OK               = 0x00,
    REFUSED          = 0x01,
    UNREACHABLE      = 0x02,
    GENERAL_ERROR    = 0x03,
};

struct TunnelFrame {
    uint32_t   stream_id{};
    TunnelCmd  cmd{};
    Bytes      data;
};

// ─── Encode ───────────────────────────────────────────────────────────────────
inline Bytes encode_tunnel_frame(uint32_t sid, TunnelCmd cmd, ByteSpan data) {
    Bytes out(TUNNEL_FRAME_HEADER + data.size());
    write_be32(out.data(), sid);
    out[4] = static_cast<uint8_t>(cmd);
    write_be16(out.data() + 5, static_cast<uint16_t>(data.size()));
    if (!data.empty()) std::memcpy(out.data() + 7, data.data(), data.size());
    return out;
}

// ─── Decode ───────────────────────────────────────────────────────────────────
inline Result<TunnelFrame> decode_tunnel_frame(ByteSpan buf) {
    if (buf.size() < TUNNEL_FRAME_HEADER)
        return Result<TunnelFrame>::err("Tunnel frame too short");

    TunnelFrame f;
    f.stream_id = read_be32(buf.data());
    f.cmd       = static_cast<TunnelCmd>(buf[4]);
    uint16_t dlen = read_be16(buf.data() + 5);

    if (buf.size() < TUNNEL_FRAME_HEADER + dlen)
        return Result<TunnelFrame>::err("Tunnel frame data truncated");

    f.data = Bytes(buf.data() + 7, buf.data() + 7 + dlen);
    return Result<TunnelFrame>::ok(std::move(f));
}

// ─── Build STREAM_OPEN payload ─────────────────────────────────────────────────
inline Bytes make_open_payload(const std::string& host, uint16_t port) {
    bool is_ipv4 = false;
    // Simple heuristic: if it contains only digits and dots, treat as IPv4
    // For proper detection use Asio's address parsing
    Bytes out;
    // Always use domain type (0x03) — resolver on server handles it
    out.push_back(0x03); // domain
    out.push_back(static_cast<uint8_t>(host.size()));
    for (char c : host) out.push_back(static_cast<uint8_t>(c));
    out.push_back(static_cast<uint8_t>((port >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>( port        & 0xFF));
    (void)is_ipv4;
    return out;
}

// ─── Parse STREAM_OPEN payload ────────────────────────────────────────────────
inline Result<std::pair<std::string, uint16_t>> parse_open_payload(ByteSpan data) {
    if (data.size() < 4) return Result<std::pair<std::string, uint16_t>>::err("too short");
    uint8_t atype = data[0];
    std::string host;
    size_t off = 1;
    if (atype == 0x01) { // IPv4
        if (data.size() < 7) return Result<std::pair<std::string, uint16_t>>::err("ipv4 short");
        host = std::to_string(data[1]) + "." + std::to_string(data[2]) +
               "." + std::to_string(data[3]) + "." + std::to_string(data[4]);
        off = 5;
    } else if (atype == 0x03) { // domain
        uint8_t len = data[1]; off = 2;
        if (data.size() < static_cast<size_t>(2 + len + 2))
            return Result<std::pair<std::string, uint16_t>>::err("domain short");
        host = std::string(reinterpret_cast<const char*>(data.data() + off), len);
        off += len;
    } else if (atype == 0x04) { // IPv6 (16 bytes)
        if (data.size() < 19) return Result<std::pair<std::string, uint16_t>>::err("ipv6 short");
        // Format as hex string — Asio resolver can handle it
        char buf[64];
        snprintf(buf, sizeof(buf),
            "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
            "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
            data[1],data[2],data[3],data[4],data[5],data[6],data[7],data[8],
            data[9],data[10],data[11],data[12],data[13],data[14],data[15],data[16]);
        host = buf; off = 17;
    } else {
        return Result<std::pair<std::string, uint16_t>>::err("unknown addr type");
    }
    uint16_t port = static_cast<uint16_t>((data[off] << 8) | data[off+1]);
    return Result<std::pair<std::string, uint16_t>>::ok({host, port});
}

} // namespace epn::tunnel
