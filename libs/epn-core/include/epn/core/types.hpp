#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <vector>
#include <chrono>
#include <random>
#include <sstream>
#include <iomanip>

namespace epn::core {

// ─── Byte container types ────────────────────────────────────────────────────
using Bytes = std::vector<uint8_t>;
using ByteSpan = std::span<const uint8_t>;
using MutableByteSpan = std::span<uint8_t>;

// ─── Fixed-size identifiers ───────────────────────────────────────────────────
struct SessionId {
    std::array<uint8_t, 32> data{};

    bool operator==(const SessionId& o) const { return data == o.data; }
    bool operator<(const SessionId& o) const { return data < o.data; }
    bool is_zero() const {
        for (auto b : data) if (b) return false;
        return true;
    }
};

struct NodeId {
    std::array<uint8_t, 32> data{};

    bool operator==(const NodeId& o) const { return data == o.data; }
    bool operator<(const NodeId& o) const { return data < o.data; }
};

// ─── Key types (raw buffers — wrapped in crypto module) ───────────────────────
using RawPublicKey   = std::array<uint8_t, 32>;  // X25519 / Ed25519 pubkey
using RawPrivateKey  = std::array<uint8_t, 32>;  // X25519 privkey
using RawSignKey     = std::array<uint8_t, 64>;  // Ed25519 sign key (seed+pk)
using RawSignPubKey  = std::array<uint8_t, 32>;  // Ed25519 verify key
using RawSignature   = std::array<uint8_t, 64>;  // Ed25519 signature
using RawNonce       = std::array<uint8_t, 12>;  // ChaCha20-Poly1305 nonce
using RawSessionKey  = std::array<uint8_t, 32>;  // AEAD key

// ─── Node role ────────────────────────────────────────────────────────────────
enum class NodeRole : uint8_t {
    Relay         = 0x01,
    Server        = 0x02,  // echo / application server
    Client        = 0x03,
    TunnelServer  = 0x04,  // epn-tun-server (TCP proxy exit node)
};

// ─── Protocol constants ───────────────────────────────────────────────────────
inline constexpr size_t MIN_HOPS           = 3;
inline constexpr size_t MAX_HOPS           = 7;
inline constexpr uint32_t MAX_FRAME_SIZE   = 16 * 1024 * 1024; // 16 MiB
inline constexpr uint32_t MAX_PAYLOAD_SIZE = 64 * 1024;         // 64 KiB
inline constexpr int SESSION_TTL_SECS      = 300;
inline constexpr int DISCOVERY_TTL_SECS    = 60;
inline constexpr int KEEPALIVE_INTERVAL_MS = 10000;

// ─── Hex helpers ─────────────────────────────────────────────────────────────
inline std::string to_hex(ByteSpan data) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t b : data) oss << std::setw(2) << static_cast<int>(b);
    return oss.str();
}

inline Bytes from_hex(const std::string& hex) {
    Bytes out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        uint8_t b = static_cast<uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16));
        out.push_back(b);
    }
    return out;
}

// ─── Big-endian serialization ─────────────────────────────────────────────────
inline void write_be32(uint8_t* dst, uint32_t v) {
    dst[0] = static_cast<uint8_t>((v >> 24) & 0xFF);
    dst[1] = static_cast<uint8_t>((v >> 16) & 0xFF);
    dst[2] = static_cast<uint8_t>((v >>  8) & 0xFF);
    dst[3] = static_cast<uint8_t>((v      ) & 0xFF);
}

inline uint32_t read_be32(const uint8_t* src) {
    return (static_cast<uint32_t>(src[0]) << 24) |
           (static_cast<uint32_t>(src[1]) << 16) |
           (static_cast<uint32_t>(src[2]) <<  8) |
           (static_cast<uint32_t>(src[3]));
}

inline void write_be16(uint8_t* dst, uint16_t v) {
    dst[0] = static_cast<uint8_t>((v >> 8) & 0xFF);
    dst[1] = static_cast<uint8_t>((v     ) & 0xFF);
}

inline uint16_t read_be16(const uint8_t* src) {
    return static_cast<uint16_t>((src[0] << 8) | src[1]);
}

// ─── Timestamp ────────────────────────────────────────────────────────────────
inline int64_t now_unix() {
    using namespace std::chrono;
    return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
}

inline int64_t now_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

} // namespace epn::core
