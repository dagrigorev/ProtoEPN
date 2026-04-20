#pragma once

#include <epn/core/types.hpp>
#include <cstdint>
#include <string>

namespace epn::protocol {

using namespace epn::core;

// ─── Message type codes ───────────────────────────────────────────────────────
enum class MsgType : uint8_t {
    // Control plane — relay chain
    ONION_FORWARD  = 0x01,  // Contains layered-encrypted routing packet
    ROUTE_READY    = 0x02,  // Server→client: route established, session_id confirmed
    SESSION_DATA   = 0x03,  // E2E encrypted data (client↔server, relays proxy)
    TEARDOWN       = 0x04,  // Terminate session, zeroise state
    KEEPALIVE      = 0x05,  // Heartbeat (prevents timeout)
    ERROR_MSG      = 0x06,  // Protocol error

    // Discovery protocol (TCP, JSON payload)
    DISC_REGISTER  = 0x10,  // Node registers with discovery server
    DISC_QUERY     = 0x11,  // Client queries for nodes by role
    DISC_RESPONSE  = 0x12,  // Discovery server responds with node list
    DISC_ACK       = 0x13,  // Registration acknowledged
};

// ─── Wire frame ───────────────────────────────────────────────────────────────
// Header: [4-byte payload_len BE][1-byte msg_type]
// Body:   [payload_len bytes]
// Total:  5 + payload_len bytes
//
// Maximum frame size: 16 MiB (enforced on read)
struct Frame {
    MsgType type;
    Bytes   payload;

    Frame() = default;
    Frame(MsgType t, Bytes p) : type(t), payload(std::move(p)) {}
};

// ─── Onion hop types (inside encrypted onion payload) ─────────────────────────
enum class HopType : uint8_t {
    RELAY = 0x01,  // This hop: decrypt, forward inner to next_hop
    FINAL = 0x02,  // This hop: decrypt, deliver final payload to server
};

// ─── Session data header (prepended to encrypted SESSION_DATA payload) ─────────
// [32 bytes session_id][12 bytes nonce][ciphertext...]
inline constexpr size_t SESSION_HEADER_SIZE = 32 + 12; // session_id + nonce

// ─── Error codes ─────────────────────────────────────────────────────────────
enum class EpnError : uint16_t {
    OK                  = 0x0000,
    AUTH_FAILED         = 0x0001,  // AEAD decryption / signature verification failed
    REPLAY_DETECTED     = 0x0002,  // Nonce seen before
    SESSION_EXPIRED     = 0x0003,  // TTL exceeded
    INVALID_FRAME       = 0x0004,  // Malformed frame / length mismatch
    NO_ROUTE            = 0x0005,  // Cannot reach next hop
    CAPACITY_EXCEEDED   = 0x0006,  // Too many sessions
    UNKNOWN_SESSION     = 0x0007,  // Session ID not found
    INVALID_HOP_TYPE    = 0x0008,  // Unknown hop type in onion
    KEY_REUSE_DETECTED  = 0x0009,  // Ephemeral pubkey seen before
    INTERNAL_ERROR      = 0xFFFF,
};

} // namespace epn::protocol
