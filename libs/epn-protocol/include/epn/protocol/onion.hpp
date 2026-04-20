#pragma once

#include <epn/core/types.hpp>
#include <epn/core/result.hpp>
#include <epn/crypto/keys.hpp>
#include <epn/crypto/kdf.hpp>
#include <epn/crypto/aead.hpp>
#include <epn/protocol/messages.hpp>
#include <string>
#include <vector>
#include <mutex>
#include <unordered_map>

namespace epn::protocol {

using namespace epn::core;

// ─── Wire format per onion layer ──────────────────────────────────────────────
//   [32] client_ephemeral_pubkey   X25519 pubkey for DH
//   [12] nonce                     ChaCha20-Poly1305 IETF nonce
//   [ 4] ciphertext_len BE
//   [ N] ciphertext                encrypted HopPayload + 16-byte Poly1305 tag
//
// HopPayload for RELAY hop:
//   [1]  hop_type = 0x01
//   [2]  next_port BE
//   [1]  addr_len
//   [M]  next_addr UTF-8
//   [..]  inner_onion_packet
//
// HopPayload for FINAL hop (server):
//   [1]  hop_type = 0x02
//   [32] session_id  (chosen by client, echoed in ROUTE_READY)
//   [..] application payload
//
// AAD = "EPN-ONION-V1" || client_ephemeral_pubkey
// This binds ciphertext to the specific ephemeral key used for this layer.

inline constexpr size_t ONION_HEADER_SIZE = 32 + 12 + 4;

// ─── Hop descriptor (client builds the route from these) ──────────────────────
struct HopDescriptor {
    std::string          addr;
    uint16_t             port;
    crypto::RawPublicKey node_pubkey;
};

// ─── Result from build_onion ──────────────────────────────────────────────────
// Includes the wire bytes AND the E2E session key shared with the server.
// Client uses server_session_key for SESSION_DATA encryption/decryption.
struct OnionBuildResult {
    Bytes            wire;                 // outermost onion layer → send to hops[0]
    crypto::SessionKey server_session_key; // forward+backward keys, client↔server
};

// ─── Build onion packet ───────────────────────────────────────────────────────
// hops: [relay1, relay2, ..., relayN, server]  (server is last)
// Returns wire bytes for outermost layer + E2E session key with server.
Result<OnionBuildResult> build_onion(
    const std::vector<HopDescriptor>& hops,
    const SessionId&                  session_id,
    ByteSpan                          payload
);

// ─── Peel one onion layer (relay / server side) ───────────────────────────────
struct PeeledOnion {
    HopType     hop_type;
    std::string next_addr;    // RELAY: address of next hop
    uint16_t    next_port{};  // RELAY: port of next hop
    SessionId   session_id;   // FINAL: session_id echoed in ROUTE_READY
    Bytes       inner;        // RELAY: inner onion wire; FINAL: application payload
};

Result<PeeledOnion> peel_onion(
    const crypto::RawPrivateKey& node_privkey,
    ByteSpan                     onion_wire
);

// ─── Ephemeral key tracker (anti-replay) ─────────────────────────────────────
// Each relay/server rejects onion packets whose ephemeral pubkey was seen before.
class EphemeralKeyTracker {
public:
    explicit EphemeralKeyTracker(int window_secs = 120) : window_secs_(window_secs) {}

    bool check_and_insert(const crypto::RawPublicKey& epk) {
        std::lock_guard<std::mutex> lk(mu_);
        evict_expired();
        std::string k(reinterpret_cast<const char*>(epk.data()), 32);
        if (seen_.count(k)) return false;
        seen_[k] = now_unix();
        return true;
    }

private:
    void evict_expired() {
        int64_t cutoff = now_unix() - window_secs_;
        for (auto it = seen_.begin(); it != seen_.end(); ) {
            if (it->second < cutoff) it = seen_.erase(it);
            else ++it;
        }
    }
    std::mutex mu_;
    std::unordered_map<std::string, int64_t> seen_;
    int window_secs_;
};

} // namespace epn::protocol
