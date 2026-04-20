#pragma once

#include <epn/core/types.hpp>
#include <epn/core/result.hpp>
#include <epn/crypto/keys.hpp>
#include <epn/crypto/signing.hpp>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <mutex>
#include <unordered_map>
#include <chrono>

namespace epn::discovery {

using namespace epn::core;
using json = nlohmann::json;

// ─── Node announcement ────────────────────────────────────────────────────────
struct NodeAnnouncement {
    // Stable node identity (BLAKE2b hash of DH pubkey)
    std::string node_id_hex;

    // Role
    NodeRole role;

    // Network info
    std::string addr;
    uint16_t    port;

    // Crypto keys
    crypto::RawPublicKey  dh_pubkey;      // X25519 — for DH in onion routing
    crypto::RawSignPubKey sign_pubkey;    // Ed25519 — for verifying this announcement

    // Temporal validity
    int64_t timestamp;   // Unix seconds
    int32_t ttl;         // seconds until expiry

    // Ed25519 signature over canonical payload (see signing.hpp)
    crypto::RawSignature signature;

    // Capabilities flags (extensible)
    uint32_t capabilities{0};

    bool is_expired(int64_t now = now_unix()) const {
        return (now - timestamp) > static_cast<int64_t>(ttl);
    }

    // Serialise to JSON (for wire transport)
    json to_json() const;

    // Deserialise from JSON
    static Result<NodeAnnouncement> from_json(const json& j);

    // Verify the embedded signature
    Result<void> verify_signature() const;
};

// ─── In-memory announcement registry ─────────────────────────────────────────
// Thread-safe store for the discovery server.
// Periodically sweeps expired entries.
class AnnouncementRegistry {
public:
    AnnouncementRegistry() = default;

    // Insert/update an announcement (validates signature and timestamp)
    Result<void> upsert(NodeAnnouncement ann);

    // Query nodes by role (excludes expired entries)
    std::vector<NodeAnnouncement> query(NodeRole role) const;

    // Remove a specific node
    void remove(const std::string& node_id_hex);

    // Sweep expired entries (call periodically)
    size_t sweep_expired();

    size_t size() const {
        std::lock_guard lk(mu_);
        return store_.size();
    }

private:
    mutable std::mutex mu_;
    std::unordered_map<std::string, NodeAnnouncement> store_; // key = node_id_hex
};

} // namespace epn::discovery
