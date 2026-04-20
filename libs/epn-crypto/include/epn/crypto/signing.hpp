#pragma once

#include <epn/core/types.hpp>
#include <epn/core/result.hpp>
#include <epn/crypto/keys.hpp>
#include <sodium.h>

namespace epn::crypto {

using namespace epn::core;

// ─── Ed25519 digital signatures ───────────────────────────────────────────────
// Used for signing Discovery announcements (not for encryption)

// Sign message with Ed25519 private key
// Returns 64-byte detached signature
Result<RawSignature> sign_detached(
    const RawSignKey&  sk,
    ByteSpan           message
);

// Verify Ed25519 detached signature
// Returns ok() if valid, err() if invalid
Result<void> verify_detached(
    const RawSignPubKey& pk,
    ByteSpan             message,
    const RawSignature&  sig
);

// ─── Announcement signing helpers ────────────────────────────────────────────
// Canonical message format for signing:
// "EPN-ANNOUNCE" || node_type(1) || pubkey(32) || sign_pubkey(32) || timestamp(8) || ttl(4) || addr_len(2) || addr || port(2)
Bytes make_announcement_signing_payload(
    core::NodeRole      role,
    const RawPublicKey& dh_pubkey,
    const RawSignPubKey& sign_pubkey,
    int64_t             timestamp,
    int32_t             ttl,
    const std::string&  addr,
    uint16_t            port
);

} // namespace epn::crypto
