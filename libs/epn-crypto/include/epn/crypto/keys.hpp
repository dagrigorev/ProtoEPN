#pragma once

#include <epn/core/types.hpp>
#include <epn/core/result.hpp>
#include <sodium.h>
#include <array>
#include <memory>
#include <cstring>

namespace epn::crypto {

using namespace epn::core;

// ─── X25519 DH Keypair (ephemeral) ───────────────────────────────────────────
// CRITICAL: privkey is zeroed in destructor — NEVER copy by value
struct X25519KeyPair {
    RawPublicKey  pubkey{};
    RawPrivateKey privkey{};

    X25519KeyPair() = default;

    // Non-copyable to prevent accidental key duplication
    X25519KeyPair(const X25519KeyPair&)            = delete;
    X25519KeyPair& operator=(const X25519KeyPair&) = delete;

    // Movable
    X25519KeyPair(X25519KeyPair&& o) noexcept : pubkey(o.pubkey), privkey(o.privkey) {
        sodium_memzero(o.privkey.data(), o.privkey.size());
    }
    X25519KeyPair& operator=(X25519KeyPair&& o) noexcept {
        if (this != &o) {
            sodium_memzero(privkey.data(), privkey.size());
            pubkey  = o.pubkey;
            privkey = o.privkey;
            sodium_memzero(o.privkey.data(), o.privkey.size());
        }
        return *this;
    }

    ~X25519KeyPair() {
        sodium_memzero(privkey.data(), privkey.size());
    }
};

// ─── Ed25519 Signing Keypair ──────────────────────────────────────────────────
struct SigningKeyPair {
    RawSignPubKey pubkey{};
    RawSignKey    privkey{};  // 64 bytes: seed (32) || pubkey (32)

    SigningKeyPair() = default;
    SigningKeyPair(const SigningKeyPair&)            = delete;
    SigningKeyPair& operator=(const SigningKeyPair&) = delete;

    SigningKeyPair(SigningKeyPair&& o) noexcept : pubkey(o.pubkey), privkey(o.privkey) {
        sodium_memzero(o.privkey.data(), o.privkey.size());
    }
    SigningKeyPair& operator=(SigningKeyPair&& o) noexcept {
        if (this != &o) {
            sodium_memzero(privkey.data(), privkey.size());
            pubkey  = o.pubkey;
            privkey = o.privkey;
            sodium_memzero(o.privkey.data(), o.privkey.size());
        }
        return *this;
    }
    ~SigningKeyPair() {
        sodium_memzero(privkey.data(), privkey.size());
    }
};

// ─── Sensitive byte container (zeroed on destruction) ─────────────────────────
struct SecretBytes {
    Bytes data;

    SecretBytes() = default;
    explicit SecretBytes(size_t n) : data(n, 0) {}
    explicit SecretBytes(Bytes b) : data(std::move(b)) {}

    SecretBytes(const SecretBytes&)            = delete;
    SecretBytes& operator=(const SecretBytes&) = delete;
    SecretBytes(SecretBytes&&)                 = default;
    SecretBytes& operator=(SecretBytes&&)      = default;

    ~SecretBytes() {
        if (!data.empty()) sodium_memzero(data.data(), data.size());
    }

    size_t size() const { return data.size(); }
    uint8_t* ptr()  { return data.data(); }
    const uint8_t* ptr() const { return data.data(); }
};

// ─── Session key (AEAD key, zeroed on destruction) ────────────────────────────
struct SessionKey {
    RawSessionKey forward{};   // client→server direction
    RawSessionKey backward{};  // server→client direction

    SessionKey() = default;
    SessionKey(const SessionKey&)            = delete;
    SessionKey& operator=(const SessionKey&) = delete;
    SessionKey(SessionKey&&)                 = default;
    SessionKey& operator=(SessionKey&&)      = default;

    ~SessionKey() {
        sodium_memzero(forward.data(),  forward.size());
        sodium_memzero(backward.data(), backward.size());
    }
};

// ─── Factory functions ────────────────────────────────────────────────────────
Result<X25519KeyPair> generate_x25519_keypair();
Result<SigningKeyPair> generate_signing_keypair();
Bytes  generate_random_bytes(size_t n);
SessionId generate_session_id();

// Derive NodeId from X25519 pubkey (BLAKE2b-256 hash)
NodeId pubkey_to_node_id(const RawPublicKey& pubkey);

} // namespace epn::crypto
