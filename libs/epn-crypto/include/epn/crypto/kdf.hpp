#pragma once

#include <epn/core/types.hpp>
#include <epn/core/result.hpp>
#include <epn/crypto/keys.hpp>
#include <sodium.h>
#include <string_view>

namespace epn::crypto {

using namespace epn::core;

// ─── HKDF-SHA256 (RFC 5869) ──────────────────────────────────────────────────
// Implemented via HMAC-SHA256 (libsodium crypto_auth_hmacsha256)
// libsodium 1.0.18 does not expose crypto_kdf_hkdf_sha256_* directly

Bytes hkdf_sha256_extract(
    ByteSpan ikm,                  // Input key material
    ByteSpan salt = {}             // Optional salt (zeros if empty)
);

Bytes hkdf_sha256_expand(
    ByteSpan prk,                  // Pseudo-random key (output of extract)
    ByteSpan info,                 // Context/label string
    size_t   okm_len               // Desired output length (max 255*32 = 8160)
);

// Combined extract+expand
Bytes hkdf_sha256(
    ByteSpan     ikm,
    ByteSpan     info,
    size_t       okm_len,
    ByteSpan     salt = {}
);

// ─── X25519 Diffie-Hellman ───────────────────────────────────────────────────
// Performs Curve25519 scalar multiplication
// Returns 32-byte shared secret (MUST be fed into HKDF — raw DH output is not a key)
Result<SecretBytes> x25519_dh(
    const RawPrivateKey& sk,
    const RawPublicKey&  pk
);

// ─── Session key derivation ───────────────────────────────────────────────────
// Derives forward + backward session keys from a DH shared secret.
//
// Protocol:
//   shared = X25519(client_ephemeral_sk, node_pk)
//   ikm    = shared || client_ephemeral_pk || node_pk
//   prk    = HKDF-Extract(salt="epn-v1", ikm)
//   forward_key  = HKDF-Expand(prk, "epn-forward-v1",  32)
//   backward_key = HKDF-Expand(prk, "epn-backward-v1", 32)
//
// This ensures:
//   - Forward/backward keys are cryptographically separated
//   - Keys are bound to both parties' identities (via pubkeys in ikm)
//   - Post-handshake forward secrecy (ephemeral client key)
Result<SessionKey> derive_session_keys(
    const SecretBytes&   shared_secret,
    const RawPublicKey&  client_ephemeral_pk,
    const RawPublicKey&  node_pk
);

// ─── Post-quantum hybrid key exchange (optional) ──────────────────────────────
// Hybrid X25519 + ML-KEM-768 (Kyber) via liboqs
// Falls back to X25519-only if EPN_ENABLE_PQ_CRYPTO not defined
//
// Combined shared secret: HKDF(x25519_ss || kyber_ss, "epn-hybrid-v1", 64)
// This ensures security as long as at least one primitive is unbroken.
#ifdef EPN_ENABLE_PQ_CRYPTO
struct HybridKeyPair {
    X25519KeyPair classical;
    Bytes         pq_public;   // ML-KEM-768 public key (1184 bytes)
    Bytes         pq_private;  // ML-KEM-768 private key (2400 bytes)

    ~HybridKeyPair() {
        if (!pq_private.empty())
            sodium_memzero(pq_private.data(), pq_private.size());
    }
};

Result<HybridKeyPair>  generate_hybrid_keypair();
Result<Bytes>          hybrid_encapsulate(const HybridKeyPair& peer_public, Bytes& ciphertext_out);
Result<SecretBytes>    hybrid_decapsulate(const HybridKeyPair& my_keypair, ByteSpan ciphertext);
#endif

} // namespace epn::crypto
