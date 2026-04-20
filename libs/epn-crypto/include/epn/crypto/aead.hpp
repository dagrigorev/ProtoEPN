#pragma once

#include <epn/core/types.hpp>
#include <epn/core/result.hpp>
#include <epn/crypto/keys.hpp>
#include <sodium.h>
#include <atomic>
#include <unordered_set>
#include <mutex>
#include <chrono>
#include <unordered_map>

namespace epn::crypto {

using namespace epn::core;

// ─── ChaCha20-Poly1305-IETF constants ────────────────────────────────────────
inline constexpr size_t AEAD_KEY_SIZE   = crypto_aead_chacha20poly1305_ietf_KEYBYTES;  // 32
inline constexpr size_t AEAD_NONCE_SIZE = crypto_aead_chacha20poly1305_ietf_NPUBBYTES; // 12
inline constexpr size_t AEAD_TAG_SIZE   = crypto_aead_chacha20poly1305_ietf_ABYTES;    // 16

static_assert(AEAD_KEY_SIZE   == 32);
static_assert(AEAD_NONCE_SIZE == 12);
static_assert(AEAD_TAG_SIZE   == 16);

// ─── AEAD result ─────────────────────────────────────────────────────────────
struct AeadCiphertext {
    RawNonce nonce;
    Bytes    ciphertext; // plaintext + 16-byte Poly1305 tag
};

// ─── Encrypt ─────────────────────────────────────────────────────────────────
// key:  32-byte session key
// pt:   plaintext
// aad:  additional authenticated data (may be empty)
// Returns: AeadCiphertext with fresh random nonce
Result<AeadCiphertext> aead_encrypt(
    const RawSessionKey& key,
    ByteSpan             pt,
    ByteSpan             aad = {}
);

// Encrypt with explicit nonce (for counter-based nonce schemes)
Result<AeadCiphertext> aead_encrypt_with_nonce(
    const RawSessionKey& key,
    const RawNonce&      nonce,
    ByteSpan             pt,
    ByteSpan             aad = {}
);

// ─── Decrypt ─────────────────────────────────────────────────────────────────
// Returns plaintext or error (includes auth tag verification)
Result<Bytes> aead_decrypt(
    const RawSessionKey& key,
    const RawNonce&      nonce,
    ByteSpan             ct,   // includes 16-byte tag
    ByteSpan             aad = {}
);

// ─── Nonce counter (per-session, direction-aware) ─────────────────────────────
// Uses 64-bit counter in the last 8 bytes of the 12-byte nonce
// First 4 bytes: direction_tag (0x00000001 = forward, 0x00000002 = backward)
struct NonceCounter {
    uint32_t direction_tag; // distinguishes forward vs backward channels
    std::atomic<uint64_t> counter{0};

    explicit NonceCounter(uint32_t tag) : direction_tag(tag) {}

    RawNonce next() {
        RawNonce n{};
        uint64_t c = counter.fetch_add(1, std::memory_order_seq_cst);
        // First 4 bytes: direction tag (BE)
        n[0] = static_cast<uint8_t>((direction_tag >> 24) & 0xFF);
        n[1] = static_cast<uint8_t>((direction_tag >> 16) & 0xFF);
        n[2] = static_cast<uint8_t>((direction_tag >>  8) & 0xFF);
        n[3] = static_cast<uint8_t>((direction_tag      ) & 0xFF);
        // Last 8 bytes: counter (BE)
        n[4]  = static_cast<uint8_t>((c >> 56) & 0xFF);
        n[5]  = static_cast<uint8_t>((c >> 48) & 0xFF);
        n[6]  = static_cast<uint8_t>((c >> 40) & 0xFF);
        n[7]  = static_cast<uint8_t>((c >> 32) & 0xFF);
        n[8]  = static_cast<uint8_t>((c >> 24) & 0xFF);
        n[9]  = static_cast<uint8_t>((c >> 16) & 0xFF);
        n[10] = static_cast<uint8_t>((c >>  8) & 0xFF);
        n[11] = static_cast<uint8_t>((c       ) & 0xFF);
        return n;
    }
};

// Forward: 0x00000001, Backward: 0x00000002
inline constexpr uint32_t NONCE_DIRECTION_FORWARD  = 0x00000001;
inline constexpr uint32_t NONCE_DIRECTION_BACKWARD = 0x00000002;

// ─── Replay protection window ─────────────────────────────────────────────────
// Tracks seen nonces for one-time use (route setup packets)
// Uses time-windowed set with a 60-second window
class ReplayFilter {
public:
    explicit ReplayFilter(int window_secs = 60) : window_secs_(window_secs) {}

    // Returns true if nonce is fresh (not seen before)
    bool check_and_insert(const RawNonce& nonce) {
        std::lock_guard<std::mutex> lk(mu_);
        evict_expired();
        auto key = nonce_to_string(nonce);
        if (seen_.count(key)) return false;
        seen_[key] = now_unix();
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

    std::string nonce_to_string(const RawNonce& n) {
        return std::string(reinterpret_cast<const char*>(n.data()), n.size());
    }

    std::mutex mu_;
    std::unordered_map<std::string, int64_t> seen_;
    int window_secs_;
};

} // namespace epn::crypto
