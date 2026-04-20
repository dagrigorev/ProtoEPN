#include <epn/crypto/kdf.hpp>
#include <sodium.h>
#include <cstring>
#include <stdexcept>

namespace epn::crypto {

// ─── HKDF-SHA256 ─────────────────────────────────────────────────────────────
// RFC 5869, using HMAC-SHA256 from libsodium

Bytes hkdf_sha256_extract(ByteSpan ikm, ByteSpan salt) {
    static const uint8_t ZEROS[32]{};
    const uint8_t* salt_ptr = salt.empty() ? ZEROS : salt.data();
    size_t         salt_len = salt.empty() ? 32     : salt.size();

    Bytes prk(crypto_auth_hmacsha256_BYTES); // 32 bytes

    crypto_auth_hmacsha256_state state;
    crypto_auth_hmacsha256_init(&state, salt_ptr, salt_len);
    crypto_auth_hmacsha256_update(&state, ikm.data(), ikm.size());
    crypto_auth_hmacsha256_final(&state, prk.data());

    return prk;
}

Bytes hkdf_sha256_expand(ByteSpan prk, ByteSpan info, size_t okm_len) {
    if (prk.size() < 32)
        throw std::invalid_argument("HKDF-Expand: PRK too short");
    if (okm_len > 255 * 32)
        throw std::invalid_argument("HKDF-Expand: okm_len too large");

    Bytes okm;
    okm.reserve(okm_len + 32);

    Bytes t_prev;
    uint8_t counter = 1;

    while (okm.size() < okm_len) {
        Bytes t_curr(32);
        crypto_auth_hmacsha256_state state;
        crypto_auth_hmacsha256_init(&state, prk.data(), prk.size());
        if (!t_prev.empty())
            crypto_auth_hmacsha256_update(&state, t_prev.data(), t_prev.size());
        if (!info.empty())
            crypto_auth_hmacsha256_update(&state, info.data(), info.size());
        crypto_auth_hmacsha256_update(&state, &counter, 1);
        crypto_auth_hmacsha256_final(&state, t_curr.data());

        okm.insert(okm.end(), t_curr.begin(), t_curr.end());
        t_prev = std::move(t_curr);
        ++counter;
    }

    okm.resize(okm_len);
    sodium_memzero(t_prev.data(), t_prev.size());
    return okm;
}

Bytes hkdf_sha256(ByteSpan ikm, ByteSpan info, size_t okm_len, ByteSpan salt) {
    auto prk = hkdf_sha256_extract(ikm, salt);
    auto okm = hkdf_sha256_expand(prk, info, okm_len);
    sodium_memzero(prk.data(), prk.size());
    return okm;
}

// ─── X25519 DH ───────────────────────────────────────────────────────────────
Result<SecretBytes> x25519_dh(const RawPrivateKey& sk, const RawPublicKey& pk) {
    SecretBytes shared(crypto_scalarmult_BYTES); // 32 bytes

    if (crypto_scalarmult(shared.ptr(), sk.data(), pk.data()) != 0) {
        // DH failed — likely low-order public key (attack attempt)
        return Result<SecretBytes>::err("X25519 DH failed: low-order or invalid public key");
    }

    // Sanity check: reject all-zero output (another low-order indicator)
    if (sodium_is_zero(shared.ptr(), shared.size())) {
        sodium_memzero(shared.ptr(), shared.size());
        return Result<SecretBytes>::err("X25519 DH produced all-zero shared secret");
    }

    return Result<SecretBytes>::ok(std::move(shared));
}

// ─── Session key derivation ───────────────────────────────────────────────────
Result<SessionKey> derive_session_keys(
    const SecretBytes&  shared_secret,
    const RawPublicKey& client_ephemeral_pk,
    const RawPublicKey& node_pk)
{
    // IKM = shared_secret || client_ephemeral_pk || node_pk
    Bytes ikm;
    ikm.reserve(shared_secret.size() + 32 + 32);
    ikm.insert(ikm.end(), shared_secret.data.begin(), shared_secret.data.end());
    ikm.insert(ikm.end(), client_ephemeral_pk.begin(), client_ephemeral_pk.end());
    ikm.insert(ikm.end(), node_pk.begin(), node_pk.end());

    static const uint8_t SALT[] = "epn-v1";
    Bytes prk = hkdf_sha256_extract(
        {ikm.data(), ikm.size()},
        {SALT, sizeof(SALT) - 1}
    );

    static const uint8_t FWD_LABEL[] = "epn-forward-v1";
    static const uint8_t BWD_LABEL[] = "epn-backward-v1";

    Bytes fwd_key = hkdf_sha256_expand(
        {prk.data(), prk.size()},
        {FWD_LABEL, sizeof(FWD_LABEL) - 1},
        32
    );
    Bytes bwd_key = hkdf_sha256_expand(
        {prk.data(), prk.size()},
        {BWD_LABEL, sizeof(BWD_LABEL) - 1},
        32
    );

    // Zeroize intermediate material
    sodium_memzero(ikm.data(), ikm.size());
    sodium_memzero(prk.data(), prk.size());

    SessionKey sk;
    std::copy(fwd_key.begin(), fwd_key.end(), sk.forward.begin());
    std::copy(bwd_key.begin(), bwd_key.end(), sk.backward.begin());

    sodium_memzero(fwd_key.data(), fwd_key.size());
    sodium_memzero(bwd_key.data(), bwd_key.size());

    return Result<SessionKey>::ok(std::move(sk));
}

} // namespace epn::crypto
