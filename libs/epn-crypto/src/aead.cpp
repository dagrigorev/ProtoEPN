#include <epn/crypto/aead.hpp>
#include <sodium.h>
#include <cstring>

namespace epn::crypto {

Result<AeadCiphertext> aead_encrypt(
    const RawSessionKey& key,
    ByteSpan             pt,
    ByteSpan             aad)
{
    RawNonce nonce;
    randombytes_buf(nonce.data(), nonce.size());
    return aead_encrypt_with_nonce(key, nonce, pt, aad);
}

Result<AeadCiphertext> aead_encrypt_with_nonce(
    const RawSessionKey& key,
    const RawNonce&      nonce,
    ByteSpan             pt,
    ByteSpan             aad)
{
    AeadCiphertext result;
    result.nonce = nonce;
    result.ciphertext.resize(pt.size() + AEAD_TAG_SIZE);

    unsigned long long ct_len = 0;
    int rc = crypto_aead_chacha20poly1305_ietf_encrypt(
        result.ciphertext.data(),
        &ct_len,
        pt.data(), pt.size(),
        aad.empty() ? nullptr : aad.data(), aad.size(),
        nullptr,            // nsec — not used
        nonce.data(),
        key.data()
    );

    if (rc != 0) {
        return Result<AeadCiphertext>::err("AEAD encryption failed");
    }

    result.ciphertext.resize(static_cast<size_t>(ct_len));
    return Result<AeadCiphertext>::ok(std::move(result));
}

Result<Bytes> aead_decrypt(
    const RawSessionKey& key,
    const RawNonce&      nonce,
    ByteSpan             ct,
    ByteSpan             aad)
{
    if (ct.size() < AEAD_TAG_SIZE) {
        return Result<Bytes>::err("Ciphertext too short (missing auth tag)");
    }

    Bytes pt(ct.size() - AEAD_TAG_SIZE);
    unsigned long long pt_len = 0;

    int rc = crypto_aead_chacha20poly1305_ietf_decrypt(
        pt.data(),
        &pt_len,
        nullptr,            // nsec — not used
        ct.data(), ct.size(),
        aad.empty() ? nullptr : aad.data(), aad.size(),
        nonce.data(),
        key.data()
    );

    if (rc != 0) {
        // Do NOT reveal whether it was tag mismatch vs other error
        return Result<Bytes>::err("AEAD decryption failed (authentication error)");
    }

    pt.resize(static_cast<size_t>(pt_len));
    return Result<Bytes>::ok(std::move(pt));
}

} // namespace epn::crypto
