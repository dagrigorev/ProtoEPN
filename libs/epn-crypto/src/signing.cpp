#include <epn/crypto/signing.hpp>
#include <sodium.h>
#include <cstring>

namespace epn::crypto {

Result<RawSignature> sign_detached(const RawSignKey& sk, ByteSpan message) {
    RawSignature sig;
    unsigned long long sig_len = 0;

    int rc = crypto_sign_detached(
        sig.data(), &sig_len,
        message.data(), message.size(),
        sk.data()
    );

    if (rc != 0 || sig_len != sig.size()) {
        return Result<RawSignature>::err("Ed25519 signing failed");
    }

    return Result<RawSignature>::ok(sig);
}

Result<void> verify_detached(
    const RawSignPubKey& pk,
    ByteSpan             message,
    const RawSignature&  sig)
{
    int rc = crypto_sign_verify_detached(
        sig.data(),
        message.data(), message.size(),
        pk.data()
    );

    if (rc != 0) {
        return Result<void>::err("Ed25519 signature verification failed");
    }

    return Result<void>::ok();
}

Bytes make_announcement_signing_payload(
    core::NodeRole      role,
    const RawPublicKey& dh_pubkey,
    const RawSignPubKey& sign_pubkey,
    int64_t             timestamp,
    int32_t             ttl,
    const std::string&  addr,
    uint16_t            port)
{
    // Format: "EPN-ANNOUNCE" || role(1) || dh_pubkey(32) || sign_pubkey(32) ||
    //          timestamp(8,BE) || ttl(4,BE) || addr_len(2,BE) || addr || port(2,BE)
    static const uint8_t PREFIX[] = "EPN-ANNOUNCE";
    const size_t prefix_len = sizeof(PREFIX) - 1;
    const size_t addr_len   = addr.size();
    const size_t total      = prefix_len + 1 + 32 + 32 + 8 + 4 + 2 + addr_len + 2;

    Bytes payload(total);
    size_t offset = 0;

    std::memcpy(payload.data() + offset, PREFIX, prefix_len); offset += prefix_len;
    payload[offset++] = static_cast<uint8_t>(role);
    std::memcpy(payload.data() + offset, dh_pubkey.data(), 32);   offset += 32;
    std::memcpy(payload.data() + offset, sign_pubkey.data(), 32);  offset += 32;

    // timestamp (8 bytes BE)
    for (int i = 7; i >= 0; --i) {
        payload[offset++] = static_cast<uint8_t>((timestamp >> (i * 8)) & 0xFF);
    }
    // ttl (4 bytes BE)
    core::write_be32(payload.data() + offset, static_cast<uint32_t>(ttl)); offset += 4;
    // addr_len (2 bytes BE)
    core::write_be16(payload.data() + offset, static_cast<uint16_t>(addr_len)); offset += 2;
    // addr
    std::memcpy(payload.data() + offset, addr.data(), addr_len); offset += addr_len;
    // port (2 bytes BE)
    core::write_be16(payload.data() + offset, port); offset += 2;

    return payload;
}

} // namespace epn::crypto
