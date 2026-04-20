#include <epn/protocol/onion.hpp>
#include <sodium.h>
#include <cstring>
#include <stdexcept>

namespace epn::protocol {

using namespace epn::core;
using namespace epn::crypto;

static const uint8_t AAD_PREFIX[]   = "EPN-ONION-V1";
static const size_t  AAD_PREFIX_LEN = sizeof(AAD_PREFIX) - 1;

static Bytes make_aad(const RawPublicKey& epk) {
    Bytes aad(AAD_PREFIX_LEN + 32);
    std::memcpy(aad.data(), AAD_PREFIX, AAD_PREFIX_LEN);
    std::memcpy(aad.data() + AAD_PREFIX_LEN, epk.data(), 32);
    return aad;
}

// ─── Encrypt one layer, optionally returning the derived session key ───────────
struct LayerResult {
    Bytes      wire;
    SessionKey session_key; // only meaningful if capture_key == true
};

static Result<LayerResult> encrypt_layer(
    const RawPublicKey& hop_pubkey,
    ByteSpan            inner,
    bool                capture_key = false)
{
    auto kp_res = generate_x25519_keypair();
    if (kp_res.is_err()) return Result<LayerResult>::err(kp_res.error());
    auto& kp = kp_res.value();

    auto dh_res = x25519_dh(kp.privkey, hop_pubkey);
    if (dh_res.is_err()) return Result<LayerResult>::err("DH: " + dh_res.error());

    auto sk_res = derive_session_keys(dh_res.value(), kp.pubkey, hop_pubkey);
    if (sk_res.is_err()) return Result<LayerResult>::err("KDF: " + sk_res.error());

    Bytes aad = make_aad(kp.pubkey);

    auto ct_res = aead_encrypt(sk_res.value().forward,
                               {inner.data(), inner.size()},
                               {aad.data(), aad.size()});
    if (ct_res.is_err()) return Result<LayerResult>::err("AEAD: " + ct_res.error());

    auto& ct = ct_res.value();
    Bytes wire(32 + 12 + 4 + ct.ciphertext.size());
    size_t off = 0;
    std::memcpy(wire.data() + off, kp.pubkey.data(), 32);                             off += 32;
    std::memcpy(wire.data() + off, ct.nonce.data(), 12);                              off += 12;
    write_be32(wire.data() + off, static_cast<uint32_t>(ct.ciphertext.size()));       off += 4;
    std::memcpy(wire.data() + off, ct.ciphertext.data(), ct.ciphertext.size());

    LayerResult result;
    result.wire = std::move(wire);
    if (capture_key) result.session_key = std::move(sk_res.value());
    return Result<LayerResult>::ok(std::move(result));
}

// Relay hop plaintext: [1 RELAY][2 BE port][1 addr_len][addr][inner]
static Bytes make_relay_payload(const std::string& addr, uint16_t port, ByteSpan inner) {
    Bytes p(1 + 2 + 1 + addr.size() + inner.size());
    size_t off = 0;
    p[off++] = static_cast<uint8_t>(HopType::RELAY);
    write_be16(p.data() + off, port);                                  off += 2;
    p[off++] = static_cast<uint8_t>(addr.size());
    std::memcpy(p.data() + off, addr.data(), addr.size());             off += addr.size();
    std::memcpy(p.data() + off, inner.data(), inner.size());
    return p;
}

// Final hop plaintext: [1 FINAL][32 session_id][payload]
static Bytes make_final_payload(const SessionId& sid, ByteSpan payload) {
    Bytes p(1 + 32 + payload.size());
    p[0] = static_cast<uint8_t>(HopType::FINAL);
    std::memcpy(p.data() + 1,  sid.data.data(), 32);
    std::memcpy(p.data() + 33, payload.data(),  payload.size());
    return p;
}

// ─── build_onion ─────────────────────────────────────────────────────────────
Result<OnionBuildResult> build_onion(
    const std::vector<HopDescriptor>& hops,
    const SessionId&                  session_id,
    ByteSpan                          payload)
{
    if (hops.size() < 2)
        return Result<OnionBuildResult>::err("Need ≥2 hops (relay + server)");

    // Innermost layer: server (FINAL hop) — capture session key for client
    const HopDescriptor& server = hops.back();
    Bytes final_pt = make_final_payload(session_id, payload);

    auto server_layer = encrypt_layer(server.node_pubkey,
                                      {final_pt.data(), final_pt.size()},
                                      /*capture_key=*/true);
    if (server_layer.is_err())
        return Result<OnionBuildResult>::err("Server layer: " + server_layer.error());

    // Save server session key before it gets moved
    SessionKey server_sk = std::move(server_layer.value().session_key);
    Bytes current = std::move(server_layer.value().wire);

    // Wrap relay layers from inner to outer
    for (int i = static_cast<int>(hops.size()) - 2; i >= 0; --i) {
        const HopDescriptor& next = hops[static_cast<size_t>(i + 1)];
        Bytes relay_pt = make_relay_payload(next.addr, next.port,
                                            {current.data(), current.size()});
        auto wrapped = encrypt_layer(hops[static_cast<size_t>(i)].node_pubkey,
                                     {relay_pt.data(), relay_pt.size()},
                                     /*capture_key=*/false);
        if (wrapped.is_err())
            return Result<OnionBuildResult>::err(
                "Relay " + std::to_string(i) + ": " + wrapped.error());
        current = std::move(wrapped.value().wire);
    }

    OnionBuildResult result;
    result.wire             = std::move(current);
    result.server_session_key = std::move(server_sk);
    return Result<OnionBuildResult>::ok(std::move(result));
}

// ─── peel_onion ──────────────────────────────────────────────────────────────
Result<PeeledOnion> peel_onion(const RawPrivateKey& privkey, ByteSpan wire) {
    if (wire.size() < ONION_HEADER_SIZE)
        return Result<PeeledOnion>::err("Packet too short");

    size_t off = 0;
    RawPublicKey epk;
    std::memcpy(epk.data(), wire.data() + off, 32); off += 32;

    RawNonce nonce;
    std::memcpy(nonce.data(), wire.data() + off, 12); off += 12;

    uint32_t ct_len = read_be32(wire.data() + off); off += 4;
    if (wire.size() < off + ct_len || ct_len < AEAD_TAG_SIZE)
        return Result<PeeledOnion>::err("Ciphertext truncated or too short");

    ByteSpan ct(wire.data() + off, ct_len);

    // Derive our own pubkey for key derivation context
    RawPublicKey our_pk;
    crypto_scalarmult_base(our_pk.data(), privkey.data());

    auto dh_res = x25519_dh(privkey, epk);
    if (dh_res.is_err()) return Result<PeeledOnion>::err("DH: " + dh_res.error());

    auto sk_res = derive_session_keys(dh_res.value(), epk, our_pk);
    if (sk_res.is_err()) return Result<PeeledOnion>::err("KDF: " + sk_res.error());

    Bytes aad = make_aad(epk);
    auto pt_res = aead_decrypt(sk_res.value().forward, nonce, ct,
                               {aad.data(), aad.size()});
    if (pt_res.is_err()) return Result<PeeledOnion>::err("Decrypt: " + pt_res.error());

    const Bytes& pt = pt_res.value();
    if (pt.empty()) return Result<PeeledOnion>::err("Empty plaintext");

    PeeledOnion result;
    result.hop_type = static_cast<HopType>(pt[0]);

    if (result.hop_type == HopType::RELAY) {
        if (pt.size() < 4) return Result<PeeledOnion>::err("RELAY too short");
        size_t poff = 1;
        result.next_port = read_be16(pt.data() + poff);          poff += 2;
        uint8_t alen = pt[poff++];
        if (pt.size() < poff + alen) return Result<PeeledOnion>::err("addr truncated");
        result.next_addr = std::string(
            reinterpret_cast<const char*>(pt.data() + poff), alen);
        poff += alen;
        result.inner = Bytes(pt.begin() + static_cast<ptrdiff_t>(poff), pt.end());

    } else if (result.hop_type == HopType::FINAL) {
        if (pt.size() < 33) return Result<PeeledOnion>::err("FINAL too short");
        std::memcpy(result.session_id.data.data(), pt.data() + 1, 32);
        result.inner = Bytes(pt.begin() + 33, pt.end());

    } else {
        return Result<PeeledOnion>::err("Unknown hop_type 0x" + to_hex({pt.data(), 1}));
    }

    return Result<PeeledOnion>::ok(std::move(result));
}

} // namespace epn::protocol
