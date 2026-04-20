#include <epn/crypto/keys.hpp>
#include <sodium.h>
#include <stdexcept>

namespace epn::crypto {

Result<X25519KeyPair> generate_x25519_keypair() {
    // libsodium: crypto_box uses Curve25519 (X25519) internally
    // crypto_box_keypair generates a keypair suitable for X25519 DH
    X25519KeyPair kp;
    if (crypto_box_keypair(kp.pubkey.data(), kp.privkey.data()) != 0) {
        return Result<X25519KeyPair>::err("X25519 keypair generation failed");
    }
    return Result<X25519KeyPair>::ok(std::move(kp));
}

Result<SigningKeyPair> generate_signing_keypair() {
    SigningKeyPair kp;
    if (crypto_sign_keypair(kp.pubkey.data(), kp.privkey.data()) != 0) {
        return Result<SigningKeyPair>::err("Ed25519 keypair generation failed");
    }
    return Result<SigningKeyPair>::ok(std::move(kp));
}

Bytes generate_random_bytes(size_t n) {
    Bytes out(n);
    randombytes_buf(out.data(), n);
    return out;
}

SessionId generate_session_id() {
    SessionId sid;
    randombytes_buf(sid.data.data(), sid.data.size());
    return sid;
}

NodeId pubkey_to_node_id(const RawPublicKey& pubkey) {
    NodeId nid;
    // BLAKE2b-256 hash of the pubkey
    crypto_generichash(
        nid.data.data(), nid.data.size(),
        pubkey.data(), pubkey.size(),
        nullptr, 0
    );
    return nid;
}

} // namespace epn::crypto
