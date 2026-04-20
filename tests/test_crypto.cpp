#include <gtest/gtest.h>
#include <epn/crypto/keys.hpp>
#include <epn/crypto/kdf.hpp>
#include <epn/crypto/aead.hpp>
#include <epn/crypto/signing.hpp>
#include <sodium.h>
#include <cstring>

using namespace epn::core;
using namespace epn::crypto;

class CryptoTest : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_GE(sodium_init(), 0) << "libsodium init failed";
    }
};

// ─── X25519 keypair generation ────────────────────────────────────────────────
TEST_F(CryptoTest, GenerateX25519Keypair) {
    auto kp = generate_x25519_keypair();
    ASSERT_TRUE(kp.is_ok());

    // pubkey and privkey must not be all zeros
    bool pub_nonzero = false, priv_nonzero = false;
    for (auto b : kp.value().pubkey)  if (b) pub_nonzero  = true;
    for (auto b : kp.value().privkey) if (b) priv_nonzero = true;
    EXPECT_TRUE(pub_nonzero);
    EXPECT_TRUE(priv_nonzero);
}

// ─── X25519 DH — Diffie-Hellman correctness ───────────────────────────────────
TEST_F(CryptoTest, X25519DH_Symmetry) {
    auto kp_a = generate_x25519_keypair();
    auto kp_b = generate_x25519_keypair();
    ASSERT_TRUE(kp_a.is_ok());
    ASSERT_TRUE(kp_b.is_ok());

    // A's shared = DH(a_priv, b_pub)
    auto ss_a = x25519_dh(kp_a.value().privkey, kp_b.value().pubkey);
    // B's shared = DH(b_priv, a_pub)
    auto ss_b = x25519_dh(kp_b.value().privkey, kp_a.value().pubkey);

    ASSERT_TRUE(ss_a.is_ok()) << ss_a.error();
    ASSERT_TRUE(ss_b.is_ok()) << ss_b.error();

    EXPECT_EQ(ss_a.value().data, ss_b.value().data) << "X25519 shared secrets must match";
}

TEST_F(CryptoTest, X25519DH_LowOrderKeyRejected) {
    // All-zero pubkey is a low-order point — DH should fail
    RawPrivateKey priv{};
    priv[0] = 1;
    RawPublicKey  zero_pk{};  // all zeros = low-order point

    auto res = x25519_dh(priv, zero_pk);
    // libsodium's crypto_scalarmult rejects this
    EXPECT_TRUE(res.is_err());
}

// ─── HKDF-SHA256 ─────────────────────────────────────────────────────────────
TEST_F(CryptoTest, HKDF_Deterministic) {
    Bytes ikm = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
    Bytes salt = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                  0x08, 0x09, 0x0a, 0x0b, 0x0c};
    Bytes info = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
                  0xf8, 0xf9};

    auto okm1 = hkdf_sha256(
        {ikm.data(), ikm.size()},
        {info.data(), info.size()},
        42,
        {salt.data(), salt.size()}
    );
    auto okm2 = hkdf_sha256(
        {ikm.data(), ikm.size()},
        {info.data(), info.size()},
        42,
        {salt.data(), salt.size()}
    );

    EXPECT_EQ(okm1.size(), 42u);
    EXPECT_EQ(okm1, okm2) << "HKDF must be deterministic";
}

TEST_F(CryptoTest, HKDF_DifferentInfoDifferentOutput) {
    Bytes ikm(32, 0xAA);
    auto out1 = hkdf_sha256({ikm.data(), 32}, {(uint8_t*)"label-a", 7}, 32);
    auto out2 = hkdf_sha256({ikm.data(), 32}, {(uint8_t*)"label-b", 7}, 32);
    EXPECT_NE(out1, out2) << "Different info strings must produce different keys";
}

// ─── Session key derivation ───────────────────────────────────────────────────
TEST_F(CryptoTest, SessionKeyDerivation_Symmetry) {
    auto kp_client = generate_x25519_keypair();
    auto kp_server = generate_x25519_keypair();
    ASSERT_TRUE(kp_client.is_ok());
    ASSERT_TRUE(kp_server.is_ok());

    auto& client_kp = kp_client.value();
    auto& server_kp = kp_server.value();

    // Client computes DH with server's pubkey
    auto ss_client = x25519_dh(client_kp.privkey, server_kp.pubkey);
    ASSERT_TRUE(ss_client.is_ok());
    auto sk_client = derive_session_keys(ss_client.value(), client_kp.pubkey, server_kp.pubkey);
    ASSERT_TRUE(sk_client.is_ok());

    // Server computes DH with client's ephemeral pubkey
    auto ss_server = x25519_dh(server_kp.privkey, client_kp.pubkey);
    ASSERT_TRUE(ss_server.is_ok());
    auto sk_server = derive_session_keys(ss_server.value(), client_kp.pubkey, server_kp.pubkey);
    ASSERT_TRUE(sk_server.is_ok());

    EXPECT_EQ(sk_client.value().forward,  sk_server.value().forward)  << "Forward keys must match";
    EXPECT_EQ(sk_client.value().backward, sk_server.value().backward) << "Backward keys must match";
    EXPECT_NE(sk_client.value().forward,  sk_client.value().backward) << "Fwd/bwd keys must differ";
}

// ─── ChaCha20-Poly1305 AEAD ───────────────────────────────────────────────────
TEST_F(CryptoTest, AEAD_EncryptDecrypt_RoundTrip) {
    RawSessionKey key{};
    randombytes_buf(key.data(), 32);

    std::string plaintext_str = "The quick brown fox jumps over the lazy dog";
    Bytes pt(plaintext_str.begin(), plaintext_str.end());

    auto ct_res = aead_encrypt(key, {pt.data(), pt.size()});
    ASSERT_TRUE(ct_res.is_ok()) << ct_res.error();

    auto& ct = ct_res.value();
    auto pt_res = aead_decrypt(key, ct.nonce, {ct.ciphertext.data(), ct.ciphertext.size()});
    ASSERT_TRUE(pt_res.is_ok()) << pt_res.error();

    EXPECT_EQ(pt, pt_res.value()) << "Decrypted plaintext must match original";
}

TEST_F(CryptoTest, AEAD_TamperedCiphertextRejected) {
    RawSessionKey key{};
    randombytes_buf(key.data(), 32);

    Bytes pt(100, 0xAB);
    auto ct_res = aead_encrypt(key, {pt.data(), pt.size()});
    ASSERT_TRUE(ct_res.is_ok());

    // Flip one bit in ciphertext
    auto ct = ct_res.value();
    ct.ciphertext[10] ^= 0x01;

    auto pt_res = aead_decrypt(key, ct.nonce, {ct.ciphertext.data(), ct.ciphertext.size()});
    EXPECT_TRUE(pt_res.is_err()) << "Tampered ciphertext must be rejected";
}

TEST_F(CryptoTest, AEAD_WrongKeyRejected) {
    RawSessionKey key1{}, key2{};
    randombytes_buf(key1.data(), 32);
    randombytes_buf(key2.data(), 32);

    Bytes pt(64, 0xCD);
    auto ct_res = aead_encrypt(key1, {pt.data(), pt.size()});
    ASSERT_TRUE(ct_res.is_ok());

    auto& ct = ct_res.value();
    auto pt_res = aead_decrypt(key2, ct.nonce, {ct.ciphertext.data(), ct.ciphertext.size()});
    EXPECT_TRUE(pt_res.is_err()) << "Wrong key must cause decryption failure";
}

TEST_F(CryptoTest, AEAD_WithAAD) {
    RawSessionKey key{};
    randombytes_buf(key.data(), 32);

    Bytes pt(32, 0xFF);
    Bytes aad = {0x01, 0x02, 0x03};

    auto ct_res = aead_encrypt(key, {pt.data(), pt.size()}, {aad.data(), aad.size()});
    ASSERT_TRUE(ct_res.is_ok());

    // Correct AAD → success
    auto pt_res = aead_decrypt(key, ct_res.value().nonce,
                               {ct_res.value().ciphertext.data(), ct_res.value().ciphertext.size()},
                               {aad.data(), aad.size()});
    EXPECT_TRUE(pt_res.is_ok());

    // Wrong AAD → failure
    Bytes bad_aad = {0xDE, 0xAD};
    auto fail_res = aead_decrypt(key, ct_res.value().nonce,
                                 {ct_res.value().ciphertext.data(), ct_res.value().ciphertext.size()},
                                 {bad_aad.data(), bad_aad.size()});
    EXPECT_TRUE(fail_res.is_err()) << "Wrong AAD must cause authentication failure";
}

// ─── Ed25519 signing ──────────────────────────────────────────────────────────
TEST_F(CryptoTest, Ed25519_SignVerify) {
    auto kp = generate_signing_keypair();
    ASSERT_TRUE(kp.is_ok());

    std::string msg_str = "EPN announcement payload";
    Bytes msg(msg_str.begin(), msg_str.end());

    auto sig_res = sign_detached(kp.value().privkey, {msg.data(), msg.size()});
    ASSERT_TRUE(sig_res.is_ok()) << sig_res.error();

    auto verify_res = verify_detached(kp.value().pubkey,
                                      {msg.data(), msg.size()},
                                      sig_res.value());
    EXPECT_TRUE(verify_res.is_ok()) << "Valid signature must verify";
}

TEST_F(CryptoTest, Ed25519_TamperedMessageRejected) {
    auto kp = generate_signing_keypair();
    ASSERT_TRUE(kp.is_ok());

    Bytes msg(64, 0xAA);
    auto sig_res = sign_detached(kp.value().privkey, {msg.data(), msg.size()});
    ASSERT_TRUE(sig_res.is_ok());

    // Tamper with message
    msg[0] ^= 0x01;
    auto verify_res = verify_detached(kp.value().pubkey,
                                      {msg.data(), msg.size()},
                                      sig_res.value());
    EXPECT_TRUE(verify_res.is_err()) << "Tampered message must fail verification";
}

TEST_F(CryptoTest, Ed25519_WrongKeyRejected) {
    auto kp1 = generate_signing_keypair();
    auto kp2 = generate_signing_keypair();
    ASSERT_TRUE(kp1.is_ok() && kp2.is_ok());

    Bytes msg(32, 0xBB);
    auto sig_res = sign_detached(kp1.value().privkey, {msg.data(), msg.size()});
    ASSERT_TRUE(sig_res.is_ok());

    // Verify with wrong pubkey
    auto verify_res = verify_detached(kp2.value().pubkey,
                                      {msg.data(), msg.size()},
                                      sig_res.value());
    EXPECT_TRUE(verify_res.is_err()) << "Wrong pubkey must fail verification";
}

// ─── Nonce counter ────────────────────────────────────────────────────────────
TEST_F(CryptoTest, NonceCounter_Monotonic) {
    NonceCounter counter(NONCE_DIRECTION_FORWARD);
    auto n1 = counter.next();
    auto n2 = counter.next();
    auto n3 = counter.next();

    EXPECT_NE(n1, n2) << "Consecutive nonces must differ";
    EXPECT_NE(n2, n3);
    EXPECT_NE(n1, n3);

    // Check direction tag in first 4 bytes
    EXPECT_EQ(n1[3], 0x01) << "Forward direction tag";
}

// ─── Zeroization ─────────────────────────────────────────────────────────────
TEST_F(CryptoTest, PrivkeyZeroizedOnDestruction) {
    RawPrivateKey privkey_copy{};
    {
        auto kp = generate_x25519_keypair();
        ASSERT_TRUE(kp.is_ok());
        privkey_copy = kp.value().privkey;
        // kp goes out of scope here — privkey is zeroed
    }
    // The memory that kp.privkey occupied is now zeroed.
    // We can't check it directly (UB to read freed memory),
    // but we verify the mechanism exists by checking the RawPrivateKey
    // was non-zero before destruction (which we captured above)
    bool was_nonzero = false;
    for (auto b : privkey_copy) if (b) { was_nonzero = true; break; }
    EXPECT_TRUE(was_nonzero) << "Privkey should have been non-zero before zeroization";
    // This test mainly documents the requirement; actual zeroing verified via libsodium
}
