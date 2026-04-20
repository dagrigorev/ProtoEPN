#include <gtest/gtest.h>
#include <epn/protocol/framing.hpp>
#include <epn/protocol/onion.hpp>
#include <epn/crypto/keys.hpp>
#include <epn/crypto/signing.hpp>
#include <sodium.h>

using namespace epn::core;
using namespace epn::crypto;
using namespace epn::protocol;

class ProtocolTest : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);
    }
};

// ─── Frame encoding / decoding ────────────────────────────────────────────────
TEST_F(ProtocolTest, FrameEncodeDecode_Empty) {
    Frame f{MsgType::KEEPALIVE, {}};
    auto wire = encode_frame(f);

    // Header: 4-byte len (0) + 1-byte type
    ASSERT_EQ(wire.size(), 5u);
    EXPECT_EQ(read_be32(wire.data()), 0u);
    EXPECT_EQ(wire[4], static_cast<uint8_t>(MsgType::KEEPALIVE));

    auto decoded = decode_frame({wire.data(), wire.size()});
    ASSERT_TRUE(decoded.is_ok());
    EXPECT_EQ(decoded.value().type, MsgType::KEEPALIVE);
    EXPECT_TRUE(decoded.value().payload.empty());
}

TEST_F(ProtocolTest, FrameEncodeDecode_WithPayload) {
    Bytes payload(256, 0xAB);
    Frame f{MsgType::SESSION_DATA, payload};
    auto wire = encode_frame(f);

    EXPECT_EQ(wire.size(), 5u + 256u);

    auto decoded = decode_frame({wire.data(), wire.size()});
    ASSERT_TRUE(decoded.is_ok());
    EXPECT_EQ(decoded.value().type, MsgType::SESSION_DATA);
    EXPECT_EQ(decoded.value().payload, payload);
}

TEST_F(ProtocolTest, FrameDecode_TooShort) {
    Bytes truncated = {0x00, 0x00};  // Not even a full header
    auto decoded = decode_frame({truncated.data(), truncated.size()});
    EXPECT_TRUE(decoded.is_err());
}

TEST_F(ProtocolTest, FrameDecode_TruncatedPayload) {
    // Claim 100 bytes payload but only provide 10
    Bytes wire(5 + 10);
    write_be32(wire.data(), 100);  // claim 100
    wire[4] = static_cast<uint8_t>(MsgType::SESSION_DATA);
    // only 10 payload bytes follow

    auto decoded = decode_frame({wire.data(), wire.size()});
    EXPECT_TRUE(decoded.is_err());
}

TEST_F(ProtocolTest, PeekFrameTotalLen) {
    Frame f{MsgType::ONION_FORWARD, Bytes(500, 0x01)};
    auto wire = encode_frame(f);

    EXPECT_EQ(peek_frame_total_len({wire.data(), wire.size()}), 5u + 500u);
    EXPECT_EQ(peek_frame_total_len({wire.data(), 3}), 0u);  // Too short to peek
}

// ─── Onion construction and peeling ──────────────────────────────────────────
class OnionTest : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);

        // Generate keypairs for 3 relays + server
        for (int i = 0; i < 4; ++i) {
            auto kp = generate_x25519_keypair();
            ASSERT_TRUE(kp.is_ok());
            keypairs_.push_back(std::move(kp.value()));
        }
    }

    std::vector<X25519KeyPair> keypairs_;
};

TEST_F(OnionTest, BuildAndPeel_SingleHop) {
    // 1 relay + server (minimal 2-hop)
    std::vector<HopDescriptor> hops;

    // Relay
    HopDescriptor relay_hop;
    relay_hop.addr        = "127.0.0.1";
    relay_hop.port        = 9001;
    relay_hop.node_pubkey = keypairs_[0].pubkey;
    hops.push_back(relay_hop);

    // Server (final)
    HopDescriptor server_hop;
    server_hop.addr        = "127.0.0.1";
    server_hop.port        = 9100;
    server_hop.node_pubkey = keypairs_[1].pubkey;
    hops.push_back(server_hop);

    SessionId sid{};
    randombytes_buf(sid.data.data(), 32);

    Bytes payload = {0xDE, 0xAD, 0xBE, 0xEF};

    auto onion_res = build_onion(hops, sid, {payload.data(), payload.size()});
    ASSERT_TRUE(onion_res.is_ok()) << onion_res.error();
    Bytes onion_wire = onion_res.value().wire;

    // Relay peels outer layer
    auto peeled_relay = peel_onion(keypairs_[0].privkey,
                                   {onion_wire.data(), onion_wire.size()});
    ASSERT_TRUE(peeled_relay.is_ok()) << peeled_relay.error();

    EXPECT_EQ(peeled_relay.value().hop_type, HopType::RELAY);
    EXPECT_EQ(peeled_relay.value().next_addr, "127.0.0.1");
    EXPECT_EQ(peeled_relay.value().next_port, 9100);
    EXPECT_FALSE(peeled_relay.value().inner.empty());

    // Server peels inner layer
    auto peeled_server = peel_onion(keypairs_[1].privkey,
                                    {peeled_relay.value().inner.data(),
                                     peeled_relay.value().inner.size()});
    ASSERT_TRUE(peeled_server.is_ok()) << peeled_server.error();

    EXPECT_EQ(peeled_server.value().hop_type, HopType::FINAL);
    EXPECT_EQ(peeled_server.value().session_id.data, sid.data);
    EXPECT_EQ(peeled_server.value().inner, payload);
}

TEST_F(OnionTest, BuildAndPeel_ThreeHops) {
    // 3 relays + server (standard EPN route)
    std::vector<HopDescriptor> hops;
    std::vector<std::string> addrs = {"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"};
    std::vector<uint16_t>    ports = {9001, 9002, 9003, 9100};
    std::vector<NodeRole>    roles = {NodeRole::Relay, NodeRole::Relay,
                                       NodeRole::Relay, NodeRole::Server};

    for (int i = 0; i < 4; ++i) {
        HopDescriptor h;
        h.addr        = addrs[static_cast<size_t>(i)];
        h.port        = ports[static_cast<size_t>(i)];
        h.node_pubkey = keypairs_[static_cast<size_t>(i)].pubkey;
        hops.push_back(h);
    }

    SessionId sid{};
    randombytes_buf(sid.data.data(), 32);

    std::string msg_str = "Sensitive ephemeral data";
    Bytes payload(msg_str.begin(), msg_str.end());

    auto onion_res = build_onion(hops, sid, {payload.data(), payload.size()});
    ASSERT_TRUE(onion_res.is_ok()) << onion_res.error();
    Bytes onion_wire = onion_res.value().wire;

    Bytes current = onion_wire;

    // Relay1 peels
    auto p1 = peel_onion(keypairs_[0].privkey, {current.data(), current.size()});
    ASSERT_TRUE(p1.is_ok()) << p1.error();
    EXPECT_EQ(p1.value().hop_type,  HopType::RELAY);
    EXPECT_EQ(p1.value().next_addr, "10.0.0.2");
    EXPECT_EQ(p1.value().next_port, 9002);

    // Relay2 peels
    auto p2 = peel_onion(keypairs_[1].privkey,
                         {p1.value().inner.data(), p1.value().inner.size()});
    ASSERT_TRUE(p2.is_ok()) << p2.error();
    EXPECT_EQ(p2.value().hop_type,  HopType::RELAY);
    EXPECT_EQ(p2.value().next_addr, "10.0.0.3");
    EXPECT_EQ(p2.value().next_port, 9003);

    // Relay3 peels
    auto p3 = peel_onion(keypairs_[2].privkey,
                         {p2.value().inner.data(), p2.value().inner.size()});
    ASSERT_TRUE(p3.is_ok()) << p3.error();
    EXPECT_EQ(p3.value().hop_type,  HopType::RELAY);
    EXPECT_EQ(p3.value().next_addr, "10.0.0.4");
    EXPECT_EQ(p3.value().next_port, 9100);

    // Server peels final
    auto p_final = peel_onion(keypairs_[3].privkey,
                              {p3.value().inner.data(), p3.value().inner.size()});
    ASSERT_TRUE(p_final.is_ok()) << p_final.error();
    EXPECT_EQ(p_final.value().hop_type,  HopType::FINAL);
    EXPECT_EQ(p_final.value().session_id.data, sid.data);
    EXPECT_EQ(p_final.value().inner, payload);
}

TEST_F(OnionTest, WrongKeyCannotPeel) {
    std::vector<HopDescriptor> hops;
    for (int i = 0; i < 2; ++i) {
        HopDescriptor h;
        h.addr        = "127.0.0.1";
        h.port        = static_cast<uint16_t>(9000 + i);
        h.node_pubkey = keypairs_[static_cast<size_t>(i)].pubkey;
        hops.push_back(h);
    }

    SessionId sid{};
    randombytes_buf(sid.data.data(), 32);
    Bytes payload(16, 0xFF);

    auto onion_res = build_onion(hops, sid, {payload.data(), payload.size()});
    ASSERT_TRUE(onion_res.is_ok());
    Bytes onion_wire = onion_res.value().wire;

    // Try to peel with relay2's key (wrong key for outer layer)
    auto bad_peel = peel_onion(keypairs_[1].privkey,
                               {onion_wire.data(), onion_wire.size()});
    EXPECT_TRUE(bad_peel.is_err()) << "Wrong key must fail decryption";
}

TEST_F(OnionTest, EphemeralKeyTracker_ReplayDetected) {
    EphemeralKeyTracker tracker(60);

    RawPublicKey epk{};
    randombytes_buf(epk.data(), 32);

    EXPECT_TRUE(tracker.check_and_insert(epk));   // First time: fresh
    EXPECT_FALSE(tracker.check_and_insert(epk));  // Second time: replay
    EXPECT_FALSE(tracker.check_and_insert(epk));  // Third time: still replay
}

TEST_F(OnionTest, EphemeralKeyTracker_DifferentKeysAccepted) {
    EphemeralKeyTracker tracker(60);

    for (int i = 0; i < 100; ++i) {
        RawPublicKey epk{};
        randombytes_buf(epk.data(), 32);
        EXPECT_TRUE(tracker.check_and_insert(epk)) << "Fresh key should be accepted";
    }
}

// ─── Announce signing ─────────────────────────────────────────────────────────
TEST_F(ProtocolTest, AnnouncePayload_Canonical) {
    auto sign_kp = generate_signing_keypair();
    ASSERT_TRUE(sign_kp.is_ok());

    RawPublicKey dh_pk{};
    randombytes_buf(dh_pk.data(), 32);

    auto payload = epn::crypto::make_announcement_signing_payload(
        NodeRole::Relay, dh_pk, sign_kp.value().pubkey,
        1700000000LL, 60, "192.168.1.1", 9001
    );

    EXPECT_FALSE(payload.empty());

    // Sign and verify
    auto sig = epn::crypto::sign_detached(
        sign_kp.value().privkey, {payload.data(), payload.size()});
    ASSERT_TRUE(sig.is_ok());

    auto verify = epn::crypto::verify_detached(
        sign_kp.value().pubkey, {payload.data(), payload.size()}, sig.value());
    EXPECT_TRUE(verify.is_ok()) << "Announcement signature must verify";
}
