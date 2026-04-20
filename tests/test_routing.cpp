#include <gtest/gtest.h>
#include <epn/discovery/announcement.hpp>
#include <epn/crypto/keys.hpp>
#include <epn/crypto/signing.hpp>
#include <sodium.h>

using namespace epn::core;
using namespace epn::crypto;
using namespace epn::discovery;

class DiscoveryTest : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);
    }

    // Build a valid, signed NodeAnnouncement
    NodeAnnouncement make_announcement(NodeRole role, const std::string& addr, uint16_t port) {
        auto kp      = generate_x25519_keypair();
        auto sign_kp = generate_signing_keypair();
        EXPECT_TRUE(kp.is_ok());
        EXPECT_TRUE(sign_kp.is_ok());

        NodeId nid = pubkey_to_node_id(kp.value().pubkey);

        NodeAnnouncement ann;
        ann.node_id_hex = to_hex({nid.data.data(), 32});
        ann.role        = role;
        ann.addr        = addr;
        ann.port        = port;
        ann.dh_pubkey   = kp.value().pubkey;
        ann.sign_pubkey = sign_kp.value().pubkey;
        ann.timestamp   = now_unix();
        ann.ttl         = 60;

        auto payload = make_announcement_signing_payload(
            role, ann.dh_pubkey, ann.sign_pubkey,
            ann.timestamp, ann.ttl, addr, port);
        auto sig = sign_detached(sign_kp.value().privkey, {payload.data(), payload.size()});
        EXPECT_TRUE(sig.is_ok());
        ann.signature = sig.value();

        return ann;
    }
};

// ─── AnnouncementRegistry ─────────────────────────────────────────────────────
TEST_F(DiscoveryTest, Registry_UpsertAndQuery) {
    AnnouncementRegistry reg;

    auto ann = make_announcement(NodeRole::Relay, "127.0.0.1", 9001);
    auto res = reg.upsert(ann);
    ASSERT_TRUE(res.is_ok()) << res.error();
    EXPECT_EQ(reg.size(), 1u);

    auto relays = reg.query(NodeRole::Relay);
    EXPECT_EQ(relays.size(), 1u);
    EXPECT_EQ(relays[0].addr, "127.0.0.1");
    EXPECT_EQ(relays[0].port, 9001);

    // Querying servers should return nothing
    auto servers = reg.query(NodeRole::Server);
    EXPECT_TRUE(servers.empty());
}

TEST_F(DiscoveryTest, Registry_MultipleRelays) {
    AnnouncementRegistry reg;

    for (int i = 0; i < 5; ++i) {
        auto ann = make_announcement(NodeRole::Relay, "127.0.0.1",
                                     static_cast<uint16_t>(9000 + i));
        ASSERT_TRUE(reg.upsert(ann).is_ok());
    }

    auto ann_server = make_announcement(NodeRole::Server, "127.0.0.1", 9100);
    ASSERT_TRUE(reg.upsert(ann_server).is_ok());

    EXPECT_EQ(reg.size(), 6u);
    EXPECT_EQ(reg.query(NodeRole::Relay).size(), 5u);
    EXPECT_EQ(reg.query(NodeRole::Server).size(), 1u);
}

TEST_F(DiscoveryTest, Registry_InvalidSignatureRejected) {
    AnnouncementRegistry reg;

    auto ann = make_announcement(NodeRole::Relay, "127.0.0.1", 9001);
    // Corrupt the signature
    ann.signature[0] ^= 0xFF;
    ann.signature[1] ^= 0xFF;

    auto res = reg.upsert(ann);
    EXPECT_TRUE(res.is_err()) << "Bad signature should be rejected";
    EXPECT_EQ(reg.size(), 0u);
}

TEST_F(DiscoveryTest, Registry_ExpiredAnnouncementRejected) {
    AnnouncementRegistry reg;

    auto kp      = generate_x25519_keypair();
    auto sign_kp = generate_signing_keypair();
    ASSERT_TRUE(kp.is_ok() && sign_kp.is_ok());

    NodeAnnouncement ann;
    NodeId nid = pubkey_to_node_id(kp.value().pubkey);
    ann.node_id_hex = to_hex({nid.data.data(), 32});
    ann.role        = NodeRole::Relay;
    ann.addr        = "127.0.0.1";
    ann.port        = 9001;
    ann.dh_pubkey   = kp.value().pubkey;
    ann.sign_pubkey = sign_kp.value().pubkey;
    ann.timestamp   = now_unix() - 120;  // 2 minutes ago
    ann.ttl         = 60;                // 1 minute TTL → already expired

    auto payload = make_announcement_signing_payload(
        ann.role, ann.dh_pubkey, ann.sign_pubkey,
        ann.timestamp, ann.ttl, ann.addr, ann.port);
    auto sig = sign_detached(sign_kp.value().privkey, {payload.data(), payload.size()});
    ASSERT_TRUE(sig.is_ok());
    ann.signature = sig.value();

    auto res = reg.upsert(ann);
    EXPECT_TRUE(res.is_err()) << "Expired announcement should be rejected";
}

TEST_F(DiscoveryTest, Registry_SweepExpired) {
    AnnouncementRegistry reg;

    // Add a valid announcement
    auto ann = make_announcement(NodeRole::Relay, "127.0.0.1", 9001);
    ASSERT_TRUE(reg.upsert(ann).is_ok());
    EXPECT_EQ(reg.size(), 1u);

    // Sweep (nothing expired yet)
    EXPECT_EQ(reg.sweep_expired(), 0u);
    EXPECT_EQ(reg.size(), 1u);
}

TEST_F(DiscoveryTest, Registry_Upsert_UpdatesExistingNode) {
    AnnouncementRegistry reg;

    auto kp      = generate_x25519_keypair();
    auto sign_kp = generate_signing_keypair();
    ASSERT_TRUE(kp.is_ok() && sign_kp.is_ok());

    NodeId nid = pubkey_to_node_id(kp.value().pubkey);
    std::string node_id_hex = to_hex({nid.data.data(), 32});

    auto make_ann = [&](uint16_t port) {
        NodeAnnouncement ann;
        ann.node_id_hex = node_id_hex;
        ann.role        = NodeRole::Relay;
        ann.addr        = "127.0.0.1";
        ann.port        = port;
        ann.dh_pubkey   = kp.value().pubkey;
        ann.sign_pubkey = sign_kp.value().pubkey;
        ann.timestamp   = now_unix();
        ann.ttl         = 60;

        auto payload = make_announcement_signing_payload(
            ann.role, ann.dh_pubkey, ann.sign_pubkey,
            ann.timestamp, ann.ttl, ann.addr, ann.port);
        auto sig = sign_detached(sign_kp.value().privkey, {payload.data(), payload.size()});
        ann.signature = sig.value();
        return ann;
    };

    ASSERT_TRUE(reg.upsert(make_ann(9001)).is_ok());
    EXPECT_EQ(reg.size(), 1u);

    // Upsert same node with different port — should update, not add
    ASSERT_TRUE(reg.upsert(make_ann(9002)).is_ok());
    EXPECT_EQ(reg.size(), 1u);

    auto relays = reg.query(NodeRole::Relay);
    ASSERT_EQ(relays.size(), 1u);
    EXPECT_EQ(relays[0].port, 9002);
}

TEST_F(DiscoveryTest, Announcement_JsonRoundTrip) {
    auto ann = make_announcement(NodeRole::Server, "10.0.0.1", 9100);
    auto j   = ann.to_json();

    auto decoded = NodeAnnouncement::from_json(j);
    ASSERT_TRUE(decoded.is_ok()) << decoded.error();

    EXPECT_EQ(decoded.value().node_id_hex, ann.node_id_hex);
    EXPECT_EQ(decoded.value().role,        ann.role);
    EXPECT_EQ(decoded.value().addr,        ann.addr);
    EXPECT_EQ(decoded.value().port,        ann.port);
    EXPECT_EQ(decoded.value().dh_pubkey,   ann.dh_pubkey);
    EXPECT_EQ(decoded.value().sign_pubkey, ann.sign_pubkey);
    EXPECT_EQ(decoded.value().signature,   ann.signature);
    EXPECT_EQ(decoded.value().timestamp,   ann.timestamp);
    EXPECT_EQ(decoded.value().ttl,         ann.ttl);

    // Verify signature of the round-tripped announcement
    auto verify = decoded.value().verify_signature();
    EXPECT_TRUE(verify.is_ok()) << "Round-tripped announcement signature must verify";
}
