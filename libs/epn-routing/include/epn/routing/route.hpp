#pragma once

#include <epn/core/types.hpp>
#include <epn/core/result.hpp>
#include <epn/crypto/keys.hpp>
#include <epn/protocol/onion.hpp>
#include <epn/discovery/announcement.hpp>
#include <epn/discovery/client.hpp>
#include <vector>
#include <string>
#include <random>
#include <algorithm>

namespace epn::routing {

using namespace epn::core;

// ─── BuiltRoute ───────────────────────────────────────────────────────────────
struct BuiltRoute {
    protocol::HopDescriptor              entry_point;
    std::vector<protocol::HopDescriptor> hops;
    SessionId                            session_id;
    Bytes                                onion_packet;

    // E2E session key shared exclusively between client and server.
    // Derived from ephemeral X25519 DH during build_onion().
    // Relay nodes never see this key.
    crypto::SessionKey server_session_key;
};

// ─── RoutePlanner ─────────────────────────────────────────────────────────────
class RoutePlanner {
public:
    explicit RoutePlanner(discovery::DiscoveryClient& disc)
        : disc_(disc), rng_(std::random_device{}()) {}

    Result<BuiltRoute> build_route(ByteSpan payload, size_t num_relays = MIN_HOPS);

    Result<BuiltRoute> build_route_to(
        const std::string& server_node_id_hex,
        ByteSpan           payload,
        size_t             num_relays = MIN_HOPS);

private:
    Result<std::vector<discovery::NodeAnnouncement>> select_relays(size_t n);

    discovery::DiscoveryClient& disc_;
    std::mt19937_64             rng_;
};

} // namespace epn::routing
