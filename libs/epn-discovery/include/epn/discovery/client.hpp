#pragma once

#include <epn/discovery/announcement.hpp>
#include <epn/transport/connection.hpp>
#include <asio.hpp>
#include <functional>
#include <vector>
#include <string>

namespace epn::discovery {

using namespace epn::core;

// ─── Synchronous discovery client ─────────────────────────────────────────────
// Used by relay, server, and client nodes to talk to the discovery server.
// Uses a fresh TCP connection per request (stateless, ephemeral).
class DiscoveryClient {
public:
    DiscoveryClient(const std::string& disc_host, uint16_t disc_port)
        : disc_host_(disc_host), disc_port_(disc_port) {}

    // Register this node with the discovery server
    // Signs the announcement before sending
    Result<void> register_node(
        const NodeAnnouncement&       ann,
        const crypto::SigningKeyPair& signing_kp
    );

    // Query nodes by role; returns list of active announcements
    Result<std::vector<NodeAnnouncement>> query_nodes(NodeRole role);

    // Register and schedule periodic re-registration (every ttl/2 seconds)
    // Runs on the provided io_context in background
    void start_periodic_registration(
        asio::io_context&             ioc,
        NodeAnnouncement              ann,
        const crypto::SigningKeyPair& signing_kp,
        int                           interval_secs = DISCOVERY_TTL_SECS / 2
    );

private:
    Result<json> send_request(const json& req);

    std::string disc_host_;
    uint16_t    disc_port_;
};

} // namespace epn::discovery
