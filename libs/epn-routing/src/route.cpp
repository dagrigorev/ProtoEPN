#include <epn/routing/route.hpp>
#include <epn/observability/log.hpp>

namespace epn::routing {

using namespace epn::core;

Result<std::vector<discovery::NodeAnnouncement>>
RoutePlanner::select_relays(size_t n) {
    auto res = disc_.query_nodes(NodeRole::Relay);
    if (res.is_err()) return Result<std::vector<discovery::NodeAnnouncement>>::err(res.error());
    auto& pool = res.value();
    if (pool.size() < n)
        return Result<std::vector<discovery::NodeAnnouncement>>::err(
            "Need " + std::to_string(n) + " relays, only " +
            std::to_string(pool.size()) + " available");

    std::shuffle(pool.begin(), pool.end(), rng_);
    pool.resize(n);

    LOG_DEBUG("RoutePlanner: selected {} relays", n);
    for (auto& r : pool)
        LOG_DEBUG("  relay: {}:{} id={}", r.addr, r.port, r.node_id_hex.substr(0, 8));
    return Result<std::vector<discovery::NodeAnnouncement>>::ok(std::move(pool));
}

Result<BuiltRoute> RoutePlanner::build_route(ByteSpan payload, size_t num_relays) {
    auto servers = disc_.query_nodes(NodeRole::Server);
    if (servers.is_err()) servers = decltype(servers)::ok({});
    auto tunnel_srv = disc_.query_nodes(NodeRole::TunnelServer);
    if (tunnel_srv.is_ok())
        for (auto& ts : tunnel_srv.value())
            servers.value().push_back(ts);
    if (servers.value().empty()) return Result<BuiltRoute>::err("No servers in discovery");

    std::uniform_int_distribution<size_t> pick(0, servers.value().size() - 1);
    const auto& srv = servers.value()[pick(rng_)];
    LOG_DEBUG("RoutePlanner: selected server {}:{}", srv.addr, srv.port);
    return build_route_to(srv.node_id_hex, payload, num_relays);
}

Result<BuiltRoute> RoutePlanner::build_route_to(
    const std::string& server_node_id_hex,
    ByteSpan           payload,
    size_t             num_relays)
{
    // Query both Server and TunnelServer roles (any server endpoint is valid)
    auto servers = disc_.query_nodes(NodeRole::Server);
    if (servers.is_err()) servers = decltype(servers)::ok({});
    auto tunnel_servers = disc_.query_nodes(NodeRole::TunnelServer);
    if (tunnel_servers.is_ok())
        for (auto& ts : tunnel_servers.value())
            servers.value().push_back(ts);

    const discovery::NodeAnnouncement* srv = nullptr;
    for (auto& s : servers.value())
        if (s.node_id_hex == server_node_id_hex) { srv = &s; break; }
    if (!srv) return Result<BuiltRoute>::err("Server not found: " + server_node_id_hex);

    auto relays = select_relays(num_relays);
    if (relays.is_err()) return Result<BuiltRoute>::err(relays.error());

    // Build hop list: [relay1 … relayN, server]
    std::vector<protocol::HopDescriptor> hops;
    hops.reserve(num_relays + 1);
    for (auto& r : relays.value()) {
        protocol::HopDescriptor h;
        h.addr = r.addr; h.port = r.port; h.node_pubkey = r.dh_pubkey;
        hops.push_back(std::move(h));
    }
    protocol::HopDescriptor server_hop;
    server_hop.addr       = srv->addr;
    server_hop.port       = srv->port;
    server_hop.node_pubkey = srv->dh_pubkey;
    hops.push_back(std::move(server_hop));

    SessionId sid = crypto::generate_session_id();

    auto onion_res = protocol::build_onion(hops, sid, payload);
    if (onion_res.is_err()) return Result<BuiltRoute>::err("Onion: " + onion_res.error());

    BuiltRoute route;
    route.entry_point         = hops[0];
    route.hops                = std::move(hops);
    route.session_id          = sid;
    route.onion_packet        = std::move(onion_res.value().wire);
    route.server_session_key  = std::move(onion_res.value().server_session_key);

    LOG_INFO("RoutePlanner: built {}-hop route, sid={}",
             route.hops.size(), to_hex({sid.data.data(), 8}));
    return Result<BuiltRoute>::ok(std::move(route));
}

} // namespace epn::routing
