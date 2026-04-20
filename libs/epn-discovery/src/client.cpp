#include <epn/discovery/client.hpp>
#include <epn/observability/log.hpp>
#include <asio.hpp>
#include <nlohmann/json.hpp>
#include <cstring>

namespace epn::discovery {

using asio::ip::tcp;
using json = nlohmann::json;

// ─── Framed JSON transport (sync, one-shot per request) ───────────────────────
static bool send_framed_json(tcp::socket& sock, uint8_t msg_type, const json& payload) {
    try {
        std::string body  = payload.dump();
        uint32_t    len   = static_cast<uint32_t>(body.size());
        std::vector<uint8_t> wire(5 + len);
        core::write_be32(wire.data(), len);
        wire[4] = msg_type;
        std::memcpy(wire.data() + 5, body.data(), len);
        asio::write(sock, asio::buffer(wire));
        return true;
    } catch (...) { return false; }
}

static Result<json> recv_framed_json(tcp::socket& sock) {
    try {
        std::array<uint8_t, 5> hdr{};
        asio::read(sock, asio::buffer(hdr));
        uint32_t len = core::read_be32(hdr.data());
        if (len > 1024 * 1024) return Result<json>::err("Response too large");
        std::vector<uint8_t> body(len);
        if (len > 0) asio::read(sock, asio::buffer(body));
        return Result<json>::ok(json::parse(body.begin(), body.end()));
    } catch (const std::exception& e) {
        return Result<json>::err(std::string("recv: ") + e.what());
    }
}

// ─── send_request ─────────────────────────────────────────────────────────────
Result<json> DiscoveryClient::send_request(const json& req) {
    try {
        asio::io_context ioc;
        tcp::resolver    resolver(ioc);
        auto endpoints = resolver.resolve(disc_host_, std::to_string(disc_port_));
        tcp::socket sock(ioc);
        asio::connect(sock, endpoints);
        sock.set_option(tcp::no_delay(true));

        uint8_t msg_type = 0x11; // default: DISC_QUERY
        std::string t = req.value("type", "");
        if (t == "register") msg_type = 0x10;

        if (!send_framed_json(sock, msg_type, req))
            return Result<json>::err("Failed to send discovery request");

        return recv_framed_json(sock);
    } catch (const std::exception& e) {
        return Result<json>::err(std::string("Discovery connect error: ") + e.what());
    }
}

// ─── register_node ────────────────────────────────────────────────────────────
Result<void> DiscoveryClient::register_node(
    const NodeAnnouncement&       ann,
    const crypto::SigningKeyPair& signing_kp)
{
    auto payload = crypto::make_announcement_signing_payload(
        ann.role, ann.dh_pubkey, ann.sign_pubkey,
        ann.timestamp, ann.ttl, ann.addr, ann.port);

    auto sig_res = crypto::sign_detached(
        signing_kp.privkey, {payload.data(), payload.size()});
    if (sig_res.is_err()) return Result<void>::err(sig_res.error());

    NodeAnnouncement signed_ann = ann;
    signed_ann.signature = sig_res.value();

    json req        = signed_ann.to_json();
    req["type"]     = "register";

    auto resp = send_request(req);
    if (resp.is_err()) return Result<void>::err(resp.error());

    if (resp.value().value("status", "") != "ok")
        return Result<void>::err("Rejected: " + resp.value().dump());

    return Result<void>::ok();
}

// ─── query_nodes ─────────────────────────────────────────────────────────────
Result<std::vector<NodeAnnouncement>> DiscoveryClient::query_nodes(NodeRole role) {
    json req{{"type", "query"}, {"role", static_cast<int>(role)}};
    auto resp = send_request(req);
    if (resp.is_err())
        return Result<std::vector<NodeAnnouncement>>::err(resp.error());

    std::vector<NodeAnnouncement> nodes;
    if (!resp.value().contains("nodes"))
        return Result<std::vector<NodeAnnouncement>>::ok({});

    for (auto& entry : resp.value()["nodes"]) {
        auto ann_res = NodeAnnouncement::from_json(entry);
        if (ann_res.is_ok() && ann_res.value().verify_signature().is_ok())
            nodes.push_back(std::move(ann_res.value()));
        else
            LOG_WARN("DiscoveryClient: skipping node with bad sig or parse error");
    }
    return Result<std::vector<NodeAnnouncement>>::ok(std::move(nodes));
}

// ─── start_periodic_registration ─────────────────────────────────────────────
void DiscoveryClient::start_periodic_registration(
    asio::io_context&             ioc,
    NodeAnnouncement              ann,
    const crypto::SigningKeyPair& signing_kp,
    int                           interval_secs)
{
    auto timer = std::make_shared<asio::steady_timer>(ioc);

    // Capture signing_kp by reference — caller must keep it alive
    std::function<void()> tick = [this, timer, ann, &signing_kp,
                                   interval_secs, &tick]() mutable {
        ann.timestamp = now_unix();
        auto res = register_node(ann, signing_kp);
        if (res.is_err()) LOG_WARN("Periodic re-reg failed: {}", res.error());
        else              LOG_DEBUG("Re-registered with discovery");

        timer->expires_after(std::chrono::seconds(interval_secs));
        timer->async_wait([&tick](std::error_code ec) {
            if (!ec) tick();
        });
    };

    timer->expires_after(std::chrono::seconds(interval_secs));
    timer->async_wait([tick](std::error_code ec) mutable {
        if (!ec) tick();
    });
}

} // namespace epn::discovery
