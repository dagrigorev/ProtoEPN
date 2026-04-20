#include <epn/discovery/announcement.hpp>
#include <epn/observability/log.hpp>
#include <stdexcept>
#include <cstring>

namespace epn::discovery {

// ─── NodeAnnouncement::to_json ────────────────────────────────────────────────
json NodeAnnouncement::to_json() const {
    return json{
        {"node_id",       node_id_hex},
        {"role",          static_cast<int>(role)},
        {"addr",          addr},
        {"port",          port},
        {"dh_pubkey",     to_hex({dh_pubkey.data(), 32})},
        {"sign_pubkey",   to_hex({sign_pubkey.data(), 32})},
        {"timestamp",     timestamp},
        {"ttl",           ttl},
        {"signature",     to_hex({signature.data(), 64})},
        {"capabilities",  capabilities},
    };
}

// ─── NodeAnnouncement::from_json ──────────────────────────────────────────────
Result<NodeAnnouncement> NodeAnnouncement::from_json(const json& j) {
    try {
        NodeAnnouncement ann;
        ann.node_id_hex  = j.at("node_id").get<std::string>();
        ann.role         = static_cast<NodeRole>(j.at("role").get<int>());
        ann.addr         = j.at("addr").get<std::string>();
        ann.port         = j.at("port").get<uint16_t>();
        ann.timestamp    = j.at("timestamp").get<int64_t>();
        ann.ttl          = j.at("ttl").get<int32_t>();
        ann.capabilities = j.value("capabilities", 0u);

        auto dh_bytes   = from_hex(j.at("dh_pubkey").get<std::string>());
        auto sign_bytes = from_hex(j.at("sign_pubkey").get<std::string>());
        auto sig_bytes  = from_hex(j.at("signature").get<std::string>());

        if (dh_bytes.size()   != 32) return Result<NodeAnnouncement>::err("bad dh_pubkey length");
        if (sign_bytes.size() != 32) return Result<NodeAnnouncement>::err("bad sign_pubkey length");
        if (sig_bytes.size()  != 64) return Result<NodeAnnouncement>::err("bad signature length");

        std::copy(dh_bytes.begin(),   dh_bytes.end(),   ann.dh_pubkey.begin());
        std::copy(sign_bytes.begin(), sign_bytes.end(), ann.sign_pubkey.begin());
        std::copy(sig_bytes.begin(),  sig_bytes.end(),  ann.signature.begin());

        return Result<NodeAnnouncement>::ok(std::move(ann));
    } catch (const std::exception& e) {
        return Result<NodeAnnouncement>::err(std::string("JSON parse error: ") + e.what());
    }
}

// ─── Verify signature ─────────────────────────────────────────────────────────
Result<void> NodeAnnouncement::verify_signature() const {
    auto payload = crypto::make_announcement_signing_payload(
        role, dh_pubkey, sign_pubkey, timestamp, ttl, addr, port
    );
    return crypto::verify_detached(sign_pubkey, {payload.data(), payload.size()}, signature);
}

// ─── AnnouncementRegistry ─────────────────────────────────────────────────────
Result<void> AnnouncementRegistry::upsert(NodeAnnouncement ann) {
    // Reject expired announcements
    int64_t now = now_unix();
    if (ann.is_expired(now)) {
        return Result<void>::err("Announcement already expired");
    }
    // Reject future timestamps (clock skew tolerance: 30s)
    if (ann.timestamp > now + 30) {
        return Result<void>::err("Announcement timestamp too far in future");
    }
    // Verify signature
    auto vr = ann.verify_signature();
    if (vr.is_err()) {
        return Result<void>::err("Invalid signature: " + vr.error());
    }

    std::lock_guard lk(mu_);
    store_[ann.node_id_hex] = std::move(ann);
    return Result<void>::ok();
}

std::vector<NodeAnnouncement> AnnouncementRegistry::query(NodeRole role) const {
    std::lock_guard lk(mu_);
    std::vector<NodeAnnouncement> result;
    int64_t now = now_unix();
    for (auto& [id, ann] : store_) {
        if (ann.role == role && !ann.is_expired(now)) {
            result.push_back(ann);
        }
    }
    return result;
}

void AnnouncementRegistry::remove(const std::string& node_id_hex) {
    std::lock_guard lk(mu_);
    store_.erase(node_id_hex);
}

size_t AnnouncementRegistry::sweep_expired() {
    std::lock_guard lk(mu_);
    size_t removed = 0;
    int64_t now = now_unix();
    for (auto it = store_.begin(); it != store_.end(); ) {
        if (it->second.is_expired(now)) {
            it = store_.erase(it);
            ++removed;
        } else {
            ++it;
        }
    }
    return removed;
}

} // namespace epn::discovery
