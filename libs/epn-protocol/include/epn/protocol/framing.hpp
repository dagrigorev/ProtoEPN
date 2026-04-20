#pragma once

#include <epn/core/types.hpp>
#include <epn/core/result.hpp>
#include <epn/protocol/messages.hpp>

namespace epn::protocol {

using namespace epn::core;

// ─── Frame serialization ──────────────────────────────────────────────────────

// Encode frame to wire bytes: [4-byte len BE][1-byte type][payload]
Bytes encode_frame(const Frame& f);

// Decode frame from a complete wire buffer (must contain exactly one frame)
Result<Frame> decode_frame(ByteSpan wire);

// Peek at the total frame length from the first 4 header bytes
// Returns the total wire length (header + payload), or 0 if buf too short
uint32_t peek_frame_total_len(ByteSpan buf);

// ─── Helper builders ──────────────────────────────────────────────────────────
inline Frame make_keepalive() {
    return Frame{MsgType::KEEPALIVE, {}};
}

inline Frame make_teardown(const SessionId& sid) {
    return Frame{MsgType::TEARDOWN, {sid.data.begin(), sid.data.end()}};
}

inline Frame make_error(EpnError code, const std::string& msg = {}) {
    Bytes p(2 + msg.size());
    p[0] = static_cast<uint8_t>(static_cast<uint16_t>(code) >> 8);
    p[1] = static_cast<uint8_t>(static_cast<uint16_t>(code) & 0xFF);
    if (!msg.empty()) std::copy(msg.begin(), msg.end(), p.begin() + 2);
    return Frame{MsgType::ERROR_MSG, std::move(p)};
}

inline Frame make_route_ready(const SessionId& sid) {
    return Frame{MsgType::ROUTE_READY, {sid.data.begin(), sid.data.end()}};
}

} // namespace epn::protocol
