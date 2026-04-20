#include <epn/protocol/framing.hpp>
#include <cstring>

namespace epn::protocol {

Bytes encode_frame(const Frame& f) {
    // [4-byte payload_len BE][1-byte type][payload]
    const size_t payload_len = f.payload.size();
    Bytes wire(5 + payload_len);

    core::write_be32(wire.data(), static_cast<uint32_t>(payload_len));
    wire[4] = static_cast<uint8_t>(f.type);

    if (payload_len > 0) {
        std::memcpy(wire.data() + 5, f.payload.data(), payload_len);
    }

    return wire;
}

Result<Frame> decode_frame(ByteSpan wire) {
    if (wire.size() < 5) {
        return Result<Frame>::err("Frame too short: need at least 5 bytes header");
    }

    uint32_t payload_len = core::read_be32(wire.data());

    if (payload_len > MAX_FRAME_SIZE) {
        return Result<Frame>::err("Frame payload_len exceeds MAX_FRAME_SIZE");
    }

    if (wire.size() < 5 + payload_len) {
        return Result<Frame>::err("Frame buffer truncated");
    }

    Frame f;
    f.type    = static_cast<MsgType>(wire[4]);
    f.payload = Bytes(wire.data() + 5, wire.data() + 5 + payload_len);

    return Result<Frame>::ok(std::move(f));
}

uint32_t peek_frame_total_len(ByteSpan buf) {
    if (buf.size() < 4) return 0;
    uint32_t payload_len = core::read_be32(buf.data());
    return 5 + payload_len; // header(5) + payload
}

} // namespace epn::protocol
