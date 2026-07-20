#pragma once

#include "rule_engine/python/protocol/types.hpp"

#include <expected>
#include <span>
#include <vector>

namespace rule_engine::python::protocol_v2 {

    struct DecodedFrame {
        PeerEnvelope envelope;
        std::size_t bytes_consumed {};
    };

    [[nodiscard]] std::expected<std::vector<std::byte>, ProtocolError>
    encode_payload(const PeerEnvelope &envelope, const ProtocolLimits &limits = {});

    [[nodiscard]] std::expected<PeerEnvelope, ProtocolError> decode_payload(std::span<const std::byte> payload,
                                                                            const ProtocolLimits &limits = {});

    [[nodiscard]] std::expected<std::vector<std::byte>, ProtocolError> encode_frame(const PeerEnvelope &envelope,
                                                                                    const ProtocolLimits &limits = {});

    [[nodiscard]] std::expected<DecodedFrame, ProtocolError> decode_frame(std::span<const std::byte> bytes,
                                                                          const ProtocolLimits &limits = {});

} // namespace rule_engine::python::protocol_v2
