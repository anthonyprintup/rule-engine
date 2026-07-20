#pragma once

#include "rule_engine/python/contract/distributed.hpp"

#include <cstddef>
#include <expected>
#include <span>
#include <vector>

namespace rule_engine::python::cluster::serialization {

    struct CodecError {
        std::string message;
    };

    [[nodiscard]] std::expected<std::vector<std::byte>, CodecError> encode(const FrozenValue &value);
    [[nodiscard]] std::expected<FrozenValue, CodecError> decode_frozen(std::span<const std::byte> bytes);

    [[nodiscard]] std::expected<std::vector<std::byte>, CodecError> encode(const EventEnvelope &value);
    [[nodiscard]] std::expected<EventEnvelope, CodecError> decode_event(std::span<const std::byte> bytes);

    [[nodiscard]] std::expected<std::vector<std::byte>, CodecError> encode(const EvaluationResult &value);
    [[nodiscard]] std::expected<EvaluationResult, CodecError> decode_evaluation(std::span<const std::byte> bytes);

    [[nodiscard]] std::expected<std::vector<std::byte>, CodecError> encode(const EffectIntent &value);
    [[nodiscard]] std::expected<EffectIntent, CodecError> decode_effect(std::span<const std::byte> bytes);

    [[nodiscard]] std::expected<std::vector<std::byte>, CodecError> encode(const OutboxRecord &value);
    [[nodiscard]] std::expected<OutboxRecord, CodecError> decode_outbox(std::span<const std::byte> bytes);

    [[nodiscard]] std::expected<std::vector<std::byte>, CodecError> encode(const TransactionReceipt &value);
    [[nodiscard]] std::expected<TransactionReceipt, CodecError> decode_receipt(std::span<const std::byte> bytes);

    [[nodiscard]] std::expected<std::vector<std::byte>, CodecError> encode(const RuntimeTransaction &value);
    [[nodiscard]] std::expected<void, CodecError> validate(const RuntimeTransaction &value);

} // namespace rule_engine::python::cluster::serialization
