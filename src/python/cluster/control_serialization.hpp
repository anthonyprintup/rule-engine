#pragma once

#include "rule_engine/python/cluster/control_plane.hpp"

#include <cstddef>
#include <expected>
#include <span>
#include <vector>

namespace rule_engine::python::cluster::control_serialization {

    struct CodecError {
        std::string message;
    };

    [[nodiscard]] std::expected<std::vector<std::byte>, CodecError> encode(const GenerationSnapshot &value);
    [[nodiscard]] std::expected<GenerationSnapshot, CodecError> decode_generation(std::span<const std::byte> bytes);

    [[nodiscard]] std::expected<std::vector<std::byte>, CodecError> encode(const DurablePackControlSnapshot &value);
    [[nodiscard]] std::expected<DurablePackControlSnapshot, CodecError> decode_pack(std::span<const std::byte> bytes);

    [[nodiscard]] std::expected<std::vector<std::byte>, CodecError> encode(const DurableResidentNode &value);
    [[nodiscard]] std::expected<DurableResidentNode, CodecError> decode_node(std::span<const std::byte> bytes);

    [[nodiscard]] std::expected<std::vector<std::byte>, CodecError> encode(const AdminOperationRecord &value);
    [[nodiscard]] std::expected<AdminOperationRecord, CodecError> decode_operation(std::span<const std::byte> bytes);

    [[nodiscard]] std::expected<std::vector<std::byte>, CodecError>
    activation_fingerprint(const PackId &pack, std::uint64_t target_generation);
    [[nodiscard]] std::expected<std::vector<std::byte>, CodecError> stage_fingerprint(const GenerationRequest &request);
    [[nodiscard]] std::expected<std::vector<std::byte>, CodecError>
    rollback_fingerprint(const PackId &pack, std::uint64_t source_generation, std::uint64_t new_generation,
                         const StateTransitionPlan &state_transition);

} // namespace rule_engine::python::cluster::control_serialization
