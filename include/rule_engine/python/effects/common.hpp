#pragma once

#include "rule_engine/python/contract.hpp"

#include <cstddef>
#include <expected>
#include <initializer_list>
#include <optional>
#include <string>
#include <string_view>

namespace rule_engine::python::effects {

    enum struct ExecutionMode : std::uint8_t { live, replay };

    enum struct EffectErrorCode : std::uint8_t {
        invalid_argument,
        unknown_scope,
        scope_not_open,
        child_scope_open,
        invalid_scope_operation,
        already_finalized,
        intent_limit_exhausted,
        byte_limit_exhausted,
        label_rejected,
        duplicate_reach_mismatch,
        unknown_intent,
        replay_forbids_dispatch,
    };

    struct EffectError {
        EffectErrorCode code {};
        std::string message;
        std::optional<SourceSpan> span;
    };

    [[nodiscard]] std::string stable_domain_key(std::string_view domain,
                                                std::initializer_list<std::string_view> components);
    [[nodiscard]] std::size_t frozen_value_size(const FrozenValue &value) noexcept;
    [[nodiscard]] bool same_frozen_value(const FrozenValue &left, const FrozenValue &right) noexcept;

} // namespace rule_engine::python::effects
