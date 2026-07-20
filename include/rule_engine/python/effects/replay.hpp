#pragma once

#include "rule_engine/python/effects/journal.hpp"

#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace rule_engine::python::effects {

    enum struct CapturedInputKind : std::uint8_t { fact, service, history, deterministic_time, cache };

    struct CapturedInput {
        std::string key;
        CapturedInputKind kind {CapturedInputKind::fact};
        std::optional<FrozenValue> value;
        std::string terminal_code;
    };

    enum struct ReplayErrorCode : std::uint8_t {
        duplicate_capture,
        input_missing,
        dispatch_forbidden,
        durable_commit_forbidden,
    };

    struct ReplayError {
        ReplayErrorCode code {};
        std::string message;
    };

    struct CapturedInputReplayHost {
        [[nodiscard]] static std::expected<CapturedInputReplayHost, ReplayError>
        create(std::vector<CapturedInput> captures);

        [[nodiscard]] std::expected<CapturedInput, ReplayError> resolve(std::string_view key) const;
        [[nodiscard]] std::expected<void, ReplayError> dispatch(const EffectIntent &intent);
        [[nodiscard]] std::expected<void, ReplayError> commit(const FinalizedJournal &journal);

        [[nodiscard]] std::uint64_t blocked_dispatches() const noexcept;
        [[nodiscard]] std::uint64_t blocked_commits() const noexcept;
        [[nodiscard]] std::uint64_t live_dispatches() const noexcept;

    private:
        explicit CapturedInputReplayHost(std::vector<CapturedInput> captures) noexcept;

        std::vector<CapturedInput> captures_;
        std::uint64_t blocked_dispatches_ {};
        std::uint64_t blocked_commits_ {};
    };

    struct ParityDifference {
        std::size_t index {};
        std::string field;
        std::string expected;
        std::string actual;
    };

    [[nodiscard]] std::vector<ParityDifference> compare_effect_journals(std::span<const EffectIntent> expected,
                                                                        std::span<const EffectIntent> actual);

} // namespace rule_engine::python::effects
