#pragma once

#include "rule_engine/python/effects/journal.hpp"
#include "rule_engine/python/effects/labels.hpp"
#include "rule_engine/python/effects/recorder.hpp"
#include "rule_engine/python/effects/replay.hpp"

#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <vector>

namespace rule_engine::python::effects {

    struct ExecutionReplayExpectation {
        EvaluationResult result;
        std::vector<EffectIntent> journal;
        RecorderSnapshot recorder;
    };

    struct ExecutionJournalConfig {
        InvocationOwner root_owner;
        ExecutionMode mode {ExecutionMode::live};
        JournalLimits journal_limits;
        FlightRecorderConfig recorder;
        std::optional<ExecutionReplayExpectation> parity_expectation;
    };

    enum struct ExecutionAdapterErrorCode : std::uint8_t {
        invalid_configuration,
        invalid_step,
        adapter_failed,
        step_after_terminal,
        journal_rejected,
        recorder_rejected,
        control_scope_rejected,
        terminal_result_mismatch,
    };

    struct ExecutionAdapterError {
        ExecutionAdapterErrorCode code {};
        std::string message;
        std::optional<SourceSpan> span;
    };

    struct ExecutionObservation {
        std::vector<EffectReceipt> effects;
        bool terminal {};
    };

    struct ExecutionCompletion {
        EvaluationResult result;
        FinalizedJournal journal;
        RecorderSnapshot recorder;
        std::vector<ParityDifference> parity_differences;
    };

    // Bridges contract VmStep deltas into the transactional effects domain.
    // VM-owned IDs are preserved; this adapter owns nested reach attribution,
    // control-label joins, terminal disposition, recording, and replay parity.
    struct ExecutionJournalAdapter {
        struct Implementation;

        [[nodiscard]] static std::expected<ExecutionJournalAdapter, ExecutionAdapterError>
        create(ExecutionJournalConfig config);

        ExecutionJournalAdapter(ExecutionJournalAdapter &&other) noexcept;
        ExecutionJournalAdapter &operator=(ExecutionJournalAdapter &&other) noexcept;
        ExecutionJournalAdapter(const ExecutionJournalAdapter &) = delete;
        ExecutionJournalAdapter &operator=(const ExecutionJournalAdapter &) = delete;
        ~ExecutionJournalAdapter();

        [[nodiscard]] JournalScopeId root_scope() const noexcept;
        [[nodiscard]] std::expected<JournalScopeId, EffectError>
        open_scope(JournalScopeId parent, JournalScopeKind kind, InvocationOwner owner);
        [[nodiscard]] std::expected<void, EffectError> request_commit(JournalScopeId scope);
        [[nodiscard]] std::expected<void, EffectError> close_scope(JournalScopeId scope, JournalExit exit);
        [[nodiscard]] std::expected<void, EffectError> rollback_scope(JournalScopeId scope);

        [[nodiscard]] ControlLabelToken push_control(const DataLabel &condition_label);
        [[nodiscard]] std::expected<void, ExecutionAdapterError> pop_control(ControlLabelToken token);
        [[nodiscard]] const DataLabel &control_label() const noexcept;

        [[nodiscard]] std::expected<ExecutionObservation, ExecutionAdapterError> observe_step(const VmStep &step,
                                                                                              JournalScopeId scope);

        [[nodiscard]] const ExecutionCompletion *completion() const noexcept;
        [[nodiscard]] bool failed() const noexcept;

    private:
        explicit ExecutionJournalAdapter(std::unique_ptr<Implementation> implementation) noexcept;

        std::unique_ptr<Implementation> implementation_;
    };

} // namespace rule_engine::python::effects
