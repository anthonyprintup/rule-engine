#include "rule_engine/python/effects/execution.hpp"

#include <algorithm>
#include <iterator>
#include <utility>

namespace rule_engine::python::effects {
    namespace {

        bool terminal_state(const VmStepState state) noexcept {
            return state == VmStepState::complete || state == VmStepState::faulted ||
                   state == VmStepState::quarantined || state == VmStepState::canceled;
        }

        bool state_matches_outcome(const VmStepState state, const EvaluationOutcome outcome) noexcept {
            switch (state) {
                case VmStepState::complete:
                    return outcome == EvaluationOutcome::match || outcome == EvaluationOutcome::no_match;
                case VmStepState::faulted: return outcome == EvaluationOutcome::faulted;
                case VmStepState::quarantined: return outcome == EvaluationOutcome::quarantined;
                case VmStepState::canceled: return outcome == EvaluationOutcome::canceled;
                case VmStepState::yielded:
                case VmStepState::waiting_for_facts:
                case VmStepState::waiting_for_capabilities: return false;
                default: return false;
            }
        }

        bool same_recorder_event(const RecorderEvent &left, const RecorderEvent &right) noexcept {
            return left.sequence == right.sequence && left.kind == right.kind && left.span == right.span &&
                   left.label == right.label && left.summary == right.summary;
        }

        bool same_vm_result_identity(const EffectIntent &left, const EffectIntent &right) noexcept {
            return left.id == right.id && left.invocation == right.invocation && left.owner == right.owner &&
                   left.binding == right.binding && left.sequence == right.sequence && left.kind == right.kind &&
                   left.payload.canonical_digest == right.payload.canonical_digest && left.span == right.span &&
                   left.idempotency_key == right.idempotency_key;
        }

        ExecutionAdapterError adapter_error(const ExecutionAdapterErrorCode code, std::string message,
                                            std::optional<SourceSpan> span = std::nullopt) {
            return ExecutionAdapterError {.code = code, .message = std::move(message), .span = std::move(span)};
        }

        std::vector<EffectIntent> semantic_committed_intents(const FinalizedJournal &journal) {
            std::vector<EffectIntent> result;
            if (!journal.clean) {
                return result;
            }
            std::ranges::copy_if(journal.intents, std::back_inserter(result), [](const EffectIntent &intent) {
                return intent.disposition != EffectDisposition::rolled_back;
            });
            return result;
        }

    } // namespace

    struct ExecutionJournalAdapter::Implementation {
        EffectJournal journal;
        FlightRecorder recorder;
        ControlLabelStack control;
        std::optional<ExecutionReplayExpectation> parity_expectation;
        std::vector<RecorderEvent> observed_recorder_events;
        std::optional<ExecutionCompletion> completed;
        bool poisoned {};

        Implementation(EffectJournal selected_journal, FlightRecorder selected_recorder):
            journal {std::move(selected_journal)}, recorder {std::move(selected_recorder)} {}
    };

    std::expected<ExecutionJournalAdapter, ExecutionAdapterError>
    ExecutionJournalAdapter::create(ExecutionJournalConfig config) {
        auto journal = EffectJournal::create(config.root_owner, config.mode, config.journal_limits);
        if (!journal.has_value()) {
            return std::unexpected(adapter_error(ExecutionAdapterErrorCode::invalid_configuration,
                                                 journal.error().message, journal.error().span));
        }
        auto recorder = FlightRecorder::create(config.recorder);
        if (!recorder.has_value()) {
            return std::unexpected(
                adapter_error(ExecutionAdapterErrorCode::invalid_configuration, recorder.error().message));
        }
        auto implementation = std::make_unique<Implementation>(std::move(*journal), std::move(*recorder));
        implementation->parity_expectation = std::move(config.parity_expectation);
        return ExecutionJournalAdapter {std::move(implementation)};
    }

    ExecutionJournalAdapter::ExecutionJournalAdapter(std::unique_ptr<Implementation> implementation) noexcept:
        implementation_ {std::move(implementation)} {}

    ExecutionJournalAdapter::ExecutionJournalAdapter(ExecutionJournalAdapter &&other) noexcept = default;
    ExecutionJournalAdapter &ExecutionJournalAdapter::operator=(ExecutionJournalAdapter &&other) noexcept = default;
    ExecutionJournalAdapter::~ExecutionJournalAdapter() = default;

    JournalScopeId ExecutionJournalAdapter::root_scope() const noexcept {
        return implementation_->journal.root_scope();
    }

    std::expected<JournalScopeId, EffectError> ExecutionJournalAdapter::open_scope(const JournalScopeId parent,
                                                                                   const JournalScopeKind kind,
                                                                                   InvocationOwner owner) {
        return implementation_->journal.open_scope(parent, kind, std::move(owner));
    }

    std::expected<void, EffectError> ExecutionJournalAdapter::request_commit(const JournalScopeId scope) {
        return implementation_->journal.request_commit(scope);
    }

    std::expected<void, EffectError> ExecutionJournalAdapter::close_scope(const JournalScopeId scope,
                                                                          const JournalExit exit) {
        return implementation_->journal.close_scope(scope, exit);
    }

    std::expected<void, EffectError> ExecutionJournalAdapter::rollback_scope(const JournalScopeId scope) {
        return implementation_->journal.rollback_scope(scope);
    }

    ControlLabelToken ExecutionJournalAdapter::push_control(const DataLabel &condition_label) {
        return implementation_->control.push(condition_label);
    }

    std::expected<void, ExecutionAdapterError> ExecutionJournalAdapter::pop_control(const ControlLabelToken token) {
        const auto popped = implementation_->control.pop(token);
        if (!popped.has_value()) {
            return std::unexpected(
                adapter_error(ExecutionAdapterErrorCode::control_scope_rejected, popped.error().message));
        }
        return {};
    }

    const DataLabel &ExecutionJournalAdapter::control_label() const noexcept {
        return implementation_->control.current();
    }

    std::expected<ExecutionObservation, ExecutionAdapterError>
    ExecutionJournalAdapter::observe_step(const VmStep &step, const JournalScopeId scope) {
        if (implementation_->poisoned) {
            return std::unexpected(adapter_error(ExecutionAdapterErrorCode::adapter_failed,
                                                 "the execution adapter is poisoned by an earlier rejected step"));
        }
        if (implementation_->completed.has_value()) {
            return std::unexpected(adapter_error(ExecutionAdapterErrorCode::step_after_terminal,
                                                 "a VM step cannot be observed after terminal finalization"));
        }

        const auto is_terminal = terminal_state(step.state);
        if (is_terminal != step.result.has_value()) {
            implementation_->poisoned = true;
            return std::unexpected(adapter_error(ExecutionAdapterErrorCode::invalid_step,
                                                 "only a terminal VM step may carry an evaluation result"));
        }
        if (is_terminal && !state_matches_outcome(step.state, step.result->outcome)) {
            implementation_->poisoned = true;
            return std::unexpected(adapter_error(ExecutionAdapterErrorCode::terminal_result_mismatch,
                                                 "the VM terminal state and evaluation outcome disagree"));
        }

        ExecutionObservation observation {.effects = {}, .terminal = is_terminal};
        observation.effects.reserve(step.journal_delta.size());
        for (const auto &intent : step.journal_delta) {
            const auto appended = implementation_->journal.append_vm_intent(scope, intent, control_label());
            if (!appended.has_value()) {
                implementation_->poisoned = true;
                return std::unexpected(adapter_error(ExecutionAdapterErrorCode::journal_rejected,
                                                     appended.error().message, appended.error().span));
            }
            observation.effects.push_back(*appended);
        }

        for (const auto &event : step.recorder_delta) {
            const auto prior =
                std::ranges::find(implementation_->observed_recorder_events, event.sequence, &RecorderEvent::sequence);
            if (prior != implementation_->observed_recorder_events.end()) {
                if (same_recorder_event(*prior, event)) {
                    continue;
                }
                implementation_->poisoned = true;
                return std::unexpected(
                    adapter_error(ExecutionAdapterErrorCode::recorder_rejected,
                                  "a resumed recorder sequence was reused with different event semantics", event.span));
            }
            const auto recorded = implementation_->recorder.record(event);
            if (!recorded.has_value()) {
                implementation_->poisoned = true;
                return std::unexpected(
                    adapter_error(ExecutionAdapterErrorCode::recorder_rejected, recorded.error().message, event.span));
            }
            implementation_->observed_recorder_events.push_back(event);
        }

        if (!is_terminal) {
            return observation;
        }

        if (step.result->outcome == EvaluationOutcome::match || step.result->outcome == EvaluationOutcome::no_match) {
            const auto &observed = implementation_->journal.intents();
            if (step.result->committed_effects.size() != observed.size() ||
                !std::ranges::equal(step.result->committed_effects, observed, same_vm_result_identity)) {
                implementation_->poisoned = true;
                return std::unexpected(
                    adapter_error(ExecutionAdapterErrorCode::terminal_result_mismatch,
                                  "the VM terminal result does not describe the complete ordered journal"));
            }
        } else if (!step.result->committed_effects.empty()) {
            implementation_->poisoned = true;
            return std::unexpected(
                adapter_error(ExecutionAdapterErrorCode::terminal_result_mismatch,
                              "a faulted, quarantined, or canceled VM result cannot claim committed effects"));
        }

        auto finalized = implementation_->journal.finish_root(step.result->outcome);
        if (!finalized.has_value()) {
            implementation_->poisoned = true;
            return std::unexpected(adapter_error(ExecutionAdapterErrorCode::journal_rejected, finalized.error().message,
                                                 finalized.error().span));
        }
        auto normalized_result = *step.result;
        normalized_result.committed_effects = semantic_committed_intents(*finalized);
        if (!finalized->clean) {
            normalized_result.state_mutations.clear();
        }
        auto recorder_snapshot = implementation_->recorder.snapshot();
        std::vector<ParityDifference> parity_differences;
        if (implementation_->parity_expectation.has_value()) {
            auto result_differences =
                compare_evaluation_results(implementation_->parity_expectation->result, normalized_result);
            auto journal_differences =
                compare_effect_journals(implementation_->parity_expectation->journal, finalized->intents);
            for (auto &difference : journal_differences) { difference.field = "journal." + difference.field; }
            auto recorder_differences =
                compare_recorder_snapshots(implementation_->parity_expectation->recorder, recorder_snapshot);
            parity_differences.insert(parity_differences.end(), std::make_move_iterator(result_differences.begin()),
                                      std::make_move_iterator(result_differences.end()));
            parity_differences.insert(parity_differences.end(), std::make_move_iterator(journal_differences.begin()),
                                      std::make_move_iterator(journal_differences.end()));
            parity_differences.insert(parity_differences.end(), std::make_move_iterator(recorder_differences.begin()),
                                      std::make_move_iterator(recorder_differences.end()));
        }
        implementation_->completed = ExecutionCompletion {
            .result = std::move(normalized_result),
            .journal = std::move(*finalized),
            .recorder = std::move(recorder_snapshot),
            .parity_differences = std::move(parity_differences),
        };
        return observation;
    }

    const ExecutionCompletion *ExecutionJournalAdapter::completion() const noexcept {
        return implementation_->completed.has_value() ? &*implementation_->completed : nullptr;
    }

    bool ExecutionJournalAdapter::failed() const noexcept { return implementation_->poisoned; }

} // namespace rule_engine::python::effects
