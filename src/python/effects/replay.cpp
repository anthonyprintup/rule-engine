#include "rule_engine/python/effects/replay.hpp"

#include <algorithm>
#include <utility>

namespace rule_engine::python::effects {
    namespace {

        std::string disposition_text(const EffectDisposition disposition) {
            return std::to_string(static_cast<std::uint32_t>(disposition));
        }

        std::string label_text(const DataLabel &label) {
            std::string result = std::to_string(static_cast<std::uint32_t>(label.classification));
            for (const auto &category : label.categories) { result += ":" + category; }
            return result;
        }

        std::string span_text(const SourceSpan &span) {
            return stable_domain_key(
                "source-span-v1", {span.source.value, std::to_string(span.begin_byte), std::to_string(span.end_byte)});
        }

        void compare_string(std::vector<ParityDifference> &differences, const std::size_t index, std::string field,
                            const std::string &expected, const std::string &actual) {
            if (expected == actual) {
                return;
            }
            differences.push_back(ParityDifference {
                .index = index,
                .field = std::move(field),
                .expected = expected,
                .actual = actual,
            });
        }

        std::string optional_bool_text(const std::optional<bool> value) {
            return value.has_value() ? (*value ? "true" : "false") : "none";
        }

        std::string fault_text(const std::optional<FaultChain> &fault) {
            if (!fault.has_value()) {
                return "none";
            }
            std::string result = stable_domain_key("fault-flags-v1", {fault->double_fault ? "double" : "single",
                                                                      fault->triple_fault ? "triple" : "not-triple"});
            for (const auto &frame : fault->frames) {
                result += stable_domain_key("fault-frame-v1",
                                            {frame.code, frame.message, frame.executable.value, span_text(frame.span)});
            }
            return result;
        }

        std::string mutation_text(const StateMutation &mutation) {
            const auto value_digest =
                mutation.value.has_value() ? mutation.value->canonical_digest : std::string {"none"};
            const auto value_label =
                mutation.value.has_value() ? label_text(mutation.value->label) : std::string {"none"};
            return stable_domain_key("state-mutation-v1",
                                     {mutation.owner.value, mutation.namespace_name, mutation.key,
                                      std::to_string(mutation.expected_version), value_digest, value_label});
        }

        std::string recorder_entry_text(const RecorderEntry &entry) {
            if (const auto *event = std::get_if<RecorderEvent>(&entry); event != nullptr) {
                return stable_domain_key("recorder-event-v1",
                                         {std::to_string(event->sequence), event->kind, span_text(event->span),
                                          label_text(event->label), event->summary});
            }
            const auto &dropped = std::get<DroppedRecorderEvents>(entry);
            return stable_domain_key("recorder-dropped-v1",
                                     {std::to_string(dropped.first_sequence), std::to_string(dropped.last_sequence),
                                      std::to_string(dropped.event_count), std::to_string(dropped.estimated_bytes)});
        }

    } // namespace

    std::expected<CapturedInputReplayHost, ReplayError>
    CapturedInputReplayHost::create(std::vector<CapturedInput> captures) {
        std::ranges::sort(captures, {}, &CapturedInput::key);
        for (std::size_t index = 0; index < captures.size(); ++index) {
            if (captures[index].key.empty() ||
                (!captures[index].value.has_value() && captures[index].terminal_code.empty())) {
                return std::unexpected(ReplayError {
                    .code = ReplayErrorCode::input_missing,
                    .message = "every replay capture requires a key and a value or terminal code",
                });
            }
            if (index != 0 && captures[index - 1U].key == captures[index].key) {
                return std::unexpected(ReplayError {
                    .code = ReplayErrorCode::duplicate_capture,
                    .message = "replay captures must contain one result for each canonical request key",
                });
            }
        }
        return CapturedInputReplayHost {std::move(captures)};
    }

    CapturedInputReplayHost::CapturedInputReplayHost(std::vector<CapturedInput> captures) noexcept:
        captures_ {std::move(captures)} {}

    std::expected<CapturedInput, ReplayError> CapturedInputReplayHost::resolve(const std::string_view key) const {
        const auto found = std::ranges::lower_bound(captures_, key, {}, &CapturedInput::key);
        if (found == captures_.end() || found->key != key) {
            return std::unexpected(ReplayError {
                .code = ReplayErrorCode::input_missing,
                .message = "diagnostic replay has no captured result for the requested input",
            });
        }
        return *found;
    }

    std::expected<void, ReplayError> CapturedInputReplayHost::dispatch(const EffectIntent &intent) {
        (void) intent;
        ++blocked_dispatches_;
        return std::unexpected(ReplayError {
            .code = ReplayErrorCode::dispatch_forbidden,
            .message = "replay cannot dispatch an external action",
        });
    }

    std::expected<void, ReplayError> CapturedInputReplayHost::commit(const FinalizedJournal &journal) {
        (void) journal;
        ++blocked_commits_;
        return std::unexpected(ReplayError {
            .code = ReplayErrorCode::durable_commit_forbidden,
            .message = "replay cannot commit state, effects, retention, or outbox rows",
        });
    }

    std::uint64_t CapturedInputReplayHost::blocked_dispatches() const noexcept { return blocked_dispatches_; }

    std::uint64_t CapturedInputReplayHost::blocked_commits() const noexcept { return blocked_commits_; }

    std::uint64_t CapturedInputReplayHost::live_dispatches() const noexcept { return 0; }

    std::vector<ParityDifference> compare_effect_journals(const std::span<const EffectIntent> expected,
                                                          const std::span<const EffectIntent> actual) {
        std::vector<ParityDifference> differences;
        if (expected.size() != actual.size()) {
            differences.push_back(ParityDifference {
                .index = std::min(expected.size(), actual.size()),
                .field = "size",
                .expected = std::to_string(expected.size()),
                .actual = std::to_string(actual.size()),
            });
        }

        const auto count = std::min(expected.size(), actual.size());
        for (std::size_t index = 0; index < count; ++index) {
            const auto &left = expected[index];
            const auto &right = actual[index];
            compare_string(differences, index, "intent", left.id.value, right.id.value);
            compare_string(differences, index, "invocation", left.invocation.value, right.invocation.value);
            compare_string(differences, index, "owner", left.owner.value, right.owner.value);
            compare_string(differences, index, "binding", left.binding.value, right.binding.value);
            compare_string(differences, index, "sequence", std::to_string(left.sequence),
                           std::to_string(right.sequence));
            compare_string(differences, index, "kind", left.kind, right.kind);
            compare_string(differences, index, "payload_digest", left.payload.canonical_digest,
                           right.payload.canonical_digest);
            compare_string(differences, index, "label", label_text(left.payload.label),
                           label_text(right.payload.label));
            compare_string(differences, index, "span", span_text(left.span), span_text(right.span));
            compare_string(differences, index, "policy", left.policy.policy_digest, right.policy.policy_digest);
            compare_string(differences, index, "policy_id", left.policy.policy_id, right.policy.policy_id);
            compare_string(differences, index, "sink_ceiling", label_text(left.policy.sink_ceiling),
                           label_text(right.policy.sink_ceiling));
            compare_string(differences, index, "dry_run", left.policy.dry_run ? "true" : "false",
                           right.policy.dry_run ? "true" : "false");
            compare_string(differences, index, "disposition", disposition_text(left.disposition),
                           disposition_text(right.disposition));
            compare_string(differences, index, "idempotency", left.idempotency_key, right.idempotency_key);
        }
        return differences;
    }

    std::vector<ParityDifference> compare_evaluation_results(const EvaluationResult &expected,
                                                             const EvaluationResult &actual) {
        std::vector<ParityDifference> differences;
        compare_string(differences, 0, "result.outcome", std::to_string(static_cast<std::uint32_t>(expected.outcome)),
                       std::to_string(static_cast<std::uint32_t>(actual.outcome)));
        compare_string(differences, 0, "result.verdict", optional_bool_text(expected.verdict),
                       optional_bool_text(actual.verdict));
        compare_string(differences, 0, "result.fault", fault_text(expected.fault), fault_text(actual.fault));
        compare_string(differences, 0, "result.state.size", std::to_string(expected.state_mutations.size()),
                       std::to_string(actual.state_mutations.size()));
        const auto mutation_count = std::min(expected.state_mutations.size(), actual.state_mutations.size());
        for (std::size_t index = 0; index < mutation_count; ++index) {
            compare_string(differences, index, "result.state", mutation_text(expected.state_mutations[index]),
                           mutation_text(actual.state_mutations[index]));
        }
        auto journal_differences = compare_effect_journals(expected.committed_effects, actual.committed_effects);
        for (auto &difference : journal_differences) { difference.field = "result.effects." + difference.field; }
        differences.insert(differences.end(), std::make_move_iterator(journal_differences.begin()),
                           std::make_move_iterator(journal_differences.end()));
        return differences;
    }

    std::vector<ParityDifference> compare_recorder_snapshots(const RecorderSnapshot &expected,
                                                             const RecorderSnapshot &actual) {
        std::vector<ParityDifference> differences;
        compare_string(differences, 0, "recorder.armed", expected.armed ? "true" : "false",
                       actual.armed ? "true" : "false");
        compare_string(differences, 0, "recorder.publication", expected.publication_requested ? "true" : "false",
                       actual.publication_requested ? "true" : "false");
        compare_string(differences, 0, "recorder.truncated", expected.truncated ? "true" : "false",
                       actual.truncated ? "true" : "false");
        compare_string(differences, 0, "recorder.bytes", std::to_string(expected.estimated_bytes),
                       std::to_string(actual.estimated_bytes));
        compare_string(differences, 0, "recorder.redacted", std::to_string(expected.redacted_events),
                       std::to_string(actual.redacted_events));
        compare_string(differences, 0, "recorder.size", std::to_string(expected.entries.size()),
                       std::to_string(actual.entries.size()));
        const auto count = std::min(expected.entries.size(), actual.entries.size());
        for (std::size_t index = 0; index < count; ++index) {
            compare_string(differences, index, "recorder.entry", recorder_entry_text(expected.entries[index]),
                           recorder_entry_text(actual.entries[index]));
        }
        return differences;
    }

} // namespace rule_engine::python::effects
