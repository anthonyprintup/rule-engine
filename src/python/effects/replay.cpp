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

} // namespace rule_engine::python::effects
