#pragma once

#include "rule_engine/python/effects/common.hpp"

#include <compare>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace rule_engine::python::effects {

    struct InvocationOwner {
        ExecutionId execution;
        InvocationId invocation;
        ExecutableId executable;
        BindingId binding;
    };

    enum struct ReceiptEligibility : std::uint8_t { queued, dry_run, suppressed };

    struct EffectCallPolicy {
        EffectPolicySnapshot snapshot;
        ReceiptEligibility eligibility {ReceiptEligibility::queued};
    };

    struct EffectDraft {
        // The VM supplies a stable token for one dynamic reach. Reusing the same
        // token after suspension is idempotent; loop iterations use distinct tokens.
        std::string reach_key;
        std::string kind;
        FrozenValue payload;
        SourceSpan span;
        EffectCallPolicy policy;
        DataLabel control_label;
    };

    struct JournalScopeId {
        std::uint64_t value {};
        auto operator<=>(const JournalScopeId &) const = default;
    };

    enum struct JournalScopeKind : std::uint8_t { root, child_invocation, explicit_transaction };
    enum struct JournalScopeDisposition : std::uint8_t { open, eligible_to_merge, merged, rolled_back, committed };
    enum struct JournalExit : std::uint8_t { normal, exceptional };

    struct EffectReceipt {
        IntentId intent;
        ReceiptEligibility call_site_eligibility {ReceiptEligibility::queued};
        EffectDisposition final_disposition {EffectDisposition::pending};
    };

    struct JournalLimits {
        std::uint32_t maximum_intents {balanced_v1.normal.effect_intents};
        std::size_t maximum_bytes {balanced_v1.normal.effect_bytes};
    };

    struct FinalizedJournal {
        ExecutionMode mode {ExecutionMode::live};
        EvaluationOutcome outcome {EvaluationOutcome::faulted};
        bool clean {};
        std::vector<EffectIntent> intents;

        [[nodiscard]] bool durable_commit_allowed() const noexcept;
        [[nodiscard]] std::vector<EffectIntent> durable_intents() const;
        [[nodiscard]] std::vector<EffectIntent> dispatchable_intents(std::string_view kind = "post") const;
    };

    struct EffectJournal {
        struct Implementation;

        [[nodiscard]] static std::expected<EffectJournal, EffectError>
        create(InvocationOwner root_owner, ExecutionMode mode = ExecutionMode::live, JournalLimits limits = {});

        EffectJournal(EffectJournal &&other) noexcept;
        EffectJournal &operator=(EffectJournal &&other) noexcept;
        EffectJournal(const EffectJournal &) = delete;
        EffectJournal &operator=(const EffectJournal &) = delete;
        ~EffectJournal();

        [[nodiscard]] JournalScopeId root_scope() const noexcept;
        [[nodiscard]] std::expected<JournalScopeId, EffectError>
        open_scope(JournalScopeId parent, JournalScopeKind kind, InvocationOwner owner);
        [[nodiscard]] std::expected<void, EffectError> request_commit(JournalScopeId scope);
        [[nodiscard]] std::expected<void, EffectError> close_scope(JournalScopeId scope, JournalExit exit);
        [[nodiscard]] std::expected<void, EffectError> rollback_scope(JournalScopeId scope);

        [[nodiscard]] std::expected<EffectReceipt, EffectError> append(JournalScopeId scope, const EffectDraft &draft);
        [[nodiscard]] std::expected<EffectReceipt, EffectError> receipt(const IntentId &intent) const;
        [[nodiscard]] std::expected<JournalScopeDisposition, EffectError> scope_disposition(JournalScopeId scope) const;
        [[nodiscard]] const std::vector<EffectIntent> &intents() const noexcept;
        [[nodiscard]] std::size_t charged_bytes() const noexcept;

        [[nodiscard]] std::expected<FinalizedJournal, EffectError> finish_root(EvaluationOutcome outcome);

    private:
        explicit EffectJournal(std::unique_ptr<Implementation> implementation) noexcept;

        std::unique_ptr<Implementation> implementation_;
    };

} // namespace rule_engine::python::effects
