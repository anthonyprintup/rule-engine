#include "rule_engine/python/effects/journal.hpp"

#include "rule_engine/python/effects/labels.hpp"

#include <algorithm>
#include <limits>
#include <utility>

namespace rule_engine::python::effects {
    namespace {

        struct ScopeState {
            JournalScopeId id;
            std::optional<JournalScopeId> parent;
            JournalScopeKind kind {JournalScopeKind::explicit_transaction};
            InvocationOwner owner;
            JournalScopeDisposition disposition {JournalScopeDisposition::open};
            bool commit_requested {};
        };

        struct ReachedEffect {
            std::string key;
            std::size_t intent_index {};
            std::string source_payload_digest;
            DataLabel source_payload_label;
        };

        bool owner_valid(const InvocationOwner &owner) noexcept {
            return !owner.execution.empty() && !owner.invocation.empty() && !owner.executable.empty() &&
                   !owner.binding.empty();
        }

        FrozenValue redact_payload(const FrozenValue &payload) {
            return FrozenValue {
                .value = make_fact(std::monostate {}),
                .label = payload.label,
                .canonical_digest = "redacted:v1",
            };
        }

        EffectDisposition initial_disposition(const ReceiptEligibility eligibility) noexcept {
            switch (eligibility) {
                case ReceiptEligibility::queued: return EffectDisposition::pending;
                case ReceiptEligibility::dry_run: return EffectDisposition::dry_run;
                case ReceiptEligibility::suppressed: return EffectDisposition::suppressed;
                default: return EffectDisposition::suppressed;
            }
        }

        bool clean_outcome(const EvaluationOutcome outcome) noexcept {
            return outcome == EvaluationOutcome::match || outcome == EvaluationOutcome::no_match;
        }

        bool same_policy(const EffectPolicySnapshot &left, const EffectPolicySnapshot &right) noexcept {
            return left.policy_id == right.policy_id && left.policy_digest == right.policy_digest &&
                   left.sink_ceiling == right.sink_ceiling && left.dry_run == right.dry_run;
        }

        ReceiptEligibility vm_eligibility(const EffectIntent &intent) noexcept {
            if (intent.disposition == EffectDisposition::suppressed) {
                return ReceiptEligibility::suppressed;
            }
            if (intent.disposition == EffectDisposition::dry_run || intent.policy.dry_run) {
                return ReceiptEligibility::dry_run;
            }
            return ReceiptEligibility::queued;
        }

        bool same_vm_intent(const EffectIntent &left, const EffectIntent &right) noexcept {
            return left.id == right.id && left.invocation == right.invocation && left.owner == right.owner &&
                   left.binding == right.binding && left.sequence == right.sequence && left.kind == right.kind &&
                   same_frozen_value(left.payload, right.payload) && left.span == right.span &&
                   same_policy(left.policy, right.policy) && left.disposition == right.disposition &&
                   left.idempotency_key == right.idempotency_key;
        }

        std::size_t intent_charge(const EffectIntent &intent) noexcept {
            return frozen_value_size(intent.payload) + intent.id.value.size() + intent.invocation.value.size() +
                   intent.owner.value.size() + intent.binding.value.size() + intent.kind.size() +
                   intent.policy.policy_id.size() + intent.policy.policy_digest.size() + intent.idempotency_key.size() +
                   std::to_string(intent.sequence).size();
        }

    } // namespace

    struct EffectJournal::Implementation {
        InvocationOwner root_owner;
        ExecutionMode mode {ExecutionMode::live};
        JournalLimits limits;
        std::vector<ScopeState> scopes;
        std::vector<EffectIntent> intents;
        std::vector<JournalScopeId> intent_scopes;
        std::vector<ReceiptEligibility> intent_eligibilities;
        std::vector<ReachedEffect> reached;
        std::size_t charged_bytes {};
        std::uint64_t next_scope {2};
        std::uint64_t next_sequence {1};
        bool finalized {};

        [[nodiscard]] ScopeState *find_scope(const JournalScopeId id) noexcept {
            const auto found = std::ranges::find(scopes, id, &ScopeState::id);
            return found == scopes.end() ? nullptr : &*found;
        }

        [[nodiscard]] const ScopeState *find_scope(const JournalScopeId id) const noexcept {
            const auto found = std::ranges::find(scopes, id, &ScopeState::id);
            return found == scopes.end() ? nullptr : &*found;
        }

        [[nodiscard]] bool is_descendant_of(JournalScopeId candidate, const JournalScopeId ancestor) const noexcept {
            while (candidate != ancestor) {
                const auto *scope = find_scope(candidate);
                if (scope == nullptr || !scope->parent.has_value()) {
                    return false;
                }
                candidate = *scope->parent;
            }
            return true;
        }

        [[nodiscard]] bool has_open_descendant(const JournalScopeId parent) const noexcept {
            return std::ranges::any_of(scopes, [&](const ScopeState &scope) {
                const auto unclosed = scope.disposition == JournalScopeDisposition::open ||
                                      scope.disposition == JournalScopeDisposition::eligible_to_merge;
                return scope.id != parent && unclosed && is_descendant_of(scope.id, parent);
            });
        }

        void mark_rolled_back(const JournalScopeId scope_id) {
            for (std::size_t index = 0; index < intents.size(); ++index) {
                if (is_descendant_of(intent_scopes[index], scope_id)) {
                    intents[index].disposition = EffectDisposition::rolled_back;
                }
            }
            for (auto &scope : scopes) {
                if (is_descendant_of(scope.id, scope_id)) {
                    scope.disposition = JournalScopeDisposition::rolled_back;
                }
            }
        }
    };

    bool FinalizedJournal::durable_commit_allowed() const noexcept { return mode == ExecutionMode::live && clean; }

    std::vector<EffectIntent> FinalizedJournal::durable_intents() const {
        std::vector<EffectIntent> result;
        if (!durable_commit_allowed()) {
            return result;
        }
        std::ranges::copy_if(intents, std::back_inserter(result), [](const EffectIntent &intent) {
            return intent.disposition != EffectDisposition::rolled_back;
        });
        return result;
    }

    std::vector<EffectIntent> FinalizedJournal::dispatchable_intents(const std::string_view kind) const {
        std::vector<EffectIntent> result;
        if (!durable_commit_allowed()) {
            return result;
        }
        std::ranges::copy_if(intents, std::back_inserter(result), [&](const EffectIntent &intent) {
            return intent.kind == kind && intent.disposition == EffectDisposition::committed;
        });
        return result;
    }

    std::expected<EffectJournal, EffectError>
    EffectJournal::create(InvocationOwner root_owner, const ExecutionMode mode, const JournalLimits limits) {
        if (!owner_valid(root_owner) || limits.maximum_intents == 0 || limits.maximum_bytes == 0) {
            return std::unexpected(EffectError {
                .code = EffectErrorCode::invalid_argument,
                .message = "an effect journal requires complete root ownership and non-zero limits",
                .span = std::nullopt,
            });
        }

        auto implementation = std::make_unique<Implementation>();
        implementation->root_owner = std::move(root_owner);
        implementation->mode = mode;
        implementation->limits = limits;
        implementation->scopes.push_back(ScopeState {
            .id = JournalScopeId {1},
            .parent = std::nullopt,
            .kind = JournalScopeKind::root,
            .owner = implementation->root_owner,
            .disposition = JournalScopeDisposition::open,
            .commit_requested = true,
        });
        return EffectJournal {std::move(implementation)};
    }

    EffectJournal::EffectJournal(std::unique_ptr<Implementation> implementation) noexcept:
        implementation_ {std::move(implementation)} {}

    EffectJournal::EffectJournal(EffectJournal &&other) noexcept = default;
    EffectJournal &EffectJournal::operator=(EffectJournal &&other) noexcept = default;
    EffectJournal::~EffectJournal() = default;

    JournalScopeId EffectJournal::root_scope() const noexcept { return JournalScopeId {1}; }

    std::expected<JournalScopeId, EffectError>
    EffectJournal::open_scope(const JournalScopeId parent, const JournalScopeKind kind, InvocationOwner owner) {
        if (implementation_->finalized) {
            return std::unexpected(EffectError {.code = EffectErrorCode::already_finalized,
                                                .message = "the root journal is already finalized",
                                                .span = std::nullopt});
        }
        if (kind == JournalScopeKind::root || !owner_valid(owner) ||
            owner.execution != implementation_->root_owner.execution) {
            return std::unexpected(EffectError {
                .code = EffectErrorCode::invalid_argument,
                .message = "nested scopes require valid ownership in the root execution",
                .span = std::nullopt,
            });
        }
        const auto *parent_scope = implementation_->find_scope(parent);
        if (parent_scope == nullptr) {
            return std::unexpected(EffectError {.code = EffectErrorCode::unknown_scope,
                                                .message = "the parent journal scope does not exist",
                                                .span = std::nullopt});
        }
        if (parent_scope->disposition != JournalScopeDisposition::open &&
            parent_scope->disposition != JournalScopeDisposition::eligible_to_merge) {
            return std::unexpected(EffectError {.code = EffectErrorCode::scope_not_open,
                                                .message = "a nested scope can only open below an open parent",
                                                .span = std::nullopt});
        }
        if (implementation_->next_scope == std::numeric_limits<std::uint64_t>::max()) {
            return std::unexpected(EffectError {.code = EffectErrorCode::invalid_scope_operation,
                                                .message = "journal scope identity space is exhausted",
                                                .span = std::nullopt});
        }

        const JournalScopeId id {implementation_->next_scope++};
        implementation_->scopes.push_back(ScopeState {
            .id = id,
            .parent = parent,
            .kind = kind,
            .owner = std::move(owner),
            .disposition = JournalScopeDisposition::open,
            .commit_requested = false,
        });
        return id;
    }

    std::expected<void, EffectError> EffectJournal::request_commit(const JournalScopeId scope) {
        auto *state = implementation_->find_scope(scope);
        if (state == nullptr) {
            return std::unexpected(EffectError {.code = EffectErrorCode::unknown_scope,
                                                .message = "the journal scope does not exist",
                                                .span = std::nullopt});
        }
        if (state->kind != JournalScopeKind::explicit_transaction ||
            state->disposition != JournalScopeDisposition::open) {
            return std::unexpected(EffectError {
                .code = EffectErrorCode::invalid_scope_operation,
                .message = "only an open explicit transaction can request commit",
                .span = std::nullopt,
            });
        }
        state->commit_requested = true;
        state->disposition = JournalScopeDisposition::eligible_to_merge;
        return {};
    }

    std::expected<void, EffectError> EffectJournal::close_scope(const JournalScopeId scope, const JournalExit exit) {
        auto *state = implementation_->find_scope(scope);
        if (state == nullptr) {
            return std::unexpected(EffectError {.code = EffectErrorCode::unknown_scope,
                                                .message = "the journal scope does not exist",
                                                .span = std::nullopt});
        }
        if (state->kind == JournalScopeKind::root) {
            return std::unexpected(EffectError {.code = EffectErrorCode::invalid_scope_operation,
                                                .message = "the root scope closes only through finish_root",
                                                .span = std::nullopt});
        }
        if (state->disposition != JournalScopeDisposition::open &&
            state->disposition != JournalScopeDisposition::eligible_to_merge) {
            return std::unexpected(EffectError {.code = EffectErrorCode::scope_not_open,
                                                .message = "the journal scope is already closed",
                                                .span = std::nullopt});
        }
        if (implementation_->has_open_descendant(scope)) {
            return std::unexpected(EffectError {.code = EffectErrorCode::child_scope_open,
                                                .message = "all child scopes must close before their parent",
                                                .span = std::nullopt});
        }

        const auto merge = exit == JournalExit::normal &&
                           (state->kind == JournalScopeKind::child_invocation || state->commit_requested);
        if (!merge) {
            implementation_->mark_rolled_back(scope);
            return {};
        }
        state->disposition = JournalScopeDisposition::merged;
        return {};
    }

    std::expected<void, EffectError> EffectJournal::rollback_scope(const JournalScopeId scope) {
        auto *state = implementation_->find_scope(scope);
        if (state == nullptr) {
            return std::unexpected(EffectError {.code = EffectErrorCode::unknown_scope,
                                                .message = "the journal scope does not exist",
                                                .span = std::nullopt});
        }
        if (state->kind == JournalScopeKind::root ||
            (state->disposition != JournalScopeDisposition::open &&
             state->disposition != JournalScopeDisposition::eligible_to_merge)) {
            return std::unexpected(EffectError {.code = EffectErrorCode::invalid_scope_operation,
                                                .message = "only an open nested scope can be rolled back explicitly",
                                                .span = std::nullopt});
        }
        implementation_->mark_rolled_back(scope);
        return {};
    }

    std::expected<EffectReceipt, EffectError> EffectJournal::append(const JournalScopeId scope_id,
                                                                    const EffectDraft &draft) {
        if (implementation_->finalized) {
            return std::unexpected(EffectError {.code = EffectErrorCode::already_finalized,
                                                .message = "the root journal is already finalized",
                                                .span = draft.span});
        }
        const auto *scope = implementation_->find_scope(scope_id);
        if (scope == nullptr) {
            return std::unexpected(EffectError {.code = EffectErrorCode::unknown_scope,
                                                .message = "the journal scope does not exist",
                                                .span = draft.span});
        }
        if (scope->disposition != JournalScopeDisposition::open &&
            scope->disposition != JournalScopeDisposition::eligible_to_merge) {
            return std::unexpected(EffectError {.code = EffectErrorCode::scope_not_open,
                                                .message = "effects can only be appended to an open scope",
                                                .span = draft.span});
        }
        if (draft.reach_key.empty() || draft.kind.empty() || !draft.payload.value.valid() ||
            draft.payload.canonical_digest.empty() || !draft.span.valid() || draft.policy.snapshot.policy_id.empty() ||
            draft.policy.snapshot.policy_digest.empty()) {
            return std::unexpected(
                EffectError {.code = EffectErrorCode::invalid_argument,
                             .message = "an effect requires a stable reach key, payload, span, and policy",
                             .span = draft.span});
        }

        auto payload = apply_control_label(draft.payload, draft.control_label);
        if (!may_flow_to(payload.label, draft.policy.snapshot.sink_ceiling)) {
            return std::unexpected(EffectError {.code = EffectErrorCode::label_rejected,
                                                .message = "the effect payload exceeds the sink classification ceiling",
                                                .span = draft.span});
        }

        const auto deduplication_key = stable_domain_key(
            "effect-reach-v1", {scope->owner.execution.value, scope->owner.invocation.value, draft.reach_key});
        auto normalized_policy = draft.policy.snapshot;
        normalized_policy.dry_run = draft.policy.eligibility == ReceiptEligibility::dry_run;
        const auto prior_reach = std::ranges::find(implementation_->reached, deduplication_key, &ReachedEffect::key);
        if (prior_reach != implementation_->reached.end()) {
            const auto index = prior_reach->intent_index;
            const auto &prior = implementation_->intents[index];
            if (prior.kind != draft.kind || prior_reach->source_payload_digest != payload.canonical_digest ||
                prior_reach->source_payload_label != payload.label || prior.span != draft.span ||
                !same_policy(prior.policy, normalized_policy) || implementation_->intent_scopes[index] != scope_id ||
                implementation_->intent_eligibilities[index] != draft.policy.eligibility) {
                return std::unexpected(EffectError {
                    .code = EffectErrorCode::duplicate_reach_mismatch,
                    .message = "a resumed effect reach token was reused with different semantics",
                    .span = draft.span,
                });
            }
            return receipt(prior.id);
        }

        if (implementation_->intents.size() >= implementation_->limits.maximum_intents) {
            return std::unexpected(EffectError {.code = EffectErrorCode::intent_limit_exhausted,
                                                .message = "the evaluation effect-intent limit is exhausted",
                                                .span = draft.span});
        }

        auto stored_payload =
            draft.policy.eligibility == ReceiptEligibility::suppressed ? redact_payload(payload) : std::move(payload);
        const auto sequence = implementation_->next_sequence;
        const auto sequence_text = std::to_string(sequence);
        const auto intent_key = stable_domain_key(
            "intent-v1", {scope->owner.execution.value, scope->owner.invocation.value, draft.reach_key});
        const auto idempotency_key =
            stable_domain_key("effect-idempotency-v1", {intent_key, scope->owner.binding.value, draft.kind});
        if (std::ranges::find(implementation_->intents, IntentId {intent_key}, &EffectIntent::id) !=
                implementation_->intents.end() ||
            std::ranges::find(implementation_->intents, idempotency_key, &EffectIntent::idempotency_key) !=
                implementation_->intents.end()) {
            return std::unexpected(EffectError {
                .code = EffectErrorCode::duplicate_reach_mismatch,
                .message = "the effect identity collides with an existing VM or journal reach",
                .span = draft.span,
            });
        }

        EffectIntent intent {
            .id = IntentId {intent_key},
            .invocation = scope->owner.invocation,
            .owner = scope->owner.executable,
            .binding = scope->owner.binding,
            .sequence = sequence,
            .kind = draft.kind,
            .payload = std::move(stored_payload),
            .span = draft.span,
            .policy = std::move(normalized_policy),
            .disposition = initial_disposition(draft.policy.eligibility),
            .idempotency_key = idempotency_key,
        };
        const auto charge = frozen_value_size(intent.payload) + intent.id.value.size() +
                            intent.invocation.value.size() + intent.owner.value.size() + intent.binding.value.size() +
                            intent.kind.size() + intent.policy.policy_id.size() + intent.policy.policy_digest.size() +
                            intent.idempotency_key.size() + sequence_text.size();
        if (charge > implementation_->limits.maximum_bytes -
                         std::min(implementation_->limits.maximum_bytes, implementation_->charged_bytes)) {
            return std::unexpected(EffectError {.code = EffectErrorCode::byte_limit_exhausted,
                                                .message = "the evaluation frozen-effect byte limit is exhausted",
                                                .span = draft.span});
        }

        const auto index = implementation_->intents.size();
        implementation_->intents.push_back(std::move(intent));
        implementation_->intent_scopes.push_back(scope_id);
        implementation_->intent_eligibilities.push_back(draft.policy.eligibility);
        implementation_->reached.push_back(ReachedEffect {
            .key = deduplication_key,
            .intent_index = index,
            .source_payload_digest = draft.payload.canonical_digest,
            .source_payload_label = apply_control_label(draft.payload, draft.control_label).label,
        });
        implementation_->charged_bytes += charge;
        ++implementation_->next_sequence;
        return receipt(implementation_->intents.back().id);
    }

    std::expected<EffectReceipt, EffectError> EffectJournal::append_vm_intent(const JournalScopeId scope_id,
                                                                              const EffectIntent &supplied,
                                                                              const DataLabel &control_label) {
        if (implementation_->finalized) {
            return std::unexpected(EffectError {.code = EffectErrorCode::already_finalized,
                                                .message = "the root journal is already finalized",
                                                .span = supplied.span});
        }
        const auto *scope = implementation_->find_scope(scope_id);
        if (scope == nullptr) {
            return std::unexpected(EffectError {.code = EffectErrorCode::unknown_scope,
                                                .message = "the journal scope does not exist",
                                                .span = supplied.span});
        }
        if (scope->disposition != JournalScopeDisposition::open &&
            scope->disposition != JournalScopeDisposition::eligible_to_merge) {
            return std::unexpected(EffectError {.code = EffectErrorCode::scope_not_open,
                                                .message = "VM effects can only be appended to an open scope",
                                                .span = supplied.span});
        }
        if (supplied.id.empty() || supplied.invocation.empty() || supplied.owner.empty() || supplied.binding.empty() ||
            supplied.kind.empty() || !supplied.payload.value.valid() || supplied.payload.canonical_digest.empty() ||
            !supplied.span.valid() || supplied.policy.policy_id.empty() || supplied.policy.policy_digest.empty() ||
            supplied.idempotency_key.empty() || supplied.sequence == 0 ||
            supplied.disposition == EffectDisposition::committed) {
            return std::unexpected(EffectError {
                .code = EffectErrorCode::invalid_argument,
                .message = "a VM effect delta requires an uncommitted immutable identity, payload, span, and policy",
                .span = supplied.span,
            });
        }
        if (supplied.invocation != scope->owner.invocation || supplied.owner != scope->owner.executable ||
            supplied.binding != scope->owner.binding) {
            return std::unexpected(EffectError {
                .code = EffectErrorCode::ownership_mismatch,
                .message = "the VM effect identity does not belong to the selected journal scope",
                .span = supplied.span,
            });
        }

        auto normalized = supplied;
        normalized.payload = apply_control_label(supplied.payload, control_label);
        const auto eligibility = vm_eligibility(supplied);
        normalized.policy.dry_run = eligibility == ReceiptEligibility::dry_run;
        normalized.disposition = supplied.disposition == EffectDisposition::rolled_back ?
                                     EffectDisposition::rolled_back :
                                     initial_disposition(eligibility);
        if (!may_flow_to(normalized.payload.label, normalized.policy.sink_ceiling)) {
            return std::unexpected(
                EffectError {.code = EffectErrorCode::label_rejected,
                             .message = "the VM effect payload exceeds the sink classification ceiling",
                             .span = supplied.span});
        }

        const auto existing = std::ranges::find(implementation_->intents, supplied.id, &EffectIntent::id);
        if (existing != implementation_->intents.end()) {
            const auto index = static_cast<std::size_t>(std::distance(implementation_->intents.begin(), existing));
            if (implementation_->intent_scopes[index] != scope_id ||
                implementation_->intent_eligibilities[index] != eligibility || !same_vm_intent(*existing, normalized)) {
                return std::unexpected(EffectError {
                    .code = EffectErrorCode::duplicate_reach_mismatch,
                    .message = "a resumed VM intent was reused with different semantics or ownership",
                    .span = supplied.span,
                });
            }
            return receipt(existing->id);
        }
        if (std::ranges::find(implementation_->intents, supplied.idempotency_key, &EffectIntent::idempotency_key) !=
            implementation_->intents.end()) {
            return std::unexpected(EffectError {
                .code = EffectErrorCode::duplicate_reach_mismatch,
                .message = "a VM intent reused an idempotency key owned by a different effect",
                .span = supplied.span,
            });
        }
        if (supplied.sequence != implementation_->next_sequence) {
            return std::unexpected(EffectError {
                .code = EffectErrorCode::sequence_mismatch,
                .message = "VM effect deltas must preserve the evaluation-wide journal sequence",
                .span = supplied.span,
            });
        }
        if (implementation_->intents.size() >= implementation_->limits.maximum_intents) {
            return std::unexpected(EffectError {.code = EffectErrorCode::intent_limit_exhausted,
                                                .message = "the evaluation effect-intent limit is exhausted",
                                                .span = supplied.span});
        }
        const auto charge = intent_charge(normalized);
        if (charge > implementation_->limits.maximum_bytes -
                         std::min(implementation_->limits.maximum_bytes, implementation_->charged_bytes)) {
            return std::unexpected(EffectError {.code = EffectErrorCode::byte_limit_exhausted,
                                                .message = "the evaluation frozen-effect byte limit is exhausted",
                                                .span = supplied.span});
        }

        implementation_->intents.push_back(std::move(normalized));
        implementation_->intent_scopes.push_back(scope_id);
        implementation_->intent_eligibilities.push_back(eligibility);
        implementation_->charged_bytes += charge;
        ++implementation_->next_sequence;
        return receipt(implementation_->intents.back().id);
    }

    std::expected<EffectReceipt, EffectError> EffectJournal::receipt(const IntentId &intent) const {
        const auto found = std::ranges::find(implementation_->intents, intent, &EffectIntent::id);
        if (found == implementation_->intents.end()) {
            return std::unexpected(EffectError {.code = EffectErrorCode::unknown_intent,
                                                .message = "the intent does not belong to this journal",
                                                .span = std::nullopt});
        }
        const auto index = static_cast<std::size_t>(std::distance(implementation_->intents.begin(), found));
        return EffectReceipt {
            .intent = found->id,
            .call_site_eligibility = implementation_->intent_eligibilities[index],
            .final_disposition = found->disposition,
        };
    }

    std::expected<JournalScopeDisposition, EffectError>
    EffectJournal::scope_disposition(const JournalScopeId scope) const {
        const auto *state = implementation_->find_scope(scope);
        if (state == nullptr) {
            return std::unexpected(EffectError {.code = EffectErrorCode::unknown_scope,
                                                .message = "the journal scope does not exist",
                                                .span = std::nullopt});
        }
        return state->disposition;
    }

    const std::vector<EffectIntent> &EffectJournal::intents() const noexcept { return implementation_->intents; }

    std::size_t EffectJournal::charged_bytes() const noexcept { return implementation_->charged_bytes; }

    std::expected<FinalizedJournal, EffectError> EffectJournal::finish_root(const EvaluationOutcome outcome) {
        if (implementation_->finalized) {
            return std::unexpected(EffectError {.code = EffectErrorCode::already_finalized,
                                                .message = "the root journal is already finalized",
                                                .span = std::nullopt});
        }
        if (implementation_->has_open_descendant(root_scope())) {
            return std::unexpected(EffectError {.code = EffectErrorCode::child_scope_open,
                                                .message = "all nested scopes must close before root finalization",
                                                .span = std::nullopt});
        }

        const auto clean = clean_outcome(outcome);
        if (!clean) {
            implementation_->mark_rolled_back(root_scope());
        } else {
            for (auto &intent : implementation_->intents) {
                if (intent.disposition == EffectDisposition::pending) {
                    intent.disposition = EffectDisposition::committed;
                }
            }
            for (auto &scope : implementation_->scopes) {
                if (scope.disposition != JournalScopeDisposition::rolled_back) {
                    scope.disposition = JournalScopeDisposition::committed;
                }
            }
        }
        implementation_->finalized = true;
        return FinalizedJournal {
            .mode = implementation_->mode,
            .outcome = outcome,
            .clean = clean,
            .intents = implementation_->intents,
        };
    }

} // namespace rule_engine::python::effects
