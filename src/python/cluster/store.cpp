#include "rule_engine/python/cluster/store.hpp"

#include "rule_engine/python/contract/subject.hpp"

#include <algorithm>
#include <limits>
#include <set>
#include <tuple>
#include <utility>

namespace rule_engine::python::cluster {
    namespace {

        StoreError store_error(const StoreErrorCode code, std::string message, const bool retryable = false) {
            return StoreError {.code = code, .message = std::move(message), .retryable = retryable};
        }

        void append_field(std::string &result, const std::string_view value) {
            result += std::to_string(value.size());
            result.push_back(':');
            result.append(value);
            result.push_back(';');
        }

        template<typename Value> void append_number(std::string &result, const Value value) {
            append_field(result, std::to_string(value));
        }

        void append_label(std::string &result, const DataLabel &label) {
            append_number(result, static_cast<std::uint8_t>(label.classification));
            append_number(result, label.categories.size());
            for (const auto &category : label.categories) { append_field(result, category); }
        }

        void append_frozen(std::string &result, const FrozenValue &value) {
            append_field(result, value.canonical_digest);
            append_label(result, value.label);
            append_number(result, value.value.valid());
        }

        void append_optional_frozen(std::string &result, const std::optional<FrozenValue> &value) {
            append_number(result, value.has_value());
            if (value) {
                append_frozen(result, *value);
            }
        }

        void append_state(std::string &result, const StateMutation &state) {
            append_field(result, state.owner.value);
            append_field(result, state.namespace_name);
            append_field(result, state.key);
            append_number(result, state.expected_version);
            append_optional_frozen(result, state.value);
        }

        void append_effect(std::string &result, const EffectIntent &effect) {
            append_field(result, effect.id.value);
            append_field(result, effect.invocation.value);
            append_field(result, effect.owner.value);
            append_field(result, effect.binding.value);
            append_number(result, effect.sequence);
            append_field(result, effect.kind);
            append_frozen(result, effect.payload);
            append_field(result, effect.span.source.value);
            append_number(result, effect.span.begin_byte);
            append_number(result, effect.span.end_byte);
            append_field(result, effect.policy.policy_id);
            append_field(result, effect.policy.policy_digest);
            append_label(result, effect.policy.sink_ceiling);
            append_number(result, effect.policy.dry_run);
            append_number(result, static_cast<std::uint8_t>(effect.disposition));
            append_field(result, effect.idempotency_key);
        }

        void append_event(std::string &result, const EventEnvelope &event) {
            append_field(result, event.id.value);
            append_field(result, event.schema.value);
            append_field(result, event.tenant.value);
            append_field(result, event.peer.value);
            append_number(result, event.subject.has_value());
            if (event.subject) {
                append_field(result, canonical_subject_key(*event.subject));
            }
            append_number(result, event.producer_unix_ms);
            append_number(result, event.ingest_unix_ms);
            append_label(result, event.label);
            append_number(result, event.causation.has_value());
            if (event.causation) {
                append_field(result, event.causation->value);
            }
            append_frozen(result, event.payload);
        }

        std::string state_signature(const std::vector<StateMutation> &state) {
            std::string result;
            append_number(result, state.size());
            for (const auto &mutation : state) { append_state(result, mutation); }
            return result;
        }

        std::string effect_signature(const std::vector<EffectIntent> &effects) {
            std::string result;
            append_number(result, effects.size());
            for (const auto &effect : effects) { append_effect(result, effect); }
            return result;
        }

        bool valid_frozen(const FrozenValue &value) { return value.value.valid() && !value.canonical_digest.empty(); }

        std::uint64_t saturating_add(const std::uint64_t left, const std::uint64_t right) {
            if (right > std::numeric_limits<std::uint64_t>::max() - left) {
                return std::numeric_limits<std::uint64_t>::max();
            }
            return left + right;
        }

    } // namespace

    std::string InMemoryRuntimeStore::transaction_signature(const RuntimeTransaction &transaction) {
        std::string result;
        append_field(result, "runtime-transaction-v1");
        append_event(result, transaction.input);
        append_field(result, transaction.cursor.consumer);
        append_number(result, transaction.cursor.expected_position);
        append_number(result, transaction.cursor.new_position);
        append_number(result, static_cast<std::uint8_t>(transaction.evaluation.outcome));
        append_number(result, transaction.evaluation.verdict.has_value());
        if (transaction.evaluation.verdict) {
            append_number(result, *transaction.evaluation.verdict);
        }
        append_number(result, transaction.evaluation.fault.has_value());
        if (transaction.evaluation.fault) {
            append_number(result, transaction.evaluation.fault->double_fault);
            append_number(result, transaction.evaluation.fault->triple_fault);
            append_number(result, transaction.evaluation.fault->frames.size());
            for (const auto &frame : transaction.evaluation.fault->frames) {
                append_field(result, frame.code);
                append_field(result, frame.message);
                append_field(result, frame.executable.value);
                append_field(result, frame.span.source.value);
                append_number(result, frame.span.begin_byte);
                append_number(result, frame.span.end_byte);
            }
        }
        append_field(result, state_signature(transaction.evaluation.state_mutations));
        append_field(result, effect_signature(transaction.evaluation.committed_effects));
        append_field(result, state_signature(transaction.state));
        append_number(result, transaction.emitted_events.size());
        for (const auto &event : transaction.emitted_events) { append_event(result, event); }
        append_field(result, effect_signature(transaction.journal));
        append_number(result, transaction.outbox.size());
        for (const auto &outbox : transaction.outbox) {
            append_field(result, outbox.intent.value);
            append_field(result, outbox.destination);
            append_frozen(result, outbox.payload);
            append_field(result, outbox.idempotency_key);
            append_number(result, outbox.not_before_unix_ms);
        }
        append_number(result, transaction.fence_token);
        return result;
    }

    std::expected<void, StoreError>
    InMemoryRuntimeStore::validate_transaction_locked(const RuntimeTransaction &transaction,
                                                      const std::string_view) const {
        if (transaction.input.id.empty() || transaction.input.schema.empty() || transaction.input.tenant.empty() ||
            transaction.input.peer.empty() || !valid_frozen(transaction.input.payload)) {
            return std::unexpected(
                store_error(StoreErrorCode::constraint_violation, "input event identity or payload is invalid"));
        }
        if (transaction.cursor.consumer.empty() ||
            transaction.cursor.expected_position == std::numeric_limits<std::uint64_t>::max() ||
            transaction.cursor.new_position != transaction.cursor.expected_position + 1U) {
            return std::unexpected(store_error(StoreErrorCode::constraint_violation,
                                               "cursor must advance exactly one position in a named serial domain"));
        }
        const auto fence = consumer_fences_.find(transaction.cursor.consumer);
        if (fence == consumer_fences_.end() || transaction.fence_token == 0 ||
            fence->second != transaction.fence_token) {
            return std::unexpected(
                store_error(StoreErrorCode::stale_fence, "transaction does not own the current consumer fence"));
        }
        const auto cursor = cursors_.find(transaction.cursor.consumer);
        const auto current_position = cursor == cursors_.end() ? 0U : cursor->second;
        if (transaction.cursor.expected_position != current_position) {
            return std::unexpected(store_error(StoreErrorCode::conflict, "consumer cursor precondition failed", true));
        }
        if (events_.contains(transaction.input.id.value)) {
            return std::unexpected(
                store_error(StoreErrorCode::constraint_violation, "input event ID is already committed"));
        }

        if (!transaction.evaluation.state_mutations.empty() &&
            state_signature(transaction.evaluation.state_mutations) != state_signature(transaction.state)) {
            return std::unexpected(store_error(StoreErrorCode::constraint_violation,
                                               "evaluation and transaction state mutations disagree"));
        }
        if (!transaction.evaluation.committed_effects.empty() &&
            effect_signature(transaction.evaluation.committed_effects) != effect_signature(transaction.journal)) {
            return std::unexpected(store_error(StoreErrorCode::constraint_violation,
                                               "evaluation and transaction effect journals disagree"));
        }
        if (transaction.evaluation.outcome == EvaluationOutcome::canceled &&
            (!transaction.state.empty() || !transaction.journal.empty() || !transaction.outbox.empty())) {
            return std::unexpected(store_error(StoreErrorCode::constraint_violation,
                                               "a canceled evaluation cannot commit user state or effects"));
        }

        std::set<StoredStateKey> state_keys;
        for (const auto &mutation : transaction.state) {
            const StoredStateKey key {
                .owner = mutation.owner,
                .namespace_name = mutation.namespace_name,
                .key = mutation.key,
            };
            if (key.owner.empty() || key.namespace_name.empty() || key.key.empty() || !state_keys.insert(key).second ||
                (mutation.value && !valid_frozen(*mutation.value))) {
                return std::unexpected(
                    store_error(StoreErrorCode::constraint_violation, "state mutation is invalid or duplicated"));
            }
            const auto current = state_.find(key);
            const auto current_version = current == state_.end() ? 0U : current->second.version;
            if (mutation.expected_version != current_version) {
                return std::unexpected(store_error(StoreErrorCode::conflict, "state MVCC precondition failed", true));
            }
        }

        std::set<std::string, std::less<>> event_ids {transaction.input.id.value};
        for (const auto &event : transaction.emitted_events) {
            if (event.id.empty() || event.schema.empty() || event.tenant.empty() || event.peer.empty() ||
                !valid_frozen(event.payload) || !event_ids.insert(event.id.value).second ||
                events_.contains(event.id.value)) {
                return std::unexpected(store_error(StoreErrorCode::constraint_violation,
                                                   "emitted event identity or payload is invalid or duplicated"));
            }
        }

        std::map<std::string, EffectDisposition, std::less<>> effect_ids;
        for (const auto &effect : transaction.journal) {
            if (effect.id.empty() || effect.invocation.empty() || effect.owner.empty() || effect.binding.empty() ||
                effect.idempotency_key.empty() || !effect.span.valid() || !valid_frozen(effect.payload) ||
                effect.disposition == EffectDisposition::pending ||
                effect.disposition == EffectDisposition::rolled_back ||
                !effect_ids.emplace(effect.id.value, effect.disposition).second || journal_.contains(effect.id.value)) {
                return std::unexpected(
                    store_error(StoreErrorCode::constraint_violation, "effect journal entry is invalid or duplicated"));
            }
        }

        std::set<std::string, std::less<>> outbox_intents;
        std::set<std::string, std::less<>> outbox_keys;
        for (const auto &[_, stored] : outbox_) { outbox_keys.insert(stored.record.idempotency_key); }
        for (const auto &record : transaction.outbox) {
            const auto effect = effect_ids.find(record.intent.value);
            if (record.intent.empty() || record.destination.empty() || record.idempotency_key.empty() ||
                !valid_frozen(record.payload) || !outbox_intents.insert(record.intent.value).second ||
                !outbox_keys.insert(record.idempotency_key).second || outbox_.contains(record.intent.value) ||
                effect == effect_ids.end() || effect->second != EffectDisposition::committed) {
                return std::unexpected(store_error(StoreErrorCode::constraint_violation,
                                                   "outbox row must uniquely reference a committed effect"));
            }
        }

        return {};
    }

    std::expected<TransactionReceipt, StoreError>
    InMemoryRuntimeStore::transact_event(const RuntimeTransaction &transaction) {
        const auto signature = transaction_signature(transaction);
        std::unique_lock lock {mutex_};

        if (const auto receipt = receipts_.find(transaction.input.id.value); receipt != receipts_.end()) {
            if (receipt->second.transaction_signature != signature) {
                return std::unexpected(store_error(StoreErrorCode::constraint_violation,
                                                   "duplicate input event has different transaction content"));
            }
            return receipt->second.receipt;
        }

        if (auto validation = validate_transaction_locked(transaction, signature); !validation) {
            return std::unexpected(std::move(validation.error()));
        }
        if (fail_next_commit_) {
            auto failure = std::move(*fail_next_commit_);
            fail_next_commit_.reset();
            lock.unlock();
            static_cast<void>(audit_.append(transaction.input.ingest_unix_ms, "runtime-store", "event.commit",
                                            transaction.input.id.value, "rolled_back", failure.message));
            return std::unexpected(std::move(failure));
        }

        TransactionReceipt receipt {
            .input = transaction.input.id,
            .committed_cursor = transaction.cursor.new_position,
            .emitted_events = {},
            .outbox_intents = {},
        };

        events_.emplace(transaction.input.id.value, transaction.input);
        for (const auto &event : transaction.emitted_events) {
            events_.emplace(event.id.value, event);
            receipt.emitted_events.push_back(event.id);
        }
        for (const auto &mutation : transaction.state) {
            const StoredStateKey key {
                .owner = mutation.owner,
                .namespace_name = mutation.namespace_name,
                .key = mutation.key,
            };
            state_.insert_or_assign(key, StoredStateCell {
                                             .key = key,
                                             .version = mutation.expected_version + 1U,
                                             .value = mutation.value,
                                         });
        }
        results_.emplace(transaction.input.id.value,
                         StoredResult {.input = transaction.input.id, .evaluation = transaction.evaluation});
        for (const auto &effect : transaction.journal) { journal_.emplace(effect.id.value, effect); }
        for (const auto &record : transaction.outbox) {
            outbox_.emplace(record.intent.value, StoredOutboxRecord {
                                                     .record = record,
                                                     .state = StoredOutboxState::pending,
                                                     .owner = {},
                                                     .fence = 0,
                                                     .lease_until_unix_ms = 0,
                                                     .attempts = 0,
                                                     .terminal_detail = {},
                                                 });
            receipt.outbox_intents.push_back(record.intent);
        }
        cursors_.insert_or_assign(transaction.cursor.consumer, transaction.cursor.new_position);
        receipts_.emplace(transaction.input.id.value,
                          ReceiptEntry {.transaction_signature = signature, .receipt = receipt});

        lock.unlock();
        static_cast<void>(audit_.append(transaction.input.ingest_unix_ms, "runtime-store", "event.commit",
                                        transaction.input.id.value, "committed", transaction.cursor.consumer));
        return receipt;
    }

    std::expected<void, StoreError> InMemoryRuntimeStore::install_consumer_fence(const std::string_view consumer,
                                                                                 const std::uint64_t fence) {
        if (consumer.empty() || fence == 0) {
            return std::unexpected(
                store_error(StoreErrorCode::constraint_violation, "consumer fence must be named and non-zero"));
        }
        const std::scoped_lock lock {mutex_};
        const auto current = consumer_fences_.find(consumer);
        if (current != consumer_fences_.end() && fence < current->second) {
            return std::unexpected(store_error(StoreErrorCode::stale_fence, "consumer fence cannot move backward"));
        }
        consumer_fences_.insert_or_assign(std::string {consumer}, fence);
        return {};
    }

    std::uint64_t InMemoryRuntimeStore::consumer_fence(const std::string_view consumer) const {
        const std::scoped_lock lock {mutex_};
        const auto current = consumer_fences_.find(consumer);
        return current == consumer_fences_.end() ? 0U : current->second;
    }

    std::optional<TransactionReceipt> InMemoryRuntimeStore::lookup_receipt(const EventId &input) const {
        const std::scoped_lock lock {mutex_};
        const auto receipt = receipts_.find(input.value);
        if (receipt == receipts_.end()) {
            return std::nullopt;
        }
        return receipt->second.receipt;
    }

    std::optional<StoredStateCell> InMemoryRuntimeStore::read_state(const StoredStateKey &key) const {
        const std::scoped_lock lock {mutex_};
        const auto value = state_.find(key);
        if (value == state_.end()) {
            return std::nullopt;
        }
        return value->second;
    }

    std::expected<std::vector<OutboxLease>, StoreError>
    InMemoryRuntimeStore::claim_outbox(const std::string_view owner, const std::uint64_t now_unix_ms,
                                       const std::uint64_t lease_duration_ms, const std::size_t limit) {
        if (owner.empty() || lease_duration_ms == 0 || limit == 0) {
            return std::unexpected(
                store_error(StoreErrorCode::constraint_violation, "outbox claim arguments are invalid"));
        }

        std::unique_lock lock {mutex_};
        std::vector<StoredOutboxRecord *> candidates;
        for (auto &[_, stored] : outbox_) {
            const auto pending =
                stored.state == StoredOutboxState::pending && stored.record.not_before_unix_ms <= now_unix_ms;
            const auto expired = stored.state == StoredOutboxState::leased && stored.lease_until_unix_ms < now_unix_ms;
            if (pending || expired) {
                candidates.push_back(&stored);
            }
        }
        std::ranges::sort(candidates, [](const StoredOutboxRecord *left, const StoredOutboxRecord *right) {
            return std::tie(left->record.not_before_unix_ms, left->record.intent.value) <
                   std::tie(right->record.not_before_unix_ms, right->record.intent.value);
        });

        std::vector<OutboxLease> leases;
        leases.reserve(std::min(limit, candidates.size()));
        for (auto *stored : candidates) {
            if (leases.size() == limit) {
                break;
            }
            stored->state = StoredOutboxState::leased;
            stored->owner = std::string {owner};
            ++stored->fence;
            ++stored->attempts;
            stored->lease_until_unix_ms = saturating_add(now_unix_ms, lease_duration_ms);
            leases.push_back(OutboxLease {
                .record = stored->record,
                .owner = stored->owner,
                .fence = stored->fence,
                .lease_until_unix_ms = stored->lease_until_unix_ms,
                .attempt = stored->attempts,
            });
        }
        lock.unlock();
        if (!leases.empty()) {
            static_cast<void>(
                audit_.append(now_unix_ms, owner, "outbox.claim", "outbox", "leased", std::to_string(leases.size())));
        }
        return leases;
    }

    std::expected<void, StoreError> InMemoryRuntimeStore::settle_outbox(const OutboxSettlement &settlement) {
        std::unique_lock lock {mutex_};
        const auto item = outbox_.find(settlement.intent.value);
        if (item == outbox_.end()) {
            return std::unexpected(store_error(StoreErrorCode::constraint_violation, "outbox intent does not exist"));
        }
        auto &stored = item->second;
        if (stored.state != StoredOutboxState::leased || stored.owner != settlement.owner ||
            stored.fence != settlement.fence || settlement.now_unix_ms > stored.lease_until_unix_ms) {
            return std::unexpected(store_error(StoreErrorCode::stale_fence, "outbox lease is stale"));
        }

        std::string outcome;
        switch (settlement.kind) {
            case OutboxSettlementKind::delivered:
                stored.state = StoredOutboxState::delivered;
                stored.terminal_detail = settlement.detail;
                outcome = "delivered";
                break;
            case OutboxSettlementKind::retry:
                if (settlement.retry_not_before_unix_ms <= settlement.now_unix_ms) {
                    return std::unexpected(store_error(StoreErrorCode::constraint_violation,
                                                       "outbox retry must be scheduled in the future"));
                }
                stored.state = StoredOutboxState::pending;
                stored.record.not_before_unix_ms = settlement.retry_not_before_unix_ms;
                stored.owner.clear();
                stored.lease_until_unix_ms = 0;
                stored.terminal_detail = settlement.detail;
                outcome = "retry";
                break;
            case OutboxSettlementKind::dead_letter:
                stored.state = StoredOutboxState::dead_letter;
                stored.terminal_detail = settlement.detail;
                outcome = "dead_letter";
                break;
            default:
                return std::unexpected(
                    store_error(StoreErrorCode::constraint_violation, "unknown outbox settlement kind"));
        }
        lock.unlock();
        static_cast<void>(audit_.append(settlement.now_unix_ms, settlement.owner, "outbox.settle",
                                        settlement.intent.value, outcome, settlement.detail));
        return {};
    }

    void InMemoryRuntimeStore::fail_next_commit(StoreError error) {
        const std::scoped_lock lock {mutex_};
        fail_next_commit_ = std::move(error);
    }

    RuntimeStoreSnapshot InMemoryRuntimeStore::snapshot() const {
        const std::scoped_lock lock {mutex_};
        RuntimeStoreSnapshot result;
        result.events.reserve(events_.size());
        result.cursors.reserve(cursors_.size());
        result.state.reserve(state_.size());
        result.results.reserve(results_.size());
        result.journal.reserve(journal_.size());
        result.outbox.reserve(outbox_.size());
        result.receipts.reserve(receipts_.size());
        for (const auto &[_, event] : events_) { result.events.push_back(event); }
        for (const auto &[consumer, cursor] : cursors_) { result.cursors.emplace_back(consumer, cursor); }
        for (const auto &[_, value] : state_) { result.state.push_back(value); }
        for (const auto &[_, value] : results_) { result.results.push_back(value); }
        for (const auto &[_, value] : journal_) { result.journal.push_back(value); }
        for (const auto &[_, value] : outbox_) { result.outbox.push_back(value); }
        for (const auto &[_, value] : receipts_) { result.receipts.push_back(value.receipt); }
        return result;
    }

} // namespace rule_engine::python::cluster
