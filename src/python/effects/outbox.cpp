#include "rule_engine/python/effects/outbox.hpp"

#include <algorithm>
#include <limits>
#include <tuple>
#include <utility>

namespace rule_engine::python::effects {
    namespace {

        inline constexpr std::uint32_t maximum_delivery_attempts = 10;
        inline constexpr std::uint64_t base_retry_delay_ms = 1'000;
        inline constexpr std::uint64_t maximum_retry_delay_ms = 3'600'000;

        std::uint64_t saturating_add(const std::uint64_t left, const std::uint64_t right) noexcept {
            if (right > std::numeric_limits<std::uint64_t>::max() - left) {
                return std::numeric_limits<std::uint64_t>::max();
            }
            return left + right;
        }

        std::uint64_t stable_hash(const std::string_view value) noexcept {
            std::uint64_t hash = 1469598103934665603ULL;
            for (const auto character : value) {
                hash ^= static_cast<std::uint8_t>(character);
                hash *= 1099511628211ULL;
            }
            return hash;
        }

        bool transient_failure(const DeliveryFailure &failure) noexcept {
            if (failure.kind == DeliveryFailureKind::transport) {
                return true;
            }
            return failure.status_code == 408 || failure.status_code == 425 || failure.status_code == 429 ||
                   failure.status_code >= 500;
        }

        std::uint64_t retry_delay(const OutboxEntry &entry, const DeliveryFailure &failure) noexcept {
            if (failure.retry_after_ms.has_value()) {
                return std::min(*failure.retry_after_ms, maximum_retry_delay_ms);
            }
            const auto exponent = entry.attempts == 0 ? 0U : entry.attempts - 1U;
            const auto shift = std::min(exponent, 20U);
            const auto multiplier = std::uint64_t {1} << shift;
            const auto unclamped = base_retry_delay_ms > std::numeric_limits<std::uint64_t>::max() / multiplier ?
                                       std::numeric_limits<std::uint64_t>::max() :
                                       base_retry_delay_ms * multiplier;
            const auto ceiling = std::min(unclamped, maximum_retry_delay_ms);
            const auto seed =
                stable_domain_key("outbox-jitter-v1", {entry.record.idempotency_key, std::to_string(entry.attempts)});
            return stable_hash(seed) % (ceiling + 1U);
        }

        void clear_lease(OutboxEntry &entry) {
            entry.lease_owner.clear();
            entry.lease_expires_unix_ms = 0;
        }

        bool same_record(const OutboxEntry &entry, const EffectIntent &intent, const std::string_view destination,
                         const std::uint64_t committed_unix_ms, const std::uint64_t lifetime_ms) noexcept {
            return entry.record.intent == intent.id && entry.record.destination == destination &&
                   entry.record.idempotency_key == intent.idempotency_key &&
                   same_frozen_value(entry.record.payload, intent.payload) &&
                   entry.record.not_before_unix_ms == committed_unix_ms &&
                   entry.committed_unix_ms == committed_unix_ms &&
                   entry.expires_unix_ms == saturating_add(committed_unix_ms, lifetime_ms);
        }

        bool valid_snapshot_entry(const OutboxEntry &entry) noexcept {
            if (entry.record.intent.empty() || entry.record.destination.empty() ||
                entry.record.idempotency_key.empty() || !entry.record.payload.value.valid() ||
                entry.record.payload.canonical_digest.empty() || entry.committed_unix_ms == 0 ||
                entry.expires_unix_ms <= entry.committed_unix_ms || entry.attempts > maximum_delivery_attempts) {
                return false;
            }
            if (entry.state == OutboxState::leased) {
                return !entry.lease_owner.empty() && entry.lease_token != 0 && entry.lease_expires_unix_ms != 0 &&
                       entry.lease_expires_unix_ms <= entry.expires_unix_ms;
            }
            return entry.lease_owner.empty() && entry.lease_expires_unix_ms == 0;
        }

    } // namespace

    struct OutboxQueue::Implementation {
        std::vector<OutboxEntry> entries;

        [[nodiscard]] OutboxEntry *find(const IntentId &intent) noexcept {
            const auto found =
                std::ranges::find(entries, intent, [](const OutboxEntry &entry) { return entry.record.intent; });
            return found == entries.end() ? nullptr : &*found;
        }

        [[nodiscard]] const OutboxEntry *find(const IntentId &intent) const noexcept {
            const auto found =
                std::ranges::find(entries, intent, [](const OutboxEntry &entry) { return entry.record.intent; });
            return found == entries.end() ? nullptr : &*found;
        }

        [[nodiscard]] bool valid_lease(const OutboxEntry &entry, const OutboxLease &lease,
                                       const std::uint64_t now_unix_ms) const noexcept {
            return entry.state == OutboxState::leased && entry.record.intent == lease.intent &&
                   entry.lease_owner == lease.worker && entry.lease_token == lease.token &&
                   entry.attempts == lease.attempt && now_unix_ms < entry.lease_expires_unix_ms;
        }
    };

    std::expected<OutboxQueue, OutboxError> OutboxQueue::create() {
        return OutboxQueue {std::make_unique<Implementation>()};
    }

    std::expected<OutboxQueue, OutboxError> OutboxQueue::restore(std::vector<OutboxEntry> entries) {
        for (std::size_t index = 0; index < entries.size(); ++index) {
            if (!valid_snapshot_entry(entries[index])) {
                return std::unexpected(OutboxError {.code = OutboxErrorCode::invalid_snapshot,
                                                    .message = "the durable outbox snapshot contains an invalid row"});
            }
            for (std::size_t prior = 0; prior < index; ++prior) {
                if (entries[prior].record.intent == entries[index].record.intent ||
                    entries[prior].record.idempotency_key == entries[index].record.idempotency_key) {
                    return std::unexpected(OutboxError {
                        .code = OutboxErrorCode::invalid_snapshot,
                        .message = "the durable outbox snapshot contains duplicate intent or idempotency keys",
                    });
                }
            }
        }
        for (auto &entry : entries) {
            const auto claimable = entry.state == OutboxState::pending || entry.state == OutboxState::retry_wait;
            if (claimable && entry.attempts >= maximum_delivery_attempts) {
                entry.state = OutboxState::dead_letter;
                entry.last_error = "restored delivery exhausted the permitted attempts";
            }
        }
        auto implementation = std::make_unique<Implementation>();
        implementation->entries = std::move(entries);
        return OutboxQueue {std::move(implementation)};
    }

    OutboxQueue::OutboxQueue(std::unique_ptr<Implementation> implementation) noexcept:
        implementation_ {std::move(implementation)} {}

    OutboxQueue::OutboxQueue(OutboxQueue &&other) noexcept = default;
    OutboxQueue &OutboxQueue::operator=(OutboxQueue &&other) noexcept = default;
    OutboxQueue::~OutboxQueue() = default;

    std::expected<EnqueueResult, OutboxError> OutboxQueue::enqueue(const FinalizedJournal &journal,
                                                                   const IntentId &intent_id, std::string destination,
                                                                   const std::uint64_t committed_unix_ms,
                                                                   const std::uint64_t lifetime_ms) {
        if (journal.mode == ExecutionMode::replay) {
            return std::unexpected(OutboxError {.code = OutboxErrorCode::replay_forbidden,
                                                .message = "diagnostic replay cannot create an outbox row"});
        }
        if (!journal.durable_commit_allowed()) {
            return std::unexpected(OutboxError {.code = OutboxErrorCode::intent_not_committed,
                                                .message = "the journal is not eligible for durable commit"});
        }
        const auto found_intent = std::ranges::find(journal.intents, intent_id, &EffectIntent::id);
        if (found_intent == journal.intents.end()) {
            return std::unexpected(
                OutboxError {.code = OutboxErrorCode::unknown_intent,
                             .message = "the outbox intent does not belong to the finalized journal"});
        }
        const auto &intent = *found_intent;
        if (intent.disposition != EffectDisposition::committed || intent.kind != "post") {
            return std::unexpected(OutboxError {.code = OutboxErrorCode::intent_not_committed,
                                                .message = "only a committed post intent can enter the outbox"});
        }
        if (intent.id.empty() || destination.empty() || intent.idempotency_key.empty() ||
            !intent.payload.value.valid() || intent.payload.canonical_digest.empty() || committed_unix_ms == 0 ||
            lifetime_ms == 0) {
            return std::unexpected(
                OutboxError {.code = OutboxErrorCode::invalid_record,
                             .message = "the outbox record identity, payload, and lifetime are required"});
        }

        const auto duplicate_key =
            std::ranges::find(implementation_->entries, intent.idempotency_key,
                              [](const OutboxEntry &entry) { return entry.record.idempotency_key; });
        if (duplicate_key != implementation_->entries.end()) {
            if (!same_record(*duplicate_key, intent, destination, committed_unix_ms, lifetime_ms)) {
                return std::unexpected(OutboxError {
                    .code = OutboxErrorCode::duplicate_idempotency_mismatch,
                    .message = "an idempotency key was reused for a different destination, intent, or payload",
                });
            }
            return EnqueueResult {.intent = duplicate_key->record.intent, .inserted = false};
        }
        const auto duplicate_intent = implementation_->find(intent.id);
        if (duplicate_intent != nullptr) {
            return std::unexpected(OutboxError {.code = OutboxErrorCode::duplicate_intent_mismatch,
                                                .message = "an intent ID was reused with a different idempotency key"});
        }

        implementation_->entries.push_back(OutboxEntry {
            .record = {.intent = intent.id,
                       .destination = std::move(destination),
                       .payload = intent.payload,
                       .idempotency_key = intent.idempotency_key,
                       .not_before_unix_ms = committed_unix_ms},
            .state = OutboxState::pending,
            .committed_unix_ms = committed_unix_ms,
            .expires_unix_ms = saturating_add(committed_unix_ms, lifetime_ms),
            .next_attempt_unix_ms = committed_unix_ms,
            .attempts = 0,
            .lease_token = 0,
            .lease_owner = {},
            .lease_expires_unix_ms = 0,
            .last_error = {},
            .acknowledgment = std::nullopt,
        });
        return EnqueueResult {.intent = intent.id, .inserted = true};
    }

    std::expected<OutboxLease, OutboxError> OutboxQueue::claim(std::string worker, const std::uint64_t now_unix_ms,
                                                               const std::uint64_t lease_duration_ms) {
        if (worker.empty() || lease_duration_ms == 0) {
            return std::unexpected(OutboxError {.code = OutboxErrorCode::invalid_record,
                                                .message = "an outbox claim requires a worker and lease duration"});
        }
        release_expired_leases(now_unix_ms);
        expire_due(now_unix_ms);

        OutboxEntry *selected {};
        for (auto &entry : implementation_->entries) {
            const auto claimable_state = entry.state == OutboxState::pending || entry.state == OutboxState::retry_wait;
            if (claimable_state && entry.attempts >= maximum_delivery_attempts) {
                entry.state = OutboxState::dead_letter;
                entry.last_error = "delivery exhausted the permitted attempts before claim";
                continue;
            }
            if (!claimable_state || entry.next_attempt_unix_ms > now_unix_ms || entry.expires_unix_ms <= now_unix_ms) {
                continue;
            }
            if (selected == nullptr ||
                std::tie(entry.next_attempt_unix_ms, entry.committed_unix_ms, entry.record.intent.value) <
                    std::tie(selected->next_attempt_unix_ms, selected->committed_unix_ms,
                             selected->record.intent.value)) {
                selected = &entry;
            }
        }
        if (selected == nullptr) {
            return std::unexpected(OutboxError {.code = OutboxErrorCode::no_claimable_record,
                                                .message = "the outbox has no due claimable record"});
        }
        if (selected->lease_token == std::numeric_limits<std::uint64_t>::max()) {
            return std::unexpected(OutboxError {.code = OutboxErrorCode::invalid_state,
                                                .message = "the durable outbox lease token is exhausted"});
        }

        selected->state = OutboxState::leased;
        selected->lease_owner = std::move(worker);
        selected->lease_expires_unix_ms =
            std::min(saturating_add(now_unix_ms, lease_duration_ms), selected->expires_unix_ms);
        ++selected->lease_token;
        ++selected->attempts;
        return OutboxLease {
            .intent = selected->record.intent,
            .worker = selected->lease_owner,
            .token = selected->lease_token,
            .attempt = selected->attempts,
            .record = selected->record,
            .expires_unix_ms = selected->lease_expires_unix_ms,
        };
    }

    std::expected<ActionDeliveryRecord, OutboxError>
    OutboxQueue::acknowledge(const OutboxLease &lease, const std::uint64_t now_unix_ms,
                             std::optional<FrozenValue> acknowledgment) {
        auto *entry = implementation_->find(lease.intent);
        if (entry == nullptr) {
            return std::unexpected(OutboxError {.code = OutboxErrorCode::unknown_intent,
                                                .message = "the acknowledged outbox intent does not exist"});
        }
        if (!implementation_->valid_lease(*entry, lease, now_unix_ms)) {
            return std::unexpected(OutboxError {.code = OutboxErrorCode::stale_lease,
                                                .message = "a stale or mismatched lease cannot acknowledge delivery"});
        }
        if (acknowledgment.has_value() &&
            (!acknowledgment->value.valid() || acknowledgment->canonical_digest.empty())) {
            return std::unexpected(
                OutboxError {.code = OutboxErrorCode::invalid_record,
                             .message = "an action acknowledgment must be a validated frozen value"});
        }

        entry->state = OutboxState::delivered;
        entry->acknowledgment = std::move(acknowledgment);
        entry->last_error.clear();
        clear_lease(*entry);
        return ActionDeliveryRecord {.intent = entry->record.intent,
                                     .state = entry->state,
                                     .attempts = entry->attempts,
                                     .acknowledgment = entry->acknowledgment,
                                     .summary = "delivered"};
    }

    std::expected<ActionDeliveryRecord, OutboxError>
    OutboxQueue::fail(const OutboxLease &lease, const DeliveryFailure &failure, const std::uint64_t now_unix_ms) {
        auto *entry = implementation_->find(lease.intent);
        if (entry == nullptr) {
            return std::unexpected(OutboxError {.code = OutboxErrorCode::unknown_intent,
                                                .message = "the failed outbox intent does not exist"});
        }
        if (!implementation_->valid_lease(*entry, lease, now_unix_ms)) {
            return std::unexpected(OutboxError {.code = OutboxErrorCode::stale_lease,
                                                .message = "a stale or mismatched lease cannot fail delivery"});
        }
        const auto valid_failure =
            !failure.summary.empty() && ((failure.kind == DeliveryFailureKind::transport && failure.status_code == 0) ||
                                         (failure.kind == DeliveryFailureKind::http_status &&
                                          failure.status_code >= 100 && failure.status_code <= 599));
        if (!valid_failure) {
            return std::unexpected(
                OutboxError {.code = OutboxErrorCode::invalid_record,
                             .message = "a delivery failure requires a valid kind, status, and summary"});
        }

        entry->last_error = failure.summary;
        clear_lease(*entry);
        if (now_unix_ms >= entry->expires_unix_ms) {
            entry->state = OutboxState::expired;
        } else if (!transient_failure(failure) || entry->attempts >= maximum_delivery_attempts) {
            entry->state = OutboxState::dead_letter;
        } else {
            const auto next_attempt = saturating_add(now_unix_ms, retry_delay(*entry, failure));
            if (next_attempt >= entry->expires_unix_ms) {
                entry->state = OutboxState::dead_letter;
                entry->last_error = "retry window exhausted: " + failure.summary;
            } else {
                entry->state = OutboxState::retry_wait;
                entry->next_attempt_unix_ms = next_attempt;
            }
        }

        return ActionDeliveryRecord {.intent = entry->record.intent,
                                     .state = entry->state,
                                     .attempts = entry->attempts,
                                     .acknowledgment = std::nullopt,
                                     .summary = entry->last_error};
    }

    void OutboxQueue::release_expired_leases(const std::uint64_t now_unix_ms) {
        for (auto &entry : implementation_->entries) {
            if (entry.state != OutboxState::leased || entry.lease_expires_unix_ms > now_unix_ms) {
                continue;
            }
            clear_lease(entry);
            if (entry.expires_unix_ms <= now_unix_ms) {
                entry.state = OutboxState::expired;
                entry.last_error = "delivery lifetime expired while leased";
            } else if (entry.attempts >= maximum_delivery_attempts) {
                entry.state = OutboxState::dead_letter;
                entry.last_error = "delivery lease expired after the final permitted attempt";
            } else {
                entry.state = OutboxState::retry_wait;
                entry.next_attempt_unix_ms = now_unix_ms;
                entry.last_error = "delivery lease expired before acknowledgment";
            }
        }
    }

    void OutboxQueue::expire_due(const std::uint64_t now_unix_ms) {
        for (auto &entry : implementation_->entries) {
            const auto pending = entry.state == OutboxState::pending || entry.state == OutboxState::retry_wait;
            if (pending && entry.expires_unix_ms <= now_unix_ms) {
                entry.state = OutboxState::expired;
                entry.last_error = "delivery lifetime expired";
            }
        }
    }

    std::vector<OutboxEntry> OutboxQueue::snapshot() const {
        auto result = implementation_->entries;
        std::ranges::sort(result, [](const OutboxEntry &left, const OutboxEntry &right) {
            return std::tie(left.committed_unix_ms, left.record.intent.value) <
                   std::tie(right.committed_unix_ms, right.record.intent.value);
        });
        return result;
    }

    std::optional<OutboxEntry> OutboxQueue::find(const IntentId &intent) const {
        const auto *entry = implementation_->find(intent);
        return entry == nullptr ? std::nullopt : std::optional<OutboxEntry> {*entry};
    }

    std::size_t OutboxQueue::size() const noexcept { return implementation_->entries.size(); }

    std::expected<ActionDeliveryRecord, OutboxError>
    OutboxDispatcher::dispatch_one(IOutboxDeliveryStore &store, IActionTransport &transport,
                                   const OutboxDispatcherConfig &config, const std::uint64_t now_unix_ms) {
        if (config.mode == ExecutionMode::replay) {
            return std::unexpected(OutboxError {.code = OutboxErrorCode::replay_forbidden,
                                                .message = "diagnostic replay cannot claim or dispatch outbox work"});
        }
        if (config.worker.empty() || config.lease_duration_ms == 0) {
            return std::unexpected(
                OutboxError {.code = OutboxErrorCode::invalid_record,
                             .message = "an outbox dispatcher requires a worker and lease duration"});
        }
        auto lease = store.claim(config.worker, now_unix_ms, config.lease_duration_ms);
        if (!lease.has_value()) {
            return std::unexpected(lease.error());
        }
        auto delivered = transport.dispatch(*lease);
        if (delivered.has_value()) {
            if (delivered->completed_unix_ms < now_unix_ms) {
                return store.fail(
                    *lease,
                    DeliveryFailure {.kind = DeliveryFailureKind::transport,
                                     .status_code = 0,
                                     .retry_after_ms = std::nullopt,
                                     .summary = "transport returned a completion timestamp before dispatch"},
                    now_unix_ms);
            }
            return store.acknowledge(*lease, delivered->completed_unix_ms, std::move(delivered->acknowledgment));
        }
        if (delivered.error().completed_unix_ms < now_unix_ms) {
            return store.fail(*lease,
                              DeliveryFailure {.kind = DeliveryFailureKind::transport,
                                               .status_code = 0,
                                               .retry_after_ms = std::nullopt,
                                               .summary = "transport returned a failure timestamp before dispatch"},
                              now_unix_ms);
        }
        return store.fail(*lease, delivered.error().failure, delivered.error().completed_unix_ms);
    }

} // namespace rule_engine::python::effects
