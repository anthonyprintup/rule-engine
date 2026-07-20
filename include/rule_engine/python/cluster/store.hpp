#pragma once

#include "rule_engine/python/cluster/audit.hpp"
#include "rule_engine/python/contract/distributed.hpp"

#include <cstdint>
#include <expected>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace rule_engine::python::cluster {

    struct StoredStateKey {
        ExecutableId owner;
        std::string namespace_name;
        std::string key;

        auto operator<=>(const StoredStateKey &) const = default;
    };

    struct StoredStateCell {
        StoredStateKey key;
        std::uint64_t version {};
        std::optional<FrozenValue> value;
    };

    struct StoredResult {
        EventId input;
        EvaluationResult evaluation;
    };

    enum struct StoredOutboxState : std::uint8_t { pending, leased, delivered, dead_letter };

    struct StoredOutboxRecord {
        OutboxRecord record;
        StoredOutboxState state {StoredOutboxState::pending};
        std::string owner;
        std::uint64_t fence {};
        std::uint64_t lease_until_unix_ms {};
        std::uint32_t attempts {};
        std::string terminal_detail;
    };

    struct OutboxLease {
        OutboxRecord record;
        std::string owner;
        std::uint64_t fence {};
        std::uint64_t lease_until_unix_ms {};
        std::uint32_t attempt {};
    };

    enum struct OutboxSettlementKind : std::uint8_t { delivered, retry, dead_letter };

    struct OutboxSettlement {
        IntentId intent;
        std::string owner;
        std::uint64_t fence {};
        std::uint64_t now_unix_ms {};
        OutboxSettlementKind kind {};
        std::uint64_t retry_not_before_unix_ms {};
        std::string detail;
    };

    struct RuntimeStoreSnapshot {
        std::vector<EventEnvelope> events;
        std::vector<std::pair<std::string, std::uint64_t>> cursors;
        std::vector<StoredStateCell> state;
        std::vector<StoredResult> results;
        std::vector<EffectIntent> journal;
        std::vector<StoredOutboxRecord> outbox;
        std::vector<TransactionReceipt> receipts;
    };

    struct InMemoryRuntimeStore final: IRuntimeStore {
        explicit InMemoryRuntimeStore(AuditTrail &audit): audit_ {audit} {}

        [[nodiscard]] std::expected<TransactionReceipt, StoreError>
        transact_event(const RuntimeTransaction &transaction) override;

        // Installs a monotonically increasing database-style fence for one
        // serial consumer domain. Equal values are idempotent; lower values are
        // rejected. The transaction's cursor.consumer selects this fence.
        [[nodiscard]] std::expected<void, StoreError> install_consumer_fence(std::string_view consumer,
                                                                             std::uint64_t fence);
        [[nodiscard]] std::uint64_t consumer_fence(std::string_view consumer) const;

        [[nodiscard]] std::optional<TransactionReceipt> lookup_receipt(const EventId &input) const;
        [[nodiscard]] std::optional<StoredStateCell> read_state(const StoredStateKey &key) const;

        [[nodiscard]] std::expected<std::vector<OutboxLease>, StoreError> claim_outbox(std::string_view owner,
                                                                                       std::uint64_t now_unix_ms,
                                                                                       std::uint64_t lease_duration_ms,
                                                                                       std::size_t limit);
        [[nodiscard]] std::expected<void, StoreError> settle_outbox(const OutboxSettlement &settlement);

        // Deterministic failure injection used to prove that validation and
        // publication form one logical transaction.
        void fail_next_commit(StoreError error);

        [[nodiscard]] RuntimeStoreSnapshot snapshot() const;

    private:
        struct ReceiptEntry {
            std::string transaction_signature;
            TransactionReceipt receipt;
        };

        [[nodiscard]] static std::string transaction_signature(const RuntimeTransaction &transaction);
        [[nodiscard]] std::expected<void, StoreError> validate_transaction_locked(const RuntimeTransaction &transaction,
                                                                                  std::string_view signature) const;

        AuditTrail &audit_;
        mutable std::mutex mutex_;
        std::map<std::string, EventEnvelope, std::less<>> events_;
        std::map<std::string, std::uint64_t, std::less<>> cursors_;
        std::map<StoredStateKey, StoredStateCell> state_;
        std::map<std::string, StoredResult, std::less<>> results_;
        std::map<std::string, EffectIntent, std::less<>> journal_;
        std::map<std::string, StoredOutboxRecord, std::less<>> outbox_;
        std::map<std::string, ReceiptEntry, std::less<>> receipts_;
        std::map<std::string, std::uint64_t, std::less<>> consumer_fences_;
        std::optional<StoreError> fail_next_commit_;
    };

} // namespace rule_engine::python::cluster
