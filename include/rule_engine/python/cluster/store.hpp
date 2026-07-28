#pragma once

#include "rule_engine/python/cluster/audit.hpp"
#include "rule_engine/python/cluster/configuration.hpp"
#include "rule_engine/python/contract/distributed.hpp"

#include <chrono>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
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

    struct LeaseResource {
        std::string scope;
        std::string key;

        auto operator<=>(const LeaseResource &) const = default;
    };

    struct FencedLease {
        LeaseResource resource;
        std::string owner;
        std::uint64_t fence {};
        std::uint64_t lease_until_unix_ms {};
    };

    struct LeaseSnapshot {
        LeaseResource resource;
        std::string owner;
        std::uint64_t fence {};
        std::uint64_t lease_until_unix_ms {};
        bool held {};
    };

    struct AgentStreamId {
        TenantId tenant;
        PeerId peer;
        std::string agent_epoch;

        auto operator<=>(const AgentStreamId &) const = default;
    };

    struct AgentMessageCommit {
        AgentStreamId stream;
        SessionId session;
        std::uint64_t session_fence {};
        std::uint64_t sequence {};
        std::uint64_t received_at_unix_ms {};
        std::uint8_t body_kind {};
        std::vector<std::byte> body;
    };

    struct AgentMessageReceipt {
        std::uint64_t acknowledged_through {};
        bool duplicate {};
    };

    struct StoredAgentMessage {
        AgentMessageCommit commit;
    };

    struct RuntimeStoreSnapshot {
        std::vector<EventEnvelope> events;
        std::vector<std::pair<std::string, std::uint64_t>> cursors;
        std::vector<StoredStateCell> state;
        std::vector<StoredResult> results;
        std::vector<EffectIntent> journal;
        std::vector<StoredOutboxRecord> outbox;
        std::vector<TransactionReceipt> receipts;
        std::vector<StoredAgentMessage> agent_messages;
    };

    struct RuntimeStoreHealth {
        StoreBackendKind backend {StoreBackendKind::in_memory_reference};
        bool driver_available {};
        bool connected {};
        bool migrations_compatible {};
        std::uint32_t schema_version {};
        std::string server_version;
        std::string detail;
    };

    struct HistoryQuery {
        TenantId tenant;
        PeerId peer;
        SchemaId schema;
        std::uint64_t begin_ingest_unix_ms {};
        std::uint64_t end_ingest_unix_ms {};
        std::size_t limit {};
    };

    struct IClusterRuntimeStore: IRuntimeStore {
        [[nodiscard]] virtual std::expected<void, StoreError> install_consumer_fence(std::string_view consumer,
                                                                                     std::uint64_t fence) = 0;
        [[nodiscard]] virtual std::expected<std::uint64_t, StoreError>
        load_consumer_fence(std::string_view consumer) const = 0;
        [[nodiscard]] virtual std::expected<std::uint64_t, StoreError>
        load_agent_receipt(const AgentStreamId &stream) const = 0;
        [[nodiscard]] virtual std::expected<AgentMessageReceipt, StoreError>
        transact_agent_message(const AgentMessageCommit &message) = 0;
        [[nodiscard]] virtual std::expected<std::optional<TransactionReceipt>, StoreError>
        load_receipt(const EventId &input) const = 0;
        [[nodiscard]] virtual std::expected<std::optional<StoredStateCell>, StoreError>
        load_state(const StoredStateKey &key) const = 0;
        [[nodiscard]] virtual std::expected<std::vector<EventEnvelope>, StoreError>
        read_history(const HistoryQuery &query) const = 0;

        [[nodiscard]] virtual std::expected<std::vector<OutboxLease>, StoreError>
        claim_outbox(std::string_view owner, std::uint64_t now_unix_ms, std::uint64_t lease_duration_ms,
                     std::size_t limit) = 0;
        [[nodiscard]] virtual std::expected<void, StoreError> settle_outbox(const OutboxSettlement &settlement) = 0;

        [[nodiscard]] virtual std::expected<FencedLease, StoreError> claim_lease(const LeaseResource &resource,
                                                                                 std::string_view owner,
                                                                                 std::uint64_t now_unix_ms,
                                                                                 std::uint64_t lease_duration_ms) = 0;
        [[nodiscard]] virtual std::expected<FencedLease, StoreError>
        renew_lease(const FencedLease &lease, std::uint64_t now_unix_ms, std::uint64_t lease_duration_ms) = 0;
        [[nodiscard]] virtual std::expected<void, StoreError> release_lease(const FencedLease &lease,
                                                                            std::uint64_t now_unix_ms) = 0;
        [[nodiscard]] virtual std::expected<bool, StoreError> lease_is_current(const FencedLease &lease,
                                                                               std::uint64_t now_unix_ms) const = 0;
        [[nodiscard]] virtual std::expected<std::vector<LeaseSnapshot>, StoreError>
        inspect_leases(std::uint64_t now_unix_ms) const = 0;

        [[nodiscard]] virtual std::expected<RuntimeStoreSnapshot, StoreError> inspect() const = 0;
        [[nodiscard]] virtual RuntimeStoreHealth health() const = 0;
    };

    struct InMemoryRuntimeStore final: IClusterRuntimeStore {
        explicit InMemoryRuntimeStore(AuditTrail &audit): audit_ {audit} {}

        [[nodiscard]] std::expected<TransactionReceipt, StoreError>
        transact_event(const RuntimeTransaction &transaction) override;

        // Installs a monotonically increasing database-style fence for one
        // serial consumer domain. Equal values are idempotent; lower values are
        // rejected. The transaction's cursor.consumer selects this fence.
        [[nodiscard]] std::expected<void, StoreError> install_consumer_fence(std::string_view consumer,
                                                                             std::uint64_t fence) override;
        [[nodiscard]] std::expected<std::uint64_t, StoreError>
        load_consumer_fence(std::string_view consumer) const override;
        [[nodiscard]] std::expected<std::uint64_t, StoreError>
        load_agent_receipt(const AgentStreamId &stream) const override;
        [[nodiscard]] std::expected<AgentMessageReceipt, StoreError>
        transact_agent_message(const AgentMessageCommit &message) override;
        [[nodiscard]] std::uint64_t consumer_fence(std::string_view consumer) const;

        [[nodiscard]] std::expected<std::optional<TransactionReceipt>, StoreError>
        load_receipt(const EventId &input) const override;
        [[nodiscard]] std::expected<std::optional<StoredStateCell>, StoreError>
        load_state(const StoredStateKey &key) const override;
        [[nodiscard]] std::optional<TransactionReceipt> lookup_receipt(const EventId &input) const;
        [[nodiscard]] std::optional<StoredStateCell> read_state(const StoredStateKey &key) const;
        [[nodiscard]] std::expected<std::vector<EventEnvelope>, StoreError>
        read_history(const HistoryQuery &query) const override;

        [[nodiscard]] std::expected<std::vector<OutboxLease>, StoreError> claim_outbox(std::string_view owner,
                                                                                       std::uint64_t now_unix_ms,
                                                                                       std::uint64_t lease_duration_ms,
                                                                                       std::size_t limit) override;
        [[nodiscard]] std::expected<void, StoreError> settle_outbox(const OutboxSettlement &settlement) override;

        [[nodiscard]] std::expected<FencedLease, StoreError> claim_lease(const LeaseResource &resource,
                                                                         std::string_view owner,
                                                                         std::uint64_t now_unix_ms,
                                                                         std::uint64_t lease_duration_ms) override;
        [[nodiscard]] std::expected<FencedLease, StoreError>
        renew_lease(const FencedLease &lease, std::uint64_t now_unix_ms, std::uint64_t lease_duration_ms) override;
        [[nodiscard]] std::expected<void, StoreError> release_lease(const FencedLease &lease,
                                                                    std::uint64_t now_unix_ms) override;
        [[nodiscard]] std::expected<bool, StoreError> lease_is_current(const FencedLease &lease,
                                                                       std::uint64_t now_unix_ms) const override;
        [[nodiscard]] std::expected<std::vector<LeaseSnapshot>, StoreError>
        inspect_leases(std::uint64_t now_unix_ms) const override;

        // Deterministic failure injection used to prove that validation and
        // publication form one logical transaction.
        void fail_next_commit(StoreError error);

        [[nodiscard]] std::expected<RuntimeStoreSnapshot, StoreError> inspect() const override;
        [[nodiscard]] RuntimeStoreSnapshot snapshot() const;
        [[nodiscard]] RuntimeStoreHealth health() const override;

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
        std::map<AgentStreamId, std::uint64_t> agent_receipts_;
        std::map<std::pair<AgentStreamId, std::uint64_t>, StoredAgentMessage> agent_messages_;
        struct LeaseRecord {
            std::string owner;
            std::uint64_t fence {};
            std::uint64_t lease_until_unix_ms {};
            bool held {};
        };
        std::map<LeaseResource, LeaseRecord> leases_;
        std::optional<StoreError> fail_next_commit_;
    };

    struct SqliteRuntimeStore final: IClusterRuntimeStore {
        [[nodiscard]] static std::expected<std::unique_ptr<SqliteRuntimeStore>, StoreError>
        open(const SqliteDevConfig &config, AuditTrail &audit);
        ~SqliteRuntimeStore() override;

        SqliteRuntimeStore(const SqliteRuntimeStore &) = delete;
        SqliteRuntimeStore &operator=(const SqliteRuntimeStore &) = delete;

        [[nodiscard]] std::expected<TransactionReceipt, StoreError>
        transact_event(const RuntimeTransaction &transaction) override;
        [[nodiscard]] std::expected<void, StoreError> install_consumer_fence(std::string_view consumer,
                                                                             std::uint64_t fence) override;
        [[nodiscard]] std::expected<std::uint64_t, StoreError>
        load_consumer_fence(std::string_view consumer) const override;
        [[nodiscard]] std::expected<std::uint64_t, StoreError>
        load_agent_receipt(const AgentStreamId &stream) const override;
        [[nodiscard]] std::expected<AgentMessageReceipt, StoreError>
        transact_agent_message(const AgentMessageCommit &message) override;
        [[nodiscard]] std::expected<std::optional<TransactionReceipt>, StoreError>
        load_receipt(const EventId &input) const override;
        [[nodiscard]] std::expected<std::optional<StoredStateCell>, StoreError>
        load_state(const StoredStateKey &key) const override;
        [[nodiscard]] std::expected<std::vector<EventEnvelope>, StoreError>
        read_history(const HistoryQuery &query) const override;
        [[nodiscard]] std::expected<std::vector<OutboxLease>, StoreError> claim_outbox(std::string_view owner,
                                                                                       std::uint64_t now_unix_ms,
                                                                                       std::uint64_t lease_duration_ms,
                                                                                       std::size_t limit) override;
        [[nodiscard]] std::expected<void, StoreError> settle_outbox(const OutboxSettlement &settlement) override;
        [[nodiscard]] std::expected<FencedLease, StoreError> claim_lease(const LeaseResource &resource,
                                                                         std::string_view owner,
                                                                         std::uint64_t now_unix_ms,
                                                                         std::uint64_t lease_duration_ms) override;
        [[nodiscard]] std::expected<FencedLease, StoreError>
        renew_lease(const FencedLease &lease, std::uint64_t now_unix_ms, std::uint64_t lease_duration_ms) override;
        [[nodiscard]] std::expected<void, StoreError> release_lease(const FencedLease &lease,
                                                                    std::uint64_t now_unix_ms) override;
        [[nodiscard]] std::expected<bool, StoreError> lease_is_current(const FencedLease &lease,
                                                                       std::uint64_t now_unix_ms) const override;
        [[nodiscard]] std::expected<std::vector<LeaseSnapshot>, StoreError>
        inspect_leases(std::uint64_t now_unix_ms) const override;
        [[nodiscard]] std::expected<RuntimeStoreSnapshot, StoreError> inspect() const override;
        [[nodiscard]] RuntimeStoreHealth health() const override;

    private:
        struct Impl;
        explicit SqliteRuntimeStore(std::unique_ptr<Impl> impl);
        std::unique_ptr<Impl> impl_;
    };

    struct PostgreSqlRuntimeStore final: IClusterRuntimeStore {
        [[nodiscard]] static std::expected<std::unique_ptr<PostgreSqlRuntimeStore>, StoreError>
        open(const PostgreSql17Config &config, AuditTrail &audit);
        [[nodiscard]] static std::expected<std::unique_ptr<PostgreSqlRuntimeStore>, StoreError>
        open_resolved(const PostgreSql17Config &config, std::string_view connection_string, AuditTrail &audit);
        ~PostgreSqlRuntimeStore() override;

        PostgreSqlRuntimeStore(const PostgreSqlRuntimeStore &) = delete;
        PostgreSqlRuntimeStore &operator=(const PostgreSqlRuntimeStore &) = delete;

        [[nodiscard]] std::expected<TransactionReceipt, StoreError>
        transact_event(const RuntimeTransaction &transaction) override;
        [[nodiscard]] std::expected<void, StoreError> install_consumer_fence(std::string_view consumer,
                                                                             std::uint64_t fence) override;
        [[nodiscard]] std::expected<std::uint64_t, StoreError>
        load_consumer_fence(std::string_view consumer) const override;
        [[nodiscard]] std::expected<std::uint64_t, StoreError>
        load_agent_receipt(const AgentStreamId &stream) const override;
        [[nodiscard]] std::expected<AgentMessageReceipt, StoreError>
        transact_agent_message(const AgentMessageCommit &message) override;
        [[nodiscard]] std::expected<std::optional<TransactionReceipt>, StoreError>
        load_receipt(const EventId &input) const override;
        [[nodiscard]] std::expected<std::optional<StoredStateCell>, StoreError>
        load_state(const StoredStateKey &key) const override;
        [[nodiscard]] std::expected<std::vector<EventEnvelope>, StoreError>
        read_history(const HistoryQuery &query) const override;
        [[nodiscard]] std::expected<std::vector<OutboxLease>, StoreError> claim_outbox(std::string_view owner,
                                                                                       std::uint64_t now_unix_ms,
                                                                                       std::uint64_t lease_duration_ms,
                                                                                       std::size_t limit) override;
        [[nodiscard]] std::expected<void, StoreError> settle_outbox(const OutboxSettlement &settlement) override;
        [[nodiscard]] std::expected<FencedLease, StoreError> claim_lease(const LeaseResource &resource,
                                                                         std::string_view owner,
                                                                         std::uint64_t now_unix_ms,
                                                                         std::uint64_t lease_duration_ms) override;
        [[nodiscard]] std::expected<FencedLease, StoreError>
        renew_lease(const FencedLease &lease, std::uint64_t now_unix_ms, std::uint64_t lease_duration_ms) override;
        [[nodiscard]] std::expected<void, StoreError> release_lease(const FencedLease &lease,
                                                                    std::uint64_t now_unix_ms) override;
        [[nodiscard]] std::expected<bool, StoreError> lease_is_current(const FencedLease &lease,
                                                                       std::uint64_t now_unix_ms) const override;
        [[nodiscard]] std::expected<std::vector<LeaseSnapshot>, StoreError>
        inspect_leases(std::uint64_t now_unix_ms) const override;
        [[nodiscard]] std::expected<RuntimeStoreSnapshot, StoreError> inspect() const override;
        [[nodiscard]] RuntimeStoreHealth health() const override;

    private:
        struct Impl;
        explicit PostgreSqlRuntimeStore(std::unique_ptr<Impl> impl);
        std::unique_ptr<Impl> impl_;
    };

} // namespace rule_engine::python::cluster
