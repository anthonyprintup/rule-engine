#pragma once

#include "rule_engine/python/cluster/audit.hpp"
#include "rule_engine/python/cluster/store.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace rule_engine::python::cluster {

    struct FencedLeaseManager {
        explicit FencedLeaseManager(AuditTrail &audit): audit_ {audit} {}

        [[nodiscard]] std::expected<FencedLease, StoreError> claim(const LeaseResource &resource,
                                                                   std::string_view owner, std::uint64_t now_unix_ms,
                                                                   std::uint64_t lease_duration_ms);
        [[nodiscard]] std::expected<FencedLease, StoreError> renew(const FencedLease &lease, std::uint64_t now_unix_ms,
                                                                   std::uint64_t lease_duration_ms);
        [[nodiscard]] std::expected<void, StoreError> release(const FencedLease &lease, std::uint64_t now_unix_ms);
        [[nodiscard]] bool is_current(const FencedLease &lease, std::uint64_t now_unix_ms) const;
        [[nodiscard]] std::vector<LeaseSnapshot> snapshot(std::uint64_t now_unix_ms) const;

    private:
        struct LeaseRecord {
            std::string owner;
            std::uint64_t fence {};
            std::uint64_t lease_until_unix_ms {};
            bool held {};
        };

        AuditTrail &audit_;
        mutable std::mutex mutex_;
        std::map<LeaseResource, LeaseRecord> leases_;
    };

    enum struct WorkPhase : std::uint8_t { ready, leased, completed };

    struct WorkDefinition {
        std::string work_id;
        PackId pack;
        std::uint64_t generation {};
        std::string serial_domain;
        EventId event;
        std::int32_t priority {};
        std::uint64_t ingest_position {};
    };

    struct WorkLease {
        WorkDefinition work;
        std::string node_id;
        std::uint64_t attempt {};
        std::uint64_t fence {};
        std::uint64_t lease_until_unix_ms {};
    };

    struct WorkSnapshot {
        WorkDefinition work;
        WorkPhase phase {WorkPhase::ready};
        std::string node_id;
        std::uint64_t attempt {};
        std::uint64_t fence {};
        std::uint64_t lease_until_unix_ms {};
    };

    struct DeterministicWorkCoordinator {
        DeterministicWorkCoordinator(IClusterRuntimeStore &store, AuditTrail &audit): store_ {store}, audit_ {audit} {}

        [[nodiscard]] std::expected<bool, StoreError> enqueue(const WorkDefinition &work);
        [[nodiscard]] std::expected<std::vector<WorkLease>, StoreError>
        claim(std::string_view node_id, std::uint64_t now_unix_ms, std::uint64_t lease_duration_ms, std::size_t limit);
        [[nodiscard]] std::expected<TransactionReceipt, StoreError>
        commit(const WorkLease &lease, RuntimeTransaction transaction, std::uint64_t now_unix_ms);
        [[nodiscard]] std::expected<void, StoreError> abandon(const WorkLease &lease, std::uint64_t now_unix_ms);

        [[nodiscard]] std::expected<std::optional<TransactionReceipt>, StoreError>
        recover_receipt(const EventId &input) const;
        [[nodiscard]] std::vector<WorkSnapshot> snapshot() const;
        [[nodiscard]] std::expected<std::vector<LeaseSnapshot>, StoreError>
        lease_snapshot(std::uint64_t now_unix_ms) const {
            return store_.inspect_leases(now_unix_ms);
        }

    private:
        [[nodiscard]] static bool definition_matches(const WorkDefinition &left, const WorkDefinition &right);

        IClusterRuntimeStore &store_;
        AuditTrail &audit_;
        mutable std::mutex mutex_;
        std::map<std::string, WorkSnapshot, std::less<>> work_;
    };

} // namespace rule_engine::python::cluster
