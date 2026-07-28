#pragma once

#include "rule_engine/python/cluster/audit.hpp"
#include "rule_engine/python/contract/distributed.hpp"

#include <cstdint>
#include <expected>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace rule_engine::python::cluster {

    enum struct GenerationPhase : std::uint8_t { compiling, ready, draining, active, retired, failed };
    enum struct StateTransitionMode : std::uint8_t { carry, migrate, reset, retained_gap };

    struct StateTransitionPlan {
        StateTransitionMode mode {StateTransitionMode::carry};
        std::string source_namespace;
        std::string target_namespace;
        std::string migration_id;
        bool reset_authorized {};
        bool accept_state_gap {};
    };

    struct ClusterNode {
        std::string node_id;
        std::string platform_abi;
        std::uint64_t lease_fence {};
        bool healthy {};
        bool serving {};
    };

    struct GenerationRequest {
        PackId pack;
        PackVersion version;
        SourceDigest source_digest;
        std::uint64_t generation {};
        std::string state_schema_hash;
        std::string state_namespace;
        std::vector<std::string> required_capability_hashes;
        StateTransitionPlan state_transition;
        std::optional<std::uint64_t> rollback_from;
        bool signature_verified {};
    };

    struct CompilationReport {
        std::string node_id;
        std::uint64_t node_lease_fence {};
        bool success {};
        std::string semantic_hash;
        std::string binding_hash;
        std::string executable_hash;
        std::vector<std::string> capability_hashes;
        DiagnosticSet diagnostics;
    };

    struct GenerationSnapshot {
        GenerationRequest request;
        GenerationPhase phase {GenerationPhase::compiling};
        std::vector<std::string> target_nodes;
        std::vector<CompilationReport> reports;
        std::string semantic_hash;
        std::string binding_hash;
        std::vector<std::string> requeued_work;
        std::string failure;
    };

    struct ActiveGenerationSnapshot {
        PackId pack;
        std::optional<std::uint64_t> generation;
        std::uint64_t assignment_fence {};
        bool accepting_assignments {};
        std::optional<std::uint64_t> drain_boundary;
        std::optional<std::uint64_t> drain_target;
        std::vector<std::string> in_flight_work;
    };

    struct NodeSnapshot {
        ClusterNode node;
        std::vector<std::pair<PackId, std::uint64_t>> compiled_active_generations;
    };

    struct DrainReceipt {
        PackId pack;
        std::optional<std::uint64_t> old_generation;
        std::uint64_t target_generation {};
        std::uint64_t drain_boundary {};
        std::uint64_t successor_assignment_fence {};
        std::vector<std::string> in_flight_work;
    };

    struct ActivationReceipt {
        PackId pack;
        std::optional<std::uint64_t> retired_generation;
        std::uint64_t active_generation {};
        std::uint64_t activation_cursor {};
        std::uint64_t assignment_fence {};
        std::vector<std::string> requeued_work;
    };

    // Fail-closed startup check for the exact executable a node intends to
    // serve. The caller separately proves a current node lease; the report
    // fence here is historical staging evidence and intentionally need not
    // equal a lease acquired after restart.
    [[nodiscard]] std::expected<void, StoreError> qualify_resident_compilation(const GenerationSnapshot &generation,
                                                                               std::string_view node_id,
                                                                               std::string_view platform_abi,
                                                                               const CompiledPack &compiled);

    struct ActivationController {
        explicit ActivationController(AuditTrail &audit): audit_ {audit} {}

        [[nodiscard]] std::expected<void, StoreError> register_node(const ClusterNode &node, std::uint64_t now_unix_ms,
                                                                    std::string_view actor);
        [[nodiscard]] std::expected<GenerationSnapshot, StoreError>
        begin_stage(const GenerationRequest &request, std::uint64_t now_unix_ms, std::string_view actor);
        [[nodiscard]] std::expected<void, StoreError> report_compilation(const PackId &pack, std::uint64_t generation,
                                                                         const CompilationReport &report,
                                                                         std::uint64_t now_unix_ms);
        [[nodiscard]] std::expected<GenerationSnapshot, StoreError>
        finalize_stage(const PackId &pack, std::uint64_t generation, std::uint64_t now_unix_ms, std::string_view actor);

        [[nodiscard]] std::expected<DrainReceipt, StoreError>
        begin_drain(const PackId &pack, std::uint64_t target_generation, std::uint64_t drain_boundary,
                    std::uint64_t now_unix_ms, std::string_view actor);
        [[nodiscard]] std::expected<void, StoreError> register_assignment(const PackId &pack, std::uint64_t generation,
                                                                          std::string_view work_id,
                                                                          std::uint64_t assignment_fence);
        [[nodiscard]] std::expected<void, StoreError> finish_assignment(const PackId &pack, std::uint64_t generation,
                                                                        std::string_view work_id,
                                                                        std::uint64_t assignment_fence);
        [[nodiscard]] std::expected<std::vector<std::string>, StoreError>
        fence_stragglers(const PackId &pack, std::uint64_t target_generation, std::uint64_t now_unix_ms,
                         std::string_view actor);
        [[nodiscard]] std::expected<ActivationReceipt, StoreError>
        flip(const PackId &pack, std::uint64_t target_generation, std::uint64_t now_unix_ms, std::string_view actor);

        [[nodiscard]] std::expected<GenerationSnapshot, StoreError>
        begin_rollback_stage(const PackId &pack, std::uint64_t source_generation, std::uint64_t new_generation,
                             StateTransitionPlan state_transition, std::uint64_t now_unix_ms, std::string_view actor);

        [[nodiscard]] std::expected<void, StoreError>
        record_active_compilation(std::string_view node_id, std::uint64_t node_lease_fence, const PackId &pack,
                                  std::uint64_t generation, std::string_view semantic_hash,
                                  std::string_view binding_hash, std::uint64_t now_unix_ms);

        [[nodiscard]] bool assignment_allowed(const PackId &pack, std::uint64_t generation) const;
        [[nodiscard]] bool node_ready_for_pack(std::string_view node_id, const PackId &pack) const;
        [[nodiscard]] std::optional<GenerationSnapshot> generation_snapshot(const PackId &pack,
                                                                            std::uint64_t generation) const;
        [[nodiscard]] ActiveGenerationSnapshot active_snapshot(const PackId &pack) const;
        [[nodiscard]] std::vector<NodeSnapshot> node_snapshot() const;

    private:
        struct GenerationKey {
            PackId pack;
            std::uint64_t generation {};

            auto operator<=>(const GenerationKey &) const = default;
        };

        struct NodeRecord {
            ClusterNode node;
            std::map<PackId, std::uint64_t> compiled_active_generations;
        };

        struct PackControl {
            std::optional<std::uint64_t> active_generation;
            std::uint64_t assignment_fence {};
            bool accepting_assignments {};
            std::optional<std::uint64_t> drain_boundary;
            std::optional<std::uint64_t> drain_target;
            std::map<std::string, std::uint64_t, std::less<>> in_flight;
            std::vector<std::string> pending_requeues;
        };

        [[nodiscard]] static StoreError error(StoreErrorCode code, std::string message, bool retryable = false);
        [[nodiscard]] std::expected<void, StoreError>
        validate_state_transition_locked(const GenerationRequest &request, const PackControl &control) const;

        AuditTrail &audit_;
        mutable std::mutex mutex_;
        std::map<std::string, NodeRecord, std::less<>> nodes_;
        std::map<GenerationKey, GenerationSnapshot> generations_;
        std::map<PackId, PackControl> controls_;
    };

} // namespace rule_engine::python::cluster
