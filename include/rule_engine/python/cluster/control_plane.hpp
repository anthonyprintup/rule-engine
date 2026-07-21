#pragma once

#include "rule_engine/python/cluster/activation.hpp"
#include "rule_engine/python/cluster/configuration.hpp"
#include "rule_engine/python/cluster/store.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace rule_engine::python::cluster {

    enum struct AdminOperationKind : std::uint8_t { stage, activate, rollback };
    enum struct AdminOperationPhase : std::uint8_t { previewed, staged, draining, fenced, applied, failed };

    struct AdminMutationRequest {
        std::string operation_id;
        RequestId request_id;
        std::string idempotency_key;
        std::string actor;
        std::string reason;
        std::uint64_t expected_pack_version {};
        std::uint64_t at_unix_ms {};
    };

    struct AdminApplyRequest {
        std::string operation_id;
        std::string idempotency_key;
        std::uint64_t expected_pack_version {};
        std::uint64_t at_unix_ms {};
    };

    struct AdminOperationRecord {
        std::string operation_id;
        RequestId request_id;
        std::string idempotency_key;
        std::vector<std::byte> request_fingerprint;
        std::string actor;
        std::string reason;
        AdminOperationKind kind {AdminOperationKind::stage};
        AdminOperationPhase phase {AdminOperationPhase::previewed};
        PackId pack;
        std::uint64_t target_generation {};
        std::optional<std::uint64_t> rollback_source_generation;
        std::optional<std::uint64_t> previous_active_generation;
        StateTransitionPlan state_transition;
        std::uint64_t expected_pack_version {};
        std::uint64_t created_at_unix_ms {};
        std::uint64_t updated_at_unix_ms {};
        std::optional<std::uint64_t> drain_boundary;
        std::vector<std::string> requeued_work;
        std::optional<ActivationReceipt> result;
        std::string failure;
    };

    struct DurablePackControlSnapshot {
        PackId pack;
        std::uint64_t resource_version {};
        std::optional<std::uint64_t> active_generation;
        std::uint64_t assignment_fence {};
        bool accepting_assignments {};
        std::optional<std::uint64_t> drain_boundary;
        std::optional<std::uint64_t> drain_target;
        std::vector<std::string> pending_requeues;
    };

    struct DurableControlState {
        std::uint64_t storage_revision {};
        std::vector<GenerationSnapshot> generations;
        std::vector<DurablePackControlSnapshot> packs;
    };

    struct ControlPlaneInspection {
        DurableControlState state;
        std::vector<AdminOperationRecord> operations;
        std::vector<AuditRecord> audit;
    };

    struct ControlPlaneCommit {
        std::uint64_t expected_storage_revision {};
        DurableControlState state;
        AdminOperationRecord operation;
        AuditRecord audit;
    };

    struct IActivationControlStore {
        virtual ~IActivationControlStore() = default;

        [[nodiscard]] virtual std::expected<DurableControlState, StoreError> load_state() const = 0;
        [[nodiscard]] virtual std::expected<std::optional<AdminOperationRecord>, StoreError>
        find_operation(std::string_view operation_id) const = 0;
        [[nodiscard]] virtual std::expected<std::optional<AdminOperationRecord>, StoreError>
        find_operation_by_idempotency(std::string_view idempotency_key) const = 0;
        [[nodiscard]] virtual std::expected<void, StoreError> commit(const ControlPlaneCommit &commit) = 0;
        [[nodiscard]] virtual std::expected<ControlPlaneInspection, StoreError> inspect() const = 0;
        [[nodiscard]] virtual RuntimeStoreHealth health() const = 0;
    };

    struct SqliteActivationControlStore final: IActivationControlStore {
        [[nodiscard]] static std::expected<std::unique_ptr<SqliteActivationControlStore>, StoreError>
        open(const SqliteDevConfig &config);
        ~SqliteActivationControlStore() override;

        SqliteActivationControlStore(const SqliteActivationControlStore &) = delete;
        SqliteActivationControlStore &operator=(const SqliteActivationControlStore &) = delete;

        [[nodiscard]] std::expected<DurableControlState, StoreError> load_state() const override;
        [[nodiscard]] std::expected<std::optional<AdminOperationRecord>, StoreError>
        find_operation(std::string_view operation_id) const override;
        [[nodiscard]] std::expected<std::optional<AdminOperationRecord>, StoreError>
        find_operation_by_idempotency(std::string_view idempotency_key) const override;
        [[nodiscard]] std::expected<void, StoreError> commit(const ControlPlaneCommit &commit) override;
        [[nodiscard]] std::expected<ControlPlaneInspection, StoreError> inspect() const override;
        [[nodiscard]] RuntimeStoreHealth health() const override;

    private:
        struct Impl;
        explicit SqliteActivationControlStore(std::unique_ptr<Impl> impl);
        std::unique_ptr<Impl> impl_;
    };

    struct PostgreSqlActivationControlStore final: IActivationControlStore {
        [[nodiscard]] static std::expected<std::unique_ptr<PostgreSqlActivationControlStore>, StoreError>
        open(const PostgreSql17Config &config);
        [[nodiscard]] static std::expected<std::unique_ptr<PostgreSqlActivationControlStore>, StoreError>
        open_resolved(const PostgreSql17Config &config, std::string_view connection_string);
        ~PostgreSqlActivationControlStore() override;

        PostgreSqlActivationControlStore(const PostgreSqlActivationControlStore &) = delete;
        PostgreSqlActivationControlStore &operator=(const PostgreSqlActivationControlStore &) = delete;

        [[nodiscard]] std::expected<DurableControlState, StoreError> load_state() const override;
        [[nodiscard]] std::expected<std::optional<AdminOperationRecord>, StoreError>
        find_operation(std::string_view operation_id) const override;
        [[nodiscard]] std::expected<std::optional<AdminOperationRecord>, StoreError>
        find_operation_by_idempotency(std::string_view idempotency_key) const override;
        [[nodiscard]] std::expected<void, StoreError> commit(const ControlPlaneCommit &commit) override;
        [[nodiscard]] std::expected<ControlPlaneInspection, StoreError> inspect() const override;
        [[nodiscard]] RuntimeStoreHealth health() const override;

    private:
        struct Impl;
        explicit PostgreSqlActivationControlStore(std::unique_ptr<Impl> impl);
        std::unique_ptr<Impl> impl_;
    };

    // Authentication and authorization are intentionally outside this class.
    // The actor is durable audit attribution only; callers must authorize it
    // before invoking a mutation.
    struct DurableActivationAdmin {
        explicit DurableActivationAdmin(IActivationControlStore &store): store_ {store} {}

        [[nodiscard]] std::expected<AdminOperationRecord, StoreError>
        preview_stage(const AdminMutationRequest &request, const GenerationSnapshot &generation);
        [[nodiscard]] std::expected<GenerationSnapshot, StoreError> apply_stage(const AdminApplyRequest &request,
                                                                                const GenerationSnapshot &generation);

        [[nodiscard]] std::expected<AdminOperationRecord, StoreError>
        preview_activation(const AdminMutationRequest &request, const PackId &pack, std::uint64_t target_generation);
        [[nodiscard]] std::expected<DrainReceipt, StoreError> begin_drain(const AdminApplyRequest &request,
                                                                          std::uint64_t drain_boundary);
        [[nodiscard]] std::expected<std::vector<std::string>, StoreError>
        fence_stragglers(const AdminApplyRequest &request, std::vector<std::string> work_ids);
        [[nodiscard]] std::expected<ActivationReceipt, StoreError> flip(const AdminApplyRequest &request);

        [[nodiscard]] std::expected<AdminOperationRecord, StoreError>
        preview_rollback(const AdminMutationRequest &request, const PackId &pack, std::uint64_t source_generation,
                         std::uint64_t new_generation, const StateTransitionPlan &state_transition);
        [[nodiscard]] std::expected<GenerationSnapshot, StoreError>
        apply_rollback_stage(const AdminApplyRequest &request, const GenerationSnapshot &generation);

        [[nodiscard]] std::expected<DurableControlState, StoreError> state_snapshot() const;
        [[nodiscard]] std::expected<std::optional<AdminOperationRecord>, StoreError>
        operation_snapshot(std::string_view operation_id) const;
        [[nodiscard]] std::expected<ControlPlaneInspection, StoreError> inspect() const;

    private:
        IActivationControlStore &store_;
    };

} // namespace rule_engine::python::cluster
