#pragma once

#include "rule_engine/python/cluster/control_plane.hpp"

#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <vector>

namespace rule_engine::python::cluster {

    enum struct AdminPrincipalKind : std::uint8_t { administrator, automation, pack_signer };

    struct AuthenticatedAdminPrincipal {
        std::string principal_id;
        TenantId home_tenant;
        AdminPrincipalKind kind {AdminPrincipalKind::pack_signer};
        std::string authentication_id;
    };

    struct AdminCallContext {
        std::optional<AuthenticatedAdminPrincipal> principal;
        std::uint64_t at_unix_ms {};
    };

    enum struct AdminControlOperation : std::uint8_t {
        stage_preview,
        stage_apply,
        activation_preview,
        activation_drain,
        activation_fence,
        activation_flip,
        rollback_preview,
        rollback_stage_apply,
        pack_read,
        operation_read,
        pack_inspect,
    };

    enum struct AdminResourceKind : std::uint8_t { pack, pack_operation };

    struct AdminResource {
        TenantId tenant;
        PackId pack;
        AdminResourceKind kind {AdminResourceKind::pack};
        std::string operation_id;

        auto operator<=>(const AdminResource &) const = default;
    };

    struct AdminAuthorizationRequest {
        AdminControlOperation operation {AdminControlOperation::pack_read};
        AdminResource resource;
    };

    enum struct AdminAuthorizationOutcome : std::uint8_t { denied, allowed };

    struct AdminAuthorizationDecision {
        AdminAuthorizationOutcome outcome {AdminAuthorizationOutcome::denied};
        std::string decision_id;
        std::string detail;
    };

    struct AdminAuthorizerFailure {
        std::string message;
        bool retryable {};
    };

    struct IAdminAuthorizer {
        virtual ~IAdminAuthorizer() = default;
        [[nodiscard]] virtual std::expected<AdminAuthorizationDecision, AdminAuthorizerFailure>
        authorize(const AuthenticatedAdminPrincipal &principal, const AdminAuthorizationRequest &request) const = 0;
    };

    enum struct AdminSecurityAuditOutcome : std::uint8_t {
        allowed,
        unauthenticated,
        non_admin_identity_rejected,
        invalid_resource,
        authorizer_unavailable,
        denied,
    };

    struct AdminSecurityAuditEvent {
        std::optional<std::string> principal_id;
        AdminAuthorizationRequest request;
        AdminSecurityAuditOutcome outcome {AdminSecurityAuditOutcome::denied};
        std::string decision_id;
        std::string detail;
        std::uint64_t at_unix_ms {};
    };

    // This sink is deliberately separate from IActivationControlStore. A denied
    // request may be reported here, but can never append to the control-plane
    // audit table or mutate activation state.
    struct IAdminSecurityAuditSink {
        virtual ~IAdminSecurityAuditSink() = default;
        virtual void record(const AdminSecurityAuditEvent &event) noexcept = 0;
    };

    enum struct AuthorizedAdminErrorCode : std::uint8_t {
        unauthenticated,
        unauthorized,
        authorizer_unavailable,
        invalid_resource,
        resource_mismatch,
        store_failure,
    };

    struct AuthorizedAdminError {
        AuthorizedAdminErrorCode code {AuthorizedAdminErrorCode::unauthenticated};
        std::string message;
        bool retryable {};
        std::optional<StoreErrorCode> store_code;
    };

    struct AuthorizedPackSnapshot {
        std::uint64_t storage_revision {};
        std::optional<DurablePackControlSnapshot> control;
        std::vector<GenerationSnapshot> generations;
    };

    struct AuthorizedPackInspection {
        AuthorizedPackSnapshot state;
        std::vector<AdminOperationRecord> operations;
        std::vector<AuditRecord> audit;
    };

    // Credential verification is upstream. This facade accepts only an
    // authenticated principal object and an explicit authorizer decision. It
    // never treats request.actor or a pack-signer identity as authority.
    struct AuthorizedActivationAdmin {
        explicit AuthorizedActivationAdmin(DurableActivationAdmin &admin, const IAdminAuthorizer *authorizer = nullptr,
                                           IAdminSecurityAuditSink *security_audit = nullptr):
            admin_ {admin}, authorizer_ {authorizer}, security_audit_ {security_audit} {}

        [[nodiscard]] std::expected<AdminOperationRecord, AuthorizedAdminError>
        preview_stage(const AdminCallContext &context, const TenantId &tenant, const AdminMutationRequest &request,
                      const GenerationSnapshot &generation);
        [[nodiscard]] std::expected<GenerationSnapshot, AuthorizedAdminError>
        apply_stage(const AdminCallContext &context, const TenantId &tenant, const AdminApplyRequest &request,
                    const GenerationSnapshot &generation);

        [[nodiscard]] std::expected<AdminOperationRecord, AuthorizedAdminError>
        preview_activation(const AdminCallContext &context, const TenantId &tenant, const AdminMutationRequest &request,
                           const PackId &pack, std::uint64_t target_generation);
        [[nodiscard]] std::expected<DrainReceipt, AuthorizedAdminError>
        begin_drain(const AdminCallContext &context, const TenantId &tenant, const PackId &pack,
                    const AdminApplyRequest &request, std::uint64_t drain_boundary);
        [[nodiscard]] std::expected<std::vector<std::string>, AuthorizedAdminError>
        fence_stragglers(const AdminCallContext &context, const TenantId &tenant, const PackId &pack,
                         const AdminApplyRequest &request, std::vector<std::string> work_ids);
        [[nodiscard]] std::expected<ActivationReceipt, AuthorizedAdminError> flip(const AdminCallContext &context,
                                                                                  const TenantId &tenant,
                                                                                  const PackId &pack,
                                                                                  const AdminApplyRequest &request);

        [[nodiscard]] std::expected<AdminOperationRecord, AuthorizedAdminError>
        preview_rollback(const AdminCallContext &context, const TenantId &tenant, const AdminMutationRequest &request,
                         const PackId &pack, std::uint64_t source_generation, std::uint64_t new_generation,
                         const StateTransitionPlan &state_transition);
        [[nodiscard]] std::expected<GenerationSnapshot, AuthorizedAdminError>
        apply_rollback_stage(const AdminCallContext &context, const TenantId &tenant, const AdminApplyRequest &request,
                             const GenerationSnapshot &generation);

        [[nodiscard]] std::expected<AuthorizedPackSnapshot, AuthorizedAdminError>
        pack_snapshot(const AdminCallContext &context, const TenantId &tenant, const PackId &pack) const;
        [[nodiscard]] std::expected<std::optional<AdminOperationRecord>, AuthorizedAdminError>
        operation_snapshot(const AdminCallContext &context, const TenantId &tenant, const PackId &pack,
                           std::string operation_id) const;
        [[nodiscard]] std::expected<AuthorizedPackInspection, AuthorizedAdminError>
        inspect_pack(const AdminCallContext &context, const TenantId &tenant, const PackId &pack) const;

    private:
        [[nodiscard]] std::expected<const AuthenticatedAdminPrincipal *, AuthorizedAdminError>
        authorize(const AdminCallContext &context, const AdminAuthorizationRequest &request) const;
        [[nodiscard]] std::expected<void, AuthorizedAdminError> verify_operation_pack(const AdminApplyRequest &request,
                                                                                      const PackId &pack) const;

        DurableActivationAdmin &admin_;
        const IAdminAuthorizer *authorizer_ {};
        IAdminSecurityAuditSink *security_audit_ {};
    };

} // namespace rule_engine::python::cluster
