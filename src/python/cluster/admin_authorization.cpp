#include "rule_engine/python/cluster/admin_authorization.hpp"

#include <algorithm>
#include <iterator>
#include <set>
#include <string_view>
#include <utility>

namespace rule_engine::python::cluster {
    namespace {

        AuthorizedAdminError access_error(const AuthorizedAdminErrorCode code, std::string message,
                                          const bool retryable = false) {
            return AuthorizedAdminError {
                .code = code, .message = std::move(message), .retryable = retryable, .store_code = std::nullopt};
        }

        AuthorizedAdminError store_error(const StoreError &error) {
            return AuthorizedAdminError {.code = AuthorizedAdminErrorCode::store_failure,
                                         .message = error.message,
                                         .retryable = error.retryable,
                                         .store_code = error.code};
        }

        AdminResource pack_resource(const TenantId &tenant, const PackId &pack) {
            return AdminResource {.tenant = tenant, .pack = pack, .kind = AdminResourceKind::pack, .operation_id = {}};
        }

        AdminResource operation_resource(const TenantId &tenant, const PackId &pack,
                                         const std::string_view operation_id) {
            return AdminResource {.tenant = tenant,
                                  .pack = pack,
                                  .kind = AdminResourceKind::pack_operation,
                                  .operation_id = std::string {operation_id}};
        }

        bool valid_resource(const AdminResource &resource) {
            if (resource.tenant.empty() || resource.pack.empty()) {
                return false;
            }
            switch (resource.kind) {
                case AdminResourceKind::pack: return resource.operation_id.empty();
                case AdminResourceKind::pack_operation: return !resource.operation_id.empty();
                default: return false;
            }
        }

        template<typename Value>
        std::expected<Value, AuthorizedAdminError> mapped(std::expected<Value, StoreError> result) {
            if (!result) {
                return std::unexpected(store_error(result.error()));
            }
            return std::move(*result);
        }

        void emit_security_event(IAdminSecurityAuditSink *sink, const AdminCallContext &context,
                                 const AdminAuthorizationRequest &request, const AdminSecurityAuditOutcome outcome,
                                 std::string decision_id, std::string detail) {
            if (sink == nullptr) {
                return;
            }
            sink->record(AdminSecurityAuditEvent {
                .principal_id =
                    context.principal ? std::optional<std::string> {context.principal->principal_id} : std::nullopt,
                .request = request,
                .outcome = outcome,
                .decision_id = std::move(decision_id),
                .detail = std::move(detail),
                .at_unix_ms = context.at_unix_ms,
            });
        }

    } // namespace

    std::expected<const AuthenticatedAdminPrincipal *, AuthorizedAdminError>
    AuthorizedActivationAdmin::authorize(const AdminCallContext &context,
                                         const AdminAuthorizationRequest &request) const {
        if (!context.principal || context.principal->principal_id.empty() || context.principal->home_tenant.empty() ||
            context.principal->authentication_id.empty()) {
            emit_security_event(security_audit_, context, request, AdminSecurityAuditOutcome::unauthenticated, {},
                                "an upstream-authenticated principal is required");
            return std::unexpected(access_error(AuthorizedAdminErrorCode::unauthenticated,
                                                "an upstream-authenticated principal is required"));
        }
        if (context.principal->kind != AdminPrincipalKind::administrator &&
            context.principal->kind != AdminPrincipalKind::automation) {
            emit_security_event(security_audit_, context, request,
                                AdminSecurityAuditOutcome::non_admin_identity_rejected, {},
                                "a non-admin identity, including a pack signer, grants no administrative capability");
            return std::unexpected(access_error(AuthorizedAdminErrorCode::unauthorized,
                                                "a non-admin identity, including a pack signer, grants no "
                                                "administrative capability"));
        }
        if (!valid_resource(request.resource)) {
            emit_security_event(security_audit_, context, request, AdminSecurityAuditOutcome::invalid_resource, {},
                                "admin authorization resource is incomplete");
            return std::unexpected(
                access_error(AuthorizedAdminErrorCode::invalid_resource, "admin authorization resource is incomplete"));
        }
        if (authorizer_ == nullptr) {
            emit_security_event(security_audit_, context, request, AdminSecurityAuditOutcome::authorizer_unavailable,
                                {}, "no admin authorizer is configured");
            return std::unexpected(
                access_error(AuthorizedAdminErrorCode::authorizer_unavailable, "no admin authorizer is configured"));
        }
        auto decision = authorizer_->authorize(*context.principal, request);
        if (!decision) {
            emit_security_event(security_audit_, context, request, AdminSecurityAuditOutcome::authorizer_unavailable,
                                {}, decision.error().message);
            return std::unexpected(access_error(AuthorizedAdminErrorCode::authorizer_unavailable,
                                                decision.error().message, decision.error().retryable));
        }
        if (decision->decision_id.empty()) {
            emit_security_event(security_audit_, context, request, AdminSecurityAuditOutcome::authorizer_unavailable,
                                {}, "admin authorizer returned a decision without an identity");
            return std::unexpected(access_error(AuthorizedAdminErrorCode::authorizer_unavailable,
                                                "admin authorizer returned a decision without an identity"));
        }
        if (decision->outcome != AdminAuthorizationOutcome::allowed) {
            emit_security_event(security_audit_, context, request, AdminSecurityAuditOutcome::denied,
                                decision->decision_id, decision->detail);
            return std::unexpected(
                access_error(AuthorizedAdminErrorCode::unauthorized,
                             decision->detail.empty() ? "admin operation is not authorized" : decision->detail));
        }
        emit_security_event(security_audit_, context, request, AdminSecurityAuditOutcome::allowed,
                            decision->decision_id, decision->detail);
        return &*context.principal;
    }

    std::expected<void, AuthorizedAdminError>
    AuthorizedActivationAdmin::verify_operation_pack(const AdminApplyRequest &request, const PackId &pack) const {
        auto operation = admin_.operation_snapshot(request.operation_id);
        if (!operation) {
            return std::unexpected(store_error(operation.error()));
        }
        if (!*operation || (*operation)->pack != pack) {
            return std::unexpected(access_error(AuthorizedAdminErrorCode::resource_mismatch,
                                                "authorized resource does not match the requested operation"));
        }
        return {};
    }

    std::expected<AdminOperationRecord, AuthorizedAdminError>
    AuthorizedActivationAdmin::preview_stage(const AdminCallContext &context, const TenantId &tenant,
                                             const AdminMutationRequest &request,
                                             const GenerationSnapshot &generation) {
        const AdminAuthorizationRequest authorization {
            .operation = AdminControlOperation::stage_preview,
            .resource = operation_resource(tenant, generation.request.pack, request.operation_id),
        };
        const auto principal = authorize(context, authorization);
        if (!principal) {
            return std::unexpected(principal.error());
        }
        auto attributed = request;
        attributed.actor = (*principal)->principal_id;
        return mapped(admin_.preview_stage(attributed, generation));
    }

    std::expected<GenerationSnapshot, AuthorizedAdminError>
    AuthorizedActivationAdmin::apply_stage(const AdminCallContext &context, const TenantId &tenant,
                                           const AdminApplyRequest &request, const GenerationSnapshot &generation) {
        const AdminAuthorizationRequest authorization {
            .operation = AdminControlOperation::stage_apply,
            .resource = operation_resource(tenant, generation.request.pack, request.operation_id),
        };
        if (auto authorized = authorize(context, authorization); !authorized) {
            return std::unexpected(authorized.error());
        }
        if (auto verified = verify_operation_pack(request, generation.request.pack); !verified) {
            return std::unexpected(verified.error());
        }
        return mapped(admin_.apply_stage(request, generation));
    }

    std::expected<AdminOperationRecord, AuthorizedAdminError>
    AuthorizedActivationAdmin::preview_activation(const AdminCallContext &context, const TenantId &tenant,
                                                  const AdminMutationRequest &request, const PackId &pack,
                                                  const std::uint64_t target_generation) {
        const AdminAuthorizationRequest authorization {
            .operation = AdminControlOperation::activation_preview,
            .resource = operation_resource(tenant, pack, request.operation_id),
        };
        const auto principal = authorize(context, authorization);
        if (!principal) {
            return std::unexpected(principal.error());
        }
        auto attributed = request;
        attributed.actor = (*principal)->principal_id;
        return mapped(admin_.preview_activation(attributed, pack, target_generation));
    }

    std::expected<DrainReceipt, AuthorizedAdminError>
    AuthorizedActivationAdmin::begin_drain(const AdminCallContext &context, const TenantId &tenant, const PackId &pack,
                                           const AdminApplyRequest &request, const std::uint64_t drain_boundary) {
        const AdminAuthorizationRequest authorization {
            .operation = AdminControlOperation::activation_drain,
            .resource = operation_resource(tenant, pack, request.operation_id),
        };
        if (auto authorized = authorize(context, authorization); !authorized) {
            return std::unexpected(authorized.error());
        }
        if (auto verified = verify_operation_pack(request, pack); !verified) {
            return std::unexpected(verified.error());
        }
        return mapped(admin_.begin_drain(request, drain_boundary));
    }

    std::expected<std::vector<std::string>, AuthorizedAdminError>
    AuthorizedActivationAdmin::fence_stragglers(const AdminCallContext &context, const TenantId &tenant,
                                                const PackId &pack, const AdminApplyRequest &request,
                                                std::vector<std::string> work_ids) {
        const AdminAuthorizationRequest authorization {
            .operation = AdminControlOperation::activation_fence,
            .resource = operation_resource(tenant, pack, request.operation_id),
        };
        if (auto authorized = authorize(context, authorization); !authorized) {
            return std::unexpected(authorized.error());
        }
        if (auto verified = verify_operation_pack(request, pack); !verified) {
            return std::unexpected(verified.error());
        }
        return mapped(admin_.fence_stragglers(request, std::move(work_ids)));
    }

    std::expected<ActivationReceipt, AuthorizedAdminError>
    AuthorizedActivationAdmin::flip(const AdminCallContext &context, const TenantId &tenant, const PackId &pack,
                                    const AdminApplyRequest &request) {
        const AdminAuthorizationRequest authorization {
            .operation = AdminControlOperation::activation_flip,
            .resource = operation_resource(tenant, pack, request.operation_id),
        };
        if (auto authorized = authorize(context, authorization); !authorized) {
            return std::unexpected(authorized.error());
        }
        if (auto verified = verify_operation_pack(request, pack); !verified) {
            return std::unexpected(verified.error());
        }
        return mapped(admin_.flip(request));
    }

    std::expected<AdminOperationRecord, AuthorizedAdminError> AuthorizedActivationAdmin::preview_rollback(
        const AdminCallContext &context, const TenantId &tenant, const AdminMutationRequest &request,
        const PackId &pack, const std::uint64_t source_generation, const std::uint64_t new_generation,
        const StateTransitionPlan &state_transition) {
        const AdminAuthorizationRequest authorization {
            .operation = AdminControlOperation::rollback_preview,
            .resource = operation_resource(tenant, pack, request.operation_id),
        };
        const auto principal = authorize(context, authorization);
        if (!principal) {
            return std::unexpected(principal.error());
        }
        auto attributed = request;
        attributed.actor = (*principal)->principal_id;
        return mapped(admin_.preview_rollback(attributed, pack, source_generation, new_generation, state_transition));
    }

    std::expected<GenerationSnapshot, AuthorizedAdminError>
    AuthorizedActivationAdmin::apply_rollback_stage(const AdminCallContext &context, const TenantId &tenant,
                                                    const AdminApplyRequest &request,
                                                    const GenerationSnapshot &generation) {
        const AdminAuthorizationRequest authorization {
            .operation = AdminControlOperation::rollback_stage_apply,
            .resource = operation_resource(tenant, generation.request.pack, request.operation_id),
        };
        if (auto authorized = authorize(context, authorization); !authorized) {
            return std::unexpected(authorized.error());
        }
        if (auto verified = verify_operation_pack(request, generation.request.pack); !verified) {
            return std::unexpected(verified.error());
        }
        return mapped(admin_.apply_rollback_stage(request, generation));
    }

    std::expected<AuthorizedPackSnapshot, AuthorizedAdminError>
    AuthorizedActivationAdmin::pack_snapshot(const AdminCallContext &context, const TenantId &tenant,
                                             const PackId &pack) const {
        const AdminAuthorizationRequest authorization {
            .operation = AdminControlOperation::pack_read,
            .resource = pack_resource(tenant, pack),
        };
        if (auto authorized = authorize(context, authorization); !authorized) {
            return std::unexpected(authorized.error());
        }
        auto state = admin_.state_snapshot();
        if (!state) {
            return std::unexpected(store_error(state.error()));
        }
        AuthorizedPackSnapshot result {
            .storage_revision = state->storage_revision, .control = std::nullopt, .generations = {}};
        const auto control = std::ranges::find(state->packs, pack, &DurablePackControlSnapshot::pack);
        if (control != state->packs.end()) {
            result.control = *control;
        }
        std::ranges::copy_if(state->generations, std::back_inserter(result.generations),
                             [&](const GenerationSnapshot &generation) { return generation.request.pack == pack; });
        return result;
    }

    std::expected<void, AuthorizedAdminError>
    AuthorizedActivationAdmin::authorize_pack_upload(const AdminCallContext &context, const TenantId &tenant,
                                                     const PackId &pack) const {
        const AdminAuthorizationRequest authorization {
            .operation = AdminControlOperation::pack_upload,
            .resource = pack_resource(tenant, pack),
        };
        if (auto authorized = authorize(context, authorization); !authorized) {
            return std::unexpected(authorized.error());
        }
        return {};
    }

    std::expected<std::optional<AdminOperationRecord>, AuthorizedAdminError>
    AuthorizedActivationAdmin::operation_snapshot(const AdminCallContext &context, const TenantId &tenant,
                                                  const PackId &pack, std::string operation_id) const {
        const AdminAuthorizationRequest authorization {
            .operation = AdminControlOperation::operation_read,
            .resource = operation_resource(tenant, pack, operation_id),
        };
        if (auto authorized = authorize(context, authorization); !authorized) {
            return std::unexpected(authorized.error());
        }
        auto operation = admin_.operation_snapshot(operation_id);
        if (!operation) {
            return std::unexpected(store_error(operation.error()));
        }
        if (*operation && (*operation)->pack != pack) {
            return std::optional<AdminOperationRecord> {};
        }
        return std::move(*operation);
    }

    std::expected<AuthorizedPackInspection, AuthorizedAdminError>
    AuthorizedActivationAdmin::inspect_pack(const AdminCallContext &context, const TenantId &tenant,
                                            const PackId &pack) const {
        const AdminAuthorizationRequest authorization {
            .operation = AdminControlOperation::pack_inspect,
            .resource = pack_resource(tenant, pack),
        };
        if (auto authorized = authorize(context, authorization); !authorized) {
            return std::unexpected(authorized.error());
        }
        auto inspection = admin_.inspect();
        if (!inspection) {
            return std::unexpected(store_error(inspection.error()));
        }
        AuthorizedPackInspection result {.state = {.storage_revision = inspection->state.storage_revision,
                                                   .control = std::nullopt,
                                                   .generations = {}},
                                         .operations = {},
                                         .audit = {}};
        const auto control = std::ranges::find(inspection->state.packs, pack, &DurablePackControlSnapshot::pack);
        if (control != inspection->state.packs.end()) {
            result.state.control = *control;
        }
        std::ranges::copy_if(inspection->state.generations, std::back_inserter(result.state.generations),
                             [&](const GenerationSnapshot &generation) { return generation.request.pack == pack; });
        std::ranges::copy_if(inspection->operations, std::back_inserter(result.operations),
                             [&](const AdminOperationRecord &operation) { return operation.pack == pack; });

        std::set<std::string, std::less<>> audit_resources;
        for (const auto &generation : result.state.generations) {
            audit_resources.insert(pack.value + ":" + std::to_string(generation.request.generation));
        }
        for (const auto &operation : result.operations) {
            audit_resources.insert(pack.value + ":" + std::to_string(operation.target_generation));
        }
        std::ranges::copy_if(inspection->audit, std::back_inserter(result.audit),
                             [&](const AuditRecord &audit) { return audit_resources.contains(audit.resource); });
        return result;
    }

} // namespace rule_engine::python::cluster
