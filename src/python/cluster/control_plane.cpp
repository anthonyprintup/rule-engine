#include "rule_engine/python/cluster/control_plane.hpp"

#include "control_serialization.hpp"

#include <algorithm>
#include <limits>
#include <set>
#include <tuple>
#include <utility>

namespace rule_engine::python::cluster {
    namespace {

        StoreError control_error(const StoreErrorCode code, std::string message, const bool retryable = false) {
            return StoreError {.code = code, .message = std::move(message), .retryable = retryable};
        }

        StoreError invalid(std::string message) {
            return control_error(StoreErrorCode::constraint_violation, std::move(message));
        }

        StoreError stale(std::string message) { return control_error(StoreErrorCode::stale_fence, std::move(message)); }

        std::vector<std::string> normalized(std::vector<std::string> values) {
            std::ranges::sort(values);
            values.erase(std::ranges::unique(values).begin(), values.end());
            return values;
        }

        GenerationSnapshot canonical_generation(GenerationSnapshot generation) {
            generation.request.required_capability_hashes =
                normalized(std::move(generation.request.required_capability_hashes));
            if (generation.request.state_transition.target_namespace.empty()) {
                generation.request.state_transition.target_namespace = generation.request.state_namespace;
            }
            generation.target_nodes = normalized(std::move(generation.target_nodes));
            for (auto &target : generation.targets) {
                target.capability_hashes = normalized(std::move(target.capability_hashes));
            }
            std::ranges::sort(generation.targets, {}, &StageTargetNode::node_id);
            for (auto &report : generation.reports) {
                report.capability_hashes = normalized(std::move(report.capability_hashes));
            }
            std::ranges::sort(generation.reports, {}, &CompilationReport::node_id);
            generation.requeued_work = normalized(std::move(generation.requeued_work));
            return generation;
        }

        std::expected<void, StoreError> validate_staged_generation(const GenerationSnapshot &generation) {
            const auto &request = generation.request;
            if (request.pack.empty() || request.version.empty() || request.source_digest.empty() ||
                request.generation == 0 || request.state_schema_hash.empty() || request.state_namespace.empty() ||
                !request.signature_verified || generation.phase != GenerationPhase::ready ||
                generation.semantic_hash.empty() || generation.binding_hash.empty() || !generation.failure.empty() ||
                !generation.requeued_work.empty() || generation.target_nodes.empty() ||
                generation.target_nodes.size() != generation.reports.size()) {
                return std::unexpected(invalid("staged generation metadata is incomplete or not ready"));
            }
            if (request.state_transition.target_namespace != request.state_namespace) {
                return std::unexpected(invalid("staged generation state target does not match its namespace"));
            }
            std::set<std::string, std::less<>> targets;
            for (const auto &target : generation.target_nodes) {
                if (target.empty() || !targets.insert(target).second) {
                    return std::unexpected(invalid("staged generation targets are empty or duplicated"));
                }
            }
            std::set<std::string, std::less<>> reports;
            for (const auto &report : generation.reports) {
                if (report.node_id.empty() || report.node_lease_fence == 0 || !report.success ||
                    report.semantic_hash != generation.semantic_hash ||
                    report.binding_hash != generation.binding_hash || report.executable_hash.empty() ||
                    !targets.contains(report.node_id) || !reports.insert(report.node_id).second) {
                    return std::unexpected(invalid("staged compilation evidence is incomplete or inconsistent"));
                }
                for (const auto &required : request.required_capability_hashes) {
                    if (!std::ranges::binary_search(report.capability_hashes, required)) {
                        return std::unexpected(
                            invalid("a staged node does not provide every required capability hash"));
                    }
                }
            }
            if (!generation.targets.empty()) {
                if (generation.targets.size() != generation.target_nodes.size()) {
                    return std::unexpected(invalid("staged target evidence does not match the target node set"));
                }
                for (std::size_t index = 0; index < generation.targets.size(); ++index) {
                    const auto &target = generation.targets[index];
                    if (target.node_id != generation.target_nodes[index] || target.platform_abi.empty() ||
                        target.lease_fence == 0 || target.lease_until_unix_ms == 0) {
                        return std::unexpected(invalid("staged target evidence is incomplete or inconsistent"));
                    }
                    for (const auto &required : request.required_capability_hashes) {
                        if (!std::ranges::binary_search(target.capability_hashes, required)) {
                            return std::unexpected(
                                invalid("a staged target does not advertise every required capability hash"));
                        }
                    }
                }
            }
            return {};
        }

        GenerationRequest canonical_request(GenerationRequest request) {
            request.required_capability_hashes = normalized(std::move(request.required_capability_hashes));
            if (request.state_transition.target_namespace.empty()) {
                request.state_transition.target_namespace = request.state_namespace;
            }
            return request;
        }

        std::expected<void, StoreError> validate_server_stage_request(const GenerationRequest &request) {
            if (request.pack.empty() || request.version.empty() || request.source_digest.empty() ||
                request.generation == 0 || request.state_schema_hash.empty() || request.state_namespace.empty() ||
                !request.signature_verified || request.rollback_from ||
                request.state_transition.target_namespace != request.state_namespace ||
                std::ranges::any_of(request.required_capability_hashes,
                                    [](const auto &capability) { return capability.empty(); })) {
                return std::unexpected(invalid("server-owned stage request metadata is incomplete"));
            }
            return {};
        }

        GenerationSnapshot *find_generation(DurableControlState &state, const PackId &pack,
                                            const std::uint64_t generation) {
            const auto found = std::ranges::find_if(state.generations, [&](const GenerationSnapshot &candidate) {
                return candidate.request.pack == pack && candidate.request.generation == generation;
            });
            return found == state.generations.end() ? nullptr : &*found;
        }

        const GenerationSnapshot *find_generation(const DurableControlState &state, const PackId &pack,
                                                  const std::uint64_t generation) {
            const auto found = std::ranges::find_if(state.generations, [&](const GenerationSnapshot &candidate) {
                return candidate.request.pack == pack && candidate.request.generation == generation;
            });
            return found == state.generations.end() ? nullptr : &*found;
        }

        DurablePackControlSnapshot *find_pack(DurableControlState &state, const PackId &pack) {
            const auto found = std::ranges::find(state.packs, pack, &DurablePackControlSnapshot::pack);
            return found == state.packs.end() ? nullptr : &*found;
        }

        const DurablePackControlSnapshot *find_pack(const DurableControlState &state, const PackId &pack) {
            const auto found = std::ranges::find(state.packs, pack, &DurablePackControlSnapshot::pack);
            return found == state.packs.end() ? nullptr : &*found;
        }

        DurablePackControlSnapshot &ensure_pack(DurableControlState &state, const PackId &pack) {
            if (auto *control = find_pack(state, pack); control != nullptr) {
                return *control;
            }
            state.packs.push_back(DurablePackControlSnapshot {.pack = pack,
                                                              .resource_version = 0,
                                                              .active_generation = std::nullopt,
                                                              .assignment_fence = 0,
                                                              .accepting_assignments = false,
                                                              .drain_boundary = std::nullopt,
                                                              .drain_target = std::nullopt,
                                                              .pending_requeues = {}});
            return state.packs.back();
        }

        std::uint64_t pack_version(const DurableControlState &state, const PackId &pack) {
            const auto *control = find_pack(state, pack);
            return control == nullptr ? 0U : control->resource_version;
        }

        bool generation_number_available(const DurableControlState &state, const PackId &pack,
                                         const std::uint64_t generation) {
            for (const auto &existing : state.generations) {
                if (existing.request.pack == pack && existing.request.generation >= generation) {
                    return false;
                }
            }
            return true;
        }

        std::expected<void, StoreError> validate_mutation_request(const AdminMutationRequest &request) {
            if (request.operation_id.empty() || request.request_id.empty() || request.idempotency_key.empty() ||
                request.actor.empty() || request.reason.empty()) {
                return std::unexpected(invalid("admin mutation identity, actor, and reason are required"));
            }
            return {};
        }

        std::expected<void, StoreError> validate_apply_request(const AdminApplyRequest &request) {
            if (request.operation_id.empty() || request.idempotency_key.empty()) {
                return std::unexpected(invalid("admin apply operation and idempotency identities are required"));
            }
            return {};
        }

        bool transition_matches(const StateTransitionPlan &left, const StateTransitionPlan &right) {
            return left.mode == right.mode && left.source_namespace == right.source_namespace &&
                   left.target_namespace == right.target_namespace && left.migration_id == right.migration_id &&
                   left.reset_authorized == right.reset_authorized && left.accept_state_gap == right.accept_state_gap;
        }

        std::expected<void, StoreError> validate_state_transition(const DurableControlState &state,
                                                                  const GenerationRequest &request) {
            const auto *control = find_pack(state, request.pack);
            if (control == nullptr || !control->active_generation) {
                if (request.state_transition.mode == StateTransitionMode::retained_gap) {
                    return std::unexpected(
                        control_error(StoreErrorCode::incompatible_schema,
                                      "retained state cannot be selected without an active generation"));
                }
                return {};
            }
            const auto *current = find_generation(state, request.pack, *control->active_generation);
            if (current == nullptr || current->phase != GenerationPhase::active) {
                return std::unexpected(invalid("active generation metadata is inconsistent"));
            }
            const auto same_schema = current->request.state_schema_hash == request.state_schema_hash;
            switch (request.state_transition.mode) {
                case StateTransitionMode::carry:
                    if (!same_schema || request.state_namespace != current->request.state_namespace) {
                        return std::unexpected(
                            control_error(StoreErrorCode::incompatible_schema,
                                          "state carry requires an identical active schema and namespace"));
                    }
                    return {};
                case StateTransitionMode::migrate:
                    if (same_schema || request.state_transition.migration_id.empty() ||
                        request.state_transition.source_namespace != current->request.state_namespace ||
                        request.state_transition.target_namespace != request.state_namespace) {
                        return std::unexpected(control_error(
                            StoreErrorCode::incompatible_schema,
                            "state migration requires distinct schemas, source, target, and migration identity"));
                    }
                    return {};
                case StateTransitionMode::reset:
                    if (!request.state_transition.reset_authorized ||
                        request.state_transition.target_namespace != request.state_namespace) {
                        return std::unexpected(
                            control_error(StoreErrorCode::incompatible_schema,
                                          "state reset requires manifest authorization and the target namespace"));
                    }
                    return {};
                case StateTransitionMode::retained_gap:
                    if (!request.rollback_from || !request.state_transition.accept_state_gap ||
                        request.state_transition.target_namespace != request.state_namespace) {
                        return std::unexpected(
                            control_error(StoreErrorCode::incompatible_schema,
                                          "retained state requires rollback identity and explicit gap acceptance"));
                    }
                    return {};
                default:
                    return std::unexpected(
                        control_error(StoreErrorCode::incompatible_schema, "state transition mode is invalid"));
            }
        }

        std::expected<StateTransitionPlan, StoreError> canonical_rollback_transition(StateTransitionPlan transition,
                                                                                     const GenerationSnapshot &source,
                                                                                     const GenerationSnapshot &active) {
            switch (transition.mode) {
                case StateTransitionMode::carry:
                    if (source.request.state_schema_hash != active.request.state_schema_hash) {
                        return std::unexpected(
                            control_error(StoreErrorCode::incompatible_schema,
                                          "rollback carry requires identical active and source state schemas"));
                    }
                    transition.source_namespace = active.request.state_namespace;
                    transition.target_namespace = active.request.state_namespace;
                    return transition;
                case StateTransitionMode::migrate:
                    if (transition.migration_id.empty() ||
                        transition.source_namespace != active.request.state_namespace ||
                        transition.target_namespace.empty()) {
                        return std::unexpected(control_error(
                            StoreErrorCode::incompatible_schema,
                            "rollback migration requires the active source namespace, target namespace, and ID"));
                    }
                    return transition;
                case StateTransitionMode::reset:
                    if (!transition.reset_authorized || transition.target_namespace.empty()) {
                        return std::unexpected(control_error(
                            StoreErrorCode::incompatible_schema,
                            "rollback reset requires manifest authorization and an explicit target namespace"));
                    }
                    return transition;
                case StateTransitionMode::retained_gap:
                    if (!transition.accept_state_gap || transition.target_namespace.empty()) {
                        return std::unexpected(control_error(
                            StoreErrorCode::incompatible_schema,
                            "retained rollback state requires explicit gap acceptance and a target namespace"));
                    }
                    return transition;
                default:
                    return std::unexpected(
                        control_error(StoreErrorCode::incompatible_schema, "rollback state transition is invalid"));
            }
        }

        std::expected<std::optional<AdminOperationRecord>, StoreError>
        resolve_preview_idempotency(IActivationControlStore &store, const AdminMutationRequest &request,
                                    const AdminOperationKind kind, const PackId &pack,
                                    const std::span<const std::byte> fingerprint) {
            auto existing = store.find_operation_by_idempotency(request.idempotency_key);
            if (!existing) {
                return std::unexpected(existing.error());
            }
            if (*existing) {
                if ((*existing)->kind != kind || (*existing)->pack != pack ||
                    !std::ranges::equal((*existing)->request_fingerprint, fingerprint)) {
                    return std::unexpected(invalid("idempotency key was already used for a different mutation"));
                }
                return *existing;
            }
            auto operation_id = store.find_operation(request.operation_id);
            if (!operation_id) {
                return std::unexpected(operation_id.error());
            }
            if (*operation_id) {
                return std::unexpected(invalid("operation ID was already used with another idempotency key"));
            }
            return std::optional<AdminOperationRecord> {};
        }

        std::expected<AdminOperationRecord, StoreError> load_apply_operation(IActivationControlStore &store,
                                                                             const AdminApplyRequest &request) {
            if (auto valid = validate_apply_request(request); !valid) {
                return std::unexpected(valid.error());
            }
            auto operation = store.find_operation(request.operation_id);
            if (!operation) {
                return std::unexpected(operation.error());
            }
            if (!*operation) {
                return std::unexpected(invalid("admin operation does not exist"));
            }
            if ((*operation)->idempotency_key != request.idempotency_key) {
                return std::unexpected(invalid("admin apply idempotency key does not match the preview"));
            }
            return **operation;
        }

        std::expected<void, StoreError> advance_revision(DurableControlState &state) {
            if (state.storage_revision == std::numeric_limits<std::uint64_t>::max()) {
                return std::unexpected(
                    control_error(StoreErrorCode::unavailable, "control-plane storage revision space is exhausted"));
            }
            ++state.storage_revision;
            return {};
        }

        std::expected<void, StoreError> advance_pack(DurablePackControlSnapshot &pack) {
            if (pack.resource_version == std::numeric_limits<std::uint64_t>::max()) {
                return std::unexpected(
                    control_error(StoreErrorCode::unavailable, "pack resource version space is exhausted"));
            }
            ++pack.resource_version;
            return {};
        }

        std::expected<void, StoreError> advance_assignment_fence(DurablePackControlSnapshot &pack) {
            if (pack.assignment_fence == std::numeric_limits<std::uint64_t>::max()) {
                return std::unexpected(
                    control_error(StoreErrorCode::unavailable, "pack assignment fence space is exhausted"));
            }
            ++pack.assignment_fence;
            return {};
        }

        std::expected<void, StoreError> commit_transition(IActivationControlStore &store,
                                                          const std::uint64_t expected_storage_revision,
                                                          DurableControlState state, AdminOperationRecord operation,
                                                          AuditRecord audit) {
            if (auto advanced = advance_revision(state); !advanced) {
                return std::unexpected(advanced.error());
            }
            return store.commit(ControlPlaneCommit {.expected_storage_revision = expected_storage_revision,
                                                    .state = std::move(state),
                                                    .operation = std::move(operation),
                                                    .audit = std::move(audit)});
        }

        AuditRecord admin_audit(const std::uint64_t at_unix_ms, const AdminOperationRecord &operation,
                                std::string action, std::string outcome, std::string detail) {
            return AuditRecord {.sequence = 0,
                                .at_unix_ms = at_unix_ms,
                                .actor = operation.actor,
                                .action = std::move(action),
                                .resource = operation.pack.value + ":" + std::to_string(operation.target_generation),
                                .outcome = std::move(outcome),
                                .detail = std::move(detail)};
        }

    } // namespace

    std::expected<AdminOperationRecord, StoreError>
    DurableActivationAdmin::preview_stage(const AdminMutationRequest &request, const GenerationSnapshot &generation) {
        if (auto valid = validate_mutation_request(request); !valid) {
            return std::unexpected(valid.error());
        }
        auto canonical = canonical_generation(generation);
        if (auto valid = validate_staged_generation(canonical); !valid) {
            return std::unexpected(valid.error());
        }
        if (canonical.request.rollback_from) {
            return std::unexpected(invalid("ordinary stage preview cannot contain rollback metadata"));
        }
        auto fingerprint = control_serialization::encode(canonical);
        if (!fingerprint) {
            return std::unexpected(invalid("stage preview could not be canonicalized: " + fingerprint.error().message));
        }
        auto idempotent = resolve_preview_idempotency(store_, request, AdminOperationKind::stage,
                                                      canonical.request.pack, *fingerprint);
        if (!idempotent) {
            return std::unexpected(idempotent.error());
        }
        if (*idempotent) {
            return **idempotent;
        }
        auto state = store_.load_state();
        if (!state) {
            return std::unexpected(state.error());
        }
        if (pack_version(*state, canonical.request.pack) != request.expected_pack_version) {
            return std::unexpected(stale("stage preview uses a stale pack resource version"));
        }
        if (auto transition = validate_state_transition(*state, canonical.request); !transition) {
            return std::unexpected(transition.error());
        }
        if (!generation_number_available(*state, canonical.request.pack, canonical.request.generation)) {
            return std::unexpected(invalid("generation number is already used or does not increase monotonically"));
        }
        AdminOperationRecord operation {.operation_id = request.operation_id,
                                        .request_id = request.request_id,
                                        .idempotency_key = request.idempotency_key,
                                        .request_fingerprint = std::move(*fingerprint),
                                        .actor = request.actor,
                                        .reason = request.reason,
                                        .kind = AdminOperationKind::stage,
                                        .phase = AdminOperationPhase::previewed,
                                        .pack = canonical.request.pack,
                                        .target_generation = canonical.request.generation,
                                        .rollback_source_generation = std::nullopt,
                                        .previous_active_generation = std::nullopt,
                                        .state_transition = canonical.request.state_transition,
                                        .expected_pack_version = request.expected_pack_version,
                                        .created_at_unix_ms = request.at_unix_ms,
                                        .updated_at_unix_ms = request.at_unix_ms,
                                        .drain_boundary = std::nullopt,
                                        .requeued_work = {},
                                        .result = std::nullopt,
                                        .failure = {}};
        const auto expected_storage_revision = state->storage_revision;
        auto audit =
            admin_audit(request.at_unix_ms, operation, "admin.pack.stage.preview", "previewed", request.reason);
        if (auto committed =
                commit_transition(store_, expected_storage_revision, std::move(*state), operation, std::move(audit));
            !committed) {
            return std::unexpected(committed.error());
        }
        return operation;
    }

    std::expected<GenerationSnapshot, StoreError>
    DurableActivationAdmin::apply_stage(const AdminApplyRequest &request, const GenerationSnapshot &generation) {
        auto operation = load_apply_operation(store_, request);
        if (!operation) {
            return std::unexpected(operation.error());
        }
        auto canonical = canonical_generation(generation);
        auto fingerprint = control_serialization::encode(canonical);
        if (!fingerprint || operation->request_fingerprint != *fingerprint) {
            return std::unexpected(invalid("stage apply does not match its preview"));
        }
        if (operation->kind != AdminOperationKind::stage) {
            return std::unexpected(invalid("operation is not a stage preview"));
        }
        auto state = store_.load_state();
        if (!state) {
            return std::unexpected(state.error());
        }
        if (operation->phase == AdminOperationPhase::applied) {
            const auto *existing = find_generation(*state, operation->pack, operation->target_generation);
            if (existing == nullptr) {
                return std::unexpected(invalid("applied stage metadata is missing"));
            }
            return *existing;
        }
        if (operation->phase != AdminOperationPhase::previewed ||
            request.expected_pack_version != operation->expected_pack_version ||
            pack_version(*state, operation->pack) != request.expected_pack_version) {
            return std::unexpected(stale("stage apply uses a stale pack resource version"));
        }
        if (auto transition = validate_state_transition(*state, canonical.request); !transition) {
            return std::unexpected(transition.error());
        }
        if (auto valid = validate_staged_generation(canonical); !valid) {
            return std::unexpected(valid.error());
        }
        if (!generation_number_available(*state, operation->pack, operation->target_generation)) {
            return std::unexpected(invalid("generation number became unavailable after preview"));
        }
        auto &pack = ensure_pack(*state, operation->pack);
        if (auto advanced = advance_pack(pack); !advanced) {
            return std::unexpected(advanced.error());
        }
        state->generations.push_back(canonical);
        operation->phase = AdminOperationPhase::applied;
        operation->expected_pack_version = pack.resource_version;
        operation->updated_at_unix_ms = request.at_unix_ms;
        const auto expected_storage_revision = state->storage_revision;
        auto audit = admin_audit(request.at_unix_ms, *operation, "admin.pack.stage.apply", "staged", operation->reason);
        if (auto committed =
                commit_transition(store_, expected_storage_revision, std::move(*state), *operation, std::move(audit));
            !committed) {
            return std::unexpected(committed.error());
        }
        return canonical;
    }

    std::expected<AdminOperationRecord, StoreError>
    DurableActivationAdmin::preview_server_stage(const AdminMutationRequest &request,
                                                 const GenerationRequest &generation) {
        if (auto valid = validate_mutation_request(request); !valid) {
            return std::unexpected(valid.error());
        }
        auto canonical = canonical_request(generation);
        if (auto valid = validate_server_stage_request(canonical); !valid) {
            return std::unexpected(valid.error());
        }
        auto fingerprint = control_serialization::stage_fingerprint(canonical);
        if (!fingerprint) {
            return std::unexpected(invalid("server-owned stage preview could not be canonicalized"));
        }
        auto idempotent =
            resolve_preview_idempotency(store_, request, AdminOperationKind::stage, canonical.pack, *fingerprint);
        if (!idempotent) {
            return std::unexpected(idempotent.error());
        }
        if (*idempotent) {
            return **idempotent;
        }
        auto state = store_.load_state();
        if (!state) {
            return std::unexpected(state.error());
        }
        if (pack_version(*state, canonical.pack) != request.expected_pack_version ||
            !generation_number_available(*state, canonical.pack, canonical.generation)) {
            return std::unexpected(stale("server-owned stage preview uses a stale pack version or generation"));
        }
        if (auto transition = validate_state_transition(*state, canonical); !transition) {
            return std::unexpected(transition.error());
        }
        AdminOperationRecord operation {.operation_id = request.operation_id,
                                        .request_id = request.request_id,
                                        .idempotency_key = request.idempotency_key,
                                        .request_fingerprint = std::move(*fingerprint),
                                        .actor = request.actor,
                                        .reason = request.reason,
                                        .kind = AdminOperationKind::stage,
                                        .phase = AdminOperationPhase::previewed,
                                        .pack = canonical.pack,
                                        .target_generation = canonical.generation,
                                        .rollback_source_generation = std::nullopt,
                                        .previous_active_generation = std::nullopt,
                                        .state_transition = canonical.state_transition,
                                        .expected_pack_version = request.expected_pack_version,
                                        .created_at_unix_ms = request.at_unix_ms,
                                        .updated_at_unix_ms = request.at_unix_ms,
                                        .drain_boundary = std::nullopt,
                                        .requeued_work = {},
                                        .result = std::nullopt,
                                        .failure = {}};
        const auto expected_storage_revision = state->storage_revision;
        auto audit =
            admin_audit(request.at_unix_ms, operation, "admin.pack.stage.preview", "previewed", request.reason);
        if (auto committed =
                commit_transition(store_, expected_storage_revision, std::move(*state), operation, std::move(audit));
            !committed) {
            return std::unexpected(committed.error());
        }
        return operation;
    }

    std::expected<GenerationSnapshot, StoreError>
    DurableActivationAdmin::begin_server_stage(const AdminApplyRequest &request, const GenerationRequest &generation) {
        auto operation = load_apply_operation(store_, request);
        if (!operation) {
            return std::unexpected(operation.error());
        }
        auto canonical = canonical_request(generation);
        auto fingerprint = control_serialization::stage_fingerprint(canonical);
        if (!fingerprint || operation->request_fingerprint != *fingerprint ||
            operation->kind != AdminOperationKind::stage) {
            return std::unexpected(invalid("server-owned stage apply does not match its preview"));
        }
        auto state = store_.load_state();
        if (!state) {
            return std::unexpected(state.error());
        }
        if (const auto *existing = find_generation(*state, operation->pack, operation->target_generation);
            existing != nullptr) {
            if (existing->request.pack != canonical.pack || existing->request.generation != canonical.generation ||
                existing->request.source_digest != canonical.source_digest) {
                return std::unexpected(invalid("server-owned stage retry changed durable generation metadata"));
            }
            return *existing;
        }
        if (operation->phase != AdminOperationPhase::previewed ||
            request.expected_pack_version != operation->expected_pack_version ||
            pack_version(*state, operation->pack) != request.expected_pack_version ||
            !generation_number_available(*state, operation->pack, operation->target_generation)) {
            return std::unexpected(stale("server-owned stage apply uses a stale pack version or generation"));
        }
        if (auto valid = validate_server_stage_request(canonical); !valid) {
            return std::unexpected(valid.error());
        }
        if (auto transition = validate_state_transition(*state, canonical); !transition) {
            return std::unexpected(transition.error());
        }
        auto nodes = store_.node_snapshot();
        if (!nodes) {
            return std::unexpected(nodes.error());
        }
        GenerationSnapshot snapshot {.request = canonical,
                                     .phase = GenerationPhase::compiling,
                                     .target_nodes = {},
                                     .targets = {},
                                     .reports = {},
                                     .semantic_hash = {},
                                     .binding_hash = {},
                                     .requeued_work = {},
                                     .failure = {}};
        for (const auto &node : *nodes) {
            const auto capabilities_match =
                std::ranges::all_of(canonical.required_capability_hashes, [&](const auto &required) {
                    return std::ranges::binary_search(node.capability_hashes, required);
                });
            if (!node.serving || node.lease_until_unix_ms <= request.at_unix_ms || !capabilities_match) {
                continue;
            }
            snapshot.target_nodes.push_back(node.node_id);
            snapshot.targets.push_back(StageTargetNode {.node_id = node.node_id,
                                                        .platform_abi = node.platform_abi,
                                                        .lease_fence = node.lease_fence,
                                                        .lease_until_unix_ms = node.lease_until_unix_ms,
                                                        .capability_hashes = node.capability_hashes});
        }
        snapshot = canonical_generation(std::move(snapshot));
        if (snapshot.targets.empty()) {
            return std::unexpected(
                control_error(StoreErrorCode::unavailable, "no eligible serving resident nodes are available", true));
        }
        auto &pack = ensure_pack(*state, operation->pack);
        if (auto advanced = advance_pack(pack); !advanced) {
            return std::unexpected(advanced.error());
        }
        state->generations.push_back(snapshot);
        operation->expected_pack_version = pack.resource_version;
        operation->updated_at_unix_ms = request.at_unix_ms;
        const auto expected_storage_revision = state->storage_revision;
        auto audit = admin_audit(request.at_unix_ms, *operation, "admin.pack.stage.apply", "compiling",
                                 std::to_string(snapshot.targets.size()));
        if (auto committed =
                commit_transition(store_, expected_storage_revision, std::move(*state), *operation, std::move(audit));
            !committed) {
            return std::unexpected(committed.error());
        }
        return snapshot;
    }

    std::expected<GenerationSnapshot, StoreError>
    DurableActivationAdmin::report_server_compilation(const std::string_view operation_id,
                                                      const CompilationReport &report, const std::uint64_t at_unix_ms) {
        auto operation = store_.find_operation(operation_id);
        if (!operation) {
            return std::unexpected(operation.error());
        }
        if (!*operation || (*operation)->kind != AdminOperationKind::stage || at_unix_ms == 0U) {
            return std::unexpected(invalid("server compilation report does not name a stage operation"));
        }
        auto state = store_.load_state();
        if (!state) {
            return std::unexpected(state.error());
        }
        auto *generation = find_generation(*state, (*operation)->pack, (*operation)->target_generation);
        auto *pack = find_pack(*state, (*operation)->pack);
        if (generation == nullptr || pack == nullptr) {
            return std::unexpected(invalid("server compilation report generation is missing"));
        }
        auto canonical_report = report;
        canonical_report.capability_hashes = normalized(std::move(canonical_report.capability_hashes));
        const auto target = std::ranges::find(generation->targets, canonical_report.node_id, &StageTargetNode::node_id);
        if (target == generation->targets.end() || canonical_report.node_lease_fence != target->lease_fence) {
            return std::unexpected(stale("server compilation report does not match the frozen target lease"));
        }
        const auto existing =
            std::ranges::find(generation->reports, canonical_report.node_id, &CompilationReport::node_id);
        if (existing != generation->reports.end()) {
            if (existing->node_lease_fence != canonical_report.node_lease_fence ||
                existing->success != canonical_report.success ||
                existing->semantic_hash != canonical_report.semantic_hash ||
                existing->binding_hash != canonical_report.binding_hash ||
                existing->executable_hash != canonical_report.executable_hash ||
                existing->capability_hashes != canonical_report.capability_hashes) {
                return std::unexpected(invalid("server compilation report retry changed durable evidence"));
            }
            return *generation;
        }
        if ((*operation)->phase != AdminOperationPhase::previewed || generation->phase != GenerationPhase::compiling) {
            return std::unexpected(invalid("stage operation no longer accepts compilation reports"));
        }
        auto nodes = store_.node_snapshot();
        if (!nodes) {
            return std::unexpected(nodes.error());
        }
        const auto node = std::ranges::find(*nodes, canonical_report.node_id, &DurableResidentNode::node_id);
        if (node == nodes->end() || !node->serving || node->lease_fence != target->lease_fence ||
            node->lease_until_unix_ms <= at_unix_ms || node->platform_abi != target->platform_abi ||
            node->capability_hashes != target->capability_hashes) {
            return std::unexpected(stale("server compilation report target lease is no longer current"));
        }
        if (canonical_report.success &&
            (canonical_report.semantic_hash.empty() || canonical_report.binding_hash.empty() ||
             canonical_report.executable_hash.empty() ||
             !std::ranges::all_of(generation->request.required_capability_hashes, [&](const auto &required) {
                 return std::ranges::binary_search(canonical_report.capability_hashes, required);
             }))) {
            return std::unexpected(invalid("successful server compilation report is incomplete"));
        }
        if (canonical_report.success && !generation->reports.empty() &&
            (generation->semantic_hash != canonical_report.semantic_hash ||
             generation->binding_hash != canonical_report.binding_hash)) {
            canonical_report.success = false;
        }
        generation->reports.push_back(std::move(canonical_report));
        std::ranges::sort(generation->reports, {}, &CompilationReport::node_id);
        if (!generation->reports.back().success ||
            std::ranges::any_of(generation->reports, [](const auto &candidate) { return !candidate.success; })) {
            generation->phase = GenerationPhase::failed;
            generation->failure = "resident compilation failed or disagreed";
            (*operation)->phase = AdminOperationPhase::failed;
            (*operation)->failure = generation->failure;
        } else {
            generation->semantic_hash = generation->reports.front().semantic_hash;
            generation->binding_hash = generation->reports.front().binding_hash;
            if (generation->reports.size() == generation->targets.size()) {
                generation->phase = GenerationPhase::ready;
                (*operation)->phase = AdminOperationPhase::staged;
            }
        }
        if (auto advanced = advance_pack(*pack); !advanced) {
            return std::unexpected(advanced.error());
        }
        (*operation)->expected_pack_version = pack->resource_version;
        (*operation)->updated_at_unix_ms = at_unix_ms;
        const auto expected_storage_revision = state->storage_revision;
        const auto outcome = (*operation)->phase == AdminOperationPhase::failed ? "failed" :
                             (*operation)->phase == AdminOperationPhase::staged ? "staged" :
                                                                                  "compiling";
        auto audit = admin_audit(at_unix_ms, **operation, "resident.pack.stage.report", outcome,
                                 std::to_string(generation->reports.size()));
        auto result = *generation;
        if (auto committed =
                commit_transition(store_, expected_storage_revision, std::move(*state), **operation, std::move(audit));
            !committed) {
            return std::unexpected(committed.error());
        }
        return result;
    }

    std::expected<AdminOperationRecord, StoreError>
    DurableActivationAdmin::preview_activation(const AdminMutationRequest &request, const PackId &pack,
                                               const std::uint64_t target_generation) {
        if (auto valid = validate_mutation_request(request); !valid) {
            return std::unexpected(valid.error());
        }
        if (pack.empty() || target_generation == 0) {
            return std::unexpected(invalid("activation preview requires a pack and generation"));
        }
        auto fingerprint = control_serialization::activation_fingerprint(pack, target_generation);
        if (!fingerprint) {
            return std::unexpected(invalid("activation preview could not be canonicalized"));
        }
        auto idempotent =
            resolve_preview_idempotency(store_, request, AdminOperationKind::activate, pack, *fingerprint);
        if (!idempotent) {
            return std::unexpected(idempotent.error());
        }
        if (*idempotent) {
            return **idempotent;
        }
        auto state = store_.load_state();
        if (!state) {
            return std::unexpected(state.error());
        }
        const auto *target = find_generation(*state, pack, target_generation);
        const auto *control = find_pack(*state, pack);
        if (target == nullptr || target->phase != GenerationPhase::ready) {
            return std::unexpected(invalid("activation target is not a staged ready generation"));
        }
        if (pack_version(*state, pack) != request.expected_pack_version) {
            return std::unexpected(stale("activation preview uses a stale pack resource version"));
        }
        if (auto transition = validate_state_transition(*state, target->request); !transition) {
            return std::unexpected(transition.error());
        }
        if (control != nullptr && control->drain_target) {
            return std::unexpected(
                control_error(StoreErrorCode::conflict, "another activation drain is already in progress", true));
        }
        AdminOperationRecord operation {.operation_id = request.operation_id,
                                        .request_id = request.request_id,
                                        .idempotency_key = request.idempotency_key,
                                        .request_fingerprint = std::move(*fingerprint),
                                        .actor = request.actor,
                                        .reason = request.reason,
                                        .kind = AdminOperationKind::activate,
                                        .phase = AdminOperationPhase::previewed,
                                        .pack = pack,
                                        .target_generation = target_generation,
                                        .rollback_source_generation = std::nullopt,
                                        .previous_active_generation = std::nullopt,
                                        .state_transition = target->request.state_transition,
                                        .expected_pack_version = request.expected_pack_version,
                                        .created_at_unix_ms = request.at_unix_ms,
                                        .updated_at_unix_ms = request.at_unix_ms,
                                        .drain_boundary = std::nullopt,
                                        .requeued_work = {},
                                        .result = std::nullopt,
                                        .failure = {}};
        const auto expected_storage_revision = state->storage_revision;
        auto audit =
            admin_audit(request.at_unix_ms, operation, "admin.pack.activate.preview", "previewed", request.reason);
        if (auto committed =
                commit_transition(store_, expected_storage_revision, std::move(*state), operation, std::move(audit));
            !committed) {
            return std::unexpected(committed.error());
        }
        return operation;
    }

    std::expected<DrainReceipt, StoreError> DurableActivationAdmin::begin_drain(const AdminApplyRequest &request,
                                                                                const std::uint64_t drain_boundary) {
        auto operation = load_apply_operation(store_, request);
        if (!operation) {
            return std::unexpected(operation.error());
        }
        if (operation->kind != AdminOperationKind::activate && operation->kind != AdminOperationKind::rollback) {
            return std::unexpected(invalid("operation cannot begin an activation drain"));
        }
        if (operation->phase == AdminOperationPhase::draining || operation->phase == AdminOperationPhase::fenced ||
            operation->phase == AdminOperationPhase::applied) {
            if (operation->drain_boundary != drain_boundary) {
                return std::unexpected(invalid("drain retry changed the durable boundary"));
            }
            auto state = store_.load_state();
            if (!state) {
                return std::unexpected(state.error());
            }
            const auto *pack = find_pack(*state, operation->pack);
            if (pack == nullptr) {
                return std::unexpected(invalid("durable pack control is missing"));
            }
            return DrainReceipt {.pack = operation->pack,
                                 .old_generation = operation->previous_active_generation,
                                 .target_generation = operation->target_generation,
                                 .drain_boundary = drain_boundary,
                                 .successor_assignment_fence = pack->assignment_fence,
                                 .in_flight_work = operation->requeued_work};
        }
        const auto expected_phase = operation->kind == AdminOperationKind::rollback ? AdminOperationPhase::staged :
                                                                                      AdminOperationPhase::previewed;
        if (operation->phase != expected_phase) {
            return std::unexpected(invalid("operation is not ready to begin draining"));
        }
        auto state = store_.load_state();
        if (!state) {
            return std::unexpected(state.error());
        }
        auto *target = find_generation(*state, operation->pack, operation->target_generation);
        auto *control = find_pack(*state, operation->pack);
        if (target == nullptr || target->phase != GenerationPhase::ready || control == nullptr) {
            return std::unexpected(invalid("activation target or pack control is not ready"));
        }
        if (request.expected_pack_version != operation->expected_pack_version ||
            control->resource_version != request.expected_pack_version) {
            return std::unexpected(stale("drain apply uses a stale pack resource version"));
        }
        if (auto transition = validate_state_transition(*state, target->request); !transition) {
            return std::unexpected(transition.error());
        }
        if (control->drain_target) {
            return std::unexpected(
                control_error(StoreErrorCode::conflict, "another activation drain is already in progress", true));
        }
        operation->previous_active_generation = control->active_generation;
        if (control->active_generation) {
            auto *active = find_generation(*state, operation->pack, *control->active_generation);
            if (active == nullptr || active->phase != GenerationPhase::active) {
                return std::unexpected(invalid("active generation metadata is inconsistent"));
            }
            active->phase = GenerationPhase::draining;
        }
        if (auto advanced = advance_assignment_fence(*control); !advanced) {
            return std::unexpected(advanced.error());
        }
        if (auto advanced = advance_pack(*control); !advanced) {
            return std::unexpected(advanced.error());
        }
        control->accepting_assignments = false;
        control->drain_boundary = drain_boundary;
        control->drain_target = operation->target_generation;
        operation->phase = AdminOperationPhase::draining;
        operation->drain_boundary = drain_boundary;
        operation->expected_pack_version = control->resource_version;
        operation->updated_at_unix_ms = request.at_unix_ms;
        const DrainReceipt receipt {.pack = operation->pack,
                                    .old_generation = operation->previous_active_generation,
                                    .target_generation = operation->target_generation,
                                    .drain_boundary = drain_boundary,
                                    .successor_assignment_fence = control->assignment_fence,
                                    .in_flight_work = {}};
        const auto expected_storage_revision = state->storage_revision;
        auto audit = admin_audit(request.at_unix_ms, *operation, "admin.pack.activate.drain", "draining",
                                 std::to_string(drain_boundary));
        if (auto committed =
                commit_transition(store_, expected_storage_revision, std::move(*state), *operation, std::move(audit));
            !committed) {
            return std::unexpected(committed.error());
        }
        return receipt;
    }

    std::expected<std::vector<std::string>, StoreError>
    DurableActivationAdmin::fence_stragglers(const AdminApplyRequest &request, std::vector<std::string> work_ids) {
        auto operation = load_apply_operation(store_, request);
        if (!operation) {
            return std::unexpected(operation.error());
        }
        work_ids = normalized(std::move(work_ids));
        if (std::ranges::any_of(work_ids, [](const std::string &work_id) { return work_id.empty(); })) {
            return std::unexpected(invalid("straggler work IDs cannot be empty"));
        }
        if (operation->phase == AdminOperationPhase::fenced || operation->phase == AdminOperationPhase::applied) {
            if (operation->requeued_work != work_ids) {
                return std::unexpected(invalid("fence retry changed the durable requeue set"));
            }
            return work_ids;
        }
        if (operation->phase != AdminOperationPhase::draining || !operation->drain_boundary) {
            return std::unexpected(invalid("operation is not draining"));
        }
        auto state = store_.load_state();
        if (!state) {
            return std::unexpected(state.error());
        }
        auto *control = find_pack(*state, operation->pack);
        auto *target = find_generation(*state, operation->pack, operation->target_generation);
        if (control == nullptr || target == nullptr || control->drain_target != operation->target_generation ||
            control->drain_boundary != operation->drain_boundary) {
            return std::unexpected(invalid("durable drain state is inconsistent"));
        }
        if (request.expected_pack_version != operation->expected_pack_version ||
            control->resource_version != request.expected_pack_version) {
            return std::unexpected(stale("fence apply uses a stale pack resource version"));
        }
        if (auto advanced = advance_assignment_fence(*control); !advanced) {
            return std::unexpected(advanced.error());
        }
        if (auto advanced = advance_pack(*control); !advanced) {
            return std::unexpected(advanced.error());
        }
        control->pending_requeues = normalized([&] {
            auto combined = control->pending_requeues;
            combined.insert(combined.end(), work_ids.begin(), work_ids.end());
            return combined;
        }());
        target->requeued_work = normalized([&] {
            auto combined = target->requeued_work;
            combined.insert(combined.end(), work_ids.begin(), work_ids.end());
            return combined;
        }());
        operation->phase = AdminOperationPhase::fenced;
        operation->requeued_work = work_ids;
        operation->expected_pack_version = control->resource_version;
        operation->updated_at_unix_ms = request.at_unix_ms;
        const auto expected_storage_revision = state->storage_revision;
        auto audit = admin_audit(request.at_unix_ms, *operation, "admin.pack.activate.fence", "fenced",
                                 std::to_string(work_ids.size()));
        if (auto committed =
                commit_transition(store_, expected_storage_revision, std::move(*state), *operation, std::move(audit));
            !committed) {
            return std::unexpected(committed.error());
        }
        return work_ids;
    }

    std::expected<ActivationReceipt, StoreError> DurableActivationAdmin::flip(const AdminApplyRequest &request) {
        auto operation = load_apply_operation(store_, request);
        if (!operation) {
            return std::unexpected(operation.error());
        }
        if (operation->phase == AdminOperationPhase::applied && operation->result) {
            return *operation->result;
        }
        if (operation->phase != AdminOperationPhase::fenced || !operation->drain_boundary) {
            return std::unexpected(invalid("operation must be explicitly fenced before flip"));
        }
        auto state = store_.load_state();
        if (!state) {
            return std::unexpected(state.error());
        }
        auto *control = find_pack(*state, operation->pack);
        auto *target = find_generation(*state, operation->pack, operation->target_generation);
        if (control == nullptr || target == nullptr || target->phase != GenerationPhase::ready ||
            control->drain_target != operation->target_generation ||
            control->drain_boundary != operation->drain_boundary ||
            control->active_generation != operation->previous_active_generation) {
            return std::unexpected(invalid("activation state is not ready for atomic flip"));
        }
        if (request.expected_pack_version != operation->expected_pack_version ||
            control->resource_version != request.expected_pack_version) {
            return std::unexpected(stale("flip uses a stale pack resource version"));
        }
        if (operation->previous_active_generation) {
            auto *old = find_generation(*state, operation->pack, *operation->previous_active_generation);
            if (old == nullptr || old->phase != GenerationPhase::draining) {
                return std::unexpected(invalid("old generation is not durably draining"));
            }
            old->phase = GenerationPhase::retired;
        }
        target->phase = GenerationPhase::active;
        control->active_generation = operation->target_generation;
        control->accepting_assignments = true;
        control->drain_boundary.reset();
        control->drain_target.reset();
        if (auto advanced = advance_pack(*control); !advanced) {
            return std::unexpected(advanced.error());
        }
        ActivationReceipt receipt {.pack = operation->pack,
                                   .retired_generation = operation->previous_active_generation,
                                   .active_generation = operation->target_generation,
                                   .activation_cursor = *operation->drain_boundary,
                                   .assignment_fence = control->assignment_fence,
                                   .requeued_work = control->pending_requeues};
        control->pending_requeues.clear();
        operation->phase = AdminOperationPhase::applied;
        operation->result = receipt;
        operation->expected_pack_version = control->resource_version;
        operation->updated_at_unix_ms = request.at_unix_ms;
        const auto expected_storage_revision = state->storage_revision;
        auto audit = admin_audit(request.at_unix_ms, *operation, "admin.pack.activate.flip", "active",
                                 std::to_string(receipt.activation_cursor));
        if (auto committed =
                commit_transition(store_, expected_storage_revision, std::move(*state), *operation, std::move(audit));
            !committed) {
            return std::unexpected(committed.error());
        }
        return receipt;
    }

    std::expected<AdminOperationRecord, StoreError>
    DurableActivationAdmin::preview_rollback(const AdminMutationRequest &request, const PackId &pack,
                                             const std::uint64_t source_generation, const std::uint64_t new_generation,
                                             const StateTransitionPlan &state_transition) {
        if (auto valid = validate_mutation_request(request); !valid) {
            return std::unexpected(valid.error());
        }
        if (pack.empty() || source_generation == 0 || new_generation == 0) {
            return std::unexpected(invalid("rollback pack and generation identities are required"));
        }
        auto fingerprint =
            control_serialization::rollback_fingerprint(pack, source_generation, new_generation, state_transition);
        if (!fingerprint) {
            return std::unexpected(invalid("rollback preview could not be canonicalized"));
        }
        auto idempotent =
            resolve_preview_idempotency(store_, request, AdminOperationKind::rollback, pack, *fingerprint);
        if (!idempotent) {
            return std::unexpected(idempotent.error());
        }
        if (*idempotent) {
            return **idempotent;
        }
        auto state = store_.load_state();
        if (!state) {
            return std::unexpected(state.error());
        }
        const auto *control = find_pack(*state, pack);
        const auto *source = find_generation(*state, pack, source_generation);
        if (control == nullptr || !control->active_generation || control->drain_target || source == nullptr ||
            source->phase != GenerationPhase::retired || *control->active_generation == source_generation) {
            return std::unexpected(invalid("rollback source, active generation, or control state is invalid"));
        }
        const auto *active = find_generation(*state, pack, *control->active_generation);
        if (active == nullptr || active->phase != GenerationPhase::active) {
            return std::unexpected(invalid("rollback active generation metadata is inconsistent"));
        }
        if (control->resource_version != request.expected_pack_version ||
            !generation_number_available(*state, pack, new_generation)) {
            return std::unexpected(stale("rollback preview uses a stale pack version or generation number"));
        }
        auto transition = canonical_rollback_transition(state_transition, *source, *active);
        if (!transition) {
            return std::unexpected(transition.error());
        }
        auto rollback_request = source->request;
        rollback_request.generation = new_generation;
        rollback_request.state_namespace = transition->target_namespace;
        rollback_request.state_transition = *transition;
        rollback_request.rollback_from = source_generation;
        if (auto compatible = validate_state_transition(*state, rollback_request); !compatible) {
            return std::unexpected(compatible.error());
        }
        AdminOperationRecord operation {.operation_id = request.operation_id,
                                        .request_id = request.request_id,
                                        .idempotency_key = request.idempotency_key,
                                        .request_fingerprint = std::move(*fingerprint),
                                        .actor = request.actor,
                                        .reason = request.reason,
                                        .kind = AdminOperationKind::rollback,
                                        .phase = AdminOperationPhase::previewed,
                                        .pack = pack,
                                        .target_generation = new_generation,
                                        .rollback_source_generation = source_generation,
                                        .previous_active_generation = std::nullopt,
                                        .state_transition = *transition,
                                        .expected_pack_version = request.expected_pack_version,
                                        .created_at_unix_ms = request.at_unix_ms,
                                        .updated_at_unix_ms = request.at_unix_ms,
                                        .drain_boundary = std::nullopt,
                                        .requeued_work = {},
                                        .result = std::nullopt,
                                        .failure = {}};
        const auto expected_storage_revision = state->storage_revision;
        auto audit =
            admin_audit(request.at_unix_ms, operation, "admin.pack.rollback.preview", "previewed", request.reason);
        if (auto committed =
                commit_transition(store_, expected_storage_revision, std::move(*state), operation, std::move(audit));
            !committed) {
            return std::unexpected(committed.error());
        }
        return operation;
    }

    std::expected<GenerationSnapshot, StoreError>
    DurableActivationAdmin::apply_rollback_stage(const AdminApplyRequest &request,
                                                 const GenerationSnapshot &generation) {
        auto operation = load_apply_operation(store_, request);
        if (!operation) {
            return std::unexpected(operation.error());
        }
        if (operation->kind != AdminOperationKind::rollback) {
            return std::unexpected(invalid("operation is not a rollback preview"));
        }
        auto canonical = canonical_generation(generation);
        auto state = store_.load_state();
        if (!state) {
            return std::unexpected(state.error());
        }
        if (operation->phase == AdminOperationPhase::staged || operation->phase == AdminOperationPhase::draining ||
            operation->phase == AdminOperationPhase::fenced || operation->phase == AdminOperationPhase::applied) {
            const auto *existing = find_generation(*state, operation->pack, operation->target_generation);
            if (existing == nullptr) {
                return std::unexpected(invalid("durable rollback generation metadata is missing"));
            }
            const auto encoded_existing = control_serialization::encode(*existing);
            const auto encoded_candidate = control_serialization::encode(canonical);
            if (!encoded_existing || !encoded_candidate || *encoded_existing != *encoded_candidate) {
                return std::unexpected(invalid("rollback stage retry changed the durable generation metadata"));
            }
            return *existing;
        }
        if (operation->phase != AdminOperationPhase::previewed ||
            request.expected_pack_version != operation->expected_pack_version ||
            pack_version(*state, operation->pack) != request.expected_pack_version) {
            return std::unexpected(stale("rollback stage uses a stale pack resource version"));
        }
        if (auto valid = validate_staged_generation(canonical); !valid) {
            return std::unexpected(valid.error());
        }
        if (auto transition = validate_state_transition(*state, canonical.request); !transition) {
            return std::unexpected(transition.error());
        }
        const auto *source = operation->rollback_source_generation ?
                                 find_generation(*state, operation->pack, *operation->rollback_source_generation) :
                                 nullptr;
        if (source == nullptr || source->phase != GenerationPhase::retired ||
            canonical.request.pack != operation->pack || canonical.request.generation != operation->target_generation ||
            canonical.request.rollback_from != operation->rollback_source_generation ||
            canonical.request.version != source->request.version ||
            canonical.request.source_digest != source->request.source_digest ||
            canonical.request.state_schema_hash != source->request.state_schema_hash ||
            canonical.semantic_hash != source->semantic_hash || canonical.binding_hash != source->binding_hash ||
            canonical.request.state_namespace != operation->state_transition.target_namespace ||
            !transition_matches(canonical.request.state_transition, operation->state_transition) ||
            canonical.request.required_capability_hashes != source->request.required_capability_hashes ||
            !generation_number_available(*state, operation->pack, operation->target_generation)) {
            return std::unexpected(invalid("rollback stage does not match its retained source and preview"));
        }
        auto &pack = ensure_pack(*state, operation->pack);
        if (auto advanced = advance_pack(pack); !advanced) {
            return std::unexpected(advanced.error());
        }
        state->generations.push_back(canonical);
        operation->phase = AdminOperationPhase::staged;
        operation->expected_pack_version = pack.resource_version;
        operation->updated_at_unix_ms = request.at_unix_ms;
        const auto expected_storage_revision = state->storage_revision;
        auto audit =
            admin_audit(request.at_unix_ms, *operation, "admin.pack.rollback.stage", "staged", operation->reason);
        if (auto committed =
                commit_transition(store_, expected_storage_revision, std::move(*state), *operation, std::move(audit));
            !committed) {
            return std::unexpected(committed.error());
        }
        return canonical;
    }

    std::expected<DurableControlState, StoreError> DurableActivationAdmin::state_snapshot() const {
        return store_.load_state();
    }

    std::expected<std::optional<AdminOperationRecord>, StoreError>
    DurableActivationAdmin::operation_snapshot(const std::string_view operation_id) const {
        return store_.find_operation(operation_id);
    }

    std::expected<ControlPlaneInspection, StoreError> DurableActivationAdmin::inspect() const {
        return store_.inspect();
    }

} // namespace rule_engine::python::cluster
