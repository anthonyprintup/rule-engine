#include "rule_engine/python/cluster/activation.hpp"

#include <algorithm>
#include <set>
#include <utility>

namespace rule_engine::python::cluster {
    namespace {

        std::vector<std::string> normalized(std::vector<std::string> values) {
            std::ranges::sort(values);
            values.erase(std::ranges::unique(values).begin(), values.end());
            return values;
        }

        bool compilation_matches(const CompilationReport &left, const CompilationReport &right) {
            return left.node_id == right.node_id && left.node_lease_fence == right.node_lease_fence &&
                   left.success == right.success && left.semantic_hash == right.semantic_hash &&
                   left.binding_hash == right.binding_hash && left.executable_hash == right.executable_hash &&
                   normalized(left.capability_hashes) == normalized(right.capability_hashes);
        }

        std::string generation_resource(const PackId &pack, const std::uint64_t generation) {
            return pack.value + ":" + std::to_string(generation);
        }

    } // namespace

    std::expected<void, StoreError> qualify_resident_compilation(const GenerationSnapshot &generation,
                                                                 const std::string_view node_id,
                                                                 const std::string_view platform_abi,
                                                                 const CompiledPack &compiled) {
        const auto reject = [](const StoreErrorCode code, std::string message) {
            return std::unexpected(StoreError {.code = code, .message = std::move(message), .retryable = false});
        };
        if (node_id.empty() || platform_abi.empty()) {
            return reject(StoreErrorCode::constraint_violation,
                          "resident compilation qualification identity is invalid");
        }
        if (generation.phase != GenerationPhase::active) {
            return reject(StoreErrorCode::stale_fence, "resident generation is not active");
        }
        if (compiled.pack != generation.request.pack || compiled.version != generation.request.version ||
            compiled.source_digest != generation.request.source_digest ||
            compiled.compiler_abi != python_static_compiler_abi_v1) {
            return reject(StoreErrorCode::constraint_violation,
                          "resident compiled pack does not match the durable source generation");
        }
        const auto report = std::ranges::find(generation.reports, node_id, &CompilationReport::node_id);
        if (report == generation.reports.end() || !report->success || report->node_lease_fence == 0U) {
            return reject(StoreErrorCode::stale_fence, "resident node has no successful staged compilation report");
        }
        const auto binding_hash = canonical_operator_bindings_hash(compiled.bindings);
        const auto executable_hash = compiled_pack_executable_hash(compiled, platform_abi);
        if (compiled.semantic_hash.empty() || generation.semantic_hash != compiled.semantic_hash ||
            generation.binding_hash != binding_hash || report->semantic_hash != compiled.semantic_hash ||
            report->binding_hash != binding_hash || report->executable_hash != executable_hash) {
            return reject(StoreErrorCode::incompatible_schema,
                          "resident compiler, binding, or executable identity differs from activation evidence");
        }
        return {};
    }

    StoreError ActivationController::error(const StoreErrorCode code, std::string message, const bool retryable) {
        return StoreError {.code = code, .message = std::move(message), .retryable = retryable};
    }

    std::expected<void, StoreError> ActivationController::register_node(const ClusterNode &node,
                                                                        const std::uint64_t now_unix_ms,
                                                                        const std::string_view actor) {
        if (node.node_id.empty() || node.platform_abi.empty() || node.lease_fence == 0) {
            return std::unexpected(error(StoreErrorCode::constraint_violation, "cluster node identity is invalid"));
        }

        std::unique_lock lock {mutex_};
        const auto current = nodes_.find(node.node_id);
        if (current != nodes_.end() && node.lease_fence < current->second.node.lease_fence) {
            return std::unexpected(error(StoreErrorCode::stale_fence, "node lease fence moved backward"));
        }
        if (current != nodes_.end() && node.lease_fence == current->second.node.lease_fence &&
            node.platform_abi != current->second.node.platform_abi) {
            return std::unexpected(
                error(StoreErrorCode::constraint_violation, "platform ABI changed under one node lease fence"));
        }

        if (current == nodes_.end()) {
            nodes_.emplace(node.node_id, NodeRecord {
                                             .node = node,
                                             .compiled_active_generations = {},
                                         });
        } else {
            if (node.lease_fence > current->second.node.lease_fence) {
                current->second.compiled_active_generations.clear();
            }
            current->second.node = node;
        }
        lock.unlock();
        static_cast<void>(audit_.append(now_unix_ms, actor, "node.register", node.node_id, "accepted",
                                        std::to_string(node.lease_fence)));
        return {};
    }

    std::expected<void, StoreError>
    ActivationController::validate_state_transition_locked(const GenerationRequest &request,
                                                           const PackControl &control) const {
        if (request.state_schema_hash.empty() || request.state_namespace.empty()) {
            return std::unexpected(
                error(StoreErrorCode::incompatible_schema, "generation state schema and namespace are required"));
        }
        if (!control.active_generation) {
            if (request.state_transition.mode == StateTransitionMode::retained_gap) {
                return std::unexpected(error(StoreErrorCode::incompatible_schema,
                                             "retained state cannot be selected without an active generation"));
            }
            return {};
        }

        const auto current =
            generations_.find(GenerationKey {.pack = request.pack, .generation = *control.active_generation});
        if (current == generations_.end()) {
            return std::unexpected(
                error(StoreErrorCode::constraint_violation, "active generation metadata is missing"));
        }
        const auto same_schema = current->second.request.state_schema_hash == request.state_schema_hash;
        switch (request.state_transition.mode) {
            case StateTransitionMode::carry:
                if (!same_schema || request.state_namespace != current->second.request.state_namespace) {
                    return std::unexpected(error(StoreErrorCode::incompatible_schema,
                                                 "state carry requires an identical schema and namespace"));
                }
                return {};
            case StateTransitionMode::migrate:
                if (same_schema || request.state_transition.migration_id.empty() ||
                    request.state_transition.source_namespace != current->second.request.state_namespace ||
                    request.state_transition.target_namespace != request.state_namespace) {
                    return std::unexpected(error(StoreErrorCode::incompatible_schema,
                                                 "state migration requires source, target, and migration identity"));
                }
                return {};
            case StateTransitionMode::reset:
                if (!request.state_transition.reset_authorized ||
                    request.state_transition.target_namespace != request.state_namespace) {
                    return std::unexpected(error(StoreErrorCode::incompatible_schema,
                                                 "state reset requires manifest authorization and target namespace"));
                }
                return {};
            case StateTransitionMode::retained_gap:
                if (!request.rollback_from || !request.state_transition.accept_state_gap ||
                    request.state_transition.target_namespace != request.state_namespace) {
                    return std::unexpected(
                        error(StoreErrorCode::incompatible_schema,
                              "retained state requires rollback identity and explicit gap acceptance"));
                }
                return {};
            default: return std::unexpected(error(StoreErrorCode::incompatible_schema, "unknown state transition"));
        }
    }

    std::expected<GenerationSnapshot, StoreError> ActivationController::begin_stage(const GenerationRequest &request,
                                                                                    const std::uint64_t now_unix_ms,
                                                                                    const std::string_view actor) {
        if (request.pack.empty() || request.version.empty() || request.source_digest.empty() ||
            request.generation == 0 || !request.signature_verified ||
            request.policy.version != "activation-policy.v1" || request.policy.bundle_hash.size() != 71U ||
            !request.policy.bundle_hash.starts_with("sha256:") ||
            !std::ranges::all_of(std::string_view {request.policy.bundle_hash}.substr(7U), [](const char character) {
                return (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f');
            })) {
            return std::unexpected(error(StoreErrorCode::constraint_violation,
                                         "generation requires verified source and complete identity"));
        }

        std::unique_lock lock {mutex_};
        const GenerationKey key {.pack = request.pack, .generation = request.generation};
        if (generations_.contains(key)) {
            return std::unexpected(
                error(StoreErrorCode::constraint_violation, "generation number is already registered"));
        }
        for (const auto &[existing, _] : generations_) {
            if (existing.pack == request.pack && existing.generation >= request.generation) {
                return std::unexpected(
                    error(StoreErrorCode::constraint_violation, "generation numbers must increase monotonically"));
            }
        }

        auto canonical_request = request;
        canonical_request.required_capability_hashes = normalized(canonical_request.required_capability_hashes);
        if (canonical_request.state_transition.target_namespace.empty()) {
            canonical_request.state_transition.target_namespace = canonical_request.state_namespace;
        }
        const auto control = controls_.find(request.pack);
        const PackControl empty_control;
        const auto &selected_control = control == controls_.end() ? empty_control : control->second;
        if (auto state = validate_state_transition_locked(canonical_request, selected_control); !state) {
            return std::unexpected(state.error());
        }

        std::vector<std::string> targets;
        for (const auto &[node_id, node] : nodes_) {
            if (node.node.healthy && node.node.serving) {
                targets.push_back(node_id);
            }
        }
        if (targets.empty()) {
            return std::unexpected(error(StoreErrorCode::unavailable, "no healthy serving nodes are available", true));
        }

        GenerationSnapshot snapshot {
            .request = std::move(canonical_request),
            .phase = GenerationPhase::compiling,
            .target_nodes = std::move(targets),
            .targets = {},
            .reports = {},
            .semantic_hash = {},
            .binding_hash = {},
            .requeued_work = {},
            .failure = {},
        };
        generations_.emplace(key, snapshot);
        controls_.try_emplace(request.pack);
        lock.unlock();
        static_cast<void>(audit_.append(now_unix_ms, actor, "pack.stage.begin",
                                        generation_resource(request.pack, request.generation), "compiling",
                                        std::to_string(snapshot.target_nodes.size())));
        return snapshot;
    }

    std::expected<void, StoreError> ActivationController::report_compilation(const PackId &pack,
                                                                             const std::uint64_t generation,
                                                                             const CompilationReport &report,
                                                                             const std::uint64_t now_unix_ms) {
        std::unique_lock lock {mutex_};
        const auto staged = generations_.find(GenerationKey {.pack = pack, .generation = generation});
        if (staged == generations_.end() || staged->second.phase != GenerationPhase::compiling) {
            return std::unexpected(error(StoreErrorCode::constraint_violation,
                                         "compilation report does not target a compiling generation"));
        }
        if (!std::ranges::contains(staged->second.target_nodes, report.node_id)) {
            return std::unexpected(
                error(StoreErrorCode::constraint_violation, "node is not in the frozen stage target set"));
        }
        const auto node = nodes_.find(report.node_id);
        if (node == nodes_.end() || node->second.node.lease_fence != report.node_lease_fence) {
            return std::unexpected(error(StoreErrorCode::stale_fence, "compilation report uses a stale node fence"));
        }
        if (const auto existing =
                std::ranges::find(staged->second.reports, report.node_id, &CompilationReport::node_id);
            existing != staged->second.reports.end()) {
            if (compilation_matches(*existing, report)) {
                return {};
            }
            return std::unexpected(error(StoreErrorCode::constraint_violation,
                                         "node reported different compilation evidence for one stage"));
        }

        auto canonical_report = report;
        canonical_report.capability_hashes = normalized(canonical_report.capability_hashes);
        staged->second.reports.push_back(std::move(canonical_report));
        lock.unlock();
        static_cast<void>(audit_.append(now_unix_ms, report.node_id, "pack.stage.report",
                                        generation_resource(pack, generation), report.success ? "compiled" : "failed",
                                        report.executable_hash));
        return {};
    }

    std::expected<GenerationSnapshot, StoreError> ActivationController::finalize_stage(const PackId &pack,
                                                                                       const std::uint64_t generation,
                                                                                       const std::uint64_t now_unix_ms,
                                                                                       const std::string_view actor) {
        std::unique_lock lock {mutex_};
        const auto staged = generations_.find(GenerationKey {.pack = pack, .generation = generation});
        if (staged == generations_.end() || staged->second.phase != GenerationPhase::compiling) {
            return std::unexpected(
                error(StoreErrorCode::constraint_violation, "generation is not awaiting stage finalization"));
        }
        if (staged->second.reports.size() != staged->second.target_nodes.size()) {
            return std::unexpected(error(StoreErrorCode::conflict, "not every frozen target has reported", true));
        }

        std::string semantic_hash;
        std::string binding_hash;
        std::string failure;
        for (const auto &target : staged->second.target_nodes) {
            const auto node = nodes_.find(target);
            const auto report = std::ranges::find(staged->second.reports, target, &CompilationReport::node_id);
            if (node == nodes_.end() || report == staged->second.reports.end() || !node->second.node.healthy ||
                !node->second.node.serving || node->second.node.lease_fence != report->node_lease_fence) {
                failure = "frozen target lost its healthy serving lease";
                break;
            }
            if (!report->success || report->semantic_hash.empty() || report->binding_hash.empty() ||
                report->executable_hash.empty()) {
                failure = "a target did not produce a valid executable";
                break;
            }
            if (report->capability_hashes != staged->second.request.required_capability_hashes) {
                failure = "required capability hashes differ";
                break;
            }
            if (semantic_hash.empty()) {
                semantic_hash = report->semantic_hash;
                binding_hash = report->binding_hash;
            } else if (semantic_hash != report->semantic_hash || binding_hash != report->binding_hash) {
                failure = "platform-independent semantic or binding hashes differ";
                break;
            }
        }

        if (!failure.empty()) {
            staged->second.phase = GenerationPhase::failed;
            staged->second.failure = failure;
            const auto result = staged->second;
            lock.unlock();
            static_cast<void>(audit_.append(now_unix_ms, actor, "pack.stage.finalize",
                                            generation_resource(pack, generation), "failed", failure));
            return result;
        }

        staged->second.phase = GenerationPhase::ready;
        staged->second.semantic_hash = std::move(semantic_hash);
        staged->second.binding_hash = std::move(binding_hash);
        const auto result = staged->second;
        lock.unlock();
        static_cast<void>(audit_.append(now_unix_ms, actor, "pack.stage.finalize",
                                        generation_resource(pack, generation), "ready", result.semantic_hash));
        return result;
    }

    std::expected<DrainReceipt, StoreError> ActivationController::begin_drain(const PackId &pack,
                                                                              const std::uint64_t target_generation,
                                                                              const std::uint64_t drain_boundary,
                                                                              const std::uint64_t now_unix_ms,
                                                                              const std::string_view actor) {
        std::unique_lock lock {mutex_};
        const auto target = generations_.find(GenerationKey {.pack = pack, .generation = target_generation});
        if (target == generations_.end() || target->second.phase != GenerationPhase::ready) {
            return std::unexpected(error(StoreErrorCode::constraint_violation, "target generation is not ready"));
        }
        auto &control = controls_[pack];
        if (control.drain_target) {
            return std::unexpected(error(StoreErrorCode::conflict, "another activation drain is in progress", true));
        }
        if (auto state = validate_state_transition_locked(target->second.request, control); !state) {
            return std::unexpected(state.error());
        }

        const auto old_generation = control.active_generation;
        if (old_generation) {
            const auto old = generations_.find(GenerationKey {.pack = pack, .generation = *old_generation});
            if (old == generations_.end() || old->second.phase != GenerationPhase::active) {
                return std::unexpected(
                    error(StoreErrorCode::constraint_violation, "current active generation is inconsistent"));
            }
            old->second.phase = GenerationPhase::draining;
        }
        control.accepting_assignments = false;
        ++control.assignment_fence;
        control.drain_boundary = drain_boundary;
        control.drain_target = target_generation;

        std::vector<std::string> in_flight;
        in_flight.reserve(control.in_flight.size());
        for (const auto &[work_id, _] : control.in_flight) { in_flight.push_back(work_id); }
        const DrainReceipt receipt {
            .pack = pack,
            .old_generation = old_generation,
            .target_generation = target_generation,
            .drain_boundary = drain_boundary,
            .successor_assignment_fence = control.assignment_fence,
            .in_flight_work = std::move(in_flight),
        };
        lock.unlock();
        static_cast<void>(audit_.append(now_unix_ms, actor, "pack.activate.drain",
                                        generation_resource(pack, target_generation), "draining",
                                        std::to_string(receipt.in_flight_work.size())));
        return receipt;
    }

    std::expected<void, StoreError> ActivationController::register_assignment(const PackId &pack,
                                                                              const std::uint64_t generation,
                                                                              const std::string_view work_id,
                                                                              const std::uint64_t assignment_fence) {
        if (work_id.empty()) {
            return std::unexpected(error(StoreErrorCode::constraint_violation, "work ID is empty"));
        }
        const std::scoped_lock lock {mutex_};
        const auto control = controls_.find(pack);
        if (control == controls_.end() || !control->second.active_generation ||
            *control->second.active_generation != generation || !control->second.accepting_assignments ||
            control->second.assignment_fence != assignment_fence) {
            return std::unexpected(error(StoreErrorCode::stale_fence, "generation is not accepting this assignment"));
        }
        const auto [existing, inserted] = control->second.in_flight.emplace(std::string {work_id}, assignment_fence);
        if (!inserted && existing->second != assignment_fence) {
            return std::unexpected(error(StoreErrorCode::stale_fence, "assignment ID has a different fence"));
        }
        return {};
    }

    std::expected<void, StoreError> ActivationController::finish_assignment(const PackId &pack,
                                                                            const std::uint64_t generation,
                                                                            const std::string_view work_id,
                                                                            const std::uint64_t assignment_fence) {
        const std::scoped_lock lock {mutex_};
        const auto control = controls_.find(pack);
        if (control == controls_.end() || !control->second.active_generation ||
            *control->second.active_generation != generation) {
            return std::unexpected(error(StoreErrorCode::stale_fence, "assignment generation is stale"));
        }
        const auto work = control->second.in_flight.find(work_id);
        if (work == control->second.in_flight.end() || work->second != assignment_fence) {
            return std::unexpected(error(StoreErrorCode::stale_fence, "assignment fence is stale"));
        }
        control->second.in_flight.erase(work);
        return {};
    }

    std::expected<std::vector<std::string>, StoreError>
    ActivationController::fence_stragglers(const PackId &pack, const std::uint64_t target_generation,
                                           const std::uint64_t now_unix_ms, const std::string_view actor) {
        std::unique_lock lock {mutex_};
        const auto control = controls_.find(pack);
        if (control == controls_.end() || control->second.drain_target != target_generation) {
            return std::unexpected(error(StoreErrorCode::constraint_violation, "activation is not draining"));
        }

        std::vector<std::string> requeued;
        requeued.reserve(control->second.in_flight.size());
        for (const auto &[work_id, _] : control->second.in_flight) { requeued.push_back(work_id); }
        control->second.in_flight.clear();
        ++control->second.assignment_fence;
        control->second.pending_requeues.insert(control->second.pending_requeues.end(), requeued.begin(),
                                                requeued.end());
        const auto target = generations_.find(GenerationKey {.pack = pack, .generation = target_generation});
        if (target != generations_.end()) {
            target->second.requeued_work.insert(target->second.requeued_work.end(), requeued.begin(), requeued.end());
        }
        lock.unlock();
        static_cast<void>(audit_.append(now_unix_ms, actor, "pack.activate.fence_stragglers",
                                        generation_resource(pack, target_generation), "fenced",
                                        std::to_string(requeued.size())));
        return requeued;
    }

    std::expected<ActivationReceipt, StoreError> ActivationController::flip(const PackId &pack,
                                                                            const std::uint64_t target_generation,
                                                                            const std::uint64_t now_unix_ms,
                                                                            const std::string_view actor) {
        std::unique_lock lock {mutex_};
        const auto target = generations_.find(GenerationKey {.pack = pack, .generation = target_generation});
        const auto control = controls_.find(pack);
        if (target == generations_.end() || target->second.phase != GenerationPhase::ready ||
            control == controls_.end() || control->second.drain_target != target_generation ||
            !control->second.drain_boundary) {
            return std::unexpected(error(StoreErrorCode::constraint_violation, "activation is not ready to flip"));
        }
        if (!control->second.in_flight.empty()) {
            return std::unexpected(error(StoreErrorCode::conflict, "old-generation work is still in flight", true));
        }
        for (const auto &report : target->second.reports) {
            const auto node = nodes_.find(report.node_id);
            if (node == nodes_.end() || !node->second.node.healthy || !node->second.node.serving ||
                node->second.node.lease_fence != report.node_lease_fence) {
                return std::unexpected(
                    error(StoreErrorCode::unavailable, "a staged target is no longer a healthy serving node", true));
            }
        }

        const auto retired_generation = control->second.active_generation;
        if (retired_generation) {
            const auto old = generations_.find(GenerationKey {.pack = pack, .generation = *retired_generation});
            if (old == generations_.end() || old->second.phase != GenerationPhase::draining) {
                return std::unexpected(
                    error(StoreErrorCode::constraint_violation, "old generation is not in the draining phase"));
            }
            old->second.phase = GenerationPhase::retired;
        }
        target->second.phase = GenerationPhase::active;
        control->second.active_generation = target_generation;
        control->second.accepting_assignments = true;

        for (const auto &report : target->second.reports) {
            nodes_.at(report.node_id).compiled_active_generations.insert_or_assign(pack, target_generation);
        }

        ActivationReceipt receipt {
            .pack = pack,
            .retired_generation = retired_generation,
            .active_generation = target_generation,
            .activation_cursor = *control->second.drain_boundary,
            .assignment_fence = control->second.assignment_fence,
            .requeued_work = control->second.pending_requeues,
        };
        control->second.drain_boundary.reset();
        control->second.drain_target.reset();
        control->second.pending_requeues.clear();
        lock.unlock();
        static_cast<void>(audit_.append(now_unix_ms, actor, "pack.activate.flip",
                                        generation_resource(pack, target_generation), "active",
                                        std::to_string(receipt.activation_cursor)));
        return receipt;
    }

    std::expected<GenerationSnapshot, StoreError>
    ActivationController::begin_rollback_stage(const PackId &pack, const std::uint64_t source_generation,
                                               const std::uint64_t new_generation, StateTransitionPlan state_transition,
                                               const std::uint64_t now_unix_ms, const std::string_view actor) {
        GenerationRequest request;
        {
            const std::scoped_lock lock {mutex_};
            const auto source = generations_.find(GenerationKey {.pack = pack, .generation = source_generation});
            const auto control = controls_.find(pack);
            if (source == generations_.end() || source->second.phase != GenerationPhase::retired ||
                control == controls_.end() || !control->second.active_generation ||
                *control->second.active_generation == source_generation) {
                return std::unexpected(
                    error(StoreErrorCode::constraint_violation, "rollback source is not a retired generation"));
            }

            if (state_transition.mode == StateTransitionMode::carry) {
                const auto current =
                    generations_.find(GenerationKey {.pack = pack, .generation = *control->second.active_generation});
                if (current == generations_.end() ||
                    current->second.request.state_schema_hash != source->second.request.state_schema_hash) {
                    return std::unexpected(error(StoreErrorCode::incompatible_schema,
                                                 "rollback carry requires the current schema to match"));
                }
                state_transition.source_namespace = current->second.request.state_namespace;
                state_transition.target_namespace = current->second.request.state_namespace;
            }

            request = GenerationRequest {
                .pack = pack,
                .version = source->second.request.version,
                .source_digest = source->second.request.source_digest,
                .generation = new_generation,
                .state_schema_hash = source->second.request.state_schema_hash,
                .state_namespace = state_transition.target_namespace,
                .required_capability_hashes = source->second.request.required_capability_hashes,
                .state_transition = std::move(state_transition),
                .rollback_from = source_generation,
                .signature_verified = true,
                .policy = source->second.request.policy,
            };
        }
        return begin_stage(request, now_unix_ms, actor);
    }

    std::expected<void, StoreError> ActivationController::record_active_compilation(
        const std::string_view node_id, const std::uint64_t node_lease_fence, const PackId &pack,
        const std::uint64_t generation, const std::string_view semantic_hash, const std::string_view binding_hash,
        const std::uint64_t now_unix_ms) {
        std::unique_lock lock {mutex_};
        const auto node = nodes_.find(node_id);
        const auto active = generations_.find(GenerationKey {.pack = pack, .generation = generation});
        const auto control = controls_.find(pack);
        if (node == nodes_.end() || node->second.node.lease_fence != node_lease_fence) {
            return std::unexpected(error(StoreErrorCode::stale_fence, "node compilation uses a stale lease"));
        }
        if (control == controls_.end() || control->second.active_generation != generation ||
            active == generations_.end() || active->second.phase != GenerationPhase::active ||
            active->second.semantic_hash != semantic_hash || active->second.binding_hash != binding_hash) {
            return std::unexpected(
                error(StoreErrorCode::constraint_violation, "node compilation does not match the active generation"));
        }
        node->second.compiled_active_generations.insert_or_assign(pack, generation);
        lock.unlock();
        static_cast<void>(audit_.append(now_unix_ms, node_id, "node.compile_active",
                                        generation_resource(pack, generation), "ready", std::string {semantic_hash}));
        return {};
    }

    bool ActivationController::assignment_allowed(const PackId &pack, const std::uint64_t generation) const {
        const std::scoped_lock lock {mutex_};
        const auto control = controls_.find(pack);
        return control != controls_.end() && control->second.active_generation == generation &&
               control->second.accepting_assignments;
    }

    bool ActivationController::node_ready_for_pack(const std::string_view node_id, const PackId &pack) const {
        const std::scoped_lock lock {mutex_};
        const auto node = nodes_.find(node_id);
        const auto control = controls_.find(pack);
        if (node == nodes_.end() || control == controls_.end() || !control->second.active_generation ||
            !node->second.node.healthy || !node->second.node.serving) {
            return false;
        }
        const auto compiled = node->second.compiled_active_generations.find(pack);
        return compiled != node->second.compiled_active_generations.end() &&
               compiled->second == *control->second.active_generation;
    }

    std::optional<GenerationSnapshot> ActivationController::generation_snapshot(const PackId &pack,
                                                                                const std::uint64_t generation) const {
        const std::scoped_lock lock {mutex_};
        const auto snapshot = generations_.find(GenerationKey {.pack = pack, .generation = generation});
        if (snapshot == generations_.end()) {
            return std::nullopt;
        }
        return snapshot->second;
    }

    ActiveGenerationSnapshot ActivationController::active_snapshot(const PackId &pack) const {
        const std::scoped_lock lock {mutex_};
        ActiveGenerationSnapshot result {
            .pack = pack,
            .generation = std::nullopt,
            .assignment_fence = 0,
            .accepting_assignments = false,
            .drain_boundary = std::nullopt,
            .drain_target = std::nullopt,
            .in_flight_work = {},
        };
        const auto control = controls_.find(pack);
        if (control == controls_.end()) {
            return result;
        }
        result.generation = control->second.active_generation;
        result.assignment_fence = control->second.assignment_fence;
        result.accepting_assignments = control->second.accepting_assignments;
        result.drain_boundary = control->second.drain_boundary;
        result.drain_target = control->second.drain_target;
        result.in_flight_work.reserve(control->second.in_flight.size());
        for (const auto &[work_id, _] : control->second.in_flight) { result.in_flight_work.push_back(work_id); }
        return result;
    }

    std::vector<NodeSnapshot> ActivationController::node_snapshot() const {
        const std::scoped_lock lock {mutex_};
        std::vector<NodeSnapshot> result;
        result.reserve(nodes_.size());
        for (const auto &[_, node] : nodes_) {
            NodeSnapshot snapshot {
                .node = node.node,
                .compiled_active_generations = {},
            };
            snapshot.compiled_active_generations.reserve(node.compiled_active_generations.size());
            for (const auto &[pack, generation] : node.compiled_active_generations) {
                snapshot.compiled_active_generations.emplace_back(pack, generation);
            }
            result.push_back(std::move(snapshot));
        }
        return result;
    }

} // namespace rule_engine::python::cluster
