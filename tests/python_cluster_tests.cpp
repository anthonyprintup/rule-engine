#include "rule_engine/python/cluster/cluster.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <functional>
#include <memory>
#include <set>
#include <string>
#include <system_error>
#include <vector>

#if defined(_WIN32)
#include <process.h>
#else
#include <unistd.h>
#endif

namespace {

    using namespace rule_engine::python;
    using namespace rule_engine::python::cluster;

    constexpr std::uint64_t minute_ms = 60'000;

    std::uint64_t current_process_id() {
#if defined(_WIN32)
        return static_cast<std::uint64_t>(_getpid());
#else
        return static_cast<std::uint64_t>(getpid());
#endif
    }

    struct TemporaryDatabase {
        std::filesystem::path path;

        TemporaryDatabase() {
            static std::atomic_uint64_t sequence {};
            std::error_code error;
            auto directory = std::filesystem::temp_directory_path(error);
            if (error) {
                directory = std::filesystem::current_path(error);
            }
            path = directory / ("rule-engine-python-cluster-" + std::to_string(current_process_id()) + "-" +
                                std::to_string(++sequence) + ".sqlite3");
        }

        ~TemporaryDatabase() {
            std::error_code error;
            std::filesystem::remove(path, error);
            std::filesystem::remove(path.string() + "-wal", error);
            std::filesystem::remove(path.string() + "-shm", error);
        }

        TemporaryDatabase(const TemporaryDatabase &) = delete;
        TemporaryDatabase &operator=(const TemporaryDatabase &) = delete;
    };

    std::expected<std::unique_ptr<SqliteRuntimeStore>, StoreError> open_sqlite(const TemporaryDatabase &database,
                                                                               AuditTrail &audit) {
        return SqliteRuntimeStore::open(
            SqliteDevConfig {
                .database_path = database.path.string(),
                .server_processes = 1,
                .busy_timeout = std::chrono::seconds {2},
                .wal = true,
                .foreign_keys = true,
                .remote_cluster = false,
                .high_availability = false,
                .deployment_mode = DeploymentMode::single_node_dev,
            },
            audit);
    }

    std::expected<std::unique_ptr<SqliteActivationControlStore>, StoreError>
    open_control(const TemporaryDatabase &database) {
        return SqliteActivationControlStore::open(SqliteDevConfig {
            .database_path = database.path.string(),
            .server_processes = 1,
            .busy_timeout = std::chrono::seconds {2},
            .wal = true,
            .foreign_keys = true,
            .remote_cluster = false,
            .high_availability = false,
            .deployment_mode = DeploymentMode::single_node_dev,
        });
    }

    FrozenValue frozen(const std::string &digest, const std::string &text = "value") {
        return FrozenValue {
            .value = make_fact(UnicodeValue {.utf8 = text}),
            .label = DataLabel {},
            .canonical_digest = digest,
        };
    }

    SourceSpan source_span() {
        return SourceSpan {.source = SourceId {"rules/main.py"}, .begin_byte = 1, .end_byte = 5};
    }

    EventEnvelope event(const std::string &id, const std::uint64_t ingest_position) {
        return EventEnvelope {
            .id = EventId {id},
            .schema = SchemaId {"event/process/v1"},
            .tenant = TenantId {"tenant-a"},
            .peer = PeerId {"peer-a"},
            .subject = std::nullopt,
            .producer_unix_ms = ingest_position,
            .ingest_unix_ms = ingest_position,
            .label = DataLabel {},
            .causation = std::nullopt,
            .payload = frozen("sha256:" + id, id),
        };
    }

    EffectIntent effect(const std::string &id) {
        return EffectIntent {
            .id = IntentId {id},
            .invocation = InvocationId {"invocation-1"},
            .owner = ExecutableId {"executable-1"},
            .binding = BindingId {"binding-1"},
            .sequence = 1,
            .kind = "post",
            .payload = frozen("sha256:" + id, id),
            .span = source_span(),
            .policy =
                EffectPolicySnapshot {
                    .policy_id = "post-policy",
                    .policy_digest = "sha256:policy",
                    .sink_ceiling = DataLabel {},
                    .dry_run = false,
                },
            .disposition = EffectDisposition::committed,
            .idempotency_key = "idempotency:" + id,
        };
    }

    StateMutation state_mutation(const std::uint64_t expected_version, const std::string &digest) {
        return StateMutation {
            .owner = ExecutableId {"executable-1"},
            .namespace_name = "pack-state",
            .key = "counter",
            .expected_version = expected_version,
            .value = frozen(digest, digest),
        };
    }

    RuntimeTransaction transaction(const std::string &event_id, const std::string &consumer,
                                   const std::uint64_t expected_cursor, const std::uint64_t fence,
                                   const std::uint64_t state_version, const bool with_effects = false,
                                   const bool with_emitted_event = false) {
        auto input = event(event_id, expected_cursor + 1);
        std::vector<StateMutation> state {state_mutation(state_version, "sha256:state-" + event_id)};
        std::vector<EffectIntent> journal;
        std::vector<EventIntent> event_journal;
        std::vector<OutboxRecord> outbox;
        if (with_effects) {
            journal.push_back(effect("intent-" + event_id));
            outbox.push_back(OutboxRecord {
                .intent = journal.front().id,
                .destination = "operator-sink",
                .payload = journal.front().payload,
                .idempotency_key = journal.front().idempotency_key,
                .not_before_unix_ms = 0,
            });
        }
        std::vector<EventEnvelope> emitted;
        if (with_emitted_event) {
            const auto intent_id = deterministic_event_intent_id(input.id, InvocationId {"invocation-1"}, 1U);
            event_journal.push_back(EventIntent {
                .id = intent_id,
                .root_event = input.id,
                .invocation = InvocationId {"invocation-1"},
                .owner = ExecutableId {"executable-1"},
                .binding = BindingId {"binding-1"},
                .sequence = 1U,
                .schema = SchemaId {"event/process/v1"},
                .schema_hash = "sha256:event-process-v1",
                .payload = frozen("sha256:emitted-" + event_id, "emitted-" + event_id),
                .span = source_span(),
                .disposition = EventDisposition::committed,
            });
            emitted.push_back(EventEnvelope {
                .id = EventId {intent_id.value},
                .schema = event_journal.front().schema,
                .tenant = input.tenant,
                .peer = input.peer,
                .subject = input.subject,
                .producer_unix_ms = input.ingest_unix_ms,
                .ingest_unix_ms = input.ingest_unix_ms,
                .label = event_journal.front().payload.label,
                .causation = input.id,
                .payload = event_journal.front().payload,
            });
        }
        EvaluationResult evaluation {
            .outcome = EvaluationOutcome::match,
            .verdict = true,
            .committed_effects = journal,
            .committed_events = event_journal,
            .state_mutations = state,
            .fault = std::nullopt,
        };
        return RuntimeTransaction {
            .input = std::move(input),
            .cursor =
                CursorAdvance {
                    .consumer = consumer,
                    .expected_position = expected_cursor,
                    .new_position = expected_cursor + 1,
                },
            .evaluation = std::move(evaluation),
            .state = std::move(state),
            .emitted_events = std::move(emitted),
            .journal = std::move(journal),
            .outbox = std::move(outbox),
            .fence_token = fence,
        };
    }

    ClusterNode node(const std::string &id, const std::uint64_t fence) {
        return ClusterNode {
            .node_id = id,
            .platform_abi = id == "node-linux" ? "linux-x64-v1" : "windows-x64-v1",
            .lease_fence = fence,
            .healthy = true,
            .serving = true,
        };
    }

    GenerationRequest generation(const std::uint64_t number, const std::string &source,
                                 const std::string &schema = "state-schema-v1",
                                 const std::string &state_namespace = "state-live") {
        return GenerationRequest {
            .pack = PackId {"pack-a"},
            .version = PackVersion {"1.0." + std::to_string(number)},
            .source_digest = SourceDigest {source},
            .generation = number,
            .state_schema_hash = schema,
            .state_namespace = state_namespace,
            .required_capability_hashes = {},
            .state_transition =
                StateTransitionPlan {
                    .mode = StateTransitionMode::carry,
                    .source_namespace = state_namespace,
                    .target_namespace = state_namespace,
                    .migration_id = {},
                    .reset_authorized = false,
                    .accept_state_gap = false,
                },
            .rollback_from = std::nullopt,
            .signature_verified = true,
            .policy = {.version = "activation-policy.v1",
                       .bundle_hash = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
        };
    }

    CompilationReport compilation(const ClusterNode &target, const std::string &semantic, const std::string &binding) {
        return CompilationReport {
            .node_id = target.node_id,
            .node_lease_fence = target.lease_fence,
            .success = true,
            .semantic_hash = semantic,
            .binding_hash = binding,
            .executable_hash = "sha256:executable:" + target.platform_abi + ":" + semantic,
            .capability_hashes = {},
            .diagnostics = {},
        };
    }

    GenerationSnapshot ready_generation(const std::uint64_t number, const std::string &source,
                                        const std::string &schema = "state-schema-v1",
                                        const std::string &state_namespace = "state-live") {
        const auto first = node("node-a", 11);
        const auto second = node("node-b", 12);
        const auto semantic = "sha256:semantic-" + std::to_string(number);
        const auto binding = "sha256:binding-" + std::to_string(number);
        return GenerationSnapshot {
            .request = generation(number, source, schema, state_namespace),
            .phase = GenerationPhase::ready,
            .target_nodes = {first.node_id, second.node_id},
            .reports = {compilation(first, semantic, binding), compilation(second, semantic, binding)},
            .semantic_hash = semantic,
            .binding_hash = binding,
            .requeued_work = {},
            .failure = {},
        };
    }

    AdminMutationRequest mutation_request(const std::string &identity, const std::uint64_t expected_pack_version,
                                          const std::uint64_t at_unix_ms) {
        return AdminMutationRequest {.operation_id = "operation-" + identity,
                                     .request_id = RequestId {"request-" + identity},
                                     .idempotency_key = "idempotency-" + identity,
                                     .actor = "operator-a",
                                     .reason = "test " + identity,
                                     .expected_pack_version = expected_pack_version,
                                     .at_unix_ms = at_unix_ms};
    }

    AdminApplyRequest apply_request(const AdminOperationRecord &operation, const std::uint64_t expected_pack_version,
                                    const std::uint64_t at_unix_ms) {
        return AdminApplyRequest {.operation_id = operation.operation_id,
                                  .idempotency_key = operation.idempotency_key,
                                  .expected_pack_version = expected_pack_version,
                                  .at_unix_ms = at_unix_ms};
    }

    std::uint64_t stage_and_activate(DurableActivationAdmin &admin, const GenerationSnapshot &generation,
                                     const std::uint64_t pack_version, const std::string &identity,
                                     const std::uint64_t at_unix_ms) {
        const auto stage =
            admin.preview_stage(mutation_request(identity + "-stage", pack_version, at_unix_ms), generation);
        REQUIRE(stage.has_value());
        REQUIRE(admin.apply_stage(apply_request(*stage, pack_version, at_unix_ms + 1), generation).has_value());

        const auto activation =
            admin.preview_activation(mutation_request(identity + "-activate", pack_version + 1, at_unix_ms + 2),
                                     generation.request.pack, generation.request.generation);
        REQUIRE(activation.has_value());
        REQUIRE(admin.begin_drain(apply_request(*activation, pack_version + 1, at_unix_ms + 3), at_unix_ms + 100)
                    .has_value());
        REQUIRE(admin.fence_stragglers(apply_request(*activation, pack_version + 2, at_unix_ms + 4), {}).has_value());
        REQUIRE(admin.flip(apply_request(*activation, pack_version + 3, at_unix_ms + 5)).has_value());
        return pack_version + 4;
    }

    struct CountingControlStore final: IActivationControlStore {
        mutable std::size_t load_calls {};
        mutable std::size_t find_operation_calls {};
        mutable std::size_t find_idempotency_calls {};
        mutable std::size_t inspect_calls {};
        std::size_t commit_calls {};
        DurableControlState state;
        std::optional<AdminOperationRecord> operation;

        [[nodiscard]] std::expected<DurableControlState, StoreError> load_state() const override {
            ++load_calls;
            return state;
        }

        [[nodiscard]] std::expected<std::optional<AdminOperationRecord>, StoreError>
        find_operation(const std::string_view) const override {
            ++find_operation_calls;
            return operation;
        }

        [[nodiscard]] std::expected<std::optional<AdminOperationRecord>, StoreError>
        find_operation_by_idempotency(const std::string_view) const override {
            ++find_idempotency_calls;
            return operation;
        }

        [[nodiscard]] std::expected<void, StoreError> upsert_node(const DurableResidentNode &) override { return {}; }

        [[nodiscard]] std::expected<std::vector<DurableResidentNode>, StoreError> node_snapshot() const override {
            return std::vector<DurableResidentNode> {};
        }

        [[nodiscard]] std::expected<void, StoreError> commit(const ControlPlaneCommit &) override {
            ++commit_calls;
            return {};
        }

        [[nodiscard]] std::expected<ControlPlaneInspection, StoreError> inspect() const override {
            ++inspect_calls;
            return ControlPlaneInspection {.state = state, .operations = {}, .audit = {}};
        }

        [[nodiscard]] RuntimeStoreHealth health() const override { return {}; }

        [[nodiscard]] std::size_t total_calls() const {
            return load_calls + find_operation_calls + find_idempotency_calls + inspect_calls + commit_calls;
        }
    };

    struct RecordingSecurityAudit final: IAdminSecurityAuditSink {
        std::vector<AdminSecurityAuditEvent> events;

        void record(const AdminSecurityAuditEvent &event) noexcept override { events.push_back(event); }
    };

    struct TestAdminAuthorizer final: IAdminAuthorizer {
        bool allow_all {};
        bool unavailable {};
        TenantId allowed_tenant;
        PackId allowed_pack;
        std::set<AdminControlOperation> allowed_operations;
        mutable std::vector<AdminAuthorizationRequest> requests;

        [[nodiscard]] std::expected<AdminAuthorizationDecision, AdminAuthorizerFailure>
        authorize(const AuthenticatedAdminPrincipal &principal,
                  const AdminAuthorizationRequest &request) const override {
            requests.push_back(request);
            if (unavailable) {
                return std::unexpected(
                    AdminAuthorizerFailure {.message = "policy service unavailable", .retryable = true});
            }
            const auto allowed =
                allow_all || (principal.home_tenant == allowed_tenant && request.resource.tenant == allowed_tenant &&
                              request.resource.pack == allowed_pack && allowed_operations.contains(request.operation));
            return AdminAuthorizationDecision {.outcome = allowed ? AdminAuthorizationOutcome::allowed :
                                                                    AdminAuthorizationOutcome::denied,
                                               .decision_id = "decision-" + std::to_string(requests.size()),
                                               .detail = allowed ? "test policy allowed" : "test policy denied"};
        }
    };

    AdminCallContext admin_context(const TenantId &tenant, const std::string &principal = "admin-a",
                                   const AdminPrincipalKind kind = AdminPrincipalKind::administrator) {
        return AdminCallContext {.principal = AuthenticatedAdminPrincipal {.principal_id = principal,
                                                                           .home_tenant = tenant,
                                                                           .kind = kind,
                                                                           .authentication_id = "upstream-session-a"},
                                 .at_unix_ms = 1};
    }

    void stage_ready(ActivationController &activation, const GenerationRequest &request,
                     const std::vector<ClusterNode> &targets, const std::string &semantic, const std::string &binding,
                     const std::uint64_t now) {
        const auto begun = activation.begin_stage(request, now, "operator");
        REQUIRE(begun.has_value());
        REQUIRE(begun->target_nodes.size() == targets.size());
        for (const auto &target : targets) {
            REQUIRE(activation
                        .report_compilation(request.pack, request.generation, compilation(target, semantic, binding),
                                            now + 1)
                        .has_value());
        }
        const auto finalized = activation.finalize_stage(request.pack, request.generation, now + 2, "operator");
        REQUIRE(finalized.has_value());
        REQUIRE(finalized->phase == GenerationPhase::ready);
    }

    void verify_runtime_store_contract(IClusterRuntimeStore &store) {
        REQUIRE(store.health().driver_available);
        REQUIRE(store.health().connected);
        REQUIRE(store.health().migrations_compatible);
        REQUIRE(store.install_consumer_fence("contract:peer", 7).has_value());

        const auto proposed = transaction("contract-event", "contract:peer", 0, 7, 0, true, true);
        const auto receipt = store.transact_event(proposed);
        REQUIRE(receipt.has_value());
        REQUIRE(receipt->committed_cursor == 1);
        REQUIRE(store.transact_event(proposed)->committed_cursor == 1);

        const auto state = store.load_state(
            StoredStateKey {.owner = ExecutableId {"executable-1"}, .namespace_name = "pack-state", .key = "counter"});
        REQUIRE(state.has_value());
        REQUIRE(state->has_value());
        REQUIRE((*state)->version == 1);
        REQUIRE((*state)->value->canonical_digest == "sha256:state-contract-event");

        const auto history = store.read_history(HistoryQuery {
            .tenant = TenantId {"tenant-a"},
            .peer = PeerId {"peer-a"},
            .schema = SchemaId {"event/process/v1"},
            .begin_ingest_unix_ms = 0,
            .end_ingest_unix_ms = 10,
            .limit = 10,
        });
        REQUIRE(history.has_value());
        REQUIRE(history->size() == 2);
        REQUIRE(std::ranges::find(*history, EventId {"contract-event"}, &EventEnvelope::id) != history->end());

        const auto snapshot = store.inspect();
        REQUIRE(snapshot.has_value());
        REQUIRE(snapshot->events.size() == 2);
        REQUIRE(snapshot->state.size() == 1);
        REQUIRE(snapshot->results.size() == 1);
        REQUIRE(snapshot->results.front().evaluation.committed_events.size() == 1);
        REQUIRE(snapshot->results.front().evaluation.committed_events.front().id ==
                proposed.evaluation.committed_events.front().id);
        REQUIRE(snapshot->journal.size() == 1);
        REQUIRE(snapshot->outbox.size() == 1);
        REQUIRE(snapshot->receipts.size() == 1);

        const auto conflict = store.transact_event(transaction("contract-conflict", "contract:peer", 1, 7, 0, true));
        REQUIRE_FALSE(conflict.has_value());
        REQUIRE(conflict.error().code == StoreErrorCode::conflict);
        const auto after_conflict = store.inspect();
        REQUIRE(after_conflict.has_value());
        REQUIRE(after_conflict->events.size() == snapshot->events.size());
        REQUIRE(after_conflict->journal.size() == snapshot->journal.size());
        REQUIRE(after_conflict->outbox.size() == snapshot->outbox.size());

        const auto first = store.claim_outbox("contract-worker-a", 100, 10, 1);
        REQUIRE(first.has_value());
        REQUIRE(first->size() == 1);
        REQUIRE(store.claim_outbox("contract-worker-b", 110, 10, 1)->empty());
        const auto takeover = store.claim_outbox("contract-worker-b", 111, 10, 1);
        REQUIRE(takeover->size() == 1);
        REQUIRE(takeover->front().fence > first->front().fence);
        REQUIRE(store
                    .settle_outbox(OutboxSettlement {
                        .intent = takeover->front().record.intent,
                        .owner = takeover->front().owner,
                        .fence = takeover->front().fence,
                        .now_unix_ms = 111,
                        .kind = OutboxSettlementKind::delivered,
                        .retry_not_before_unix_ms = 0,
                        .detail = "contract delivered",
                    })
                    .has_value());
    }

    void verify_agent_ingress_contract(IClusterRuntimeStore &store) {
        const AgentStreamId stream {
            .tenant = TenantId {"tenant-agent"},
            .peer = PeerId {"peer-agent"},
            .agent_epoch = "epoch-1",
        };
        const LeaseResource resource {.scope = "agent-session", .key = "tenant-agent/peer-agent"};
        const auto lease = store.claim_lease(resource, "session-1", 100, 100);
        REQUIRE(lease.has_value());
        REQUIRE(store.load_agent_receipt(stream) == 0);

        const AgentMessageCommit first {
            .stream = stream,
            .session = SessionId {"session-1"},
            .session_fence = lease->fence,
            .sequence = 1,
            .received_at_unix_ms = 101,
            .body_kind = 4,
            .body = {std::byte {0x01}, std::byte {0x02}},
        };
        const auto first_receipt = store.transact_agent_message(first);
        REQUIRE(first_receipt.has_value());
        REQUIRE(first_receipt->acknowledged_through == 1);
        REQUIRE_FALSE(first_receipt->duplicate);

        auto second = first;
        second.sequence = 2;
        second.received_at_unix_ms = 102;
        second.body = {std::byte {0x03}};
        REQUIRE(store.transact_agent_message(second)->acknowledged_through == 2);
        REQUIRE(store.load_agent_receipt(stream) == 2);

        const auto duplicate = store.transact_agent_message(first);
        REQUIRE(duplicate.has_value());
        REQUIRE(duplicate->acknowledged_through == 2);
        REQUIRE(duplicate->duplicate);

        auto changed_replay = first;
        changed_replay.body = {std::byte {0x7f}};
        const auto changed = store.transact_agent_message(changed_replay);
        REQUIRE_FALSE(changed.has_value());
        REQUIRE(changed.error().code == StoreErrorCode::constraint_violation);

        auto gap = second;
        gap.sequence = 4;
        gap.body = {std::byte {0x04}};
        const auto skipped = store.transact_agent_message(gap);
        REQUIRE_FALSE(skipped.has_value());
        REQUIRE(skipped.error().code == StoreErrorCode::conflict);

        auto expired = second;
        expired.sequence = 3;
        expired.received_at_unix_ms = 201;
        expired.body = {std::byte {0x05}};
        const auto stale = store.transact_agent_message(expired);
        REQUIRE_FALSE(stale.has_value());
        REQUIRE(stale.error().code == StoreErrorCode::stale_fence);

        const auto snapshot = store.inspect();
        REQUIRE(snapshot.has_value());
        REQUIRE(snapshot->agent_messages.size() == 2);
    }

    TEST_CASE("backend contracts distinguish production intent from implemented adapters") {
        const auto postgres = validate_store_backend(PostgreSql17Config {
            .connection_reference = "secret://runtime/postgres",
            .server_major = 17,
            .server_processes = 2,
            .pool_size = 16,
            .statement_timeout = std::chrono::seconds {5},
            .verify_tls_peer = true,
            .external_ha_configured = true,
            .deployment_mode = DeploymentMode::production_cluster,
        });
        REQUIRE(postgres.has_value());
        REQUIRE(postgres->kind == StoreBackendKind::postgresql17);
        REQUIRE(postgres->production_allowed);
        REQUIRE(postgres->active_active);
        REQUIRE(postgres->database_time_leases);
#if defined(RULE_ENGINE_HAS_POSTGRESQL)
        REQUIRE(postgres->implementation_available);
#else
        REQUIRE_FALSE(postgres->implementation_available);
#endif

        const auto sqlite = validate_store_backend(SqliteDevConfig {.database_path = "dev.db"});
        REQUIRE(sqlite.has_value());
        REQUIRE(sqlite->implementation_available);
        REQUIRE_FALSE(sqlite->production_allowed);
        REQUIRE_FALSE(sqlite->database_time_leases);

        const auto clustered_sqlite = validate_store_backend(SqliteDevConfig {
            .database_path = "dev.db",
            .server_processes = 2,
        });
        REQUIRE_FALSE(clustered_sqlite.has_value());
        REQUIRE(clustered_sqlite.error().code == ConfigurationErrorCode::clustered_sqlite);

        const auto reference = validate_store_backend(InMemoryReferenceConfig {});
        REQUIRE(reference.has_value());
        REQUIRE(reference->implementation_available);
        REQUIRE_FALSE(reference->production_allowed);
    }

    TEST_CASE("resident compilation qualification binds source semantics bindings executable and node fence") {
        CompiledPack compiled {
            .pack = PackId {"pack-a"},
            .version = PackVersion {"1.0.1"},
            .source_digest = SourceDigest {"sha256:signed-source"},
            .compiler_abi = std::string {python_static_compiler_abi_v1},
            .semantic_hash = "fnv1a64:0000000000000001",
            .schemas = {.descriptors = {}, .canonical_hash = "fnv1a64:0000000000000002"},
            .constants = {},
            .functions = {},
            .bindings = {{.id = BindingId {"binding-a"},
                          .executable = ExecutableId {"rule-a"},
                          .capabilities = {},
                          .budget = balanced_v1}},
            .optimization_certificates = {},
        };
        const auto binding_hash = canonical_operator_bindings_hash(compiled.bindings);
        const auto executable_hash = compiled_pack_executable_hash(compiled, "windows-x64-v1");
        GenerationSnapshot active {
            .request = generation(1, compiled.source_digest.value),
            .phase = GenerationPhase::active,
            .target_nodes = {"node-a"},
            .reports = {{.node_id = "node-a",
                         .node_lease_fence = 17,
                         .success = true,
                         .semantic_hash = compiled.semantic_hash,
                         .binding_hash = binding_hash,
                         .executable_hash = executable_hash,
                         .capability_hashes = {},
                         .diagnostics = {}}},
            .semantic_hash = compiled.semantic_hash,
            .binding_hash = binding_hash,
            .requeued_work = {},
            .failure = {},
        };
        REQUIRE(qualify_resident_compilation(active, "node-a", "windows-x64-v1", compiled).has_value());

        auto changed = compiled;
        changed.semantic_hash = "fnv1a64:0000000000000003";
        const auto semantic_mismatch = qualify_resident_compilation(active, "node-a", "windows-x64-v1", changed);
        REQUIRE_FALSE(semantic_mismatch.has_value());
        REQUIRE(semantic_mismatch.error().code == StoreErrorCode::incompatible_schema);

        auto restarted = active;
        restarted.reports.front().node_lease_fence = 9U;
        REQUIRE(qualify_resident_compilation(restarted, "node-a", "windows-x64-v1", compiled).has_value());
    }

    TEST_CASE("authorized admin facade fails closed before touching persistence") {
        CountingControlStore store;
        DurableActivationAdmin durable {store};
        TestAdminAuthorizer allow_all;
        allow_all.allow_all = true;
        RecordingSecurityAudit security_audit;
        AuthorizedActivationAdmin authorized {durable, &allow_all, &security_audit};
        const auto staged = ready_generation(1, "sha256:auth-source");
        const auto request = mutation_request("auth-required", 0, 10);
        const TenantId tenant {"tenant-a"};

        const auto unauthenticated = authorized.preview_stage(AdminCallContext {}, tenant, request, staged);
        REQUIRE_FALSE(unauthenticated.has_value());
        REQUIRE(unauthenticated.error().code == AuthorizedAdminErrorCode::unauthenticated);
        REQUIRE(allow_all.requests.empty());
        REQUIRE(store.total_calls() == 0);

        auto malformed = admin_context(tenant);
        malformed.principal->authentication_id.clear();
        const auto malformed_identity = authorized.pack_snapshot(malformed, tenant, staged.request.pack);
        REQUIRE_FALSE(malformed_identity.has_value());
        REQUIRE(malformed_identity.error().code == AuthorizedAdminErrorCode::unauthenticated);
        REQUIRE(store.total_calls() == 0);

        const auto invalid_resource = authorized.pack_snapshot(admin_context(tenant), TenantId {}, staged.request.pack);
        REQUIRE_FALSE(invalid_resource.has_value());
        REQUIRE(invalid_resource.error().code == AuthorizedAdminErrorCode::invalid_resource);
        REQUIRE(allow_all.requests.empty());
        REQUIRE(store.total_calls() == 0);

        AuthorizedActivationAdmin missing_authorizer {durable, nullptr, &security_audit};
        const auto missing = missing_authorizer.preview_stage(admin_context(tenant), tenant, request, staged);
        REQUIRE_FALSE(missing.has_value());
        REQUIRE(missing.error().code == AuthorizedAdminErrorCode::authorizer_unavailable);
        REQUIRE(store.total_calls() == 0);

        TestAdminAuthorizer unavailable;
        unavailable.unavailable = true;
        AuthorizedActivationAdmin failed_authorizer {durable, &unavailable, &security_audit};
        const auto failed = failed_authorizer.inspect_pack(admin_context(tenant), tenant, staged.request.pack);
        REQUIRE_FALSE(failed.has_value());
        REQUIRE(failed.error().code == AuthorizedAdminErrorCode::authorizer_unavailable);
        REQUIRE(failed.error().retryable);
        REQUIRE(store.total_calls() == 0);

        REQUIRE(security_audit.events.size() == 5);
        REQUIRE(security_audit.events[0].outcome == AdminSecurityAuditOutcome::unauthenticated);
        REQUIRE(security_audit.events[1].outcome == AdminSecurityAuditOutcome::unauthenticated);
        REQUIRE(security_audit.events[2].outcome == AdminSecurityAuditOutcome::invalid_resource);
        REQUIRE(security_audit.events[3].outcome == AdminSecurityAuditOutcome::authorizer_unavailable);
        REQUIRE(security_audit.events[4].outcome == AdminSecurityAuditOutcome::authorizer_unavailable);
    }

    TEST_CASE("admin authorization scopes tenant resource and operation before store access") {
        CountingControlStore store;
        DurableActivationAdmin durable {store};
        const TenantId tenant_a {"tenant-a"};
        const TenantId tenant_b {"tenant-b"};
        TestAdminAuthorizer policy;
        policy.allowed_tenant = tenant_a;
        policy.allowed_pack = PackId {"pack-a"};
        policy.allowed_operations = {AdminControlOperation::stage_preview};
        RecordingSecurityAudit security_audit;
        AuthorizedActivationAdmin authorized {durable, &policy, &security_audit};
        const auto context = admin_context(tenant_a);
        const auto pack_a = ready_generation(1, "sha256:pack-a");
        auto pack_b = ready_generation(1, "sha256:pack-b");
        pack_b.request.pack = PackId {"pack-b"};

        const auto cross_tenant =
            authorized.preview_stage(context, tenant_b, mutation_request("cross-tenant", 0, 10), pack_a);
        REQUIRE_FALSE(cross_tenant.has_value());
        REQUIRE(cross_tenant.error().code == AuthorizedAdminErrorCode::unauthorized);

        const auto cross_resource =
            authorized.preview_stage(context, tenant_a, mutation_request("cross-resource", 0, 11), pack_b);
        REQUIRE_FALSE(cross_resource.has_value());
        REQUIRE(cross_resource.error().code == AuthorizedAdminErrorCode::unauthorized);

        const auto wrong_operation = authorized.preview_activation(
            context, tenant_a, mutation_request("wrong-operation", 0, 12), pack_a.request.pack, 1);
        REQUIRE_FALSE(wrong_operation.has_value());
        REQUIRE(wrong_operation.error().code == AuthorizedAdminErrorCode::unauthorized);

        const auto denied_read = authorized.pack_snapshot(context, tenant_a, pack_a.request.pack);
        REQUIRE_FALSE(denied_read.has_value());
        REQUIRE(denied_read.error().code == AuthorizedAdminErrorCode::unauthorized);

        const auto foreign_principal = authorized.preview_stage(admin_context(tenant_b, "foreign-admin"), tenant_a,
                                                                mutation_request("foreign-principal", 0, 13), pack_a);
        REQUIRE_FALSE(foreign_principal.has_value());
        REQUIRE(foreign_principal.error().code == AuthorizedAdminErrorCode::unauthorized);

        REQUIRE(policy.requests.size() == 5);
        REQUIRE(security_audit.events.size() == 5);
        REQUIRE(std::ranges::all_of(security_audit.events, [](const AdminSecurityAuditEvent &event) {
            return event.outcome == AdminSecurityAuditOutcome::denied;
        }));
        REQUIRE(store.total_calls() == 0);
    }

    TEST_CASE("pack signer authentication never grants administrative authority") {
        CountingControlStore store;
        DurableActivationAdmin durable {store};
        TestAdminAuthorizer allow_all;
        allow_all.allow_all = true;
        RecordingSecurityAudit security_audit;
        AuthorizedActivationAdmin authorized {durable, &allow_all, &security_audit};
        const TenantId tenant {"tenant-a"};
        const auto staged = ready_generation(1, "sha256:signed-source");
        auto request = mutation_request("signer-cannot-stage", 0, 10);
        request.actor = "signer-a";

        const auto denied = authorized.preview_stage(admin_context(tenant, "signer-a", AdminPrincipalKind::pack_signer),
                                                     tenant, request, staged);
        REQUIRE_FALSE(denied.has_value());
        REQUIRE(denied.error().code == AuthorizedAdminErrorCode::unauthorized);
        REQUIRE(allow_all.requests.empty());
        REQUIRE(store.total_calls() == 0);
        REQUIRE(security_audit.events.size() == 1);
        REQUIRE(security_audit.events.front().outcome == AdminSecurityAuditOutcome::non_admin_identity_rejected);
    }

    TEST_CASE("runtime store contract is parameterized across reference and SQLite adapters") {
        SECTION("in-memory reference") {
            AuditTrail audit;
            InMemoryRuntimeStore store {audit};
            verify_runtime_store_contract(store);
            verify_agent_ingress_contract(store);
        }
        SECTION("SQLite durable adapter") {
            TemporaryDatabase database;
            AuditTrail audit;
            const auto store = open_sqlite(database, audit);
            REQUIRE(store.has_value());
            verify_runtime_store_contract(**store);
            verify_agent_ingress_contract(**store);
        }
    }

    TEST_CASE("SQLite reopens committed receipts state history outbox and migrations") {
        TemporaryDatabase database;
        AuditTrail first_audit;
        {
            const auto store = open_sqlite(database, first_audit);
            REQUIRE(store.has_value());
            REQUIRE((*store)->install_consumer_fence("durable:peer", 3).has_value());
            REQUIRE((*store)
                        ->transact_event(transaction("durable-event", "durable:peer", 0, 3, 0, true, true))
                        .has_value());
            const auto agent_lease =
                (*store)->claim_lease(LeaseResource {.scope = "agent-session", .key = "tenant-durable/peer-durable"},
                                      "session-durable", 10, 100);
            REQUIRE(agent_lease.has_value());
            REQUIRE((*store)
                        ->transact_agent_message(AgentMessageCommit {
                            .stream = {.tenant = TenantId {"tenant-durable"},
                                       .peer = PeerId {"peer-durable"},
                                       .agent_epoch = "epoch-durable"},
                            .session = SessionId {"session-durable"},
                            .session_fence = agent_lease->fence,
                            .sequence = 1,
                            .received_at_unix_ms = 11,
                            .body_kind = 4,
                            .body = {std::byte {0x2a}},
                        })
                        .has_value());
            REQUIRE((*store)->health().schema_version == runtime_store_schema_version);
        }

        AuditTrail reopened_audit;
        const auto reopened = open_sqlite(database, reopened_audit);
        REQUIRE(reopened.has_value());
        const auto receipt = (*reopened)->load_receipt(EventId {"durable-event"});
        REQUIRE(receipt.has_value());
        REQUIRE(receipt->has_value());
        REQUIRE((*receipt)->committed_cursor == 1);
        const auto state = (*reopened)->load_state(
            StoredStateKey {.owner = ExecutableId {"executable-1"}, .namespace_name = "pack-state", .key = "counter"});
        REQUIRE(state.has_value());
        REQUIRE(state->has_value());
        REQUIRE((*state)->value->canonical_digest == "sha256:state-durable-event");
        REQUIRE((*reopened)
                    ->read_history(HistoryQuery {
                        .tenant = TenantId {"tenant-a"},
                        .peer = PeerId {"peer-a"},
                        .schema = SchemaId {"event/process/v1"},
                        .begin_ingest_unix_ms = 0,
                        .end_ingest_unix_ms = 10,
                        .limit = 10,
                    })
                    ->size() == 2);
        REQUIRE((*reopened)->inspect()->outbox.size() == 1);
        const AgentStreamId durable_stream {
            .tenant = TenantId {"tenant-durable"}, .peer = PeerId {"peer-durable"}, .agent_epoch = "epoch-durable"};
        REQUIRE((*reopened)->load_agent_receipt(durable_stream) == 1);
        REQUIRE((*reopened)->inspect()->agent_messages.size() == 1);
    }

    TEST_CASE("SQLite runtime and activation stores coexist on one durable authority") {
        TemporaryDatabase database;
        const auto staged_generation = ready_generation(1, "sha256:shared-source");
        {
            AuditTrail audit;
            const auto runtime = open_sqlite(database, audit);
            const auto control = open_control(database);
            REQUIRE(runtime.has_value());
            REQUIRE(control.has_value());
            DurableActivationAdmin admin {**control};
            const auto preview = admin.preview_stage(mutation_request("shared-stage", 0, 10), staged_generation);
            REQUIRE(preview.has_value());
            REQUIRE(admin.apply_stage(apply_request(*preview, 0, 11), staged_generation).has_value());
            REQUIRE((*runtime)->install_consumer_fence("shared:peer", 2).has_value());
            REQUIRE((*runtime)->transact_event(transaction("shared-event", "shared:peer", 0, 2, 0)).has_value());
        }

        AuditTrail reopened_audit;
        const auto runtime = open_sqlite(database, reopened_audit);
        const auto control = open_control(database);
        REQUIRE(runtime.has_value());
        REQUIRE(control.has_value());
        REQUIRE((*runtime)->load_receipt(EventId {"shared-event"})->has_value());
        const auto inspection = (*control)->inspect();
        REQUIRE(inspection.has_value());
        REQUIRE(inspection->state.generations.size() == 1);
        REQUIRE(inspection->audit.size() == 2);
    }

    TEST_CASE("durable resident node evidence survives restart and rejects stale lease identity") {
        TemporaryDatabase database;
        const DurableResidentNode first {
            .node_id = "resident-a",
            .platform_abi = "windows-x86_64-msvc-v1",
            .lease_fence = 7,
            .lease_until_unix_ms = 2'000,
            .updated_at_unix_ms = 1'000,
            .serving = true,
            .capability_hashes = {"sha256:capability-a", "sha256:capability-b"},
        };

        {
            const auto store = open_control(database);
            REQUIRE(store.has_value());
            REQUIRE((*store)->health().schema_version == 2);
            REQUIRE((*store)->upsert_node(first).has_value());

            auto heartbeat = first;
            heartbeat.lease_until_unix_ms = 2'500;
            heartbeat.updated_at_unix_ms = 1'500;
            REQUIRE((*store)->upsert_node(heartbeat).has_value());

            auto changed_within_fence = heartbeat;
            changed_within_fence.platform_abi = "linux-x86_64-gnu-v1";
            changed_within_fence.updated_at_unix_ms = 1'600;
            const auto rejected = (*store)->upsert_node(changed_within_fence);
            REQUIRE_FALSE(rejected.has_value());
            REQUIRE(rejected.error().code == StoreErrorCode::stale_fence);
        }

        {
            const auto store = open_control(database);
            REQUIRE(store.has_value());
            const auto snapshot = (*store)->node_snapshot();
            REQUIRE(snapshot.has_value());
            REQUIRE(snapshot->size() == 1);
            REQUIRE(snapshot->front().node_id == first.node_id);
            REQUIRE(snapshot->front().lease_fence == first.lease_fence);
            REQUIRE(snapshot->front().lease_until_unix_ms == 2'500);
            REQUIRE(snapshot->front().capability_hashes == first.capability_hashes);

            auto stale = snapshot->front();
            stale.lease_fence = 6;
            stale.updated_at_unix_ms = 1'700;
            const auto rejected = (*store)->upsert_node(stale);
            REQUIRE_FALSE(rejected.has_value());
            REQUIRE(rejected.error().code == StoreErrorCode::stale_fence);

            auto successor = snapshot->front();
            successor.lease_fence = 8;
            successor.lease_until_unix_ms = 3'000;
            successor.updated_at_unix_ms = 2'000;
            successor.serving = false;
            successor.platform_abi = "windows-x86_64-msvc-v2";
            successor.capability_hashes = {"sha256:capability-c"};
            REQUIRE((*store)->upsert_node(successor).has_value());
            REQUIRE((*store)->node_snapshot()->front().lease_fence == 8);
            REQUIRE_FALSE((*store)->node_snapshot()->front().serving);
        }
    }

    TEST_CASE("server-owned stage freezes resident leases and finalizes only matching reports") {
        TemporaryDatabase database;
        const auto requested = generation(1, "sha256:server-owned-source");
        const auto preview_request = mutation_request("server-owned-stage", 0, 1'000);
        AdminOperationRecord preview;

        {
            const auto store = open_control(database);
            REQUIRE(store.has_value());
            REQUIRE((*store)
                        ->upsert_node(DurableResidentNode {.node_id = "node-a",
                                                           .platform_abi = "windows-x64-v1",
                                                           .lease_fence = 11,
                                                           .lease_until_unix_ms = 10'000,
                                                           .updated_at_unix_ms = 900,
                                                           .serving = true,
                                                           .capability_hashes = {}})
                        .has_value());
            REQUIRE((*store)
                        ->upsert_node(DurableResidentNode {.node_id = "node-b",
                                                           .platform_abi = "linux-x64-v1",
                                                           .lease_fence = 12,
                                                           .lease_until_unix_ms = 10'000,
                                                           .updated_at_unix_ms = 900,
                                                           .serving = true,
                                                           .capability_hashes = {}})
                        .has_value());

            DurableActivationAdmin admin {**store};
            const auto created = admin.preview_server_stage(preview_request, requested);
            REQUIRE(created.has_value());
            preview = *created;
            auto changed_policy = requested;
            changed_policy.policy.bundle_hash =
                "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
            const auto rejected_policy_retry = admin.preview_server_stage(preview_request, changed_policy);
            REQUIRE_FALSE(rejected_policy_retry.has_value());
            REQUIRE(rejected_policy_retry.error().code == StoreErrorCode::constraint_violation);
            const auto compiling = admin.begin_server_stage(apply_request(preview, 0, 1'001), requested);
            REQUIRE(compiling.has_value());
            REQUIRE(compiling->phase == GenerationPhase::compiling);
            REQUIRE(compiling->target_nodes == std::vector<std::string> {"node-a", "node-b"});
            REQUIRE(compiling->targets.size() == 2);
            REQUIRE(compiling->targets.front().lease_fence == 11);
            REQUIRE(compiling->request.policy == requested.policy);
        }

        {
            const auto store = open_control(database);
            REQUIRE(store.has_value());
            DurableActivationAdmin admin {**store};

            auto stale_report = compilation(node("node-a", 10), "sha256:semantic", "sha256:binding");
            const auto stale = admin.report_server_compilation(preview.operation_id, stale_report, 1'100);
            REQUIRE_FALSE(stale.has_value());
            REQUIRE(stale.error().code == StoreErrorCode::stale_fence);

            const auto first = admin.report_server_compilation(
                preview.operation_id, compilation(node("node-a", 11), "sha256:semantic", "sha256:binding"), 1'101);
            REQUIRE(first.has_value());
            REQUIRE(first->phase == GenerationPhase::compiling);
            REQUIRE(first->reports.size() == 1);

            const auto finalized = admin.report_server_compilation(
                preview.operation_id, compilation(node("node-b", 12), "sha256:semantic", "sha256:binding"), 1'102);
            REQUIRE(finalized.has_value());
            REQUIRE(finalized->phase == GenerationPhase::ready);
            REQUIRE(finalized->semantic_hash == "sha256:semantic");
            REQUIRE(finalized->binding_hash == "sha256:binding");
            REQUIRE(admin.operation_snapshot(preview.operation_id)->value().phase == AdminOperationPhase::staged);

            const auto state = admin.state_snapshot();
            REQUIRE(state.has_value());
            REQUIRE(state->packs.front().resource_version == 3);
            REQUIRE(state->generations.front().request.policy == requested.policy);
            REQUIRE_FALSE(state->packs.front().active_generation.has_value());
            REQUIRE_FALSE(state->packs.front().accepting_assignments);
        }
    }

    TEST_CASE("server-owned stage freezes only residents with the required capability inventory") {
        TemporaryDatabase database;
        const auto store = open_control(database);
        REQUIRE(store);
        REQUIRE((*store)
                    ->upsert_node(DurableResidentNode {.node_id = "node-capable",
                                                       .platform_abi = "windows-x64-v1",
                                                       .lease_fence = 21,
                                                       .lease_until_unix_ms = 10'000,
                                                       .updated_at_unix_ms = 900,
                                                       .serving = true,
                                                       .capability_hashes = {"com.acme.fact.process"}})
                    .has_value());
        REQUIRE((*store)
                    ->upsert_node(DurableResidentNode {.node_id = "node-incompatible",
                                                       .platform_abi = "linux-x64-v1",
                                                       .lease_fence = 22,
                                                       .lease_until_unix_ms = 10'000,
                                                       .updated_at_unix_ms = 900,
                                                       .serving = true,
                                                       .capability_hashes = {"com.acme.scan.regex"}})
                    .has_value());

        auto requested = generation(1, "sha256:capability-source");
        requested.required_capability_hashes = {"com.acme.fact.process"};
        DurableActivationAdmin admin {**store};
        const auto preview = admin.preview_server_stage(mutation_request("capability-stage", 0, 1'000), requested);
        REQUIRE(preview);
        const auto compiling = admin.begin_server_stage(apply_request(*preview, 0, 1'001), requested);
        REQUIRE(compiling);
        CHECK(compiling->target_nodes == std::vector<std::string> {"node-capable"});
        REQUIRE(compiling->targets.size() == 1U);
        CHECK(compiling->targets.front().capability_hashes == std::vector<std::string> {"com.acme.fact.process"});
    }

    TEST_CASE("server-owned stage fails closed when resident compilation disagrees") {
        TemporaryDatabase database;
        const auto store = open_control(database);
        REQUIRE(store.has_value());
        REQUIRE((*store)
                    ->upsert_node(DurableResidentNode {.node_id = "node-a",
                                                       .platform_abi = "windows-x64-v1",
                                                       .lease_fence = 11,
                                                       .lease_until_unix_ms = 10'000,
                                                       .updated_at_unix_ms = 900,
                                                       .serving = true,
                                                       .capability_hashes = {}})
                    .has_value());
        REQUIRE((*store)
                    ->upsert_node(DurableResidentNode {.node_id = "node-b",
                                                       .platform_abi = "linux-x64-v1",
                                                       .lease_fence = 12,
                                                       .lease_until_unix_ms = 10'000,
                                                       .updated_at_unix_ms = 900,
                                                       .serving = true,
                                                       .capability_hashes = {}})
                    .has_value());
        DurableActivationAdmin admin {**store};
        const auto requested = generation(1, "sha256:server-owned-source");
        const auto preview = admin.preview_server_stage(mutation_request("server-owned-mismatch", 0, 1'000), requested);
        REQUIRE(preview.has_value());
        REQUIRE(admin.begin_server_stage(apply_request(*preview, 0, 1'001), requested).has_value());
        REQUIRE(admin
                    .report_server_compilation(preview->operation_id,
                                               compilation(node("node-a", 11), "sha256:semantic-a", "sha256:binding"),
                                               1'100)
                    .has_value());
        const auto mismatch = admin.report_server_compilation(
            preview->operation_id, compilation(node("node-b", 12), "sha256:semantic-b", "sha256:binding"), 1'101);
        REQUIRE(mismatch.has_value());
        REQUIRE(mismatch->phase == GenerationPhase::failed);
        REQUIRE(admin.operation_snapshot(preview->operation_id)->value().phase == AdminOperationPhase::failed);
        REQUIRE_FALSE(admin.state_snapshot()->packs.front().active_generation.has_value());
    }

    TEST_CASE("server-owned rollback rejects semantic drift from retained source") {
        TemporaryDatabase database;
        const auto store = open_control(database);
        REQUIRE(store.has_value());
        DurableActivationAdmin admin {**store};
        const auto retained = ready_generation(1, "sha256:source-one");
        const auto active = ready_generation(2, "sha256:source-two");
        auto pack_version = stage_and_activate(admin, retained, 0, "rollback-drift-retained", 10);
        pack_version = stage_and_activate(admin, active, pack_version, "rollback-drift-active", 30);
        REQUIRE(pack_version == 8);
        REQUIRE((*store)
                    ->upsert_node(DurableResidentNode {.node_id = "node-a",
                                                       .platform_abi = "windows-x64-v1",
                                                       .lease_fence = 21,
                                                       .lease_until_unix_ms = 10'000,
                                                       .updated_at_unix_ms = 49,
                                                       .serving = true,
                                                       .capability_hashes = {}})
                    .has_value());
        const StateTransitionPlan carry {.mode = StateTransitionMode::carry,
                                         .source_namespace = {},
                                         .target_namespace = {},
                                         .migration_id = {},
                                         .reset_authorized = false,
                                         .accept_state_gap = false};
        const auto preview =
            admin.preview_rollback(mutation_request("rollback-drift", 8, 50), retained.request.pack, 1, 3, carry);
        REQUIRE(preview.has_value());
        REQUIRE(admin.begin_server_rollback(apply_request(*preview, 8, 51), 1, 3).has_value());
        const auto drifted = admin.report_server_compilation(
            preview->operation_id, compilation(node("node-a", 21), "sha256:changed-semantics", retained.binding_hash),
            52);
        REQUIRE(drifted.has_value());
        REQUIRE(drifted->phase == GenerationPhase::failed);
        REQUIRE(admin.operation_snapshot(preview->operation_id)->value().phase == AdminOperationPhase::failed);
        REQUIRE(admin.state_snapshot()->packs.front().active_generation == 2);
    }

    TEST_CASE("durable activation operations are idempotent and resume across SQLite restarts") {
        TemporaryDatabase database;
        const auto first_generation = ready_generation(1, "sha256:source-one");
        const auto stage_request = mutation_request("durable-stage-one", 0, 10);
        const auto activation_request = mutation_request("durable-activate-one", 1, 20);

        {
            const auto store = open_control(database);
            REQUIRE(store.has_value());
            DurableActivationAdmin admin {**store};

            const auto stage = admin.preview_stage(stage_request, first_generation);
            REQUIRE(stage.has_value());
            REQUIRE(stage->phase == AdminOperationPhase::previewed);
            REQUIRE(admin.preview_stage(stage_request, first_generation)->phase == AdminOperationPhase::previewed);

            auto changed_generation = first_generation;
            changed_generation.request.source_digest = SourceDigest {"sha256:different"};
            const auto changed_retry = admin.preview_stage(stage_request, changed_generation);
            REQUIRE_FALSE(changed_retry.has_value());
            REQUIRE(changed_retry.error().code == StoreErrorCode::constraint_violation);

            const auto preview_inspection = admin.inspect();
            REQUIRE(preview_inspection.has_value());
            REQUIRE(preview_inspection->state.generations.empty());
            REQUIRE(preview_inspection->state.packs.empty());
            REQUIRE(preview_inspection->audit.size() == 1);

            const auto staged = admin.apply_stage(apply_request(*stage, 0, 11), first_generation);
            REQUIRE(staged.has_value());
            REQUIRE(admin.apply_stage(apply_request(*stage, 0, 12), first_generation).has_value());

            const auto activation = admin.preview_activation(activation_request, first_generation.request.pack, 1);
            REQUIRE(activation.has_value());
            const auto activation_preview = admin.state_snapshot();
            REQUIRE(activation_preview.has_value());
            REQUIRE(activation_preview->packs.size() == 1);
            REQUIRE_FALSE(activation_preview->packs.front().active_generation.has_value());
            REQUIRE_FALSE(activation_preview->packs.front().drain_target.has_value());
            REQUIRE(activation_preview->packs.front().resource_version == 1);
        }

        {
            const auto store = open_control(database);
            REQUIRE(store.has_value());
            DurableActivationAdmin admin {**store};
            const auto activation = admin.preview_activation(activation_request, first_generation.request.pack, 1);
            REQUIRE(activation.has_value());
            REQUIRE(activation->phase == AdminOperationPhase::previewed);

            const auto drained = admin.begin_drain(apply_request(*activation, 1, 21), 500);
            REQUIRE(drained.has_value());
            REQUIRE_FALSE(drained->old_generation.has_value());
            REQUIRE(drained->successor_assignment_fence == 1);
            REQUIRE(admin.begin_drain(apply_request(*activation, 1, 22), 500)->successor_assignment_fence == 1);

            const auto draining = admin.state_snapshot();
            REQUIRE(draining.has_value());
            REQUIRE(draining->packs.front().resource_version == 2);
            REQUIRE_FALSE(draining->packs.front().accepting_assignments);
            REQUIRE(draining->packs.front().drain_target == 1);
        }

        {
            const auto store = open_control(database);
            REQUIRE(store.has_value());
            DurableActivationAdmin admin {**store};
            const auto operation = admin.operation_snapshot(activation_request.operation_id);
            REQUIRE(operation.has_value());
            REQUIRE(operation->has_value());

            const auto fenced =
                admin.fence_stragglers(apply_request(**operation, 2, 23), {"work-b", "work-a", "work-a"});
            REQUIRE(fenced.has_value());
            REQUIRE(*fenced == std::vector<std::string> {"work-a", "work-b"});
            const auto fence_retry = admin.fence_stragglers(apply_request(**operation, 2, 24), {"work-a", "work-b"});
            REQUIRE(fence_retry.has_value());
            REQUIRE(*fence_retry == *fenced);
        }

        {
            const auto store = open_control(database);
            REQUIRE(store.has_value());
            DurableActivationAdmin admin {**store};
            const auto operation = admin.operation_snapshot(activation_request.operation_id);
            REQUIRE(operation.has_value());
            REQUIRE(operation->has_value());

            const auto flipped = admin.flip(apply_request(**operation, 3, 25));
            REQUIRE(flipped.has_value());
            REQUIRE(flipped->active_generation == 1);
            REQUIRE_FALSE(flipped->retired_generation.has_value());
            REQUIRE(flipped->assignment_fence == 2);
            REQUIRE(flipped->requeued_work == std::vector<std::string> {"work-a", "work-b"});
            const auto flip_retry = admin.flip(apply_request(**operation, 3, 26));
            REQUIRE(flip_retry.has_value());
            REQUIRE(flip_retry->active_generation == flipped->active_generation);
            REQUIRE(flip_retry->activation_cursor == flipped->activation_cursor);
            REQUIRE(admin.preview_activation(activation_request, first_generation.request.pack, 1)->phase ==
                    AdminOperationPhase::applied);

            const auto inspection = admin.inspect();
            REQUIRE(inspection.has_value());
            REQUIRE(inspection->state.storage_revision == 6);
            REQUIRE(inspection->state.packs.front().resource_version == 4);
            REQUIRE(inspection->state.packs.front().active_generation == 1);
            REQUIRE(inspection->state.packs.front().accepting_assignments);
            REQUIRE_FALSE(inspection->state.packs.front().drain_boundary.has_value());
            REQUIRE(inspection->state.packs.front().pending_requeues.empty());
            REQUIRE(inspection->state.generations.front().phase == GenerationPhase::active);
            REQUIRE(inspection->operations.size() == 2);
            REQUIRE(inspection->audit.size() == 6);
            REQUIRE(inspection->audit.front().action == "admin.pack.stage.preview");
            REQUIRE(inspection->audit.back().action == "admin.pack.activate.flip");
            REQUIRE(std::ranges::all_of(inspection->audit,
                                        [](const AuditRecord &record) { return record.actor == "operator-a"; }));
        }
    }

    TEST_CASE("authorized facade gates and attributes every durable admin operation") {
        TemporaryDatabase database;
        const auto store = open_control(database);
        REQUIRE(store.has_value());
        DurableActivationAdmin durable {**store};
        TestAdminAuthorizer allow_all;
        allow_all.allow_all = true;
        RecordingSecurityAudit security_audit;
        AuthorizedActivationAdmin admin {durable, &allow_all, &security_audit};
        const TenantId tenant {"tenant-a"};
        const auto context = admin_context(tenant, "authenticated-admin");
        const auto first_generation = ready_generation(1, "sha256:source-one");
        const auto second_generation = ready_generation(2, "sha256:source-two");

        auto first_stage_request = mutation_request("authorized-first-stage", 0, 10);
        first_stage_request.actor = "untrusted-request-actor";
        const auto first_stage = admin.preview_stage(context, tenant, first_stage_request, first_generation);
        REQUIRE(first_stage.has_value());
        REQUIRE(first_stage->actor == "authenticated-admin");
        REQUIRE(admin.apply_stage(context, tenant, apply_request(*first_stage, 0, 11), first_generation).has_value());
        const auto first_activation = admin.preview_activation(
            context, tenant, mutation_request("authorized-first-activation", 1, 12), first_generation.request.pack, 1);
        REQUIRE(first_activation.has_value());
        REQUIRE(admin
                    .begin_drain(context, tenant, first_generation.request.pack,
                                 apply_request(*first_activation, 1, 13), 100)
                    .has_value());
        REQUIRE(admin
                    .fence_stragglers(context, tenant, first_generation.request.pack,
                                      apply_request(*first_activation, 2, 14), {})
                    .has_value());
        REQUIRE(admin.flip(context, tenant, first_generation.request.pack, apply_request(*first_activation, 3, 15))
                    .has_value());

        const auto second_stage =
            admin.preview_stage(context, tenant, mutation_request("authorized-second-stage", 4, 20), second_generation);
        REQUIRE(second_stage.has_value());
        REQUIRE(admin.apply_stage(context, tenant, apply_request(*second_stage, 4, 21), second_generation).has_value());
        const auto second_activation =
            admin.preview_activation(context, tenant, mutation_request("authorized-second-activation", 5, 22),
                                     second_generation.request.pack, 2);
        REQUIRE(second_activation.has_value());
        REQUIRE(admin
                    .begin_drain(context, tenant, second_generation.request.pack,
                                 apply_request(*second_activation, 5, 23), 200)
                    .has_value());
        REQUIRE(admin
                    .fence_stragglers(context, tenant, second_generation.request.pack,
                                      apply_request(*second_activation, 6, 24), {"work-two"})
                    .has_value());
        REQUIRE(admin.flip(context, tenant, second_generation.request.pack, apply_request(*second_activation, 7, 25))
                    .has_value());

        const StateTransitionPlan rollback_transition {.mode = StateTransitionMode::carry,
                                                       .source_namespace = {},
                                                       .target_namespace = {},
                                                       .migration_id = {},
                                                       .reset_authorized = false,
                                                       .accept_state_gap = false};
        const auto rollback = admin.preview_rollback(context, tenant, mutation_request("authorized-rollback", 8, 30),
                                                     first_generation.request.pack, 1, 3, rollback_transition);
        REQUIRE(rollback.has_value());
        REQUIRE(rollback->actor == "authenticated-admin");
        auto rollback_generation = first_generation;
        rollback_generation.request.generation = 3;
        rollback_generation.request.rollback_from = 1;
        rollback_generation.request.state_transition = rollback->state_transition;
        REQUIRE(admin.apply_rollback_stage(context, tenant, apply_request(*rollback, 8, 31), rollback_generation)
                    .has_value());

        const auto snapshot = admin.pack_snapshot(context, tenant, first_generation.request.pack);
        REQUIRE(snapshot.has_value());
        REQUIRE(snapshot->control.has_value());
        REQUIRE(snapshot->control->resource_version == 9);
        REQUIRE(snapshot->control->active_generation == 2);
        REQUIRE(snapshot->generations.size() == 3);

        const auto operation =
            admin.operation_snapshot(context, tenant, first_generation.request.pack, rollback->operation_id);
        REQUIRE(operation.has_value());
        REQUIRE(operation->has_value());
        REQUIRE((*operation)->kind == AdminOperationKind::rollback);

        const auto inspection = admin.inspect_pack(context, tenant, first_generation.request.pack);
        REQUIRE(inspection.has_value());
        REQUIRE(inspection->operations.size() == 5);
        REQUIRE(inspection->audit.size() == 14);
        REQUIRE(std::ranges::all_of(inspection->audit,
                                    [](const AuditRecord &record) { return record.actor == "authenticated-admin"; }));

        const auto wrong_resource =
            admin.operation_snapshot(context, tenant, PackId {"pack-b"}, rollback->operation_id);
        REQUIRE(wrong_resource.has_value());
        REQUIRE_FALSE(wrong_resource->has_value());
        const auto unchanged = durable.inspect();
        REQUIRE(unchanged.has_value());
        REQUIRE(unchanged->state.storage_revision == 14);
        REQUIRE(unchanged->audit.size() == 14);

        std::set<AdminControlOperation> observed_operations;
        for (const auto &request : allow_all.requests) { observed_operations.insert(request.operation); }
        REQUIRE(observed_operations ==
                std::set<AdminControlOperation> {
                    AdminControlOperation::stage_preview, AdminControlOperation::stage_apply,
                    AdminControlOperation::activation_preview, AdminControlOperation::activation_drain,
                    AdminControlOperation::activation_fence, AdminControlOperation::activation_flip,
                    AdminControlOperation::rollback_preview, AdminControlOperation::rollback_stage_apply,
                    AdminControlOperation::pack_read, AdminControlOperation::operation_read,
                    AdminControlOperation::pack_inspect});
        REQUIRE(security_audit.events.size() == allow_all.requests.size());
        REQUIRE(std::ranges::all_of(security_audit.events, [](const AdminSecurityAuditEvent &event) {
            return event.outcome == AdminSecurityAuditOutcome::allowed && !event.decision_id.empty();
        }));

        allow_all.allow_all = false;
        const auto denied_after_state =
            admin.preview_stage(context, tenant, mutation_request("denied-after-state", 9, 40),
                                ready_generation(4, "sha256:denied-source"));
        REQUIRE_FALSE(denied_after_state.has_value());
        REQUIRE(denied_after_state.error().code == AuthorizedAdminErrorCode::unauthorized);
        const auto after_denial = durable.inspect();
        REQUIRE(after_denial.has_value());
        REQUIRE(after_denial->state.storage_revision == unchanged->state.storage_revision);
        REQUIRE(after_denial->state.generations.size() == unchanged->state.generations.size());
        REQUIRE(after_denial->operations.size() == unchanged->operations.size());
        REQUIRE(after_denial->audit.size() == unchanged->audit.size());
        REQUIRE(security_audit.events.back().outcome == AdminSecurityAuditOutcome::denied);
    }

    TEST_CASE("control-plane apply rejects stale previews without partially staging a generation") {
        TemporaryDatabase database;
        const auto store = open_control(database);
        REQUIRE(store.has_value());
        DurableActivationAdmin admin {**store};
        const auto first_generation = ready_generation(1, "sha256:source-one");
        const auto second_generation = ready_generation(2, "sha256:source-two");

        const auto first = admin.preview_stage(mutation_request("winner", 0, 10), first_generation);
        const auto second = admin.preview_stage(mutation_request("stale", 0, 11), second_generation);
        REQUIRE(first.has_value());
        REQUIRE(second.has_value());
        REQUIRE(admin.state_snapshot()->generations.empty());
        REQUIRE(admin.apply_stage(apply_request(*first, 0, 12), first_generation).has_value());

        const auto stale_apply = admin.apply_stage(apply_request(*second, 0, 13), second_generation);
        REQUIRE_FALSE(stale_apply.has_value());
        REQUIRE(stale_apply.error().code == StoreErrorCode::stale_fence);
        const auto inspection = admin.inspect();
        REQUIRE(inspection.has_value());
        REQUIRE(inspection->state.generations.size() == 1);
        REQUIRE(inspection->state.generations.front().request.generation == 1);
        REQUIRE(inspection->state.packs.front().resource_version == 1);
        REQUIRE(inspection->audit.size() == 3);
        REQUIRE(admin.operation_snapshot(second->operation_id)->value().phase == AdminOperationPhase::previewed);
    }

    TEST_CASE("durable staging fails closed on implicit incompatible state transitions") {
        TemporaryDatabase database;
        const auto store = open_control(database);
        REQUIRE(store.has_value());
        DurableActivationAdmin admin {**store};
        const auto active = ready_generation(1, "sha256:source-one");
        REQUIRE(stage_and_activate(admin, active, 0, "state-baseline", 10) == 4);

        auto incompatible = ready_generation(2, "sha256:source-two", "state-schema-v2", "state-v2");
        const auto rejected = admin.preview_stage(mutation_request("implicit-state-change", 4, 30), incompatible);
        REQUIRE_FALSE(rejected.has_value());
        REQUIRE(rejected.error().code == StoreErrorCode::incompatible_schema);
        REQUIRE(admin.state_snapshot()->generations.size() == 1);

        incompatible.request.state_transition = StateTransitionPlan {.mode = StateTransitionMode::migrate,
                                                                     .source_namespace = "state-live",
                                                                     .target_namespace = "state-v2",
                                                                     .migration_id = "migration-v2",
                                                                     .reset_authorized = false,
                                                                     .accept_state_gap = false};
        const auto explicit_migration =
            admin.preview_stage(mutation_request("explicit-state-change", 4, 31), incompatible);
        REQUIRE(explicit_migration.has_value());
        REQUIRE(explicit_migration->state_transition.mode == StateTransitionMode::migrate);
        REQUIRE(admin.state_snapshot()->generations.size() == 1);
    }

    TEST_CASE("rollback is a durable forward activation with an explicit state strategy") {
        TemporaryDatabase database;
        const auto first_generation = ready_generation(1, "sha256:source-one");
        const auto second_generation = ready_generation(2, "sha256:source-two");
        AdminMutationRequest rollback_request;
        StateTransitionPlan rollback_transition;

        {
            const auto store = open_control(database);
            REQUIRE(store.has_value());
            DurableActivationAdmin admin {**store};
            auto pack_version = stage_and_activate(admin, first_generation, 0, "first", 10);
            pack_version = stage_and_activate(admin, second_generation, pack_version, "second", 30);
            REQUIRE(pack_version == 8);

            rollback_request = mutation_request("rollback-one", pack_version, 50);
            rollback_transition = StateTransitionPlan {.mode = StateTransitionMode::carry,
                                                       .source_namespace = {},
                                                       .target_namespace = {},
                                                       .migration_id = {},
                                                       .reset_authorized = false,
                                                       .accept_state_gap = false};
            const auto preview =
                admin.preview_rollback(rollback_request, first_generation.request.pack, 1, 3, rollback_transition);
            REQUIRE(preview.has_value());
            REQUIRE(preview->state_transition.source_namespace == "state-live");
            REQUIRE(preview->state_transition.target_namespace == "state-live");
            REQUIRE(admin.state_snapshot()->generations.size() == 2);

            REQUIRE((*store)
                        ->upsert_node(DurableResidentNode {.node_id = "node-a",
                                                           .platform_abi = "windows-x64-v1",
                                                           .lease_fence = 21,
                                                           .lease_until_unix_ms = 10'000,
                                                           .updated_at_unix_ms = 49,
                                                           .serving = true,
                                                           .capability_hashes = {}})
                        .has_value());
            const auto compiling = admin.begin_server_rollback(apply_request(*preview, 8, 51), 1, 3);
            REQUIRE(compiling.has_value());
            REQUIRE(compiling->phase == GenerationPhase::compiling);
            REQUIRE(compiling->request.rollback_from == 1);
            REQUIRE(admin.state_snapshot()->packs.front().resource_version == 9);
            const auto staged = admin.report_server_compilation(
                preview->operation_id,
                compilation(node("node-a", 21), first_generation.semantic_hash, first_generation.binding_hash), 52);
            REQUIRE(staged.has_value());
            REQUIRE(staged->phase == GenerationPhase::ready);
            REQUIRE(admin.operation_snapshot(preview->operation_id)->value().phase == AdminOperationPhase::staged);
            REQUIRE(admin.state_snapshot()->packs.front().resource_version == 10);
        }

        {
            const auto store = open_control(database);
            REQUIRE(store.has_value());
            DurableActivationAdmin admin {**store};
            const auto preview =
                admin.preview_rollback(rollback_request, first_generation.request.pack, 1, 3, rollback_transition);
            REQUIRE(preview.has_value());
            REQUIRE(preview->phase == AdminOperationPhase::staged);
            REQUIRE(admin.begin_server_rollback(apply_request(*preview, 8, 52), 1, 3).has_value());

            const auto drained = admin.begin_drain(apply_request(*preview, 10, 53), 900);
            REQUIRE(drained.has_value());
            REQUIRE(drained->old_generation == 2);
            REQUIRE(drained->target_generation == 3);
        }

        {
            const auto store = open_control(database);
            REQUIRE(store.has_value());
            DurableActivationAdmin admin {**store};
            const auto operation = admin.operation_snapshot(rollback_request.operation_id);
            REQUIRE(operation.has_value());
            REQUIRE(operation->has_value());
            REQUIRE(admin.fence_stragglers(apply_request(**operation, 11, 54), {"rollback-work"}).has_value());
            const auto activated = admin.flip(apply_request(**operation, 12, 55));
            REQUIRE(activated.has_value());
            REQUIRE(activated->retired_generation == 2);
            REQUIRE(activated->active_generation == 3);
            REQUIRE(activated->requeued_work == std::vector<std::string> {"rollback-work"});

            const auto inspection = admin.inspect();
            REQUIRE(inspection.has_value());
            REQUIRE(inspection->state.packs.front().resource_version == 13);
            REQUIRE(inspection->state.packs.front().active_generation == 3);
            REQUIRE(inspection->state.packs.front().accepting_assignments);
            REQUIRE(inspection->state.generations.size() == 3);
            REQUIRE(inspection->state.generations[0].phase == GenerationPhase::retired);
            REQUIRE(inspection->state.generations[1].phase == GenerationPhase::retired);
            REQUIRE(inspection->state.generations[2].phase == GenerationPhase::active);
            REQUIRE(inspection->operations.size() == 5);
            REQUIRE(inspection->audit.size() == 17);
            REQUIRE(admin.preview_rollback(rollback_request, first_generation.request.pack, 1, 3, rollback_transition)
                        ->phase == AdminOperationPhase::applied);

            const auto reused_generation =
                admin.preview_rollback(mutation_request("rollback-stale-generation", 12, 56),
                                       first_generation.request.pack, 1, 2, rollback_transition);
            REQUIRE_FALSE(reused_generation.has_value());
            REQUIRE(reused_generation.error().code == StoreErrorCode::stale_fence);
        }
    }

    TEST_CASE("SQLite shared leases fence a crashed coordinator and recover its receipt") {
        TemporaryDatabase database;
        AuditTrail audit_a;
        AuditTrail audit_b;
        const auto store_a = open_sqlite(database, audit_a);
        const auto store_b = open_sqlite(database, audit_b);
        REQUIRE(store_a.has_value());
        REQUIRE(store_b.has_value());
        DeterministicWorkCoordinator node_a {**store_a, audit_a};
        DeterministicWorkCoordinator node_b {**store_b, audit_b};
        const WorkDefinition work {.work_id = "durable-work",
                                   .pack = PackId {"pack-a"},
                                   .generation = 1,
                                   .serial_domain = "durable:domain",
                                   .event = EventId {"durable-work-event"},
                                   .priority = 1,
                                   .ingest_position = 1};
        REQUIRE(node_a.enqueue(work).value());
        REQUIRE(node_b.enqueue(work).value());

        const auto first = node_a.claim("node-a", 0, 10, 1);
        REQUIRE(first->size() == 1);
        REQUIRE(node_b.claim("node-b", 10, 10, 1)->empty());
        const auto takeover = node_b.claim("node-b", 11, 10, 1);
        REQUIRE(takeover->size() == 1);
        REQUIRE(takeover->front().fence > first->front().fence);
        const auto stale = node_a.commit(first->front(), transaction("durable-work-event", "ignored", 0, 0, 0), 11);
        REQUIRE_FALSE(stale.has_value());
        REQUIRE(stale.error().code == StoreErrorCode::stale_fence);
        REQUIRE(
            node_b.commit(takeover->front(), transaction("durable-work-event", "ignored", 0, 0, 0), 11).has_value());

        AuditTrail audit_c;
        const auto store_c = open_sqlite(database, audit_c);
        REQUIRE(store_c.has_value());
        DeterministicWorkCoordinator recovered {**store_c, audit_c};
        REQUIRE(recovered.enqueue(work).value());
        REQUIRE(recovered.claim("node-c", 12, 10, 1)->empty());
        REQUIRE(recovered.snapshot().front().phase == WorkPhase::completed);
    }

    TEST_CASE("runtime store atomically commits event cursor state result journal and outbox") {
        AuditTrail audit;
        InMemoryRuntimeStore store {audit};
        REQUIRE(store.install_consumer_fence("peer:alpha", 1).has_value());

        const auto proposed = transaction("event-1", "peer:alpha", 0, 1, 0, true, true);
        const auto committed = store.transact_event(proposed);
        REQUIRE(committed.has_value());
        REQUIRE(committed->committed_cursor == 1);
        REQUIRE(committed->emitted_events ==
                std::vector<EventId> {EventId {proposed.evaluation.committed_events.front().id.value}});
        REQUIRE(committed->outbox_intents == std::vector<IntentId> {IntentId {"intent-event-1"}});

        const auto snapshot = store.snapshot();
        REQUIRE(snapshot.events.size() == 2);
        REQUIRE(snapshot.cursors == std::vector<std::pair<std::string, std::uint64_t>> {{"peer:alpha", 1}});
        REQUIRE(snapshot.state.size() == 1);
        REQUIRE(snapshot.state.front().version == 1);
        REQUIRE(snapshot.results.size() == 1);
        REQUIRE(snapshot.journal.size() == 1);
        REQUIRE(snapshot.outbox.size() == 1);
        REQUIRE(snapshot.receipts.size() == 1);

        const auto duplicate = store.transact_event(proposed);
        REQUIRE(duplicate.has_value());
        REQUIRE(duplicate->committed_cursor == committed->committed_cursor);
        REQUIRE(store.snapshot().events.size() == 2);

        auto conflicting_duplicate = proposed;
        conflicting_duplicate.evaluation.verdict = false;
        const auto rejected = store.transact_event(conflicting_duplicate);
        REQUIRE_FALSE(rejected.has_value());
        REQUIRE(rejected.error().code == StoreErrorCode::constraint_violation);
        REQUIRE(store.snapshot().results.size() == 1);

        auto injected = transaction("event-injected", "peer:alpha", 1, 1, 1);
        injected.emitted_events.push_back(event("caller-controlled", 2));
        const auto arbitrary_event = store.transact_event(injected);
        REQUIRE_FALSE(arbitrary_event.has_value());
        REQUIRE(arbitrary_event.error().code == StoreErrorCode::constraint_violation);
        REQUIRE(store.snapshot().events.size() == 2);
    }

    TEST_CASE("agent ACK boundary survives failure before commit and retry after recovery") {
        AuditTrail audit;
        InMemoryRuntimeStore store {audit};
        const AgentStreamId stream {
            .tenant = TenantId {"tenant-crash"},
            .peer = PeerId {"peer-crash"},
            .agent_epoch = "epoch-crash",
        };
        const auto lease = store.claim_lease(LeaseResource {.scope = "agent-session", .key = "tenant-crash/peer-crash"},
                                             "session-crash", 10, 100);
        REQUIRE(lease.has_value());
        const AgentMessageCommit message {
            .stream = stream,
            .session = SessionId {"session-crash"},
            .session_fence = lease->fence,
            .sequence = 1,
            .received_at_unix_ms = 11,
            .body_kind = 4,
            .body = {std::byte {0x2a}},
        };

        store.fail_next_commit(
            StoreError {.code = StoreErrorCode::unavailable, .message = "injected crash", .retryable = true});
        const auto failed = store.transact_agent_message(message);
        REQUIRE_FALSE(failed.has_value());
        REQUIRE(store.load_agent_receipt(stream) == 0);
        REQUIRE(store.inspect()->agent_messages.empty());

        const auto retried = store.transact_agent_message(message);
        REQUIRE(retried.has_value());
        REQUIRE(retried->acknowledged_through == 1);
        REQUIRE_FALSE(retried->duplicate);
        REQUIRE(store.load_agent_receipt(stream) == 1);
        REQUIRE(store.inspect()->agent_messages.size() == 1);
    }

    TEST_CASE("runtime store rollback CAS and stale fence failures publish nothing") {
        AuditTrail audit;
        InMemoryRuntimeStore store {audit};
        REQUIRE(store.install_consumer_fence("group:a", 4).has_value());

        const auto first = transaction("event-a", "group:a", 0, 4, 0);
        store.fail_next_commit(StoreError {
            .code = StoreErrorCode::unavailable,
            .message = "injected before publish",
            .retryable = true,
        });
        const auto failed = store.transact_event(first);
        REQUIRE_FALSE(failed.has_value());
        REQUIRE(failed.error().code == StoreErrorCode::unavailable);
        REQUIRE(store.snapshot().events.empty());
        REQUIRE_FALSE(store
                          .read_state(StoredStateKey {
                              .owner = ExecutableId {"executable-1"}, .namespace_name = "pack-state", .key = "counter"})
                          .has_value());

        REQUIRE(store.transact_event(first).has_value());
        const auto before_conflict = store.snapshot();
        const auto stale_state = transaction("event-b", "group:a", 1, 4, 0, true);
        const auto conflict = store.transact_event(stale_state);
        REQUIRE_FALSE(conflict.has_value());
        REQUIRE(conflict.error().code == StoreErrorCode::conflict);
        const auto after_conflict = store.snapshot();
        REQUIRE(after_conflict.events.size() == before_conflict.events.size());
        REQUIRE(after_conflict.journal.size() == before_conflict.journal.size());
        REQUIRE(after_conflict.outbox.size() == before_conflict.outbox.size());

        REQUIRE(store.install_consumer_fence("group:a", 5).has_value());
        const auto stale_fence = transaction("event-c", "group:a", 1, 4, 1);
        const auto rejected = store.transact_event(stale_fence);
        REQUIRE_FALSE(rejected.has_value());
        REQUIRE(rejected.error().code == StoreErrorCode::stale_fence);
        REQUIRE(store.snapshot().events.size() == 1);

        const auto current = transaction("event-c", "group:a", 1, 5, 1);
        REQUIRE(store.transact_event(current).has_value());
        REQUIRE(store
                    .read_state(StoredStateKey {
                        .owner = ExecutableId {"executable-1"}, .namespace_name = "pack-state", .key = "counter"})
                    ->version == 2);
    }

    TEST_CASE("fenced lease takeover makes the previous owner stale") {
        AuditTrail audit;
        FencedLeaseManager leases {audit};
        const LeaseResource resource {.scope = "peer", .key = "peer-a"};

        const auto first = leases.claim(resource, "node-a", 100, 10);
        REQUIRE(first.has_value());
        REQUIRE(first->fence == 1);

        const auto blocked = leases.claim(resource, "node-b", 109, 10);
        REQUIRE_FALSE(blocked.has_value());
        REQUIRE(blocked.error().code == StoreErrorCode::conflict);

        REQUIRE_FALSE(leases.claim(resource, "node-b", 110, 10).has_value());

        const auto takeover = leases.claim(resource, "node-b", 111, 10);
        REQUIRE(takeover.has_value());
        REQUIRE(takeover->fence > first->fence);
        REQUIRE_FALSE(leases.renew(*first, 111, 10).has_value());
        REQUIRE(leases.renew(*takeover, 112, 10).has_value());
        REQUIRE(leases.release(*takeover, 113).has_value());
        REQUIRE_FALSE(leases.is_current(*takeover, 113));
        REQUIRE(leases.snapshot(113).front().fence > takeover->fence);
    }

    TEST_CASE("two nodes claim deterministic serial domains and recover expired work") {
        AuditTrail audit;
        InMemoryRuntimeStore store {audit};
        DeterministicWorkCoordinator coordinator {store, audit};

        REQUIRE(coordinator
                    .enqueue(WorkDefinition {
                        .work_id = "work-a1",
                        .pack = PackId {"pack-a"},
                        .generation = 1,
                        .serial_domain = "peer:a",
                        .event = EventId {"event-a1"},
                        .priority = 10,
                        .ingest_position = 1,
                    })
                    .value());
        REQUIRE(coordinator
                    .enqueue(WorkDefinition {
                        .work_id = "work-a2",
                        .pack = PackId {"pack-a"},
                        .generation = 1,
                        .serial_domain = "peer:a",
                        .event = EventId {"event-a2"},
                        .priority = 100,
                        .ingest_position = 2,
                    })
                    .value());
        REQUIRE(coordinator
                    .enqueue(WorkDefinition {
                        .work_id = "work-b1",
                        .pack = PackId {"pack-a"},
                        .generation = 1,
                        .serial_domain = "peer:b",
                        .event = EventId {"event-b1"},
                        .priority = 5,
                        .ingest_position = 1,
                    })
                    .value());

        const auto node_a = coordinator.claim("node-a", 0, 10, 1);
        REQUIRE(node_a.has_value());
        REQUIRE(node_a->size() == 1);
        REQUIRE(node_a->front().work.work_id == "work-a1");

        const auto node_b = coordinator.claim("node-b", 1, 10, 2);
        REQUIRE(node_b.has_value());
        REQUIRE(node_b->size() == 1);
        REQUIRE(node_b->front().work.work_id == "work-b1");

        REQUIRE(coordinator.claim("node-b", 10, 10, 1)->empty());

        const auto takeover = coordinator.claim("node-b", 11, 10, 1);
        REQUIRE(takeover.has_value());
        REQUIRE(takeover->size() == 1);
        REQUIRE(takeover->front().work.work_id == "work-a1");
        REQUIRE(takeover->front().fence > node_a->front().fence);

        const auto stale_commit = coordinator.commit(node_a->front(), transaction("event-a1", "ignored", 0, 0, 0), 11);
        REQUIRE_FALSE(stale_commit.has_value());
        REQUIRE(stale_commit.error().code == StoreErrorCode::stale_fence);

        const auto committed = coordinator.commit(takeover->front(), transaction("event-a1", "ignored", 0, 0, 0), 11);
        REQUIRE(committed.has_value());
        REQUIRE(coordinator.recover_receipt(EventId {"event-a1"}).has_value());

        const auto next = coordinator.claim("node-a", 12, 10, 1);
        REQUIRE(next.has_value());
        REQUIRE(next->size() == 1);
        REQUIRE(next->front().work.work_id == "work-a2");
        REQUIRE(coordinator.commit(next->front(), transaction("event-a2", "ignored", 1, 0, 1), 12).has_value());

        const auto snapshot = coordinator.snapshot();
        REQUIRE(std::ranges::count_if(
                    snapshot, [](const WorkSnapshot &work) { return work.phase == WorkPhase::completed; }) == 2);
    }

    TEST_CASE("outbox rows use deterministic leases takeover retry and dead letter") {
        AuditTrail audit;
        InMemoryRuntimeStore store {audit};
        REQUIRE(store.install_consumer_fence("peer:outbox", 1).has_value());
        REQUIRE(store.transact_event(transaction("event-outbox", "peer:outbox", 0, 1, 0, true)).has_value());

        const auto first = store.claim_outbox("worker-a", 100, 10, 1);
        REQUIRE(first.has_value());
        REQUIRE(first->size() == 1);
        REQUIRE(store.claim_outbox("worker-b", 109, 10, 1)->empty());
        REQUIRE(store.claim_outbox("worker-b", 110, 10, 1)->empty());

        const auto takeover = store.claim_outbox("worker-b", 111, 10, 1);
        REQUIRE(takeover.has_value());
        REQUIRE(takeover->size() == 1);
        REQUIRE(takeover->front().fence > first->front().fence);

        const auto stale = store.settle_outbox(OutboxSettlement {
            .intent = first->front().record.intent,
            .owner = first->front().owner,
            .fence = first->front().fence,
            .now_unix_ms = 111,
            .kind = OutboxSettlementKind::delivered,
            .retry_not_before_unix_ms = 0,
            .detail = {},
        });
        REQUIRE_FALSE(stale.has_value());
        REQUIRE(stale.error().code == StoreErrorCode::stale_fence);

        REQUIRE(store
                    .settle_outbox(OutboxSettlement {
                        .intent = takeover->front().record.intent,
                        .owner = takeover->front().owner,
                        .fence = takeover->front().fence,
                        .now_unix_ms = 111,
                        .kind = OutboxSettlementKind::retry,
                        .retry_not_before_unix_ms = 200,
                        .detail = "transient",
                    })
                    .has_value());
        REQUIRE(store.claim_outbox("worker-c", 199, 10, 1)->empty());
        const auto retried = store.claim_outbox("worker-c", 200, 10, 1);
        REQUIRE(retried->size() == 1);
        REQUIRE(retried->front().attempt == 3);
        REQUIRE(store
                    .settle_outbox(OutboxSettlement {
                        .intent = retried->front().record.intent,
                        .owner = retried->front().owner,
                        .fence = retried->front().fence,
                        .now_unix_ms = 200,
                        .kind = OutboxSettlementKind::dead_letter,
                        .detail = "permanent",
                    })
                    .has_value());
        REQUIRE(store.snapshot().outbox.front().state == StoredOutboxState::dead_letter);
    }

    TEST_CASE("activation compares every node drains without overlap and rolls back forward") {
        AuditTrail audit;
        ActivationController activation {audit};
        const auto windows = node("node-windows", 10);
        const auto linux = node("node-linux", 20);
        const std::vector initial_nodes {windows, linux};
        REQUIRE(activation.register_node(windows, 1, "operator").has_value());
        REQUIRE(activation.register_node(linux, 1, "operator").has_value());

        const auto first = generation(1, "sha256:source-one");
        stage_ready(activation, first, initial_nodes, "sha256:semantic-one", "sha256:bindings-one", 10);
        REQUIRE(activation.begin_drain(first.pack, 1, 100, 13, "operator").has_value());
        const auto first_activation = activation.flip(first.pack, 1, 14, "operator");
        REQUIRE(first_activation.has_value());
        REQUIRE(first_activation->active_generation == 1);
        REQUIRE(activation.assignment_allowed(first.pack, 1));
        const auto first_fence = first_activation->assignment_fence;
        REQUIRE(activation.register_assignment(first.pack, 1, "old-work", first_fence).has_value());

        const auto mismatch = generation(2, "sha256:source-two");
        REQUIRE(activation.begin_stage(mismatch, 20, "operator").has_value());
        REQUIRE(activation
                    .report_compilation(mismatch.pack, 2,
                                        compilation(windows, "sha256:semantic-two", "sha256:bindings-two"), 21)
                    .has_value());
        REQUIRE(activation
                    .report_compilation(mismatch.pack, 2, compilation(linux, "sha256:drift", "sha256:bindings-two"), 21)
                    .has_value());
        const auto mismatch_result = activation.finalize_stage(mismatch.pack, 2, 22, "operator");
        REQUIRE(mismatch_result.has_value());
        REQUIRE(mismatch_result->phase == GenerationPhase::failed);
        REQUIRE(activation.active_snapshot(first.pack).generation == 1);

        const auto third = generation(3, "sha256:source-three");
        REQUIRE(activation.begin_stage(third, 30, "operator").has_value());
        const auto joining = node("node-joining", 30);
        REQUIRE(activation.register_node(joining, 31, "operator").has_value());
        REQUIRE(activation
                    .report_compilation(third.pack, 3,
                                        compilation(windows, "sha256:semantic-three", "sha256:bindings-three"), 31)
                    .has_value());
        REQUIRE(activation
                    .report_compilation(third.pack, 3,
                                        compilation(linux, "sha256:semantic-three", "sha256:bindings-three"), 31)
                    .has_value());
        REQUIRE(activation.finalize_stage(third.pack, 3, 32, "operator")->phase == GenerationPhase::ready);

        const auto drain = activation.begin_drain(third.pack, 3, 200, 33, "operator");
        REQUIRE(drain.has_value());
        REQUIRE(drain->in_flight_work == std::vector<std::string> {"old-work"});
        REQUIRE_FALSE(activation.assignment_allowed(first.pack, 1));
        REQUIRE_FALSE(activation.assignment_allowed(third.pack, 3));
        const auto blocked_flip = activation.flip(third.pack, 3, 34, "operator");
        REQUIRE_FALSE(blocked_flip.has_value());
        REQUIRE(blocked_flip.error().code == StoreErrorCode::conflict);

        const auto requeued = activation.fence_stragglers(third.pack, 3, 35, "operator");
        REQUIRE(requeued == std::vector<std::string> {"old-work"});
        const auto cutover = activation.flip(third.pack, 3, 36, "operator");
        REQUIRE(cutover.has_value());
        REQUIRE(cutover->retired_generation == 1);
        REQUIRE(cutover->requeued_work == std::vector<std::string> {"old-work"});
        REQUIRE(activation.assignment_allowed(third.pack, 3));
        REQUIRE_FALSE(activation.assignment_allowed(first.pack, 1));
        REQUIRE_FALSE(activation.finish_assignment(first.pack, 1, "old-work", first_fence).has_value());
        REQUIRE_FALSE(activation.node_ready_for_pack(joining.node_id, third.pack));
        REQUIRE(activation
                    .record_active_compilation(joining.node_id, joining.lease_fence, third.pack, 3,
                                               "sha256:semantic-three", "sha256:bindings-three", 37)
                    .has_value());
        REQUIRE(activation.node_ready_for_pack(joining.node_id, third.pack));

        const auto rollback = activation.begin_rollback_stage(third.pack, 1, 4,
                                                              StateTransitionPlan {
                                                                  .mode = StateTransitionMode::carry,
                                                                  .source_namespace = {},
                                                                  .target_namespace = {},
                                                                  .migration_id = {},
                                                                  .reset_authorized = false,
                                                                  .accept_state_gap = false,
                                                              },
                                                              40, "operator");
        REQUIRE(rollback.has_value());
        REQUIRE(rollback->request.rollback_from == 1);
        const std::vector rollback_nodes {windows, linux, joining};
        for (const auto &target : rollback_nodes) {
            REQUIRE(activation
                        .report_compilation(third.pack, 4,
                                            compilation(target, "sha256:semantic-one", "sha256:bindings-one"), 41)
                        .has_value());
        }
        REQUIRE(activation.finalize_stage(third.pack, 4, 42, "operator")->phase == GenerationPhase::ready);
        REQUIRE(activation.begin_drain(third.pack, 4, 300, 43, "operator").has_value());
        const auto rolled_back = activation.flip(third.pack, 4, 44, "operator");
        REQUIRE(rolled_back.has_value());
        REQUIRE(rolled_back->retired_generation == 3);
        REQUIRE(rolled_back->active_generation == 4);
        REQUIRE(activation.generation_snapshot(third.pack, 4)->request.source_digest ==
                SourceDigest {"sha256:source-one"});
    }

    TEST_CASE("peer breaker uses exact window quarantine and one half-open probe") {
        AuditTrail audit;
        TripleFaultBreaker breaker {audit};
        const BindingId binding {"binding-peer"};
        const PeerId peer {"peer-one"};
        const SourceDigest source {"sha256:signed-one"};
        breaker.activate_signed_source(binding, source, 0, "operator");

        REQUIRE(breaker.record_triple_fault(binding, peer, source, 0)->allowed);
        REQUIRE(breaker.record_triple_fault(binding, peer, source, minute_ms)->allowed);
        const auto third = breaker.record_triple_fault(binding, peer, source, 2 * minute_ms);
        REQUIRE(third.has_value());
        REQUIRE(third->kind == BreakerAdmissionKind::peer_quarantined);
        REQUIRE_FALSE(third->allowed);

        const auto blocked = breaker.admit(binding, peer, source, 31 * minute_ms);
        REQUIRE(blocked->kind == BreakerAdmissionKind::peer_quarantined);
        const auto probe = breaker.admit(binding, peer, source, 32 * minute_ms);
        REQUIRE(probe->kind == BreakerAdmissionKind::half_open_probe);
        REQUIRE(probe->allowed);
        REQUIRE_FALSE(breaker.admit(binding, peer, source, 32 * minute_ms)->allowed);
        REQUIRE(breaker.complete_half_open(binding, peer, source, true, 32 * minute_ms).has_value());
        REQUIRE(breaker.admit(binding, peer, source, 32 * minute_ms)->kind == BreakerAdmissionKind::allowed);

        REQUIRE(breaker.record_triple_fault(binding, peer, source, 40 * minute_ms)->allowed);
        REQUIRE(breaker.record_triple_fault(binding, peer, source, 41 * minute_ms)->allowed);
        REQUIRE_FALSE(breaker.record_triple_fault(binding, peer, source, 42 * minute_ms)->allowed);
        REQUIRE(breaker.admit(binding, peer, source, 72 * minute_ms)->kind == BreakerAdmissionKind::half_open_probe);
        REQUIRE(breaker.complete_half_open(binding, peer, source, false, 72 * minute_ms).has_value());
        REQUIRE(breaker.admit(binding, peer, source, 73 * minute_ms)->kind == BreakerAdmissionKind::peer_quarantined);

        const PeerId window_peer {"peer-window"};
        REQUIRE(breaker.record_triple_fault(binding, window_peer, source, 80 * minute_ms)->allowed);
        REQUIRE(breaker.record_triple_fault(binding, window_peer, source, 81 * minute_ms)->allowed);
        REQUIRE(breaker.record_triple_fault(binding, window_peer, source, 92 * minute_ms)->allowed);
    }

    TEST_CASE("global breaker requires five faults across three peers until clear or new signed source") {
        AuditTrail audit;
        TripleFaultBreaker breaker {audit};
        const BindingId binding {"binding-global"};
        const SourceDigest source_one {"sha256:signed-one"};
        const SourceDigest source_two {"sha256:signed-two"};
        breaker.activate_signed_source(binding, source_one, 0, "operator");

        const std::vector peers {
            PeerId {"peer-a"}, PeerId {"peer-b"}, PeerId {"peer-c"}, PeerId {"peer-a"}, PeerId {"peer-b"},
        };
        for (std::size_t index = 0; index < peers.size(); ++index) {
            REQUIRE(breaker
                        .record_triple_fault(binding, peers[index], source_one,
                                             static_cast<std::uint64_t>(index) * minute_ms)
                        .has_value());
        }
        REQUIRE(breaker.global_snapshot(5 * minute_ms).front().quarantined);
        REQUIRE(breaker.admit(binding, PeerId {"peer-z"}, source_one, 100 * minute_ms)->kind ==
                BreakerAdmissionKind::global_quarantined);

        REQUIRE(breaker.clear_global(binding, 101 * minute_ms, "operator").has_value());
        REQUIRE_FALSE(breaker.global_snapshot(101 * minute_ms).front().quarantined);
        REQUIRE(breaker.admit(binding, PeerId {"peer-z"}, source_one, 101 * minute_ms)->allowed);

        for (std::size_t index = 0; index < peers.size(); ++index) {
            REQUIRE(breaker
                        .record_triple_fault(binding, peers[index], source_one,
                                             (110 + static_cast<std::uint64_t>(index)) * minute_ms)
                        .has_value());
        }
        REQUIRE(breaker.global_snapshot(115 * minute_ms).front().quarantined);
        breaker.activate_signed_source(binding, source_two, 116 * minute_ms, "operator");
        REQUIRE_FALSE(breaker.global_snapshot(116 * minute_ms).front().quarantined);
        REQUIRE(breaker.admit(binding, PeerId {"peer-z"}, source_two, 116 * minute_ms)->allowed);
        REQUIRE(breaker.admit(binding, PeerId {"peer-z"}, source_one, 116 * minute_ms)->kind ==
                BreakerAdmissionKind::source_not_active);
    }

    TEST_CASE("readiness and audit snapshots expose blockers without claiming unavailable drivers") {
        const auto backend = validate_store_backend(InMemoryReferenceConfig {});
        REQUIRE(backend.has_value());
        const ReadinessInput ready_input {
            .process_responsive = true,
            .database_reachable = true,
            .backend_driver_ready = true,
            .migrations_compatible = true,
            .node_lease_current = true,
            .trust_policy_loaded = true,
            .retention_profiles_loaded = true,
            .active_generation_compiled = true,
            .schemas_compatible = true,
            .required_capabilities_available = true,
            .backend = *backend,
        };
        REQUIRE(evaluate_readiness(ready_input).ready);

        auto blocked_input = ready_input;
        blocked_input.active_generation_compiled = false;
        const auto blocked = evaluate_readiness(blocked_input);
        REQUIRE(blocked.live);
        REQUIRE_FALSE(blocked.ready);
        REQUIRE(blocked.blockers == std::vector<std::string> {"active pack generation is not compiled locally"});

        AuditTrail audit;
        REQUIRE(audit.append(1, "operator", "pack.stage", "pack-a:1", "ready", "two nodes") == 1);
        REQUIRE(audit.append(2, "node-a", "work.claim", "work-1", "leased", "fence 4") == 2);
        const auto records = audit.snapshot();
        REQUIRE(records.size() == 2);
        REQUIRE(records.front().sequence == 1);
        REQUIRE(records.back().sequence == 2);

        const auto postgres_backend = validate_store_backend(PostgreSql17Config {
            .connection_reference = "secret://runtime/postgres",
            .server_major = 17,
            .server_processes = 2,
            .pool_size = 16,
            .statement_timeout = std::chrono::seconds {5},
            .verify_tls_peer = true,
            .external_ha_configured = true,
            .deployment_mode = DeploymentMode::production_cluster,
        });
        REQUIRE(postgres_backend.has_value());
        auto postgres_input = ready_input;
        postgres_input.backend = *postgres_backend;
        const RuntimeStoreHealth disconnected_postgres {
            .backend = StoreBackendKind::postgresql17,
            .driver_available = postgres_backend->implementation_available,
            .connected = false,
            .migrations_compatible = false,
            .schema_version = 0,
            .server_version = {},
            .detail = "qualification database is absent",
        };
        const auto postgres_readiness = evaluate_readiness(postgres_input, disconnected_postgres);
        REQUIRE_FALSE(postgres_readiness.ready);
        REQUIRE(std::ranges::contains(postgres_readiness.blockers, "runtime store is unreachable"));
        REQUIRE(std::ranges::contains(postgres_readiness.blockers, "store migrations are incompatible"));
#if !defined(RULE_ENGINE_HAS_POSTGRESQL)
        REQUIRE(std::ranges::contains(postgres_readiness.blockers, "selected runtime-store driver is not ready"));
        const auto unavailable = PostgreSqlRuntimeStore::open(
            PostgreSql17Config {
                .connection_reference = "secret://runtime/postgres",
            },
            audit);
        REQUIRE_FALSE(unavailable.has_value());
        REQUIRE(unavailable.error().code == StoreErrorCode::unavailable);
        const auto unavailable_control = PostgreSqlActivationControlStore::open(PostgreSql17Config {
            .connection_reference = "secret://runtime/postgres",
        });
        REQUIRE_FALSE(unavailable_control.has_value());
        REQUIRE(unavailable_control.error().code == StoreErrorCode::unavailable);
#endif
    }

} // namespace
