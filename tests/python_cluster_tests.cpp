#include "rule_engine/python/cluster/cluster.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <functional>
#include <memory>
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
        std::vector<StateMutation> state {state_mutation(state_version, "sha256:state-" + event_id)};
        std::vector<EffectIntent> journal;
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
            emitted.push_back(event("emitted-" + event_id, expected_cursor + 1));
        }
        EvaluationResult evaluation {
            .outcome = EvaluationOutcome::match,
            .verdict = true,
            .committed_effects = journal,
            .state_mutations = state,
            .fault = std::nullopt,
        };
        return RuntimeTransaction {
            .input = event(event_id, expected_cursor + 1),
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
        REQUIRE(history->front().id == EventId {"contract-event"});

        const auto snapshot = store.inspect();
        REQUIRE(snapshot.has_value());
        REQUIRE(snapshot->events.size() == 2);
        REQUIRE(snapshot->state.size() == 1);
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

    TEST_CASE("runtime store contract is parameterized across reference and SQLite adapters") {
        SECTION("in-memory reference") {
            AuditTrail audit;
            InMemoryRuntimeStore store {audit};
            verify_runtime_store_contract(store);
        }
        SECTION("SQLite durable adapter") {
            TemporaryDatabase database;
            AuditTrail audit;
            const auto store = open_sqlite(database, audit);
            REQUIRE(store.has_value());
            verify_runtime_store_contract(**store);
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
        GenerationSnapshot rollback_generation;

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

            rollback_generation = first_generation;
            rollback_generation.request.generation = 3;
            rollback_generation.request.rollback_from = 1;
            rollback_generation.request.state_transition = preview->state_transition;
            const auto staged = admin.apply_rollback_stage(apply_request(*preview, 8, 51), rollback_generation);
            REQUIRE(staged.has_value());
            REQUIRE(staged->request.rollback_from == 1);
            REQUIRE(admin.state_snapshot()->packs.front().resource_version == 9);
        }

        {
            const auto store = open_control(database);
            REQUIRE(store.has_value());
            DurableActivationAdmin admin {**store};
            const auto preview =
                admin.preview_rollback(rollback_request, first_generation.request.pack, 1, 3, rollback_transition);
            REQUIRE(preview.has_value());
            REQUIRE(preview->phase == AdminOperationPhase::staged);
            REQUIRE(admin.apply_rollback_stage(apply_request(*preview, 8, 52), rollback_generation).has_value());

            const auto drained = admin.begin_drain(apply_request(*preview, 9, 53), 900);
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
            REQUIRE(admin.fence_stragglers(apply_request(**operation, 10, 54), {"rollback-work"}).has_value());
            const auto activated = admin.flip(apply_request(**operation, 11, 55));
            REQUIRE(activated.has_value());
            REQUIRE(activated->retired_generation == 2);
            REQUIRE(activated->active_generation == 3);
            REQUIRE(activated->requeued_work == std::vector<std::string> {"rollback-work"});

            const auto inspection = admin.inspect();
            REQUIRE(inspection.has_value());
            REQUIRE(inspection->state.packs.front().resource_version == 12);
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
        REQUIRE(committed->emitted_events == std::vector<EventId> {EventId {"emitted-event-1"}});
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
