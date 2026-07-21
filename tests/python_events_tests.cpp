#include "rule_engine/python/events/reference_runtime.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace {

    using namespace rule_engine::python;
    using namespace rule_engine::python::events;

    DataLabel public_label() { return DataLabel {.classification = Classification::public_data, .categories = {}}; }

    DataLabel security_label(const Classification classification = Classification::internal) {
        return DataLabel {.classification = classification, .categories = {"security"}};
    }

    FrozenValue record_value(const std::string &schema, const std::string &digest, DataLabel label = public_label()) {
        return FrozenValue {
            .value = make_fact(FactRecord {
                .schema = SchemaId {schema},
                .fields = {{.field_id = 1, .value = make_fact(UnicodeValue {digest})}},
            }),
            .label = std::move(label),
            .canonical_digest = digest,
        };
    }

    EventSchema event_schema(const std::string &event_id, const std::string &payload_id,
                             DataLabel ceiling = public_label()) {
        return EventSchema {
            .id = SchemaId {event_id},
            .family = EventFamily::observation,
            .payload_shape = PayloadShape::record,
            .payload_record_schema = SchemaId {payload_id},
            .label_ceiling = std::move(ceiling),
            .subject_required = false,
        };
    }

    EventEnvelope event(const std::string &id, const std::string &event_schema_id, const std::string &payload_schema_id,
                        const std::uint64_t producer, const std::uint64_t ingest,
                        const std::string &tenant = "tenant-a", const std::string &peer = "peer-a",
                        DataLabel label = public_label(), std::optional<EventId> causation = std::nullopt) {
        auto payload_label = label;
        return EventEnvelope {
            .id = EventId {id},
            .schema = SchemaId {event_schema_id},
            .tenant = TenantId {tenant},
            .peer = PeerId {peer},
            .subject = std::nullopt,
            .producer_unix_ms = producer,
            .ingest_unix_ms = ingest,
            .label = std::move(label),
            .causation = std::move(causation),
            .payload = record_value(payload_schema_id, "digest:" + id, std::move(payload_label)),
        };
    }

    StateNamespace state_namespace() {
        return StateNamespace {
            .tenant = TenantId {"tenant-a"},
            .owner = ExecutableId {"pack-a.rule"},
            .namespace_id = "state-v1",
            .schema = SchemaId {"state.counter/v1"},
            .label_ceiling = security_label(Classification::sensitive),
            .shared_readers = {ExecutableId {"pack-b.reader"}},
            .shared_writers = {},
        };
    }

    StateAddress state_address() {
        return StateAddress {
            .tenant = TenantId {"tenant-a"},
            .owner = ExecutableId {"pack-a.rule"},
            .namespace_id = "state-v1",
            .schema = SchemaId {"state.counter/v1"},
            .peer = PeerId {"peer-a"},
            .scope = "correlation-group",
            .key = "image:C:/game.exe",
        };
    }

    SchemaCatalog projection_schemas() {
        return SchemaCatalog {
            .descriptors = {SchemaDescriptor {
                .id = SchemaId {"custom.alert/v1"},
                .kind = SchemaKind::event,
                .qualified_name = "rules.CustomAlert",
                .canonical_hash = "sha256:custom-alert-v1",
                .fields = {SchemaField {.field_id = 1U,
                                        .name = "message",
                                        .type = SchemaId {"text"},
                                        .optional = false,
                                        .label = security_label()}},
            }},
            .canonical_hash = "sha256:projection-schemas",
        };
    }

    VmInvocation projection_invocation() {
        return VmInvocation {
            .execution = ExecutionId {"execution-a"},
            .invocation = InvocationId {"invocation-a"},
            .root_event = EventId {"root-a"},
            .binding = BindingId {"binding-a"},
            .subject = SubjectKey {.peer = PeerId {"peer-a"},
                                   .descriptor = SchemaId {"process/v1"},
                                   .identity = {{.field_id = 1U, .value = std::uint64_t {7U}}},
                                   .parent = {}},
        };
    }

    EventIntent projection_intent(const std::uint64_t sequence) {
        return EventIntent {
            .id = deterministic_event_intent_id(EventId {"root-a"}, InvocationId {"invocation-a"}, sequence),
            .root_event = EventId {"root-a"},
            .invocation = InvocationId {"invocation-a"},
            .owner = ExecutableId {"rules.emit"},
            .binding = BindingId {"binding-a"},
            .sequence = sequence,
            .schema = SchemaId {"custom.alert/v1"},
            .schema_hash = "sha256:custom-alert-v1",
            .payload = record_value("custom.alert/v1", "digest:event-" + std::to_string(sequence), security_label()),
            .span = SourceSpan {.source = SourceId {"rules.py"}, .begin_byte = 10U, .end_byte = 11U},
            .disposition = EventDisposition::committed,
        };
    }

    TEST_CASE("committed event projection is pure ordered causal and deterministic") {
        const auto root = event("root-a", "input/v1", "input.payload/v1", 100U, 110U);
        const auto invocation = projection_invocation();
        const std::vector intents {projection_intent(1U), projection_intent(3U)};

        const auto first = project_committed_events(root, invocation, projection_schemas(), intents);
        const auto second = project_committed_events(root, invocation, projection_schemas(), intents);

        REQUIRE(first.has_value());
        REQUIRE(second.has_value());
        REQUIRE(first->size() == 2U);
        CHECK(first->front().id == EventId {intents.front().id.value});
        CHECK(first->back().id == EventId {intents.back().id.value});
        CHECK(first->front().causation == EventId {"root-a"});
        CHECK(first->front().tenant == root.tenant);
        CHECK(first->front().peer == root.peer);
        CHECK(first->front().producer_unix_ms == root.ingest_unix_ms);
        CHECK(first->front().payload.canonical_digest == second->front().payload.canonical_digest);
        CHECK(first->front().label == security_label());
    }

    TEST_CASE("event projection rejects malformed identity order schema payload and budgets") {
        const auto root = event("root-a", "input/v1", "input.payload/v1", 100U, 110U);
        const auto invocation = projection_invocation();

        SECTION("identity and order") {
            auto wrong_identity = projection_intent(1U);
            wrong_identity.id = IntentId {"forged"};
            const std::array intents {wrong_identity};
            const auto rejected = project_committed_events(root, invocation, projection_schemas(), intents);
            REQUIRE_FALSE(rejected.has_value());
            CHECK(rejected.error().code == EventProjectionErrorCode::invalid_identity);

            const std::array reversed {projection_intent(2U), projection_intent(1U)};
            const auto out_of_order = project_committed_events(root, invocation, projection_schemas(), reversed);
            REQUIRE_FALSE(out_of_order.has_value());
            CHECK(out_of_order.error().code == EventProjectionErrorCode::invalid_order);
        }

        SECTION("schema hash and field type") {
            auto wrong_hash = projection_intent(1U);
            wrong_hash.schema_hash = "sha256:other";
            const std::array intents {wrong_hash};
            const auto rejected = project_committed_events(root, invocation, projection_schemas(), intents);
            REQUIRE_FALSE(rejected.has_value());
            CHECK(rejected.error().code == EventProjectionErrorCode::invalid_schema);

            auto wrong_value = projection_intent(1U);
            wrong_value.payload.value = make_fact(FactRecord {
                .schema = SchemaId {"custom.alert/v1"},
                .fields = {{.field_id = 1U, .value = make_fact(true)}},
            });
            const std::array malformed {wrong_value};
            const auto value_rejected = project_committed_events(root, invocation, projection_schemas(), malformed);
            REQUIRE_FALSE(value_rejected.has_value());
            CHECK(value_rejected.error().code == EventProjectionErrorCode::invalid_schema);
        }

        SECTION("label disposition and count") {
            auto wrong_label = projection_intent(1U);
            wrong_label.payload.label = public_label();
            const std::array intents {wrong_label};
            const auto label_rejected = project_committed_events(root, invocation, projection_schemas(), intents);
            REQUIRE_FALSE(label_rejected.has_value());
            CHECK(label_rejected.error().code == EventProjectionErrorCode::invalid_payload);

            auto pending = projection_intent(1U);
            pending.disposition = EventDisposition::pending;
            const std::array pending_intents {pending};
            const auto pending_rejected =
                project_committed_events(root, invocation, projection_schemas(), pending_intents);
            REQUIRE_FALSE(pending_rejected.has_value());
            CHECK(pending_rejected.error().code == EventProjectionErrorCode::invalid_identity);

            const std::array too_many {projection_intent(1U), projection_intent(2U)};
            const auto budget_rejected = project_committed_events(
                root, invocation, projection_schemas(), too_many,
                EventProjectionLimits {.maximum_intents = 1U, .maximum_bytes = 1U * mebibyte, .maximum_depth = 8U});
            REQUIRE_FALSE(budget_rejected.has_value());
            CHECK(budget_rejected.error().code == EventProjectionErrorCode::budget_exhausted);
        }
    }

    TEST_CASE("typed event admission validates schema labels and causation") {
        InMemoryReferenceRuntime runtime;
        REQUIRE(runtime
                    .register_event_schema(event_schema("process.observed/v1", "process.payload/v1",
                                                        security_label(Classification::sensitive)))
                    .has_value());

        const auto parent = event("event-parent", "process.observed/v1", "process.payload/v1", 100, 110, "tenant-a",
                                  "peer-a", security_label());
        const auto admitted = runtime.append_event(parent);
        REQUIRE(admitted.has_value());
        REQUIRE_FALSE(admitted->duplicate);
        REQUIRE(admitted->causation_depth == 0);

        const auto duplicate = runtime.append_event(parent);
        REQUIRE(duplicate.has_value());
        REQUIRE(duplicate->duplicate);
        REQUIRE(duplicate->ingest_position == admitted->ingest_position);

        const auto child =
            runtime.append_event(event("event-child", "process.observed/v1", "process.payload/v1", 120, 130, "tenant-a",
                                       "peer-a", security_label(), EventId {"event-parent"}));
        REQUIRE(child.has_value());
        REQUIRE(child->causation_depth == 1);

        const auto wrong_record = runtime.append_event(event("event-wrong", "process.observed/v1", "other.payload/v1",
                                                             140, 150, "tenant-a", "peer-a", security_label()));
        REQUIRE_FALSE(wrong_record.has_value());
        REQUIRE(wrong_record.error().code == ErrorCode::schema_mismatch);

        const auto excessive_label =
            runtime.append_event(event("event-secret", "process.observed/v1", "process.payload/v1", 160, 170,
                                       "tenant-a", "peer-a", security_label(Classification::secret)));
        REQUIRE_FALSE(excessive_label.has_value());
        REQUIRE(excessive_label.error().code == ErrorCode::invalid_label);

        const auto self_caused =
            runtime.append_event(event("event-cycle", "process.observed/v1", "process.payload/v1", 180, 190, "tenant-a",
                                       "peer-a", security_label(), EventId {"event-cycle"}));
        REQUIRE_FALSE(self_caused.has_value());
        REQUIRE(self_caused.error().code == ErrorCode::causation_cycle);
    }

    TEST_CASE("bounded history is tenant peer schema and time scoped with stable pagination") {
        InMemoryReferenceRuntime runtime;
        REQUIRE(runtime.register_event_schema(event_schema("process/v1", "process.payload/v1")).has_value());

        REQUIRE(runtime.append_event(event("event-b", "process/v1", "process.payload/v1", 150, 200)).has_value());
        REQUIRE(runtime.append_event(event("event-a", "process/v1", "process.payload/v1", 140, 200)).has_value());
        REQUIRE(runtime.append_event(event("event-c", "process/v1", "process.payload/v1", 160, 300)).has_value());
        REQUIRE(runtime.append_event(event("other-tenant", "process/v1", "process.payload/v1", 170, 250, "tenant-b"))
                    .has_value());
        REQUIRE(
            runtime
                .append_event(event("other-peer", "process/v1", "process.payload/v1", 180, 260, "tenant-a", "peer-b"))
                .has_value());

        HistoryPlan plan {
            .tenant = TenantId {"tenant-a"},
            .peer = PeerId {"peer-a"},
            .fleet_history = false,
            .schemas = {SchemaId {"process/v1"}},
            .time_basis = HistoryTimeBasis::ingest,
            .begin_unix_ms = 100,
            .end_unix_ms = 400,
            .limit = 3,
            .page_rows = 1,
            .result_ceiling = public_label(),
            .after = std::nullopt,
        };

        const auto first = runtime.query_history(plan);
        REQUIRE(first.has_value());
        REQUIRE(first->events.size() == 1);
        REQUIRE(first->events.front().id == EventId {"event-a"});
        REQUIRE(first->next.has_value());

        REQUIRE(runtime.append_event(event("event-new", "process/v1", "process.payload/v1", 155, 250)).has_value());

        plan.after = first->next;
        const auto second = runtime.query_history(plan);
        REQUIRE(second.has_value());
        REQUIRE(second->events.size() == 1);
        REQUIRE(second->events.front().id == EventId {"event-b"});
        REQUIRE(second->next.has_value());

        plan.after = second->next;
        const auto third = runtime.query_history(plan);
        REQUIRE(third.has_value());
        REQUIRE(third->events.size() == 1);
        REQUIRE(third->events.front().id == EventId {"event-c"});
        REQUIRE_FALSE(third->next.has_value());

        plan.peer.reset();
        plan.after.reset();
        plan.fleet_history = true;
        plan.limit = 5;
        plan.page_rows = 5;
        const auto fleet = runtime.query_history(plan);
        REQUIRE(fleet.has_value());
        REQUIRE(fleet->events.size() == 5);
        REQUIRE(fleet->events[0].id == EventId {"event-a"});
        REQUIRE(fleet->events[1].id == EventId {"event-b"});
        REQUIRE(fleet->events[2].id == EventId {"event-new"});
        REQUIRE(fleet->events[3].id == EventId {"other-peer"});
        REQUIRE(fleet->events[4].id == EventId {"event-c"});

        plan.fleet_history = false;
        const auto unbounded_peer = runtime.query_history(plan);
        REQUIRE_FALSE(unbounded_peer.has_value());
        REQUIRE(unbounded_peer.error().code == ErrorCode::invalid_bounds);
    }

    TEST_CASE("history rejects results above the capability label ceiling") {
        InMemoryReferenceRuntime runtime;
        REQUIRE(runtime
                    .register_event_schema(
                        event_schema("security/v1", "security.payload/v1", security_label(Classification::secret)))
                    .has_value());
        REQUIRE(runtime
                    .append_event(event("secret-event", "security/v1", "security.payload/v1", 100, 110, "tenant-a",
                                        "peer-a", security_label(Classification::secret)))
                    .has_value());

        const HistoryPlan plan {
            .tenant = TenantId {"tenant-a"},
            .peer = PeerId {"peer-a"},
            .fleet_history = false,
            .schemas = {SchemaId {"security/v1"}},
            .time_basis = HistoryTimeBasis::ingest,
            .begin_unix_ms = 1,
            .end_unix_ms = 1'000,
            .limit = 10,
            .page_rows = 10,
            .result_ceiling = security_label(Classification::internal),
            .after = std::nullopt,
        };
        const auto denied = runtime.query_history(plan);
        REQUIRE_FALSE(denied.has_value());
        REQUIRE(denied.error().code == ErrorCode::invalid_label);
    }

    TEST_CASE("state overlays commit atomically roll back and reject stale CAS") {
        InMemoryReferenceRuntime runtime;
        REQUIRE(runtime.register_state_namespace(state_namespace()).has_value());
        const auto address = state_address();

        auto rolled_back = runtime.begin_state(StateAccess {
            .tenant = TenantId {"tenant-a"}, .actor = ExecutableId {"pack-a.rule"}, .evaluation_ingest_unix_ms = 100});
        REQUIRE(rolled_back.has_value());
        REQUIRE(rolled_back->write(address, record_value("state.counter/v1", "value:discard", security_label()))
                    .has_value());
        const auto rollback_receipt = runtime.commit_state(*rolled_back, false);
        REQUIRE(rollback_receipt.has_value());
        REQUIRE_FALSE(rollback_receipt->committed);

        auto initial = runtime.begin_state(StateAccess {
            .tenant = TenantId {"tenant-a"}, .actor = ExecutableId {"pack-a.rule"}, .evaluation_ingest_unix_ms = 110});
        REQUIRE(initial.has_value());
        const auto absent = initial->read(address);
        REQUIRE(absent.has_value());
        REQUIRE_FALSE(absent->value.has_value());
        const auto wrong_schema =
            initial->write(address, record_value("state.other/v1", "value:wrong-schema", security_label()));
        REQUIRE_FALSE(wrong_schema.has_value());
        REQUIRE(wrong_schema.error().code == ErrorCode::schema_mismatch);
        REQUIRE(initial->write(address, record_value("state.counter/v1", "value:1", security_label())).has_value());
        const auto initial_receipt = runtime.commit_state(*initial, true);
        REQUIRE(initial_receipt.has_value());
        REQUIRE(initial_receipt->committed);
        REQUIRE(initial_receipt->highest_version == 1);

        auto left = runtime.begin_state(StateAccess {
            .tenant = TenantId {"tenant-a"}, .actor = ExecutableId {"pack-a.rule"}, .evaluation_ingest_unix_ms = 120});
        auto right = runtime.begin_state(StateAccess {
            .tenant = TenantId {"tenant-a"}, .actor = ExecutableId {"pack-a.rule"}, .evaluation_ingest_unix_ms = 130});
        REQUIRE(left.has_value());
        REQUIRE(right.has_value());
        REQUIRE(left->read(address)->version == 1);
        REQUIRE(right->read(address)->version == 1);
        REQUIRE(left->write(address, record_value("state.counter/v1", "value:2", security_label())).has_value());
        REQUIRE(right->write(address, record_value("state.counter/v1", "value:3", security_label())).has_value());
        REQUIRE(runtime.commit_state(*left, true).has_value());
        const auto stale = runtime.commit_state(*right, true);
        REQUIRE_FALSE(stale.has_value());
        REQUIRE(stale.error().code == ErrorCode::state_conflict);

        auto shared_reader = runtime.begin_state(StateAccess {.tenant = TenantId {"tenant-a"},
                                                              .actor = ExecutableId {"pack-b.reader"},
                                                              .evaluation_ingest_unix_ms = 140});
        REQUIRE(shared_reader.has_value());
        REQUIRE(shared_reader->read(address).has_value());
        const auto denied_write =
            shared_reader->write(address, record_value("state.counter/v1", "value:4", security_label()));
        REQUIRE_FALSE(denied_write.has_value());
        REQUIRE(denied_write.error().code == ErrorCode::unauthorized);
    }

    TEST_CASE("captured-input MVCC retry uses three attempts and one shared budget") {
        MvccRetryController retries {60};
        const auto captured = record_value("service.reply/v1", "service:answer");
        REQUIRE(retries.inputs.capture("service:callsite:0", captured).has_value());

        REQUIRE(retries.begin_attempt() == 1);
        REQUIRE(retries.budget.charge(20).has_value());
        REQUIRE(retries.state_conflict() == ConflictDisposition::retry);
        REQUIRE(retries.inputs.sealed());
        REQUIRE(retries.inputs.resolve("service:callsite:0").has_value());
        const auto divergent = retries.inputs.resolve("service:new-branch:0");
        REQUIRE_FALSE(divergent.has_value());
        REQUIRE(divergent.error().code == ErrorCode::replay_diverged);

        REQUIRE(retries.begin_attempt() == 2);
        REQUIRE(retries.budget.charge(20).has_value());
        REQUIRE(retries.state_conflict() == ConflictDisposition::retry);
        REQUIRE(retries.begin_attempt() == 3);
        REQUIRE(retries.budget.charge(20).has_value());
        REQUIRE(retries.budget.remaining() == 0);
        REQUIRE(retries.state_conflict() == ConflictDisposition::exhausted);
        const auto fourth = retries.begin_attempt();
        REQUIRE_FALSE(fourth.has_value());
        REQUIRE(fourth.error().code == ErrorCode::replay_exhausted);

        SharedRetryBudget budget {.limit = 10, .consumed = 9};
        const auto exhausted = budget.charge(2);
        REQUIRE_FALSE(exhausted.has_value());
        REQUIRE(exhausted.error().code == ErrorCode::budget_exhausted);
        REQUIRE(budget.consumed == 9);
    }

    TEST_CASE("correlation keys are typed and causation graphs must be acyclic") {
        const auto boolean = canonical_group_key(CorrelationKey {.value = true});
        const auto integer = canonical_group_key(CorrelationKey {.value = IntegerValue {"1"}});
        REQUIRE(boolean.has_value());
        REQUIRE(integer.has_value());
        REQUIRE(*boolean != *integer);

        const CorrelationKey tuple {
            .value =
                CorrelationTuple {
                    CorrelationKey {.value = UnicodeValue {"peer-a"}},
                    CorrelationKey {.value = IntegerValue {"42"}},
                },
        };
        REQUIRE(canonical_group_key(tuple).has_value());

        REQUIRE(validate_correlation_dag({CorrelationEdge {.source = BindingId {"a"}, .target = BindingId {"b"}},
                                          CorrelationEdge {.source = BindingId {"b"}, .target = BindingId {"c"}}})
                    .has_value());
        const auto cycle =
            validate_correlation_dag({CorrelationEdge {.source = BindingId {"a"}, .target = BindingId {"b"}},
                                      CorrelationEdge {.source = BindingId {"b"}, .target = BindingId {"a"}}});
        REQUIRE_FALSE(cycle.has_value());
        REQUIRE(cycle.error().code == ErrorCode::causation_cycle);
    }

    TEST_CASE("correlation groups isolate claims advance defined faults and mark late events") {
        InMemoryReferenceRuntime runtime;
        REQUIRE(runtime.register_event_schema(event_schema("process/v1", "process.payload/v1")).has_value());
        const auto first_event = event("event-1", "process/v1", "process.payload/v1", 1'000, 1'100);
        const auto late_event = event("event-2", "process/v1", "process.payload/v1", 850, 1'200);
        REQUIRE(runtime.append_event(first_event).has_value());
        REQUIRE(runtime.append_event(late_event).has_value());

        const CorrelationGroupId group_a {
            .tenant = TenantId {"tenant-a"},
            .executable = ExecutableId {"pack.rule"},
            .binding = BindingId {"correlation.a"},
            .canonical_key = "key:a",
        };
        const CorrelationGroupId group_b {
            .tenant = TenantId {"tenant-a"},
            .executable = ExecutableId {"pack.rule"},
            .binding = BindingId {"correlation.a"},
            .canonical_key = "key:b",
        };
        const auto lease_a = runtime.claim_group(group_a);
        REQUIRE(lease_a.has_value());
        const auto duplicate_claim = runtime.claim_group(group_a);
        REQUIRE_FALSE(duplicate_claim.has_value());
        REQUIRE(duplicate_claim.error().code == ErrorCode::group_busy);
        const auto lease_b = runtime.claim_group(group_b);
        REQUIRE(lease_b.has_value());

        const CorrelationTimePolicy policy {
            .time_basis = HistoryTimeBasis::producer,
            .allowed_lateness_ms = 100,
            .accepted_clock_skew_ms = 100,
        };
        const auto admitted = runtime.admit_group_event(*lease_a, first_event, policy, 1'100);
        REQUIRE(admitted.has_value());
        REQUIRE(admitted->watermark == 900);
        REQUIRE_FALSE(admitted->late_beyond_watermark);
        const auto late = runtime.admit_group_event(*lease_a, late_event, policy, 1'200);
        REQUIRE(late.has_value());
        REQUIRE(late->late_beyond_watermark);
        REQUIRE(late->watermark == 1'000);

        const auto fault_cursor = runtime.complete_group(*lease_a, CorrelationCompletion::defined_fault);
        REQUIRE(fault_cursor.has_value());
        REQUIRE(*fault_cursor == 1);
        REQUIRE(runtime.complete_group(*lease_b, CorrelationCompletion::rolled_back) == 0);
        REQUIRE(runtime.group_cursor(group_a) == 1);
        REQUIRE(runtime.group_cursor(group_b) == 0);

        const auto retry_lease = runtime.claim_group(group_a);
        REQUIRE(retry_lease.has_value());
        REQUIRE(runtime.complete_group(*retry_lease, CorrelationCompletion::retryable_fault) == 1);
        REQUIRE(runtime.group_cursor(group_a) == 1);
    }

    TEST_CASE("retention capture and audited purge are bounded and purge fenced") {
        InMemoryReferenceRuntime runtime;
        REQUIRE(runtime
                    .register_event_schema(
                        event_schema("process/v1", "process.payload/v1", security_label(Classification::sensitive)))
                    .has_value());
        const auto source_event = event("event-purge", "process/v1", "process.payload/v1", 900, 1'000, "tenant-a",
                                        "peer-a", security_label());
        REQUIRE(runtime.append_event(source_event).has_value());
        REQUIRE(runtime.register_state_namespace(state_namespace()).has_value());
        const auto address = state_address();
        auto state = runtime.begin_state(StateAccess {.tenant = TenantId {"tenant-a"},
                                                      .actor = ExecutableId {"pack-a.rule"},
                                                      .evaluation_ingest_unix_ms = 1'000});
        REQUIRE(state.has_value());
        REQUIRE(state->write(address, record_value("state.counter/v1", "state:purge", security_label())).has_value());
        REQUIRE(runtime.commit_state(*state, true).has_value());

        const RetentionProfile retention_profile {
            .id = "incident.v1",
            .label_ceiling = security_label(Classification::sensitive),
            .maximum_ttl_ms = 5'000,
            .maximum_intents = 4,
        };
        REQUIRE(runtime
                    .retain(retention_profile,
                            RetentionIntent {.id = IntentId {"retain-1"},
                                             .tenant = TenantId {"tenant-a"},
                                             .event = EventId {"event-purge"},
                                             .profile = "incident.v1",
                                             .label = security_label(),
                                             .expires_unix_ms = 3'000,
                                             .logical_read = true},
                            1'000)
                    .has_value());
        const auto excessive_retention =
            runtime.retain(retention_profile,
                           RetentionIntent {.id = IntentId {"retain-secret"},
                                            .tenant = TenantId {"tenant-a"},
                                            .event = EventId {"event-purge"},
                                            .profile = "incident.v1",
                                            .label = security_label(Classification::secret),
                                            .expires_unix_ms = 3'000,
                                            .logical_read = false},
                           1'000);
        REQUIRE_FALSE(excessive_retention.has_value());

        const CaptureProfile capture_profile {
            .id = "process-triage.v1",
            .label_ceiling = security_label(Classification::sensitive),
            .maximum_ttl_ms = 5'000,
            .maximum_pending = 4,
        };
        const CaptureIntent capture_intent {
            .id = IntentId {"capture-1"},
            .tenant = TenantId {"tenant-a"},
            .peer = PeerId {"peer-a"},
            .subject = std::nullopt,
            .profile = "process-triage.v1",
            .parameters = record_value("capture.parameters/v1", "capture:parameters", security_label()),
            .anchor = EventId {"event-purge"},
            .reason = "retain evidence",
            .dedupe_key = "event-purge",
            .expires_unix_ms = 3'000,
            .dry_run = true,
        };
        const auto capture = runtime.capture(capture_profile, capture_intent, 1'000);
        REQUIRE(capture.has_value());
        REQUIRE_FALSE(capture->duplicate);
        REQUIRE(capture->dry_run);
        const auto duplicate_capture = runtime.capture(capture_profile, capture_intent, 1'000);
        REQUIRE(duplicate_capture.has_value());
        REQUIRE(duplicate_capture->duplicate);

        auto stale_after_purge = runtime.begin_state(StateAccess {.tenant = TenantId {"tenant-a"},
                                                                  .actor = ExecutableId {"pack-a.rule"},
                                                                  .evaluation_ingest_unix_ms = 1'050});
        REQUIRE(stale_after_purge.has_value());
        REQUIRE(stale_after_purge->write(address, record_value("state.counter/v1", "state:stale", security_label()))
                    .has_value());

        const PurgeRequest purge {
            .tenant = TenantId {"tenant-a"},
            .peer = PeerId {"peer-a"},
            .begin_ingest_unix_ms = 900,
            .end_ingest_unix_ms = 1'100,
            .reason = "privacy request",
        };
        const auto preview = runtime.preview_purge(purge);
        REQUIRE(preview.has_value());
        REQUIRE(preview->events == 1);
        REQUIRE(preview->state_cells == 1);
        REQUIRE(preview->retention_intents == 1);
        REQUIRE(preview->capture_intents == 1);

        const auto audit = runtime.purge(purge);
        REQUIRE(audit.has_value());
        REQUIRE(audit->purge_epoch == 1);
        REQUIRE(audit->removed.events == 1);
        REQUIRE(audit->tombstones == std::vector<EventId> {EventId {"event-purge"}});
        REQUIRE(runtime.purge_audits().size() == 1);

        const auto stale_commit = runtime.commit_state(*stale_after_purge, true);
        REQUIRE_FALSE(stale_commit.has_value());
        REQUIRE(stale_commit.error().code == ErrorCode::state_conflict);

        const auto resurrect = runtime.append_event(source_event);
        REQUIRE_FALSE(resurrect.has_value());
        REQUIRE(resurrect.error().code == ErrorCode::duplicate_conflict);

        auto after = runtime.begin_state(StateAccess {.tenant = TenantId {"tenant-a"},
                                                      .actor = ExecutableId {"pack-a.rule"},
                                                      .evaluation_ingest_unix_ms = 1'200});
        REQUIRE(after.has_value());
        const auto absent = after->read(address);
        REQUIRE(absent.has_value());
        REQUIRE_FALSE(absent->value.has_value());
    }

} // namespace
