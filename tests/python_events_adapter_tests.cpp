#include "rule_engine/python/events/runtime_adapter.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

    using namespace rule_engine::python;
    using namespace rule_engine::python::effects;
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

    EventEnvelope event(const std::string &id, const std::uint64_t producer, const std::uint64_t ingest,
                        DataLabel label = public_label(), const std::string &event_schema_id = "process/v1",
                        const std::string &payload_schema_id = "process.payload/v1") {
        auto payload_label = label;
        return EventEnvelope {
            .id = EventId {id},
            .schema = SchemaId {event_schema_id},
            .tenant = TenantId {"tenant-a"},
            .peer = PeerId {"peer-a"},
            .subject = std::nullopt,
            .producer_unix_ms = producer,
            .ingest_unix_ms = ingest,
            .label = std::move(label),
            .causation = std::nullopt,
            .payload = record_value(payload_schema_id, "digest:" + id, std::move(payload_label)),
        };
    }

    RuntimeTransaction transaction_for(EventEnvelope input,
                                       const EvaluationOutcome outcome = EvaluationOutcome::no_match) {
        return RuntimeTransaction {
            .input = std::move(input),
            .cursor = {.consumer = "test", .expected_position = 0, .new_position = 1},
            .evaluation =
                EvaluationResult {
                    .outcome = outcome,
                    .verdict = std::nullopt,
                    .committed_effects = {},
                    .committed_events = {},
                    .state_mutations = {},
                    .fault = std::nullopt,
                },
            .state = {},
            .emitted_events = {},
            .journal = {},
            .outbox = {},
            .fence_token = 1,
        };
    }

    StoreError store_failure(const StoreErrorCode code, std::string message = "scripted failure") {
        return StoreError {.code = code, .message = std::move(message), .retryable = code == StoreErrorCode::conflict};
    }

    struct RecordingHistoryStore final: IHistoryCandidateStore {
        explicit RecordingHistoryStore(std::vector<EventEnvelope> input_candidates):
            candidates {std::move(input_candidates)} {}

        std::vector<EventEnvelope> candidates;
        mutable std::vector<HistoryPredicate> received_pushdown;

        [[nodiscard]] std::expected<HistoryPage, Error>
        query_candidates(const HistoryPlan &, const std::span<const HistoryPredicate> pushdown) const override {
            received_pushdown.assign(pushdown.begin(), pushdown.end());
            return HistoryPage {.events = candidates, .next = std::nullopt};
        }
    };

    struct ScriptedRuntimeStore final: IRuntimeStore {
        ScriptedRuntimeStore() = default;
        explicit ScriptedRuntimeStore(std::vector<std::optional<StoreError>> input_outcomes):
            outcomes {std::move(input_outcomes)} {}

        std::vector<std::optional<StoreError>> outcomes;
        std::vector<RuntimeTransaction> transactions;

        [[nodiscard]] std::expected<TransactionReceipt, StoreError>
        transact_event(const RuntimeTransaction &transaction) override {
            transactions.push_back(transaction);
            const auto index = transactions.size() - 1U;
            if (index < outcomes.size() && outcomes[index]) {
                return std::unexpected(*outcomes[index]);
            }
            return TransactionReceipt {
                .input = transaction.input.id,
                .committed_cursor = transaction.cursor.new_position,
                .emitted_events = {},
                .outbox_intents = {},
            };
        }
    };

    struct CountingStateSnapshots final: IStateSnapshotStore {
        mutable std::uint64_t reads {};

        [[nodiscard]] std::expected<StateReadResponse, StoreError>
        read_state(const StateReadRequest &request) const override {
            ++reads;
            return StateReadResponse {
                .request_id = request.request_id,
                .value = record_value("state.counter/v1", "state:" + std::to_string(reads)),
                .version = reads,
                .diagnostic = std::nullopt,
            };
        }
    };

    struct CountingExternalInputs final: IExternalInputSource {
        std::uint64_t calls {};

        [[nodiscard]] std::expected<CapturedInput, Error> resolve(const std::string_view key,
                                                                  const CapturedInputKind kind) override {
            ++calls;
            return CapturedInput {
                .key = std::string {key},
                .kind = kind,
                .value = record_value("service.reply/v1", "service:stable"),
                .terminal_code = {},
            };
        }
    };

    enum struct AttemptBehavior : std::uint8_t { commit, rollback, diverge_on_retry };

    struct RetryAttemptFactory;

    struct RetryAttempt final: IMvccEvaluationAttempt {
        RetryAttempt(RetryAttemptFactory &input_owner, const std::uint32_t input_number):
            owner {input_owner}, number {input_number} {}

        RetryAttemptFactory &owner;
        std::uint32_t number {};

        [[nodiscard]] std::expected<MvccEvaluationProposal, Error> evaluate(MvccEvaluationContext &context) override;
    };

    struct RetryAttemptFactory final: IMvccEvaluationFactory {
        RetryAttemptFactory() = default;
        explicit RetryAttemptFactory(const AttemptBehavior input_behavior): behavior {input_behavior} {}

        AttemptBehavior behavior {AttemptBehavior::commit};
        std::uint64_t charge_per_attempt {10};
        std::vector<std::uint32_t> starts;

        [[nodiscard]] std::expected<std::unique_ptr<IMvccEvaluationAttempt>, Error>
        start(const std::uint32_t attempt) override {
            starts.push_back(attempt);
            return std::unique_ptr<IMvccEvaluationAttempt> {std::make_unique<RetryAttempt>(*this, attempt)};
        }
    };

    std::expected<MvccEvaluationProposal, Error> RetryAttempt::evaluate(MvccEvaluationContext &context) {
        const auto state = context.read_state(StateReadRequest {
            .request_id = RequestId {"state:" + std::to_string(number)},
            .owner = ExecutableId {"pack.rule"},
            .namespace_name = "state-v1",
            .key = "key",
            .schema = SchemaId {"state.counter/v1"},
        });
        if (!state) {
            return std::unexpected(state.error());
        }
        const auto input_key = owner.behavior == AttemptBehavior::diverge_on_retry && number > 1U ?
                                   "service:new-branch" :
                                   "service:stable-branch";
        const auto input = context.resolve_input(input_key, CapturedInputKind::service);
        if (!input) {
            return std::unexpected(input.error());
        }
        if (auto charged = context.charge(owner.charge_per_attempt); !charged) {
            return std::unexpected(charged.error());
        }
        return MvccEvaluationProposal {
            .transaction = transaction_for(event("event-attempt", 100, 110)),
            .commit = owner.behavior != AttemptBehavior::rollback,
        };
    }

    std::string state_key(const StateAddress &address) {
        return address.tenant.value + "|" + address.owner.value + "|" + address.namespace_id + "|" +
               address.schema.value + "|" + (address.peer ? address.peer->value : "fleet") + "|" + address.scope + "|" +
               address.key;
    }

    struct MemoryNamespaceStore final: IStateNamespaceStore {
        std::map<std::string, StateRead, std::less<>> cells;
        std::vector<LazyStateMigrationWrite> writes;
        bool conflict_with_racer {};
        std::optional<FrozenValue> racer_value;

        [[nodiscard]] std::expected<StateRead, StoreError> read(const StateAddress &address) const override {
            const auto found = cells.find(state_key(address));
            return found == cells.end() ? StateRead {} : found->second;
        }

        [[nodiscard]] std::expected<StateRead, StoreError>
        install_migrated(const LazyStateMigrationWrite &write) override {
            writes.push_back(write);
            const auto source = cells.find(state_key(write.source));
            const auto source_version = source == cells.end() ? 0U : source->second.version;
            const auto target = cells.find(state_key(write.target));
            const auto target_version = target == cells.end() ? 0U : target->second.version;
            if (source_version != write.source_version || target_version != write.target_expected_version) {
                return std::unexpected(store_failure(StoreErrorCode::conflict));
            }
            if (conflict_with_racer) {
                conflict_with_racer = false;
                cells.insert_or_assign(state_key(write.target),
                                       StateRead {.value = racer_value, .version = target_version + 1U});
                return std::unexpected(store_failure(StoreErrorCode::conflict));
            }
            const StateRead installed {.value = write.value, .version = target_version + 1U};
            cells.insert_or_assign(state_key(write.target), installed);
            return installed;
        }
    };

    StateNamespace state_namespace(const std::string &name, const std::string &schema,
                                   DataLabel ceiling = security_label(Classification::sensitive)) {
        return StateNamespace {
            .tenant = TenantId {"tenant-a"},
            .owner = ExecutableId {"pack.rule"},
            .namespace_id = name,
            .schema = SchemaId {schema},
            .label_ceiling = std::move(ceiling),
            .shared_readers = {},
            .shared_writers = {},
        };
    }

    StateAddress state_address(const StateNamespace &state_namespace, const std::string &key = "key") {
        return StateAddress {
            .tenant = state_namespace.tenant,
            .owner = state_namespace.owner,
            .namespace_id = state_namespace.namespace_id,
            .schema = state_namespace.schema,
            .peer = PeerId {"peer-a"},
            .scope = "correlation-group",
            .key = key,
        };
    }

    struct VersionMigration final: IPureStateMigration {
        StateMigrationDescriptor migration_descriptor {
            .id = "counter-v1-to-v2",
            .source_schema = SchemaId {"state.counter/v1"},
            .target_schema = SchemaId {"state.counter/v2"},
        };
        mutable std::uint64_t calls {};
        DataLabel output_label = security_label();

        [[nodiscard]] const StateMigrationDescriptor &descriptor() const noexcept override {
            return migration_descriptor;
        }

        [[nodiscard]] std::expected<FrozenValue, Error> migrate(const FrozenValue &) const override {
            ++calls;
            return record_value("state.counter/v2", "migrated:v2", output_label);
        }
    };

    struct FixedCorrelationEvaluator final: ICorrelationEvaluator {
        explicit FixedCorrelationEvaluator(CorrelationEvaluationProposal input_proposal):
            proposal {std::move(input_proposal)} {}

        CorrelationEvaluationProposal proposal;
        std::uint64_t calls {};
        std::optional<WindowAdmission> observed_window;

        [[nodiscard]] std::expected<CorrelationEvaluationProposal, Error>
        evaluate(const EventEnvelope &, const WindowAdmission &window) override {
            ++calls;
            observed_window = window;
            return proposal;
        }
    };

    CorrelationGroupId correlation_group(const std::string &key = "image:game.exe") {
        return CorrelationGroupId {
            .tenant = TenantId {"tenant-a"},
            .executable = ExecutableId {"pack.rule"},
            .binding = BindingId {"process-chain"},
            .canonical_key = key,
        };
    }

    TEST_CASE("fluent history plans are canonical bounded and split pure predicates") {
        auto builder = HistoryPlanBuilder::peer_local(TenantId {"tenant-a"}, PeerId {"peer-a"});
        const auto plan =
            builder.event_schemas({SchemaId {"thread/v1"}, SchemaId {"process/v1"}, SchemaId {"thread/v1"}})
                .between(100, 1'000)
                .ordered_by(HistoryTimeBasis::ingest)
                .bounded_to(10, 3)
                .label_ceiling(public_label())
                .build();
        REQUIRE(plan.has_value());
        REQUIRE(plan->schemas == std::vector<SchemaId> {SchemaId {"process/v1"}, SchemaId {"thread/v1"}});

        auto invalid = HistoryPlanBuilder::fleet(TenantId {"tenant-a"});
        REQUIRE_FALSE(invalid.event_schemas({SchemaId {"process/v1"}})
                          .between(100, 100)
                          .bounded_to(1, 1)
                          .label_ceiling(public_label())
                          .build()
                          .has_value());

        RecordingHistoryStore store {
            {event("event-a", 90, 110), event("event-b", 100, 120), event("event-c", 110, 130)}};
        const std::vector predicates {
            HistoryPredicate {.field = HistoryPredicateField::schema,
                              .operation = HistoryPredicateOperator::equal,
                              .value = std::string {"process/v1"}},
            HistoryPredicate {.field = HistoryPredicateField::payload_digest,
                              .operation = HistoryPredicateOperator::equal,
                              .value = std::string {"digest:event-b"}},
        };
        const HistoryQueryAdapter adapter {store};
        const auto page = adapter.query_page(*plan, predicates);
        REQUIRE(page.has_value());
        REQUIRE(page->events.size() == 1);
        REQUIRE(page->events.front().id == EventId {"event-b"});
        REQUIRE(store.received_pushdown.size() == 1);
        REQUIRE(store.received_pushdown.front().field == HistoryPredicateField::schema);

        InMemoryReferenceRuntime reference;
        REQUIRE(reference.register_event_schema(event_schema("process/v1", "process.payload/v1")).has_value());
        REQUIRE(reference.append_event(event("event-a", 90, 110)).has_value());
        REQUIRE(reference.append_event(event("event-b", 100, 120)).has_value());
        REQUIRE(reference.append_event(event("event-c", 110, 130)).has_value());
        const ReferenceHistoryCandidateStore reference_store {reference};
        const HistoryQueryAdapter reference_adapter {reference_store};
        const auto reference_page = reference_adapter.query_page(*plan, predicates);
        REQUIRE(reference_page.has_value());
        REQUIRE(reference_page->events.size() == 1);
        REQUIRE(reference_page->events.front().id == EventId {"event-b"});

        const std::vector malformed {
            HistoryPredicate {.field = HistoryPredicateField::ingest_timestamp,
                              .operation = HistoryPredicateOperator::greater,
                              .value = std::string {"not-an-integer"}},
        };
        REQUIRE_FALSE(split_history_predicates(malformed).has_value());
    }

    TEST_CASE("MVCC runner creates fresh attempts seals inputs and shares one budget") {
        ScriptedRuntimeStore transactions {
            {store_failure(StoreErrorCode::conflict), store_failure(StoreErrorCode::conflict), std::nullopt}};
        CountingStateSnapshots state;
        CountingExternalInputs inputs;
        RetryAttemptFactory factory;
        TransactionalMvccRunner runner {transactions, state, inputs, 30};

        const auto result = runner.run(factory);
        REQUIRE(result.has_value());
        REQUIRE(result->committed);
        REQUIRE(result->attempts == 3);
        REQUIRE(result->budget_consumed == 30);
        REQUIRE(result->captured_inputs.size() == 1);
        REQUIRE(factory.starts == std::vector<std::uint32_t> {1, 2, 3});
        REQUIRE(state.reads == 3);
        REQUIRE(inputs.calls == 1);
        REQUIRE(transactions.transactions.size() == 3);
    }

    TEST_CASE("MVCC runner rolls back without publication and detects divergent retry reads") {
        CountingStateSnapshots state;
        CountingExternalInputs inputs;

        ScriptedRuntimeStore rollback_store;
        RetryAttemptFactory rollback_factory {AttemptBehavior::rollback};
        TransactionalMvccRunner rollback_runner {rollback_store, state, inputs, 10};
        const auto rolled_back = rollback_runner.run(rollback_factory);
        REQUIRE(rolled_back.has_value());
        REQUIRE_FALSE(rolled_back->committed);
        REQUIRE(rolled_back->attempts == 1);
        REQUIRE(rollback_store.transactions.empty());

        ScriptedRuntimeStore divergence_store {{store_failure(StoreErrorCode::conflict)}};
        RetryAttemptFactory divergence_factory {AttemptBehavior::diverge_on_retry};
        TransactionalMvccRunner divergence_runner {divergence_store, state, inputs, 30};
        const auto divergent = divergence_runner.run(divergence_factory);
        REQUIRE_FALSE(divergent.has_value());
        REQUIRE(divergent.error().code == ErrorCode::replay_diverged);
        REQUIRE(divergence_store.transactions.size() == 1);
        REQUIRE(divergence_factory.starts == std::vector<std::uint32_t> {1, 2});

        ScriptedRuntimeStore unavailable_store {{store_failure(StoreErrorCode::unavailable)}};
        RetryAttemptFactory unavailable_factory;
        TransactionalMvccRunner unavailable_runner {unavailable_store, state, inputs, 10};
        const auto unavailable = unavailable_runner.run(unavailable_factory);
        REQUIRE_FALSE(unavailable.has_value());
        REQUIRE(unavailable.error().code == ErrorCode::store_failure);
        REQUIRE(unavailable_factory.starts == std::vector<std::uint32_t> {1});

        ScriptedRuntimeStore exhausted_store {{store_failure(StoreErrorCode::conflict),
                                               store_failure(StoreErrorCode::conflict),
                                               store_failure(StoreErrorCode::conflict)}};
        RetryAttemptFactory exhausted_factory;
        TransactionalMvccRunner exhausted_runner {exhausted_store, state, inputs, 30};
        const auto exhausted = exhausted_runner.run(exhausted_factory);
        REQUIRE_FALSE(exhausted.has_value());
        REQUIRE(exhausted.error().code == ErrorCode::replay_exhausted);
        REQUIRE(exhausted_factory.starts == std::vector<std::uint32_t> {1, 2, 3});

        ScriptedRuntimeStore budget_store {{store_failure(StoreErrorCode::conflict)}};
        RetryAttemptFactory budget_factory;
        budget_factory.charge_per_attempt = 6;
        TransactionalMvccRunner budget_runner {budget_store, state, inputs, 10};
        const auto budget = budget_runner.run(budget_factory);
        REQUIRE_FALSE(budget.has_value());
        REQUIRE(budget.error().code == ErrorCode::budget_exhausted);
        REQUIRE(budget_store.transactions.size() == 1);
    }

    TEST_CASE("lazy namespace migration is pure transactional and preserves rollback state") {
        const auto source_namespace = state_namespace("state-v1", "state.counter/v1");
        const auto target_namespace = state_namespace("state-v2", "state.counter/v2");
        const auto source = state_address(source_namespace);
        const auto target = state_address(target_namespace);
        MemoryNamespaceStore store;
        store.cells.emplace(
            state_key(source),
            StateRead {.value = record_value("state.counter/v1", "source:v1", security_label()), .version = 7});
        VersionMigration migration;
        const auto lazy = LazyStateNamespace::create(store,
                                                     StateNamespaceTransition {
                                                         .mode = StateNamespaceTransitionMode::migrate,
                                                         .source = source_namespace,
                                                         .target = target_namespace,
                                                         .migration_id = "counter-v1-to-v2",
                                                         .reset_authorized = false,
                                                         .retain_source_for_rollback = true,
                                                     },
                                                     &migration);
        REQUIRE(lazy.has_value());

        const auto first = lazy->read(target);
        REQUIRE(first.has_value());
        REQUIRE(first->version == 1);
        REQUIRE(first->value->canonical_digest == "migrated:v2");
        REQUIRE(migration.calls == 1);
        REQUIRE(store.writes.size() == 1);
        REQUIRE(store.writes.front().source_version == 7);
        REQUIRE(store.cells.at(state_key(source)).value->canonical_digest == "source:v1");

        const auto second = lazy->read(target);
        REQUIRE(second.has_value());
        REQUIRE(second->value->canonical_digest == "migrated:v2");
        REQUIRE(migration.calls == 1);
        REQUIRE(store.writes.size() == 1);

        VersionMigration impure;
        impure.migration_descriptor.performs_external_reads = true;
        REQUIRE_FALSE(LazyStateNamespace::create(store,
                                                 StateNamespaceTransition {
                                                     .mode = StateNamespaceTransitionMode::migrate,
                                                     .source = source_namespace,
                                                     .target = target_namespace,
                                                     .migration_id = "counter-v1-to-v2",
                                                     .retain_source_for_rollback = true,
                                                 },
                                                 &impure)
                          .has_value());

        MemoryNamespaceStore labeled_store;
        labeled_store.cells.emplace(
            state_key(source),
            StateRead {.value = record_value("state.counter/v1", "source:v1", security_label()), .version = 1});
        VersionMigration excessive_label;
        excessive_label.output_label = security_label(Classification::secret);
        const auto labeled_lazy = LazyStateNamespace::create(labeled_store,
                                                             StateNamespaceTransition {
                                                                 .mode = StateNamespaceTransitionMode::migrate,
                                                                 .source = source_namespace,
                                                                 .target = target_namespace,
                                                                 .migration_id = "counter-v1-to-v2",
                                                                 .reset_authorized = false,
                                                                 .retain_source_for_rollback = true,
                                                             },
                                                             &excessive_label);
        REQUIRE(labeled_lazy.has_value());
        const auto rejected_label = labeled_lazy->read(target);
        REQUIRE_FALSE(rejected_label.has_value());
        REQUIRE(rejected_label.error().code == ErrorCode::invalid_label);
    }

    TEST_CASE("lazy state carry reset and CAS races have explicit outcomes") {
        const auto source_namespace = state_namespace("carry-source", "state.counter/v1");
        const auto carry_namespace = state_namespace("carry-target", "state.counter/v1");
        MemoryNamespaceStore store;
        const auto source = state_address(source_namespace);
        const auto target = state_address(carry_namespace);
        store.cells.emplace(
            state_key(source),
            StateRead {.value = record_value("state.counter/v1", "carry:value", security_label()), .version = 2});
        const auto carry = LazyStateNamespace::create(store, StateNamespaceTransition {
                                                                 .mode = StateNamespaceTransitionMode::carry,
                                                                 .source = source_namespace,
                                                                 .target = carry_namespace,
                                                                 .migration_id = {},
                                                                 .reset_authorized = false,
                                                                 .retain_source_for_rollback = true,
                                                             });
        REQUIRE(carry.has_value());
        REQUIRE(carry->read(target)->value->canonical_digest == "carry:value");

        const auto reset_namespace = state_namespace("reset-target", "state.counter/v2");
        const auto reset = LazyStateNamespace::create(store, StateNamespaceTransition {
                                                                 .mode = StateNamespaceTransitionMode::reset,
                                                                 .source = source_namespace,
                                                                 .target = reset_namespace,
                                                                 .migration_id = {},
                                                                 .reset_authorized = true,
                                                                 .retain_source_for_rollback = true,
                                                             });
        REQUIRE(reset.has_value());
        const auto reset_value = reset->read(state_address(reset_namespace));
        REQUIRE(reset_value.has_value());
        REQUIRE_FALSE(reset_value->value.has_value());

        const auto race_target_namespace = state_namespace("race-target", "state.counter/v1");
        const auto race = LazyStateNamespace::create(store, StateNamespaceTransition {
                                                                .mode = StateNamespaceTransitionMode::carry,
                                                                .source = source_namespace,
                                                                .target = race_target_namespace,
                                                                .migration_id = {},
                                                                .reset_authorized = false,
                                                                .retain_source_for_rollback = true,
                                                            });
        REQUIRE(race.has_value());
        store.conflict_with_racer = true;
        store.racer_value = record_value("state.counter/v1", "race:winner", security_label());
        const auto raced = race->read(state_address(race_target_namespace));
        REQUIRE(raced.has_value());
        REQUIRE(raced->value->canonical_digest == "race:winner");
    }

    TEST_CASE("serialized correlation persists defined faults and advances one group cursor") {
        InMemoryReferenceRuntime reference;
        REQUIRE(reference.register_event_schema(event_schema("process/v1", "process.payload/v1")).has_value());
        const auto input = event("event-defined-fault", 1'000, 1'100);
        REQUIRE(reference.append_event(input).has_value());
        ReferenceCorrelationStateStore groups {reference};
        ScriptedRuntimeStore transactions;
        SerializedCorrelationRunner runner {groups, transactions};
        FixedCorrelationEvaluator evaluator {
            CorrelationEvaluationProposal {
                .completion = CorrelationCompletion::defined_fault,
                .transaction = transaction_for(input, EvaluationOutcome::faulted),
            },
        };
        const CorrelationTimePolicy policy {
            .time_basis = HistoryTimeBasis::producer,
            .allowed_lateness_ms = 100,
            .accepted_clock_skew_ms = 100,
        };

        const auto result = runner.run(correlation_group(), input, policy, 1'100, {}, evaluator);
        REQUIRE(result.has_value());
        REQUIRE(result->completion == CorrelationCompletion::defined_fault);
        REQUIRE(result->group_cursor == 1);
        REQUIRE(result->window.selected_timestamp == 1'000);
        REQUIRE(result->window.watermark == 900);
        REQUIRE(transactions.transactions.size() == 1);
        REQUIRE(transactions.transactions.front().cursor.consumer == correlation_consumer_key(correlation_group()));
        REQUIRE(transactions.transactions.front().cursor.expected_position == 0);
        REQUIRE(transactions.transactions.front().cursor.new_position == 1);
        REQUIRE(transactions.transactions.front().fence_token == 1);
        REQUIRE(reference.group_cursor(correlation_group()) == 1);
    }

    TEST_CASE("correlation rollback failures causation and quarantine release are deterministic") {
        InMemoryReferenceRuntime reference;
        REQUIRE(reference.register_event_schema(event_schema("process/v1", "process.payload/v1")).has_value());
        const auto input = event("event-correlation", 1'000, 1'100);
        REQUIRE(reference.append_event(input).has_value());
        ReferenceCorrelationStateStore groups {reference};
        const CorrelationTimePolicy ingest_policy {};

        ScriptedRuntimeStore failed_store {{store_failure(StoreErrorCode::unavailable)}};
        SerializedCorrelationRunner failed_runner {groups, failed_store};
        FixedCorrelationEvaluator failed_evaluator {
            CorrelationEvaluationProposal {
                .completion = CorrelationCompletion::committed,
                .transaction = transaction_for(input, EvaluationOutcome::match),
            },
        };
        const auto failed = failed_runner.run(correlation_group(), input, ingest_policy, 1'100, {}, failed_evaluator);
        REQUIRE_FALSE(failed.has_value());
        REQUIRE(failed.error().code == ErrorCode::store_failure);
        REQUIRE(reference.group_cursor(correlation_group()) == 0);

        ScriptedRuntimeStore rollback_store;
        SerializedCorrelationRunner rollback_runner {groups, rollback_store};
        FixedCorrelationEvaluator rollback_evaluator {
            CorrelationEvaluationProposal {
                .completion = CorrelationCompletion::rolled_back,
                .transaction = std::nullopt,
            },
        };
        const auto rolled_back =
            rollback_runner.run(correlation_group(), input, ingest_policy, 1'100, {}, rollback_evaluator);
        REQUIRE(rolled_back.has_value());
        REQUIRE(rolled_back->window.selected_timestamp == 1'100);
        REQUIRE(rolled_back->group_cursor == 0);
        REQUIRE(rollback_store.transactions.empty());

        auto bad_causation = transaction_for(input, EvaluationOutcome::match);
        bad_causation.emitted_events.push_back(event("event-output", 1'010, 1'110));
        ScriptedRuntimeStore causation_store;
        SerializedCorrelationRunner causation_runner {groups, causation_store};
        FixedCorrelationEvaluator causation_evaluator {
            CorrelationEvaluationProposal {
                .completion = CorrelationCompletion::committed,
                .transaction = std::move(bad_causation),
            },
        };
        const auto causation =
            causation_runner.run(correlation_group(), input, ingest_policy, 1'100, {}, causation_evaluator);
        REQUIRE_FALSE(causation.has_value());
        REQUIRE(causation.error().code == ErrorCode::causation_cycle);
        REQUIRE(causation_store.transactions.empty());

        ScriptedRuntimeStore quarantine_store;
        SerializedCorrelationRunner quarantine_runner {groups, quarantine_store};
        FixedCorrelationEvaluator quarantine_evaluator {
            CorrelationEvaluationProposal {
                .completion = CorrelationCompletion::quarantined,
                .transaction = transaction_for(input, EvaluationOutcome::quarantined),
            },
        };
        const auto quarantined =
            quarantine_runner.run(correlation_group(), input, ingest_policy, 1'100, {}, quarantine_evaluator);
        REQUIRE(quarantined.has_value());
        REQUIRE(quarantined->group_cursor == 1);
        const auto gated =
            rollback_runner.run(correlation_group(), input, ingest_policy, 1'100, {}, rollback_evaluator);
        REQUIRE_FALSE(gated.has_value());
        REQUIRE(gated.error().code == ErrorCode::group_quarantined);
        REQUIRE(groups.clear_quarantine(correlation_group()).has_value());
        REQUIRE(
            rollback_runner.run(correlation_group(), input, ingest_policy, 1'100, {}, rollback_evaluator).has_value());

        const std::vector cycle {
            CorrelationEdge {.source = BindingId {"a"}, .target = BindingId {"b"}},
            CorrelationEdge {.source = BindingId {"b"}, .target = BindingId {"a"}},
        };
        REQUIRE_FALSE(
            rollback_runner.run(correlation_group("cycle"), input, ingest_policy, 1'100, cycle, rollback_evaluator)
                .has_value());
    }

    TEST_CASE("retention capture and purge enforce exact profile boundaries") {
        InMemoryReferenceRuntime runtime {EventRuntimeLimits {
            .maximum_retention_intents = 2,
            .maximum_capture_intents = 2,
        }};
        REQUIRE(runtime
                    .register_event_schema(
                        event_schema("process/v1", "process.payload/v1", security_label(Classification::sensitive)))
                    .has_value());
        REQUIRE(runtime.append_event(event("event-governance", 900, 1'000, security_label())).has_value());

        const RetentionProfile retention {
            .id = "incident.v1",
            .label_ceiling = security_label(Classification::sensitive),
            .maximum_ttl_ms = 100,
            .maximum_intents = 1,
        };
        REQUIRE(runtime
                    .retain(retention,
                            RetentionIntent {.id = IntentId {"retain-boundary"},
                                             .tenant = TenantId {"tenant-a"},
                                             .event = EventId {"event-governance"},
                                             .profile = "incident.v1",
                                             .label = security_label(Classification::sensitive),
                                             .expires_unix_ms = 1'100,
                                             .logical_read = true},
                            1'000)
                    .has_value());
        const auto retention_quota = runtime.retain(retention,
                                                    RetentionIntent {.id = IntentId {"retain-over-quota"},
                                                                     .tenant = TenantId {"tenant-a"},
                                                                     .event = EventId {"event-governance"},
                                                                     .profile = "incident.v1",
                                                                     .label = security_label(),
                                                                     .expires_unix_ms = 1'050,
                                                                     .logical_read = false},
                                                    1'000);
        REQUIRE_FALSE(retention_quota.has_value());
        REQUIRE(retention_quota.error().code == ErrorCode::quota_exceeded);
        auto excessive_ttl_retention = RetentionIntent {
            .id = IntentId {"retain-over-ttl"},
            .tenant = TenantId {"tenant-a"},
            .event = EventId {"event-governance"},
            .profile = "incident.v1",
            .label = security_label(),
            .expires_unix_ms = 1'101,
            .logical_read = false,
        };
        const auto retention_ttl = runtime.retain(retention, std::move(excessive_ttl_retention), 1'000);
        REQUIRE_FALSE(retention_ttl.has_value());
        REQUIRE(retention_ttl.error().code == ErrorCode::invalid_bounds);

        const CaptureProfile capture {
            .id = "triage.v1",
            .label_ceiling = security_label(Classification::sensitive),
            .maximum_ttl_ms = 100,
            .maximum_pending = 1,
        };
        const CaptureIntent boundary_capture {
            .id = IntentId {"capture-boundary"},
            .tenant = TenantId {"tenant-a"},
            .peer = PeerId {"peer-a"},
            .subject = std::nullopt,
            .profile = "triage.v1",
            .parameters =
                record_value("capture.parameters/v1", "capture:boundary", security_label(Classification::sensitive)),
            .anchor = EventId {"event-governance"},
            .reason = "boundary",
            .dedupe_key = "boundary",
            .expires_unix_ms = 1'100,
            .dry_run = false,
        };
        REQUIRE(runtime.capture(capture, boundary_capture, 1'000).has_value());
        REQUIRE(runtime.capture(capture, boundary_capture, 1'000)->duplicate);
        auto over_quota_capture = boundary_capture;
        over_quota_capture.id = IntentId {"capture-over-quota"};
        over_quota_capture.dedupe_key = "another";
        const auto capture_quota = runtime.capture(capture, over_quota_capture, 1'000);
        REQUIRE_FALSE(capture_quota.has_value());
        REQUIRE(capture_quota.error().code == ErrorCode::quota_exceeded);

        auto excessive_ttl_capture = boundary_capture;
        excessive_ttl_capture.id = IntentId {"capture-over-ttl"};
        excessive_ttl_capture.dedupe_key = "over-ttl";
        excessive_ttl_capture.expires_unix_ms = 1'101;
        const auto capture_ttl = runtime.capture(capture, excessive_ttl_capture, 1'000);
        REQUIRE_FALSE(capture_ttl.has_value());
        REQUIRE(capture_ttl.error().code == ErrorCode::invalid_bounds);

        auto excessive_label = boundary_capture;
        excessive_label.id = IntentId {"capture-secret"};
        excessive_label.dedupe_key = "secret";
        excessive_label.parameters =
            record_value("capture.parameters/v1", "capture:secret", security_label(Classification::secret));
        REQUIRE_FALSE(runtime.capture(capture, excessive_label, 1'000).has_value());

        REQUIRE_FALSE(runtime
                          .preview_purge(PurgeRequest {
                              .tenant = TenantId {"tenant-a"},
                              .peer = PeerId {"peer-a"},
                              .begin_ingest_unix_ms = 1'000,
                              .end_ingest_unix_ms = 1'000,
                              .reason = "invalid",
                          })
                          .has_value());
        const auto purged = runtime.purge(PurgeRequest {
            .tenant = TenantId {"tenant-a"},
            .peer = PeerId {"peer-a"},
            .begin_ingest_unix_ms = 900,
            .end_ingest_unix_ms = 1'100,
            .reason = "boundary purge",
        });
        REQUIRE(purged.has_value());
        REQUIRE(purged->removed.events == 1);
        REQUIRE(purged->removed.retention_intents == 1);
        REQUIRE(purged->removed.capture_intents == 1);
    }

} // namespace
