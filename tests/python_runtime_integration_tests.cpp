#include "rule_engine/python/runtime/orchestrator.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace {

    using namespace rule_engine::python;
    using namespace rule_engine::python::effects;
    using namespace rule_engine::python::runtime;

    [[nodiscard]] SourceSpan source_span() {
        return {.source = SourceId {"rules.py"}, .begin_byte = 1U, .end_byte = 2U};
    }

    [[nodiscard]] SubjectKey subject() {
        return {
            .peer = PeerId {"peer-1"},
            .descriptor = SchemaId {"process/v1"},
            .identity = {{.field_id = 1U, .value = std::uint64_t {42U}}},
        };
    }

    [[nodiscard]] FrozenValue frozen_bool(const bool value, std::string digest = "sha256:value") {
        return {
            .value = make_fact(value),
            .label = DataLabel {.classification = Classification::internal},
            .canonical_digest = std::move(digest),
        };
    }

    [[nodiscard]] FactRequest fact_request() {
        return {
            .request_id = RequestId {"request:fact:1"},
            .subject = subject(),
            .route = {.provider = "process", .fact = "image_name"},
            .expected_schema = SchemaId {"unicode/v1"},
            .deadline_unix_ms = 1'000U,
        };
    }

    [[nodiscard]] StateReadRequest state_request() {
        return {
            .request_id = RequestId {"request:state:1"},
            .owner = ExecutableId {"rule"},
            .namespace_name = "peer-state/v1",
            .key = "counter",
            .schema = SchemaId {"integer/v1"},
        };
    }

    [[nodiscard]] CapabilityRequest capability_request() {
        return {
            .request_id = RequestId {"request:capability:1"},
            .capability = CapabilityId {"reputation.query/v1"},
            .request_schema = SchemaId {"reputation-request/v1"},
            .arguments = frozen_bool(true, "sha256:arguments"),
            .deadline_unix_ms = 1'000U,
        };
    }

    [[nodiscard]] HistoryRequest history_request() {
        return {
            .request_id = RequestId {"request:history:1"},
            .tenant = TenantId {"tenant-1"},
            .peer = PeerId {"peer-1"},
            .event_schema = SchemaId {"observation/v1"},
            .begin_ingest_unix_ms = 10U,
            .end_ingest_unix_ms = 20U,
            .limit = 4U,
        };
    }

    [[nodiscard]] EvaluationResult clean_result(const bool verdict = true) {
        return {
            .outcome = verdict ? EvaluationOutcome::match : EvaluationOutcome::no_match,
            .verdict = verdict,
        };
    }

    [[nodiscard]] EvaluationResult canceled_result() { return {.outcome = EvaluationOutcome::canceled}; }

    [[nodiscard]] EffectIntent effect(std::string id, const EffectDisposition disposition, const bool dry_run = false) {
        return {
            .id = IntentId {id},
            .invocation = InvocationId {"invocation-1"},
            .owner = ExecutableId {"rule"},
            .binding = BindingId {"binding-1"},
            .sequence = 1U,
            .kind = "post",
            .payload = frozen_bool(true, "sha256:effect"),
            .span = source_span(),
            .policy =
                EffectPolicySnapshot {
                    .policy_id = "policy/v1",
                    .policy_digest = "sha256:policy",
                    .dry_run = dry_run,
                },
            .disposition = disposition,
            .idempotency_key = "idempotency:" + id,
        };
    }

    enum struct SessionScenario : std::uint8_t {
        fact,
        state_conflict,
        effects,
        cancellation,
        constant,
        capabilities,
    };

    struct ScriptedSession final: VmSession {
        explicit ScriptedSession(const SessionScenario value): scenario {value} {}

        SessionScenario scenario {SessionScenario::constant};
        std::uint32_t stage {};

        [[nodiscard]] VmStep step(HostResponses responses) override {
            if (responses.cancel) {
                return {.state = VmStepState::canceled, .result = canceled_result()};
            }
            switch (scenario) {
                case SessionScenario::fact:
                case SessionScenario::cancellation:
                    if (stage++ == 0U) {
                        return {.state = VmStepState::waiting_for_facts, .fact_requests = {fact_request()}};
                    }
                    if (responses.facts.size() == 1U) {
                        return {.state = VmStepState::complete, .result = clean_result()};
                    }
                    return {.state = VmStepState::waiting_for_facts, .fact_requests = {fact_request()}};
                case SessionScenario::state_conflict:
                    if (stage++ == 0U) {
                        return {
                            .state = VmStepState::waiting_for_capabilities,
                            .fact_requests = {fact_request()},
                            .state_requests = {state_request()},
                        };
                    }
                    if (responses.facts.size() == 1U && responses.state.size() == 1U) {
                        auto result = clean_result();
                        result.state_mutations.push_back(StateMutation {
                            .owner = ExecutableId {"rule"},
                            .namespace_name = "peer-state/v1",
                            .key = "counter",
                            .expected_version = responses.state.front().version,
                            .value = frozen_bool(true, "sha256:state-write"),
                        });
                        return {.state = VmStepState::complete, .result = std::move(result)};
                    }
                    return {.state = VmStepState::faulted,
                            .result = EvaluationResult {.outcome = EvaluationOutcome::faulted}};
                case SessionScenario::effects: {
                    auto result = clean_result(false);
                    result.committed_effects = {
                        effect("intent:committed", EffectDisposition::committed),
                        effect("intent:rolled-back", EffectDisposition::rolled_back),
                        effect("intent:dry-run", EffectDisposition::committed, true),
                    };
                    return {.state = VmStepState::complete, .result = std::move(result)};
                }
                case SessionScenario::capabilities:
                    if (stage++ == 0U) {
                        return {
                            .state = VmStepState::waiting_for_capabilities,
                            .capability_requests = {capability_request()},
                            .history_requests = {history_request()},
                        };
                    }
                    if (responses.capabilities.size() == 1U && responses.history.size() == 1U) {
                        return {.state = VmStepState::complete, .result = clean_result()};
                    }
                    return {.state = VmStepState::faulted,
                            .result = EvaluationResult {.outcome = EvaluationOutcome::faulted}};
                case SessionScenario::constant: return {.state = VmStepState::complete, .result = clean_result()};
                default:
                    return {.state = VmStepState::faulted,
                            .result = EvaluationResult {.outcome = EvaluationOutcome::faulted}};
            }
        }
    };

    struct ScriptedVmFactory final: VmFactory {
        explicit ScriptedVmFactory(const SessionScenario value): scenario {value} {}

        SessionScenario scenario {SessionScenario::constant};
        std::uint32_t starts {};

        [[nodiscard]] std::expected<std::unique_ptr<VmSession>, DiagnosticSet> start(const CompiledPack &,
                                                                                     const VmInvocation &) override {
            ++starts;
            return std::unique_ptr<VmSession> {std::make_unique<ScriptedSession>(scenario)};
        }
    };

    [[nodiscard]] CompiledPack compiled_pack() {
        return {
            .pack = PackId {"pack"},
            .version = PackVersion {"1"},
            .source_digest = SourceDigest {"sha256:source"},
            .compiler_abi = "python-3.14.6/static-compiler-v1",
            .semantic_hash = "sha256:semantic",
            .constants = {make_fact(true)},
            .functions = {BytecodeFunction {
                .id = ExecutableId {"rule"},
                .qualified_name = "rule",
                .register_count = 1U,
                .instructions =
                    {
                        {.opcode = Opcode::load_const, .destination = 0U, .immediate = 0U, .span = source_span()},
                        {.opcode = Opcode::return_value, .operand_a = 0U, .span = source_span()},
                    },
            }},
        };
    }

    struct FakeCompiler final: PackCompiler {
        [[nodiscard]] std::expected<CompiledPack, DiagnosticSet>
        compile(const VerifiedRulePack &, const SchemaCatalog &, const OperatorBindings &) override {
            return compiled_pack();
        }
    };

    struct EngineProviderProbe final: IProviderDispatcher {
        std::uint32_t fact_dispatches {};
        std::uint32_t scan_dispatches {};

        void request_facts(std::vector<FactRequest>) override { ++fact_dispatches; }
        void request_scans(std::vector<ScanRequest>) override { ++scan_dispatches; }
        void cancel(std::vector<RequestId>) override {}
    };

    struct UnusedEngineStore final: IRuntimeStore {
        std::uint32_t commits {};

        [[nodiscard]] std::expected<TransactionReceipt, StoreError>
        transact_event(const RuntimeTransaction &) override {
            ++commits;
            return std::unexpected(StoreError {
                .code = StoreErrorCode::constraint_violation,
                .message = "resident runtime must use its transaction port",
            });
        }
    };

    struct ProviderPort final: IProviderResponsePort {
        std::uint32_t fact_dispatches {};
        std::uint32_t scan_dispatches {};
        std::vector<RequestId> canceled;

        [[nodiscard]] std::expected<std::vector<FactResponse>, PortError>
        resolve_facts(const std::span<const FactRequest> requests) noexcept override {
            ++fact_dispatches;
            std::vector<FactResponse> result;
            for (const auto &request : requests) {
                result.push_back({
                    .request_id = request.request_id,
                    .subject = request.subject,
                    .status = FactTerminalStatus::value,
                    .value = make_fact(UnicodeValue {.utf8 = "demo.exe"}),
                });
            }
            return result;
        }

        [[nodiscard]] std::expected<std::vector<ScanResponse>, PortError>
        resolve_scans(const std::span<const ScanRequest> requests) noexcept override {
            ++scan_dispatches;
            std::vector<ScanResponse> result;
            for (const auto &request : requests) {
                result.push_back({
                    .request_id = request.request_id,
                    .subject = request.subject,
                    .status = FactTerminalStatus::value,
                });
            }
            return result;
        }

        void cancel(const std::span<const RequestId> requests) noexcept override {
            canceled.insert(canceled.end(), requests.begin(), requests.end());
        }
    };

    struct CapabilityPort final: ICapabilityResponsePort {
        std::uint32_t dispatches {};
        std::vector<RequestId> canceled;

        [[nodiscard]] std::expected<std::vector<CapabilityResponse>, PortError>
        resolve(const std::span<const CapabilityRequest> requests) noexcept override {
            ++dispatches;
            std::vector<CapabilityResponse> result;
            for (const auto &request : requests) {
                result.push_back({
                    .request_id = request.request_id,
                    .status = FactTerminalStatus::value,
                    .value = frozen_bool(true, "sha256:service"),
                });
            }
            return result;
        }

        void cancel(const std::span<const RequestId> requests) noexcept override {
            canceled.insert(canceled.end(), requests.begin(), requests.end());
        }
    };

    struct StatePort final: IStateResponsePort {
        std::uint32_t reads {};

        [[nodiscard]] std::expected<std::vector<StateReadResponse>, PortError>
        read(const std::span<const StateReadRequest> requests) noexcept override {
            ++reads;
            std::vector<StateReadResponse> result;
            for (const auto &request : requests) {
                result.push_back({
                    .request_id = request.request_id,
                    .value = frozen_bool(reads != 1U, "sha256:state-read:" + std::to_string(reads)),
                    .version = reads - 1U,
                });
            }
            return result;
        }
    };

    struct HistoryPort final: IHistoryResponsePort {
        std::uint32_t dispatches {};
        std::vector<RequestId> canceled;

        [[nodiscard]] std::expected<std::vector<HistoryResponse>, PortError>
        query(const std::span<const HistoryRequest> requests) noexcept override {
            ++dispatches;
            std::vector<HistoryResponse> result;
            for (const auto &request : requests) {
                result.push_back({
                    .request_id = request.request_id,
                    .rows = {frozen_bool(true, "sha256:history")},
                });
            }
            return result;
        }

        void cancel(const std::span<const RequestId> requests) noexcept override {
            canceled.insert(canceled.end(), requests.begin(), requests.end());
        }
    };

    struct ScriptedControl final: IWorkControlPort {
        std::vector<WorkControlState> script;
        std::size_t calls {};

        [[nodiscard]] std::expected<WorkControlState, PortError>
        observe(const ResidentWorkIdentity &) noexcept override {
            if (calls < script.size()) {
                return script[calls++];
            }
            ++calls;
            return WorkControlState::current;
        }
    };

    struct TransactionPort final: ITransactionPort {
        std::uint32_t conflicts_remaining {};
        std::uint32_t commits {};
        std::vector<RuntimeTransaction> proposals;

        [[nodiscard]] std::expected<TransactionReceipt, StoreError>
        commit(const ResidentWorkIdentity &work, const RuntimeTransaction &transaction) noexcept override {
            ++commits;
            proposals.push_back(transaction);
            if (transaction.cursor.consumer != work.serial_domain || transaction.fence_token != work.fence) {
                return std::unexpected(StoreError {
                    .code = StoreErrorCode::stale_fence,
                    .message = "identity mismatch",
                });
            }
            if (conflicts_remaining != 0U) {
                --conflicts_remaining;
                return std::unexpected(StoreError {
                    .code = StoreErrorCode::conflict,
                    .message = "state version conflict",
                    .retryable = true,
                });
            }
            TransactionReceipt receipt {
                .input = transaction.input.id,
                .committed_cursor = transaction.cursor.new_position,
            };
            for (const auto &row : transaction.outbox) { receipt.outbox_intents.push_back(row.intent); }
            return receipt;
        }
    };

    [[nodiscard]] VerifiedRulePack verified_pack() {
        return {
            .manifest = PackManifest {.pack = PackId {"pack"}, .version = PackVersion {"1"}},
            .trust = TrustResult {.production_authorized = true},
            .closure_digest = SourceDigest {"sha256:source"},
        };
    }

    [[nodiscard]] ResidentEvaluationRequest evaluation_request() {
        return {
            .work =
                ResidentWorkIdentity {
                    .work_id = "work-1",
                    .node_id = "node-a",
                    .serial_domain = "peer:peer-1",
                    .pack = PackId {"pack"},
                    .generation = 7U,
                    .attempt = 1U,
                    .fence = 9U,
                    .lease_until_unix_ms = 10'000U,
                },
            .invocation =
                VmInvocation {
                    .execution = ExecutionId {"execution-1"},
                    .invocation = InvocationId {"invocation-1"},
                    .binding = BindingId {"binding-1"},
                    .subject = subject(),
                    .deterministic_hash_seed = 17U,
                },
            .input =
                EventEnvelope {
                    .id = EventId {"event-1"},
                    .schema = SchemaId {"observation/v1"},
                    .tenant = TenantId {"tenant-1"},
                    .peer = PeerId {"peer-1"},
                    .subject = subject(),
                    .producer_unix_ms = 10U,
                    .ingest_unix_ms = 20U,
                    .payload = frozen_bool(true, "sha256:event"),
                },
            .cursor = {.consumer = "peer:peer-1", .expected_position = 0U, .new_position = 1U},
        };
    }

    struct Fixture {
        FakeCompiler compiler;
        ScriptedVmFactory vm;
        EngineProviderProbe engine_provider;
        UnusedEngineStore engine_store;
        RuntimeEngine engine {compiler, vm, engine_provider, engine_store};
        ProviderPort providers;
        CapabilityPort capabilities;
        StatePort state;
        HistoryPort history;
        ScriptedControl control;
        TransactionPort transactions;

        explicit Fixture(const SessionScenario scenario): vm {scenario} {
            REQUIRE(engine.activate(verified_pack(), {}, {}).has_value());
        }

        [[nodiscard]] HostResponsePorts ports() {
            return {.providers = providers, .capabilities = capabilities, .state = state, .history = history};
        }
    };

} // namespace

TEST_CASE("resident runtime resumes one fact request without duplicate reads") {
    Fixture fixture {SessionScenario::fact};
    ResidentRuntime runtime {fixture.engine, fixture.ports(), fixture.control, fixture.transactions};

    const auto result = runtime.evaluate(evaluation_request());

    REQUIRE(result.has_value());
    CHECK(result->committed());
    CHECK(result->evaluation.outcome == EvaluationOutcome::match);
    CHECK(result->attempts == 1U);
    CHECK(fixture.providers.fact_dispatches == 1U);
    CHECK(fixture.engine_provider.fact_dispatches == 0U);
    CHECK(result->captured_inputs.size() == 1U);
}

TEST_CASE("resident runtime refreshes state while replaying captured facts after an MVCC conflict") {
    Fixture fixture {SessionScenario::state_conflict};
    fixture.transactions.conflicts_remaining = 1U;
    ResidentRuntime runtime {fixture.engine, fixture.ports(), fixture.control, fixture.transactions};

    const auto result = runtime.evaluate(evaluation_request());

    REQUIRE(result.has_value());
    CHECK(result->committed());
    CHECK(result->attempts == 2U);
    CHECK(fixture.vm.starts == 2U);
    CHECK(fixture.providers.fact_dispatches == 1U);
    CHECK(fixture.state.reads == 2U);
    REQUIRE(fixture.transactions.proposals.size() == 2U);
    REQUIRE(fixture.transactions.proposals.back().state.size() == 1U);
    CHECK(fixture.transactions.proposals.back().state.front().expected_version == 1U);
}

TEST_CASE("resident runtime commits only durable effects and projects only eligible posts to the outbox") {
    Fixture fixture {SessionScenario::effects};
    ResidentRuntime runtime {fixture.engine, fixture.ports(), fixture.control, fixture.transactions};

    const auto result = runtime.evaluate(evaluation_request());

    REQUIRE(result.has_value());
    REQUIRE(result->candidate.has_value());
    CHECK(result->evaluation.outcome == EvaluationOutcome::no_match);
    CHECK(result->candidate->journal.size() == 2U);
    CHECK(result->candidate->outbox.size() == 1U);
    CHECK(result->candidate->outbox.front().intent == IntentId {"intent:committed"});
    CHECK(std::ranges::none_of(result->candidate->journal, [](const EffectIntent &intent) {
        return intent.id == IntentId {"intent:rolled-back"};
    }));
}

TEST_CASE("resident runtime cancels outstanding host work and never commits a canceled VM") {
    Fixture fixture {SessionScenario::cancellation};
    fixture.control.script = {WorkControlState::current, WorkControlState::canceled};
    ResidentRuntime runtime {fixture.engine, fixture.ports(), fixture.control, fixture.transactions};

    const auto result = runtime.evaluate(evaluation_request());

    REQUIRE(result.has_value());
    CHECK_FALSE(result->committed());
    CHECK(result->evaluation.outcome == EvaluationOutcome::canceled);
    CHECK(fixture.providers.fact_dispatches == 0U);
    REQUIRE(fixture.providers.canceled.size() == 1U);
    CHECK(fixture.providers.canceled.front() == RequestId {"request:fact:1"});
    CHECK(fixture.transactions.commits == 0U);
}

TEST_CASE("resident runtime rejects a stale fence before making a terminal result visible") {
    Fixture fixture {SessionScenario::constant};
    fixture.control.script = {WorkControlState::current, WorkControlState::stale};
    ResidentRuntime runtime {fixture.engine, fixture.ports(), fixture.control, fixture.transactions};

    const auto result = runtime.evaluate(evaluation_request());

    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == ResidentRuntimeErrorCode::stale_fence);
    CHECK(fixture.transactions.commits == 0U);
}

TEST_CASE("diagnostic replay uses captured responses and performs no live dispatch or commit") {
    Fixture fixture {SessionScenario::fact};
    ResidentRuntime runtime {fixture.engine, fixture.ports(), fixture.control, fixture.transactions};
    auto request = evaluation_request();
    const auto live = runtime.evaluate(request);
    REQUIRE(live.has_value());
    REQUIRE(live->committed());
    REQUIRE(fixture.providers.fact_dispatches == 1U);
    REQUIRE(fixture.transactions.commits == 1U);

    request.mode = ExecutionMode::replay;
    request.replay_inputs = live->captured_inputs;
    const auto replayed = runtime.evaluate(std::move(request));

    REQUIRE(replayed.has_value());
    CHECK_FALSE(replayed->committed());
    CHECK(replayed->candidate.has_value());
    CHECK(replayed->evaluation.outcome == live->evaluation.outcome);
    CHECK(fixture.providers.fact_dispatches == 1U);
    CHECK(fixture.capabilities.dispatches == 0U);
    CHECK(fixture.state.reads == 0U);
    CHECK(fixture.history.dispatches == 0U);
    CHECK(fixture.transactions.commits == 1U);
    CHECK(fixture.control.calls == 3U);
}

TEST_CASE("capability and history requests cross only their typed response ports") {
    Fixture fixture {SessionScenario::capabilities};
    ResidentRuntime runtime {fixture.engine, fixture.ports(), fixture.control, fixture.transactions};

    const auto result = runtime.evaluate(evaluation_request());

    REQUIRE(result.has_value());
    CHECK(result->committed());
    CHECK(fixture.capabilities.dispatches == 1U);
    CHECK(fixture.history.dispatches == 1U);
    CHECK(fixture.providers.fact_dispatches == 0U);
    CHECK(fixture.engine_provider.fact_dispatches == 0U);
}
