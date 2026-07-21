#include "rule_engine/python/runtime/adapters.hpp"
#include "rule_engine/python/runtime/orchestrator.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
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

    [[nodiscard]] ScanRequest scan_request() {
        return {
            .request_id = RequestId {"request:scan:1"},
            .subject = subject(),
            .space =
                ScanSpace {
                    .kind = "memory",
                    .begin = 0x1'000U,
                    .size = 16U,
                    .permissions = 4U,
                    .identity = "region-1",
                    .label = DataLabel {.classification = Classification::internal},
                    .subject_generation = 7U,
                },
            .plan =
                ScanPlan {
                    .plan_id = "plan-1",
                    .encoded_pattern = "literal:A",
                    .maximum_bytes = 16U,
                    .maximum_matches = 4U,
                    .context_bytes_before = 0U,
                    .context_bytes_after = 0U,
                    .result_mode = ScanResultMode::exact_complete,
                    .pattern_ids = {"pattern-1"},
                },
            .deadline_unix_ms = 1'000U,
        };
    }

    [[nodiscard]] protocol_v2::WorkLeaseMessage provider_work(const bool include_scan = true) {
        return {
            .session = SessionId {"session-1"},
            .peer = PeerId {"peer-1"},
            .session_fence = 3U,
            .work_id = "provider-work-1",
            .attempt_id = "provider-attempt-1",
            .work_fence = 9U,
            .generation = 7U,
            .server_sequence = 1U,
            .route = "process",
            .facts = {fact_request()},
            .scans = include_scan ? std::vector<ScanRequest> {scan_request()} : std::vector<ScanRequest> {},
        };
    }

    [[nodiscard]] protocol_v2::WorkResultMessage provider_result(const protocol_v2::WorkLeaseMessage &work) {
        protocol_v2::WorkResultMessage result {
            .originating_session = work.session,
            .peer = work.peer,
            .originating_session_fence = work.session_fence,
            .work_id = work.work_id,
            .attempt_id = work.attempt_id,
            .work_fence = work.work_fence,
            .generation = work.generation,
        };
        for (const auto &request : work.facts) {
            result.facts.push_back({
                .request_id = request.request_id,
                .subject = request.subject,
                .status = FactTerminalStatus::value,
                .value = make_fact(UnicodeValue {.utf8 = "demo.exe"}),
            });
        }
        for (const auto &request : work.scans) {
            result.scans.push_back({
                .request_id = request.request_id,
                .subject = request.subject,
                .status = FactTerminalStatus::value,
                .matches = {ScanMatch {
                    .offset = 2U,
                    .length = 1U,
                    .pattern_id = "pattern-1",
                    .scan_space_id = request.space.identity,
                    .absolute_address = request.space.begin + 2U,
                    .permission_snapshot = request.space.permissions,
                    .matched_bytes = {std::byte {0x41}},
                    .label = request.space.label,
                    .subject_generation = request.space.subject_generation,
                }},
                .truncated = false,
                .mode = request.plan.result_mode,
            });
        }
        return result;
    }

    [[nodiscard]] protocol_v2::PeerEnvelope provider_envelope(const std::uint64_t sequence,
                                                              protocol_v2::WorkResultMessage result) {
        return {
            .protocol_major = protocol_v2::major_version,
            .protocol_minor = protocol_v2::initial_minor_version,
            .message_id = "message-" + std::to_string(sequence),
            .session = SessionId {"session-1"},
            .agent_epoch = "agent-epoch-1",
            .agent_sequence = sequence,
            .acknowledged_agent_sequence = 0U,
            .body = std::move(result),
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

    struct ProtocolCancelSink final: IProtocolV2CancelSink {
        std::vector<RequestId> canceled;

        void cancel(const protocol_v2::WorkLeaseMessage &,
                    const std::span<const RequestId> requests) noexcept override {
            canceled.insert(canceled.end(), requests.begin(), requests.end());
        }
    };

    struct TestClock final: IRuntimeClock {
        std::uint64_t now {};

        [[nodiscard]] std::uint64_t now_unix_ms() const noexcept override { return now; }
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
        DispatchFreeRuntimeEngineDriver vm_driver {engine};
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
    ResidentRuntime runtime {fixture.vm_driver, fixture.ports(), fixture.control, fixture.transactions};

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
    ResidentRuntime runtime {fixture.vm_driver, fixture.ports(), fixture.control, fixture.transactions};

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
    ResidentRuntime runtime {fixture.vm_driver, fixture.ports(), fixture.control, fixture.transactions};

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
    ResidentRuntime runtime {fixture.vm_driver, fixture.ports(), fixture.control, fixture.transactions};

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
    ResidentRuntime runtime {fixture.vm_driver, fixture.ports(), fixture.control, fixture.transactions};

    const auto result = runtime.evaluate(evaluation_request());

    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == ResidentRuntimeErrorCode::stale_fence);
    CHECK(fixture.transactions.commits == 0U);
}

TEST_CASE("resident runtime rejects work for a different active pack") {
    Fixture fixture {SessionScenario::constant};
    ResidentRuntime runtime {fixture.vm_driver, fixture.ports(), fixture.control, fixture.transactions};
    auto request = evaluation_request();
    request.work.pack = PackId {"other-pack"};

    const auto result = runtime.evaluate(std::move(request));

    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == ResidentRuntimeErrorCode::invalid_work);
    CHECK(fixture.transactions.commits == 0U);
    CHECK(fixture.engine_provider.fact_dispatches == 0U);
}

TEST_CASE("diagnostic replay uses captured responses and performs no live dispatch or commit") {
    Fixture fixture {SessionScenario::fact};
    ResidentRuntime runtime {fixture.vm_driver, fixture.ports(), fixture.control, fixture.transactions};
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
    CHECK(fixture.engine_provider.fact_dispatches == 0U);
    CHECK(fixture.engine_provider.scan_dispatches == 0U);
}

TEST_CASE("capability and history requests cross only their typed response ports") {
    Fixture fixture {SessionScenario::capabilities};
    ResidentRuntime runtime {fixture.vm_driver, fixture.ports(), fixture.control, fixture.transactions};

    const auto result = runtime.evaluate(evaluation_request());

    REQUIRE(result.has_value());
    CHECK(result->committed());
    CHECK(fixture.capabilities.dispatches == 1U);
    CHECK(fixture.history.dispatches == 1U);
    CHECK(fixture.providers.fact_dispatches == 0U);
    CHECK(fixture.engine_provider.fact_dispatches == 0U);
}

TEST_CASE("protocol-v2 terminal responses are bound to the exact request subject and fence") {
    ProtocolCancelSink cancel_sink;
    const auto work = provider_work();
    auto port = ProtocolV2ProviderResponsePort::create(work, cancel_sink);
    REQUIRE(port.has_value());

    auto stale = provider_result(work);
    ++stale.work_fence;
    const auto rejected = port->admit(stale);
    REQUIRE_FALSE(rejected.has_value());
    CHECK(rejected.error().code == protocol_v2::ProtocolErrorCode::stale_fence);

    auto wrong_subject = provider_result(work);
    wrong_subject.facts.front().subject.identity.front().value = std::uint64_t {43U};
    const auto subject_rejected = port->admit(wrong_subject);
    REQUIRE_FALSE(subject_rejected.has_value());
    CHECK(subject_rejected.error().code == protocol_v2::ProtocolErrorCode::provider_violation);

    auto out_of_bounds_scan = provider_result(work);
    ++out_of_bounds_scan.scans.front().matches.front().absolute_address;
    const auto scan_rejected = port->admit(out_of_bounds_scan);
    REQUIRE_FALSE(scan_rejected.has_value());
    CHECK(scan_rejected.error().code == protocol_v2::ProtocolErrorCode::provider_violation);

    const auto unavailable = port->resolve_facts(work.facts);
    REQUIRE_FALSE(unavailable.has_value());
    CHECK(unavailable.error().code == PortErrorCode::unavailable);

    REQUIRE(port->admit(provider_result(work)).has_value());
    const auto facts = port->resolve_facts(work.facts);
    REQUIRE(facts.has_value());
    REQUIRE(facts->size() == 1U);
    CHECK(facts->front().request_id == work.facts.front().request_id);
    CHECK(canonical_subject_key(facts->front().subject) == canonical_subject_key(work.facts.front().subject));

    const auto scans = port->resolve_scans(work.scans);
    REQUIRE(scans.has_value());
    REQUIRE(scans->size() == 1U);
    REQUIRE(scans->front().matches.size() == 1U);
    CHECK(scans->front().matches.front().absolute_address == 0x1'002U);
}

TEST_CASE("protocol-v2 durable admission rejects conflicts and exposes only contiguous sequences") {
    auto gate = ProtocolV2DurableSequenceGate::create(PeerId {"peer-1"}, SessionId {"session-1"}, 3U, "agent-epoch-1");
    REQUIRE(gate.has_value());

    auto second_result = provider_result(provider_work());
    second_result.work_id = "provider-work-2";
    const auto second_envelope = provider_envelope(2U, second_result);
    const auto second = gate->admit(second_envelope);
    REQUIRE(second.has_value());
    CHECK(*second == protocol_v2::SequenceDisposition::accepted_out_of_order);
    CHECK_FALSE(gate->next_contiguous().has_value());

    const auto duplicate = gate->admit(second_envelope);
    REQUIRE(duplicate.has_value());
    CHECK(*duplicate == protocol_v2::SequenceDisposition::duplicate);

    auto conflicting_result = second_result;
    conflicting_result.work_id = "provider-work-conflict";
    const auto conflicting = gate->admit(provider_envelope(2U, std::move(conflicting_result)));
    REQUIRE_FALSE(conflicting.has_value());
    CHECK(conflicting.error().code == protocol_v2::ProtocolErrorCode::duplicate_item);

    auto stale_result = provider_result(provider_work());
    ++stale_result.originating_session_fence;
    const auto stale = gate->admit(provider_envelope(3U, std::move(stale_result)));
    REQUIRE_FALSE(stale.has_value());
    CHECK(stale.error().code == protocol_v2::ProtocolErrorCode::stale_fence);

    const auto first = gate->admit(provider_envelope(1U, provider_result(provider_work())));
    REQUIRE(first.has_value());
    CHECK(*first == protocol_v2::SequenceDisposition::accepted);
    REQUIRE(gate->next_contiguous().has_value());
    CHECK(gate->next_contiguous()->sequence == 1U);
    REQUIRE(gate->mark_durable(1U).has_value());
    REQUIRE(gate->next_contiguous().has_value());
    CHECK(gate->next_contiguous()->sequence == 2U);
    REQUIRE(gate->mark_durable(2U).has_value());
    CHECK(gate->acknowledged_through() == 2U);
    CHECK_FALSE(gate->next_contiguous().has_value());
}

TEST_CASE("protocol-v2 provider responses drive the resident VM without RuntimeEngine dispatch") {
    Fixture fixture {SessionScenario::fact};
    ProtocolCancelSink cancel_sink;
    const auto work = provider_work(false);
    auto providers = ProtocolV2ProviderResponsePort::create(work, cancel_sink);
    REQUIRE(providers.has_value());
    REQUIRE(providers->admit(provider_result(work)).has_value());
    HostResponsePorts ports {
        .providers = *providers,
        .capabilities = fixture.capabilities,
        .state = fixture.state,
        .history = fixture.history,
    };
    ResidentRuntime runtime {fixture.vm_driver, ports, fixture.control, fixture.transactions};

    const auto result = runtime.evaluate(evaluation_request());

    REQUIRE(result.has_value());
    CHECK(result->committed());
    CHECK(fixture.engine_provider.fact_dispatches == 0U);
    CHECK(fixture.engine_provider.scan_dispatches == 0U);
}

TEST_CASE("cluster transaction adapter rejects stale generations and work attempts before commit") {
    cluster::AuditTrail audit;
    cluster::InMemoryRuntimeStore store {audit};
    cluster::DeterministicWorkCoordinator coordinator {store, audit};
    REQUIRE(coordinator
                .enqueue(cluster::WorkDefinition {
                    .work_id = "work-1",
                    .pack = PackId {"pack"},
                    .generation = 7U,
                    .serial_domain = "peer:peer-1",
                    .event = EventId {"event-1"},
                    .priority = 1,
                    .ingest_position = 1U,
                })
                .value());
    const auto first_claim = coordinator.claim("node-a", 100U, 10U, 1U);
    REQUIRE(first_claim.has_value());
    REQUIRE(first_claim->size() == 1U);
    const auto first_lease = first_claim->front();

    TestClock clock;
    clock.now = 100U;
    ClusterWorkTransactionPort first_port {coordinator, first_lease, clock};
    auto resident = evaluation_request().work;
    resident.work_id = first_lease.work.work_id;
    resident.node_id = first_lease.node_id;
    resident.serial_domain = first_lease.work.serial_domain;
    resident.pack = first_lease.work.pack;
    resident.generation = first_lease.work.generation;
    resident.attempt = first_lease.attempt;
    resident.fence = first_lease.fence;
    resident.lease_until_unix_ms = first_lease.lease_until_unix_ms;
    const auto request = evaluation_request();
    RuntimeTransaction transaction {
        .input = request.input,
        .cursor = request.cursor,
        .evaluation = clean_result(),
        .fence_token = first_lease.fence,
    };

    auto stale_generation = resident;
    ++stale_generation.generation;
    const auto generation_rejected = first_port.commit(stale_generation, transaction);
    REQUIRE_FALSE(generation_rejected.has_value());
    CHECK(generation_rejected.error().code == StoreErrorCode::stale_fence);

    auto stale_attempt = resident;
    ++stale_attempt.attempt;
    const auto attempt_rejected = first_port.commit(stale_attempt, transaction);
    REQUIRE_FALSE(attempt_rejected.has_value());
    CHECK(attempt_rejected.error().code == StoreErrorCode::stale_fence);
    REQUIRE(store.inspect()->receipts.empty());

    clock.now = 111U;
    const auto takeover_claim = coordinator.claim("node-b", clock.now, 10U, 1U);
    REQUIRE(takeover_claim.has_value());
    REQUIRE(takeover_claim->size() == 1U);
    const auto takeover = takeover_claim->front();
    CHECK(takeover.attempt > first_lease.attempt);
    CHECK(takeover.fence > first_lease.fence);

    const auto stale_commit = first_port.commit(resident, transaction);
    REQUIRE_FALSE(stale_commit.has_value());
    CHECK(stale_commit.error().code == StoreErrorCode::stale_fence);

    auto current = resident;
    current.node_id = takeover.node_id;
    current.attempt = takeover.attempt;
    current.fence = takeover.fence;
    current.lease_until_unix_ms = takeover.lease_until_unix_ms;
    transaction.fence_token = takeover.fence;
    ClusterWorkTransactionPort takeover_port {coordinator, takeover, clock};
    const auto committed = takeover_port.commit(current, transaction);
    REQUIRE(committed.has_value());
    REQUIRE(store.inspect()->receipts.size() == 1U);
}
