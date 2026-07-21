#include "rule_engine/python/runtime/adapters.hpp"
#include "rule_engine/python/runtime/orchestrator.hpp"
#include "rule_engine/python/vm/register_vm.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <limits>
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
    using namespace std::chrono_literals;

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

    [[nodiscard]] FrozenValue canonical_frozen_bool(const bool value) {
        vm::ValueHeap heap;
        auto thawed = heap.thaw(make_fact(value));
        REQUIRE(thawed.has_value());
        auto frozen = heap.freeze(*thawed);
        REQUIRE(frozen.has_value());
        return std::move(*frozen);
    }

    [[nodiscard]] FrozenValue emitted_payload() {
        return FrozenValue {
            .value = make_fact(FactRecord {
                .schema = SchemaId {"custom.alert/v1"},
                .fields = {{.field_id = 1U, .value = make_fact(UnicodeValue {.utf8 = "detected"})}},
            }),
            .label = DataLabel {.classification = Classification::internal, .categories = {"security"}},
            .canonical_digest = "sha256:custom-alert-payload",
        };
    }

    [[nodiscard]] EventIntent emitted_intent(const bool malformed = false) {
        return EventIntent {
            .id = deterministic_event_intent_id(EventId {"event-1"}, InvocationId {"invocation-1"}, 1U),
            .root_event = EventId {"event-1"},
            .invocation = InvocationId {"invocation-1"},
            .owner = ExecutableId {"rule"},
            .binding = BindingId {"binding-1"},
            .sequence = 1U,
            .schema = SchemaId {"custom.alert/v1"},
            .schema_hash = malformed ? "sha256:forged" : "sha256:custom-alert-v1",
            .payload = emitted_payload(),
            .span = source_span(),
            .disposition = EventDisposition::committed,
        };
    }

    [[nodiscard]] FactRequest fact_request() {
        return {
            .request_id = RequestId {"request:fact:1"},
            .subject = subject(),
            .route = {.provider = "process", .fact = "image_name"},
            .expected_schema = SchemaId {"unicode/v1"},
            .expected_schema_hash = "sha256:unicode-v1",
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
                .returned_schema =
                    SchemaIdentity {.id = request.expected_schema, .canonical_hash = request.expected_schema_hash},
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
        events,
        malformed_events,
    };

    struct ScriptedSession final: VmSession {
        explicit ScriptedSession(const SessionScenario value, const VmResourceUsage reported = {}):
            scenario {value}, reported_usage {reported} {}

        SessionScenario scenario {SessionScenario::constant};
        VmResourceUsage reported_usage;
        std::uint32_t stage {};

        [[nodiscard]] VmResourceUsage resource_usage() const noexcept override { return reported_usage; }

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
                case SessionScenario::events:
                case SessionScenario::malformed_events: {
                    auto result = clean_result();
                    result.committed_events.push_back(emitted_intent(scenario == SessionScenario::malformed_events));
                    return {.state = VmStepState::complete, .result = std::move(result)};
                }
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
        std::vector<VmInvocation> invocations;
        std::vector<VmResourceUsage> reported_usages;

        [[nodiscard]] std::expected<std::unique_ptr<VmSession>, DiagnosticSet>
        start(const CompiledPack &, const VmInvocation &invocation) override {
            const auto index = starts;
            ++starts;
            invocations.push_back(invocation);
            const auto usage = index < reported_usages.size() ? reported_usages[index] : VmResourceUsage {};
            return std::unique_ptr<VmSession> {std::make_unique<ScriptedSession>(scenario, usage)};
        }
    };

    [[nodiscard]] CompiledPack compiled_pack() {
        return {
            .pack = PackId {"pack"},
            .version = PackVersion {"1"},
            .source_digest = SourceDigest {"sha256:source"},
            .compiler_abi = std::string {python_static_compiler_abi_v1},
            .semantic_hash = "sha256:semantic",
            .schemas =
                SchemaCatalog {
                    .descriptors = {SchemaDescriptor {
                        .id = SchemaId {"custom.alert/v1"},
                        .kind = SchemaKind::event,
                        .qualified_name = "rules.CustomAlert",
                        .canonical_hash = "sha256:custom-alert-v1",
                        .fields = {SchemaField {.field_id = 1U,
                                                .name = "message",
                                                .type = SchemaId {"text"},
                                                .optional = false,
                                                .label = DataLabel {.classification = Classification::internal,
                                                                    .categories = {"security"}}}},
                    }},
                    .canonical_hash = "sha256:runtime-schemas",
                },
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

    struct FixedCompiler final: PackCompiler {
        explicit FixedCompiler(CompiledPack value): pack {std::move(value)} {}

        CompiledPack pack;

        [[nodiscard]] std::expected<CompiledPack, DiagnosticSet>
        compile(const VerifiedRulePack &, const SchemaCatalog &, const OperatorBindings &) override {
            return pack;
        }
    };

    struct RecordingRegisterVmFactory final: VmFactory {
        std::vector<VmInvocation> invocations;

        [[nodiscard]] std::expected<std::unique_ptr<VmSession>, DiagnosticSet>
        start(const CompiledPack &pack, const VmInvocation &invocation) override {
            invocations.push_back(invocation);
            auto session = vm::RegisterVmSession::create(pack, invocation);
            if (!session) {
                return std::unexpected(std::move(session.error()));
            }
            return std::unique_ptr<VmSession> {std::move(*session)};
        }
    };

    [[nodiscard]] CompiledPack real_state_pack() {
        return {
            .pack = PackId {"pack"},
            .version = PackVersion {"1"},
            .source_digest = SourceDigest {"sha256:source"},
            .compiler_abi = std::string {python_static_compiler_abi_v1},
            .semantic_hash = "sha256:semantic",
            .constants =
                {
                    vm::make_state_operand("peer-state/v1", "counter", SchemaId {"bool"}),
                    make_fact(true),
                },
            .functions = {BytecodeFunction {
                .id = ExecutableId {"rule"},
                .qualified_name = "rule",
                .register_count = 2U,
                .instructions =
                    {
                        {.opcode = Opcode::read_state, .destination = 0U, .immediate = 0U, .span = source_span()},
                        {.opcode = Opcode::load_const, .destination = 1U, .immediate = 1U, .span = source_span()},
                        {.opcode = Opcode::write_state, .operand_a = 1U, .immediate = 0U, .span = source_span()},
                        {.opcode = Opcode::return_value, .operand_a = 1U, .span = source_span()},
                    },
            }},
            .bindings = {OperatorBinding {
                .id = BindingId {"binding-1"},
                .executable = ExecutableId {"rule"},
                .capabilities = {},
                .budget = balanced_v1,
            }},
        };
    }

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
                    .returned_schema =
                        SchemaIdentity {.id = request.expected_schema, .canonical_hash = request.expected_schema_hash},
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
                    .value = canonical_frozen_bool(reads != 1U),
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
            for (const auto &event : transaction.emitted_events) { receipt.emitted_events.push_back(event.id); }
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
        auto budget = balanced_v1;
        // These integration cases exercise orchestration rather than the
        // balanced.v1 wall deadline. Keep them deterministic when a debug test
        // process is descheduled for longer than the production deadline.
        budget.normal.elapsed = std::chrono::hours {1};
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
                    .root_event = EventId {"event-1"},
                    .binding = BindingId {"binding-1"},
                    .subject = subject(),
                    .budget = std::move(budget),
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

    struct RealVmFixture {
        FixedCompiler compiler {real_state_pack()};
        RecordingRegisterVmFactory vm;
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

        RealVmFixture() { REQUIRE(engine.activate(verified_pack(), {}, {}).has_value()); }

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

TEST_CASE("MVCC retries inherit cumulative normal budgets while attempt peaks and recovery caps stay fresh") {
    Fixture fixture {SessionScenario::state_conflict};
    fixture.transactions.conflicts_remaining = 1U;
    const VmResourceUsage attempt_usage {
        .elapsed = 2ms,
        .active_cpu = 1ms,
        .instructions = 7U,
        .peak_frames = 2U,
        .peak_live_heap_bytes = 32U,
        .logical_heap_allocation_bytes = 64U,
        .loop_iterations_and_yields = 3U,
        .logical_facts = 2U,
        .provider_rounds = 1U,
        .fact_bytes = 11U,
        .service_calls = 2U,
        .peak_active_service_calls = 2U,
        .service_response_bytes = 13U,
        .history_queries = 1U,
        .history_rows = 2U,
        .history_bytes = 17U,
        .state_keys = 1U,
        .state_bytes = 19U,
        .effect_intents = 2U,
        .effect_bytes = 23U,
        .event_intents = 4U,
        .event_bytes = 27U,
        .recorder_events = 3U,
        .recorder_bytes = 29U,
    };
    fixture.vm.reported_usages = {attempt_usage, attempt_usage};
    ResidentRuntime runtime {fixture.vm_driver, fixture.ports(), fixture.control, fixture.transactions};
    const auto request = evaluation_request();

    const auto result = runtime.evaluate(request);

    const auto error_message = result ? std::string {} : result.error().message;
    INFO("runtime error: " << error_message);
    REQUIRE(result.has_value());
    REQUIRE(result->committed());
    REQUIRE(fixture.vm.invocations.size() == 2U);
    const auto &remaining = fixture.vm.invocations[1].budget;
    CHECK(remaining.normal.elapsed <= request.invocation.budget.normal.elapsed - 2ms);
    CHECK(remaining.normal.active_cpu == request.invocation.budget.normal.active_cpu - 1ms);
    CHECK(remaining.normal.instructions == request.invocation.budget.normal.instructions - 7U);
    CHECK(remaining.normal.loop_iterations_and_yields ==
          request.invocation.budget.normal.loop_iterations_and_yields - 3U);
    CHECK(remaining.normal.logical_facts == request.invocation.budget.normal.logical_facts - 2U);
    CHECK(remaining.normal.provider_rounds == request.invocation.budget.normal.provider_rounds - 1U);
    CHECK(remaining.normal.fact_bytes == request.invocation.budget.normal.fact_bytes - 11U);
    CHECK(remaining.normal.service_calls == request.invocation.budget.normal.service_calls - 2U);
    CHECK(remaining.normal.service_response_bytes == request.invocation.budget.normal.service_response_bytes - 13U);
    CHECK(remaining.normal.history_queries == request.invocation.budget.normal.history_queries - 1U);
    CHECK(remaining.normal.history_rows == request.invocation.budget.normal.history_rows - 2U);
    CHECK(remaining.normal.history_bytes == request.invocation.budget.normal.history_bytes - 17U);
    CHECK(remaining.normal.state_keys == request.invocation.budget.normal.state_keys - 1U);
    CHECK(remaining.normal.state_bytes == request.invocation.budget.normal.state_bytes - 19U);
    CHECK(remaining.normal.effect_intents == request.invocation.budget.normal.effect_intents - 2U);
    CHECK(remaining.normal.effect_bytes == request.invocation.budget.normal.effect_bytes - 23U);
    CHECK(remaining.normal.event_intents == request.invocation.budget.normal.event_intents - 4U);
    CHECK(remaining.normal.event_bytes == request.invocation.budget.normal.event_bytes - 27U);
    CHECK(remaining.normal.recorder_events == request.invocation.budget.normal.recorder_events - 3U);
    CHECK(remaining.normal.recorder_bytes == request.invocation.budget.normal.recorder_bytes - 29U);
    CHECK(remaining.normal.frames == request.invocation.budget.normal.frames);
    CHECK(remaining.normal.heap_bytes == request.invocation.budget.normal.heap_bytes);
    CHECK(remaining.normal.active_service_calls == request.invocation.budget.normal.active_service_calls);
    CHECK(remaining.normal.maximum_service_deadline == request.invocation.budget.normal.maximum_service_deadline);
    CHECK(remaining.finalizer_or_fault.instructions == request.invocation.budget.finalizer_or_fault.instructions);
    CHECK(remaining.double_fault.instructions == request.invocation.budget.double_fault.instructions);
    CHECK(remaining.forced_cleanup.instructions == request.invocation.budget.forced_cleanup.instructions);
    CHECK(result->resource_usage.instructions == 14U);
    CHECK(result->resource_usage.elapsed >= 4ms);
    CHECK(result->resource_usage.logical_heap_allocation_bytes == 128U);
    CHECK(result->resource_usage.event_intents == 8U);
    CHECK(result->resource_usage.event_bytes == 54U);
    CHECK(result->resource_usage.peak_frames == 2U);
    CHECK(result->resource_usage.peak_live_heap_bytes == 32U);
    CHECK(result->resource_usage.peak_active_service_calls == 2U);
}

TEST_CASE("resident runtime resets cumulative elapsed accounting for each evaluation") {
    Fixture fixture {SessionScenario::constant};
    fixture.vm.reported_usages = {
        VmResourceUsage {.elapsed = 59min},
        VmResourceUsage {},
    };
    ResidentRuntime runtime {fixture.vm_driver, fixture.ports(), fixture.control, fixture.transactions};

    const auto first = runtime.evaluate(evaluation_request());
    const auto second = runtime.evaluate(evaluation_request());

    REQUIRE(first.has_value());
    REQUIRE(second.has_value());
    REQUIRE(fixture.vm.invocations.size() == 2U);
    CHECK(fixture.vm.invocations[0].budget.normal.elapsed > 30min);
    CHECK(fixture.vm.invocations[1].budget.normal.elapsed > 30min);
    CHECK(first->resource_usage.elapsed >= 59min);
    CHECK(second->resource_usage.elapsed < 1min);
}

TEST_CASE("resident runtime rejects over-budget and overflowing VM usage before commit") {
    SECTION("one attempt exceeds its inherited instruction budget") {
        Fixture fixture {SessionScenario::constant};
        fixture.vm.reported_usages = {
            VmResourceUsage {.instructions = balanced_v1.normal.instructions + 1U},
        };
        ResidentRuntime runtime {fixture.vm_driver, fixture.ports(), fixture.control, fixture.transactions};

        const auto result = runtime.evaluate(evaluation_request());

        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().code == ResidentRuntimeErrorCode::invalid_resource_usage);
        CHECK(fixture.transactions.commits == 0U);
    }

    SECTION("logical allocation accounting cannot wrap across attempts") {
        Fixture fixture {SessionScenario::state_conflict};
        fixture.transactions.conflicts_remaining = 1U;
        fixture.vm.reported_usages = {
            VmResourceUsage {.logical_heap_allocation_bytes = std::numeric_limits<std::size_t>::max()},
            VmResourceUsage {.logical_heap_allocation_bytes = 1U},
        };
        ResidentRuntime runtime {fixture.vm_driver, fixture.ports(), fixture.control, fixture.transactions};

        const auto result = runtime.evaluate(evaluation_request());

        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().code == ResidentRuntimeErrorCode::invalid_resource_usage);
        CHECK(fixture.vm.starts == 2U);
        CHECK(fixture.transactions.commits == 1U);
    }
}

TEST_CASE("real register VM spends one instruction budget across a successful MVCC retry") {
    RealVmFixture fixture;
    fixture.transactions.conflicts_remaining = 1U;
    ResidentRuntime runtime {fixture.vm_driver, fixture.ports(), fixture.control, fixture.transactions};
    auto request = evaluation_request();
    request.invocation.budget.normal.instructions = 8U;

    const auto result = runtime.evaluate(request);

    REQUIRE(result.has_value());
    REQUIRE(result->committed());
    const auto terminal_fault =
        result->evaluation.fault.has_value() && !result->evaluation.fault->frames.empty() ?
            result->evaluation.fault->frames.front().code + " " + result->evaluation.fault->frames.front().message :
            std::string {};
    INFO("terminal fault: " << terminal_fault);
    CHECK(result->attempts == 2U);
    CHECK(result->evaluation.outcome == EvaluationOutcome::match);
    CHECK(result->resource_usage.instructions == 8U);
    CHECK(result->resource_usage.state_keys == 2U);
    CHECK(result->resource_usage.elapsed > std::chrono::nanoseconds::zero());
    CHECK(result->resource_usage.peak_frames == 1U);
    CHECK(result->resource_usage.peak_live_heap_bytes > 0U);
    CHECK(result->resource_usage.logical_heap_allocation_bytes >= result->resource_usage.peak_live_heap_bytes);
    REQUIRE(fixture.vm.invocations.size() == 2U);
    CHECK(fixture.vm.invocations[1].budget.normal.instructions == 4U);
    CHECK(fixture.vm.invocations[1].budget.normal.frames == request.invocation.budget.normal.frames);
    CHECK(fixture.vm.invocations[1].budget.normal.heap_bytes == request.invocation.budget.normal.heap_bytes);
    CHECK(fixture.vm.invocations[1].budget.finalizer_or_fault.instructions ==
          request.invocation.budget.finalizer_or_fault.instructions);
    CHECK(fixture.state.reads == 2U);
}

TEST_CASE("real register VM faults before work when a conflict leaves exactly zero instructions") {
    RealVmFixture fixture;
    fixture.transactions.conflicts_remaining = 1U;
    ResidentRuntime runtime {fixture.vm_driver, fixture.ports(), fixture.control, fixture.transactions};
    auto request = evaluation_request();
    request.invocation.budget.normal.instructions = 4U;

    const auto result = runtime.evaluate(request);

    REQUIRE(result.has_value());
    REQUIRE(result->committed());
    const auto terminal_fault =
        result->evaluation.fault.has_value() && !result->evaluation.fault->frames.empty() ?
            result->evaluation.fault->frames.front().code + " " + result->evaluation.fault->frames.front().message :
            std::string {};
    INFO("terminal fault: " << terminal_fault);
    CHECK(result->attempts == 2U);
    CHECK(result->evaluation.outcome == EvaluationOutcome::faulted);
    CHECK(result->resource_usage.instructions == 4U);
    CHECK(result->resource_usage.state_keys == 1U);
    REQUIRE(fixture.vm.invocations.size() == 2U);
    CHECK(fixture.vm.invocations[1].budget.normal.instructions == 0U);
    CHECK(fixture.state.reads == 1U);
    REQUIRE(fixture.transactions.proposals.size() == 2U);
    CHECK(fixture.transactions.proposals[1].state.empty());
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

TEST_CASE("resident runtime projects only the successful MVCC attempt event journal") {
    Fixture fixture {SessionScenario::events};
    fixture.transactions.conflicts_remaining = 1U;
    fixture.vm.reported_usages = {
        VmResourceUsage {.event_intents = 1U, .event_bytes = 31U},
        VmResourceUsage {.event_intents = 1U, .event_bytes = 31U},
    };
    ResidentRuntime runtime {fixture.vm_driver, fixture.ports(), fixture.control, fixture.transactions};

    const auto result = runtime.evaluate(evaluation_request());

    REQUIRE(result.has_value());
    REQUIRE(result->committed());
    CHECK(result->attempts == 2U);
    CHECK(fixture.vm.starts == 2U);
    CHECK(fixture.vm.invocations[1].budget.normal.event_intents == balanced_v1.normal.event_intents - 1U);
    CHECK(fixture.vm.invocations[1].budget.normal.event_bytes == balanced_v1.normal.event_bytes - 31U);
    CHECK(result->resource_usage.event_intents == 2U);
    CHECK(result->resource_usage.event_bytes == 62U);
    REQUIRE(fixture.transactions.proposals.size() == 2U);
    REQUIRE(fixture.transactions.proposals[0].emitted_events.size() == 1U);
    REQUIRE(fixture.transactions.proposals[1].emitted_events.size() == 1U);
    CHECK(fixture.transactions.proposals[0].emitted_events.front().id ==
          fixture.transactions.proposals[1].emitted_events.front().id);
    CHECK(fixture.transactions.proposals[1].emitted_events.front().causation == EventId {"event-1"});
    CHECK(fixture.transactions.proposals[1].emitted_events.front().schema == SchemaId {"custom.alert/v1"});
    REQUIRE(result->transaction.has_value());
    REQUIRE(result->transaction->emitted_events.size() == 1U);
    CHECK(result->transaction->emitted_events.front() ==
          EventId {deterministic_event_intent_id(EventId {"event-1"}, InvocationId {"invocation-1"}, 1U).value});
    CHECK(fixture.providers.fact_dispatches == 0U);
    CHECK(fixture.capabilities.dispatches == 0U);
    CHECK(fixture.history.dispatches == 0U);
    CHECK(fixture.engine_provider.fact_dispatches == 0U);
}

TEST_CASE("resident event replay remains dispatch-free and never commits") {
    Fixture fixture {SessionScenario::events};
    ResidentRuntime runtime {fixture.vm_driver, fixture.ports(), fixture.control, fixture.transactions};
    auto request = evaluation_request();
    request.mode = ExecutionMode::replay;

    const auto replayed = runtime.evaluate(std::move(request));

    REQUIRE(replayed.has_value());
    CHECK_FALSE(replayed->committed());
    REQUIRE(replayed->candidate.has_value());
    REQUIRE(replayed->candidate->emitted_events.size() == 1U);
    CHECK(fixture.transactions.commits == 0U);
    CHECK(fixture.providers.fact_dispatches == 0U);
    CHECK(fixture.capabilities.dispatches == 0U);
    CHECK(fixture.history.dispatches == 0U);
    CHECK(fixture.engine_provider.fact_dispatches == 0U);
}

TEST_CASE("resident runtime rejects malformed VM event intents before store commit") {
    Fixture fixture {SessionScenario::malformed_events};
    ResidentRuntime runtime {fixture.vm_driver, fixture.ports(), fixture.control, fixture.transactions};

    const auto rejected = runtime.evaluate(evaluation_request());

    REQUIRE_FALSE(rejected.has_value());
    CHECK(rejected.error().code == ResidentRuntimeErrorCode::event_projection_failure);
    CHECK(fixture.transactions.commits == 0U);
    CHECK(fixture.transactions.proposals.empty());
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

    auto wrong_schema = provider_result(work);
    wrong_schema.facts.front().returned_schema->canonical_hash = "sha256:wrong-revision";
    const auto schema_rejected = port->admit(wrong_schema);
    REQUIRE_FALSE(schema_rejected.has_value());
    CHECK(schema_rejected.error().code == protocol_v2::ProtocolErrorCode::provider_violation);

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
