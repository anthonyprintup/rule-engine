#include "rule_engine/python/engine.hpp"

#include <catch2/catch_test_macros.hpp>

#include <memory>
#include <optional>
#include <utility>
#include <vector>

namespace {

    using namespace rule_engine::python;

    SourceSpan source_span() { return SourceSpan {.source = SourceId {"rules.py"}, .begin_byte = 0, .end_byte = 8}; }

    SubjectKey subject() {
        return SubjectKey {.peer = PeerId {"peer-1"},
                           .descriptor = SchemaId {"process/v1"},
                           .identity = {{.field_id = 1, .value = std::uint64_t {42}}},
                           .parent = {}};
    }

    CompiledPack compiled_pack() {
        return CompiledPack {
            .pack = PackId {"pack"},
            .version = PackVersion {"1"},
            .source_digest = SourceDigest {"sha256:source"},
            .compiler_abi = "python-3.14.6/design-v1",
            .semantic_hash = "sha256:semantic",
            .schemas = {},
            .constants = {},
            .functions = {BytecodeFunction {
                .id = ExecutableId {"rule"},
                .qualified_name = "rule",
                .register_count = 1,
                .parameter_count = 0,
                .instructions = {{.opcode = Opcode::return_value, .destination = 0, .span = source_span()}},
            }},
            .bindings = {},
            .optimization_certificates = {},
        };
    }

    struct FakeCompiler final: PackCompiler {
        bool fail {};
        std::uint32_t calls {};

        std::expected<CompiledPack, DiagnosticSet> compile(const VerifiedRulePack &, const SchemaCatalog &,
                                                           const OperatorBindings &) override {
            ++calls;
            if (fail) {
                return std::unexpected(DiagnosticSet {Diagnostic {
                    .code = "TEST-COMPILE", .severity = DiagnosticSeverity::error, .message = "compile failed"}});
            }
            return compiled_pack();
        }
    };

    struct ScriptedSession final: VmSession {
        std::uint32_t calls {};

        [[nodiscard]] VmResourceUsage resource_usage() const noexcept override { return {}; }

        VmStep step(HostResponses) override {
            if (calls++ < 2) {
                return VmStep {
                    .state = VmStepState::waiting_for_facts,
                    .fact_requests = {FactRequest {
                        .request_id = RequestId {"fact-1"},
                        .subject = subject(),
                        .route = FactRoute {.provider = "process", .fact = "name"},
                        .expected_schema = SchemaId {"string/v1"},
                        .expected_schema_hash = "sha256:string-v1",
                        .deadline_unix_ms = 100,
                    }},
                };
            }

            const auto frozen = FrozenValue {
                .value = make_fact(true),
                .label = DataLabel {.classification = Classification::internal},
                .canonical_digest = "sha256:value",
            };
            const auto effect = EffectIntent {
                .id = IntentId {"intent-1"},
                .invocation = InvocationId {"invocation"},
                .owner = ExecutableId {"rule"},
                .binding = BindingId {"binding"},
                .sequence = 1,
                .kind = "audit",
                .payload = frozen,
                .span = source_span(),
                .policy = EffectPolicySnapshot {.policy_id = "policy", .policy_digest = "sha256:policy"},
                .disposition = EffectDisposition::committed,
                .idempotency_key = "idempotency-1",
            };
            return VmStep {
                .state = VmStepState::complete,
                .result =
                    EvaluationResult {
                        .outcome = EvaluationOutcome::match,
                        .verdict = true,
                        .committed_effects = {effect},
                    },
            };
        }
    };

    struct FakeVmFactory final: VmFactory {
        std::expected<std::unique_ptr<VmSession>, DiagnosticSet> start(const CompiledPack &,
                                                                       const VmInvocation &) override {
            return std::unique_ptr<VmSession> {std::make_unique<ScriptedSession>()};
        }
    };

    struct FakeProvider final: IProviderDispatcher {
        std::vector<FactRequest> facts;
        std::vector<ScanRequest> scans;
        std::vector<RequestId> canceled;

        void request_facts(std::vector<FactRequest> requests) override {
            facts.insert(facts.end(), requests.begin(), requests.end());
        }
        void request_scans(std::vector<ScanRequest> requests) override {
            scans.insert(scans.end(), requests.begin(), requests.end());
        }
        void cancel(std::vector<RequestId> requests) override {
            canceled.insert(canceled.end(), requests.begin(), requests.end());
        }
    };

    struct FakeStore final: IRuntimeStore {
        std::optional<RuntimeTransaction> transaction;
        std::optional<StoreError> failure;

        std::expected<TransactionReceipt, StoreError> transact_event(const RuntimeTransaction &value) override {
            if (failure.has_value()) {
                return std::unexpected(*failure);
            }
            transaction = value;
            return TransactionReceipt {
                .input = value.input.id,
                .committed_cursor = value.cursor.new_position,
                .emitted_events = {},
                .outbox_intents = {IntentId {"intent-1"}},
            };
        }
    };

    VerifiedRulePack verified_pack() {
        return VerifiedRulePack {
            .manifest = PackManifest {.pack = PackId {"pack"}, .version = PackVersion {"1"}},
            .sources = {},
            .trust = TrustResult {.production_authorized = true},
            .closure_digest = SourceDigest {"sha256:source"},
        };
    }

    VmInvocation invocation() {
        return VmInvocation {
            .execution = ExecutionId {"execution"},
            .invocation = InvocationId {"invocation"},
            .binding = BindingId {"binding"},
            .subject = subject(),
        };
    }

    EventEnvelope input_event() {
        return EventEnvelope {
            .id = EventId {"event-1"},
            .schema = SchemaId {"observation/v1"},
            .tenant = TenantId {"tenant"},
            .peer = PeerId {"peer-1"},
            .producer_unix_ms = 10,
            .ingest_unix_ms = 20,
            .payload = FrozenValue {.value = make_fact(true), .canonical_digest = "sha256:event"},
        };
    }

    TEST_CASE("runtime engine drives resumable evaluation and commits one atomic transaction") {
        FakeCompiler compiler;
        FakeVmFactory vm;
        FakeProvider providers;
        FakeStore store;
        RuntimeEngine engine {compiler, vm, providers, store};

        REQUIRE(engine.activate(verified_pack(), {}, {}).has_value());
        REQUIRE(compiler.calls == 1);
        auto evaluation = engine.start(invocation());
        REQUIRE(evaluation.has_value());

        const auto first = engine.advance(*evaluation, {});
        REQUIRE(first.state == VmStepState::waiting_for_facts);
        REQUIRE(providers.facts.size() == 1);

        const auto repeated = engine.advance(*evaluation, {});
        REQUIRE(repeated.state == VmStepState::waiting_for_facts);
        REQUIRE(providers.facts.size() == 1);

        const auto complete = engine.advance(*evaluation, {});
        REQUIRE(complete.state == VmStepState::complete);
        REQUIRE(evaluation->terminal_result->outcome == EvaluationOutcome::match);

        auto receipt =
            engine.commit(*evaluation, input_event(),
                          CursorAdvance {.consumer = "rules", .expected_position = 4, .new_position = 5}, {}, 9);
        REQUIRE(receipt.has_value());
        REQUIRE(store.transaction.has_value());
        REQUIRE(store.transaction->fence_token == 9);
        REQUIRE(store.transaction->journal.size() == 1);
        REQUIRE(store.transaction->outbox.size() == 1);
        REQUIRE(store.transaction->outbox.front().idempotency_key == "idempotency-1");

        const auto duplicate = engine.commit(*evaluation, input_event(), {}, {}, 9);
        REQUIRE_FALSE(duplicate.has_value());
        REQUIRE(duplicate.error().code == EngineErrorCode::already_committed);
    }

    TEST_CASE("runtime engine refuses activation diagnostics and premature commits") {
        FakeCompiler compiler;
        compiler.fail = true;
        FakeVmFactory vm;
        FakeProvider providers;
        FakeStore store;
        RuntimeEngine engine {compiler, vm, providers, store};

        const auto failed = engine.activate(verified_pack(), {}, {});
        REQUIRE_FALSE(failed.has_value());
        REQUIRE_FALSE(engine.active_pack());
        REQUIRE_FALSE(engine.start(invocation()).has_value());

        compiler.fail = false;
        REQUIRE(engine.activate(verified_pack(), {}, {}).has_value());
        auto evaluation = engine.start(invocation());
        REQUIRE(evaluation.has_value());
        const auto premature = engine.commit(*evaluation, input_event(), {}, {}, 1);
        REQUIRE_FALSE(premature.has_value());
        REQUIRE(premature.error().code == EngineErrorCode::not_terminal);
        REQUIRE_FALSE(store.transaction.has_value());
    }

    TEST_CASE("runtime engine preserves retryable store failures without marking the evaluation committed") {
        FakeCompiler compiler;
        FakeVmFactory vm;
        FakeProvider providers;
        FakeStore store;
        store.failure =
            StoreError {.code = StoreErrorCode::unavailable, .message = "store unavailable", .retryable = true};
        RuntimeEngine engine {compiler, vm, providers, store};

        REQUIRE(engine.activate(verified_pack(), {}, {}).has_value());
        auto evaluation = engine.start(invocation());
        REQUIRE(evaluation.has_value());
        static_cast<void>(engine.advance(*evaluation, {}));
        static_cast<void>(engine.advance(*evaluation, {}));
        static_cast<void>(engine.advance(*evaluation, {}));

        const auto result = engine.commit(*evaluation, input_event(), {}, {}, 1);
        REQUIRE_FALSE(result.has_value());
        REQUIRE(result.error().code == EngineErrorCode::store_failure);
        REQUIRE(result.error().store->retryable);
        REQUIRE_FALSE(evaluation->committed);
    }

} // namespace
