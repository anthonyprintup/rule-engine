#include "rule_engine/python/cluster/store.hpp"
#include "rule_engine/python/compiler.hpp"
#include "rule_engine/python/engine.hpp"
#include "rule_engine/python/vm/register_vm.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>
#include <utility>
#include <vector>

namespace {

    using namespace rule_engine::python;
    using namespace rule_engine::python::cluster;
    using namespace rule_engine::python::compiler;
    using namespace rule_engine::python::vm;

    constexpr auto module_name = "rules.main";

    [[nodiscard]] SourceSpan span(const std::uint32_t begin = 0U, const std::uint32_t end = 1U) {
        return {.source = SourceId {module_name}, .begin_byte = begin, .end_byte = end};
    }

    [[nodiscard]] AstField field(std::string name, AstValue value) {
        return {.name = std::move(name), .value = std::move(value)};
    }

    [[nodiscard]] AstNode node(const AstNodeId id, std::string kind, std::vector<AstField> fields) {
        return {.id = id, .kind = std::move(kind), .span = span(), .fields = std::move(fields)};
    }

    [[nodiscard]] VerifiedRulePack source_pack() {
        return {
            .manifest =
                PackManifest {
                    .pack = PackId {"com.example.integration"},
                    .version = PackVersion {"1.0.0"},
                    .compiler_abi = "python-3.14.6/static-compiler-v1",
                    .budget_profile = "balanced.v1",
                    .entry_modules = {module_name},
                },
            .sources =
                {SourceFile {
                    .id = SourceId {module_name},
                    .module = module_name,
                    .utf8 = "@rule(\"com.example.constant\")\ndef constant_rule() -> bool:\n    return True\n",
                    .digest = SourceDigest {"sha256:source"},
                }},
            .trust =
                TrustResult {
                    .signer_key_id = "integration-test",
                    .signature_algorithm = "Ed25519",
                    .production_authorized = true,
                },
            .closure_digest = SourceDigest {"sha256:closure"},
        };
    }

    [[nodiscard]] AstEnvelope constant_rule_ast(const bool verdict) {
        return {
            .worker_runtime = "3.14.6",
            .source_digest = SourceDigest {"sha256:closure"},
            .modules = {{.name = module_name, .source = SourceId {module_name}, .root = 1U}},
            .nodes =
                {
                    node(1U, "Module",
                         {field("body", ast_sequence({ast_reference(2U)})),
                          field("type_ignores", ast_sequence({}))}),
                    node(2U, "FunctionDef",
                         {field("name", ast_string("constant_rule")), field("args", ast_reference(3U)),
                          field("body", ast_sequence({ast_reference(8U)})),
                          field("decorator_list", ast_sequence({ast_reference(4U)})),
                          field("returns", ast_reference(7U))}),
                    node(3U, "arguments",
                         {field("posonlyargs", ast_sequence({})), field("args", ast_sequence({})),
                          field("vararg", ast_none()), field("kwonlyargs", ast_sequence({})),
                          field("kw_defaults", ast_sequence({})), field("kwarg", ast_none()),
                          field("defaults", ast_sequence({}))}),
                    node(4U, "Call",
                         {field("func", ast_reference(5U)), field("args", ast_sequence({ast_reference(6U)})),
                          field("keywords", ast_sequence({}))}),
                    node(5U, "Name", {field("id", ast_string("rule"))}),
                    node(6U, "Constant", {field("value", ast_string("com.example.constant"))}),
                    node(7U, "Name", {field("id", ast_string("bool"))}),
                    node(8U, "Return", {field("value", ast_reference(9U))}),
                    node(9U, "Constant", {field("value", ast_bool(verdict))}),
                },
        };
    }

    struct BufferAstProvider final: AstEnvelopeProvider {
        explicit BufferAstProvider(std::vector<std::byte> value): payload {std::move(value)} {}

        std::vector<std::byte> payload;

        [[nodiscard]] std::expected<std::vector<std::byte>, DiagnosticSet>
        load(const VerifiedRulePack &) override {
            return payload;
        }
    };

    struct NoopProvider final: IProviderDispatcher {
        std::size_t fact_batches {};
        std::size_t scan_batches {};

        void request_facts(std::vector<FactRequest>) override { ++fact_batches; }
        void request_scans(std::vector<ScanRequest>) override { ++scan_batches; }
        void cancel(std::vector<RequestId>) override {}
    };

    [[nodiscard]] SubjectKey subject() {
        return {
            .peer = PeerId {"peer-1"},
            .descriptor = SchemaId {"process/v1"},
            .identity = {{.field_id = 1U, .value = std::uint64_t {42U}}},
        };
    }

    [[nodiscard]] FrozenValue frozen_bool(const bool value) {
        return {
            .value = make_fact(value),
            .label = DataLabel {.classification = Classification::internal},
            .canonical_digest = value ? "sha256:true" : "sha256:false",
        };
    }

    [[nodiscard]] EventEnvelope input_event() {
        return {
            .id = EventId {"event-1"},
            .schema = SchemaId {"observation/v1"},
            .tenant = TenantId {"tenant-1"},
            .peer = PeerId {"peer-1"},
            .subject = subject(),
            .producer_unix_ms = 10U,
            .ingest_unix_ms = 20U,
            .payload = frozen_bool(true),
        };
    }

} // namespace

TEST_CASE("static Python AST compiles, executes in the register VM, and commits atomically") {
    auto encoded = encode_ast_envelope(constant_rule_ast(true));
    REQUIRE(encoded.has_value());

    BufferAstProvider ast_provider {std::move(*encoded)};
    StaticPackCompiler compiler {ast_provider};
    RegisterVmFactory vm;
    NoopProvider providers;
    AuditTrail audit;
    InMemoryRuntimeStore store {audit};
    RuntimeEngine engine {compiler, vm, providers, store};

    const auto bindings = OperatorBindings {OperatorBinding {
        .id = BindingId {"binding-1"},
        .executable = ExecutableId {"com.example.constant"},
        .budget = balanced_v1,
    }};
    REQUIRE(engine.activate(source_pack(), {}, bindings).has_value());
    REQUIRE(engine.active_pack()->functions.size() == 1U);
    REQUIRE(engine.active_pack()->semantic_hash.starts_with("fnv1a64:"));

    auto evaluation = engine.start(VmInvocation {
        .execution = ExecutionId {"execution-1"},
        .invocation = InvocationId {"invocation-1"},
        .binding = BindingId {"binding-1"},
        .subject = subject(),
        .budget = balanced_v1,
        .deterministic_hash_seed = 7U,
    });
    REQUIRE(evaluation.has_value());

    const auto step = engine.advance(*evaluation, {});
    REQUIRE(step.state == VmStepState::complete);
    REQUIRE(step.result.has_value());
    CHECK(step.result->outcome == EvaluationOutcome::match);
    CHECK(step.result->verdict == true);
    CHECK(providers.fact_batches == 0U);
    CHECK(providers.scan_batches == 0U);

    REQUIRE(store.install_consumer_fence("peer:peer-1", 1U).has_value());
    const auto receipt = engine.commit(*evaluation, input_event(),
                                       CursorAdvance {
                                           .consumer = "peer:peer-1",
                                           .expected_position = 0U,
                                           .new_position = 1U,
                                       },
                                       {}, 1U);
    REQUIRE(receipt.has_value());
    CHECK(receipt->input == EventId {"event-1"});
    CHECK(receipt->committed_cursor == 1U);

    const auto snapshot = store.snapshot();
    REQUIRE(snapshot.results.size() == 1U);
    CHECK(snapshot.results.front().evaluation.outcome == EvaluationOutcome::match);
    CHECK(snapshot.results.front().evaluation.verdict == true);
}

TEST_CASE("the same compiled Python path preserves a false verdict") {
    auto encoded = encode_ast_envelope(constant_rule_ast(false));
    REQUIRE(encoded.has_value());

    BufferAstProvider ast_provider {std::move(*encoded)};
    StaticPackCompiler compiler {ast_provider};
    RegisterVmFactory vm;
    NoopProvider providers;
    AuditTrail audit;
    InMemoryRuntimeStore store {audit};
    RuntimeEngine engine {compiler, vm, providers, store};
    const auto bindings = OperatorBindings {OperatorBinding {
        .id = BindingId {"binding-1"},
        .executable = ExecutableId {"com.example.constant"},
        .budget = balanced_v1,
    }};

    REQUIRE(engine.activate(source_pack(), {}, bindings).has_value());
    auto evaluation = engine.start(VmInvocation {
        .execution = ExecutionId {"execution-1"},
        .invocation = InvocationId {"invocation-1"},
        .binding = BindingId {"binding-1"},
        .subject = subject(),
        .budget = balanced_v1,
        .deterministic_hash_seed = 7U,
    });
    REQUIRE(evaluation.has_value());

    const auto step = engine.advance(*evaluation, {});
    REQUIRE(step.state == VmStepState::complete);
    REQUIRE(step.result.has_value());
    CHECK(step.result->outcome == EvaluationOutcome::no_match);
    CHECK(step.result->verdict == false);
}
