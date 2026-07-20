#include "rule_engine/python/compiler.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace {

    using namespace rule_engine::python;
    using namespace rule_engine::python::compiler;

    constexpr std::string_view source_name = "rules.main";

    SourceSpan span(const std::uint32_t begin = 0, const std::uint32_t end = 1) {
        return {.source = SourceId {std::string {source_name}}, .begin_byte = begin, .end_byte = end};
    }

    AstField field(std::string name, AstValue value) { return {.name = std::move(name), .value = std::move(value)}; }

    AstNode node(const AstNodeId id, std::string kind, std::vector<AstField> fields, const std::uint32_t begin = 0,
                 const std::uint32_t end = 1) {
        return {
            .id = id,
            .kind = std::move(kind),
            .span = span(begin, end),
            .fields = std::move(fields),
        };
    }

    VerifiedRulePack pack(std::string source = std::string(512, ' ')) {
        return {
            .manifest =
                {
                    .pack = PackId {"com.example.rules"},
                    .version = PackVersion {"1.0.0"},
                    .compiler_abi = "python-3.14.6/static-compiler-v1",
                    .budget_profile = "balanced.v1",
                    .entry_modules = {"rules.main"},
                    .dependency_digests = {},
                },
            .sources =
                {
                    SourceFile {
                        .id = SourceId {std::string {source_name}},
                        .module = "rules.main",
                        .utf8 = std::move(source),
                        .digest = SourceDigest {"sha256:module"},
                    },
                },
            .trust =
                {
                    .signer_key_id = "test",
                    .signature_algorithm = "Ed25519",
                    .production_authorized = true,
                },
            .closure_digest = SourceDigest {"sha256:closure"},
        };
    }

    AstEnvelope envelope(std::vector<AstNode> nodes, const AstNodeId root = 1) {
        return {
            .protocol_major = ast_envelope_protocol_major,
            .protocol_minor = ast_envelope_protocol_minor,
            .grammar_major = python_grammar_major,
            .grammar_minor = python_grammar_minor,
            .worker_runtime = "3.14.6",
            .source_digest = SourceDigest {"sha256:closure"},
            .modules = {{.name = "rules.main", .source = SourceId {std::string {source_name}}, .root = root}},
            .nodes = std::move(nodes),
        };
    }

    std::vector<std::string> diagnostic_signatures(const DiagnosticSet &diagnostics) {
        std::vector<std::string> result;
        result.reserve(diagnostics.size());
        for (const auto &diagnostic : diagnostics) {
            result.push_back(diagnostic.code + "|" + diagnostic.message + "|" +
                             (diagnostic.span ? diagnostic.span->source.value : std::string {}) + "|" +
                             std::to_string(diagnostic.span ? diagnostic.span->begin_byte : 0U));
        }
        return result;
    }

    std::vector<AstNode> constant_rule_nodes(const bool result, const bool is_async = false) {
        return {
            node(1, "Module",
                 {field("body", ast_sequence({ast_reference(2)})), field("type_ignores", ast_sequence({}))}),
            node(2, is_async ? "AsyncFunctionDef" : "FunctionDef",
                 {field("name", ast_string("constant_rule")), field("args", ast_reference(3)),
                  field("body", ast_sequence({ast_reference(8)})),
                  field("decorator_list", ast_sequence({ast_reference(4)})), field("returns", ast_reference(7))}),
            node(3, "arguments",
                 {field("posonlyargs", ast_sequence({})), field("args", ast_sequence({})), field("vararg", ast_none()),
                  field("kwonlyargs", ast_sequence({})), field("kw_defaults", ast_sequence({})),
                  field("kwarg", ast_none()), field("defaults", ast_sequence({}))}),
            node(4, "Call",
                 {field("func", ast_reference(5)), field("args", ast_sequence({ast_reference(6)})),
                  field("keywords", ast_sequence({}))}),
            node(5, "Name", {field("id", ast_string("rule"))}),
            node(6, "Constant", {field("value", ast_string("com.example.constant"))}),
            node(7, "Name", {field("id", ast_string("bool"))}),
            node(8, "Return", {field("value", ast_reference(9))}),
            node(9, "Constant", {field("value", ast_bool(result))}),
        };
    }

    std::vector<AstNode> fact_rule_nodes() {
        return {
            node(1, "Module",
                 {field("body", ast_sequence({ast_reference(2)})), field("type_ignores", ast_sequence({}))}),
            node(2, "FunctionDef",
                 {field("name", ast_string("unsigned")), field("args", ast_reference(3)),
                  field("body", ast_sequence({ast_reference(10), ast_reference(16)})),
                  field("decorator_list", ast_sequence({ast_reference(4)})), field("returns", ast_reference(7))}),
            node(3, "arguments",
                 {field("posonlyargs", ast_sequence({})), field("args", ast_sequence({ast_reference(8)})),
                  field("vararg", ast_none()), field("kwonlyargs", ast_sequence({})),
                  field("kw_defaults", ast_sequence({})), field("kwarg", ast_none()),
                  field("defaults", ast_sequence({}))}),
            node(4, "Call",
                 {field("func", ast_reference(5)), field("args", ast_sequence({ast_reference(6)})),
                  field("keywords", ast_sequence({}))}),
            node(5, "Name", {field("id", ast_string("rule"))}),
            node(6, "Constant", {field("value", ast_string("com.example.unsigned"))}),
            node(7, "Name", {field("id", ast_string("bool"))}),
            node(8, "arg", {field("arg", ast_string("process")), field("annotation", ast_reference(9))}),
            node(9, "Name", {field("id", ast_string("Process"))}),
            node(10, "If",
                 {field("test", ast_reference(11)), field("body", ast_sequence({ast_reference(14)})),
                  field("orelse", ast_sequence({}))}),
            node(11, "UnaryOp", {field("op", ast_string("Not")), field("operand", ast_reference(12))}),
            node(12, "Attribute", {field("value", ast_reference(13)), field("attr", ast_string("is_signed"))}),
            node(13, "Name", {field("id", ast_string("process"))}),
            node(14, "Return", {field("value", ast_reference(15))}),
            node(15, "Constant", {field("value", ast_bool(true))}),
            node(16, "Return", {field("value", ast_reference(17))}),
            node(17, "Constant", {field("value", ast_bool(false))}),
        };
    }

    TEST_CASE("AST envelope is bounded, versioned, and source-bound") {
        const auto rule_pack = pack();
        const auto payload = encode_ast_envelope(envelope(constant_rule_nodes(false)));
        REQUIRE(payload.has_value());

        const auto decoded = decode_ast_envelope(*payload, rule_pack);
        REQUIRE(decoded.has_value());
        REQUIRE(decoded->worker_runtime == "3.14.6");
        REQUIRE(decoded->source_digest == rule_pack.closure_digest);
        REQUIRE(decoded->nodes.size() == 9);

        const std::vector<std::byte> truncated(payload->begin(), payload->begin() + 10);
        const auto failure = decode_ast_envelope(truncated, rule_pack);
        REQUIRE_FALSE(failure.has_value());
        REQUIRE(failure.error().front().code == "PY-AST-TRUNCATED");

        auto oversized_count = *payload;
        const auto module_count_offset = ast_envelope_media_type.size() + 8U + 4U + std::string_view {"3.14.6"}.size() +
                                         4U + rule_pack.closure_digest.value.size();
        REQUIRE(module_count_offset + 4U <= oversized_count.size());
        for (std::size_t index = 0; index < 4; ++index) {
            oversized_count[module_count_offset + index] = std::byte {0xff};
        }
        const auto oversized = decode_ast_envelope(oversized_count, rule_pack);
        REQUIRE_FALSE(oversized.has_value());
        REQUIRE(oversized.error().front().code == "PY-AST-LIMIT");
    }

    TEST_CASE("UTF-8 source spans are byte offsets and never split a code point") {
        auto source = std::string {"x=\xCF\x80\n"};
        source.resize(512, ' ');
        const auto rule_pack = pack(std::move(source));
        auto value = envelope(constant_rule_nodes(false));
        value.nodes.front().span = span(2, 4);
        auto payload = encode_ast_envelope(value);
        REQUIRE(payload.has_value());
        REQUIRE(decode_ast_envelope(*payload, rule_pack).has_value());

        value.nodes.front().span = span(3, 4);
        payload = encode_ast_envelope(value);
        REQUIRE(payload.has_value());
        const auto invalid = decode_ast_envelope(*payload, rule_pack);
        REQUIRE_FALSE(invalid.has_value());
        REQUIRE(
            std::ranges::any_of(invalid.error(), [](const Diagnostic &item) { return item.code == "PY-AST-SPAN"; }));
    }

    TEST_CASE("rule source is inert data and is never executed by the compiler") {
        auto malicious = std::string {"raise RuntimeError('must never execute')\nopen('owned', 'w')\n"};
        malicious.resize(512, ' ');
        const auto rule_pack = pack(std::move(malicious));
        const auto payload = encode_ast_envelope(envelope(constant_rule_nodes(false)));
        REQUIRE(payload.has_value());

        const auto artifact = StaticCompiler {}.compile(rule_pack, *payload, {}, {});
        REQUIRE(artifact.has_value());
        REQUIRE(artifact->pack.functions.size() == 1);
        REQUIRE(artifact->pack.optimization_certificates.front().transitively_pure);
    }

    TEST_CASE("binder rejects ambient execution and reflective calls with stable diagnostics") {
        const auto nodes = std::vector<AstNode> {
            node(1, "Module",
                 {field("body", ast_sequence({ast_reference(2)})), field("type_ignores", ast_sequence({}))}),
            node(2, "Expr", {field("value", ast_reference(3))}),
            node(3, "Call",
                 {field("func", ast_reference(4)), field("args", ast_sequence({ast_reference(5)})),
                  field("keywords", ast_sequence({}))}),
            node(4, "Name", {field("id", ast_string("eval"))}),
            node(5, "Constant", {field("value", ast_string("open('owned','w')"))}),
        };
        const auto rule_pack = pack();
        const auto payload = encode_ast_envelope(envelope(nodes));
        REQUIRE(payload.has_value());

        const auto first = StaticCompiler {}.compile(rule_pack, *payload, {}, {});
        const auto second = StaticCompiler {}.compile(rule_pack, *payload, {}, {});
        REQUIRE_FALSE(first.has_value());
        REQUIRE_FALSE(second.has_value());
        REQUIRE(diagnostic_signatures(first.error()) == diagnostic_signatures(second.error()));
        REQUIRE(std::ranges::any_of(first.error(), [](const Diagnostic &item) { return item.code == "PY-DYNAMIC"; }));
        REQUIRE(std::ranges::any_of(first.error(), [](const Diagnostic &item) { return item.code == "PY-TOPLEVEL"; }));
    }

    TEST_CASE("binder rejects ambient imports and pack-local import cycles") {
        const auto compile_import = [](std::string imported) {
            const auto nodes = std::vector<AstNode> {
                node(1, "Module",
                     {field("body", ast_sequence({ast_reference(2)})), field("type_ignores", ast_sequence({}))}),
                node(2, "Import", {field("names", ast_sequence({ast_reference(3)}))}),
                node(3, "alias", {field("name", ast_string(std::move(imported))), field("asname", ast_none())}),
            };
            const auto rule_pack = pack();
            const auto payload = encode_ast_envelope(envelope(nodes));
            REQUIRE(payload.has_value());
            return StaticCompiler {}.compile(rule_pack, *payload, {}, {});
        };

        const auto ambient = compile_import("os");
        REQUIRE_FALSE(ambient.has_value());
        REQUIRE(std::ranges::any_of(ambient.error(),
                                    [](const Diagnostic &item) { return item.code == "PY-IMPORT-AMBIENT"; }));

        const auto cycle = compile_import("rules.main");
        REQUIRE_FALSE(cycle.has_value());
        REQUIRE(
            std::ranges::any_of(cycle.error(), [](const Diagnostic &item) { return item.code == "PY-IMPORT-CYCLE"; }));
    }

    TEST_CASE("reportable boundaries require annotations and generators get precise NYI diagnostics") {
        auto missing_annotation = constant_rule_nodes(false);
        const auto returns = std::ranges::find(missing_annotation[1].fields, "returns", &AstField::name);
        REQUIRE(returns != missing_annotation[1].fields.end());
        returns->value = ast_none();
        std::erase_if(missing_annotation, [](const AstNode &item) { return item.id == 7; });
        const auto annotation_payload = encode_ast_envelope(envelope(std::move(missing_annotation)));
        REQUIRE(annotation_payload.has_value());
        const auto annotation_failure = StaticCompiler {}.compile(pack(), *annotation_payload, {}, {});
        REQUIRE_FALSE(annotation_failure.has_value());
        REQUIRE(std::ranges::any_of(annotation_failure.error(),
                                    [](const Diagnostic &item) { return item.code == "PY-ANNOTATION"; }));

        auto generator = constant_rule_nodes(false);
        const auto decorators = std::ranges::find(generator[1].fields, "decorator_list", &AstField::name);
        REQUIRE(decorators != generator[1].fields.end());
        decorators->value = ast_sequence({});
        std::erase_if(generator, [](const AstNode &item) { return item.id >= 4 && item.id <= 6; });
        const auto body = std::ranges::find(generator[1].fields, "body", &AstField::name);
        REQUIRE(body != generator[1].fields.end());
        body->value = ast_sequence({ast_reference(8)});
        const auto statement = std::ranges::find(generator, AstNodeId {8}, &AstNode::id);
        REQUIRE(statement != generator.end());
        *statement = node(8, "Expr", {field("value", ast_reference(9))});
        const auto yield = std::ranges::find(generator, AstNodeId {9}, &AstNode::id);
        REQUIRE(yield != generator.end());
        *yield = node(9, "Yield", {field("value", ast_reference(10))});
        generator.push_back(node(10, "Constant", {field("value", ast_bool(true))}));
        const auto generator_payload = encode_ast_envelope(envelope(std::move(generator)));
        REQUIRE(generator_payload.has_value());
        const auto generator_failure = StaticCompiler {}.compile(pack(), *generator_payload, {}, {});
        REQUIRE_FALSE(generator_failure.has_value());
        REQUIRE(std::ranges::any_of(generator_failure.error(),
                                    [](const Diagnostic &item) { return item.code == "PY-NYI-GENERATOR-LOWERING"; }));
        REQUIRE_FALSE(std::ranges::any_of(generator_failure.error(),
                                          [](const Diagnostic &item) { return item.code == "PY-UNSUPPORTED"; }));
    }

    TEST_CASE("simple typed rule lowers to verified register bytecode and fact requirements") {
        const auto rule_pack = pack();
        const auto payload = encode_ast_envelope(envelope(fact_rule_nodes()));
        REQUIRE(payload.has_value());

        const auto artifact = StaticCompiler {}.compile(rule_pack, *payload, {}, {});
        REQUIRE(artifact.has_value());
        REQUIRE(artifact->pack.functions.size() == 1);
        const auto &function = artifact->pack.functions.front();
        REQUIRE(function.id == ExecutableId {"com.example.unsigned"});
        REQUIRE(function.parameter_count == 1);
        REQUIRE(std::ranges::any_of(function.instructions, [](const Instruction &instruction) {
            return instruction.opcode == Opcode::await_fact;
        }));
        REQUIRE(std::ranges::any_of(function.instructions, [](const Instruction &instruction) {
            return instruction.opcode == Opcode::jump_if_false;
        }));
        REQUIRE(artifact->fact_requirements.size() == 1);
        REQUIRE(artifact->fact_requirements.front().route == "process.is_signed");
        REQUIRE_FALSE(artifact->fact_requirements.front().conditional);
        REQUIRE(artifact->pack.optimization_certificates.front().logical_facts ==
                std::vector<std::string> {"process.is_signed"});
        REQUIRE(verify_compiler_output(*artifact).has_value());
    }

    TEST_CASE("if branches that both return lower without an out-of-range join jump") {
        auto nodes = constant_rule_nodes(true);
        const auto statement = std::ranges::find(nodes, AstNodeId {8}, &AstNode::id);
        REQUIRE(statement != nodes.end());
        *statement = node(8, "If",
                          {field("test", ast_reference(9)), field("body", ast_sequence({ast_reference(10)})),
                           field("orelse", ast_sequence({ast_reference(12)}))});
        const auto condition = std::ranges::find(nodes, AstNodeId {9}, &AstNode::id);
        REQUIRE(condition != nodes.end());
        *condition = node(9, "Constant", {field("value", ast_bool(true))});
        nodes.push_back(node(10, "Return", {field("value", ast_reference(11))}));
        nodes.push_back(node(11, "Constant", {field("value", ast_bool(true))}));
        nodes.push_back(node(12, "Return", {field("value", ast_reference(13))}));
        nodes.push_back(node(13, "Constant", {field("value", ast_bool(false))}));

        const auto payload = encode_ast_envelope(envelope(std::move(nodes)));
        REQUIRE(payload.has_value());
        const auto artifact = StaticCompiler {}.compile(pack(), *payload, {}, {});
        REQUIRE(artifact.has_value());
        REQUIRE(verify_compiler_output(*artifact).has_value());
    }

    TEST_CASE("compiler artifact is deterministic across envelope ordering") {
        auto ordered = constant_rule_nodes(false);
        auto reversed = ordered;
        std::ranges::reverse(reversed);
        const auto rule_pack = pack();
        const auto ordered_payload = encode_ast_envelope(envelope(std::move(ordered)));
        const auto reversed_payload = encode_ast_envelope(envelope(std::move(reversed)));
        REQUIRE(ordered_payload.has_value());
        REQUIRE(reversed_payload.has_value());
        REQUIRE(*ordered_payload == *reversed_payload);

        const auto first = StaticCompiler {}.compile(rule_pack, *ordered_payload, {}, {});
        const auto second = StaticCompiler {}.compile(rule_pack, *reversed_payload, {}, {});
        REQUIRE(first.has_value());
        REQUIRE(second.has_value());
        REQUIRE(first->canonical_form == second->canonical_form);
        REQUIRE(first->pack.semantic_hash == second->pack.semantic_hash);

        const auto true_payload = encode_ast_envelope(envelope(constant_rule_nodes(true)));
        REQUIRE(true_payload.has_value());
        const auto different = StaticCompiler {}.compile(rule_pack, *true_payload, {}, {});
        REQUIRE(different.has_value());
        REQUIRE(first->canonical_form != different->canonical_form);
        REQUIRE(first->pack.semantic_hash != different->pack.semantic_hash);
    }

    TEST_CASE("async declarations lower when simple and complex suspension is diagnosed precisely") {
        const auto rule_pack = pack();
        const auto simple_payload = encode_ast_envelope(envelope(constant_rule_nodes(true, true)));
        REQUIRE(simple_payload.has_value());
        const auto simple = StaticCompiler {}.compile(rule_pack, *simple_payload, {}, {});
        REQUIRE(simple.has_value());
        REQUIRE(simple->symbols.front().async);
        REQUIRE(simple->pack.functions.front().async);

        auto nodes = constant_rule_nodes(true, true);
        nodes.back() = node(9, "Await", {field("value", ast_reference(10))});
        nodes.push_back(node(10, "Name", {field("id", ast_string("service_call"))}));
        const auto await_payload = encode_ast_envelope(envelope(std::move(nodes)));
        REQUIRE(await_payload.has_value());
        const auto unsupported = StaticCompiler {}.compile(rule_pack, *await_payload, {}, {});
        REQUIRE_FALSE(unsupported.has_value());
        REQUIRE(std::ranges::any_of(unsupported.error(),
                                    [](const Diagnostic &item) { return item.code == "PY-NYI-ASYNC-LOWERING"; }));
        REQUIRE_FALSE(std::ranges::any_of(unsupported.error(),
                                          [](const Diagnostic &item) { return item.code == "PY-UNSUPPORTED"; }));
    }

    TEST_CASE("compiler verifier rejects malformed register operands") {
        const auto rule_pack = pack();
        const auto payload = encode_ast_envelope(envelope(constant_rule_nodes(false)));
        REQUIRE(payload.has_value());
        auto artifact = StaticCompiler {}.compile(rule_pack, *payload, {}, {});
        REQUIRE(artifact.has_value());

        auto &return_instruction = artifact->pack.functions.front().instructions.back();
        REQUIRE(return_instruction.opcode == Opcode::return_value);
        return_instruction.operand_a = artifact->pack.functions.front().register_count;
        const auto invalid = verify_compiler_output(*artifact);
        REQUIRE_FALSE(invalid.has_value());
        REQUIRE(
            std::ranges::any_of(invalid.error(), [](const Diagnostic &item) { return item.code == "PYC-OPERAND"; }));
    }

} // namespace
