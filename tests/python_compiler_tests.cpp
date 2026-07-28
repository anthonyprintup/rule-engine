#include "rule_engine/python/compiler.hpp"
#include "rule_engine/python/packaging/source_pack.hpp"
#include "rule_engine/python/vm/register_vm.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <deque>
#include <expected>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace {

    using namespace rule_engine::python;
    using namespace rule_engine::python::compiler;

    namespace packaging = rule_engine::python::packaging;
    namespace vm = rule_engine::python::vm;

#ifndef RULE_ENGINE_COMPILER_TEST_WORKER_SCRIPT
#define RULE_ENGINE_COMPILER_TEST_WORKER_SCRIPT ""
#endif

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
        const auto source_view = std::span {source.data(), source.size()};
        const auto source_digest = SourceDigest {"sha256:" + packaging::sha256_hex(std::as_bytes(source_view))};
        return {
            .manifest =
                {
                    .pack = PackId {"com.example.rules"},
                    .version = PackVersion {"1.0.0"},
                    .compiler_abi = std::string {python_static_compiler_abi_v1},
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
                        .digest = source_digest,
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

    OperatorBinding binding(std::string executable) {
        return OperatorBinding {
            .id = BindingId {"binding"},
            .executable = ExecutableId {std::move(executable)},
            .capabilities = {},
            .budget = balanced_v1,
        };
    }

    SubjectKey subject() {
        return SubjectKey {
            .peer = PeerId {"peer-1"},
            .descriptor = SchemaId {"process.v1"},
            .identity = {IdentityField {.field_id = 1U, .value = std::uint64_t {42U}}},
            .parent = {},
        };
    }

    VmInvocation invocation() {
        return VmInvocation {
            .execution = ExecutionId {"execution"},
            .invocation = InvocationId {"invocation"},
            .binding = BindingId {"binding"},
            .subject = subject(),
            .budget = balanced_v1,
            .deterministic_hash_seed = 7U,
        };
    }

    std::optional<std::string> environment_value(const char *name) {
#ifdef _WIN32
        char *raw_value {};
        std::size_t length {};
        if (_dupenv_s(&raw_value, &length, name) != 0 || raw_value == nullptr) {
            return std::nullopt;
        }
        std::string value {raw_value};
        std::free(raw_value);
        return value;
#else
        const auto *raw_value = std::getenv(name);
        return raw_value == nullptr ? std::nullopt : std::optional<std::string> {raw_value};
#endif
    }

    struct SharedRuntime {
        std::optional<packaging::PrivatePythonRuntime> runtime;
        std::filesystem::path temporary_parent;
        std::string unavailable_reason;
        std::string staging_failure;

        SharedRuntime() = default;
        SharedRuntime(const SharedRuntime &) = delete;
        SharedRuntime &operator=(const SharedRuntime &) = delete;
        SharedRuntime(SharedRuntime &&) noexcept = default;

        ~SharedRuntime() {
            if (!temporary_parent.empty()) {
                std::error_code ignored;
                std::filesystem::remove_all(temporary_parent, ignored);
            }
        }
    };

    SharedRuntime &shared_runtime() {
        static SharedRuntime state = [] {
            SharedRuntime result;
            const auto root_text = environment_value("RULE_ENGINE_TEST_PYTHON_RUNTIME_ROOT");
            const auto archive_text = environment_value("RULE_ENGINE_TEST_PYTHON_RUNTIME_ARCHIVE");
            if (!root_text || !archive_text || root_text->empty() || archive_text->empty()) {
                result.unavailable_reason = "exact CPython 3.14.6 test artifact was not configured";
                return result;
            }
            std::error_code filesystem_error;
            if (!std::filesystem::is_directory(*root_text, filesystem_error) || filesystem_error ||
                !std::filesystem::is_regular_file(*archive_text, filesystem_error) || filesystem_error) {
                result.unavailable_reason = "exact CPython 3.14.6 test artifact is absent";
                return result;
            }
            const auto temporary_root = std::filesystem::temp_directory_path(filesystem_error);
            if (filesystem_error) {
                result.unavailable_reason = "cannot resolve the test temporary directory";
                return result;
            }
            const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
            result.temporary_parent = temporary_root / ("rule-engine-python-compiler-" + std::to_string(nonce));
            if (!std::filesystem::create_directory(result.temporary_parent, filesystem_error) || filesystem_error) {
                result.unavailable_reason = "cannot create the compiler test runtime staging directory";
                result.temporary_parent.clear();
                return result;
            }
            const auto staged = packaging::stage_exact_private_runtime(packaging::PythonRuntimeStageRequest {
                .artifact_archive = *archive_text,
                .extracted_distribution = *root_text,
                .destination = result.temporary_parent / "python-3.14.6",
                .worker_script = RULE_ENGINE_COMPILER_TEST_WORKER_SCRIPT,
            });
            if (!staged) {
                result.staging_failure = staged.error().message;
                return result;
            }
            result.runtime = *staged;
            return result;
        }();
        return state;
    }

    struct QueueLauncher final: packaging::WorkerLauncher {
        std::deque<packaging::WorkerProcessResult> results;
        std::size_t calls {};

        std::expected<packaging::WorkerProcessResult, packaging::PackagingError>
        launch(const packaging::PrivatePythonRuntime &, const packaging::WorkerMode, const std::uint32_t,
               const std::span<const std::byte>, const packaging::WorkerLimits &) override {
            ++calls;
            if (results.empty()) {
                return std::unexpected(packaging::PackagingError {
                    .code = packaging::PackagingErrorCode::worker_crashed,
                    .message = "test launcher has no response",
                    .subject = std::nullopt,
                });
            }
            auto result = std::move(results.front());
            results.pop_front();
            return result;
        }
    };

    std::vector<std::byte> as_bytes(const std::string_view text) {
        const auto raw = std::as_bytes(std::span {text.data(), text.size()});
        return {raw.begin(), raw.end()};
    }

    std::string as_text(const std::span<const std::byte> bytes) {
        return {reinterpret_cast<const char *>(bytes.data()), bytes.size()};
    }

    bool replace_once(std::string &text, const std::string_view needle, const std::string_view replacement) {
        const auto position = text.find(needle);
        if (position == std::string::npos) {
            return false;
        }
        text.replace(position, needle.size(), replacement);
        return true;
    }

    std::expected<packaging::WorkerResponse, packaging::PackagingError>
    exact_worker_response(const packaging::PrivatePythonRuntime &runtime, const std::filesystem::path &temporary_root,
                          const VerifiedRulePack &rule_pack) {
        const auto &source = rule_pack.sources.front();
        packaging::WindowsJobWorkerLauncher launcher;
        launcher.temporary_root = temporary_root;
        packaging::WorkerClient client {.runtime = runtime, .launcher = launcher, .limits = {}};
        return client.invoke(packaging::WorkerRequest {
            .protocol = packaging::python_worker_protocol_v1,
            .request_id = RequestId {"compiler-json-test"},
            .mode = packaging::WorkerMode::static_parse,
            .runtime = packaging::official_windows_cpython_3146(),
            .payload =
                packaging::OpaqueWorkerPayload {
                    .schema = std::string {packaging::static_source_schema_v1},
                    .source = source.id,
                    .source_digest = source.digest,
                    .bytes = as_bytes(source.utf8),
                },
            .hash_seed = 0U,
            .generator_execution_authorized = false,
        });
    }

    std::expected<CompiledPack, DiagnosticSet> compile_exact_source(const packaging::PrivatePythonRuntime &runtime,
                                                                    const std::filesystem::path &temporary_root,
                                                                    std::string source, const std::string &executable) {
        packaging::WindowsJobWorkerLauncher launcher;
        launcher.temporary_root = temporary_root;
        packaging::WorkerClient client {.runtime = runtime, .launcher = launcher, .limits = {}};
        WorkerAstEnvelopeProvider provider {client};
        StaticPackCompiler compiler {provider};
        return compiler.compile(pack(std::move(source)), {}, OperatorBindings {binding(executable)});
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

    std::string diagnostic_text(const DiagnosticSet &diagnostics) {
        std::string result;
        for (const auto &diagnostic : diagnostics) { result += diagnostic.code + ":" + diagnostic.message + "\n"; }
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

    std::vector<AstNode> direct_fact_rule_nodes() {
        return {
            node(1, "Module",
                 {field("body", ast_sequence({ast_reference(2)})), field("type_ignores", ast_sequence({}))}),
            node(2, "FunctionDef",
                 {field("name", ast_string("unsigned")), field("args", ast_reference(3)),
                  field("body", ast_sequence({ast_reference(10)})),
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
            node(10, "Return", {field("value", ast_reference(11))}),
            node(11, "UnaryOp", {field("op", ast_reference(14)), field("operand", ast_reference(12))}),
            node(12, "Attribute", {field("value", ast_reference(13)), field("attr", ast_string("is_signed"))}),
            node(13, "Name", {field("id", ast_string("process"))}),
            node(14, "Not", {}),
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

    TEST_CASE("static pack compiler consumes the exact worker payload contract", "[compiler-vm-progress]") {
        if (!shared_runtime().runtime) {
            if (!shared_runtime().staging_failure.empty()) {
                FAIL_CHECK(shared_runtime().staging_failure);
                return;
            }
            WARN("SKIPPED: " << shared_runtime().unavailable_reason);
            return;
        }
        const auto rule_pack = pack("@rule(\"com.example.constant\")\n"
                                    "def constant_rule() -> bool:\n"
                                    "    return False\n");
        packaging::WindowsJobWorkerLauncher launcher;
        launcher.temporary_root = shared_runtime().temporary_parent;
        packaging::WorkerClient client {.runtime = *shared_runtime().runtime, .launcher = launcher, .limits = {}};
        WorkerAstEnvelopeProvider provider {client};
        StaticPackCompiler compiler {provider};

        const OperatorBindings bindings {binding("com.example.constant")};
        const auto compiled = compiler.compile(rule_pack, {}, bindings);
        INFO((compiled.has_value() ? std::string {} : diagnostic_text(compiled.error())));
        REQUIRE(compiled.has_value());
        CHECK(compiled->compiler_abi == python_static_compiler_abi_v1);
        REQUIRE(compiled->functions.size() == 1U);
        const auto &function = compiled->functions.front();
        REQUIRE(function.id == ExecutableId {"com.example.constant"});
        REQUIRE(function.instructions.size() == 2U);
        REQUIRE(function.instructions[0].opcode == Opcode::load_const);
        REQUIRE(function.instructions[1].opcode == Opcode::return_value);

        auto bounded_invocation = invocation();
        bounded_invocation.budget.normal.elapsed = std::chrono::seconds {1};
        bounded_invocation.budget.normal.instructions = function.instructions.size();
        bounded_invocation.budget.normal.loop_iterations_and_yields = 0U;
        auto session = vm::RegisterVmSession::create(*compiled, bounded_invocation);
        REQUIRE(session.has_value());
        REQUIRE((*session)->counters().instructions == 0U);
        const auto completed = (*session)->step({});
        REQUIRE(completed.state == VmStepState::complete);
        REQUIRE(completed.result.has_value());
        REQUIRE(completed.result->verdict == false);
        REQUIRE((*session)->counters().instructions == function.instructions.size());
        REQUIRE((*session)->counters().loop_iterations_and_yields == 0U);
    }

    TEST_CASE("exact worker AST JSON rejects noncanonical and adversarial envelopes deterministically") {
        auto &runtime = shared_runtime();
        if (!runtime.runtime) {
            if (!runtime.staging_failure.empty()) {
                FAIL_CHECK(runtime.staging_failure);
                return;
            }
            WARN("SKIPPED: " << runtime.unavailable_reason);
            return;
        }
        const auto rule_pack = pack("@rule(\"com.example.constant\")\n"
                                    "def constant_rule() -> bool:\n"
                                    "    return False\n");
        const auto response = exact_worker_response(*runtime.runtime, runtime.temporary_parent, rule_pack);
        REQUIRE(response.has_value());
        const auto &source = rule_pack.sources.front();
        const auto decoded =
            decode_worker_ast_json(response->payload.bytes, rule_pack, source, response->payload.source_digest);
        INFO((decoded.has_value() ? std::string {} : diagnostic_text(decoded.error())));
        REQUIRE(decoded.has_value());

        const auto canonical = as_text(response->payload.bytes);
        const auto reject = [&](const std::string_view name, std::string mutated, const std::string_view code) {
            INFO(name);
            const auto result = decode_worker_ast_json(as_bytes(mutated), rule_pack, source, source.digest);
            REQUIRE_FALSE(result.has_value());
            REQUIRE(result.error().front().code == code);
        };

        auto wrong_schema = canonical;
        REQUIRE(replace_once(wrong_schema, "\"schema\":\"rule-engine.ast/1\"", "\"schema\":\"rule-engine.ast/2\""));
        reject("wrong schema", std::move(wrong_schema), "PY-AST-VERSION");

        auto duplicate_top_level = canonical;
        REQUIRE(replace_once(duplicate_top_level, "\"format\":1", "\"format\":1,\"format\":1"));
        reject("duplicate top-level field", std::move(duplicate_top_level), "PY-AST-JSON-FIELD");

        auto out_of_order = canonical;
        REQUIRE(replace_once(out_of_order, "\"format\":1,\"schema\":\"rule-engine.ast/1\"",
                             "\"schema\":\"rule-engine.ast/1\",\"format\":1"));
        reject("out-of-order top-level field", std::move(out_of_order), "PY-AST-JSON-FIELD");

        auto unknown_node_field = canonical;
        REQUIRE(replace_once(unknown_node_field, "\"fields\":{\"body\":", "\"fields\":{\"unexpected\":null,\"body\":"));
        reject("unknown node field", std::move(unknown_node_field), "PY-AST-JSON-FIELD");

        auto duplicate_node_field = canonical;
        REQUIRE(replace_once(duplicate_node_field, "\"fields\":{\"body\":", "\"fields\":{\"body\":null,\"body\":"));
        reject("duplicate node field", std::move(duplicate_node_field), "PY-AST-JSON-FIELD");

        auto oversized_name = canonical;
        const auto long_field = "\"fields\":{\"" + std::string(129U, 'x') + "\":null,";
        REQUIRE(replace_once(oversized_name, "\"fields\":{", long_field));
        reject("oversized field name", std::move(oversized_name), "PY-AST-LIMIT");

        auto excessive_depth = canonical;
        const auto nested = "\"type_ignores\":" + std::string(maximum_ast_depth + 8U, '[') + "null" +
                            std::string(maximum_ast_depth + 8U, ']');
        REQUIRE(replace_once(excessive_depth, "\"type_ignores\":[]", nested));
        reject("excessive nesting", std::move(excessive_depth), "PY-AST-DEPTH");

        auto huge_span_number = canonical;
        REQUIRE(
            replace_once(huge_span_number, "\"col\":0", "\"col\":999999999999999999999999999999999999999999999999"));
        reject("overflowing span number", std::move(huge_span_number), "PY-AST-LIMIT");

        auto huge_token_number = canonical;
        REQUIRE(replace_once(huge_token_number, "\"end\":[0,0]",
                             "\"end\":[999999999999999999999999999999999999999999999999,0]"));
        reject("overflowing token number", std::move(huge_token_number), "PY-AST-LIMIT");

        auto invalid_base64 = canonical;
        const auto base64 = invalid_base64.find("\"wtf8_base64\":\"");
        REQUIRE(base64 != std::string::npos);
        const auto value_begin = base64 + std::string_view {"\"wtf8_base64\":\""}.size();
        REQUIRE(value_begin < invalid_base64.size());
        invalid_base64[value_begin] = '*';
        reject("invalid tagged string", std::move(invalid_base64), "PY-AST-JSON");

        auto invalid_wtf8 = canonical;
        const auto wtf8 = invalid_wtf8.find("\"wtf8_base64\":\"");
        REQUIRE(wtf8 != std::string::npos);
        const auto wtf8_begin = wtf8 + std::string_view {"\"wtf8_base64\":\""}.size();
        const auto wtf8_end = invalid_wtf8.find('"', wtf8_begin);
        REQUIRE(wtf8_end != std::string::npos);
        invalid_wtf8.replace(wtf8_begin, wtf8_end - wtf8_begin, "_w");
        reject("invalid WTF-8 string", std::move(invalid_wtf8), "PY-AST-STRING");

        auto wrong_worker = canonical;
        REQUIRE(replace_once(wrong_worker, "\"unicode\":\"16.0.0\"", "\"unicode\":\"15.1.0\""));
        reject("wrong worker identity", std::move(wrong_worker), "PY-AST-RUNTIME");

        auto truncated = canonical;
        truncated.pop_back();
        reject("truncated envelope", std::move(truncated), "PY-AST-JSON");

        const auto digest_mismatch =
            decode_worker_ast_json(response->payload.bytes, rule_pack, source, SourceDigest {"sha256:mismatch"});
        REQUIRE_FALSE(digest_mismatch.has_value());
        REQUIRE(digest_mismatch.error().front().code == "PY-AST-SOURCE");

        const std::vector<std::byte> oversized(maximum_ast_payload_bytes + 1U);
        const auto oversized_result = decode_worker_ast_json(oversized, rule_pack, source, source.digest);
        REQUIRE_FALSE(oversized_result.has_value());
        REQUIRE(oversized_result.error().front().code == "PY-AST-LIMIT");
    }

    TEST_CASE("exact worker fact rule compiles and resumes through the register VM") {
        auto &runtime = shared_runtime();
        if (!runtime.runtime) {
            if (!runtime.staging_failure.empty()) {
                FAIL_CHECK(runtime.staging_failure);
                return;
            }
            WARN("SKIPPED: " << runtime.unavailable_reason);
            return;
        }
        const auto rule_pack = pack("from rule_engine import Model, provider_fact, rule\n"
                                    "\n"
                                    "class Process(Model):\n"
                                    "    is_signed: bool = provider_fact(route=\"process.is_signed\")\n"
                                    "\n"
                                    "@rule(\"com.example.unsigned\")\n"
                                    "def unsigned(process: Process) -> bool:\n"
                                    "    return not process.is_signed\n");
        packaging::WindowsJobWorkerLauncher launcher;
        launcher.temporary_root = runtime.temporary_parent;
        packaging::WorkerClient client {.runtime = *runtime.runtime, .launcher = launcher, .limits = {}};
        WorkerAstEnvelopeProvider provider {client};
        StaticPackCompiler compiler {provider};

        const OperatorBindings bindings {binding("com.example.unsigned")};
        const auto compiled = compiler.compile(rule_pack, {}, bindings);
        INFO((compiled.has_value() ? std::string {} : diagnostic_text(compiled.error())));
        REQUIRE(compiled.has_value());
        REQUIRE(compiled->functions.size() == 1U);
        const auto &function = compiled->functions.front();
        REQUIRE(function.parameter_count == 1U);
        REQUIRE(function.register_count == 3U);
        REQUIRE(function.instructions.size() == 3U);
        CHECK(function.instructions[0].opcode == Opcode::await_fact);
        CHECK(function.instructions[0].destination == 1U);
        CHECK(function.instructions[0].operand_a == 0U);
        CHECK(function.instructions[0].immediate == 0U);
        CHECK(function.instructions[1].opcode == Opcode::unary_op);
        CHECK(function.instructions[1].destination == 2U);
        CHECK(function.instructions[1].operand_a == 1U);
        CHECK(function.instructions[1].immediate == 0U);
        CHECK(function.instructions[2].opcode == Opcode::return_value);
        CHECK(function.instructions[2].destination == 2U);
        CHECK(function.instructions[2].operand_a == 2U);

        auto session = vm::RegisterVmSession::create(*compiled, invocation());
        REQUIRE(session.has_value());
        const auto waiting = (*session)->step({});
        REQUIRE(waiting.state == VmStepState::waiting_for_facts);
        REQUIRE(waiting.fact_requests.size() == 1U);
        const auto still_waiting = (*session)->step({});
        REQUIRE(still_waiting.state == VmStepState::waiting_for_facts);
        REQUIRE(still_waiting.fact_requests.empty());

        HostResponses response;
        response.facts.push_back(FactResponse {
            .request_id = waiting.fact_requests.front().request_id,
            .subject = waiting.fact_requests.front().subject,
            .status = FactTerminalStatus::value,
            .value = make_fact(false),
            .returned_schema = SchemaIdentity {.id = waiting.fact_requests.front().expected_schema,
                                               .canonical_hash = waiting.fact_requests.front().expected_schema_hash},
            .diagnostic = std::nullopt,
        });
        const auto completed = (*session)->step(std::move(response));
        REQUIRE(completed.state == VmStepState::complete);
        REQUIRE(completed.result.has_value());
        REQUIRE(completed.result->verdict == true);
    }

    TEST_CASE("exact worker lowers fresh container displays and subscription mutation into verified bytecode",
              "[compiler-vm-progress]") {
        auto &runtime = shared_runtime();
        if (!runtime.runtime) {
            if (!runtime.staging_failure.empty()) {
                FAIL_CHECK(runtime.staging_failure);
                return;
            }
            WARN("SKIPPED: " << runtime.unavailable_reason);
            return;
        }
        const auto compiled = compile_exact_source(*runtime.runtime, runtime.temporary_parent,
                                                   "from rule_engine import rule\n"
                                                   "\n"
                                                   "@rule(\"com.example.containers\")\n"
                                                   "def containers() -> bool:\n"
                                                   "    values = [1, 2]\n"
                                                   "    values[0] = values[1]\n"
                                                   "    pair = (values[0], 3)\n"
                                                   "    mapping = {\"answer\": pair[0]}\n"
                                                   "    return mapping[\"answer\"] == 2\n",
                                                   "com.example.containers");
        INFO((compiled.has_value() ? std::string {} : diagnostic_text(compiled.error())));
        REQUIRE(compiled.has_value());
        REQUIRE(compiled->functions.size() == 1U);
        const auto &function = compiled->functions.front();
        const auto has_opcode = [&](const Opcode opcode) {
            return std::ranges::any_of(function.instructions,
                                       [&](const Instruction &instruction) { return instruction.opcode == opcode; });
        };
        CHECK(has_opcode(Opcode::build_list));
        CHECK(has_opcode(Opcode::build_tuple));
        CHECK(has_opcode(Opcode::build_dict));
        CHECK(has_opcode(Opcode::load_subscript));
        CHECK(has_opcode(Opcode::store_subscript));
        REQUIRE(verify_bytecode(*compiled).has_value());

        for (const auto &instruction : function.instructions) {
            if (instruction.opcode == Opcode::build_list || instruction.opcode == Opcode::build_tuple) {
                CHECK(instruction.operand_a <= function.register_count);
                CHECK(instruction.operand_b <= function.register_count - instruction.operand_a);
            }
            if (instruction.opcode == Opcode::build_dict) {
                CHECK(instruction.operand_a <= function.register_count);
                CHECK(instruction.operand_b <= (function.register_count - instruction.operand_a) / 2U);
            }
        }

        auto session = vm::RegisterVmSession::create(*compiled, invocation());
        REQUIRE(session.has_value());
        const auto completed = (*session)->step({});
        REQUIRE(completed.state == VmStepState::complete);
        REQUIRE(completed.result.has_value());
        CHECK(completed.result->verdict == true);

        const auto first_build = std::ranges::find(function.instructions, Opcode::build_list, &Instruction::opcode);
        REQUIRE(first_build != function.instructions.end());
        auto bounded = invocation();
        bounded.budget.normal.instructions =
            static_cast<std::uint64_t>(std::distance(function.instructions.begin(), first_build)) + 1U;
        auto budgeted = vm::RegisterVmSession::create(*compiled, bounded);
        REQUIRE(budgeted.has_value());
        const auto heap_before = (*budgeted)->heap_stats();
        const auto faulted = (*budgeted)->step({});
        REQUIRE(faulted.state == VmStepState::faulted);
        REQUIRE(faulted.result.has_value());
        REQUIRE(faulted.result->fault.has_value());
        CHECK(faulted.result->fault->frames.front().code == "PYVM4003");
        CHECK((*budgeted)->counters().instructions == bounded.budget.normal.instructions);
        CHECK((*budgeted)->heap_stats().live_objects == heap_before.live_objects);
        CHECK((*budgeted)->heap_stats().live_bytes == heap_before.live_bytes);

        auto malformed = *compiled;
        const auto malformed_build =
            std::ranges::find(malformed.functions.front().instructions, Opcode::build_list, &Instruction::opcode);
        REQUIRE(malformed_build != malformed.functions.front().instructions.end());
        malformed_build->operand_a = malformed.functions.front().register_count;
        malformed_build->operand_b = 1U;
        CHECK_FALSE(verify_bytecode(malformed).has_value());
    }

    TEST_CASE("exact worker lowers deterministic for else break and continue with charged iterator edges",
              "[compiler-vm-progress]") {
        auto &runtime = shared_runtime();
        if (!runtime.runtime) {
            if (!runtime.staging_failure.empty()) {
                FAIL_CHECK(runtime.staging_failure);
                return;
            }
            WARN("SKIPPED: " << runtime.unavailable_reason);
            return;
        }
        const auto compiled = compile_exact_source(*runtime.runtime, runtime.temporary_parent,
                                                   "from rule_engine import rule\n"
                                                   "\n"
                                                   "@rule(\"com.example.loops\")\n"
                                                   "def loops() -> bool:\n"
                                                   "    total = 0\n"
                                                   "    for value in [1, 2, 3]:\n"
                                                   "        if value == 2:\n"
                                                   "            continue\n"
                                                   "        total = total + value\n"
                                                   "    else:\n"
                                                   "        total = total + 10\n"
                                                   "    for value in []:\n"
                                                   "        total = 0\n"
                                                   "    else:\n"
                                                   "        total = total + 1\n"
                                                   "    for value in {\"x\": 1, \"y\": 2}:\n"
                                                   "        if value == \"x\":\n"
                                                   "            total = total + 4\n"
                                                   "            break\n"
                                                   "    else:\n"
                                                   "        total = 0\n"
                                                   "    return total == 19\n",
                                                   "com.example.loops");
        INFO((compiled.has_value() ? std::string {} : diagnostic_text(compiled.error())));
        REQUIRE(compiled.has_value());
        REQUIRE(compiled->functions.size() == 1U);
        const auto &function = compiled->functions.front();
        CHECK(std::ranges::count(function.instructions, Opcode::get_iter, &Instruction::opcode) == 3);
        CHECK(std::ranges::count(function.instructions, Opcode::iter_next, &Instruction::opcode) == 3);
        REQUIRE(verify_bytecode(*compiled).has_value());
        for (const auto &instruction : function.instructions) {
            if (instruction.opcode == Opcode::iter_next) {
                CHECK(instruction.immediate < function.instructions.size());
            }
        }

        auto session = vm::RegisterVmSession::create(*compiled, invocation());
        REQUIRE(session.has_value());
        const auto completed = (*session)->step({});
        REQUIRE(completed.state == VmStepState::complete);
        REQUIRE(completed.result.has_value());
        CHECK(completed.result->verdict == true);
        CHECK((*session)->counters().loop_iterations_and_yields == 4U);

        auto bounded = invocation();
        bounded.budget.normal.loop_iterations_and_yields = 3U;
        auto budgeted = vm::RegisterVmSession::create(*compiled, bounded);
        REQUIRE(budgeted.has_value());
        const auto faulted = (*budgeted)->step({});
        REQUIRE(faulted.state == VmStepState::faulted);
        REQUIRE(faulted.result.has_value());
        REQUIRE(faulted.result->fault.has_value());
        CHECK(faulted.result->fault->frames.front().code == "PYVM4006");
        CHECK((*budgeted)->counters().loop_iterations_and_yields == 3U);

        auto malformed = *compiled;
        const auto malformed_next =
            std::ranges::find(malformed.functions.front().instructions, Opcode::iter_next, &Instruction::opcode);
        REQUIRE(malformed_next != malformed.functions.front().instructions.end());
        malformed_next->immediate = static_cast<std::uint32_t>(malformed.functions.front().instructions.size());
        CHECK_FALSE(verify_bytecode(malformed).has_value());
    }

    TEST_CASE("exact worker dictionary lowering faults before evaluating a later entry") {
        auto &runtime = shared_runtime();
        if (!runtime.runtime) {
            if (!runtime.staging_failure.empty()) {
                FAIL_CHECK(runtime.staging_failure);
                return;
            }
            WARN("SKIPPED: " << runtime.unavailable_reason);
            return;
        }
        const auto compiled = compile_exact_source(*runtime.runtime, runtime.temporary_parent,
                                                   "from rule_engine import rule\n"
                                                   "\n"
                                                   "def later_entry() -> int:\n"
                                                   "    raise ValueError(\"later dictionary entry was evaluated\")\n"
                                                   "\n"
                                                   "@rule(\"com.example.dict-fault-order\")\n"
                                                   "def dictionary_fault_order() -> bool:\n"
                                                   "    mapping = {[]: True, later_entry(): True}\n"
                                                   "    return False\n",
                                                   "com.example.dict-fault-order");
        INFO((compiled.has_value() ? std::string {} : diagnostic_text(compiled.error())));
        REQUIRE(compiled.has_value());
        auto session = vm::RegisterVmSession::create(*compiled, invocation());
        REQUIRE(session.has_value());
        const auto faulted = (*session)->step({});
        REQUIRE(faulted.state == VmStepState::faulted);
        REQUIRE(faulted.result.has_value());
        REQUIRE(faulted.result->fault.has_value());
        REQUIRE_FALSE(faulted.result->fault->frames.empty());
        CHECK(faulted.result->fault->frames.front().code == "PYVM2001");
        CHECK(faulted.result->fault->frames.front().message.find("unhashable map key") != std::string::npos);
        CHECK(faulted.result->fault->frames.front().message.find("later dictionary entry") == std::string::npos);
    }

    TEST_CASE("exact worker lowers ordered typed handlers else and bare re-raise into the verified VM",
              "[compiler-vm-progress]") {
        auto &runtime = shared_runtime();
        if (!runtime.runtime) {
            if (!runtime.staging_failure.empty()) {
                FAIL_CHECK(runtime.staging_failure);
                return;
            }
            WARN("SKIPPED: " << runtime.unavailable_reason);
            return;
        }

        const auto compiled = compile_exact_source(*runtime.runtime, runtime.temporary_parent,
                                                   "from rule_engine import rule\n"
                                                   "\n"
                                                   "def reraised() -> bool:\n"
                                                   "    try:\n"
                                                   "        try:\n"
                                                   "            raise TypeError(\"inner\")\n"
                                                   "        except ValueError:\n"
                                                   "            return False\n"
                                                   "        except TypeError:\n"
                                                   "            raise\n"
                                                   "    except TypeError:\n"
                                                   "        return True\n"
                                                   "    except Exception:\n"
                                                   "        return False\n"
                                                   "\n"
                                                   "@rule(\"com.example.exceptions\")\n"
                                                   "def exception_regions() -> bool:\n"
                                                   "    else_ran = False\n"
                                                   "    try:\n"
                                                   "        probe = [1]\n"
                                                   "    except ArithmeticError:\n"
                                                   "        return False\n"
                                                   "    else:\n"
                                                   "        else_ran = True\n"
                                                   "    try:\n"
                                                   "        quotient = 1 // 0\n"
                                                   "    except ValueError:\n"
                                                   "        return False\n"
                                                   "    except ArithmeticError:\n"
                                                   "        return else_ran and reraised()\n"
                                                   "    except Exception:\n"
                                                   "        return False\n"
                                                   "    return False\n",
                                                   "com.example.exceptions");
        INFO((compiled.has_value() ? std::string {} : diagnostic_text(compiled.error())));
        REQUIRE(compiled.has_value());
        REQUIRE(verify_bytecode(*compiled).has_value());

        const auto entry_position =
            std::ranges::find(compiled->functions, ExecutableId {"com.example.exceptions"}, &BytecodeFunction::id);
        REQUIRE(entry_position != compiled->functions.end());
        const auto &entry = *entry_position;
        CHECK(std::ranges::count(entry.instructions, Opcode::match_exception, &Instruction::opcode) == 4);
        CHECK(std::ranges::count(entry.instructions, Opcode::leave_except, &Instruction::opcode) >= 1);
        CHECK(std::ranges::count(entry.instructions, Opcode::reraise, &Instruction::opcode) >= 2);
        CHECK(entry.exception_regions.size() == 2U);

        auto session = vm::RegisterVmSession::create(*compiled, invocation());
        REQUIRE(session.has_value());
        auto completed = (*session)->step({});
        while (completed.state == VmStepState::yielded) { completed = (*session)->step({}); }
        REQUIRE(completed.state == VmStepState::complete);
        REQUIRE(completed.result.has_value());
        CHECK(completed.result->verdict == true);
    }

    TEST_CASE("exact worker lowers nested finally and loop control through verified cleanup regions",
              "[compiler-vm-progress]") {
        auto &runtime = shared_runtime();
        if (!runtime.runtime) {
            if (!runtime.staging_failure.empty()) {
                FAIL_CHECK(runtime.staging_failure);
                return;
            }
            WARN("SKIPPED: " << runtime.unavailable_reason);
            return;
        }

        const auto compiled = compile_exact_source(*runtime.runtime, runtime.temporary_parent,
                                                   "from rule_engine import rule\n"
                                                   "\n"
                                                   "def replacement() -> bool:\n"
                                                   "    try:\n"
                                                   "        try:\n"
                                                   "            return False\n"
                                                   "        finally:\n"
                                                   "            raise ValueError(\"replacement\")\n"
                                                   "    except ValueError:\n"
                                                   "        return True\n"
                                                   "    return False\n"
                                                   "\n"
                                                   "@rule(\"com.example.finally\")\n"
                                                   "def finalizers() -> bool:\n"
                                                   "    total = 0\n"
                                                   "    try:\n"
                                                   "        try:\n"
                                                   "            total = total + 1\n"
                                                   "        finally:\n"
                                                   "            total = total + 10\n"
                                                   "    finally:\n"
                                                   "        total = total + 100\n"
                                                   "    for value in [1, 2, 3]:\n"
                                                   "        try:\n"
                                                   "            total = total + value\n"
                                                   "            if value == 1:\n"
                                                   "                continue\n"
                                                   "            if value == 2:\n"
                                                   "                break\n"
                                                   "        finally:\n"
                                                   "            total = total + 10\n"
                                                   "    else:\n"
                                                   "        total = 0\n"
                                                   "    return total == 134 and replacement()\n",
                                                   "com.example.finally");
        INFO((compiled.has_value() ? std::string {} : diagnostic_text(compiled.error())));
        REQUIRE(compiled.has_value());
        REQUIRE(verify_bytecode(*compiled).has_value());

        const auto entry_position =
            std::ranges::find(compiled->functions, ExecutableId {"com.example.finally"}, &BytecodeFunction::id);
        REQUIRE(entry_position != compiled->functions.end());
        const auto &entry = *entry_position;
        CHECK(std::ranges::count(entry.exception_regions, ExceptionRegionKind::cleanup, &ExceptionRegion::kind) == 3);
        CHECK(std::ranges::count(entry.instructions, Opcode::unwind_jump, &Instruction::opcode) >= 4);
        CHECK(std::ranges::count(entry.instructions, Opcode::leave_try, &Instruction::opcode) >= 3);

        auto session = vm::RegisterVmSession::create(*compiled, invocation());
        REQUIRE(session.has_value());
        auto completed = (*session)->step({});
        while (completed.state == VmStepState::yielded) { completed = (*session)->step({}); }
        REQUIRE(completed.state == VmStepState::complete);
        REQUIRE(completed.result.has_value());
        CHECK(completed.result->verdict == true);

        SECTION("ordinary edge cannot bypass source-produced cleanup") {
            auto malformed = *compiled;
            auto malformed_entry =
                std::ranges::find(malformed.functions, ExecutableId {"com.example.finally"}, &BytecodeFunction::id);
            REQUIRE(malformed_entry != malformed.functions.end());
            auto escaping = malformed_entry->instructions.end();
            for (const auto &region : malformed_entry->exception_regions) {
                if (region.kind != ExceptionRegionKind::cleanup) {
                    continue;
                }
                escaping = std::ranges::find_if(malformed_entry->instructions.begin() + region.begin_instruction,
                                                malformed_entry->instructions.begin() + region.end_instruction,
                                                [&](const Instruction &instruction) {
                                                    return instruction.opcode == Opcode::unwind_jump &&
                                                           (instruction.immediate < region.begin_instruction ||
                                                            instruction.immediate >= region.end_instruction);
                                                });
                if (escaping != malformed_entry->instructions.begin() + region.end_instruction) {
                    break;
                }
                escaping = malformed_entry->instructions.end();
            }
            REQUIRE(escaping != malformed_entry->instructions.end());
            escaping->opcode = Opcode::jump;
            const auto rejected = verify_bytecode(malformed);
            REQUIRE_FALSE(rejected.has_value());
            CHECK(std::ranges::any_of(rejected.error(), [](const Diagnostic &item) { return item.code == "PYC0114"; }));
        }

        SECTION("source-produced filter chain cannot be cycled") {
            auto malformed = *compiled;
            auto filter = std::ranges::find_if(malformed.functions, [](const BytecodeFunction &candidate) {
                return std::ranges::any_of(candidate.instructions, [](const Instruction &instruction) {
                    return instruction.opcode == Opcode::match_exception;
                });
            });
            REQUIRE(filter != malformed.functions.end());
            const auto match = std::ranges::find(filter->instructions, Opcode::match_exception, &Instruction::opcode);
            REQUIRE(match != filter->instructions.end());
            match->operand_b = static_cast<std::uint32_t>(match - filter->instructions.begin());
            const auto rejected = verify_bytecode(malformed);
            REQUIRE_FALSE(rejected.has_value());
            CHECK(std::ranges::any_of(rejected.error(), [](const Diagnostic &item) { return item.code == "PYC0112"; }));
        }
    }

    TEST_CASE("exact worker routes implicit engine faults to their closed typed handlers") {
        auto &runtime = shared_runtime();
        if (!runtime.runtime) {
            if (!runtime.staging_failure.empty()) {
                FAIL_CHECK(runtime.staging_failure);
                return;
            }
            WARN("SKIPPED: " << runtime.unavailable_reason);
            return;
        }

        const auto compiled = compile_exact_source(*runtime.runtime, runtime.temporary_parent,
                                                   "from rule_engine import rule\n"
                                                   "\n"
                                                   "@rule(\"com.example.implicit-faults\")\n"
                                                   "def implicit_faults() -> bool:\n"
                                                   "    caught = 0\n"
                                                   "    try:\n"
                                                   "        missing = [1][9]\n"
                                                   "    except ValueError:\n"
                                                   "        caught = caught + 1\n"
                                                   "    except Exception:\n"
                                                   "        return False\n"
                                                   "    try:\n"
                                                   "        invalid = {[]: True}\n"
                                                   "    except TypeError:\n"
                                                   "        caught = caught + 1\n"
                                                   "    except Exception:\n"
                                                   "        return False\n"
                                                   "    try:\n"
                                                   "        quotient = 1 // 0\n"
                                                   "    except ArithmeticError:\n"
                                                   "        caught = caught + 1\n"
                                                   "    except Exception:\n"
                                                   "        return False\n"
                                                   "    finally:\n"
                                                   "        caught = caught + 10\n"
                                                   "    return caught == 13\n",
                                                   "com.example.implicit-faults");
        INFO((compiled.has_value() ? std::string {} : diagnostic_text(compiled.error())));
        REQUIRE(compiled.has_value());
        REQUIRE(verify_bytecode(*compiled).has_value());

        auto session = vm::RegisterVmSession::create(*compiled, invocation());
        REQUIRE(session.has_value());
        auto completed = (*session)->step({});
        while (completed.state == VmStepState::yielded) { completed = (*session)->step({}); }
        REQUIRE(completed.state == VmStepState::complete);
        REQUIRE(completed.result.has_value());
        CHECK(completed.result->verdict == true);
    }

    TEST_CASE("source handlers cannot suppress instruction budgets or deployment cancellation") {
        auto &runtime = shared_runtime();
        if (!runtime.runtime) {
            if (!runtime.staging_failure.empty()) {
                FAIL_CHECK(runtime.staging_failure);
                return;
            }
            WARN("SKIPPED: " << runtime.unavailable_reason);
            return;
        }

        const auto source = "from rule_engine import Model, provider_fact, rule\n"
                            "\n"
                            "class Process(Model):\n"
                            "    is_signed: bool = provider_fact(route=\"process.is_signed\")\n"
                            "\n"
                            "@rule(\"com.example.unsuppressible\")\n"
                            "def unsuppressible(process: Process) -> bool:\n"
                            "    marker = [False]\n"
                            "    try:\n"
                            "        return process.is_signed\n"
                            "    except Exception:\n"
                            "        return True\n"
                            "    finally:\n"
                            "        marker[0] = True\n";
        const auto compiled =
            compile_exact_source(*runtime.runtime, runtime.temporary_parent, source, "com.example.unsuppressible");
        INFO((compiled.has_value() ? std::string {} : diagnostic_text(compiled.error())));
        REQUIRE(compiled.has_value());
        REQUIRE(verify_bytecode(*compiled).has_value());
        REQUIRE(compiled->functions.size() == 1U);
        const auto &function = compiled->functions.front();
        const auto await = std::ranges::find(function.instructions, Opcode::await_fact, &Instruction::opcode);
        REQUIRE(await != function.instructions.end());
        CHECK(std::ranges::count(function.exception_regions, ExceptionRegionKind::handler, &ExceptionRegion::kind) ==
              1);
        CHECK(std::ranges::count(function.exception_regions, ExceptionRegionKind::cleanup, &ExceptionRegion::kind) ==
              1);

        SECTION("instruction budget bypasses Exception and runs forced cleanup") {
            auto bounded = invocation();
            bounded.budget.normal.instructions = static_cast<std::uint64_t>(await - function.instructions.begin());
            REQUIRE(bounded.budget.normal.instructions > 0U);
            auto session = vm::RegisterVmSession::create(*compiled, bounded);
            REQUIRE(session.has_value());
            auto faulted = (*session)->step({});
            while (faulted.state == VmStepState::yielded) { faulted = (*session)->step({}); }
            REQUIRE(faulted.state == VmStepState::faulted);
            REQUIRE(faulted.result.has_value());
            REQUIRE(faulted.result->fault.has_value());
            REQUIRE_FALSE(faulted.result->fault->frames.empty());
            CHECK(faulted.result->fault->frames.front().code == "PYVM4003");
            CHECK((*session)->recovery_counters().forced_cleanup.instructions > 0U);
        }

        SECTION("cancellation bypasses Exception and resumes the same cleanup") {
            auto session = vm::RegisterVmSession::create(*compiled, invocation());
            REQUIRE(session.has_value());
            const auto waiting = (*session)->step({});
            REQUIRE(waiting.state == VmStepState::waiting_for_facts);
            REQUIRE(waiting.fact_requests.size() == 1U);
            HostResponses cancel;
            cancel.cancel = true;
            auto canceled = (*session)->step(std::move(cancel));
            while (canceled.state == VmStepState::yielded) { canceled = (*session)->step({}); }
            REQUIRE(canceled.state == VmStepState::canceled);
            REQUIRE(canceled.result.has_value());
            CHECK(canceled.result->outcome == EvaluationOutcome::canceled);
            CHECK(canceled.result->verdict == std::nullopt);
            CHECK((*session)->recovery_counters().forced_cleanup.instructions > 0U);
        }
    }

    TEST_CASE("exact worker exception gaps fail closed with stable source-spanned diagnostics") {
        auto &runtime = shared_runtime();
        if (!runtime.runtime) {
            if (!runtime.staging_failure.empty()) {
                FAIL_CHECK(runtime.staging_failure);
                return;
            }
            WARN("SKIPPED: " << runtime.unavailable_reason);
            return;
        }

        const auto source = "from rule_engine import rule\n"
                            "\n"
                            "@rule(\"com.example.rejected-exceptions\")\n"
                            "def rejected_exceptions() -> bool:\n"
                            "    try:\n"
                            "        pass\n"
                            "    except ValueError as error:\n"
                            "        pass\n"
                            "    try:\n"
                            "        pass\n"
                            "    except (ValueError, TypeError):\n"
                            "        pass\n"
                            "    try:\n"
                            "        pass\n"
                            "    except Exception:\n"
                            "        pass\n"
                            "    except ValueError:\n"
                            "        pass\n"
                            "    try:\n"
                            "        pass\n"
                            "    except TypeError:\n"
                            "        pass\n"
                            "    except TypeError:\n"
                            "        pass\n"
                            "    try:\n"
                            "        pass\n"
                            "    except ArithmeticError:\n"
                            "        pass\n"
                            "    ArithmeticError = 1\n"
                            "    try:\n"
                            "        pass\n"
                            "    except* ValueError:\n"
                            "        pass\n"
                            "    try:\n"
                            "        pass\n"
                            "    finally:\n"
                            "        raise\n"
                            "    try:\n"
                            "        raise ValueError(\"message\") from TypeError(\"cause\")\n"
                            "    except ValueError:\n"
                            "        pass\n"
                            "    raise Exception(\"catch-all is not concrete\")\n"
                            "    raise \"dynamic exception\"\n"
                            "    raise\n"
                            "    return False\n";
        const auto first =
            compile_exact_source(*runtime.runtime, runtime.temporary_parent, source, "com.example.rejected-exceptions");
        const auto second =
            compile_exact_source(*runtime.runtime, runtime.temporary_parent, source, "com.example.rejected-exceptions");
        REQUIRE_FALSE(first.has_value());
        REQUIRE_FALSE(second.has_value());
        CHECK(diagnostic_text(first.error()) == diagnostic_text(second.error()));
        const auto has_code = [&](const std::string_view code) {
            return std::ranges::any_of(first.error(), [&](const Diagnostic &item) {
                return item.code == code && item.span.has_value() && item.span->valid();
            });
        };
        CHECK(has_code("PY-NYI-EXCEPTION-BINDING"));
        CHECK(has_code("PY-NYI-EXCEPTION-FILTER"));
        CHECK(has_code("PY-EXCEPTION-NAME-SHADOWED"));
        CHECK(has_code("PY-EXCEPTION-HANDLER-ORDER"));
        CHECK(has_code("PY-NYI-EXCEPTION-GROUP-LOWERING"));
        CHECK(has_code("PY-NYI-BARE-RAISE"));
        CHECK(has_code("PY-NYI-EXCEPTION-CAUSE"));
        CHECK(has_code("PY-NYI-RAISE-EXPRESSION"));
    }

    TEST_CASE("exact worker keeps state deletion and comprehension prerequisites fail closed") {
        auto &runtime = shared_runtime();
        if (!runtime.runtime) {
            if (!runtime.staging_failure.empty()) {
                FAIL_CHECK(runtime.staging_failure);
                return;
            }
            WARN("SKIPPED: " << runtime.unavailable_reason);
            return;
        }

        SECTION("state delete requires StateKey and injected capability lowering") {
            const auto compiled = compile_exact_source(*runtime.runtime, runtime.temporary_parent,
                                                       "from rule_engine import State, StateKey, rule\n"
                                                       "\n"
                                                       "@rule(\"com.example.state-delete\")\n"
                                                       "def clear(state: State, key: StateKey[bool]) -> bool:\n"
                                                       "    state.delete(key)\n"
                                                       "    return True\n",
                                                       "com.example.state-delete");
            REQUIRE_FALSE(compiled.has_value());
            CHECK(std::ranges::any_of(compiled.error(), [](const Diagnostic &diagnostic) {
                return diagnostic.code == "PY-NYI-STATE-LOWERING" &&
                       diagnostic.message.find("StateKey") != std::string::npos &&
                       diagnostic.message.find("delete_state") != std::string::npos;
            }));
        }

        SECTION("comprehensions require a bounded result builder and scope model") {
            const auto compiled = compile_exact_source(*runtime.runtime, runtime.temporary_parent,
                                                       "from rule_engine import rule\n"
                                                       "\n"
                                                       "@rule(\"com.example.comprehension\")\n"
                                                       "def comprehension() -> bool:\n"
                                                       "    return [value for value in [True]][0]\n",
                                                       "com.example.comprehension");
            REQUIRE_FALSE(compiled.has_value());
            CHECK(std::ranges::any_of(compiled.error(), [](const Diagnostic &diagnostic) {
                return diagnostic.code == "PY-NYI-COMPREHENSION-LOWERING";
            }));
        }

        SECTION("ordinary item deletion is not miscompiled as persistent state deletion") {
            const auto compiled = compile_exact_source(*runtime.runtime, runtime.temporary_parent,
                                                       "from rule_engine import rule\n"
                                                       "\n"
                                                       "@rule(\"com.example.item-delete\")\n"
                                                       "def item_delete() -> bool:\n"
                                                       "    values = [True]\n"
                                                       "    del values[0]\n"
                                                       "    return True\n",
                                                       "com.example.item-delete");
            REQUIRE_FALSE(compiled.has_value());
            CHECK(std::ranges::any_of(compiled.error(), [](const Diagnostic &diagnostic) {
                return diagnostic.code == "PY-NYI-DELETE-LOWERING" &&
                       diagnostic.message.find("state.delete") != std::string::npos;
            }));
        }
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

    TEST_CASE("AST scalar values require canonical bounded encodings") {
        auto noncanonical_integer = envelope(constant_rule_nodes(false));
        noncanonical_integer.nodes.back() = node(9, "Constant", {field("value", ast_integer("0001"))});
        const auto integer_payload = encode_ast_envelope(noncanonical_integer);
        REQUIRE(integer_payload.has_value());
        const auto integer_result = decode_ast_envelope(*integer_payload, pack());
        REQUIRE_FALSE(integer_result.has_value());
        REQUIRE(std::ranges::any_of(integer_result.error(),
                                    [](const Diagnostic &item) { return item.code == "PY-AST-INTEGER"; }));

        auto invalid_unicode = envelope(constant_rule_nodes(false));
        invalid_unicode.nodes.back() = node(9, "Constant", {field("value", ast_string(std::string {"\xC0\x80", 2U}))});
        const auto unicode_payload = encode_ast_envelope(invalid_unicode);
        REQUIRE(unicode_payload.has_value());
        const auto unicode_result = decode_ast_envelope(*unicode_payload, pack());
        REQUIRE_FALSE(unicode_result.has_value());
        REQUIRE(std::ranges::any_of(unicode_result.error(),
                                    [](const Diagnostic &item) { return item.code == "PY-AST-UNICODE"; }));
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

    TEST_CASE("reportable boundaries require annotations and simple generators lower to yield bytecode") {
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
        const auto generator_artifact = StaticCompiler {}.compile(pack(), *generator_payload, {}, {});
        REQUIRE(generator_artifact.has_value());
        REQUIRE(generator_artifact->pack.functions.front().generator);
        REQUIRE(std::ranges::any_of(generator_artifact->pack.functions.front().instructions,
                                    [](const Instruction &item) { return item.opcode == Opcode::yield_value; }));
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
        REQUIRE(artifact->fact_requirements.front().route.provider == "process");
        REQUIRE(artifact->fact_requirements.front().route.fact == "is_signed");
        const auto operand =
            decode_vm_fact_operand(artifact->pack.constants[artifact->fact_requirements.front().operand_constant]);
        REQUIRE(operand.has_value());
        REQUIRE(operand->route.provider == "process");
        REQUIRE(operand->route.fact == "is_signed");
        REQUIRE(operand->expected_schema == SchemaId {"bool"});
        REQUIRE_FALSE(artifact->fact_requirements.front().conditional);
        REQUIRE(artifact->pack.optimization_certificates.front().logical_facts ==
                std::vector<std::string> {"process.is_signed"});
        REQUIRE(artifact->symbols.front().subject_schema == SchemaId {"Process"});
        REQUIRE(verify_compiler_output(*artifact).has_value());
        const std::array required_capabilities {CapabilityId {"windows.process.v1"}};
        const auto defaults = default_rule_bindings(*artifact, required_capabilities);
        REQUIRE(defaults.size() == 1);
        REQUIRE(defaults.front().id == BindingId {"com.example.unsigned"});
        REQUIRE(defaults.front().executable == ExecutableId {"com.example.unsigned"});
        REQUIRE(defaults.front().capabilities == std::vector<CapabilityId> {CapabilityId {"windows.process.v1"}});
    }

    TEST_CASE("compiled direct subject fact rule resumes to a verdict in the real register VM",
              "[compiler-vm-progress]") {
        const auto rule_pack = pack();
        const auto payload = encode_ast_envelope(envelope(direct_fact_rule_nodes()));
        REQUIRE(payload.has_value());

        const OperatorBindings bindings {binding("com.example.unsigned")};
        const auto artifact = StaticCompiler {}.compile(rule_pack, *payload, {}, bindings);
        INFO((artifact.has_value() ? std::string {} : diagnostic_text(artifact.error())));
        REQUIRE(artifact.has_value());
        const auto &function = artifact->pack.functions.front();
        REQUIRE(function.parameter_count == 1U);
        REQUIRE(function.register_count == 3U);
        REQUIRE(function.instructions.size() == 3U);
        REQUIRE(function.instructions[0].opcode == Opcode::await_fact);
        REQUIRE(function.instructions[0].destination == 1U);
        REQUIRE(function.instructions[0].operand_a == 0U);
        REQUIRE(function.instructions[1].opcode == Opcode::unary_op);
        REQUIRE(function.instructions[1].destination == 2U);
        REQUIRE(function.instructions[1].operand_a == 1U);
        REQUIRE(function.instructions[2].opcode == Opcode::return_value);
        REQUIRE(function.instructions[2].operand_a == 2U);

        auto bounded_invocation = invocation();
        bounded_invocation.budget.normal.elapsed = std::chrono::seconds {1};
        bounded_invocation.budget.normal.instructions = function.instructions.size();
        bounded_invocation.budget.normal.loop_iterations_and_yields = 0U;
        auto session = vm::RegisterVmSession::create(artifact->pack, bounded_invocation);
        INFO((session.has_value() ? std::string {} : diagnostic_text(session.error())));
        REQUIRE(session.has_value());
        REQUIRE((*session)->counters().instructions == 0U);
        const auto waiting = (*session)->step({});
        REQUIRE(waiting.state == VmStepState::waiting_for_facts);
        REQUIRE(waiting.fact_requests.size() == 1U);
        REQUIRE((*session)->counters().instructions == 1U);

        HostResponses response;
        response.facts.push_back(FactResponse {
            .request_id = waiting.fact_requests.front().request_id,
            .subject = waiting.fact_requests.front().subject,
            .status = FactTerminalStatus::value,
            .value = make_fact(false),
            .returned_schema = SchemaIdentity {.id = waiting.fact_requests.front().expected_schema,
                                               .canonical_hash = waiting.fact_requests.front().expected_schema_hash},
            .diagnostic = std::nullopt,
        });
        const auto completed = (*session)->step(std::move(response));
        REQUIRE(completed.state == VmStepState::complete);
        REQUIRE(completed.result.has_value());
        REQUIRE(completed.result->verdict == true);
        REQUIRE((*session)->counters().instructions == function.instructions.size());
        REQUIRE((*session)->counters().loop_iterations_and_yields == 0U);
    }

    TEST_CASE("compiler operand constants are accepted by the real register VM") {
        CompiledPack compiled {
            .pack = PackId {"com.example.interop"},
            .version = PackVersion {"1.0.0"},
            .source_digest = SourceDigest {"sha256:interop"},
            .compiler_abi = std::string {python_static_compiler_abi_v1},
            .semantic_hash = "fnv1a64:interop",
            .schemas = {},
            .constants =
                {
                    make_vm_fact_operand(FactRoute {.provider = "process", .fact = "is_signed"}, SchemaId {"bool"}),
                    make_vm_capability_operand(CapabilityId {"service.lookup"}, SchemaId {"lookup.request"}),
                },
            .functions = {BytecodeFunction {
                .id = ExecutableId {"com.example.interop"},
                .qualified_name = "rules.main.interop",
                .register_count = 2U,
                .parameter_count = 0U,
                .generator = false,
                .async = true,
                .instructions =
                    {
                        Instruction {.opcode = Opcode::await_fact,
                                     .destination = 0U,
                                     .operand_a = 0U,
                                     .operand_b = 0U,
                                     .immediate = 0U,
                                     .span = span(0U, 1U)},
                        Instruction {.opcode = Opcode::await_capability,
                                     .destination = 1U,
                                     .operand_a = 0U,
                                     .operand_b = 0U,
                                     .immediate = 1U,
                                     .span = span(1U, 2U)},
                        Instruction {.opcode = Opcode::return_value,
                                     .destination = 1U,
                                     .operand_a = 1U,
                                     .operand_b = 0U,
                                     .immediate = 0U,
                                     .span = span(2U, 3U)},
                    },
                .exception_regions = {},
            }},
            .bindings = {OperatorBinding {.id = BindingId {"binding"},
                                          .executable = ExecutableId {"com.example.interop"},
                                          .capabilities = {CapabilityId {"service.lookup"}},
                                          .budget = balanced_v1}},
            .optimization_certificates = {},
        };
        auto session = vm::RegisterVmSession::create(compiled, invocation());
        REQUIRE(session.has_value());

        const auto fact_wait = (*session)->step({});
        REQUIRE(fact_wait.state == VmStepState::waiting_for_facts);
        REQUIRE(fact_wait.fact_requests.size() == 1U);
        REQUIRE(fact_wait.fact_requests.front().route.provider == "process");
        REQUIRE(fact_wait.fact_requests.front().route.fact == "is_signed");
        REQUIRE(fact_wait.fact_requests.front().expected_schema == SchemaId {"bool"});

        HostResponses fact_response;
        fact_response.facts.push_back(FactResponse {
            .request_id = fact_wait.fact_requests.front().request_id,
            .subject = fact_wait.fact_requests.front().subject,
            .status = FactTerminalStatus::value,
            .value = make_fact(true),
            .returned_schema = SchemaIdentity {.id = fact_wait.fact_requests.front().expected_schema,
                                               .canonical_hash = fact_wait.fact_requests.front().expected_schema_hash},
            .diagnostic = std::nullopt,
        });
        const auto capability_wait = (*session)->step(std::move(fact_response));
        REQUIRE(capability_wait.state == VmStepState::waiting_for_capabilities);
        REQUIRE(capability_wait.capability_requests.size() == 1U);
        REQUIRE(capability_wait.capability_requests.front().capability == CapabilityId {"service.lookup"});
        REQUIRE(capability_wait.capability_requests.front().request_schema == SchemaId {"lookup.request"});
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
        const auto artifact_diagnostics = artifact ? std::string {} : diagnostic_text(artifact.error());
        INFO(artifact_diagnostics);
        REQUIRE(artifact.has_value());
        REQUIRE(verify_compiler_output(*artifact).has_value());
    }

    TEST_CASE("statically bound helper calls execute through real VM frames") {
        const auto nodes = std::vector<AstNode> {
            node(1, "Module",
                 {field("body", ast_sequence({ast_reference(2), ast_reference(8)})),
                  field("type_ignores", ast_sequence({}))}),
            node(2, "FunctionDef",
                 {field("name", ast_string("helper")), field("args", ast_reference(3)),
                  field("body", ast_sequence({ast_reference(4)})), field("decorator_list", ast_sequence({})),
                  field("returns", ast_reference(6))}),
            node(3, "arguments",
                 {field("posonlyargs", ast_sequence({})), field("args", ast_sequence({})), field("vararg", ast_none()),
                  field("kwonlyargs", ast_sequence({})), field("kw_defaults", ast_sequence({})),
                  field("kwarg", ast_none()), field("defaults", ast_sequence({}))}),
            node(4, "Return", {field("value", ast_reference(5))}),
            node(5, "Constant", {field("value", ast_bool(true))}),
            node(6, "Name", {field("id", ast_string("bool"))}),
            node(8, "FunctionDef",
                 {field("name", ast_string("main")), field("args", ast_reference(9)),
                  field("body", ast_sequence({ast_reference(14)})),
                  field("decorator_list", ast_sequence({ast_reference(10)})), field("returns", ast_reference(13))}),
            node(9, "arguments",
                 {field("posonlyargs", ast_sequence({})), field("args", ast_sequence({})), field("vararg", ast_none()),
                  field("kwonlyargs", ast_sequence({})), field("kw_defaults", ast_sequence({})),
                  field("kwarg", ast_none()), field("defaults", ast_sequence({}))}),
            node(10, "Call",
                 {field("func", ast_reference(11)), field("args", ast_sequence({ast_reference(12)})),
                  field("keywords", ast_sequence({}))}),
            node(11, "Name", {field("id", ast_string("rule"))}),
            node(12, "Constant", {field("value", ast_string("com.example.call"))}),
            node(13, "Name", {field("id", ast_string("bool"))}),
            node(14, "Return", {field("value", ast_reference(15))}),
            node(15, "Call",
                 {field("func", ast_reference(16)), field("args", ast_sequence({})),
                  field("keywords", ast_sequence({}))}),
            node(16, "Name", {field("id", ast_string("helper"))}),
        };
        const auto payload = encode_ast_envelope(envelope(nodes));
        REQUIRE(payload.has_value());
        const OperatorBindings bindings {binding("com.example.call")};
        const auto artifact = StaticCompiler {}.compile(pack(), *payload, {}, bindings);
        REQUIRE(artifact.has_value());
        REQUIRE(std::ranges::any_of(artifact->pack.functions, [](const BytecodeFunction &function) {
            return std::ranges::any_of(function.instructions,
                                       [](const Instruction &item) { return item.opcode == Opcode::call; });
        }));

        auto session = vm::RegisterVmSession::create(artifact->pack, invocation());
        REQUIRE(session.has_value());
        const auto completed = (*session)->step({});
        REQUIRE(completed.state == VmStepState::complete);
        REQUIRE(completed.result.has_value());
        REQUIRE(completed.result->verdict == true);
        REQUIRE((*session)->counters().peak_frames == 2U);
    }

    TEST_CASE("chained comparisons preserve short circuit bytecode and execute in the real VM") {
        auto nodes = constant_rule_nodes(false);
        nodes.back() =
            node(9, "Compare",
                 {field("left", ast_reference(10)), field("ops", ast_sequence({ast_string("Lt"), ast_string("Lt")})),
                  field("comparators", ast_sequence({ast_reference(11), ast_reference(12)}))});
        nodes.push_back(node(10, "Constant", {field("value", ast_integer("1"))}));
        nodes.push_back(node(11, "Constant", {field("value", ast_integer("2"))}));
        nodes.push_back(node(12, "Constant", {field("value", ast_integer("3"))}));
        const auto payload = encode_ast_envelope(envelope(std::move(nodes)));
        REQUIRE(payload.has_value());
        const OperatorBindings bindings {binding("com.example.constant")};
        const auto artifact = StaticCompiler {}.compile(pack(), *payload, {}, bindings);
        REQUIRE(artifact.has_value());
        const auto &instructions = artifact->pack.functions.front().instructions;
        REQUIRE(std::ranges::count(instructions, Opcode::compare, &Instruction::opcode) == 2);
        REQUIRE(std::ranges::count(instructions, Opcode::jump_if_false, &Instruction::opcode) == 1);

        auto session = vm::RegisterVmSession::create(artifact->pack, invocation());
        REQUIRE(session.has_value());
        const auto completed = (*session)->step({});
        REQUIRE(completed.state == VmStepState::complete);
        REQUIRE(completed.result.has_value());
        REQUIRE(completed.result->verdict == true);
    }

    TEST_CASE("while loop assignments use stable local registers across back edges") {
        auto nodes = constant_rule_nodes(false);
        const auto body = std::ranges::find(nodes[1].fields, "body", &AstField::name);
        REQUIRE(body != nodes[1].fields.end());
        body->value = ast_sequence({ast_reference(8), ast_reference(11), ast_reference(22)});
        nodes[7] =
            node(8, "Assign", {field("targets", ast_sequence({ast_reference(9)})), field("value", ast_reference(10))});
        nodes[8] = node(9, "Name", {field("id", ast_string("count"))});
        nodes.push_back(node(10, "Constant", {field("value", ast_integer("0"))}));
        nodes.push_back(node(11, "While",
                             {field("test", ast_reference(12)), field("body", ast_sequence({ast_reference(16)})),
                              field("orelse", ast_sequence({}))}));
        nodes.push_back(node(12, "Compare",
                             {field("left", ast_reference(13)), field("ops", ast_sequence({ast_string("Lt")})),
                              field("comparators", ast_sequence({ast_reference(14)}))}));
        nodes.push_back(node(13, "Name", {field("id", ast_string("count"))}));
        nodes.push_back(node(14, "Constant", {field("value", ast_integer("3"))}));
        nodes.push_back(node(16, "Assign",
                             {field("targets", ast_sequence({ast_reference(17)})), field("value", ast_reference(18))}));
        nodes.push_back(node(17, "Name", {field("id", ast_string("count"))}));
        nodes.push_back(node(
            18, "BinOp",
            {field("left", ast_reference(19)), field("op", ast_string("Add")), field("right", ast_reference(20))}));
        nodes.push_back(node(19, "Name", {field("id", ast_string("count"))}));
        nodes.push_back(node(20, "Constant", {field("value", ast_integer("1"))}));
        nodes.push_back(node(22, "Return", {field("value", ast_reference(23))}));
        nodes.push_back(node(23, "Compare",
                             {field("left", ast_reference(24)), field("ops", ast_sequence({ast_string("Eq")})),
                              field("comparators", ast_sequence({ast_reference(25)}))}));
        nodes.push_back(node(24, "Name", {field("id", ast_string("count"))}));
        nodes.push_back(node(25, "Constant", {field("value", ast_integer("3"))}));

        const auto payload = encode_ast_envelope(envelope(std::move(nodes)));
        REQUIRE(payload.has_value());
        const OperatorBindings bindings {binding("com.example.constant")};
        const auto artifact = StaticCompiler {}.compile(pack(), *payload, {}, bindings);
        REQUIRE(artifact.has_value());
        REQUIRE(std::ranges::any_of(artifact->pack.functions.front().instructions,
                                    [](const Instruction &item) { return item.opcode == Opcode::jump; }));

        auto session = vm::RegisterVmSession::create(artifact->pack, invocation());
        REQUIRE(session.has_value());
        const auto completed = (*session)->step({});
        REQUIRE(completed.state == VmStepState::complete);
        REQUIRE(completed.result.has_value());
        REQUIRE(completed.result->verdict == true);
        REQUIRE((*session)->counters().loop_iterations_and_yields == 3U);
    }

    TEST_CASE("literal match cases lower to ordered tests with an exhaustive wildcard") {
        auto nodes = constant_rule_nodes(false);
        nodes[7] = node(
            8, "Match",
            {field("subject", ast_reference(9)), field("cases", ast_sequence({ast_reference(10), ast_reference(15)}))});
        nodes[8] = node(9, "Constant", {field("value", ast_integer("2"))});
        nodes.push_back(node(10, "match_case",
                             {field("pattern", ast_reference(11)), field("guard", ast_none()),
                              field("body", ast_sequence({ast_reference(12)}))}));
        nodes.push_back(node(11, "MatchValue", {field("value", ast_reference(13))}));
        nodes.push_back(node(12, "Return", {field("value", ast_reference(14))}));
        nodes.push_back(node(13, "Constant", {field("value", ast_integer("1"))}));
        nodes.push_back(node(14, "Constant", {field("value", ast_bool(false))}));
        nodes.push_back(node(15, "match_case",
                             {field("pattern", ast_reference(16)), field("guard", ast_none()),
                              field("body", ast_sequence({ast_reference(17)}))}));
        nodes.push_back(node(16, "MatchAs", {field("pattern", ast_none()), field("name", ast_none())}));
        nodes.push_back(node(17, "Return", {field("value", ast_reference(18))}));
        nodes.push_back(node(18, "Constant", {field("value", ast_bool(true))}));

        const auto payload = encode_ast_envelope(envelope(std::move(nodes)));
        REQUIRE(payload.has_value());
        const OperatorBindings bindings {binding("com.example.constant")};
        const auto artifact = StaticCompiler {}.compile(pack(), *payload, {}, bindings);
        REQUIRE(artifact.has_value());
        REQUIRE(std::ranges::count(artifact->pack.functions.front().instructions, Opcode::compare,
                                   &Instruction::opcode) == 1);

        auto session = vm::RegisterVmSession::create(artifact->pack, invocation());
        REQUIRE(session.has_value());
        const auto completed = (*session)->step({});
        REQUIRE(completed.state == VmStepState::complete);
        REQUIRE(completed.result.has_value());
        REQUIRE(completed.result->verdict == true);
    }

    TEST_CASE("catch-all try regions recover explicit author faults in the real VM") {
        auto nodes = constant_rule_nodes(false);
        nodes[7] =
            node(8, "Try",
                 {field("body", ast_sequence({ast_reference(9)})), field("handlers", ast_sequence({ast_reference(11)})),
                  field("orelse", ast_sequence({})), field("finalbody", ast_sequence({}))});
        nodes[8] = node(9, "Raise", {field("exc", ast_reference(10)), field("cause", ast_none())});
        nodes.push_back(node(10, "Name", {field("id", ast_string("ValueError"))}));
        nodes.push_back(node(
            11, "ExceptHandler",
            {field("type", ast_none()), field("name", ast_none()), field("body", ast_sequence({ast_reference(12)}))}));
        nodes.push_back(node(12, "Return", {field("value", ast_reference(13))}));
        nodes.push_back(node(13, "Constant", {field("value", ast_bool(true))}));

        const auto payload = encode_ast_envelope(envelope(std::move(nodes)));
        REQUIRE(payload.has_value());
        const OperatorBindings bindings {binding("com.example.constant")};
        const auto artifact = StaticCompiler {}.compile(pack(), *payload, {}, bindings);
        REQUIRE(artifact.has_value());
        REQUIRE(artifact->pack.functions.front().exception_regions.size() == 1U);
        REQUIRE(verify_compiler_output(*artifact).has_value());

        auto session = vm::RegisterVmSession::create(artifact->pack, invocation());
        REQUIRE(session.has_value());
        const auto completed = (*session)->step({});
        REQUIRE(completed.state == VmStepState::complete);
        REQUIRE(completed.result.has_value());
        REQUIRE(completed.result->verdict == true);
    }

    TEST_CASE("explicit Model declarations produce deterministic labeled schemas") {
        auto nodes = fact_rule_nodes();
        const auto module_body = std::ranges::find(nodes.front().fields, "body", &AstField::name);
        REQUIRE(module_body != nodes.front().fields.end());
        module_body->value = ast_sequence({ast_reference(20), ast_reference(2)});
        nodes.push_back(node(20, "ClassDef",
                             {field("name", ast_string("Process")), field("bases", ast_sequence({ast_reference(21)})),
                              field("keywords", ast_sequence({})), field("body", ast_sequence({ast_reference(22)})),
                              field("decorator_list", ast_sequence({}))}));
        nodes.push_back(node(21, "Name", {field("id", ast_string("Model"))}));
        nodes.push_back(node(22, "AnnAssign",
                             {field("target", ast_reference(23)), field("annotation", ast_reference(24)),
                              field("value", ast_none()), field("simple", ast_integer("1"))}));
        nodes.push_back(node(23, "Name", {field("id", ast_string("is_signed"))}));
        nodes.push_back(node(24, "Subscript", {field("value", ast_reference(25)), field("slice", ast_reference(26))}));
        nodes.push_back(node(25, "Name", {field("id", ast_string("Sensitive"))}));
        nodes.push_back(node(26, "Name", {field("id", ast_string("bool"))}));

        const auto payload = encode_ast_envelope(envelope(nodes));
        REQUIRE(payload.has_value());
        const auto first = StaticCompiler {}.compile(pack(), *payload, {}, {});
        const auto second = StaticCompiler {}.compile(pack(), *payload, {}, {});
        REQUIRE(first.has_value());
        REQUIRE(second.has_value());
        const auto descriptor =
            std::ranges::find(first->pack.schemas.descriptors, SchemaId {"rules.main.Process"}, &SchemaDescriptor::id);
        REQUIRE(descriptor != first->pack.schemas.descriptors.end());
        REQUIRE(descriptor->kind == SchemaKind::model);
        REQUIRE(descriptor->fields.size() == 1U);
        REQUIRE(descriptor->fields.front().field_id == 1U);
        REQUIRE(descriptor->fields.front().name == "is_signed");
        REQUIRE(descriptor->fields.front().type == SchemaId {"bool"});
        REQUIRE(descriptor->fields.front().label.classification == Classification::sensitive);
        const auto second_descriptor =
            std::ranges::find(second->pack.schemas.descriptors, SchemaId {"rules.main.Process"}, &SchemaDescriptor::id);
        REQUIRE(second_descriptor != second->pack.schemas.descriptors.end());
        REQUIRE(descriptor->canonical_hash == second_descriptor->canonical_hash);
        REQUIRE(first->pack.schemas.canonical_hash == second->pack.schemas.canonical_hash);
        const auto rule_symbol = std::ranges::find(first->symbols, SymbolKind::rule, &BoundSymbol::kind);
        REQUIRE(rule_symbol != first->symbols.end());
        REQUIRE(rule_symbol->subject_schema == SchemaId {"rules.main.Process"});
    }

    TEST_CASE("recursively constant list and dictionary displays allocate fresh VM containers") {
        auto nodes = constant_rule_nodes(false);
        const auto decorators = std::ranges::find(nodes[1].fields, "decorator_list", &AstField::name);
        const auto returns = std::ranges::find(nodes[1].fields, "returns", &AstField::name);
        REQUIRE(decorators != nodes[1].fields.end());
        REQUIRE(returns != nodes[1].fields.end());
        decorators->value = ast_sequence({});
        returns->value = ast_none();
        std::erase_if(nodes, [](const AstNode &item) { return item.id >= 4U && item.id <= 7U; });
        const auto return_statement = std::ranges::find(nodes, AstNodeId {8U}, &AstNode::id);
        REQUIRE(return_statement != nodes.end());
        const auto returned_value = std::ranges::find(nodes, AstNodeId {9U}, &AstNode::id);
        REQUIRE(returned_value != nodes.end());
        *returned_value = node(9, "List", {field("elts", ast_sequence({ast_reference(10), ast_reference(11)}))});
        nodes.push_back(node(10, "Constant", {field("value", ast_integer("7"))}));
        nodes.push_back(node(
            11, "Dict",
            {field("keys", ast_sequence({ast_reference(12)})), field("values", ast_sequence({ast_reference(13)}))}));
        nodes.push_back(node(12, "Constant", {field("value", ast_string("ok"))}));
        nodes.push_back(node(13, "Constant", {field("value", ast_bool(true))}));

        const auto payload = encode_ast_envelope(envelope(std::move(nodes)));
        REQUIRE(payload.has_value());
        const auto artifact = StaticCompiler {}.compile(pack(), *payload, {}, {});
        const auto artifact_diagnostics = artifact ? std::string {} : diagnostic_text(artifact.error());
        INFO(artifact_diagnostics);
        REQUIRE(artifact.has_value());
        REQUIRE(artifact->pack.constants.size() == 3U);
        REQUIRE(artifact->pack.functions.size() == 1U);
        const auto &instructions = artifact->pack.functions.front().instructions;
        CHECK(std::ranges::count(instructions, Opcode::load_const, &Instruction::opcode) == 3);
        CHECK(std::ranges::count(instructions, Opcode::build_dict, &Instruction::opcode) == 1);
        CHECK(std::ranges::count(instructions, Opcode::build_list, &Instruction::opcode) == 1);
        REQUIRE(artifact->pack.optimization_certificates.size() == 1U);
        CHECK(artifact->pack.optimization_certificates.front().may_fault);
    }

    TEST_CASE("bounded collection control flow lowers while remaining F0 gaps fail precisely") {
        SECTION("subscription") {
            auto nodes = constant_rule_nodes(false);
            nodes[8] = node(9, "Subscript", {field("value", ast_reference(10)), field("slice", ast_reference(11))});
            nodes.push_back(node(10, "List", {field("elts", ast_sequence({}))}));
            nodes.push_back(node(11, "Constant", {field("value", ast_integer("0"))}));
            const auto payload = encode_ast_envelope(envelope(std::move(nodes)));
            REQUIRE(payload.has_value());
            const auto result = StaticCompiler {}.compile(pack(), *payload, {}, {});
            INFO((result.has_value() ? std::string {} : diagnostic_text(result.error())));
            REQUIRE(result.has_value());
            REQUIRE(result->pack.functions.size() == 1U);
            CHECK(std::ranges::any_of(result->pack.functions.front().instructions, [](const Instruction &instruction) {
                return instruction.opcode == Opcode::load_subscript;
            }));
        }

        SECTION("comprehension") {
            auto nodes = constant_rule_nodes(false);
            nodes[8] = node(9, "ListComp", {field("elt", ast_reference(10)), field("generators", ast_sequence({}))});
            nodes.push_back(node(10, "Constant", {field("value", ast_integer("1"))}));
            const auto payload = encode_ast_envelope(envelope(std::move(nodes)));
            REQUIRE(payload.has_value());
            const auto result = StaticCompiler {}.compile(pack(), *payload, {}, {});
            REQUIRE_FALSE(result.has_value());
            REQUIRE(std::ranges::any_of(
                result.error(), [](const Diagnostic &item) { return item.code == "PY-NYI-COMPREHENSION-LOWERING"; }));
        }

        SECTION("for iteration") {
            auto nodes = constant_rule_nodes(false);
            const auto body = std::ranges::find(nodes[1].fields, "body", &AstField::name);
            REQUIRE(body != nodes[1].fields.end());
            body->value = ast_sequence({ast_reference(8), ast_reference(12)});
            nodes[7] = node(8, "For",
                            {field("target", ast_reference(9)), field("iter", ast_reference(10)),
                             field("body", ast_sequence({ast_reference(11)})), field("orelse", ast_sequence({}))});
            nodes[8] = node(9, "Name", {field("id", ast_string("item"))});
            nodes.push_back(node(10, "List", {field("elts", ast_sequence({}))}));
            nodes.push_back(node(11, "Pass", {}));
            nodes.push_back(node(12, "Return", {field("value", ast_reference(13))}));
            nodes.push_back(node(13, "Constant", {field("value", ast_bool(false))}));
            const auto payload = encode_ast_envelope(envelope(std::move(nodes)));
            REQUIRE(payload.has_value());
            const auto result = StaticCompiler {}.compile(pack(), *payload, {}, {});
            INFO((result.has_value() ? std::string {} : diagnostic_text(result.error())));
            REQUIRE(result.has_value());
            REQUIRE(result->pack.functions.size() == 1U);
            const auto &instructions = result->pack.functions.front().instructions;
            CHECK(std::ranges::count(instructions, Opcode::get_iter, &Instruction::opcode) == 1);
            CHECK(std::ranges::count(instructions, Opcode::iter_next, &Instruction::opcode) == 1);
        }

        SECTION("finally unwind") {
            auto nodes = constant_rule_nodes(false);
            const auto function_body = std::ranges::find(nodes[1].fields, "body", &AstField::name);
            REQUIRE(function_body != nodes[1].fields.end());
            function_body->value = ast_sequence({ast_reference(8), ast_reference(14)});
            nodes[7] = node(8, "Try",
                            {field("body", ast_sequence({ast_reference(10)})),
                             field("handlers", ast_sequence({ast_reference(11)})), field("orelse", ast_sequence({})),
                             field("finalbody", ast_sequence({ast_reference(13)}))});
            std::erase_if(nodes, [](const AstNode &item) { return item.id == 9U; });
            nodes.push_back(node(10, "Pass", {}));
            nodes.push_back(node(11, "ExceptHandler",
                                 {field("type", ast_none()), field("name", ast_none()),
                                  field("body", ast_sequence({ast_reference(12)}))}));
            nodes.push_back(node(12, "Pass", {}));
            nodes.push_back(node(13, "Pass", {}));
            nodes.push_back(node(14, "Return", {field("value", ast_reference(15))}));
            nodes.push_back(node(15, "Constant", {field("value", ast_bool(true))}));
            const auto payload = encode_ast_envelope(envelope(std::move(nodes)));
            REQUIRE(payload.has_value());
            const auto result = StaticCompiler {}.compile(pack(), *payload, {}, {});
            INFO((result.has_value() ? std::string {} : diagnostic_text(result.error())));
            REQUIRE(result.has_value());
            REQUIRE(result->pack.functions.front().exception_regions.size() == 2U);
            CHECK(std::ranges::any_of(
                result->pack.functions.front().exception_regions,
                [](const ExceptionRegion &region) { return region.kind == ExceptionRegionKind::cleanup; }));
        }
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

    TEST_CASE("activation binding and executable identities are canonical and platform scoped") {
        OperatorBindings first {
            {.id = BindingId {"binding-b"},
             .executable = ExecutableId {"rule-b"},
             .capabilities = {CapabilityId {"capability-z"}, CapabilityId {"capability-a"}},
             .budget = balanced_v1},
            {.id = BindingId {"binding-a"},
             .executable = ExecutableId {"rule-a"},
             .capabilities = {},
             .budget = balanced_v1},
        };
        auto reordered = first;
        std::ranges::reverse(reordered);
        std::ranges::reverse(reordered.back().capabilities);
        REQUIRE(canonical_operator_bindings_hash(first) == canonical_operator_bindings_hash(reordered));

        CompiledPack compiled {
            .pack = PackId {"com.example.rules"},
            .version = PackVersion {"1.0.0"},
            .source_digest = SourceDigest {"sha256:source"},
            .compiler_abi = std::string {python_static_compiler_abi_v1},
            .semantic_hash = "fnv1a64:0000000000000001",
            .schemas = {.descriptors = {}, .canonical_hash = "fnv1a64:0000000000000002"},
            .constants = {},
            .functions = {},
            .bindings = std::move(first),
            .optimization_certificates = {},
        };
        const auto windows = compiled_pack_executable_hash(compiled, "windows-x64-v1");
        REQUIRE(windows == compiled_pack_executable_hash(compiled, "windows-x64-v1"));
        REQUIRE(windows != compiled_pack_executable_hash(compiled, "linux-x64-v1"));
        compiled.semantic_hash = "fnv1a64:0000000000000003";
        REQUIRE(windows != compiled_pack_executable_hash(compiled, "windows-x64-v1"));
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

        artifact = StaticCompiler {}.compile(rule_pack, *payload, {}, {});
        REQUIRE(artifact.has_value());
        auto &function = artifact->pack.functions.front();
        ++function.register_count;
        function.instructions.back().operand_a = function.register_count - 1U;
        const auto uninitialized = verify_compiler_output(*artifact);
        REQUIRE_FALSE(uninitialized.has_value());
        REQUIRE(std::ranges::any_of(uninitialized.error(),
                                    [](const Diagnostic &item) { return item.code == "PYC-UNINITIALIZED"; }));

        artifact = StaticCompiler {}.compile(rule_pack, *payload, {}, {});
        REQUIRE(artifact.has_value());
        auto &iterator_function = artifact->pack.functions.front();
        const auto span = iterator_function.instructions.front().span;
        iterator_function.register_count = 4U;
        iterator_function.instructions = {
            {.opcode = Opcode::build_list, .destination = 1U, .operand_a = 0U, .operand_b = 0U, .span = span},
            {.opcode = Opcode::get_iter, .destination = 2U, .operand_a = 1U, .span = span},
            {.opcode = Opcode::iter_next, .destination = 3U, .operand_a = 2U, .immediate = 4U, .span = span},
            {.opcode = Opcode::return_value, .operand_a = 3U, .span = span},
            {.opcode = Opcode::return_value, .operand_a = 3U, .span = span},
        };
        const auto exhausted_value = verify_compiler_output(*artifact);
        REQUIRE_FALSE(exhausted_value.has_value());
        REQUIRE(std::ranges::any_of(exhausted_value.error(),
                                    [](const Diagnostic &item) { return item.code == "PYC-UNINITIALIZED"; }));
    }

} // namespace
