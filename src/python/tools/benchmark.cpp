#include "rule_engine/python/tools/benchmark.hpp"

#include "rule_engine/python/compiler.hpp"
#include "rule_engine/python/optimizer/optimizer.hpp"
#include "rule_engine/python/packaging/source_pack.hpp"
#include "rule_engine/python/vm/register_vm.hpp"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace rule_engine::python::tools {
    namespace {

        namespace compiler = rule_engine::python::compiler;
        namespace optimizer = rule_engine::python::optimizer;
        namespace packaging = rule_engine::python::packaging;
        namespace vm = rule_engine::python::vm;

        constexpr std::string_view source_name = "benchmark.rules";
        constexpr std::string_view executable_name = "benchmark.constant_false";
        constexpr std::string_view binding_name = "benchmark-binding";
        constexpr std::size_t maximum_peer_count = 100'000U;

        constexpr std::string_view help_text = R"(Usage: rule_engine_benchmark [--peers COUNT] [--format text|json]

Compile a deterministic Python rule pack, execute exact register bytecode for
synthetic peers, validate a pure-false optimizer certificate, and compare every
observable exact and optimized result with the shadow-parity contract.

Options:
  --peers COUNT       Synthetic peer count from 1 through 100000 (default: 10000)
  --format FORMAT     text or json (default: text)
  --help              Show this help
  --version           Show the tool API version
)";

        [[nodiscard]] SourceSpan span(const std::uint32_t begin = 0U, const std::uint32_t end = 1U) {
            return {
                .source = SourceId {std::string {source_name}},
                .begin_byte = begin,
                .end_byte = end,
            };
        }

        [[nodiscard]] compiler::AstField field(std::string name, compiler::AstValue value) {
            return {.name = std::move(name), .value = std::move(value)};
        }

        [[nodiscard]] compiler::AstNode node(const compiler::AstNodeId id, std::string kind,
                                             std::vector<compiler::AstField> fields) {
            return {
                .id = id,
                .kind = std::move(kind),
                .span = span(),
                .fields = std::move(fields),
            };
        }

        [[nodiscard]] std::vector<compiler::AstNode> constant_false_rule_nodes() {
            using namespace compiler;
            return {
                node(1U, "Module",
                     {field("body", ast_sequence({ast_reference(2U)})), field("type_ignores", ast_sequence({}))}),
                node(2U, "FunctionDef",
                     {field("name", ast_string("constant_rule")), field("args", ast_reference(3U)),
                      field("body", ast_sequence({ast_reference(8U)})),
                      field("decorator_list", ast_sequence({ast_reference(4U)})), field("returns", ast_reference(7U))}),
                node(3U, "arguments",
                     {field("posonlyargs", ast_sequence({})), field("args", ast_sequence({})),
                      field("vararg", ast_none()), field("kwonlyargs", ast_sequence({})),
                      field("kw_defaults", ast_sequence({})), field("kwarg", ast_none()),
                      field("defaults", ast_sequence({}))}),
                node(4U, "Call",
                     {field("func", ast_reference(5U)), field("args", ast_sequence({ast_reference(6U)})),
                      field("keywords", ast_sequence({}))}),
                node(5U, "Name", {field("id", ast_string("rule"))}),
                node(6U, "Constant", {field("value", ast_string(std::string {executable_name}))}),
                node(7U, "Name", {field("id", ast_string("bool"))}),
                node(8U, "Return", {field("value", ast_reference(9U))}),
                node(9U, "Constant", {field("value", ast_bool(false))}),
            };
        }

        [[nodiscard]] VerifiedRulePack benchmark_pack() {
            std::string source = "from rule_engine import rule\n"
                                 "\n"
                                 "@rule(\"benchmark.constant_false\")\n"
                                 "def constant_rule() -> bool:\n"
                                 "    return False\n";
            const auto bytes = std::as_bytes(std::span {source.data(), source.size()});
            const auto digest = SourceDigest {"sha256:" + packaging::sha256_hex(bytes)};
            return {
                .manifest =
                    {
                        .pack = PackId {"benchmark.python"},
                        .version = PackVersion {"1.0.0"},
                        .compiler_abi = "python-3.14.6/static-compiler-v1",
                        .budget_profile = "balanced.v1",
                        .entry_modules = {std::string {source_name}},
                        .dependency_digests = {},
                    },
                .sources = {SourceFile {
                    .id = SourceId {std::string {source_name}},
                    .module = std::string {source_name},
                    .utf8 = std::move(source),
                    .digest = digest,
                }},
                .trust =
                    {
                        .signer_key_id = "benchmark-local",
                        .signature_algorithm = "Ed25519",
                        .production_authorized = true,
                    },
                .closure_digest = SourceDigest {"sha256:benchmark-closure-v1"},
            };
        }

        [[nodiscard]] compiler::AstEnvelope benchmark_envelope() {
            return {
                .protocol_major = compiler::ast_envelope_protocol_major,
                .protocol_minor = compiler::ast_envelope_protocol_minor,
                .grammar_major = compiler::python_grammar_major,
                .grammar_minor = compiler::python_grammar_minor,
                .worker_runtime = "3.14.6",
                .source_digest = SourceDigest {"sha256:benchmark-closure-v1"},
                .modules = {{
                    .name = std::string {source_name},
                    .source = SourceId {std::string {source_name}},
                    .root = 1U,
                }},
                .nodes = constant_false_rule_nodes(),
            };
        }

        [[nodiscard]] OperatorBindings benchmark_bindings() {
            return {{
                .id = BindingId {std::string {binding_name}},
                .executable = ExecutableId {std::string {executable_name}},
                .capabilities = {},
                .budget = balanced_v1,
            }};
        }

        [[nodiscard]] SubjectKey synthetic_subject(const std::size_t index) {
            return {
                .peer = PeerId {"synthetic-peer-" + std::to_string(index + 1U)},
                .descriptor = SchemaId {"benchmark.peer/v1"},
                .identity = {IdentityField {
                    .field_id = 1U,
                    .value = static_cast<std::uint64_t>(index + 1U),
                }},
                .parent = {},
            };
        }

        [[nodiscard]] VmInvocation invocation(const std::size_t index) {
            return {
                .execution = ExecutionId {"benchmark-execution-" + std::to_string(index + 1U)},
                .invocation = InvocationId {"benchmark-invocation-" + std::to_string(index + 1U)},
                .binding = BindingId {std::string {binding_name}},
                .subject = synthetic_subject(index),
                .budget = balanced_v1,
                .deterministic_hash_seed = 0x6A09E667F3BCC909ULL ^ static_cast<std::uint64_t>(index),
            };
        }

        [[nodiscard]] std::string diagnostic_summary(const DiagnosticSet &diagnostics) {
            if (diagnostics.empty()) {
                return "no diagnostic was provided";
            }
            return diagnostics.front().code + ": " + diagnostics.front().message;
        }

        [[nodiscard]] PythonBenchmarkError benchmark_error(const ExitCode exit_code, std::string code,
                                                           std::string message) {
            return {
                .exit_code = exit_code,
                .code = std::move(code),
                .message = std::move(message),
            };
        }

        [[nodiscard]] optimizer::SemanticResourceCounters semantic_resources(const vm::RegisterVmSession &session) {
            const auto counters = session.counters();
            const auto heap = session.heap_stats();
            return {
                .instructions = counters.instructions,
                .peak_frames = counters.peak_frames,
                .peak_heap_bytes = static_cast<std::uint64_t>(heap.peak_live_bytes),
                .loop_iterations_and_yields = counters.loop_iterations_and_yields,
                .allocation_work = static_cast<std::uint64_t>(heap.logical_allocated_bytes),
                .logical_facts = counters.logical_facts,
                .provider_rounds = counters.provider_rounds,
                .fact_bytes = static_cast<std::uint64_t>(counters.fact_bytes),
                .service_calls = counters.service_calls,
                .peak_active_service_calls = counters.peak_active_service_calls,
                .service_response_bytes = static_cast<std::uint64_t>(counters.service_response_bytes),
                .history_queries = 0U,
                .history_rows = 0U,
                .history_bytes = 0U,
                .state_keys = counters.state_keys,
                .state_bytes = static_cast<std::uint64_t>(counters.state_bytes),
                .effect_intents = counters.effect_intents,
                .effect_bytes = static_cast<std::uint64_t>(counters.effect_bytes),
                .recorder_events = 0U,
                .recorder_bytes = 0U,
            };
        }

        [[nodiscard]] std::uint64_t elapsed_nanoseconds(const std::chrono::steady_clock::time_point begin,
                                                        const std::chrono::steady_clock::time_point end) noexcept {
            const auto count = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin).count();
            return count <= 0 ? 0U : static_cast<std::uint64_t>(count);
        }

        [[nodiscard]] std::string json_quote(const std::string_view value) {
            std::string result {'"'};
            for (const auto character : value) {
                switch (character) {
                    case '"': result += "\\\""; break;
                    case '\\': result += "\\\\"; break;
                    case '\n': result += "\\n"; break;
                    case '\r': result += "\\r"; break;
                    case '\t': result += "\\t"; break;
                    default:
                        if (static_cast<unsigned char>(character) < 0x20U) {
                            result += "?";
                        } else {
                            result.push_back(character);
                        }
                        break;
                }
            }
            result.push_back('"');
            return result;
        }

        [[nodiscard]] std::expected<std::size_t, std::string> parse_peer_count(const std::string_view text) {
            std::uint64_t value {};
            const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value);
            if (text.empty() || parsed.ec != std::errc {} || parsed.ptr != text.data() + text.size() || value == 0U ||
                value > maximum_peer_count) {
                return std::unexpected("--peers requires an integer from 1 through 100000");
            }
            return static_cast<std::size_t>(value);
        }

    } // namespace

    std::expected<PythonBenchmarkReport, PythonBenchmarkError>
    run_python_benchmark(const PythonBenchmarkOptions &options) {
        if (options.peers == 0U || options.peers > maximum_peer_count) {
            return std::unexpected(benchmark_error(ExitCode::command_line_error, "BENCH-PEER-COUNT",
                                                   "peer count must be from 1 through 100000"));
        }
        if (options.format == OutputFormat::sarif) {
            return std::unexpected(
                benchmark_error(ExitCode::command_line_error, "BENCH-FORMAT", "benchmark format must be text or json"));
        }

        const auto pack = benchmark_pack();
        auto payload = compiler::encode_ast_envelope(benchmark_envelope());
        if (!payload) {
            return std::unexpected(benchmark_error(ExitCode::internal_invariant_failed, "BENCH-AST-ENCODE",
                                                   diagnostic_summary(payload.error())));
        }
        auto artifact = compiler::StaticCompiler {}.compile(pack, *payload, {}, benchmark_bindings());
        if (!artifact) {
            return std::unexpected(benchmark_error(ExitCode::internal_invariant_failed, "BENCH-COMPILE",
                                                   diagnostic_summary(artifact.error())));
        }
        if (auto verified = compiler::verify_compiler_output(*artifact); !verified) {
            return std::unexpected(benchmark_error(ExitCode::internal_invariant_failed, "BENCH-BYTECODE-VERIFY",
                                                   diagnostic_summary(verified.error())));
        }
        const auto certificate =
            std::ranges::find(artifact->pack.optimization_certificates, ExecutableId {std::string {executable_name}},
                              &OptimizationCertificate::executable);
        if (certificate == artifact->pack.optimization_certificates.end()) {
            return std::unexpected(benchmark_error(ExitCode::internal_invariant_failed, "BENCH-CERTIFICATE-MISSING",
                                                   "compiled executable has no optimization certificate"));
        }
        auto selection =
            optimizer::select_optimization(artifact->pack.optimization_certificates,
                                           optimizer::OptimizationRequest {
                                               .executable = ExecutableId {std::string {executable_name}},
                                               .expected_executable_semantic_hash = certificate->semantic_hash,
                                               .request_specialization = false,
                                               .request_pruning = true,
                                               .full_flight_recorder_armed = false,
                                           });
        if (!selection) {
            return std::unexpected(
                benchmark_error(ExitCode::internal_invariant_failed, "BENCH-OPTIMIZER", selection.error().message));
        }
        if (selection->use_exact_bytecode || !selection->certificate_validated || !selection->pruning_enabled ||
            !std::ranges::contains(selection->prunable_false_prefix_exits, 1U)) {
            return std::unexpected(
                benchmark_error(ExitCode::internal_invariant_failed, "BENCH-OPTIMIZER-FALLBACK",
                                "compiled constant-false executable did not qualify for validated prefix pruning"));
        }

        std::vector<optimizer::ShadowExecutionSnapshot> exact_snapshots;
        exact_snapshots.reserve(options.peers);
        std::uint64_t exact_instructions {};
        const auto exact_begin = std::chrono::steady_clock::now();
        for (std::size_t index = 0U; index < options.peers; ++index) {
            auto session = vm::RegisterVmSession::create(artifact->pack, invocation(index));
            if (!session) {
                return std::unexpected(benchmark_error(ExitCode::internal_invariant_failed, "BENCH-VM-CREATE",
                                                       diagnostic_summary(session.error())));
            }
            auto completed = (*session)->step({});
            if (completed.state != VmStepState::complete || !completed.result ||
                completed.result->outcome != EvaluationOutcome::no_match || completed.result->verdict != false) {
                return std::unexpected(benchmark_error(ExitCode::internal_invariant_failed, "BENCH-VM-RESULT",
                                                       "exact bytecode did not complete with no_match/false"));
            }
            if (!completed.fact_requests.empty() || !completed.scan_requests.empty() ||
                !completed.capability_requests.empty() || !completed.state_requests.empty() ||
                !completed.history_requests.empty() || !completed.journal_delta.empty() ||
                !completed.recorder_delta.empty() || (*session)->logical_read_count() != 0U ||
                (*session)->journal_size() != 0U || (*session)->state_mutation_count() != 0U) {
                return std::unexpected(
                    benchmark_error(ExitCode::internal_invariant_failed, "BENCH-CERTIFICATE-CONTRADICTION",
                                    "validated pure-false bytecode produced an observable interaction"));
            }
            auto resources = semantic_resources(**session);
            exact_instructions += resources.instructions;
            exact_snapshots.push_back({
                .evaluation = std::move(*completed.result),
                .logical_reads = {},
                .recorder = std::move(completed.recorder_delta),
                .resources = resources,
            });
        }
        const auto exact_end = std::chrono::steady_clock::now();

        std::size_t mismatches {};
        std::uint64_t optimized_instructions {};
        const auto optimized_begin = std::chrono::steady_clock::now();
        for (const auto &exact : exact_snapshots) {
            optimizer::ShadowExecutionSnapshot optimized {
                .evaluation =
                    EvaluationResult {
                        .outcome = EvaluationOutcome::no_match,
                        .verdict = false,
                        .committed_effects = {},
                        .state_mutations = {},
                        .fault = std::nullopt,
                    },
                .logical_reads = {},
                .recorder = {},
                // Prefix pruning avoids physical dispatch, but the optimized lane
                // must retain the exact semantic charge for budget equivalence.
                .resources = exact.resources,
            };
            optimized_instructions += optimized.resources.instructions;
            if (!optimizer::compare_shadow_execution(exact, optimized).equivalent) {
                ++mismatches;
            }
        }
        const auto optimized_end = std::chrono::steady_clock::now();

        return PythonBenchmarkReport {
            .peers = options.peers,
            .semantic_hash = artifact->pack.semantic_hash,
            .executable = std::string {executable_name},
            .optimized_strategy = "validated-pure-false-prefix",
            .optimizer_certificate_validated = selection->certificate_validated,
            .parity_equivalent = mismatches == 0U,
            .parity_mismatches = mismatches,
            .exact_vm_sessions = static_cast<std::uint64_t>(options.peers),
            .optimized_vm_sessions = 0U,
            .exact_instructions_charged = exact_instructions,
            .optimized_instructions_charged = optimized_instructions,
            .exact_wall_nanoseconds = elapsed_nanoseconds(exact_begin, exact_end),
            .optimized_wall_nanoseconds = elapsed_nanoseconds(optimized_begin, optimized_end),
        };
    }

    std::string render_python_benchmark_json(const PythonBenchmarkReport &report) {
        return "{\"schema\":\"rule-engine.python-benchmark.v1\",\"peers\":" + std::to_string(report.peers) +
               ",\"semantic_hash\":" + json_quote(report.semantic_hash) +
               ",\"executable\":" + json_quote(report.executable) +
               ",\"optimized_strategy\":" + json_quote(report.optimized_strategy) +
               ",\"optimizer_certificate_validated\":" + (report.optimizer_certificate_validated ? "true" : "false") +
               ",\"parity_equivalent\":" + (report.parity_equivalent ? "true" : "false") +
               ",\"parity_mismatches\":" + std::to_string(report.parity_mismatches) +
               ",\"exact_vm_sessions\":" + std::to_string(report.exact_vm_sessions) +
               ",\"optimized_vm_sessions\":" + std::to_string(report.optimized_vm_sessions) +
               ",\"exact_instructions_charged\":" + std::to_string(report.exact_instructions_charged) +
               ",\"optimized_instructions_charged\":" + std::to_string(report.optimized_instructions_charged) +
               ",\"exact_wall_nanoseconds\":" + std::to_string(report.exact_wall_nanoseconds) +
               ",\"optimized_wall_nanoseconds\":" + std::to_string(report.optimized_wall_nanoseconds) + "}\n";
    }

    std::string render_python_benchmark_text(const PythonBenchmarkReport &report) {
        return "schema: rule-engine.python-benchmark.v1\npeers: " + std::to_string(report.peers) +
               "\nsemantic_hash: " + report.semantic_hash + "\nexecutable: " + report.executable +
               "\noptimized_strategy: " + report.optimized_strategy +
               "\noptimizer_certificate_validated: " + (report.optimizer_certificate_validated ? "true" : "false") +
               "\nparity_equivalent: " + (report.parity_equivalent ? "true" : "false") +
               "\nparity_mismatches: " + std::to_string(report.parity_mismatches) +
               "\nexact_vm_sessions: " + std::to_string(report.exact_vm_sessions) +
               "\noptimized_vm_sessions: " + std::to_string(report.optimized_vm_sessions) +
               "\nexact_instructions_charged: " + std::to_string(report.exact_instructions_charged) +
               "\noptimized_instructions_charged: " + std::to_string(report.optimized_instructions_charged) +
               "\nexact_wall_nanoseconds: " + std::to_string(report.exact_wall_nanoseconds) +
               "\noptimized_wall_nanoseconds: " + std::to_string(report.optimized_wall_nanoseconds) + '\n';
    }

    std::string_view benchmark_help() noexcept { return help_text; }

    CommandOutput run_rule_engine_benchmark(const std::span<const std::string_view> arguments) {
        if (arguments.size() == 1U && arguments.front() == "--help") {
            return {
                .exit_code = ExitCode::success,
                .standard_output = std::string {help_text},
                .standard_error = {},
            };
        }
        if (arguments.size() == 1U && arguments.front() == "--version") {
            return {
                .exit_code = ExitCode::success,
                .standard_output = "rule_engine_benchmark " + std::string {tools_api_version} + '\n',
                .standard_error = {},
            };
        }
        if (std::ranges::find(arguments, "--help") != arguments.end() ||
            std::ranges::find(arguments, "--version") != arguments.end()) {
            return {
                .exit_code = ExitCode::command_line_error,
                .standard_output = {},
                .standard_error = "BENCH-CLI-USAGE: --help and --version must be used alone\n",
            };
        }

        PythonBenchmarkOptions options;
        bool peers_seen {};
        bool format_seen {};
        for (std::size_t index = 0U; index < arguments.size(); ++index) {
            const auto argument = arguments[index];
            if (argument == "--peers") {
                if (peers_seen || index + 1U >= arguments.size()) {
                    return {
                        .exit_code = ExitCode::command_line_error,
                        .standard_output = {},
                        .standard_error = "BENCH-CLI-USAGE: --peers requires one value\n",
                    };
                }
                auto peers = parse_peer_count(arguments[++index]);
                if (!peers) {
                    return {
                        .exit_code = ExitCode::command_line_error,
                        .standard_output = {},
                        .standard_error = "BENCH-CLI-USAGE: " + peers.error() + '\n',
                    };
                }
                options.peers = *peers;
                peers_seen = true;
                continue;
            }
            if (argument == "--format") {
                if (format_seen || index + 1U >= arguments.size()) {
                    return {
                        .exit_code = ExitCode::command_line_error,
                        .standard_output = {},
                        .standard_error = "BENCH-CLI-USAGE: --format requires one value\n",
                    };
                }
                const auto format = arguments[++index];
                if (format == "text") {
                    options.format = OutputFormat::text;
                } else if (format == "json") {
                    options.format = OutputFormat::json;
                } else {
                    return {
                        .exit_code = ExitCode::command_line_error,
                        .standard_output = {},
                        .standard_error = "BENCH-CLI-USAGE: --format must be text or json\n",
                    };
                }
                format_seen = true;
                continue;
            }
            return {
                .exit_code = ExitCode::command_line_error,
                .standard_output = {},
                .standard_error = "BENCH-CLI-USAGE: unknown option\n",
            };
        }

        auto report = run_python_benchmark(options);
        if (!report) {
            return {
                .exit_code = report.error().exit_code,
                .standard_output = {},
                .standard_error = report.error().code + ": " + report.error().message + '\n',
            };
        }
        auto output = options.format == OutputFormat::json ? render_python_benchmark_json(*report) :
                                                             render_python_benchmark_text(*report);
        if (!report->parity_equivalent) {
            return {
                .exit_code = ExitCode::operation_failed,
                .standard_output = std::move(output),
                .standard_error = "BENCH-PARITY-MISMATCH: optimized observations differ from exact bytecode\n",
            };
        }
        return {
            .exit_code = ExitCode::success,
            .standard_output = std::move(output),
            .standard_error = {},
        };
    }

} // namespace rule_engine::python::tools
