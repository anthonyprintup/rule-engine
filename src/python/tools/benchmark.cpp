#include "rule_engine/python/tools/benchmark.hpp"

#include "rule_engine/python/cluster/coordinator.hpp"
#include "rule_engine/python/cluster/store.hpp"
#include "rule_engine/python/compiler.hpp"
#include "rule_engine/python/optimizer/optimizer.hpp"
#include "rule_engine/python/packaging/source_pack.hpp"
#include "rule_engine/python/protocol/session.hpp"
#include "rule_engine/python/vm/register_vm.hpp"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace rule_engine::python::tools {
    namespace {

        namespace cluster = rule_engine::python::cluster;
        namespace compiler = rule_engine::python::compiler;
        namespace optimizer = rule_engine::python::optimizer;
        namespace packaging = rule_engine::python::packaging;
        namespace protocol = rule_engine::python::protocol_v2;
        namespace vm = rule_engine::python::vm;

        constexpr std::string_view source_name = "benchmark.rules";
        constexpr std::string_view executable_name = "benchmark.constant_false";
        constexpr std::string_view binding_name = "benchmark-binding";
        constexpr std::size_t maximum_peer_count = 100'000U;
        constexpr std::size_t resident_claim_batch_limit = 512U;
        constexpr std::size_t resident_retry_stride = 100U;
        constexpr std::size_t resident_spool_record_bytes = 80U;

        struct ResidentSimulationMetrics {
            std::uint64_t work_enqueued {};
            std::uint64_t work_committed {};
            std::uint64_t retry_attempts {};
            std::uint64_t stale_fence_rejections {};
            std::uint64_t ordering_violations {};
            std::uint64_t peak_claim_batch {};
            std::uint64_t peak_active_leases {};
            std::uint64_t final_ready_work {};
            std::uint64_t final_active_leases {};
            std::uint64_t backpressure_transitions {};
            std::uint64_t backpressure_clears {};
            std::uint64_t peak_agent_sessions {};
            std::uint64_t peak_pending_records {};
            std::uint64_t peak_pending_bytes {};
            std::uint64_t wall_nanoseconds {};
        };

        constexpr std::string_view help_text = R"(Usage: rule_engine_benchmark [--peers COUNT] [--format text|json]

Compile a deterministic Python rule pack, execute exact register bytecode for
synthetic peers, validate a pure-false optimizer certificate, and compare every
observable exact and optimized result with the shadow-parity contract. Also run
a bounded in-memory resident coordinator/session simulation over the same peer
count. The resident simulation does not open sockets, negotiate TLS, or exercise
SQLite/PostgreSQL drivers and must not be interpreted as network/database scale.

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

        [[nodiscard]] RuntimeTransaction resident_transaction(const cluster::WorkLease &lease) {
            const auto peer_number = std::to_string(lease.work.ingest_position);
            return {
                .input =
                    EventEnvelope {
                        .id = lease.work.event,
                        .schema = SchemaId {"benchmark.resident-event/v1"},
                        .tenant = TenantId {"benchmark"},
                        .peer = PeerId {"synthetic-peer-" + peer_number},
                        .subject = std::nullopt,
                        .producer_unix_ms = lease.work.ingest_position,
                        .ingest_unix_ms = lease.work.ingest_position,
                        .label = DataLabel {},
                        .causation = std::nullopt,
                        .payload =
                            FrozenValue {
                                .value = make_fact(UnicodeValue {.utf8 = lease.work.event.value}),
                                .label = DataLabel {},
                                .canonical_digest = "sha256:benchmark-resident-event-" + peer_number,
                            },
                    },
                .cursor =
                    CursorAdvance {
                        .consumer = lease.work.serial_domain,
                        .expected_position = 0U,
                        .new_position = 1U,
                    },
                .evaluation =
                    EvaluationResult {
                        .outcome = EvaluationOutcome::no_match,
                        .verdict = false,
                        .committed_effects = {},
                        .state_mutations = {},
                        .fault = std::nullopt,
                    },
                .state = {},
                .emitted_events = {},
                .journal = {},
                .outbox = {},
                .fence_token = lease.fence,
            };
        }

        [[nodiscard]] bool resident_ordered_before(const cluster::WorkLease &left, const cluster::WorkLease &right) {
            if (left.work.priority != right.work.priority) {
                return left.work.priority > right.work.priority;
            }
            return std::tie(left.work.ingest_position, left.work.work_id) <=
                   std::tie(right.work.ingest_position, right.work.work_id);
        }

        [[nodiscard]] std::expected<ResidentSimulationMetrics, PythonBenchmarkError>
        run_resident_simulation(const std::size_t peers) {
            const auto begin = std::chrono::steady_clock::now();
            cluster::AuditTrail audit;
            cluster::InMemoryRuntimeStore store {audit};
            cluster::DeterministicWorkCoordinator coordinator {store, audit};
            ResidentSimulationMetrics metrics;

            for (std::size_t index = 0U; index < peers; ++index) {
                const auto ordinal = index + 1U;
                auto queued = coordinator.enqueue(cluster::WorkDefinition {
                    .work_id = "benchmark-work-" + std::to_string(ordinal),
                    .pack = PackId {"benchmark.python"},
                    .generation = 1U,
                    .serial_domain = "benchmark-peer-domain-" + std::to_string(ordinal),
                    .event = EventId {"benchmark-resident-event-" + std::to_string(ordinal)},
                    .priority = static_cast<std::int32_t>(index % 4U),
                    .ingest_position = static_cast<std::uint64_t>(ordinal),
                });
                if (!queued || !*queued) {
                    const auto detail = queued ? "work was unexpectedly deduplicated" : queued.error().message;
                    return std::unexpected(
                        benchmark_error(ExitCode::internal_invariant_failed, "BENCH-RESIDENT-ENQUEUE", detail));
                }
                ++metrics.work_enqueued;
            }

            for (std::size_t index = 0U; index < peers; ++index) {
                const auto ordinal = index + 1U;
                const auto peer = PeerId {"synthetic-peer-" + std::to_string(ordinal)};
                const std::string epoch = "benchmark-agent-epoch-" + std::to_string(ordinal);
                protocol::AgentSessionState session {
                    peer,
                    epoch,
                    protocol::AgentSpoolLimits {
                        .maximum_records = 2U,
                        .maximum_bytes = 256U,
                        .high_water_bytes = 128U,
                        .low_water_bytes = 64U,
                    },
                };
                auto established = session.establish(protocol::ServerHelloMessage {
                    .selected_minor = protocol::initial_minor_version,
                    .session = SessionId {"benchmark-session-" + std::to_string(ordinal)},
                    .peer = peer,
                    .session_fence = 1U,
                    .acknowledged_sequence = 0U,
                    .schemas = {},
                    .capabilities = {},
                    .credit = {.bytes = 256U, .messages = 2U, .work_attempts = 2U, .snapshot_chunks = 0U},
                    .heartbeat_interval_ms = 1'000U,
                });
                if (!established) {
                    return std::unexpected(benchmark_error(ExitCode::internal_invariant_failed,
                                                           "BENCH-RESIDENT-SESSION", established.error().message));
                }
                metrics.peak_agent_sessions = std::max(metrics.peak_agent_sessions, std::uint64_t {1U});

                for (std::uint64_t record = 1U; record <= 2U; ++record) {
                    auto sequence = session.enqueue(
                        protocol::WorkResultMessage {
                            .originating_session = SessionId {"benchmark-session-" + std::to_string(ordinal)},
                            .peer = peer,
                            .originating_session_fence = 1U,
                            .work_id = "benchmark-work-" + std::to_string(ordinal),
                            .attempt_id = "benchmark-attempt-" + std::to_string(record),
                            .work_fence = record,
                            .generation = 1U,
                            .facts = {},
                            .scans = {},
                        },
                        resident_spool_record_bytes);
                    if (!sequence || *sequence != record) {
                        const auto detail = sequence ? "agent sequence was not contiguous" : sequence.error().message;
                        return std::unexpected(
                            benchmark_error(ExitCode::internal_invariant_failed, "BENCH-RESIDENT-SPOOL", detail));
                    }
                }
                metrics.peak_pending_records =
                    std::max(metrics.peak_pending_records, static_cast<std::uint64_t>(session.pending_records()));
                metrics.peak_pending_bytes =
                    std::max(metrics.peak_pending_bytes, static_cast<std::uint64_t>(session.pending_bytes()));
                if (!session.backpressured()) {
                    return std::unexpected(benchmark_error(ExitCode::internal_invariant_failed,
                                                           "BENCH-RESIDENT-BACKPRESSURE",
                                                           "the bounded agent spool did not enter backpressure"));
                }
                ++metrics.backpressure_transitions;

                const auto transmit = session.take_transmit_batch();
                if (transmit.size() != 2U) {
                    return std::unexpected(benchmark_error(ExitCode::internal_invariant_failed, "BENCH-RESIDENT-CREDIT",
                                                           "the bounded credit window did not release two records"));
                }
                auto acknowledged = session.acknowledge(protocol::AckMessage {
                    .agent_epoch = epoch,
                    .acknowledged_through = 2U,
                    .credit = {.bytes = 256U, .messages = 2U, .work_attempts = 2U, .snapshot_chunks = 0U},
                });
                if (!acknowledged || session.backpressured() || session.pending_records() != 0U ||
                    session.pending_bytes() != 0U) {
                    const auto detail = acknowledged ? "agent spool did not drain below its low-water mark" :
                                                       acknowledged.error().message;
                    return std::unexpected(benchmark_error(ExitCode::internal_invariant_failed,
                                                           "BENCH-RESIDENT-BACKPRESSURE-CLEAR", detail));
                }
                ++metrics.backpressure_clears;
            }

            const auto expected_retries = (peers + resident_retry_stride - 1U) / resident_retry_stride;
            const auto maximum_claim_rounds =
                (peers + expected_retries + resident_claim_batch_limit - 1U) / resident_claim_batch_limit + 2U;
            std::size_t claim_rounds {};
            std::uint64_t now_unix_ms {10'000U};
            while (metrics.work_committed < peers) {
                if (++claim_rounds > maximum_claim_rounds) {
                    return std::unexpected(benchmark_error(ExitCode::internal_invariant_failed,
                                                           "BENCH-RESIDENT-PROGRESS",
                                                           "coordinator exceeded its bounded claim-round budget"));
                }
                auto leases = coordinator.claim("benchmark-node", now_unix_ms, 60'000U, resident_claim_batch_limit);
                if (!leases) {
                    return std::unexpected(benchmark_error(ExitCode::internal_invariant_failed, "BENCH-RESIDENT-CLAIM",
                                                           leases.error().message));
                }
                if (leases->empty()) {
                    return std::unexpected(benchmark_error(ExitCode::internal_invariant_failed,
                                                           "BENCH-RESIDENT-PROGRESS",
                                                           "coordinator returned no work before completion"));
                }
                metrics.peak_claim_batch =
                    std::max(metrics.peak_claim_batch, static_cast<std::uint64_t>(leases->size()));
                metrics.peak_active_leases =
                    std::max(metrics.peak_active_leases, static_cast<std::uint64_t>(leases->size()));
                for (std::size_t index = 1U; index < leases->size(); ++index) {
                    if (!resident_ordered_before((*leases)[index - 1U], (*leases)[index])) {
                        ++metrics.ordering_violations;
                    }
                }

                for (const auto &lease : *leases) {
                    auto transaction = resident_transaction(lease);
                    const auto retry_this_attempt =
                        lease.attempt == 1U && (lease.work.ingest_position - 1U) % resident_retry_stride == 0U;
                    if (retry_this_attempt) {
                        auto abandoned = coordinator.abandon(lease, now_unix_ms);
                        if (!abandoned) {
                            return std::unexpected(benchmark_error(ExitCode::internal_invariant_failed,
                                                                   "BENCH-RESIDENT-ABANDON",
                                                                   abandoned.error().message));
                        }
                        ++metrics.retry_attempts;
                        auto stale = coordinator.commit(lease, std::move(transaction), now_unix_ms);
                        if (stale || stale.error().code != StoreErrorCode::stale_fence) {
                            const auto detail =
                                stale ? "an abandoned lease committed successfully" : stale.error().message;
                            return std::unexpected(benchmark_error(ExitCode::internal_invariant_failed,
                                                                   "BENCH-RESIDENT-STALE-FENCE", detail));
                        }
                        ++metrics.stale_fence_rejections;
                        continue;
                    }

                    auto committed = coordinator.commit(lease, std::move(transaction), now_unix_ms);
                    if (!committed) {
                        return std::unexpected(benchmark_error(ExitCode::internal_invariant_failed,
                                                               "BENCH-RESIDENT-COMMIT", committed.error().message));
                    }
                    ++metrics.work_committed;
                }
                ++now_unix_ms;
            }

            for (const auto &work : coordinator.snapshot()) {
                metrics.final_ready_work += work.phase == cluster::WorkPhase::ready ? 1U : 0U;
                metrics.final_active_leases += work.phase == cluster::WorkPhase::leased ? 1U : 0U;
            }
            auto stored = store.inspect();
            if (!stored) {
                return std::unexpected(benchmark_error(ExitCode::internal_invariant_failed, "BENCH-RESIDENT-INSPECT",
                                                       stored.error().message));
            }
            if (metrics.work_enqueued != peers || metrics.work_committed != peers ||
                metrics.retry_attempts != expected_retries || metrics.stale_fence_rejections != expected_retries ||
                metrics.ordering_violations != 0U || metrics.peak_claim_batch > resident_claim_batch_limit ||
                metrics.peak_active_leases > resident_claim_batch_limit || metrics.final_ready_work != 0U ||
                metrics.final_active_leases != 0U || stored->receipts.size() != peers ||
                stored->events.size() != peers || metrics.backpressure_transitions != peers ||
                metrics.backpressure_clears != peers || metrics.peak_agent_sessions > 1U ||
                metrics.peak_pending_records > 2U || metrics.peak_pending_bytes > 2U * resident_spool_record_bytes) {
                return std::unexpected(
                    benchmark_error(ExitCode::internal_invariant_failed, "BENCH-RESIDENT-INVARIANT",
                                    "resident simulation violated a queue, fence, or resource bound"));
            }
            metrics.wall_nanoseconds = elapsed_nanoseconds(begin, std::chrono::steady_clock::now());
            return metrics;
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
        const auto function = std::ranges::find(artifact->pack.functions, ExecutableId {std::string {executable_name}},
                                                &BytecodeFunction::id);
        if (function == artifact->pack.functions.end() || function->instructions.empty() ||
            function->instructions.size() > std::numeric_limits<std::uint32_t>::max()) {
            return std::unexpected(benchmark_error(ExitCode::internal_invariant_failed, "BENCH-BYTECODE-MISSING",
                                                   "compiled executable has no bounded exact bytecode body"));
        }
        auto selection = optimizer::select_optimization(
            artifact->pack.optimization_certificates,
            optimizer::OptimizationRequest {
                .executable = ExecutableId {std::string {executable_name}},
                .expected_executable_semantic_hash = certificate->semantic_hash,
                .request_specialization = false,
                .request_pruning = true,
                .full_flight_recorder_armed = false,
                .exact_instruction_count = static_cast<std::uint32_t>(function->instructions.size()),
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
                .fact_reads = {},
                .logical_reads = {},
                .recorder = std::move(completed.recorder_delta),
                .resources = resources,
                .diagnostics = {},
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
                .fact_reads = {},
                .logical_reads = {},
                .recorder = {},
                // Prefix pruning avoids physical dispatch, but the optimized lane
                // must retain the exact semantic charge for budget equivalence.
                .resources = exact.resources,
                .diagnostics = {},
            };
            optimized_instructions += optimized.resources.instructions;
            if (!optimizer::compare_shadow_execution(exact, optimized).equivalent) {
                ++mismatches;
            }
        }
        const auto optimized_end = std::chrono::steady_clock::now();

        auto resident = run_resident_simulation(options.peers);
        if (!resident) {
            return std::unexpected(std::move(resident.error()));
        }

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
            .resident_simulation_model = "bounded-in-memory-coordinator-and-agent-spool-v1",
            .resident_network_simulated = false,
            .resident_postgresql_simulated = false,
            .resident_work_enqueued = resident->work_enqueued,
            .resident_work_committed = resident->work_committed,
            .resident_retry_attempts = resident->retry_attempts,
            .resident_stale_fence_rejections = resident->stale_fence_rejections,
            .resident_ordering_violations = resident->ordering_violations,
            .resident_claim_batch_limit = resident_claim_batch_limit,
            .resident_peak_claim_batch = resident->peak_claim_batch,
            .resident_peak_active_leases = resident->peak_active_leases,
            .resident_final_ready_work = resident->final_ready_work,
            .resident_final_active_leases = resident->final_active_leases,
            .resident_backpressure_transitions = resident->backpressure_transitions,
            .resident_backpressure_clears = resident->backpressure_clears,
            .resident_peak_agent_sessions = resident->peak_agent_sessions,
            .resident_peak_pending_records = resident->peak_pending_records,
            .resident_peak_pending_bytes = resident->peak_pending_bytes,
            .resident_simulation_wall_nanoseconds = resident->wall_nanoseconds,
        };
    }

    std::string render_python_benchmark_json(const PythonBenchmarkReport &report) {
        return "{\"schema\":\"rule-engine.python-benchmark.v2\",\"peers\":" + std::to_string(report.peers) +
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
               ",\"optimized_wall_nanoseconds\":" + std::to_string(report.optimized_wall_nanoseconds) +
               ",\"resident_simulation_model\":" + json_quote(report.resident_simulation_model) +
               ",\"resident_network_simulated\":" + (report.resident_network_simulated ? "true" : "false") +
               ",\"resident_postgresql_simulated\":" + (report.resident_postgresql_simulated ? "true" : "false") +
               ",\"resident_work_enqueued\":" + std::to_string(report.resident_work_enqueued) +
               ",\"resident_work_committed\":" + std::to_string(report.resident_work_committed) +
               ",\"resident_retry_attempts\":" + std::to_string(report.resident_retry_attempts) +
               ",\"resident_stale_fence_rejections\":" + std::to_string(report.resident_stale_fence_rejections) +
               ",\"resident_ordering_violations\":" + std::to_string(report.resident_ordering_violations) +
               ",\"resident_claim_batch_limit\":" + std::to_string(report.resident_claim_batch_limit) +
               ",\"resident_peak_claim_batch\":" + std::to_string(report.resident_peak_claim_batch) +
               ",\"resident_peak_active_leases\":" + std::to_string(report.resident_peak_active_leases) +
               ",\"resident_final_ready_work\":" + std::to_string(report.resident_final_ready_work) +
               ",\"resident_final_active_leases\":" + std::to_string(report.resident_final_active_leases) +
               ",\"resident_backpressure_transitions\":" + std::to_string(report.resident_backpressure_transitions) +
               ",\"resident_backpressure_clears\":" + std::to_string(report.resident_backpressure_clears) +
               ",\"resident_peak_agent_sessions\":" + std::to_string(report.resident_peak_agent_sessions) +
               ",\"resident_peak_pending_records\":" + std::to_string(report.resident_peak_pending_records) +
               ",\"resident_peak_pending_bytes\":" + std::to_string(report.resident_peak_pending_bytes) +
               ",\"resident_simulation_wall_nanoseconds\":" +
               std::to_string(report.resident_simulation_wall_nanoseconds) + "}\n";
    }

    std::string render_python_benchmark_text(const PythonBenchmarkReport &report) {
        return "schema: rule-engine.python-benchmark.v2\npeers: " + std::to_string(report.peers) +
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
               "\noptimized_wall_nanoseconds: " + std::to_string(report.optimized_wall_nanoseconds) +
               "\nresident_simulation_model: " + report.resident_simulation_model +
               "\nresident_network_simulated: " + (report.resident_network_simulated ? "true" : "false") +
               "\nresident_postgresql_simulated: " + (report.resident_postgresql_simulated ? "true" : "false") +
               "\nresident_work_enqueued: " + std::to_string(report.resident_work_enqueued) +
               "\nresident_work_committed: " + std::to_string(report.resident_work_committed) +
               "\nresident_retry_attempts: " + std::to_string(report.resident_retry_attempts) +
               "\nresident_stale_fence_rejections: " + std::to_string(report.resident_stale_fence_rejections) +
               "\nresident_ordering_violations: " + std::to_string(report.resident_ordering_violations) +
               "\nresident_claim_batch_limit: " + std::to_string(report.resident_claim_batch_limit) +
               "\nresident_peak_claim_batch: " + std::to_string(report.resident_peak_claim_batch) +
               "\nresident_peak_active_leases: " + std::to_string(report.resident_peak_active_leases) +
               "\nresident_final_ready_work: " + std::to_string(report.resident_final_ready_work) +
               "\nresident_final_active_leases: " + std::to_string(report.resident_final_active_leases) +
               "\nresident_backpressure_transitions: " + std::to_string(report.resident_backpressure_transitions) +
               "\nresident_backpressure_clears: " + std::to_string(report.resident_backpressure_clears) +
               "\nresident_peak_agent_sessions: " + std::to_string(report.resident_peak_agent_sessions) +
               "\nresident_peak_pending_records: " + std::to_string(report.resident_peak_pending_records) +
               "\nresident_peak_pending_bytes: " + std::to_string(report.resident_peak_pending_bytes) +
               "\nresident_simulation_wall_nanoseconds: " +
               std::to_string(report.resident_simulation_wall_nanoseconds) + '\n';
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
