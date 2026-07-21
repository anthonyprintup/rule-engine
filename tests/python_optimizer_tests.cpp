#include "rule_engine/python/optimizer/optimizer.hpp"
#include "rule_engine/python/optimizer/scan_wire.hpp"
#include "rule_engine/python/optimizer/scanner.hpp"
#include "rule_engine/python/protocol.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace {

    using namespace rule_engine::python;
    using namespace rule_engine::python::optimizer;

    template<typename Type>
    concept HasPredicate = requires(Type value) { value.predicate; };

    template<typename Type>
    concept HasVerdict = requires(Type value) { value.verdict; };

    static_assert(!HasPredicate<ProviderScanRequest>);
    static_assert(!HasVerdict<ProviderScanRequest>);
    static_assert(!HasPredicate<ScanRequest>);
    static_assert(!HasVerdict<ScanResponse>);

    SourceSpan source_span() {
        return SourceSpan {.source = SourceId {"rules.main"}, .begin_byte = 10, .end_byte = 20};
    }

    OptimizationCertificate pure_certificate() {
        return OptimizationCertificate {
            .executable = ExecutableId {"rule.one"},
            .transitively_pure = true,
            .recorder_observable = false,
            .may_fault = false,
            .reads_state = false,
            .reads_history = false,
            .calls_services = false,
            .emits_effects = false,
            .emits_events = false,
            .logical_facts = {},
            .pure_false_prefix_exits = {3, 9},
            .semantic_hash = "sha256:rule-one",
        };
    }

    OptimizationRequest optimization_request() {
        return OptimizationRequest {
            .executable = ExecutableId {"rule.one"},
            .expected_executable_semantic_hash = "sha256:rule-one",
            .request_specialization = true,
            .request_pruning = true,
            .full_flight_recorder_armed = false,
            .exact_instruction_count = 10,
        };
    }

    FrozenValue frozen(std::string digest) {
        return FrozenValue {
            .value = {},
            .label = DataLabel {},
            .canonical_digest = std::move(digest),
        };
    }

    std::vector<std::byte> bytes(const std::string_view text) {
        std::vector<std::byte> result;
        result.reserve(text.size());
        for (const char value : text) { result.push_back(static_cast<std::byte>(static_cast<unsigned char>(value))); }
        return result;
    }

    std::vector<std::uint64_t> reference_literal_offsets(const std::span<const std::byte> source,
                                                         const std::span<const std::byte> pattern) {
        std::vector<std::uint64_t> result;
        if (pattern.empty() || pattern.size() > source.size()) {
            return result;
        }
        for (std::size_t offset = 0; offset <= source.size() - pattern.size(); ++offset) {
            if (std::ranges::equal(source.subspan(offset, pattern.size()), pattern)) {
                result.push_back(static_cast<std::uint64_t>(offset));
            }
        }
        return result;
    }

    std::uint32_t next_pseudo_random(std::uint32_t &state) noexcept {
        state = state * 1'664'525U + 1'013'904'223U;
        return state;
    }

    ExplicitScanSpace file_space(const std::uint64_t begin, const std::uint64_t size) {
        return ExplicitScanSpace {
            .identity = "process.image.file",
            .kind = ScanSpaceKind::image_file,
            .begin = begin,
            .size = size,
            .permissions = scan_permission_read,
            .label = DataLabel {.classification = Classification::sensitive, .categories = {"endpoint", "malware"}},
            .subject_generation = 7,
        };
    }

    TypedScanPlan plan_with(StaticScanPattern pattern, const std::uint64_t maximum_bytes = 1'024,
                            const std::uint32_t maximum_matches = 64) {
        return TypedScanPlan {
            .plan_id = "plan.one",
            .patterns = {std::move(pattern)},
            .maximum_bytes = maximum_bytes,
            .maximum_matches = maximum_matches,
            .context_bytes_before = 1,
            .context_bytes_after = 1,
            .result_mode = ScanResultMode::exact_complete,
        };
    }

    void check_same_match(const TypedScanMatch &actual, const TypedScanMatch &expected) {
        CHECK(actual.pattern_id == expected.pattern_id);
        CHECK(actual.scan_space_identity == expected.scan_space_identity);
        CHECK(actual.offset == expected.offset);
        CHECK(actual.absolute_address == expected.absolute_address);
        CHECK(actual.length == expected.length);
        CHECK(actual.permissions == expected.permissions);
        CHECK(actual.matched_bytes == expected.matched_bytes);
        CHECK(actual.context_before == expected.context_before);
        CHECK(actual.context_after == expected.context_after);
        CHECK(actual.label == expected.label);
        CHECK(actual.subject_generation == expected.subject_generation);
    }

    TEST_CASE("optimizer enables pruning only for a bound pure certificate") {
        const auto certificate = pure_certificate();
        const std::vector certificates {certificate};

        const auto selected = select_optimization(certificates, optimization_request());

        REQUIRE(selected.has_value());
        CHECK_FALSE(selected->use_exact_bytecode);
        CHECK(selected->certificate_known);
        CHECK(selected->certificate_validated);
        CHECK(selected->specialization_enabled);
        CHECK(selected->pruning_enabled);
        CHECK(selected->prunable_false_prefix_exits == std::vector<std::uint32_t> {3, 9});
        CHECK(selected->fallback_reason == ExactFallbackReason::none);

        auto specialization_request = optimization_request();
        specialization_request.request_pruning = false;
        const auto specialization = select_optimization(certificates, specialization_request);
        REQUIRE(specialization.has_value());
        CHECK_FALSE(specialization->use_exact_bytecode);
        CHECK(specialization->specialization_enabled);
        CHECK_FALSE(specialization->pruning_enabled);

        auto pruning_request = optimization_request();
        pruning_request.request_specialization = false;
        const auto pruning = select_optimization(certificates, pruning_request);
        REQUIRE(pruning.has_value());
        CHECK_FALSE(pruning->use_exact_bytecode);
        CHECK_FALSE(pruning->specialization_enabled);
        CHECK(pruning->pruning_enabled);
    }

    TEST_CASE("every observable or uncertain certificate property forces exact VM execution") {
        struct UnsafeCase {
            OptimizationCertificate certificate;
            ExactFallbackReason reason;
        };
        std::vector<UnsafeCase> cases;
        auto add_case = [&cases](const ExactFallbackReason reason, auto mutate) {
            auto certificate = pure_certificate();
            mutate(certificate);
            cases.push_back(UnsafeCase {.certificate = std::move(certificate), .reason = reason});
        };
        add_case(ExactFallbackReason::certificate_reads_state,
                 [](OptimizationCertificate &certificate) { certificate.reads_state = true; });
        add_case(ExactFallbackReason::certificate_calls_services,
                 [](OptimizationCertificate &certificate) { certificate.calls_services = true; });
        add_case(ExactFallbackReason::certificate_emits_effects,
                 [](OptimizationCertificate &certificate) { certificate.emits_effects = true; });
        add_case(ExactFallbackReason::certificate_emits_events,
                 [](OptimizationCertificate &certificate) { certificate.emits_events = true; });
        add_case(ExactFallbackReason::certificate_recorder_observable,
                 [](OptimizationCertificate &certificate) { certificate.recorder_observable = true; });
        add_case(ExactFallbackReason::certificate_reads_history,
                 [](OptimizationCertificate &certificate) { certificate.reads_history = true; });
        add_case(ExactFallbackReason::certificate_may_fault,
                 [](OptimizationCertificate &certificate) { certificate.may_fault = true; });
        add_case(ExactFallbackReason::certificate_has_logical_reads,
                 [](OptimizationCertificate &certificate) { certificate.logical_facts = {"process.name"}; });
        add_case(ExactFallbackReason::certificate_not_transitively_pure,
                 [](OptimizationCertificate &certificate) { certificate.transitively_pure = false; });

        for (const auto &test : cases) {
            CAPTURE(test.reason);
            const std::array certificates {test.certificate};
            const auto selected = select_optimization(certificates, optimization_request());
            REQUIRE(selected.has_value());
            CHECK(selected->use_exact_bytecode);
            CHECK_FALSE(selected->specialization_enabled);
            CHECK_FALSE(selected->pruning_enabled);
            CHECK(selected->fallback_reason == test.reason);
        }

        auto recorder_request = optimization_request();
        recorder_request.full_flight_recorder_armed = true;
        const std::array certificates {pure_certificate()};
        const auto recorder_selection = select_optimization(certificates, recorder_request);
        REQUIRE(recorder_selection.has_value());
        CHECK(recorder_selection->use_exact_bytecode);
        CHECK(recorder_selection->fallback_reason == ExactFallbackReason::recorder_policy_requires_exact);

        const auto missing = select_optimization({}, optimization_request());
        REQUIRE(missing.has_value());
        CHECK(missing->use_exact_bytecode);
        CHECK(missing->fallback_reason == ExactFallbackReason::certificate_missing);
    }

    TEST_CASE("pruning requires canonical in-bounds compiler-certified pure-prefix exits") {
        auto pruning_request = optimization_request();
        pruning_request.request_specialization = false;

        auto no_prefix = pure_certificate();
        no_prefix.pure_false_prefix_exits.clear();
        auto selected = select_optimization(std::array {no_prefix}, optimization_request());
        REQUIRE(selected.has_value());
        CHECK(selected->use_exact_bytecode);
        CHECK_FALSE(selected->specialization_enabled);
        CHECK(selected->fallback_reason == ExactFallbackReason::certificate_has_no_pure_prefix);
        selected = select_optimization(std::array {no_prefix}, pruning_request);
        REQUIRE(selected.has_value());
        CHECK(selected->use_exact_bytecode);
        CHECK(selected->fallback_reason == ExactFallbackReason::certificate_has_no_pure_prefix);

        auto noncanonical = pure_certificate();
        noncanonical.pure_false_prefix_exits = {9, 3};
        selected = select_optimization(std::array {noncanonical}, pruning_request);
        REQUIRE(selected.has_value());
        CHECK(selected->use_exact_bytecode);
        CHECK_FALSE(selected->certificate_validated);
        CHECK(selected->fallback_reason == ExactFallbackReason::certificate_noncanonical);

        auto out_of_bounds = pure_certificate();
        out_of_bounds.pure_false_prefix_exits = {3, 10};
        selected = select_optimization(std::array {out_of_bounds}, pruning_request);
        REQUIRE(selected.has_value());
        CHECK(selected->use_exact_bytecode);
        CHECK_FALSE(selected->certificate_validated);
        CHECK(selected->fallback_reason == ExactFallbackReason::certificate_prefix_out_of_bounds);
    }

    TEST_CASE("certificate semantic hash mismatch falls back to exact bytecode") {
        const std::vector certificates {pure_certificate()};
        auto request = optimization_request();
        request.expected_executable_semantic_hash = "sha256:different";

        const auto selected = select_optimization(certificates, request);

        REQUIRE(selected.has_value());
        CHECK(selected->use_exact_bytecode);
        CHECK(selected->certificate_known);
        CHECK_FALSE(selected->certificate_validated);
        CHECK(selected->fallback_reason == ExactFallbackReason::certificate_semantic_hash_mismatch);

        const auto validation = validate_optimization_certificate(certificates.front(), request.executable,
                                                                  request.expected_executable_semantic_hash,
                                                                  request.exact_instruction_count);
        REQUIRE_FALSE(validation.has_value());
        CHECK(validation.error().code == OptimizerErrorCode::certificate_semantic_hash_mismatch);
    }

    TEST_CASE("shadow parity compares every committable observation and redacts values") {
        ShadowExecutionSnapshot exact {
            .evaluation =
                EvaluationResult {
                    .outcome = EvaluationOutcome::match,
                    .verdict = true,
                    .committed_effects = {{.id = IntentId {"intent-1"},
                                           .invocation = InvocationId {"invocation-1"},
                                           .owner = ExecutableId {"rule.one"},
                                           .binding = BindingId {"binding.one"},
                                           .sequence = 1,
                                           .kind = "post",
                                           .payload = frozen("sha256:effect"),
                                           .span = source_span(),
                                           .policy = EffectPolicySnapshot {.policy_id = "policy",
                                                                           .policy_digest = "sha256:policy",
                                                                           .sink_ceiling = DataLabel {},
                                                                           .dry_run = false},
                                           .disposition = EffectDisposition::committed,
                                           .idempotency_key = "intent-key"}},
                    .committed_events = {{.id = IntentId {"event-intent-1"},
                                          .root_event = EventId {"root-event"},
                                          .invocation = InvocationId {"invocation-1"},
                                          .owner = ExecutableId {"rule.one"},
                                          .binding = BindingId {"binding.one"},
                                          .sequence = 1,
                                          .schema = SchemaId {"alert/v1"},
                                          .schema_hash = "sha256:alert-v1",
                                          .payload = frozen("sha256:event"),
                                          .span = source_span(),
                                          .disposition = EventDisposition::committed}},
                    .state_mutations = {{.owner = ExecutableId {"rule.one"},
                                         .namespace_name = "binding.one",
                                         .key = "counter",
                                         .expected_version = 4,
                                         .value = frozen("sha256:state")}},
                    .fault = FaultChain {.frames = {{.code = "Fault",
                                                     .message = "secret detail",
                                                     .executable = ExecutableId {"rule.one"},
                                                     .span = source_span()}},
                                         .double_fault = false,
                                         .triple_fault = false},
                },
            .fact_reads = {{.sequence = 1,
                            .subject_key_digest = "sha256:subject",
                            .route = FactRoute {.provider = "process", .fact = "signer"},
                            .schema = SchemaId {"signer/v1"},
                            .status = FactTerminalStatus::value,
                            .label = DataLabel {},
                            .value_digest = "sha256:value"}},
            .logical_reads = {{.sequence = 1,
                               .subject_key_digest = "sha256:subject",
                               .route = FactRoute {.provider = "process", .fact = "signer"},
                               .schema = SchemaId {"signer/v1"},
                               .status = FactTerminalStatus::value,
                               .span = source_span(),
                               .label = DataLabel {},
                               .value_digest = "sha256:value"}},
            .recorder =
                {{.sequence = 1, .kind = "branch", .span = source_span(), .label = DataLabel {}, .summary = "taken"}},
            .resources =
                SemanticResourceCounters {
                    .instructions = 100, .logical_facts = 1, .effect_intents = 1, .event_intents = 1},
            .diagnostics = {{.code = "RuleFault",
                             .severity = DiagnosticSeverity::error,
                             .message = "secret diagnostic",
                             .span = source_span(),
                             .related = {{.span = source_span(), .message = "secret relation"}}}},
        };
        ShadowExecutionSnapshot optimized {
            .evaluation =
                EvaluationResult {
                    .outcome = EvaluationOutcome::no_match,
                    .verdict = false,
                    .committed_effects = {},
                    .committed_events = {},
                    .state_mutations = {},
                    .fault = std::nullopt,
                },
            .fact_reads = {},
            .logical_reads = {},
            .recorder = {},
            .resources = {},
            .diagnostics = {},
        };

        const auto mismatch = compare_shadow_execution(exact, optimized);

        CHECK_FALSE(mismatch.equivalent);
        CHECK(mismatch.exact_result_is_only_committable);
        CHECK(mismatch.disable_optimized_executable);
        CHECK(mismatch.mismatch_dimension_count == 11);
        CHECK(mismatch.mismatches.size() == 11);
        CHECK_FALSE(mismatch.mismatch_data_truncated);
        std::vector<ShadowParityDimension> mismatch_dimensions;
        std::ranges::transform(mismatch.mismatches, std::back_inserter(mismatch_dimensions),
                               &RedactedShadowMismatch::dimension);
        CHECK(mismatch_dimensions ==
              std::vector {ShadowParityDimension::outcome, ShadowParityDimension::verdict,
                           ShadowParityDimension::fact_reads, ShadowParityDimension::logical_reads,
                           ShadowParityDimension::ordered_effects, ShadowParityDimension::ordered_events,
                           ShadowParityDimension::state, ShadowParityDimension::recorder, ShadowParityDimension::fault,
                           ShadowParityDimension::budgets, ShadowParityDimension::diagnostics});

        const auto parity = compare_shadow_execution(exact, exact);
        CHECK(parity.equivalent);
        CHECK_FALSE(parity.disable_optimized_executable);
        CHECK(parity.mismatches.empty());

        auto changed_fact = exact;
        changed_fact.fact_reads.front().value_digest = "sha256:other";
        const auto fact_mismatch = compare_shadow_execution(exact, changed_fact);
        REQUIRE(fact_mismatch.mismatches.size() == 1);
        CHECK(fact_mismatch.mismatches.front().dimension == ShadowParityDimension::fact_reads);
        auto changed_diagnostic = exact;
        changed_diagnostic.diagnostics.front().related.front().message = "other";
        const auto diagnostic_mismatch = compare_shadow_execution(exact, changed_diagnostic);
        REQUIRE(diagnostic_mismatch.mismatches.size() == 1);
        CHECK(diagnostic_mismatch.mismatches.front().dimension == ShadowParityDimension::diagnostics);
        auto ordered_exact = exact;
        auto second_effect = ordered_exact.evaluation.committed_effects.front();
        second_effect.id = IntentId {"intent-2"};
        second_effect.sequence = 2;
        second_effect.idempotency_key = "intent-key-2";
        ordered_exact.evaluation.committed_effects.push_back(second_effect);
        auto reordered_effects = ordered_exact;
        std::ranges::swap(reordered_effects.evaluation.committed_effects[0],
                          reordered_effects.evaluation.committed_effects[1]);
        const auto effect_order_mismatch = compare_shadow_execution(ordered_exact, reordered_effects);
        REQUIRE(effect_order_mismatch.mismatches.size() == 1);
        CHECK(effect_order_mismatch.mismatches.front().dimension == ShadowParityDimension::ordered_effects);
        CHECK(effect_order_mismatch.mismatches.front().first_difference_index == 0);

        auto ordered_events = exact;
        auto second_event = ordered_events.evaluation.committed_events.front();
        second_event.id = IntentId {"event-intent-2"};
        second_event.sequence = 2;
        ordered_events.evaluation.committed_events.push_back(second_event);
        auto reordered_events = ordered_events;
        std::ranges::swap(reordered_events.evaluation.committed_events[0],
                          reordered_events.evaluation.committed_events[1]);
        const auto event_order_mismatch = compare_shadow_execution(ordered_events, reordered_events);
        REQUIRE(event_order_mismatch.mismatches.size() == 1);
        CHECK(event_order_mismatch.mismatches.front().dimension == ShadowParityDimension::ordered_events);
        CHECK(event_order_mismatch.mismatches.front().first_difference_index == 0);

        const auto limited =
            compare_shadow_execution(exact, optimized, ShadowParityLimits {.maximum_mismatch_records = 2});
        CHECK(limited.mismatch_dimension_count == 11);
        CHECK(limited.mismatches.size() == 2);
        CHECK(limited.mismatch_data_truncated);
    }

    TEST_CASE("10000-peer optimizer qualification benchmark is bounded and parity clean") {
        constexpr std::size_t peer_count = 10'000;
        constexpr std::size_t maximum_prefixes_per_plan = 2;
        constexpr std::size_t maximum_patterns_per_plan = 1;
        constexpr std::size_t maximum_requests_per_peer = 1;
        constexpr std::size_t maximum_results_per_request = 1;

        const auto pattern = make_byte_pattern("mz", bytes("MZ"));
        REQUIRE(pattern.has_value());
        const auto source = bytes("xMZyMZz");
        const auto certificate = pure_certificate();
        const std::array certificates {certificate};

        std::size_t qualification_failures {};
        std::size_t observable_mismatches {};
        std::size_t total_plans {};
        std::size_t maximum_prefixes {};
        std::size_t maximum_patterns {};
        std::size_t total_requests {};
        std::size_t maximum_requests {};
        std::size_t total_results {};
        std::size_t maximum_results {};
        std::size_t exact_internal_results {};
        std::uint64_t deterministic_digest {};

        for (std::size_t peer_index = 0; peer_index < peer_count; ++peer_index) {
            const auto selection = select_optimization(certificates, optimization_request());
            if (!selection || selection->use_exact_bytecode || !selection->pruning_enabled ||
                selection->prunable_false_prefix_exits.size() != 2 || selection->prunable_false_prefix_exits[0] != 3 ||
                selection->prunable_false_prefix_exits[1] != 9) {
                ++qualification_failures;
                continue;
            }
            ++total_plans;
            maximum_prefixes = std::max(maximum_prefixes, selection->prunable_false_prefix_exits.size());

            auto exact_plan = plan_with(*pattern, source.size(), 4);
            exact_plan.context_bytes_before = 1;
            exact_plan.context_bytes_after = 1;
            auto optimized_plan = exact_plan;
            optimized_plan.result_mode = ScanResultMode::existential;
            maximum_patterns = std::max(maximum_patterns, optimized_plan.patterns.size());

            auto space = file_space(0, source.size());
            space.subject_generation = peer_index + 1;
            const auto exact_matches = execute_scan(space, exact_plan, source);
            if (!exact_matches || exact_matches->count() != 2) {
                ++qualification_failures;
                continue;
            }
            exact_internal_results += exact_matches->count();

            const auto peer_suffix = std::to_string(peer_index + 1);
            ProviderScanRequest provider_request {
                .request_id = RequestId {"scan-" + peer_suffix},
                .subject =
                    SubjectKey {.peer = PeerId {"peer-" + peer_suffix},
                                .descriptor = SchemaId {"process/v1"},
                                .identity = {{.field_id = 1, .value = static_cast<std::uint64_t>(peer_index + 1)}},
                                .parent = {}},
                .space = space,
                .plan = optimized_plan,
                .deadline_unix_ms = 5'000,
            };
            const auto wire_request = to_contract_scan_request(provider_request);
            if (!wire_request) {
                ++qualification_failures;
                continue;
            }
            ++total_requests;
            maximum_requests = std::max(maximum_requests, std::size_t {1});
            const auto restored_request = from_contract_scan_request(*wire_request);
            if (!restored_request || restored_request->plan.patterns.size() > maximum_patterns_per_plan) {
                ++qualification_failures;
                continue;
            }

            const auto witness = execute_scan(restored_request->space, restored_request->plan, source);
            if (!witness || witness->count() != 1) {
                ++qualification_failures;
                continue;
            }
            const auto wire_response = to_contract_scan_response(*restored_request, *witness);
            if (!wire_response) {
                ++qualification_failures;
                continue;
            }
            const auto restored_witness = from_contract_scan_response(*restored_request, *wire_response);
            if (!restored_witness) {
                ++qualification_failures;
                continue;
            }
            total_results += restored_witness->count();
            maximum_results = std::max(maximum_results, restored_witness->count());

            const auto verdict = exact_matches->exists();
            const LogicalReadObservation logical_read {
                .sequence = 1,
                .subject_key_digest = "peer-digest-" + peer_suffix,
                .route = FactRoute {.provider = "scan", .fact = "mz.exists"},
                .schema = SchemaId {"bool/v1"},
                .status = FactTerminalStatus::value,
                .span = source_span(),
                .label = space.label,
                .value_digest = verdict ? "bool:true" : "bool:false",
            };
            const SemanticResourceCounters semantic_budget {
                .instructions = 64,
                .logical_facts = 1,
                .provider_rounds = 1,
                .fact_bytes = source.size(),
            };
            const ShadowExecutionSnapshot exact_snapshot {
                .evaluation =
                    EvaluationResult {
                        .outcome = verdict ? EvaluationOutcome::match : EvaluationOutcome::no_match,
                        .verdict = verdict,
                        .committed_effects = {},
                        .committed_events = {},
                        .state_mutations = {},
                        .fault = std::nullopt,
                    },
                .fact_reads = {},
                .logical_reads = {logical_read},
                .recorder = {},
                .resources = semantic_budget,
                .diagnostics = {},
            };
            auto optimized_snapshot = exact_snapshot;
            optimized_snapshot.evaluation.verdict = restored_witness->exists();
            optimized_snapshot.evaluation.outcome =
                restored_witness->exists() ? EvaluationOutcome::match : EvaluationOutcome::no_match;
            if (!compare_shadow_execution(exact_snapshot, optimized_snapshot).equivalent) {
                ++observable_mismatches;
            }
            deterministic_digest +=
                static_cast<std::uint64_t>(peer_index + 1) * (restored_witness->matches.front().offset + 1);
        }

        CHECK(qualification_failures == 0);
        CHECK(observable_mismatches == 0);
        CHECK(total_plans == peer_count);
        CHECK(maximum_prefixes <= maximum_prefixes_per_plan);
        CHECK(maximum_patterns <= maximum_patterns_per_plan);
        CHECK(total_requests == peer_count * maximum_requests_per_peer);
        CHECK(maximum_requests <= maximum_requests_per_peer);
        CHECK(total_results == peer_count * maximum_results_per_request);
        CHECK(maximum_results <= maximum_results_per_request);
        CHECK(exact_internal_results == peer_count * 2);
        CHECK(deterministic_digest == 100'010'000);
    }

    TEST_CASE("typed byte scans return exact deterministic offsets and bounded context") {
        const auto source = bytes("xMZyMZz");
        const auto literal_bytes = bytes("MZ");
        const auto pattern = make_byte_pattern("mz", literal_bytes);
        REQUIRE(pattern.has_value());
        const auto plan = plan_with(*pattern);

        const auto matches = execute_scan(file_space(0x1000, source.size()), plan, source, 0x1000);

        REQUIRE(matches.has_value());
        REQUIRE(matches->count() == 2);
        CHECK(matches->exists());
        CHECK(matches->matches[0].offset == 1);
        CHECK(matches->matches[0].absolute_address == 0x1001);
        CHECK(matches->matches[0].length == 2);
        CHECK(matches->matches[0].permissions == scan_permission_read);
        CHECK(matches->matches[0].matched_bytes == bytes("MZ"));
        CHECK(matches->matches[0].context_before == bytes("x"));
        CHECK(matches->matches[0].context_after == bytes("y"));
        CHECK(matches->matches[0].label == file_space(0x1000, source.size()).label);
        CHECK(matches->matches[0].subject_generation == 7);
        CHECK(matches->matches[1].offset == 4);
    }

    TEST_CASE("typed scanning preserves metadata for every explicit scan space") {
        const auto source = bytes("xMZy");
        const auto pattern = make_byte_pattern("mz", bytes("MZ"));
        REQUIRE(pattern.has_value());
        const std::array kinds {ScanSpaceKind::image_file, ScanSpaceKind::mapped_image, ScanSpaceKind::mapped_section,
                                ScanSpaceKind::readable_memory};
        for (const auto kind : kinds) {
            CAPTURE(kind);
            auto space = file_space(0x8000, source.size());
            space.kind = kind;
            space.identity = "typed.space";
            space.permissions = scan_permission_read | scan_permission_execute;
            const auto matches = execute_scan(space, plan_with(*pattern), source, 0x8000);
            REQUIRE(matches.has_value());
            REQUIRE(matches->count() == 1);
            CHECK(matches->matches.front().scan_space_identity == space.identity);
            CHECK(matches->matches.front().absolute_address == 0x8001);
            CHECK(matches->matches.front().permissions == space.permissions);
            CHECK(matches->matches.front().matched_bytes == bytes("MZ"));
            CHECK(matches->matches.front().context_before == bytes("x"));
            CHECK(matches->matches.front().context_after == bytes("y"));
            CHECK(matches->matches.front().label == space.label);
            CHECK(matches->matches.front().subject_generation == space.subject_generation);
        }
    }

    TEST_CASE("literal scanner matches a deterministic reference across bounded generated inputs") {
        std::uint32_t random_state {0xC0FFEEU};
        for (std::size_t iteration = 0; iteration < 256; ++iteration) {
            CAPTURE(iteration);
            const auto source_size = std::size_t {1} + next_pseudo_random(random_state) % 128U;
            const auto pattern_size = std::min(source_size, std::size_t {1} + next_pseudo_random(random_state) % 8U);
            std::vector<std::byte> source(source_size);
            std::vector<std::byte> pattern(pattern_size);
            for (auto &value : source) { value = static_cast<std::byte>(next_pseudo_random(random_state) & 0xFFU); }
            for (auto &value : pattern) { value = static_cast<std::byte>(next_pseudo_random(random_state) & 0xFFU); }
            const auto insertion = next_pseudo_random(random_state) % (source_size - pattern_size + 1U);
            std::ranges::copy(pattern, source.begin() + static_cast<std::ptrdiff_t>(insertion));

            const auto compiled = make_byte_pattern("generated", pattern);
            REQUIRE(compiled.has_value());
            const auto result =
                execute_scan(file_space(0, source.size()), plan_with(*compiled, source.size(), 256), source);
            REQUIRE(result.has_value());

            std::vector<std::uint64_t> actual;
            actual.reserve(result->matches.size());
            for (const auto &match : result->matches) { actual.push_back(match.offset); }
            CHECK(actual == reference_literal_offsets(source, pattern));
        }
    }

    TEST_CASE("literal scanning preserves overlapping matches") {
        const auto source = bytes("aaaa");
        const auto literal = bytes("aa");
        const auto pattern = make_byte_pattern("overlap", literal);
        REQUIRE(pattern.has_value());

        const auto matches = execute_scan(file_space(0, source.size()), plan_with(*pattern), source);

        REQUIRE(matches.has_value());
        REQUIRE(matches->count() == 3);
        CHECK(matches->matches[0].offset == 0);
        CHECK(matches->matches[1].offset == 1);
        CHECK(matches->matches[2].offset == 2);
    }

    TEST_CASE("scan spaces enforce explicit source and plan bounds") {
        const auto source = bytes("xxMZxx");
        const auto literal_bytes = bytes("MZ");
        const auto pattern = make_byte_pattern("mz", literal_bytes);
        REQUIRE(pattern.has_value());

        SECTION("bounded subspace offsets are relative and addresses are absolute") {
            const auto matches = execute_scan(file_space(102, 2), plan_with(*pattern), source, 100);
            REQUIRE(matches.has_value());
            REQUIRE(matches->count() == 1);
            CHECK(matches->matches.front().offset == 0);
            CHECK(matches->matches.front().absolute_address == 102);
        }

        SECTION("space outside provided source fails closed") {
            const auto matches = execute_scan(file_space(99, 2), plan_with(*pattern), source, 100);
            REQUIRE_FALSE(matches.has_value());
            CHECK(matches.error().code == ScanErrorCode::space_out_of_bounds);
        }

        SECTION("space above plan byte budget fails before scanning") {
            const auto matches = execute_scan(file_space(100, source.size()), plan_with(*pattern, 2), source, 100);
            REQUIRE_FALSE(matches.has_value());
            CHECK(matches.error().code == ScanErrorCode::byte_budget_exceeded);
        }

        SECTION("space generation and label are mandatory canonical attribution") {
            auto missing_generation = file_space(100, source.size());
            missing_generation.subject_generation = 0;
            CHECK_FALSE(execute_scan(missing_generation, plan_with(*pattern), source, 100).has_value());

            auto noncanonical_label = file_space(100, source.size());
            noncanonical_label.label.categories = {"z", "a"};
            CHECK_FALSE(execute_scan(noncanonical_label, plan_with(*pattern), source, 100).has_value());
        }
    }

    TEST_CASE("complete MatchSet never hides result truncation") {
        const auto source = bytes("aaaa");
        const auto literal_bytes = bytes("a");
        const auto pattern = make_byte_pattern("a", literal_bytes);
        REQUIRE(pattern.has_value());

        const auto matches = execute_scan(file_space(0, source.size()), plan_with(*pattern, 4, 2), source);

        REQUIRE_FALSE(matches.has_value());
        CHECK(matches.error().code == ScanErrorCode::match_budget_exceeded);
    }

    TEST_CASE("masked byte patterns support high low and full nibble wildcards") {
        const std::array source {std::byte {0x4F}, std::byte {0x1A}, std::byte {0x40}, std::byte {0x2B}};
        const auto pattern = make_masked_pattern("masked", "4? ?A");
        REQUIRE(pattern.has_value());

        const auto matches = execute_scan(file_space(0x4000, source.size()), plan_with(*pattern), source, 0x4000);

        REQUIRE(matches.has_value());
        REQUIRE(matches->count() == 1);
        CHECK(matches->matches.front().offset == 0);
        CHECK(matches->matches.front().length == 2);

        const std::array every_form {std::byte {0x4F}, std::byte {0x99}, std::byte {0x1A}, std::byte {0xA5}};
        const auto all_nibbles = make_masked_pattern("all", "4F ?? ?A A?");
        REQUIRE(all_nibbles.has_value());
        const auto every_form_matches =
            execute_scan(file_space(0, every_form.size()), plan_with(*all_nibbles), every_form);
        REQUIRE(every_form_matches.has_value());
        REQUIRE(every_form_matches->count() == 1);
        CHECK(every_form_matches->matches.front().length == every_form.size());

        const auto invalid = make_masked_pattern("bad", "4 G?");
        REQUIRE_FALSE(invalid.has_value());
        CHECK(invalid.error().code == ScanErrorCode::invalid_masked_pattern);
    }

    TEST_CASE("invalid plans and pattern representations fail closed") {
        const auto literal_bytes = bytes("MZ");
        const auto pattern = make_byte_pattern("mz", literal_bytes);
        REQUIRE(pattern.has_value());
        const auto source = bytes("MZ");

        SECTION("unknown space kind") {
            auto space = file_space(0, source.size());
            space.kind = static_cast<ScanSpaceKind>(255);
            const auto result = execute_scan(space, plan_with(*pattern), source);
            REQUIRE_FALSE(result.has_value());
            CHECK(result.error().code == ScanErrorCode::invalid_space);
        }

        SECTION("unknown permission bits") {
            auto space = file_space(0, source.size());
            space.permissions |= 1U << 31U;
            const auto result = execute_scan(space, plan_with(*pattern), source);
            REQUIRE_FALSE(result.has_value());
            CHECK(result.error().code == ScanErrorCode::invalid_space);
        }

        SECTION("absolute range overflow") {
            const auto result = execute_scan(file_space(std::numeric_limits<std::uint64_t>::max() - 1U, 4),
                                             plan_with(*pattern), source);
            REQUIRE_FALSE(result.has_value());
            CHECK(result.error().code == ScanErrorCode::arithmetic_overflow);
        }

        SECTION("duplicate pattern IDs") {
            auto plan = plan_with(*pattern);
            plan.patterns.push_back(*pattern);
            const auto result = execute_scan(file_space(0, source.size()), plan, source);
            REQUIRE_FALSE(result.has_value());
            CHECK(result.error().code == ScanErrorCode::duplicate_pattern_id);
        }

        SECTION("aggregate cannot forge a masked pattern") {
            auto forged = *pattern;
            forged.kind = StaticPatternKind::masked_bytes;
            const auto result = execute_scan(file_space(0, source.size()), plan_with(std::move(forged)), source);
            REQUIRE_FALSE(result.has_value());
            CHECK(result.error().code == ScanErrorCode::invalid_pattern);
        }

        SECTION("aggregate cannot forge a non-nibble mask") {
            auto forged = *pattern;
            forged.kind = StaticPatternKind::masked_bytes;
            forged.bytes = {std::byte {0x01}};
            forged.mask = {std::byte {0x11}};
            const auto result = execute_scan(file_space(0, source.size()), plan_with(std::move(forged)), source);
            REQUIRE_FALSE(result.has_value());
            CHECK(result.error().code == ScanErrorCode::invalid_pattern);
        }

        SECTION("invalid UTF-8 text is rejected before scanning") {
            const std::array invalid_utf8 {static_cast<char>(0xC0), static_cast<char>(0xAF)};
            const auto result = make_text_pattern(
                "invalid", std::string_view {invalid_utf8.data(), invalid_utf8.size()}, TextEncoding::utf8);
            REQUIRE_FALSE(result.has_value());
            CHECK(result.error().code == ScanErrorCode::invalid_utf8);
        }

        SECTION("unknown text encoding is rejected") {
            const auto result = make_text_pattern("invalid", "text", static_cast<TextEncoding>(255));
            REQUIRE_FALSE(result.has_value());
            CHECK(result.error().code == ScanErrorCode::invalid_pattern);
        }

        SECTION("aggregate cannot forge invalid UTF-16") {
            auto forged = *pattern;
            forged.kind = StaticPatternKind::text_literal;
            forged.text_encoding = TextEncoding::utf16_little_endian;
            forged.bytes = {std::byte {0x41}};
            const auto result = execute_scan(file_space(0, source.size()), plan_with(std::move(forged)), source);
            REQUIRE_FALSE(result.has_value());
            CHECK(result.error().code == ScanErrorCode::invalid_pattern);
        }
    }

    TEST_CASE("text patterns use compiler-selected encoding and ASCII case behavior") {
        const auto pattern =
            make_text_pattern("powershell", "Power", TextEncoding::utf16_little_endian, TextCase::ascii_insensitive);
        const auto uppercase = make_text_pattern("source", "POWER", TextEncoding::utf16_little_endian);
        REQUIRE(pattern.has_value());
        REQUIRE(uppercase.has_value());

        const auto matches =
            execute_scan(file_space(0, uppercase->bytes.size()), plan_with(*pattern), uppercase->bytes);

        REQUIRE(matches.has_value());
        REQUIRE(matches->count() == 1);
        CHECK(matches->matches.front().offset == 0);
        CHECK(matches->matches.front().length == uppercase->bytes.size());

        const auto big_endian = make_text_pattern("be", "A\xF0\x9F\x98\x80", TextEncoding::utf16_big_endian);
        REQUIRE(big_endian.has_value());
        CHECK(big_endian->text_encoding == TextEncoding::utf16_big_endian);
        CHECK(big_endian->bytes == std::vector<std::byte> {std::byte {0x00}, std::byte {0x41}, std::byte {0xD8},
                                                           std::byte {0x3D}, std::byte {0xDE}, std::byte {0x00}});

        const auto non_ascii_pattern =
            make_text_pattern("non-ascii", "\xC5\x81", TextEncoding::utf16_little_endian, TextCase::ascii_insensitive);
        const auto different_non_ascii = make_text_pattern("different", "\xC5\xA1", TextEncoding::utf16_little_endian);
        REQUIRE(non_ascii_pattern.has_value());
        REQUIRE(different_non_ascii.has_value());
        const auto non_ascii_matches = execute_scan(file_space(0, different_non_ascii->bytes.size()),
                                                    plan_with(*non_ascii_pattern), different_non_ascii->bytes);
        REQUIRE(non_ascii_matches.has_value());
        CHECK(non_ascii_matches->empty());
    }

    TEST_CASE("RE2 validates unsupported syntax and performs bounded regex scans") {
        const auto unsupported = make_re2_pattern("backreference", R"((a)\1)");
        REQUIRE_FALSE(unsupported.has_value());
        CHECK(unsupported.error().code == ScanErrorCode::regex_syntax);
        CHECK(unsupported.error().input_offset == 3);
        CHECK_FALSE(unsupported.error().message.empty());

        const auto invalid_encoding =
            make_re2_pattern("encoding", "a", RegexOptions {.encoding = static_cast<RegexEncoding>(255)});
        REQUIRE_FALSE(invalid_encoding.has_value());
        CHECK(invalid_encoding.error().code == ScanErrorCode::invalid_pattern);

        const auto pattern = make_re2_pattern("run", "a+b");
        REQUIRE(pattern.has_value());
        const auto source = bytes("xaaabyaaab");
        const auto matches = execute_scan(file_space(0x2000, source.size()), plan_with(*pattern), source, 0x2000);

        REQUIRE(matches.has_value());
        REQUIRE(matches->count() == 2);
        CHECK(matches->matches[0].offset == 1);
        CHECK(matches->matches[0].length == 4);
        CHECK(matches->matches[1].offset == 6);
    }

    TEST_CASE("RE2 options and zero-length advancement remain deterministic and bounded") {
        SECTION("case and newline options") {
            const auto insensitive =
                make_re2_pattern("case", "a.b", RegexOptions {.case_sensitive = false, .dot_matches_newline = true});
            REQUIRE(insensitive.has_value());
            const auto source = bytes("xA\nBz");
            const auto matches = execute_scan(file_space(0, source.size()), plan_with(*insensitive), source);
            REQUIRE(matches.has_value());
            REQUIRE(matches->count() == 1);
            CHECK(matches->matches.front().offset == 1);
            CHECK(matches->matches.front().length == 3);
        }

        SECTION("multiline anchors") {
            const auto multiline = make_re2_pattern("multiline", "^b$", RegexOptions {.multiline = true});
            REQUIRE(multiline.has_value());
            const auto source = bytes("a\nb\nc");
            const auto matches = execute_scan(file_space(0, source.size()), plan_with(*multiline), source);
            REQUIRE(matches.has_value());
            REQUIRE(matches->count() == 1);
            CHECK(matches->matches.front().offset == 2);
            CHECK(matches->matches.front().length == 1);

            const auto single_line = make_re2_pattern("single-line", "^b$");
            REQUIRE(single_line.has_value());
            const auto absent = execute_scan(file_space(0, source.size()), plan_with(*single_line), source);
            REQUIRE(absent.has_value());
            CHECK(absent->empty());
        }

        SECTION("Latin-1 patterns preserve arbitrary bytes") {
            const std::string expression(1, static_cast<char>(0xFF));
            const auto latin1 =
                make_re2_pattern("latin1", expression, RegexOptions {.encoding = RegexEncoding::latin1});
            REQUIRE(latin1.has_value());
            const std::array source {std::byte {0x00}, std::byte {0xFF}, std::byte {0x01}};
            const auto matches = execute_scan(file_space(0, source.size()), plan_with(*latin1), source);
            REQUIRE(matches.has_value());
            REQUIRE(matches->count() == 1);
            CHECK(matches->matches.front().offset == 1);
            CHECK(matches->matches.front().length == 1);
        }

        SECTION("zero-length matches advance by one byte") {
            const auto empty_at_each_offset = make_re2_pattern("empty", "a*");
            REQUIRE(empty_at_each_offset.has_value());
            const auto source = bytes("bbb");
            const auto matches = execute_scan(file_space(0, source.size()), plan_with(*empty_at_each_offset), source);
            REQUIRE(matches.has_value());
            REQUIRE(matches->count() == 4);
            CHECK(matches->matches[0].offset == 0);
            CHECK(matches->matches[1].offset == 1);
            CHECK(matches->matches[2].offset == 2);
            CHECK(matches->matches[3].offset == 3);
        }
    }

    TEST_CASE("canonical scan plans round-trip and reject every truncation or mutation") {
        const auto byte_pattern = make_byte_pattern("mz", bytes("MZ"));
        const auto masked_pattern = make_masked_pattern("prologue", "4? ?A");
        const auto text_pattern =
            make_text_pattern("utf16", "Power", TextEncoding::utf16_big_endian, TextCase::ascii_insensitive);
        const auto regex_pattern = make_re2_pattern("regex", "[A-Z]{2}");
        REQUIRE(byte_pattern.has_value());
        REQUIRE(masked_pattern.has_value());
        REQUIRE(text_pattern.has_value());
        REQUIRE(regex_pattern.has_value());

        const auto space = file_space(0x4000, 256);
        const TypedScanPlan typed_plan {
            .plan_id = "plan.round-trip",
            .patterns = {*byte_pattern, *masked_pattern, *text_pattern, *regex_pattern},
            .maximum_bytes = 256,
            .maximum_matches = 32,
            .context_bytes_before = 8,
            .context_bytes_after = 12,
            .result_mode = ScanResultMode::existential,
        };
        const auto encoded = serialize_scan_plan(space, typed_plan);
        const auto encoded_again = serialize_scan_plan(space, typed_plan);
        REQUIRE(encoded.has_value());
        REQUIRE(encoded_again.has_value());
        CHECK(encoded->encoded_pattern == encoded_again->encoded_pattern);
        CHECK(encoded->context_bytes_before == typed_plan.context_bytes_before);
        CHECK(encoded->context_bytes_after == typed_plan.context_bytes_after);
        CHECK(encoded->result_mode == typed_plan.result_mode);
        CHECK(encoded->pattern_ids == std::vector<std::string> {"mz", "prologue", "utf16", "regex"});
        CHECK(std::ranges::all_of(encoded->encoded_pattern,
                                  [](const char value) { return value >= 0x20 && value <= 0x7E; }));

        const ScanSpace contract_space {
            .kind = "file",
            .begin = space.begin,
            .size = space.size,
            .permissions = space.permissions,
            .identity = space.identity,
            .label = space.label,
            .subject_generation = space.subject_generation,
        };
        const auto decoded = deserialize_scan_plan(contract_space, *encoded);
        REQUIRE(decoded.has_value());
        CHECK(decoded->space.identity == space.identity);
        CHECK(decoded->space.subject_generation == space.subject_generation);
        CHECK(decoded->space.kind == space.kind);
        CHECK(decoded->space.label == space.label);
        CHECK(decoded->plan.plan_id == typed_plan.plan_id);
        CHECK(decoded->plan.context_bytes_before == typed_plan.context_bytes_before);
        CHECK(decoded->plan.context_bytes_after == typed_plan.context_bytes_after);
        CHECK(decoded->plan.result_mode == typed_plan.result_mode);
        REQUIRE(decoded->plan.patterns.size() == typed_plan.patterns.size());
        CHECK(decoded->plan.patterns[0].bytes == byte_pattern->bytes);
        CHECK(decoded->plan.patterns[1].mask == masked_pattern->mask);
        CHECK(decoded->plan.patterns[2].text_encoding == TextEncoding::utf16_big_endian);
        CHECK(decoded->plan.patterns[2].ascii_case_insensitive);
        CHECK(decoded->plan.patterns[3].regex_source == regex_pattern->regex_source);

        for (std::size_t prefix = 0; prefix < encoded->encoded_pattern.size(); ++prefix) {
            CAPTURE(prefix);
            auto truncated = *encoded;
            truncated.encoded_pattern.resize(prefix);
            CHECK_FALSE(deserialize_scan_plan(contract_space, truncated).has_value());
        }
        for (std::size_t index = 0; index < encoded->encoded_pattern.size(); ++index) {
            CAPTURE(index);
            auto mutated = *encoded;
            const auto value = static_cast<unsigned char>(mutated.encoded_pattern[index]);
            mutated.encoded_pattern[index] = static_cast<char>(value ^ 1U);
            CHECK_FALSE(deserialize_scan_plan(contract_space, mutated).has_value());
        }

        auto trailing = *encoded;
        trailing.encoded_pattern.push_back('x');
        const auto rejected_trailing = deserialize_scan_plan(contract_space, trailing);
        REQUIRE_FALSE(rejected_trailing.has_value());
        CHECK(rejected_trailing.error().code == ScanWireErrorCode::trailing_data);

        auto mismatched_identity = contract_space;
        mismatched_identity.identity = "other-space";
        CHECK_FALSE(deserialize_scan_plan(mismatched_identity, *encoded).has_value());
        auto mismatched_generation = contract_space;
        ++mismatched_generation.subject_generation;
        CHECK_FALSE(deserialize_scan_plan(mismatched_generation, *encoded).has_value());
        auto invalid_label = contract_space;
        invalid_label.label.categories = {"z", "a"};
        CHECK_FALSE(deserialize_scan_plan(invalid_label, *encoded).has_value());
        auto mismatched_context = *encoded;
        ++mismatched_context.context_bytes_before;
        CHECK_FALSE(deserialize_scan_plan(contract_space, mismatched_context).has_value());
        auto invalid_mode = *encoded;
        invalid_mode.result_mode = static_cast<ScanResultMode>(0);
        CHECK_FALSE(deserialize_scan_plan(contract_space, invalid_mode).has_value());
        auto missing_pattern_ids = *encoded;
        missing_pattern_ids.pattern_ids.clear();
        CHECK_FALSE(deserialize_scan_plan(contract_space, missing_pattern_ids).has_value());
        auto reordered_pattern_ids = *encoded;
        std::ranges::swap(reordered_pattern_ids.pattern_ids[0], reordered_pattern_ids.pattern_ids[1]);
        CHECK_FALSE(deserialize_scan_plan(contract_space, reordered_pattern_ids).has_value());
        auto wrong_pattern_id = *encoded;
        wrong_pattern_id.pattern_ids.front() = "other";
        CHECK_FALSE(deserialize_scan_plan(contract_space, wrong_pattern_id).has_value());
    }

    TEST_CASE("provider scan adapters preserve supported spaces through protocol v2") {
        using namespace rule_engine::python::protocol_v2;

        const auto literal = make_byte_pattern("mz", bytes("MZ"), PatternOrigin::template_binding);
        const auto masked = make_masked_pattern("masked", "4? ?A");
        REQUIRE(literal.has_value());
        REQUIRE(masked.has_value());
        const std::array kinds {ScanSpaceKind::image_file, ScanSpaceKind::mapped_section,
                                ScanSpaceKind::readable_memory, ScanSpaceKind::mapped_image};
        for (const auto kind : kinds) {
            CAPTURE(kind);
            auto space = file_space(0x1000, 32);
            space.kind = kind;
            space.identity = "provider.space";
            auto plan = plan_with(*literal, 32, 16);
            plan.patterns.push_back(*masked);
            plan.context_bytes_before = 2;
            plan.context_bytes_after = 3;
            const ProviderScanRequest provider_request {
                .request_id = RequestId {"scan-1"},
                .subject = SubjectKey {.peer = PeerId {"peer-1"},
                                       .descriptor = SchemaId {"process/v1"},
                                       .identity = {{.field_id = 1, .value = std::uint64_t {42}}},
                                       .parent = {}},
                .space = space,
                .plan = plan,
                .deadline_unix_ms = 5'000,
            };

            const auto contract_request = to_contract_scan_request(provider_request);
            REQUIRE(contract_request.has_value());
            CHECK(contract_request->space.identity == provider_request.space.identity);
            CHECK(contract_request->space.label == provider_request.space.label);
            CHECK(contract_request->space.subject_generation == provider_request.space.subject_generation);
            CHECK(contract_request->plan.context_bytes_before == provider_request.plan.context_bytes_before);
            CHECK(contract_request->plan.context_bytes_after == provider_request.plan.context_bytes_after);
            CHECK(contract_request->plan.result_mode == provider_request.plan.result_mode);
            CHECK(contract_request->plan.pattern_ids == std::vector<std::string> {"mz", "masked"});
            const WorkLeaseMessage work {
                .session = SessionId {"session-1"},
                .peer = PeerId {"peer-1"},
                .session_fence = 7,
                .work_id = "work-1",
                .attempt_id = "attempt-1",
                .work_fence = 9,
                .generation = 7,
                .server_sequence = 1,
                .route = "windows.scan",
                .facts = {},
                .scans = {*contract_request},
            };
            const PeerEnvelope envelope {
                .protocol_major = major_version,
                .protocol_minor = initial_minor_version,
                .message_id = "message-1",
                .session = SessionId {"session-1"},
                .agent_epoch = "epoch-1",
                .agent_sequence = 0,
                .acknowledged_agent_sequence = 0,
                .body = work,
            };
            const auto frame = encode_frame(envelope);
            REQUIRE(frame.has_value());
            const auto decoded_frame = decode_frame(*frame);
            REQUIRE(decoded_frame.has_value());
            const auto &decoded_work = std::get<WorkLeaseMessage>(decoded_frame->envelope.body);
            REQUIRE(decoded_work.scans.size() == 1);
            const auto restored = from_contract_scan_request(decoded_work.scans.front());
            REQUIRE(restored.has_value());
            CHECK(restored->space.kind == kind);
            CHECK(restored->space.identity == provider_request.space.identity);
            CHECK(restored->space.subject_generation == provider_request.space.subject_generation);
            CHECK(restored->space.label == provider_request.space.label);
            CHECK(restored->plan.context_bytes_before == provider_request.plan.context_bytes_before);
            CHECK(restored->plan.context_bytes_after == provider_request.plan.context_bytes_after);
            CHECK(restored->plan.result_mode == provider_request.plan.result_mode);
            REQUIRE(restored->plan.patterns.size() == 2);
            CHECK(restored->plan.patterns.front().pattern_id == literal->pattern_id);
            CHECK(restored->plan.patterns.front().bytes == literal->bytes);
            CHECK(restored->plan.patterns.back().pattern_id == masked->pattern_id);
            CHECK(restored->plan.patterns.back().mask == masked->mask);
            CHECK(canonical_subject_key(restored->subject) == canonical_subject_key(provider_request.subject));
        }
    }

    TEST_CASE("provider response adapters preserve every match field and result mode") {
        const auto mz = make_byte_pattern("mz", bytes("MZ"));
        const auto aa = make_byte_pattern("aa", bytes("AA"));
        REQUIRE(mz.has_value());
        REQUIRE(aa.has_value());
        auto plan = plan_with(*mz, 7, 8);
        plan.patterns.push_back(*aa);
        plan.context_bytes_before = 1;
        plan.context_bytes_after = 2;
        ProviderScanRequest request {
            .request_id = RequestId {"scan-1"},
            .subject = SubjectKey {.peer = PeerId {"peer-1"},
                                   .descriptor = SchemaId {"process/v1"},
                                   .identity = {{.field_id = 1, .value = std::uint64_t {42}}},
                                   .parent = {}},
            .space = file_space(0x1000, 7),
            .plan = plan,
            .deadline_unix_ms = 5'000,
        };
        const auto source = bytes("xMZyAAz");
        const auto matches = execute_scan(request.space, request.plan, source, 0x1000);
        REQUIRE(matches.has_value());
        REQUIRE(matches->matches.size() == 2);

        const auto response = to_contract_scan_response(request, *matches);
        REQUIRE(response.has_value());
        CHECK(response->status == FactTerminalStatus::value);
        CHECK_FALSE(response->truncated);
        CHECK(response->mode == ScanResultMode::exact_complete);
        REQUIRE(response->matches.size() == 2);
        CHECK(response->matches[0].pattern_id == "mz");
        CHECK(response->matches[0].scan_space_id == request.space.identity);
        CHECK(response->matches[0].absolute_address == 0x1001);
        CHECK(response->matches[0].permission_snapshot == request.space.permissions);
        CHECK(response->matches[0].matched_bytes == bytes("MZ"));
        CHECK(response->matches[0].before_bytes == bytes("x"));
        CHECK(response->matches[0].after_bytes == bytes("yA"));
        CHECK(response->matches[0].label == request.space.label);
        CHECK(response->matches[0].subject_generation == request.space.subject_generation);
        using namespace rule_engine::python::protocol_v2;
        const WorkResultMessage result_message {
            .originating_session = SessionId {"session-1"},
            .peer = PeerId {"peer-1"},
            .originating_session_fence = 7,
            .work_id = "work-1",
            .attempt_id = "attempt-1",
            .work_fence = 9,
            .generation = 7,
            .facts = {},
            .scans = {*response},
        };
        const PeerEnvelope envelope {
            .protocol_major = major_version,
            .protocol_minor = initial_minor_version,
            .message_id = "result-message-1",
            .session = SessionId {"session-1"},
            .agent_epoch = "epoch-1",
            .agent_sequence = 1,
            .acknowledged_agent_sequence = 0,
            .body = result_message,
        };
        const auto frame = encode_frame(envelope);
        REQUIRE(frame.has_value());
        const auto decoded_frame = decode_frame(*frame);
        REQUIRE(decoded_frame.has_value());
        const auto &decoded_result = std::get<WorkResultMessage>(decoded_frame->envelope.body);
        REQUIRE(decoded_result.scans.size() == 1);
        const auto restored = from_contract_scan_response(request, decoded_result.scans.front());
        REQUIRE(restored.has_value());
        REQUIRE(restored->matches.size() == matches->matches.size());
        check_same_match(restored->matches[0], matches->matches[0]);
        check_same_match(restored->matches[1], matches->matches[1]);

        auto terminal = *response;
        terminal.status = FactTerminalStatus::timed_out;
        CHECK_FALSE(from_contract_scan_response(request, terminal).has_value());

        auto duplicated = *response;
        duplicated.matches.push_back(duplicated.matches.front());
        const auto duplicate_result = from_contract_scan_response(request, duplicated);
        REQUIRE_FALSE(duplicate_result.has_value());
        CHECK(duplicate_result.error().code == ScanWireErrorCode::duplicate_match);

        auto wrong_mode = *response;
        wrong_mode.mode = ScanResultMode::existential;
        CHECK_FALSE(from_contract_scan_response(request, wrong_mode).has_value());
        auto wrong_pattern = *response;
        wrong_pattern.matches.front().pattern_id = "unknown";
        CHECK_FALSE(from_contract_scan_response(request, wrong_pattern).has_value());
        auto wrong_space = *response;
        wrong_space.matches.front().scan_space_id = "other-space";
        CHECK_FALSE(from_contract_scan_response(request, wrong_space).has_value());
        auto wrong_address = *response;
        ++wrong_address.matches.front().absolute_address;
        CHECK_FALSE(from_contract_scan_response(request, wrong_address).has_value());
        auto wrong_permissions = *response;
        wrong_permissions.matches.front().permission_snapshot |= scan_permission_execute;
        CHECK_FALSE(from_contract_scan_response(request, wrong_permissions).has_value());
        auto wrong_bytes = *response;
        wrong_bytes.matches.front().matched_bytes.front() ^= std::byte {1};
        CHECK_FALSE(from_contract_scan_response(request, wrong_bytes).has_value());
        auto incomplete_context = *response;
        incomplete_context.matches.front().before_bytes.clear();
        CHECK_FALSE(from_contract_scan_response(request, incomplete_context).has_value());
        auto wrong_label = *response;
        wrong_label.matches.front().label.classification = Classification::secret;
        CHECK_FALSE(from_contract_scan_response(request, wrong_label).has_value());
        auto wrong_generation = *response;
        ++wrong_generation.matches.front().subject_generation;
        CHECK_FALSE(from_contract_scan_response(request, wrong_generation).has_value());
        ScanWireLimits tiny_result_limit;
        tiny_result_limit.maximum_result_payload_bytes = 1;
        CHECK_FALSE(to_contract_scan_response(request, *matches, tiny_result_limit).has_value());
        CHECK_FALSE(from_contract_scan_response(request, *response, tiny_result_limit).has_value());

        auto existential_request = request;
        existential_request.plan.result_mode = ScanResultMode::existential;
        const auto witness = execute_scan(existential_request.space, existential_request.plan, source, 0x1000);
        REQUIRE(witness.has_value());
        REQUIRE(witness->count() == 1);
        CHECK(witness->exists() == matches->exists());
        const auto existential_response = to_contract_scan_response(existential_request, *witness);
        REQUIRE(existential_response.has_value());
        CHECK(existential_response->mode == ScanResultMode::existential);
        const auto restored_witness = from_contract_scan_response(existential_request, *existential_response);
        REQUIRE(restored_witness.has_value());
        REQUIRE(restored_witness->count() == 1);
        check_same_match(restored_witness->matches.front(), witness->matches.front());
        auto too_many_witnesses = *existential_response;
        too_many_witnesses.matches.push_back(response->matches.back());
        CHECK_FALSE(from_contract_scan_response(existential_request, too_many_witnesses).has_value());
    }

    TEST_CASE("zero-length RE2 matches remain lossless through protocol frames") {
        using namespace rule_engine::python::protocol_v2;

        const auto empty = make_re2_pattern("empty", "a*");
        REQUIRE(empty.has_value());
        ProviderScanRequest request {
            .request_id = RequestId {"scan-empty"},
            .subject = SubjectKey {.peer = PeerId {"peer-1"},
                                   .descriptor = SchemaId {"process/v1"},
                                   .identity = {{.field_id = 1, .value = std::uint64_t {42}}},
                                   .parent = {}},
            .space = file_space(0x2000, 3),
            .plan = plan_with(*empty, 3, 4),
            .deadline_unix_ms = 5'000,
        };
        const auto matches = execute_scan(request.space, request.plan, bytes("bbb"), 0x2000);
        REQUIRE(matches.has_value());
        REQUIRE(matches->count() == 4);
        CHECK(std::ranges::all_of(matches->matches, [](const TypedScanMatch &match) {
            return match.length == 0 && match.matched_bytes.empty();
        }));

        const auto response = to_contract_scan_response(request, *matches);
        REQUIRE(response.has_value());
        const WorkResultMessage result_message {
            .originating_session = SessionId {"session-1"},
            .peer = PeerId {"peer-1"},
            .originating_session_fence = 7,
            .work_id = "work-empty",
            .attempt_id = "attempt-empty",
            .work_fence = 9,
            .generation = 7,
            .facts = {},
            .scans = {*response},
        };
        const PeerEnvelope envelope {
            .protocol_major = major_version,
            .protocol_minor = initial_minor_version,
            .message_id = "result-empty",
            .session = SessionId {"session-1"},
            .agent_epoch = "epoch-1",
            .agent_sequence = 1,
            .acknowledged_agent_sequence = 0,
            .body = result_message,
        };
        const auto frame = encode_frame(envelope);
        REQUIRE(frame.has_value());
        const auto decoded_frame = decode_frame(*frame);
        REQUIRE(decoded_frame.has_value());
        const auto &decoded_result = std::get<WorkResultMessage>(decoded_frame->envelope.body);
        REQUIRE(decoded_result.scans.size() == 1);
        const auto restored = from_contract_scan_response(request, decoded_result.scans.front());
        REQUIRE(restored.has_value());
        REQUIRE(restored->count() == matches->count());
        for (std::size_t index = 0; index < matches->count(); ++index) {
            check_same_match(restored->matches[index], matches->matches[index]);
        }
    }

    TEST_CASE("provider scan requests expose only typed subject space and plan data") {
        STATIC_REQUIRE(std::is_aggregate_v<ProviderScanRequest>);
        const auto literal_bytes = bytes("MZ");
        const auto pattern = make_byte_pattern("mz", literal_bytes, PatternOrigin::template_binding);
        REQUIRE(pattern.has_value());

        ProviderScanRequest request {
            .request_id = RequestId {"request-1"},
            .subject = SubjectKey {.peer = PeerId {"peer-1"},
                                   .descriptor = SchemaId {"process/v1"},
                                   .identity = {{.field_id = 1, .value = std::uint64_t {42}}},
                                   .parent = {}},
            .space = file_space(0, 2),
            .plan = plan_with(*pattern),
            .deadline_unix_ms = 1234,
        };

        CHECK(request.subject.valid());
        CHECK(request.space.identity == "process.image.file");
        CHECK(request.plan.patterns.front().origin == PatternOrigin::template_binding);
    }

} // namespace
