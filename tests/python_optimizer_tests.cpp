#include "rule_engine/python/optimizer/optimizer.hpp"
#include "rule_engine/python/optimizer/scanner.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace {

    using namespace rule_engine::python;
    using namespace rule_engine::python::optimizer;

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

    ExplicitScanSpace file_space(const std::uint64_t begin, const std::uint64_t size) {
        return ExplicitScanSpace {
            .identity = "process.image.file",
            .kind = ScanSpaceKind::image_file,
            .begin = begin,
            .size = size,
            .permissions = scan_permission_read,
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
        };
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
    }

    TEST_CASE("effectful and full-flight-recorded execution conservatively stays exact") {
        SECTION("effectful certificate") {
            auto certificate = pure_certificate();
            certificate.transitively_pure = false;
            certificate.emits_effects = true;
            const std::vector certificates {certificate};

            const auto selected = select_optimization(certificates, optimization_request());

            REQUIRE(selected.has_value());
            CHECK(selected->use_exact_bytecode);
            CHECK_FALSE(selected->specialization_enabled);
            CHECK_FALSE(selected->pruning_enabled);
            CHECK(selected->fallback_reason == ExactFallbackReason::certificate_not_transitively_pure);
        }

        SECTION("full recorder policy") {
            auto request = optimization_request();
            request.full_flight_recorder_armed = true;
            const std::vector certificates {pure_certificate()};

            const auto selected = select_optimization(certificates, request);

            REQUIRE(selected.has_value());
            CHECK(selected->use_exact_bytecode);
            CHECK(selected->fallback_reason == ExactFallbackReason::recorder_policy_requires_exact);
        }
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
                                                                  request.expected_executable_semantic_hash);
        REQUIRE_FALSE(validation.has_value());
        CHECK(validation.error().code == OptimizerErrorCode::certificate_semantic_hash_mismatch);
    }

    TEST_CASE("shadow parity compares every committable observation and redacts values") {
        ShadowExecutionSnapshot exact {
            .outcome = EvaluationOutcome::match,
            .verdict = true,
            .logical_reads = {{.sequence = 1,
                               .subject_key_digest = "sha256:subject",
                               .route = FactRoute {.provider = "process", .fact = "signer"},
                               .schema = SchemaId {"signer/v1"},
                               .status = FactTerminalStatus::value,
                               .span = source_span(),
                               .label = DataLabel {},
                               .value_digest = "sha256:value"}},
            .ordered_effects = {{.id = IntentId {"intent-1"},
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
            .ordered_state = {{.owner = ExecutableId {"rule.one"},
                               .namespace_name = "binding.one",
                               .key = "counter",
                               .expected_version = 4,
                               .value = frozen("sha256:state")}},
            .recorder =
                {{.sequence = 1, .kind = "branch", .span = source_span(), .label = DataLabel {}, .summary = "taken"}},
            .fault = FaultChain {.frames = {{.code = "Fault",
                                             .message = "secret detail",
                                             .executable = ExecutableId {"rule.one"},
                                             .span = source_span()}},
                                 .double_fault = false,
                                 .triple_fault = false},
        };
        ShadowExecutionSnapshot optimized {
            .outcome = EvaluationOutcome::no_match,
            .verdict = false,
            .logical_reads = {},
            .ordered_effects = {},
            .ordered_state = {},
            .recorder = {},
            .fault = std::nullopt,
        };

        const auto mismatch = compare_shadow_execution(exact, optimized);

        CHECK_FALSE(mismatch.equivalent);
        CHECK(mismatch.exact_result_is_only_committable);
        CHECK(mismatch.disable_optimized_executable);
        CHECK(mismatch.mismatch_dimension_count == 7);
        CHECK(mismatch.mismatches.size() == 7);
        CHECK_FALSE(mismatch.mismatch_data_truncated);

        const auto parity = compare_shadow_execution(exact, exact);
        CHECK(parity.equivalent);
        CHECK_FALSE(parity.disable_optimized_executable);
        CHECK(parity.mismatches.empty());
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
        CHECK(matches->matches[0].context_before == bytes("x"));
        CHECK(matches->matches[0].context_after == bytes("y"));
        CHECK(matches->matches[1].offset == 4);
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

        const auto invalid = make_masked_pattern("bad", "4 G?");
        REQUIRE_FALSE(invalid.has_value());
        CHECK(invalid.error().code == ScanErrorCode::invalid_masked_pattern);
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
    }

    TEST_CASE("RE2 validates unsupported syntax and performs bounded regex scans") {
        const auto unsupported = make_re2_pattern("backreference", R"((a)\1)");
        REQUIRE_FALSE(unsupported.has_value());

        if (re2_engine_available()) {
            CHECK(unsupported.error().code == ScanErrorCode::regex_syntax);

            const auto pattern = make_re2_pattern("run", "a+b");
            REQUIRE(pattern.has_value());
            const auto source = bytes("xaaabyaaab");
            const auto matches = execute_scan(file_space(0x2000, source.size()), plan_with(*pattern), source, 0x2000);

            REQUIRE(matches.has_value());
            REQUIRE(matches->count() == 2);
            CHECK(matches->matches[0].offset == 1);
            CHECK(matches->matches[0].length == 4);
            CHECK(matches->matches[1].offset == 6);
            return;
        }

        CHECK(unsupported.error().code == ScanErrorCode::regex_engine_unavailable);
        const auto valid_but_unavailable = make_re2_pattern("run", "a+b");
        REQUIRE_FALSE(valid_but_unavailable.has_value());
        CHECK(valid_but_unavailable.error().code == ScanErrorCode::regex_engine_unavailable);
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
