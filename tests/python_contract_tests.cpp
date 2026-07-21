#include "rule_engine/python/contract.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <limits>
#include <memory>
#include <string>
#include <utility>

namespace {

    using namespace rule_engine::python;

    SourceSpan span() { return SourceSpan {.source = SourceId {"rules.main"}, .begin_byte = 4, .end_byte = 12}; }

    CompiledPack minimal_pack() {
        BytecodeFunction function {
            .id = ExecutableId {"example.rule"},
            .qualified_name = "example.rule",
            .register_count = 1,
            .parameter_count = 0,
            .generator = false,
            .async = false,
            .instructions = {{.opcode = Opcode::return_value,
                              .destination = 0,
                              .operand_a = 0,
                              .operand_b = 0,
                              .immediate = 0,
                              .span = span()}},
            .exception_regions = {},
        };
        return CompiledPack {
            .pack = PackId {"example"},
            .version = PackVersion {"1.0.0"},
            .source_digest = SourceDigest {"sha256:source"},
            .compiler_abi = "python-3.14.6/design-v1",
            .semantic_hash = "sha256:semantic",
            .schemas = {},
            .constants = {},
            .functions = {std::move(function)},
            .bindings = {},
            .optimization_certificates = {},
        };
    }

    TEST_CASE("balanced.v1 freezes every normal executor limit") {
        using namespace std::chrono_literals;

        STATIC_REQUIRE(balanced_v1.name == "balanced.v1");
        STATIC_REQUIRE(balanced_v1.normal.elapsed == 10s);
        STATIC_REQUIRE(balanced_v1.normal.active_cpu == 100ms);
        STATIC_REQUIRE(balanced_v1.normal.instructions == 1'000'000);
        STATIC_REQUIRE(balanced_v1.normal.frames == 128);
        STATIC_REQUIRE(balanced_v1.normal.heap_bytes == 16 * mebibyte);
        STATIC_REQUIRE(balanced_v1.normal.loop_iterations_and_yields == 250'000);
        STATIC_REQUIRE(balanced_v1.normal.logical_facts == 512);
        STATIC_REQUIRE(balanced_v1.normal.provider_rounds == 16);
        STATIC_REQUIRE(balanced_v1.normal.fact_bytes == 16 * mebibyte);
        STATIC_REQUIRE(balanced_v1.normal.service_calls == 128);
        STATIC_REQUIRE(balanced_v1.normal.active_service_calls == 16);
        STATIC_REQUIRE(balanced_v1.normal.service_response_bytes == 16 * mebibyte);
        STATIC_REQUIRE(balanced_v1.normal.maximum_service_deadline == 5s);
        STATIC_REQUIRE(balanced_v1.normal.history_queries == 16);
        STATIC_REQUIRE(balanced_v1.normal.history_rows == 10'000);
        STATIC_REQUIRE(balanced_v1.normal.history_bytes == 16 * mebibyte);
        STATIC_REQUIRE(balanced_v1.normal.state_keys == 256);
        STATIC_REQUIRE(balanced_v1.normal.state_bytes == 1 * mebibyte);
        STATIC_REQUIRE(balanced_v1.normal.effect_intents == 256);
        STATIC_REQUIRE(balanced_v1.normal.effect_bytes == 2 * mebibyte);
        STATIC_REQUIRE(balanced_v1.normal.recorder_events == 25'000);
        STATIC_REQUIRE(balanced_v1.normal.recorder_bytes == 4 * mebibyte);
    }

    TEST_CASE("recovery and breaker profiles are immutable design-v1 values") {
        using namespace std::chrono_literals;

        STATIC_REQUIRE(balanced_v1.finalizer_or_fault.instructions == 100'000);
        STATIC_REQUIRE(balanced_v1.finalizer_or_fault.active_cpu == 50ms);
        STATIC_REQUIRE(balanced_v1.finalizer_or_fault.elapsed == 2s);
        STATIC_REQUIRE(balanced_v1.double_fault.instructions == 25'000);
        STATIC_REQUIRE(balanced_v1.double_fault.elapsed == 1s);
        STATIC_REQUIRE(balanced_v1.forced_cleanup.instructions == 25'000);
        STATIC_REQUIRE(balanced_v1.forced_cleanup.elapsed == 500ms);

        STATIC_REQUIRE(breaker_v1.peer_threshold == 3);
        STATIC_REQUIRE(breaker_v1.peer_window == 10min);
        STATIC_REQUIRE(breaker_v1.peer_quarantine == 30min);
        STATIC_REQUIRE(breaker_v1.global_threshold == 5);
        STATIC_REQUIRE(breaker_v1.global_distinct_peers == 3);
        STATIC_REQUIRE(breaker_v1.global_window == 15min);
    }

    TEST_CASE("labels join monotonically and enforce category ceilings") {
        const DataLabel left {.classification = Classification::internal, .categories = {"telemetry"}};
        const DataLabel right {.classification = Classification::secret, .categories = {"identity", "telemetry"}};

        const auto joined = join_labels(left, right);
        REQUIRE(joined.classification == Classification::secret);
        REQUIRE(joined.categories == std::vector<std::string> {"identity", "telemetry"});
        REQUIRE(may_flow_to(joined, DataLabel {.classification = Classification::secret,
                                               .categories = {"identity", "telemetry", "security"}}));
        REQUIRE_FALSE(
            may_flow_to(joined, DataLabel {.classification = Classification::secret, .categories = {"telemetry"}}));
    }

    TEST_CASE("subject identity is typed recursive and canonical") {
        const auto process = std::make_shared<SubjectKey>(SubjectKey {
            .peer = PeerId {"peer-1"},
            .descriptor = SchemaId {"process/v1"},
            .identity = {{.field_id = 1, .value = std::uint64_t {400}},
                         {.field_id = 2, .value = std::uint64_t {123456}}},
            .parent = {},
        });
        const SubjectKey image {
            .peer = PeerId {"peer-1"},
            .descriptor = SchemaId {"image/v1"},
            .identity = {{.field_id = 1, .value = UnicodeValue {"C:/game.exe"}}},
            .parent = process,
        };

        REQUIRE(process->valid());
        REQUIRE(image.valid());
        REQUIRE(canonical_subject_key(image) == canonical_subject_key(image));
        REQUIRE(canonical_subject_key(image) != canonical_subject_key(*process));

        auto cycle = std::make_shared<SubjectKey>(SubjectKey {
            .peer = PeerId {"peer-1"},
            .descriptor = SchemaId {"bad/v1"},
            .identity = {{.field_id = 1, .value = true}},
            .parent = {},
        });
        cycle->parent = cycle;
        REQUIRE_FALSE(cycle->valid());
        REQUIRE(canonical_subject_key(*cycle).empty());
    }

    TEST_CASE("fact values are immutable recursive handles") {
        const auto name = make_fact(UnicodeValue {"hunt"});
        const auto count = make_fact(IntegerValue {"42"});
        const auto record = make_fact(FactRecord {
            .schema = SchemaId {"example/v1"},
            .fields = {{.field_id = 1, .value = name}, {.field_id = 2, .value = count}},
        });

        REQUIRE(name.valid());
        REQUIRE(count.valid());
        REQUIRE(record.valid());
        REQUIRE(std::holds_alternative<FactRecord>(record.node->data));
    }

    TEST_CASE("bytecode verifier accepts coherent contracts and rejects contradictory certificates") {
        auto pack = minimal_pack();
        REQUIRE(verify_bytecode(pack).has_value());

        pack.optimization_certificates.push_back(OptimizationCertificate {
            .executable = ExecutableId {"example.rule"},
            .transitively_pure = true,
            .recorder_observable = false,
            .may_fault = false,
            .reads_state = false,
            .reads_history = false,
            .calls_services = false,
            .emits_effects = true,
            .logical_facts = {},
            .pure_false_prefix_exits = {},
            .semantic_hash = "sha256:certificate",
        });

        const auto result = verify_bytecode(pack);
        REQUIRE_FALSE(result.has_value());
        REQUIRE(result.error().back().code == "PYC0201");
    }

    TEST_CASE("bytecode verifier validates container iterator and state deletion encodings") {
        auto pack = minimal_pack();
        pack.constants.push_back(make_fact(std::monostate {}));
        auto &function = pack.functions.front();
        function.register_count = 4U;
        function.instructions = {
            {.opcode = Opcode::build_list,
             .destination = 0U,
             .operand_a = 1U,
             .operand_b = 2U,
             .immediate = 0U,
             .span = span()},
            {.opcode = Opcode::build_tuple,
             .destination = 1U,
             .operand_a = 0U,
             .operand_b = 1U,
             .immediate = 0U,
             .span = span()},
            {.opcode = Opcode::build_dict,
             .destination = 2U,
             .operand_a = 0U,
             .operand_b = 2U,
             .immediate = 0U,
             .span = span()},
            {.opcode = Opcode::get_iter,
             .destination = 3U,
             .operand_a = 0U,
             .operand_b = 0U,
             .immediate = 0U,
             .span = span()},
            {.opcode = Opcode::iter_next,
             .destination = 1U,
             .operand_a = 3U,
             .operand_b = 0U,
             .immediate = 7U,
             .span = span()},
            {.opcode = Opcode::load_subscript,
             .destination = 2U,
             .operand_a = 0U,
             .operand_b = 1U,
             .immediate = 0U,
             .span = span()},
            {.opcode = Opcode::store_subscript,
             .destination = 2U,
             .operand_a = 0U,
             .operand_b = 1U,
             .immediate = 0U,
             .span = span()},
            {.opcode = Opcode::delete_state,
             .destination = 0U,
             .operand_a = 0U,
             .operand_b = 0U,
             .immediate = 0U,
             .span = span()},
        };
        REQUIRE(verify_bytecode(pack).has_value());

        const auto rejects = [&](const Instruction malformed, const std::string_view code) {
            auto candidate = minimal_pack();
            candidate.functions.front().register_count = 2U;
            candidate.functions.front().instructions = {malformed};
            const auto verified = verify_bytecode(candidate);
            REQUIRE_FALSE(verified.has_value());
            CHECK(std::ranges::any_of(verified.error(), [&](const auto &item) { return item.code == code; }));
        };

        rejects(Instruction {.opcode = Opcode::build_list,
                             .destination = 0U,
                             .operand_a = 1U,
                             .operand_b = 2U,
                             .immediate = 0U,
                             .span = span()},
                "PYC0106");
        rejects(Instruction {.opcode = Opcode::build_dict,
                             .destination = 0U,
                             .operand_a = 1U,
                             .operand_b = 1U,
                             .immediate = 0U,
                             .span = span()},
                "PYC0106");
        rejects(Instruction {.opcode = Opcode::iter_next,
                             .destination = 0U,
                             .operand_a = 1U,
                             .operand_b = 0U,
                             .immediate = 1U,
                             .span = span()},
                "PYC0104");
        rejects(Instruction {.opcode = Opcode::load_subscript,
                             .destination = 0U,
                             .operand_a = 0U,
                             .operand_b = 2U,
                             .immediate = 0U,
                             .span = span()},
                "PYC0106");
        rejects(Instruction {.opcode = Opcode::get_iter,
                             .destination = 0U,
                             .operand_a = 1U,
                             .operand_b = 1U,
                             .immediate = 0U,
                             .span = span()},
                "PYC0107");
        rejects(Instruction {.opcode = Opcode::delete_state,
                             .destination = 0U,
                             .operand_a = 0U,
                             .operand_b = 0U,
                             .immediate = 0U,
                             .span = span()},
                "PYC0108");
        rejects(Instruction {.opcode = static_cast<Opcode>(std::numeric_limits<std::uint16_t>::max()), .span = span()},
                "PYC0109");
    }

    TEST_CASE("fact terminals bind one authoritative schema identity only to value responses") {
        const auto builtin = resolve_schema_identity(SchemaCatalog {}, SchemaId {"bool"});
        REQUIRE(builtin.has_value());
        REQUIRE(builtin->canonical_hash.starts_with("fnv1a64:"));

        const SubjectKey subject {.peer = PeerId {"peer"},
                                  .descriptor = SchemaId {"process/v1"},
                                  .identity = {{.field_id = 1U, .value = std::uint64_t {7U}}},
                                  .parent = nullptr};
        const FactRequest request {.request_id = RequestId {"fact"},
                                   .subject = subject,
                                   .route = {.provider = "windows", .fact = "process.signer.is_signed"},
                                   .expected_schema = builtin->id,
                                   .expected_schema_hash = builtin->canonical_hash,
                                   .deadline_unix_ms = 1U};
        FactResponse value {.request_id = request.request_id,
                            .subject = subject,
                            .status = FactTerminalStatus::value,
                            .value = make_fact(true),
                            .returned_schema = *builtin,
                            .diagnostic = std::nullopt};
        REQUIRE(valid_fact_response_shape(value));
        REQUIRE(fact_response_schema_matches(request, value));

        auto wrong_hash = value;
        wrong_hash.returned_schema->canonical_hash = "fnv1a64:0000000000000000";
        REQUIRE(valid_fact_response_shape(wrong_hash));
        REQUIRE_FALSE(fact_response_schema_matches(request, wrong_hash));

        auto missing_schema = value;
        missing_schema.returned_schema.reset();
        REQUIRE_FALSE(valid_fact_response_shape(missing_schema));

        auto mixed_value = value;
        mixed_value.diagnostic = Diagnostic {.code = "mixed",
                                             .severity = DiagnosticSeverity::error,
                                             .message = "value plus diagnostic",
                                             .span = std::nullopt,
                                             .related = {}};
        REQUIRE_FALSE(valid_fact_response_shape(mixed_value));

        FactResponse unavailable {.request_id = request.request_id,
                                  .subject = subject,
                                  .status = FactTerminalStatus::unavailable,
                                  .value = std::nullopt,
                                  .returned_schema = std::nullopt,
                                  .diagnostic = std::nullopt};
        REQUIRE(valid_fact_response_shape(unavailable));
        REQUIRE(fact_response_schema_matches(request, unavailable));
        unavailable.returned_schema = *builtin;
        REQUIRE_FALSE(valid_fact_response_shape(unavailable));

        auto unknown_terminal = unavailable;
        unknown_terminal.returned_schema.reset();
        unknown_terminal.status = static_cast<FactTerminalStatus>(0xffU);
        REQUIRE_FALSE(valid_fact_response_shape(unknown_terminal));
    }

    TEST_CASE("bytecode verifier validates typed handlers and cleanup continuations") {
        auto valid = minimal_pack();
        valid.functions.front().register_count = 3U;
        valid.functions.front().instructions = {
            {.opcode = Opcode::raise_fault,
             .destination = 0U,
             .operand_a = 0U,
             .operand_b = 0U,
             .immediate = std::to_underlying(PythonFaultKind::value_error),
             .span = span()},
            {.opcode = Opcode::unwind_jump,
             .destination = 0U,
             .operand_a = 0U,
             .operand_b = 0U,
             .immediate = 8U,
             .span = span()},
            {.opcode = Opcode::leave_try, .span = span()},
            {.opcode = Opcode::reraise, .span = span()},
            {.opcode = Opcode::match_exception,
             .destination = 1U,
             .operand_a = 7U,
             .operand_b = 5U,
             .immediate = std::to_underlying(PythonFaultKind::arithmetic_error),
             .span = span()},
            {.opcode = Opcode::match_exception,
             .destination = 1U,
             .operand_a = 7U,
             .operand_b = 6U,
             .immediate = std::to_underlying(PythonFaultKind::value_error),
             .span = span()},
            {.opcode = Opcode::reraise, .span = span()},
            {.opcode = Opcode::load_current_exception, .destination = 2U, .span = span()},
            {.opcode = Opcode::return_value, .destination = 0U, .operand_a = 0U, .span = span()},
        };
        valid.functions.front().exception_regions = {
            ExceptionRegion {.begin_instruction = 0U,
                             .end_instruction = 1U,
                             .handler_instruction = 4U,
                             .cleanup_instruction = 4U,
                             .kind = ExceptionRegionKind::handler},
            ExceptionRegion {.begin_instruction = 1U,
                             .end_instruction = 2U,
                             .handler_instruction = 3U,
                             .cleanup_instruction = 2U,
                             .kind = ExceptionRegionKind::cleanup},
        };
        REQUIRE(verify_bytecode(valid).has_value());

        SECTION("partially overlapping protected intervals are rejected") {
            auto malformed = valid;
            malformed.functions.front().exception_regions = {
                ExceptionRegion {.begin_instruction = 0U,
                                 .end_instruction = 3U,
                                 .handler_instruction = 4U,
                                 .cleanup_instruction = 4U},
                ExceptionRegion {.begin_instruction = 2U,
                                 .end_instruction = 4U,
                                 .handler_instruction = 6U,
                                 .cleanup_instruction = 6U},
            };
            const auto result = verify_bytecode(malformed);
            REQUIRE_FALSE(result.has_value());
            CHECK(std::ranges::any_of(result.error(), [](const auto &item) { return item.code == "PYC0111"; }));
        }

        SECTION("filter continuation cycles are rejected") {
            auto malformed = minimal_pack();
            malformed.functions.front().register_count = 2U;
            malformed.functions.front().instructions = {
                {.opcode = Opcode::raise_fault, .operand_a = 0U, .span = span()},
                {.opcode = Opcode::match_exception,
                 .destination = 1U,
                 .operand_a = 3U,
                 .operand_b = 1U,
                 .immediate = std::to_underlying(PythonFaultKind::type_error),
                 .span = span()},
                {.opcode = Opcode::reraise, .span = span()},
                {.opcode = Opcode::return_value, .operand_a = 0U, .span = span()},
            };
            malformed.functions.front().exception_regions = {
                ExceptionRegion {.begin_instruction = 0U,
                                 .end_instruction = 1U,
                                 .handler_instruction = 1U,
                                 .cleanup_instruction = 1U},
            };
            const auto result = verify_bytecode(malformed);
            REQUIRE_FALSE(result.has_value());
            CHECK(std::ranges::any_of(result.error(), [](const auto &item) { return item.code == "PYC0112"; }));
        }

        SECTION("ordinary fallthrough cannot bypass finally") {
            auto malformed = minimal_pack();
            malformed.functions.front().instructions = {
                {.opcode = Opcode::load_const, .destination = 0U, .span = span()},
                {.opcode = Opcode::return_value, .operand_a = 0U, .span = span()},
                {.opcode = Opcode::leave_try, .span = span()},
                {.opcode = Opcode::reraise, .span = span()},
            };
            malformed.functions.front().exception_regions = {
                ExceptionRegion {.begin_instruction = 0U,
                                 .end_instruction = 1U,
                                 .handler_instruction = 3U,
                                 .cleanup_instruction = 2U,
                                 .kind = ExceptionRegionKind::cleanup},
            };
            const auto result = verify_bytecode(malformed);
            REQUIRE_FALSE(result.has_value());
            CHECK(std::ranges::any_of(result.error(), [](const auto &item) { return item.code == "PYC0114"; }));
        }
    }

} // namespace
