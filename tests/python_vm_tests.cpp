#include "rule_engine/python/vm/register_vm.hpp"

#if defined(__clang__)
#pragma clang diagnostic ignored "-Wc2y-extensions"
#endif

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <utility>
#include <vector>

namespace {

    using namespace rule_engine::python;
    using namespace rule_engine::python::vm;

    [[nodiscard]] SourceSpan source_span(const std::uint32_t begin = 0U) {
        return SourceSpan {.source = SourceId {"rules.main"}, .begin_byte = begin, .end_byte = begin + 1U};
    }

    [[nodiscard]] FactValue text(std::string value) { return make_fact(UnicodeValue {.utf8 = std::move(value)}); }

    [[nodiscard]] FactValue integer(std::string value) { return make_fact(IntegerValue {.decimal = std::move(value)}); }

    [[nodiscard]] SubjectKey subject() {
        return SubjectKey {
            .peer = PeerId {"peer-1"},
            .descriptor = SchemaId {"process.v1"},
            .identity = {IdentityField {.field_id = 1U, .value = std::uint64_t {42U}}},
            .parent = {},
        };
    }

    [[nodiscard]] CompiledPack pack_with(std::vector<FactValue> constants, std::vector<BytecodeFunction> functions,
                                         const std::string &entry = "rule.main") {
        return CompiledPack {
            .pack = PackId {"pack"},
            .version = PackVersion {"1"},
            .source_digest = SourceDigest {"sha256:source"},
            .compiler_abi = "python-3.14.6/vm-tests",
            .semantic_hash = "sha256:semantic",
            .schemas = {},
            .constants = std::move(constants),
            .functions = std::move(functions),
            .bindings = {OperatorBinding {.id = BindingId {"binding"},
                                          .executable = ExecutableId {entry},
                                          .capabilities = {},
                                          .budget = balanced_v1}},
            .optimization_certificates = {},
        };
    }

    [[nodiscard]] VmInvocation invocation(BudgetProfile budget = balanced_v1) {
        return VmInvocation {
            .execution = ExecutionId {"execution"},
            .invocation = InvocationId {"invocation"},
            .binding = BindingId {"binding"},
            .subject = subject(),
            .budget = budget,
            .deterministic_hash_seed = 7U,
        };
    }

    [[nodiscard]] Instruction instruction(const Opcode opcode, const std::uint32_t destination = 0U,
                                          const std::uint32_t operand_a = 0U, const std::uint32_t operand_b = 0U,
                                          const std::uint32_t immediate = 0U, const std::uint32_t source_offset = 0U) {
        return Instruction {.opcode = opcode,
                            .destination = destination,
                            .operand_a = operand_a,
                            .operand_b = operand_b,
                            .immediate = immediate,
                            .span = source_span(source_offset)};
    }

    [[nodiscard]] BytecodeFunction function(std::string id, const std::uint32_t registers,
                                            std::vector<Instruction> instructions, const bool generator = false,
                                            const std::uint32_t parameters = 0U) {
        return BytecodeFunction {
            .id = ExecutableId {std::move(id)},
            .qualified_name = "rules.main",
            .register_count = registers,
            .parameter_count = parameters,
            .generator = generator,
            .async = false,
            .instructions = std::move(instructions),
            .exception_regions = {},
        };
    }

    [[nodiscard]] std::unique_ptr<RegisterVmSession> start(const CompiledPack &pack,
                                                           const VmInvocation &requested = invocation()) {
        auto session = RegisterVmSession::create(pack, requested);
        REQUIRE(session.has_value());
        return std::move(*session);
    }

    [[nodiscard]] std::string frozen_integer(const FrozenValue &value) {
        REQUIRE(value.value.valid());
        const auto *number = std::get_if<IntegerValue>(&value.value.node->data);
        REQUIRE(number != nullptr);
        return number->decimal;
    }

    [[nodiscard]] FrozenValue canonical_frozen(const FactValue &value) {
        ValueHeap heap;
        auto thawed = heap.thaw(value);
        REQUIRE(thawed.has_value());
        auto frozen = heap.freeze(*thawed);
        REQUIRE(frozen.has_value());
        return std::move(*frozen);
    }

    [[nodiscard]] bool frozen_boolean(const FrozenValue &value) {
        REQUIRE(value.value.valid());
        const auto *boolean = std::get_if<bool>(&value.value.node->data);
        REQUIRE(boolean != nullptr);
        return *boolean;
    }

    [[nodiscard]] VmStep run_internal(RegisterVmSession &session, VmStep current) {
        for (std::size_t turns = 0U;
             turns < 32U && current.state == VmStepState::yielded && !current.yielded_value.has_value() &&
             current.fact_requests.empty() && current.capability_requests.empty() && current.state_requests.empty();
             ++turns) {
            current = session.step({});
        }
        return current;
    }

} // namespace

TEST_CASE("VM heap supports arbitrary decimal integers Unicode and Python truthiness") {
    ValueHeap heap;
    auto left = heap.allocate_integer("9999999999999999999999999999999999999999");
    auto one = heap.allocate_integer("1");
    REQUIRE(left.has_value());
    REQUIRE(one.has_value());

    auto sum = heap.binary(BinaryOperation::add, *left, *one);
    REQUIRE(sum.has_value());
    CHECK(heap.integer_decimal(*sum) == "10000000000000000000000000000000000000000");

    auto negative = heap.unary(UnaryOperation::negative, *sum);
    REQUIRE(negative.has_value());
    CHECK(heap.integer_decimal(*negative) == "-10000000000000000000000000000000000000000");
    CHECK(heap.truthy(*negative) == true);

    auto unicode = heap.allocate_unicode("Zażółć 🐍");
    REQUIRE(unicode.has_value());
    CHECK(heap.unicode_utf8(*unicode) == "Zażółć 🐍");
    auto empty = heap.allocate_unicode("");
    REQUIRE(empty.has_value());
    CHECK(heap.truthy(*empty) == false);

    auto ninety_nine = heap.allocate_integer("99");
    REQUIRE(ninety_nine.has_value());
    auto product = heap.binary(BinaryOperation::multiply, *ninety_nine, *ninety_nine);
    REQUIRE(product.has_value());
    CHECK(heap.integer_decimal(*product) == "9801");
}

TEST_CASE("stable heap handles survive collection and stale generations are rejected") {
    ValueHeap heap;
    auto retained = heap.allocate_integer("7");
    auto discarded = heap.allocate_integer("8");
    REQUIRE(retained.has_value());
    REQUIRE(discarded.has_value());

    const std::vector roots {*retained};
    auto reclaimed = heap.collect(roots);
    REQUIRE(reclaimed.has_value());
    CHECK(*reclaimed > 0U);
    CHECK(heap.valid(*retained));
    CHECK_FALSE(heap.valid(*discarded));

    auto replacement = heap.allocate_integer("9");
    REQUIRE(replacement.has_value());
    CHECK(replacement->slot == discarded->slot);
    CHECK(replacement->generation != discarded->generation);
    CHECK_FALSE(heap.integer_decimal(*discarded).has_value());
}

TEST_CASE("boundary freezing is deterministic and rejects cyclic containers") {
    ValueHeap first;
    auto key = first.allocate_unicode("key");
    auto value = first.allocate_integer("12345678901234567890");
    REQUIRE(key.has_value());
    REQUIRE(value.has_value());
    const std::vector<std::pair<PyValue, PyValue>> entries {{*key, *value}};
    auto map = first.allocate_map(entries);
    REQUIRE(map.has_value());
    auto frozen = first.freeze(*map);
    REQUIRE(frozen.has_value());

    ValueHeap second;
    auto second_key = second.allocate_unicode("key");
    auto second_value = second.allocate_integer("12345678901234567890");
    REQUIRE(second_key.has_value());
    REQUIRE(second_value.has_value());
    const std::vector<std::pair<PyValue, PyValue>> second_entries {{*second_key, *second_value}};
    auto second_map = second.allocate_map(second_entries);
    REQUIRE(second_map.has_value());
    auto second_frozen = second.freeze(*second_map);
    REQUIRE(second_frozen.has_value());
    CHECK(frozen->canonical_digest == second_frozen->canonical_digest);

    auto cycle = first.allocate_list();
    REQUIRE(cycle.has_value());
    REQUIRE(first.list_append(*cycle, *cycle).has_value());
    auto rejected = first.freeze(*cycle);
    REQUIRE_FALSE(rejected.has_value());
    CHECK(rejected.error().code == FreezeErrorCode::cycle);
}

TEST_CASE("heap and boundary limits are checked before mutation") {
    ValueHeap tiny {256U};
    auto oversized = tiny.allocate_unicode(std::string(1024U, 'x'));
    REQUIRE_FALSE(oversized.has_value());
    CHECK(oversized.error().code == VmErrorCode::heap_budget_exhausted);
    CHECK(tiny.stats().live_objects == 0U);

    ValueHeap heap;
    auto value = heap.allocate_unicode("payload");
    REQUIRE(value.has_value());
    auto frozen = heap.freeze(*value, {}, FreezeLimits {.maximum_bytes = 3U});
    REQUIRE_FALSE(frozen.has_value());
    CHECK(frozen.error().code == FreezeErrorCode::budget_exhausted);
}

TEST_CASE("Python operator ABI implements numeric bitwise and containment semantics") {
    STATIC_REQUIRE(static_cast<std::uint32_t>(UnaryOperation::invert) == 3U);
    STATIC_REQUIRE(static_cast<std::uint32_t>(BinaryOperation::bit_and) == 11U);
    STATIC_REQUIRE(static_cast<std::uint32_t>(CompareOperation::not_contains) == 9U);

    ValueHeap heap;
    auto negative_seven = heap.allocate_integer("-7");
    auto three = heap.allocate_integer("3");
    auto five = heap.allocate_integer("5");
    auto six = heap.allocate_integer("6");
    REQUIRE(negative_seven.has_value());
    REQUIRE(three.has_value());
    REQUIRE(five.has_value());
    REQUIRE(six.has_value());

    auto quotient = heap.binary(BinaryOperation::floor_divide, *negative_seven, *three);
    auto remainder = heap.binary(BinaryOperation::modulo, *negative_seven, *three);
    auto power = heap.binary(BinaryOperation::power, *three, *five);
    auto shifted = heap.binary(BinaryOperation::left_shift, *three, *three);
    auto inverted = heap.unary(UnaryOperation::invert, *five);
    auto conjunction = heap.binary(BinaryOperation::bit_and, *negative_seven, *six);
    REQUIRE(quotient.has_value());
    REQUIRE(remainder.has_value());
    REQUIRE(power.has_value());
    REQUIRE(shifted.has_value());
    REQUIRE(inverted.has_value());
    REQUIRE(conjunction.has_value());
    CHECK(heap.integer_decimal(*quotient) == "-3");
    CHECK(heap.integer_decimal(*remainder) == "2");
    CHECK(heap.integer_decimal(*power) == "243");
    CHECK(heap.integer_decimal(*shifted) == "24");
    CHECK(heap.integer_decimal(*inverted) == "-6");
    auto conjunction_text = heap.integer_decimal(*conjunction);
    REQUIRE(conjunction_text.has_value());
    CHECK(*conjunction_text == "0");

    auto one = heap.allocate_integer("1");
    auto one_float = heap.allocate_float(1.0);
    auto large = heap.allocate_integer("9007199254740993");
    auto rounded_float = heap.allocate_float(9007199254740992.0);
    REQUIRE(one.has_value());
    REQUIRE(one_float.has_value());
    REQUIRE(large.has_value());
    REQUIRE(rounded_float.has_value());
    CHECK(heap.compare_operation(CompareOperation::equal, *one, *one_float) == true);
    CHECK(heap.compare_operation(CompareOperation::greater, *large, *rounded_float) == true);

    auto positive_zero = heap.allocate_float(0.0);
    auto negative_zero = heap.allocate_float(-0.0);
    auto positive_infinity = heap.allocate_float(std::numeric_limits<double>::infinity());
    auto second_positive_infinity = heap.allocate_float(std::numeric_limits<double>::infinity());
    auto negative_infinity = heap.allocate_float(-std::numeric_limits<double>::infinity());
    auto not_a_number = heap.allocate_float(std::numeric_limits<double>::quiet_NaN());
    auto second_not_a_number = heap.allocate_float(std::numeric_limits<double>::quiet_NaN());
    REQUIRE(positive_zero.has_value());
    REQUIRE(negative_zero.has_value());
    REQUIRE(positive_infinity.has_value());
    REQUIRE(second_positive_infinity.has_value());
    REQUIRE(negative_infinity.has_value());
    REQUIRE(not_a_number.has_value());
    REQUIRE(second_not_a_number.has_value());
    CHECK(heap.compare_operation(CompareOperation::equal, *positive_zero, *negative_zero) == true);
    CHECK(heap.compare_operation(CompareOperation::equal, *positive_infinity, *second_positive_infinity) == true);
    CHECK(heap.compare_operation(CompareOperation::equal, *positive_infinity, *negative_infinity) == false);
    CHECK(heap.compare_operation(CompareOperation::equal, *not_a_number, *not_a_number) == false);
    CHECK(heap.compare_operation(CompareOperation::equal, *not_a_number, *second_not_a_number) == false);
    CHECK(heap.compare_operation(CompareOperation::not_equal, *not_a_number, *not_a_number) == true);

    auto needle = heap.allocate_unicode("żół");
    auto haystack = heap.allocate_unicode("Zażółć");
    REQUIRE(needle.has_value());
    REQUIRE(haystack.has_value());
    CHECK(heap.compare_operation(CompareOperation::contains, *needle, *haystack) == true);
    const std::array list_values {*three, *five};
    auto list = heap.allocate_list(list_values);
    REQUIRE(list.has_value());
    CHECK(heap.compare_operation(CompareOperation::contains, *five, *list) == true);
    CHECK(heap.compare_operation(CompareOperation::identity, *five, *five) == true);
    CHECK(heap.compare_operation(CompareOperation::not_identity, *five, *three) == true);
}

TEST_CASE("records and maps have canonical schema-checked boundaries") {
    ValueHeap heap;
    auto name = heap.allocate_unicode("alice");
    auto enabled = heap.allocate_bool(true);
    REQUIRE(name.has_value());
    REQUIRE(enabled.has_value());
    const std::array fields {
        RecordFieldValue {.field_id = 2U, .value = *enabled},
        RecordFieldValue {.field_id = 1U, .value = *name},
    };
    auto record = heap.allocate_record(SchemaId {"account.v1"}, fields);
    REQUIRE(record.has_value());
    auto frozen_record = heap.freeze(*record);
    REQUIRE(frozen_record.has_value());
    const auto *fact_record = std::get_if<FactRecord>(&frozen_record->value.node->data);
    REQUIRE(fact_record != nullptr);
    REQUIRE(fact_record->fields.size() == 2U);
    CHECK(fact_record->fields[0].field_id == 1U);

    SchemaCatalog schemas {
        .descriptors = {SchemaDescriptor {
            .id = SchemaId {"account.v1"},
            .kind = SchemaKind::state,
            .qualified_name = "Account",
            .canonical_hash = "sha256:account",
            .fields =
                {
                    SchemaField {
                        .field_id = 1U, .name = "name", .type = SchemaId {"text"}, .optional = false, .label = {}},
                    SchemaField {
                        .field_id = 2U, .name = "enabled", .type = SchemaId {"bool"}, .optional = false, .label = {}},
                }}},
        .canonical_hash = "sha256:schemas",
    };
    REQUIRE(ValueHeap::validate_schema(frozen_record->value, SchemaId {"account.v1"}, &schemas).has_value());
    auto tampered = *frozen_record;
    tampered.canonical_digest = "fnv1a64:0000000000000000";
    CHECK_FALSE(heap.validate_frozen(tampered, SchemaId {"account.v1"}, &schemas).has_value());

    auto key_a = heap.allocate_unicode("a");
    auto key_b = heap.allocate_unicode("b");
    auto value_a = heap.allocate_integer("1");
    auto value_b = heap.allocate_integer("2");
    REQUIRE(key_a.has_value());
    REQUIRE(key_b.has_value());
    REQUIRE(value_a.has_value());
    REQUIRE(value_b.has_value());
    const std::array first_entries {std::pair {*key_b, *value_b}, std::pair {*key_a, *value_a}};
    const std::array second_entries {std::pair {*key_a, *value_a}, std::pair {*key_b, *value_b}};
    auto first = heap.allocate_map(first_entries);
    auto second = heap.allocate_map(second_entries);
    REQUIRE(first.has_value());
    REQUIRE(second.has_value());
    auto first_frozen = heap.freeze(*first);
    auto second_frozen = heap.freeze(*second);
    REQUIRE(first_frozen.has_value());
    REQUIRE(second_frozen.has_value());
    CHECK(first_frozen->canonical_digest == second_frozen->canonical_digest);
}

TEST_CASE("fact suspension resumes the exact PC without duplicate reads or intents") {
    auto pack = pack_with(
        {
            text("before"),
            text("trace"),
            make_fact_operand(FactRoute {.provider = "process", .fact = "is_signed"}, SchemaId {"bool"}),
        },
        {function("rule.main", 2U,
                  {
                      instruction(Opcode::load_const, 0U, 0U, 0U, 0U, 0U),
                      instruction(Opcode::append_effect, 0U, 0U, 0U, 1U, 1U),
                      instruction(Opcode::await_fact, 1U, 0U, 0U, 2U, 2U),
                      instruction(Opcode::return_value, 0U, 1U, 0U, 0U, 3U),
                  })});
    auto session = start(pack);

    const auto waiting = session->step({});
    REQUIRE(waiting.state == VmStepState::waiting_for_facts);
    REQUIRE(waiting.fact_requests.size() == 1U);
    REQUIRE(waiting.journal_delta.size() == 1U);
    CHECK(session->logical_read_count() == 1U);
    CHECK(session->journal_size() == 1U);
    const auto request = waiting.fact_requests.front();
    const auto intent_id = waiting.journal_delta.front().id;

    const auto still_waiting = session->step({});
    CHECK(still_waiting.state == VmStepState::waiting_for_facts);
    CHECK(still_waiting.fact_requests.empty());
    CHECK(still_waiting.journal_delta.empty());
    CHECK(session->logical_read_count() == 1U);
    CHECK(session->journal_size() == 1U);

    HostResponses response;
    response.facts.push_back(FactResponse {.request_id = request.request_id,
                                           .subject = request.subject,
                                           .status = FactTerminalStatus::value,
                                           .value = make_fact(true),
                                           .diagnostic = std::nullopt});
    const auto complete = session->step(std::move(response));
    REQUIRE(complete.state == VmStepState::complete);
    REQUIRE(complete.result.has_value());
    CHECK(complete.result->verdict == true);
    REQUIRE(complete.result->committed_effects.size() == 1U);
    CHECK(complete.result->committed_effects.front().id == intent_id);
    CHECK(complete.journal_delta.empty());
    CHECK(session->logical_read_count() == 1U);
    CHECK(session->journal_size() == 1U);
}

TEST_CASE("capability suspension freezes arguments and correlates its response") {
    auto pack = pack_with(
        {
            integer("41"),
            make_capability_operand(CapabilityId {"reputation.lookup"}, SchemaId {"lookup.request.v1"}),
        },
        {function("rule.main", 2U,
                  {
                      instruction(Opcode::load_const, 0U, 0U, 0U, 0U),
                      instruction(Opcode::await_capability, 1U, 0U, 0U, 1U),
                      instruction(Opcode::return_value, 0U, 1U),
                  })});
    auto session = start(pack);
    const auto waiting = session->step({});
    REQUIRE(waiting.state == VmStepState::waiting_for_capabilities);
    REQUIRE(waiting.capability_requests.size() == 1U);
    CHECK(frozen_integer(waiting.capability_requests.front().arguments) == "41");

    HostResponses response;
    response.capabilities.push_back(CapabilityResponse {
        .request_id = waiting.capability_requests.front().request_id,
        .status = FactTerminalStatus::value,
        .value = canonical_frozen(make_fact(true)),
        .diagnostic = std::nullopt,
    });
    const auto complete = session->step(std::move(response));
    REQUIRE(complete.state == VmStepState::complete);
    REQUIRE(complete.result.has_value());
    CHECK(complete.result->outcome == EvaluationOutcome::match);
}

TEST_CASE("invalid host responses fail closed without resuming the continuation") {
    auto pack = pack_with({make_fact_operand(FactRoute {.provider = "process", .fact = "name"}, SchemaId {"text"})},
                          {function("rule.main", 1U,
                                    {
                                        instruction(Opcode::await_fact, 0U, 0U, 0U, 0U),
                                        instruction(Opcode::return_value, 0U, 0U),
                                    })});
    auto session = start(pack);
    const auto waiting = session->step({});
    REQUIRE(waiting.fact_requests.size() == 1U);

    HostResponses response;
    response.facts.push_back(FactResponse {.request_id = RequestId {"stale-request"},
                                           .subject = waiting.fact_requests.front().subject,
                                           .status = FactTerminalStatus::value,
                                           .value = make_fact(true),
                                           .diagnostic = std::nullopt});
    const auto faulted = session->step(std::move(response));
    REQUIRE(faulted.state == VmStepState::faulted);
    REQUIRE(faulted.result.has_value());
    REQUIRE(faulted.result->fault.has_value());
    REQUIRE(faulted.result->fault->frames.size() == 1U);
    CHECK(faulted.result->fault->frames.front().code == "PYVM3001");
    CHECK(session->logical_read_count() == 1U);
}

TEST_CASE("state reads suspend once validate boundaries and preserve read-your-writes") {
    auto pack = pack_with(
        {
            make_state_operand("tenant", "enabled", SchemaId {"bool"}),
            make_fact(true),
        },
        {function("rule.main", 3U,
                  {
                      instruction(Opcode::read_state, 0U, 0U, 0U, 0U),
                      instruction(Opcode::load_const, 1U, 0U, 0U, 1U),
                      instruction(Opcode::write_state, 0U, 1U, 0U, 0U),
                      instruction(Opcode::read_state, 2U, 0U, 0U, 0U),
                      instruction(Opcode::return_value, 0U, 2U),
                  })});
    auto session = start(pack);
    const auto waiting = session->step({});
    REQUIRE(waiting.state == VmStepState::yielded);
    REQUIRE(waiting.state_requests.size() == 1U);
    CHECK(waiting.state_requests.front().namespace_name == "tenant");
    CHECK(waiting.state_requests.front().key == "enabled");
    CHECK(session->logical_read_count() == 1U);
    CHECK(session->counters().state_keys == 1U);

    const auto still_waiting = session->step({});
    CHECK(still_waiting.state == VmStepState::yielded);
    CHECK(still_waiting.state_requests.empty());
    CHECK(session->logical_read_count() == 1U);

    HostResponses response;
    response.state.push_back(StateReadResponse {.request_id = waiting.state_requests.front().request_id,
                                                .value = canonical_frozen(make_fact(false)),
                                                .version = 7U,
                                                .diagnostic = std::nullopt});
    const auto complete = session->step(std::move(response));
    REQUIRE(complete.state == VmStepState::complete);
    REQUIRE(complete.result.has_value());
    CHECK(complete.result->verdict == true);
    REQUIRE(complete.result->state_mutations.size() == 1U);
    CHECK(complete.result->state_mutations.front().expected_version == 7U);
    REQUIRE(complete.result->state_mutations.front().value.has_value());
    CHECK(frozen_boolean(*complete.result->state_mutations.front().value) == true);
    CHECK(session->logical_read_count() == 1U);
}

TEST_CASE("state responses fail closed on non-canonical digests and schemas") {
    auto make_pack = [] {
        return pack_with({make_state_operand("tenant", "enabled", SchemaId {"bool"})},
                         {function("rule.main", 1U,
                                   {
                                       instruction(Opcode::read_state, 0U, 0U, 0U, 0U),
                                       instruction(Opcode::return_value, 0U, 0U),
                                   })});
    };

    SECTION("digest") {
        const auto pack = make_pack();
        auto session = start(pack);
        const auto waiting = session->step({});
        auto value = canonical_frozen(make_fact(true));
        value.canonical_digest = "fnv1a64:bad";
        HostResponses response;
        response.state.push_back(StateReadResponse {.request_id = waiting.state_requests.front().request_id,
                                                    .value = std::move(value),
                                                    .version = 1U,
                                                    .diagnostic = std::nullopt});
        const auto faulted = session->step(std::move(response));
        CHECK(faulted.state == VmStepState::faulted);
    }

    SECTION("schema") {
        const auto pack = make_pack();
        auto session = start(pack);
        const auto waiting = session->step({});
        HostResponses response;
        response.state.push_back(StateReadResponse {.request_id = waiting.state_requests.front().request_id,
                                                    .value = canonical_frozen(text("not a bool")),
                                                    .version = 1U,
                                                    .diagnostic = std::nullopt});
        const auto faulted = session->step(std::move(response));
        CHECK(faulted.state == VmStepState::faulted);
    }
}

TEST_CASE("transactions atomically commit or roll back effects and state overlays") {
    auto transaction_pack = [](const Opcode exit_opcode, const bool prewrite) {
        std::vector<Instruction> body;
        if (prewrite) {
            body.push_back(instruction(Opcode::load_const, 0U, 0U, 0U, 1U));
            body.push_back(instruction(Opcode::write_state, 0U, 0U, 0U, 0U));
        }
        body.push_back(instruction(Opcode::begin_transaction));
        body.push_back(instruction(Opcode::load_const, 1U, 0U, 0U, 2U));
        body.push_back(instruction(Opcode::write_state, 0U, 1U, 0U, 0U));
        body.push_back(instruction(Opcode::append_effect, 0U, 1U, 0U, 3U));
        if (exit_opcode != Opcode::return_value) {
            body.push_back(instruction(exit_opcode));
        }
        body.push_back(instruction(Opcode::read_state, 2U, 0U, 0U, 0U));
        body.push_back(instruction(Opcode::compare, 3U, 2U, prewrite ? 0U : 1U,
                                   static_cast<std::uint32_t>(CompareOperation::equal)));
        body.push_back(instruction(Opcode::return_value, 0U, 3U));
        return pack_with(
            {
                make_state_operand("tenant", "flag", SchemaId {"bool"}),
                make_fact(false),
                make_fact(true),
                text("audit"),
            },
            {function("rule.main", 4U, std::move(body))});
    };

    SECTION("explicit rollback restores a mutation that existed before the transaction") {
        const auto pack = transaction_pack(Opcode::rollback_transaction, true);
        auto session = start(pack);
        const auto complete = session->step({});
        REQUIRE(complete.state == VmStepState::complete);
        REQUIRE(complete.result.has_value());
        CHECK(complete.result->verdict == true);
        CHECK(complete.result->committed_effects.empty());
        REQUIRE(complete.result->state_mutations.size() == 1U);
        REQUIRE(complete.result->state_mutations.front().value.has_value());
        CHECK(frozen_boolean(*complete.result->state_mutations.front().value) == false);
        REQUIRE(complete.journal_delta.size() == 1U);
        CHECK(complete.journal_delta.front().disposition == EffectDisposition::rolled_back);
    }

    SECTION("commit publishes both state and effect") {
        const auto pack = transaction_pack(Opcode::commit_transaction, false);
        auto session = start(pack);
        const auto complete = session->step({});
        REQUIRE(complete.result.has_value());
        CHECK(complete.result->verdict == true);
        REQUIRE(complete.result->committed_effects.size() == 1U);
        REQUIRE(complete.result->state_mutations.size() == 1U);
        CHECK(frozen_boolean(*complete.result->state_mutations.front().value) == true);
    }

    SECTION("an open transaction rolls back at return") {
        const auto pack = transaction_pack(Opcode::return_value, false);
        auto session = start(pack);
        const auto complete = session->step({});
        REQUIRE(complete.result.has_value());
        CHECK(complete.result->committed_effects.empty());
        CHECK(complete.result->state_mutations.empty());
    }
}

TEST_CASE("typed fact terminals enter verifier-approved exception regions") {
    auto body = function("rule.main", 3U,
                         {
                             instruction(Opcode::await_fact, 0U, 0U, 0U, 0U, 0U),
                             instruction(Opcode::load_const, 1U, 0U, 0U, 1U, 1U),
                             instruction(Opcode::return_value, 0U, 1U, 0U, 0U, 2U),
                             instruction(Opcode::load_const, 2U, 0U, 0U, 2U, 3U),
                             instruction(Opcode::return_value, 0U, 2U, 0U, 0U, 4U),
                         });
    body.exception_regions.push_back(ExceptionRegion {
        .begin_instruction = 0U, .end_instruction = 1U, .handler_instruction = 3U, .cleanup_instruction = 3U});
    auto pack = pack_with(
        {
            make_fact_operand(FactRoute {.provider = "process", .fact = "optional"}, SchemaId {"bool"}),
            make_fact(false),
            make_fact(true),
        },
        {std::move(body)});
    auto session = start(pack);
    const auto waiting = session->step({});
    REQUIRE(waiting.fact_requests.size() == 1U);

    HostResponses response;
    response.facts.push_back(FactResponse {.request_id = waiting.fact_requests.front().request_id,
                                           .subject = waiting.fact_requests.front().subject,
                                           .status = FactTerminalStatus::denied,
                                           .value = std::nullopt,
                                           .diagnostic = std::nullopt});
    const auto recovered = session->step(std::move(response));
    REQUIRE(recovered.state == VmStepState::complete);
    REQUIRE(recovered.result.has_value());
    CHECK(recovered.result->verdict == true);
}

TEST_CASE("static calls return through explicit frames and preserve arbitrary integer arithmetic") {
    auto pack = pack_with(
        {integer("100000000000000000000"), integer("23"), integer("100000000000000000023")},
        {
            function("rule.main", 4U,
                     {
                         instruction(Opcode::load_const, 0U, 0U, 0U, 0U),
                         instruction(Opcode::load_const, 1U, 0U, 0U, 1U),
                         instruction(Opcode::call, 2U, 0U, 2U, 1U),
                         instruction(Opcode::load_const, 3U, 0U, 0U, 2U),
                         instruction(Opcode::compare, 2U, 2U, 3U, static_cast<std::uint32_t>(CompareOperation::equal)),
                         instruction(Opcode::return_value, 0U, 2U),
                     }),
            function("helper", 3U,
                     {
                         instruction(Opcode::binary_op, 2U, 0U, 1U, static_cast<std::uint32_t>(BinaryOperation::add)),
                         instruction(Opcode::return_value, 0U, 2U),
                     },
                     false, 2U),
        });
    auto session = start(pack);
    const auto complete = session->step({});
    REQUIRE(complete.state == VmStepState::complete);
    REQUIRE(complete.result.has_value());
    CHECK(complete.result->verdict == true);
    CHECK(session->counters().peak_frames == 2U);
}

TEST_CASE("bound entrypoints admit the compiler subject parameter ABI") {
    auto pack = pack_with({}, {function("rule.main", 1U, {instruction(Opcode::return_value, 0U, 0U)}, false, 1U)});
    auto session = start(pack);
    const auto complete = session->step({});
    REQUIRE(complete.state == VmStepState::complete);
    REQUIRE(complete.result.has_value());
    CHECK(complete.result->outcome == EvaluationOutcome::no_match);
}

TEST_CASE("author exceptions cross call frames into caller handlers") {
    auto main = function("rule.main", 2U,
                         {
                             instruction(Opcode::call, 0U, 0U, 0U, 1U, 0U),
                             instruction(Opcode::return_value, 0U, 0U, 0U, 0U, 1U),
                             instruction(Opcode::load_const, 1U, 0U, 0U, 1U, 2U),
                             instruction(Opcode::return_value, 0U, 1U, 0U, 0U, 3U),
                         });
    main.exception_regions.push_back(ExceptionRegion {
        .begin_instruction = 0U, .end_instruction = 1U, .handler_instruction = 2U, .cleanup_instruction = 2U});
    auto pack =
        pack_with({text("boom"), make_fact(true)}, {
                                                       std::move(main),
                                                       function("helper", 1U,
                                                                {
                                                                    instruction(Opcode::load_const, 0U, 0U, 0U, 0U),
                                                                    instruction(Opcode::raise_fault, 0U, 0U),
                                                                }),
                                                   });
    auto session = start(pack);
    const auto complete = session->step({});
    REQUIRE(complete.state == VmStepState::complete);
    REQUIRE(complete.result.has_value());
    CHECK(complete.result->verdict == true);
    CHECK(session->counters().peak_frames == 2U);
}

TEST_CASE("return unwind runs every nested cleanup exactly once") {
    auto body = function("rule.main", 1U,
                         {
                             instruction(Opcode::load_const, 0U, 0U, 0U, 0U),
                             instruction(Opcode::return_value, 0U, 0U),
                             instruction(Opcode::leave_try),
                             instruction(Opcode::leave_try),
                         });
    body.exception_regions.push_back(ExceptionRegion {
        .begin_instruction = 0U, .end_instruction = 2U, .handler_instruction = 3U, .cleanup_instruction = 3U});
    body.exception_regions.push_back(ExceptionRegion {
        .begin_instruction = 1U, .end_instruction = 2U, .handler_instruction = 2U, .cleanup_instruction = 2U});
    auto pack = pack_with({make_fact(true)}, {std::move(body)});
    auto session = start(pack);
    const auto complete = session->step({});
    REQUIRE(complete.state == VmStepState::complete);
    CHECK(session->counters().instructions == 4U);
}

TEST_CASE("hard faults run cross-frame cleanup but remain unsuppressible") {
    auto main = function("rule.main", 1U,
                         {
                             instruction(Opcode::call, 0U, 0U, 0U, 1U),
                             instruction(Opcode::return_value, 0U, 0U),
                             instruction(Opcode::leave_try),
                             instruction(Opcode::load_const, 0U, 0U, 0U, 0U),
                             instruction(Opcode::return_value, 0U, 0U),
                         });
    main.exception_regions.push_back(ExceptionRegion {
        .begin_instruction = 0U, .end_instruction = 1U, .handler_instruction = 3U, .cleanup_instruction = 2U});
    auto pack = pack_with(
        {
            make_fact(true),
            make_handler_metadata(ExecutableId {"rule.main"}, std::nullopt, ExecutableId {"rule.on_fault"},
                                  std::nullopt),
        },
        {
            std::move(main),
            function("helper", 1U, {instruction(Opcode::jump, 0U, 0U, 0U, 0U)}),
            function("rule.on_fault", 1U,
                     {
                         instruction(Opcode::load_const, 0U, 0U, 0U, 0U),
                         instruction(Opcode::return_value, 0U, 0U),
                     }),
        });
    auto budget = balanced_v1;
    budget.normal.instructions = 2U;
    auto session = start(pack, invocation(budget));
    auto result = run_internal(*session, session->step({}));
    REQUIRE(result.state == VmStepState::faulted);
    REQUIRE(result.result.has_value());
    CHECK_FALSE(result.result->verdict.has_value());
    CHECK(session->recovery_counters().forced_cleanup.instructions == 1U);
    CHECK(session->recovery_counters().finalizer_or_fault.instructions == 0U);
}

TEST_CASE("deployment cancellation is unsuppressible while a fact is pending") {
    auto pack = pack_with({make_fact_operand(FactRoute {.provider = "process", .fact = "name"}, SchemaId {"text"})},
                          {function("rule.main", 1U,
                                    {
                                        instruction(Opcode::await_fact, 0U, 0U, 0U, 0U),
                                        instruction(Opcode::return_value, 0U, 0U),
                                    })});
    auto session = start(pack);
    REQUIRE(session->step({}).state == VmStepState::waiting_for_facts);
    HostResponses cancel;
    cancel.cancel = true;
    const auto canceled = session->step(std::move(cancel));
    REQUIRE(canceled.state == VmStepState::canceled);
    REQUIRE(canceled.result.has_value());
    CHECK(canceled.result->outcome == EvaluationOutcome::canceled);
    CHECK(canceled.result->committed_effects.empty());
}

TEST_CASE("instruction frame loop and elapsed limits are hard pre-operation faults") {
    SECTION("instruction") {
        auto pack = pack_with({make_fact(true)}, {function("rule.main", 1U,
                                                           {
                                                               instruction(Opcode::load_const, 0U, 0U, 0U, 0U),
                                                               instruction(Opcode::return_value, 0U, 0U),
                                                           })});
        auto budget = balanced_v1;
        budget.normal.instructions = 1U;
        auto session = start(pack, invocation(budget));
        const auto faulted = session->step({});
        REQUIRE(faulted.state == VmStepState::faulted);
        CHECK(session->counters().instructions == 1U);
    }

    SECTION("frame") {
        auto pack = pack_with({make_fact(true)}, {
                                                     function("rule.main", 1U,
                                                              {
                                                                  instruction(Opcode::call, 0U, 0U, 0U, 1U),
                                                                  instruction(Opcode::return_value, 0U, 0U),
                                                              }),
                                                     function("helper", 1U,
                                                              {
                                                                  instruction(Opcode::load_const, 0U, 0U, 0U, 0U),
                                                                  instruction(Opcode::return_value, 0U, 0U),
                                                              }),
                                                 });
        auto budget = balanced_v1;
        budget.normal.frames = 1U;
        auto session = start(pack, invocation(budget));
        CHECK(session->step({}).state == VmStepState::faulted);
        CHECK(session->counters().peak_frames == 1U);
    }

    SECTION("loop and yield") {
        auto pack = pack_with({make_fact(true)}, {function("rule.main", 1U,
                                                           {
                                                               instruction(Opcode::load_const, 0U, 0U, 0U, 0U),
                                                               instruction(Opcode::yield_value, 0U, 0U),
                                                               instruction(Opcode::return_value, 0U, 0U),
                                                           },
                                                           true)});
        auto budget = balanced_v1;
        budget.normal.loop_iterations_and_yields = 0U;
        auto session = start(pack, invocation(budget));
        CHECK(session->step({}).state == VmStepState::faulted);
        CHECK(session->counters().loop_iterations_and_yields == 0U);
    }

    SECTION("elapsed") {
        auto pack = pack_with({make_fact(true)}, {function("rule.main", 1U,
                                                           {
                                                               instruction(Opcode::load_const, 0U, 0U, 0U, 0U),
                                                               instruction(Opcode::return_value, 0U, 0U),
                                                           })});
        auto budget = balanced_v1;
        budget.normal.elapsed = std::chrono::milliseconds {0};
        auto session = start(pack, invocation(budget));
        CHECK(session->step({}).state == VmStepState::faulted);
        CHECK(session->counters().instructions == 0U);
    }
}

TEST_CASE("generator yield preserves its frame and resumes at the successor instruction") {
    auto pack =
        pack_with({integer("7"), make_fact(true)}, {function("rule.main", 2U,
                                                             {
                                                                 instruction(Opcode::load_const, 0U, 0U, 0U, 0U),
                                                                 instruction(Opcode::yield_value, 0U, 0U),
                                                                 instruction(Opcode::load_const, 1U, 0U, 0U, 1U),
                                                                 instruction(Opcode::return_value, 0U, 1U),
                                                             },
                                                             true)});
    auto session = start(pack);
    const auto yielded = session->step({});
    REQUIRE(yielded.state == VmStepState::yielded);
    REQUIRE(yielded.yielded_value.has_value());
    auto frozen = session->freeze_value(*yielded.yielded_value);
    REQUIRE(frozen.has_value());
    CHECK(frozen_integer(*frozen) == "7");

    const auto complete = session->step({});
    REQUIRE(complete.state == VmStepState::complete);
    REQUIRE(complete.result.has_value());
    CHECK(complete.result->verdict == true);
    CHECK(session->counters().loop_iterations_and_yields == 1U);
}

TEST_CASE("generator send throw and close resume only the suspended continuation") {
    SECTION("send") {
        auto pack = pack_with({integer("7")}, {function("rule.main", 2U,
                                                        {
                                                            instruction(Opcode::load_const, 0U, 0U, 0U, 0U),
                                                            instruction(Opcode::yield_value, 1U, 0U),
                                                            instruction(Opcode::return_value, 0U, 1U),
                                                        },
                                                        true)});
        auto session = start(pack);
        const auto yielded = session->step({});
        REQUIRE(yielded.yielded_value.has_value());
        const auto complete = session->send_generator(*yielded.yielded_value);
        REQUIRE(complete.state == VmStepState::complete);
        CHECK(complete.result->verdict == true);
    }

    SECTION("throw") {
        auto body = function("rule.main", 2U,
                             {
                                 instruction(Opcode::load_const, 0U, 0U, 0U, 0U),
                                 instruction(Opcode::yield_value, 1U, 0U),
                                 instruction(Opcode::return_value, 0U, 1U),
                                 instruction(Opcode::load_const, 1U, 0U, 0U, 1U),
                                 instruction(Opcode::return_value, 0U, 1U),
                             },
                             true);
        body.exception_regions.push_back(ExceptionRegion {
            .begin_instruction = 1U, .end_instruction = 2U, .handler_instruction = 3U, .cleanup_instruction = 3U});
        auto pack = pack_with({integer("7"), make_fact(true)}, {std::move(body)});
        auto session = start(pack);
        const auto yielded = session->step({});
        REQUIRE(yielded.yielded_value.has_value());
        const auto complete = session->throw_generator(*yielded.yielded_value);
        REQUIRE(complete.state == VmStepState::complete);
        CHECK(complete.result->verdict == true);
    }

    SECTION("close") {
        auto body = function("rule.main", 2U,
                             {
                                 instruction(Opcode::load_const, 0U, 0U, 0U, 0U),
                                 instruction(Opcode::yield_value, 1U, 0U),
                                 instruction(Opcode::return_value, 0U, 1U),
                                 instruction(Opcode::leave_try),
                                 instruction(Opcode::load_const, 1U, 0U, 0U, 1U),
                                 instruction(Opcode::return_value, 0U, 1U),
                             },
                             true);
        body.exception_regions.push_back(ExceptionRegion {
            .begin_instruction = 1U, .end_instruction = 2U, .handler_instruction = 4U, .cleanup_instruction = 3U});
        auto pack = pack_with({integer("7"), make_fact(true)}, {std::move(body)});
        auto session = start(pack);
        REQUIRE(session->step({}).state == VmStepState::yielded);
        auto closed = run_internal(*session, session->close_generator());
        REQUIRE(closed.state == VmStepState::canceled);
        CHECK(session->recovery_counters().forced_cleanup.instructions == 1U);
    }
}

TEST_CASE("structured task groups own children lexically and schedule ready tasks FIFO") {
    StructuredTasks tasks;
    const auto root = tasks.open_group();
    REQUIRE(root != 0U);
    const auto nested = tasks.open_group(root);
    REQUIRE(nested != 0U);
    auto first = tasks.start(nested);
    auto second = tasks.start(nested);
    REQUIRE(first.has_value());
    REQUIRE(second.has_value());
    CHECK(tasks.next_ready() == *first);
    CHECK(tasks.owns(nested, *first));
    CHECK(tasks.has_live_tasks(nested));
    CHECK_FALSE(tasks.close(root, TaskGroupExitMode::cancel_pending).has_value());
    CHECK_FALSE(tasks.close(nested, TaskGroupExitMode::wait_pending).has_value());
    REQUIRE(tasks.close(nested, TaskGroupExitMode::cancel_pending).has_value());
    CHECK_FALSE(tasks.has_live_tasks(nested));
    REQUIRE(tasks.close(root, TaskGroupExitMode::wait_pending).has_value());
}

TEST_CASE("structured task cancellation is transitive and close_all leaves no open groups") {
    StructuredTasks tasks;
    const auto root = tasks.open_group();
    const auto child = tasks.open_group(root);
    const auto grandchild = tasks.open_group(child);
    auto root_task = tasks.start(root);
    auto child_task = tasks.start(child);
    auto grandchild_task = tasks.start(grandchild);
    REQUIRE(root_task.has_value());
    REQUIRE(child_task.has_value());
    REQUIRE(grandchild_task.has_value());
    REQUIRE(tasks.cancel_group(child).has_value());
    CHECK(tasks.group_open(root));
    CHECK_FALSE(tasks.group_open(child));
    CHECK_FALSE(tasks.group_open(grandchild));
    CHECK(tasks.tasks()[0].state == TaskState::ready);
    CHECK(tasks.tasks()[1].state == TaskState::canceled);
    CHECK(tasks.tasks()[2].state == TaskState::canceled);
    REQUIRE(tasks.close_all().has_value());
    CHECK_FALSE(tasks.group_open(root));
    CHECK(tasks.tasks()[0].state == TaskState::canceled);
}

TEST_CASE("fresh finalizer executors keep replace abort or escalate a candidate") {
    const auto finalizer_pack = [](FactValue decision, const bool raises = false) {
        std::vector<Instruction> finalizer {
            instruction(Opcode::load_const, 0U, 0U, 0U, 1U),
            instruction(raises ? Opcode::raise_fault : Opcode::return_value, 0U, 0U),
        };
        return pack_with(
            {
                make_fact(true),
                std::move(decision),
                make_handler_metadata(ExecutableId {"rule.main"}, ExecutableId {"rule.finalize"}, std::nullopt,
                                      std::nullopt),
            },
            {
                function("rule.main", 1U,
                         {
                             instruction(Opcode::load_const, 0U, 0U, 0U, 0U),
                             instruction(Opcode::return_value, 0U, 0U),
                         }),
                function("rule.finalize", 1U, std::move(finalizer)),
            });
    };

    SECTION("keep") {
        const auto pack = finalizer_pack(text("keep"));
        auto session = start(pack);
        const auto complete = run_internal(*session, session->step({}));
        REQUIRE(complete.state == VmStepState::complete);
        CHECK(complete.result->verdict == true);
        CHECK(session->recovery_counters().finalizer_or_fault.instructions == 2U);
    }

    SECTION("replace") {
        const auto pack = finalizer_pack(make_fact(false));
        auto session = start(pack);
        const auto complete = run_internal(*session, session->step({}));
        REQUIRE(complete.state == VmStepState::complete);
        CHECK(complete.result->outcome == EvaluationOutcome::no_match);
        CHECK(complete.result->verdict == false);
    }

    SECTION("abort") {
        const auto pack = finalizer_pack(text("abort: policy"));
        auto session = start(pack);
        const auto faulted = run_internal(*session, session->step({}));
        REQUIRE(faulted.state == VmStepState::faulted);
        REQUIRE(faulted.result->fault.has_value());
        CHECK_FALSE(faulted.result->fault->double_fault);
    }

    SECTION("fault escalates without re-entering pack code") {
        const auto pack = finalizer_pack(text("finalizer exploded"), true);
        auto session = start(pack);
        const auto quarantined = run_internal(*session, session->step({}));
        REQUIRE(quarantined.state == VmStepState::quarantined);
        REQUIRE(quarantined.result->fault.has_value());
        CHECK(quarantined.result->fault->double_fault);
        CHECK(quarantined.result->fault->triple_fault);
        CHECK(session->recovery_counters().double_faults == 1U);
        CHECK(session->recovery_counters().triple_faults == 1U);
    }
}

TEST_CASE("on_fault and on_double_fault follow the bounded recovery ladder") {
    const auto recovery_pack = [](FactValue fault_decision, std::optional<FactValue> double_decision,
                                  const bool fault_handler_raises = false, const bool double_handler_raises = false) {
        std::vector<FactValue> constants {text("primary exploded"), std::move(fault_decision)};
        if (double_decision.has_value()) {
            constants.push_back(std::move(*double_decision));
        }
        constants.push_back(make_handler_metadata(
            ExecutableId {"rule.main"}, std::nullopt, ExecutableId {"rule.on_fault"},
            double_decision.has_value() ? std::optional<ExecutableId> {ExecutableId {"rule.on_double"}} :
                                          std::nullopt));
        std::vector<BytecodeFunction> functions {
            function("rule.main", 1U,
                     {
                         instruction(Opcode::load_const, 0U, 0U, 0U, 0U),
                         instruction(Opcode::raise_fault, 0U, 0U),
                     }),
            function("rule.on_fault", 1U,
                     {
                         instruction(Opcode::load_const, 0U, 0U, 0U, 1U),
                         instruction(fault_handler_raises ? Opcode::raise_fault : Opcode::return_value, 0U, 0U),
                     }),
        };
        if (double_decision.has_value()) {
            functions.push_back(
                function("rule.on_double", 1U,
                         {
                             instruction(Opcode::load_const, 0U, 0U, 0U, 2U),
                             instruction(double_handler_raises ? Opcode::raise_fault : Opcode::return_value, 0U, 0U),
                         }));
        }
        return pack_with(std::move(constants), std::move(functions));
    };

    SECTION("on_fault can complete") {
        const auto pack = recovery_pack(make_fact(true), std::nullopt);
        auto session = start(pack);
        const auto complete = run_internal(*session, session->step({}));
        REQUIRE(complete.state == VmStepState::complete);
        CHECK(complete.result->verdict == true);
        CHECK(session->recovery_counters().primary_faults == 1U);
        CHECK(session->recovery_counters().finalizer_or_fault.instructions == 2U);
    }

    SECTION("on_fault can abort or quarantine") {
        const auto abort_pack = recovery_pack(text("abort"), std::nullopt);
        auto abort_session = start(abort_pack);
        CHECK(run_internal(*abort_session, abort_session->step({})).state == VmStepState::faulted);

        const auto quarantine_pack = recovery_pack(text("quarantine"), std::nullopt);
        auto quarantine_session = start(quarantine_pack);
        CHECK(run_internal(*quarantine_session, quarantine_session->step({})).state == VmStepState::quarantined);
    }

    SECTION("retry_once gets one fresh entry executor before escalation") {
        const auto pack = recovery_pack(text("retry_once"), text("abort"));
        auto session = start(pack);
        const auto faulted = run_internal(*session, session->step({}));
        REQUIRE(faulted.state == VmStepState::faulted);
        CHECK(session->recovery_counters().double_faults == 1U);
        CHECK(session->counters().instructions == 4U);
    }

    SECTION("double fault handler can abort") {
        const auto pack = recovery_pack(text("secondary exploded"), text("abort"), true);
        auto session = start(pack);
        const auto faulted = run_internal(*session, session->step({}));
        REQUIRE(faulted.state == VmStepState::faulted);
        REQUIRE(faulted.result->fault.has_value());
        CHECK(faulted.result->fault->double_fault);
        CHECK_FALSE(faulted.result->fault->triple_fault);
        CHECK(session->recovery_counters().double_faults == 1U);
        CHECK(session->recovery_counters().double_fault.instructions == 2U);
    }

    SECTION("a fault in the double fault handler is terminal quarantine") {
        const auto pack = recovery_pack(text("secondary exploded"), text("tertiary exploded"), true, true);
        auto session = start(pack);
        const auto quarantined = run_internal(*session, session->step({}));
        REQUIRE(quarantined.state == VmStepState::quarantined);
        REQUIRE(quarantined.result->fault.has_value());
        CHECK(quarantined.result->fault->triple_fault);
        CHECK(session->recovery_counters().triple_faults == 1U);
    }
}

TEST_CASE("retry_once replays captured fact terminals without a duplicate provider read") {
    auto pack = pack_with(
        {
            make_fact_operand(FactRoute {.provider = "process", .fact = "optional"}, SchemaId {"bool"}),
            text("retry_once"),
            text("abort"),
            make_handler_metadata(ExecutableId {"rule.main"}, std::nullopt, ExecutableId {"rule.on_fault"},
                                  ExecutableId {"rule.on_double"}),
        },
        {
            function("rule.main", 1U,
                     {
                         instruction(Opcode::await_fact, 0U, 0U, 0U, 0U),
                         instruction(Opcode::return_value, 0U, 0U),
                     }),
            function("rule.on_fault", 1U,
                     {
                         instruction(Opcode::load_const, 0U, 0U, 0U, 1U),
                         instruction(Opcode::return_value, 0U, 0U),
                     }),
            function("rule.on_double", 1U,
                     {
                         instruction(Opcode::load_const, 0U, 0U, 0U, 2U),
                         instruction(Opcode::return_value, 0U, 0U),
                     }),
        });
    auto session = start(pack);
    const auto waiting = session->step({});
    REQUIRE(waiting.fact_requests.size() == 1U);
    HostResponses denied;
    denied.facts.push_back(FactResponse {.request_id = waiting.fact_requests.front().request_id,
                                         .subject = waiting.fact_requests.front().subject,
                                         .status = FactTerminalStatus::denied,
                                         .value = std::nullopt,
                                         .diagnostic = std::nullopt});
    const auto faulted = run_internal(*session, session->step(std::move(denied)));
    REQUIRE(faulted.state == VmStepState::faulted);
    CHECK(faulted.fact_requests.empty());
    CHECK(session->logical_read_count() == 1U);
    CHECK(session->counters().logical_facts == 1U);
}

TEST_CASE("recovery tiers enforce their independent instruction and heap budgets") {
    auto pack = pack_with(
        {
            make_fact(true),
            text("keep"),
            make_handler_metadata(ExecutableId {"rule.main"}, ExecutableId {"rule.finalize"}, std::nullopt,
                                  std::nullopt),
        },
        {
            function("rule.main", 1U,
                     {
                         instruction(Opcode::load_const, 0U, 0U, 0U, 0U),
                         instruction(Opcode::return_value, 0U, 0U),
                     }),
            function("rule.finalize", 1U,
                     {
                         instruction(Opcode::load_const, 0U, 0U, 0U, 1U),
                         instruction(Opcode::return_value, 0U, 0U),
                     }),
        });

    SECTION("instruction") {
        auto budget = balanced_v1;
        budget.finalizer_or_fault.instructions = 1U;
        auto session = start(pack, invocation(budget));
        const auto quarantined = run_internal(*session, session->step({}));
        CHECK(quarantined.state == VmStepState::quarantined);
        CHECK(session->recovery_counters().finalizer_or_fault.instructions == 1U);
    }

    SECTION("heap") {
        auto budget = balanced_v1;
        budget.finalizer_or_fault.heap_bytes = 0U;
        auto session = start(pack, invocation(budget));
        const auto quarantined = run_internal(*session, session->step({}));
        CHECK(quarantined.state == VmStepState::quarantined);
    }

    CHECK(balanced_v1.finalizer_or_fault.instructions == 100'000U);
    CHECK(balanced_v1.double_fault.instructions == 25'000U);
    CHECK(balanced_v1.forced_cleanup.instructions == 25'000U);
}

TEST_CASE("identical executions produce deterministic requests intents and results") {
    auto pack = pack_with(
        {
            text("payload"),
            text("trace"),
            make_fact_operand(FactRoute {.provider = "process", .fact = "flag"}, SchemaId {"bool"}),
        },
        {function("rule.main", 2U,
                  {
                      instruction(Opcode::load_const, 0U, 0U, 0U, 0U),
                      instruction(Opcode::append_effect, 0U, 0U, 0U, 1U),
                      instruction(Opcode::await_fact, 1U, 0U, 0U, 2U),
                      instruction(Opcode::return_value, 0U, 1U),
                  })});
    auto first = start(pack);
    auto second = start(pack);
    const auto first_wait = first->step({});
    const auto second_wait = second->step({});
    REQUIRE(first_wait.fact_requests.size() == 1U);
    REQUIRE(second_wait.fact_requests.size() == 1U);
    REQUIRE(first_wait.journal_delta.size() == 1U);
    REQUIRE(second_wait.journal_delta.size() == 1U);
    CHECK(first_wait.fact_requests.front().request_id == second_wait.fact_requests.front().request_id);
    CHECK(first_wait.journal_delta.front().id == second_wait.journal_delta.front().id);
    CHECK(first_wait.journal_delta.front().payload.canonical_digest ==
          second_wait.journal_delta.front().payload.canonical_digest);

    auto response_for = [](const FactRequest &request) {
        HostResponses response;
        response.facts.push_back(FactResponse {.request_id = request.request_id,
                                               .subject = request.subject,
                                               .status = FactTerminalStatus::value,
                                               .value = make_fact(true),
                                               .diagnostic = std::nullopt});
        return response;
    };
    const auto first_result = first->step(response_for(first_wait.fact_requests.front()));
    const auto second_result = second->step(response_for(second_wait.fact_requests.front()));
    REQUIRE(first_result.result.has_value());
    REQUIRE(second_result.result.has_value());
    CHECK(first_result.result->outcome == second_result.result->outcome);
    CHECK(first_result.result->verdict == second_result.result->verdict);
}
