#include "rule_engine/python/vm/register_vm.hpp"

#if defined(__clang__)
#pragma clang diagnostic ignored "-Wc2y-extensions"
#endif

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
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
        .value = FrozenValue {.value = make_fact(true), .label = {}, .canonical_digest = "bool:true"},
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
