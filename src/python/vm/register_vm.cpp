#include "rule_engine/python/vm/register_vm.hpp"

#include <algorithm>
#include <chrono>
#include <limits>
#include <set>
#include <string>
#include <utility>

namespace rule_engine::python::vm {
    namespace {

        [[nodiscard]] FactValue text_fact(std::string value) {
            return make_fact(UnicodeValue {.utf8 = std::move(value)});
        }

        [[nodiscard]] FactValue operand_record(const std::string_view schema, std::vector<FactRecordField> fields) {
            return make_fact(FactRecord {.schema = SchemaId {std::string {schema}}, .fields = std::move(fields)});
        }

        [[nodiscard]] std::optional<std::string>
        record_text_field(const FactValue &value, const std::string_view schema, const std::uint32_t field_id) {
            if (!value.valid()) {
                return std::nullopt;
            }
            const auto *record = std::get_if<FactRecord>(&value.node->data);
            if (record == nullptr || record->schema.value != schema) {
                return std::nullopt;
            }
            const auto field = std::ranges::find(record->fields, field_id, &FactRecordField::field_id);
            if (field == record->fields.end() || !field->value.valid()) {
                return std::nullopt;
            }
            const auto *text = std::get_if<UnicodeValue>(&field->value.node->data);
            return text == nullptr ? std::nullopt : std::optional<std::string> {text->utf8};
        }

        [[nodiscard]] std::optional<std::string> fact_text(const FactValue &value) {
            if (!value.valid()) {
                return std::nullopt;
            }
            const auto *text = std::get_if<UnicodeValue>(&value.node->data);
            return text == nullptr ? std::nullopt : std::optional<std::string> {text->utf8};
        }

        [[nodiscard]] std::size_t fact_size(const FactValue &value, std::set<const FactNode *> &path,
                                            const std::uint32_t depth = 0U) {
            if (!value.valid() || depth > 128U || !path.insert(value.node.get()).second) {
                return std::numeric_limits<std::size_t>::max();
            }
            const auto &data = value.node->data;
            std::size_t size {sizeof(FactNode)};
            if (const auto *integer = std::get_if<IntegerValue>(&data); integer != nullptr) {
                size += integer->decimal.size();
            } else if (const auto *unicode = std::get_if<UnicodeValue>(&data); unicode != nullptr) {
                size += unicode->utf8.size();
            } else if (const auto *bytes = std::get_if<BytesValue>(&data); bytes != nullptr) {
                size += bytes->bytes.size();
            } else if (const auto *enumeration = std::get_if<EnumValue>(&data); enumeration != nullptr) {
                size += enumeration->schema.value.size() + enumeration->member.size();
            } else if (const auto *list = std::get_if<FactList>(&data); list != nullptr) {
                for (const auto &item : list->items) {
                    const auto item_size = fact_size(item, path, depth + 1U);
                    if (item_size == std::numeric_limits<std::size_t>::max() ||
                        size > std::numeric_limits<std::size_t>::max() - item_size) {
                        size = std::numeric_limits<std::size_t>::max();
                        break;
                    }
                    size += item_size;
                }
            } else if (const auto *map = std::get_if<FactMap>(&data); map != nullptr) {
                for (const auto &entry : map->entries) {
                    const auto key_size = fact_size(entry.key, path, depth + 1U);
                    const auto value_size = fact_size(entry.value, path, depth + 1U);
                    if (key_size == std::numeric_limits<std::size_t>::max() ||
                        value_size == std::numeric_limits<std::size_t>::max() ||
                        size > std::numeric_limits<std::size_t>::max() - key_size ||
                        size + key_size > std::numeric_limits<std::size_t>::max() - value_size) {
                        size = std::numeric_limits<std::size_t>::max();
                        break;
                    }
                    size += key_size + value_size;
                }
            } else if (const auto *record = std::get_if<FactRecord>(&data); record != nullptr) {
                size += record->schema.value.size();
                for (const auto &field : record->fields) {
                    const auto field_size = fact_size(field.value, path, depth + 1U);
                    if (field_size == std::numeric_limits<std::size_t>::max() ||
                        size > std::numeric_limits<std::size_t>::max() - field_size) {
                        size = std::numeric_limits<std::size_t>::max();
                        break;
                    }
                    size += field_size;
                }
            }
            path.erase(value.node.get());
            return size;
        }

        [[nodiscard]] std::size_t fact_size(const FactValue &value) {
            std::set<const FactNode *> path;
            return fact_size(value, path);
        }

        [[nodiscard]] Diagnostic diagnostic(std::string code, std::string message,
                                            std::optional<SourceSpan> span = std::nullopt) {
            return Diagnostic {
                .code = std::move(code),
                .severity = DiagnosticSeverity::error,
                .message = std::move(message),
                .span = std::move(span),
                .related = {},
            };
        }

        [[nodiscard]] std::string error_code(const VmErrorCode code) {
            switch (code) {
                case VmErrorCode::heap_budget_exhausted: return "PYVM4004";
                case VmErrorCode::instruction_budget_exhausted: return "PYVM4003";
                case VmErrorCode::frame_budget_exhausted: return "PYVM4005";
                case VmErrorCode::loop_budget_exhausted: return "PYVM4006";
                case VmErrorCode::elapsed_budget_exhausted: return "PYVM4001";
                case VmErrorCode::fact_budget_exhausted: return "PYVM4010";
                case VmErrorCode::capability_budget_exhausted: return "PYVM4011";
                case VmErrorCode::effect_budget_exhausted: return "PYVM4012";
                case VmErrorCode::invalid_bytecode: return "PYVM1001";
                case VmErrorCode::invalid_host_response: return "PYVM3001";
                case VmErrorCode::canceled: return "PYVM4002";
                case VmErrorCode::type_error: return "PYVM2001";
                case VmErrorCode::value_error: return "PYVM2002";
                case VmErrorCode::arithmetic_error: return "PYVM2003";
                case VmErrorCode::invalid_handle:
                case VmErrorCode::stale_handle:
                case VmErrorCode::engine_fault: return "PYVM9001";
            }
            return "PYVM9001";
        }

        [[nodiscard]] std::uint64_t deadline_after(const std::chrono::milliseconds duration) {
            const auto deadline = std::chrono::system_clock::now() + duration;
            return static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(deadline.time_since_epoch()).count());
        }

        [[nodiscard]] bool operation_in_range(const std::uint32_t value, const std::uint32_t last) noexcept {
            return value <= last;
        }

    } // namespace

    FactValue make_fact_operand(FactRoute route, SchemaId expected_schema) {
        return operand_record(
            fact_operand_schema,
            {
                FactRecordField {.field_id = 1U, .value = text_fact(std::move(route.provider))},
                FactRecordField {.field_id = 2U, .value = text_fact(std::move(route.fact))},
                FactRecordField {.field_id = 3U, .value = text_fact(std::move(expected_schema.value))},
            });
    }

    FactValue make_capability_operand(CapabilityId capability, SchemaId request_schema) {
        return operand_record(capability_operand_schema,
                              {
                                  FactRecordField {.field_id = 1U, .value = text_fact(std::move(capability.value))},
                                  FactRecordField {.field_id = 2U, .value = text_fact(std::move(request_schema.value))},
                              });
    }

    struct RegisterVmSession::Impl {
        struct Frame {
            std::size_t function_index {};
            std::uint32_t pc {};
            std::vector<PyValue> registers;
            std::optional<std::uint32_t> return_register;
            GeneratorState generator_state {GeneratorState::running};
        };

        enum struct PendingKind : std::uint8_t { fact, capability };

        struct PendingRequest {
            PendingKind kind {PendingKind::fact};
            RequestId id;
            std::size_t frame_index {};
            std::uint32_t destination {};
            std::uint32_t successor_pc {};
            SourceSpan span;
            std::optional<FactRequest> fact;
            std::optional<CapabilityRequest> capability;
            bool emitted {};
        };

        CompiledPack pack;
        VmInvocation invocation;
        ValueHeap heap;
        std::vector<PyValue> constants;
        std::vector<Frame> frames;
        std::optional<PendingRequest> pending;
        std::vector<std::string> logical_reads;
        std::vector<EffectIntent> journal;
        std::vector<std::size_t> transaction_marks;
        std::size_t emitted_journal {};
        VmCounters counters;
        std::uint32_t active_service_calls {};
        std::chrono::steady_clock::time_point started {std::chrono::steady_clock::now()};
        std::chrono::steady_clock::time_point active_step_started {};
        bool active_step {};
        std::uint64_t request_sequence {};
        std::uint64_t effect_sequence {};
        std::optional<VmStepState> terminal_state;
        std::optional<EvaluationResult> terminal_result;
        StructuredTasks tasks;
        TaskGroupId root_group {};
        TaskId root_task {};

        Impl(CompiledPack value, VmInvocation requested):
            pack {std::move(value)}, invocation {std::move(requested)}, heap {invocation.budget.normal.heap_bytes} {}

        [[nodiscard]] const BytecodeFunction &function(const Frame &frame) const {
            return pack.functions[frame.function_index];
        }

        [[nodiscard]] std::vector<PyValue> roots() const {
            std::vector<PyValue> result = constants;
            for (const auto &frame : frames) {
                for (const auto value : frame.registers) {
                    if (heap.valid(value)) {
                        result.push_back(value);
                    }
                }
            }
            return result;
        }

        [[nodiscard]] std::chrono::nanoseconds current_active_time() const {
            if (!active_step) {
                return counters.active_time;
            }
            return counters.active_time + (std::chrono::steady_clock::now() - active_step_started);
        }

        [[nodiscard]] std::chrono::milliseconds remaining_elapsed() const {
            const auto elapsed =
                std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started);
            if (elapsed >= invocation.budget.normal.elapsed) {
                return std::chrono::milliseconds::zero();
            }
            return invocation.budget.normal.elapsed - elapsed;
        }

        [[nodiscard]] std::optional<VmError> check_time() const {
            const auto elapsed = std::chrono::steady_clock::now() - started;
            if (elapsed >= invocation.budget.normal.elapsed) {
                return VmError {.code = VmErrorCode::elapsed_budget_exhausted,
                                .message = "balanced.v1 elapsed deadline exhausted",
                                .span = std::nullopt};
            }
            if (current_active_time() >= invocation.budget.normal.active_cpu) {
                return VmError {.code = VmErrorCode::elapsed_budget_exhausted,
                                .message = "balanced.v1 active VM time exhausted",
                                .span = std::nullopt};
            }
            return std::nullopt;
        }

        [[nodiscard]] std::optional<VmError> charge_instructions(const std::uint64_t amount, const SourceSpan &span) {
            if (amount > invocation.budget.normal.instructions ||
                counters.instructions > invocation.budget.normal.instructions - amount) {
                return VmError {.code = VmErrorCode::instruction_budget_exhausted,
                                .message = "balanced.v1 semantic instruction budget exhausted",
                                .span = span};
            }
            counters.instructions += amount;
            return std::nullopt;
        }

        [[nodiscard]] std::optional<VmError> charge_loop(const SourceSpan &span) {
            if (counters.loop_iterations_and_yields == invocation.budget.normal.loop_iterations_and_yields) {
                return VmError {.code = VmErrorCode::loop_budget_exhausted,
                                .message = "balanced.v1 loop iteration/yield budget exhausted",
                                .span = span};
            }
            ++counters.loop_iterations_and_yields;
            return std::nullopt;
        }

        [[nodiscard]] std::optional<VmError> charge_frame(const SourceSpan &span) {
            if (frames.size() == invocation.budget.normal.frames) {
                return VmError {.code = VmErrorCode::frame_budget_exhausted,
                                .message = "balanced.v1 frame budget exhausted",
                                .span = span};
            }
            return std::nullopt;
        }

        [[nodiscard]] RequestId next_request_id() {
            ++request_sequence;
            return RequestId {"vm:" + invocation.execution.value + ":" + std::to_string(request_sequence)};
        }

        [[nodiscard]] IntentId next_intent_id() {
            ++effect_sequence;
            return IntentId {"vm:" + invocation.invocation.value + ":effect:" + std::to_string(effect_sequence)};
        }

        [[nodiscard]] VmStep terminal(VmStepState state, EvaluationResult result) {
            terminal_state = state;
            terminal_result = std::move(result);
            if (root_task != 0U) {
                const auto task_state = state == VmStepState::complete ? TaskState::complete :
                                        state == VmStepState::canceled ? TaskState::canceled :
                                                                         TaskState::faulted;
                static_cast<void>(tasks.set_state(root_task, task_state));
            }
            return make_step(state, terminal_result);
        }

        [[nodiscard]] VmStep fail(VmError fault, const VmStepState state = VmStepState::faulted) {
            FaultFrame frame {
                .code = error_code(fault.code),
                .message = std::move(fault.message),
                .executable = frames.empty() ? ExecutableId {} : function(frames.back()).id,
                .span = fault.span.value_or(SourceSpan {}),
            };
            EvaluationResult result {
                .outcome = state == VmStepState::quarantined ? EvaluationOutcome::quarantined :
                           state == VmStepState::canceled    ? EvaluationOutcome::canceled :
                                                               EvaluationOutcome::faulted,
                .verdict = std::nullopt,
                .committed_effects = {},
                .state_mutations = {},
                .fault = FaultChain {.frames = {std::move(frame)}, .double_fault = false, .triple_fault = false},
            };
            return terminal(state, std::move(result));
        }

        [[nodiscard]] VmStep complete(const PyValue value) {
            auto verdict = heap.truthy(value);
            if (!verdict) {
                return fail(verdict.error());
            }
            auto committed = journal;
            for (auto &intent : committed) {
                if (intent.disposition == EffectDisposition::pending) {
                    intent.disposition = EffectDisposition::committed;
                }
            }
            EvaluationResult result {
                .outcome = *verdict ? EvaluationOutcome::match : EvaluationOutcome::no_match,
                .verdict = *verdict,
                .committed_effects = std::move(committed),
                .state_mutations = {},
                .fault = std::nullopt,
            };
            return terminal(VmStepState::complete, std::move(result));
        }

        [[nodiscard]] VmStep make_step(const VmStepState state,
                                       const std::optional<EvaluationResult> &result = std::nullopt,
                                       const std::optional<PyValue> yielded = std::nullopt) {
            VmStep step {
                .state = state,
                .fact_requests = {},
                .scan_requests = {},
                .capability_requests = {},
                .state_requests = {},
                .history_requests = {},
                .journal_delta = {},
                .recorder_delta = {},
                .yielded_value = std::nullopt,
                .result = std::nullopt,
            };
            if (pending.has_value() && !pending->emitted) {
                if (pending->fact.has_value()) {
                    step.fact_requests.push_back(*pending->fact);
                } else if (pending->capability.has_value()) {
                    step.capability_requests.push_back(*pending->capability);
                }
                pending->emitted = true;
            }
            if (emitted_journal < journal.size()) {
                step.journal_delta.insert(step.journal_delta.end(),
                                          journal.begin() + static_cast<std::ptrdiff_t>(emitted_journal),
                                          journal.end());
                emitted_journal = journal.size();
            }
            step.yielded_value = yielded;
            step.result = result;
            return step;
        }

        [[nodiscard]] bool register_valid(const Frame &frame, const std::uint32_t index) const noexcept {
            return index < frame.registers.size() && heap.valid(frame.registers[index]);
        }

        [[nodiscard]] std::optional<VmError> validate_response_shape(const HostResponses &responses) const {
            const auto total = responses.facts.size() + responses.scans.size() + responses.capabilities.size() +
                               responses.state.size() + responses.history.size();
            if (!pending.has_value()) {
                if (total != 0U) {
                    return VmError {.code = VmErrorCode::invalid_host_response,
                                    .message = "host supplied a response with no outstanding VM request",
                                    .span = std::nullopt};
                }
                return std::nullopt;
            }
            if (total == 0U) {
                return std::nullopt;
            }
            if (total != 1U || !responses.scans.empty() || !responses.state.empty() || !responses.history.empty()) {
                return VmError {.code = VmErrorCode::invalid_host_response,
                                .message = "host response batch does not match the outstanding VM request",
                                .span = pending->span};
            }
            if (pending->kind == PendingKind::fact && responses.facts.size() != 1U) {
                return VmError {.code = VmErrorCode::invalid_host_response,
                                .message = "capability response cannot satisfy an outstanding fact request",
                                .span = pending->span};
            }
            if (pending->kind == PendingKind::capability && responses.capabilities.size() != 1U) {
                return VmError {.code = VmErrorCode::invalid_host_response,
                                .message = "fact response cannot satisfy an outstanding capability request",
                                .span = pending->span};
            }
            return std::nullopt;
        }

        [[nodiscard]] std::optional<VmError> raise_pending_terminal(std::string message) {
            auto exception = heap.allocate_unicode(message);
            if (!exception) {
                return exception.error();
            }
            const Instruction faulting {
                .opcode = Opcode::raise_fault,
                .destination = pending->destination,
                .operand_a = pending->destination,
                .operand_b = 0U,
                .immediate = 0U,
                .span = pending->span,
            };
            if (!handle_author_fault(faulting, *exception)) {
                return VmError {.code = VmErrorCode::value_error, .message = std::move(message), .span = pending->span};
            }
            pending.reset();
            return std::nullopt;
        }

        [[nodiscard]] std::optional<VmError> apply_responses(const HostResponses &responses) {
            if (const auto invalid = validate_response_shape(responses); invalid.has_value()) {
                return invalid;
            }
            if (!pending.has_value()) {
                return std::nullopt;
            }
            if (pending->kind == PendingKind::fact && responses.facts.empty()) {
                return std::nullopt;
            }
            if (pending->kind == PendingKind::capability && responses.capabilities.empty()) {
                return std::nullopt;
            }

            FactValue response_value;
            if (pending->kind == PendingKind::fact) {
                const auto &response = responses.facts.front();
                if (response.request_id != pending->id ||
                    canonical_subject_key(response.subject) != canonical_subject_key(pending->fact->subject)) {
                    return VmError {.code = VmErrorCode::invalid_host_response,
                                    .message = "fact response identity does not match its request",
                                    .span = pending->span};
                }
                if (response.status != FactTerminalStatus::value || !response.value.has_value()) {
                    return raise_pending_terminal("fact provider returned terminal status " +
                                                  std::to_string(static_cast<unsigned>(response.status)));
                }
                response_value = *response.value;
                const auto bytes = fact_size(response_value);
                if (bytes == std::numeric_limits<std::size_t>::max() || bytes > invocation.budget.normal.fact_bytes ||
                    counters.fact_bytes > invocation.budget.normal.fact_bytes - bytes) {
                    return VmError {.code = VmErrorCode::fact_budget_exhausted,
                                    .message = "balanced.v1 fact data budget exhausted",
                                    .span = pending->span};
                }
                counters.fact_bytes += bytes;
            } else {
                const auto &response = responses.capabilities.front();
                if (response.request_id != pending->id) {
                    return VmError {.code = VmErrorCode::invalid_host_response,
                                    .message = "capability response identity does not match its request",
                                    .span = pending->span};
                }
                if (response.status != FactTerminalStatus::value || !response.value.has_value()) {
                    if (active_service_calls == 0U) {
                        return VmError {.code = VmErrorCode::engine_fault,
                                        .message = "capability terminal underflowed active-call accounting",
                                        .span = pending->span};
                    }
                    --active_service_calls;
                    return raise_pending_terminal("capability returned a non-value terminal status");
                }
                response_value = response.value->value;
                const auto bytes = fact_size(response_value);
                if (bytes == std::numeric_limits<std::size_t>::max() ||
                    bytes > invocation.budget.normal.service_response_bytes ||
                    counters.service_response_bytes > invocation.budget.normal.service_response_bytes - bytes) {
                    return VmError {.code = VmErrorCode::capability_budget_exhausted,
                                    .message = "balanced.v1 service response budget exhausted",
                                    .span = pending->span};
                }
                counters.service_response_bytes += bytes;
                if (active_service_calls == 0U) {
                    return VmError {.code = VmErrorCode::engine_fault,
                                    .message = "capability response underflowed active-call accounting",
                                    .span = pending->span};
                }
                --active_service_calls;
            }

            auto thawed = heap.thaw(response_value);
            if (!thawed && thawed.error().code == VmErrorCode::heap_budget_exhausted) {
                const auto gc = heap.collect(roots());
                if (!gc) {
                    return gc.error();
                }
                thawed = heap.thaw(response_value);
            }
            if (!thawed) {
                return thawed.error();
            }
            if (pending->frame_index >= frames.size() ||
                pending->destination >= frames[pending->frame_index].registers.size()) {
                return VmError {.code = VmErrorCode::engine_fault,
                                .message = "suspension continuation references an invalid frame/register",
                                .span = pending->span};
            }
            auto &frame = frames[pending->frame_index];
            frame.registers[pending->destination] = *thawed;
            frame.pc = pending->successor_pc;
            pending.reset();
            return std::nullopt;
        }

        [[nodiscard]] std::optional<VmError> begin_fact(const Instruction &instruction, Frame &frame) {
            if (instruction.immediate >= pack.constants.size()) {
                return VmError {.code = VmErrorCode::invalid_bytecode,
                                .message = "await_fact constant index is out of range",
                                .span = instruction.span};
            }
            const auto provider = record_text_field(pack.constants[instruction.immediate], fact_operand_schema, 1U);
            const auto fact = record_text_field(pack.constants[instruction.immediate], fact_operand_schema, 2U);
            const auto schema = record_text_field(pack.constants[instruction.immediate], fact_operand_schema, 3U);
            if (!provider.has_value() || !fact.has_value() || !schema.has_value() || provider->empty() ||
                fact->empty() || schema->empty()) {
                return VmError {.code = VmErrorCode::invalid_bytecode,
                                .message = "await_fact constant is not a valid fact operand",
                                .span = instruction.span};
            }
            if (counters.logical_facts == invocation.budget.normal.logical_facts ||
                counters.provider_rounds == invocation.budget.normal.provider_rounds) {
                return VmError {.code = VmErrorCode::fact_budget_exhausted,
                                .message = "balanced.v1 logical fact/provider round budget exhausted",
                                .span = instruction.span};
            }
            ++counters.logical_facts;
            ++counters.provider_rounds;
            const auto id = next_request_id();
            FactRequest request {
                .request_id = id,
                .subject = invocation.subject,
                .route = FactRoute {.provider = *provider, .fact = *fact},
                .expected_schema = SchemaId {*schema},
                .deadline_unix_ms = deadline_after(remaining_elapsed()),
            };
            logical_reads.push_back(id.value + ":" + *provider + ":" + *fact);
            pending = PendingRequest {
                .kind = PendingKind::fact,
                .id = id,
                .frame_index = frames.size() - 1U,
                .destination = instruction.destination,
                .successor_pc = frame.pc + 1U,
                .span = instruction.span,
                .fact = std::move(request),
                .capability = std::nullopt,
                .emitted = false,
            };
            return std::nullopt;
        }

        [[nodiscard]] std::optional<VmError> begin_capability(const Instruction &instruction, Frame &frame) {
            if (instruction.immediate >= pack.constants.size() || !register_valid(frame, instruction.operand_a)) {
                return VmError {.code = VmErrorCode::invalid_bytecode,
                                .message = "await_capability operand is invalid",
                                .span = instruction.span};
            }
            const auto capability =
                record_text_field(pack.constants[instruction.immediate], capability_operand_schema, 1U);
            const auto schema = record_text_field(pack.constants[instruction.immediate], capability_operand_schema, 2U);
            if (!capability.has_value() || !schema.has_value() || capability->empty() || schema->empty()) {
                return VmError {.code = VmErrorCode::invalid_bytecode,
                                .message = "await_capability constant is not a valid capability operand",
                                .span = instruction.span};
            }
            if (counters.service_calls == invocation.budget.normal.service_calls ||
                active_service_calls == invocation.budget.normal.active_service_calls) {
                return VmError {.code = VmErrorCode::capability_budget_exhausted,
                                .message = "balanced.v1 service call budget exhausted",
                                .span = instruction.span};
            }
            auto arguments =
                heap.freeze(frame.registers[instruction.operand_a], {},
                            FreezeLimits {.maximum_bytes = invocation.budget.normal.service_response_bytes});
            if (!arguments) {
                return VmError {.code = VmErrorCode::capability_budget_exhausted,
                                .message =
                                    "capability arguments failed boundary freezing: " + arguments.error().message,
                                .span = instruction.span};
            }
            ++counters.service_calls;
            ++active_service_calls;
            counters.peak_active_service_calls = std::max(counters.peak_active_service_calls, active_service_calls);
            const auto id = next_request_id();
            CapabilityRequest request {
                .request_id = id,
                .capability = CapabilityId {*capability},
                .request_schema = SchemaId {*schema},
                .arguments = std::move(*arguments),
                .deadline_unix_ms =
                    deadline_after(std::min(invocation.budget.normal.maximum_service_deadline, remaining_elapsed())),
            };
            pending = PendingRequest {
                .kind = PendingKind::capability,
                .id = id,
                .frame_index = frames.size() - 1U,
                .destination = instruction.destination,
                .successor_pc = frame.pc + 1U,
                .span = instruction.span,
                .fact = std::nullopt,
                .capability = std::move(request),
                .emitted = false,
            };
            return std::nullopt;
        }

        [[nodiscard]] std::optional<VmError> append_effect(const Instruction &instruction, Frame &frame) {
            if (instruction.immediate >= pack.constants.size() || !register_valid(frame, instruction.operand_a)) {
                return VmError {.code = VmErrorCode::invalid_bytecode,
                                .message = "append_effect operand is invalid",
                                .span = instruction.span};
            }
            const auto kind = fact_text(pack.constants[instruction.immediate]);
            if (!kind.has_value() || kind->empty()) {
                return VmError {.code = VmErrorCode::invalid_bytecode,
                                .message = "append_effect kind constant must be non-empty Unicode",
                                .span = instruction.span};
            }
            if (counters.effect_intents == invocation.budget.normal.effect_intents) {
                return VmError {.code = VmErrorCode::effect_budget_exhausted,
                                .message = "balanced.v1 effect intent budget exhausted",
                                .span = instruction.span};
            }
            const auto remaining = invocation.budget.normal.effect_bytes - counters.effect_bytes;
            auto payload =
                heap.freeze(frame.registers[instruction.operand_a], {}, FreezeLimits {.maximum_bytes = remaining});
            if (!payload) {
                return VmError {.code = VmErrorCode::effect_budget_exhausted,
                                .message = "effect payload failed boundary freezing: " + payload.error().message,
                                .span = instruction.span};
            }
            const auto bytes = fact_size(payload->value);
            if (bytes == std::numeric_limits<std::size_t>::max() || bytes > remaining) {
                return VmError {.code = VmErrorCode::effect_budget_exhausted,
                                .message = "balanced.v1 effect payload budget exhausted",
                                .span = instruction.span};
            }
            ++counters.effect_intents;
            counters.effect_bytes += bytes;
            const auto id = next_intent_id();
            journal.push_back(EffectIntent {
                .id = id,
                .invocation = invocation.invocation,
                .owner = function(frame).id,
                .binding = invocation.binding,
                .sequence = effect_sequence,
                .kind = *kind,
                .payload = std::move(*payload),
                .span = instruction.span,
                .policy = EffectPolicySnapshot {.policy_id = "vm.default",
                                                .policy_digest = "vm.default.v1",
                                                .sink_ceiling = {},
                                                .dry_run = true},
                .disposition = EffectDisposition::pending,
                .idempotency_key = invocation.execution.value + ":" + id.value,
            });
            ++frame.pc;
            return std::nullopt;
        }

        [[nodiscard]] std::optional<std::uint64_t> projected_binary_work(const Instruction &instruction,
                                                                         const Frame &frame) const {
            const auto left = heap.integer_decimal(frame.registers[instruction.operand_a]);
            const auto right = heap.integer_decimal(frame.registers[instruction.operand_b]);
            if (!left || !right) {
                return 1U;
            }
            const auto left_digits = static_cast<std::uint64_t>(left->size() - (left->starts_with('-') ? 1U : 0U));
            const auto right_digits = static_cast<std::uint64_t>(right->size() - (right->starts_with('-') ? 1U : 0U));
            if (instruction.immediate == static_cast<std::uint32_t>(BinaryOperation::multiply)) {
                if (right_digits != 0U && left_digits > std::numeric_limits<std::uint64_t>::max() / right_digits) {
                    return std::nullopt;
                }
                return std::max<std::uint64_t>(1U, left_digits * right_digits);
            }
            return std::max<std::uint64_t>(1U, std::max(left_digits, right_digits));
        }

        [[nodiscard]] bool handle_author_fault(const Instruction &instruction, const PyValue value) {
            auto &frame = frames.back();
            const auto &regions = function(frame).exception_regions;
            for (auto region = regions.rbegin(); region != regions.rend(); ++region) {
                if (frame.pc < region->begin_instruction || frame.pc >= region->end_instruction) {
                    continue;
                }
                frame.registers[instruction.destination] = value;
                frame.pc = region->handler_instruction;
                return true;
            }
            return false;
        }

        [[nodiscard]] VmStep execute() {
            constexpr std::uint64_t cooperative_quantum {4096U};
            std::uint64_t quantum {};
            while (!frames.empty()) {
                if (const auto time_fault = check_time(); time_fault.has_value()) {
                    return fail(*time_fault);
                }
                auto &frame = frames.back();
                auto &code = function(frame);
                if (frame.pc >= code.instructions.size()) {
                    return fail(VmError {.code = VmErrorCode::invalid_bytecode,
                                         .message = "function reached the end without return",
                                         .span = std::nullopt});
                }
                const auto instruction = code.instructions[frame.pc];
                if (const auto budget_fault = charge_instructions(1U, instruction.span); budget_fault.has_value()) {
                    return fail(*budget_fault);
                }
                ++quantum;

                switch (instruction.opcode) {
                    case Opcode::load_const:
                        if (instruction.immediate >= constants.size()) {
                            return fail(VmError {.code = VmErrorCode::invalid_bytecode,
                                                 .message = "load_const index is out of range",
                                                 .span = instruction.span});
                        }
                        frame.registers[instruction.destination] = constants[instruction.immediate];
                        ++frame.pc;
                        break;
                    case Opcode::move:
                        if (!register_valid(frame, instruction.operand_a)) {
                            return fail(VmError {.code = VmErrorCode::invalid_bytecode,
                                                 .message = "move reads an uninitialized register",
                                                 .span = instruction.span});
                        }
                        frame.registers[instruction.destination] = frame.registers[instruction.operand_a];
                        ++frame.pc;
                        break;
                    case Opcode::unary_op: {
                        if (!register_valid(frame, instruction.operand_a) ||
                            !operation_in_range(instruction.immediate,
                                                static_cast<std::uint32_t>(UnaryOperation::negative))) {
                            return fail(VmError {.code = VmErrorCode::invalid_bytecode,
                                                 .message = "unary operation encoding is invalid",
                                                 .span = instruction.span});
                        }
                        auto value = heap.unary(static_cast<UnaryOperation>(instruction.immediate),
                                                frame.registers[instruction.operand_a]);
                        if (!value) {
                            return fail(value.error());
                        }
                        frame.registers[instruction.destination] = *value;
                        ++frame.pc;
                        break;
                    }
                    case Opcode::binary_op: {
                        if (!register_valid(frame, instruction.operand_a) ||
                            !register_valid(frame, instruction.operand_b) ||
                            !operation_in_range(instruction.immediate,
                                                static_cast<std::uint32_t>(BinaryOperation::multiply))) {
                            return fail(VmError {.code = VmErrorCode::invalid_bytecode,
                                                 .message = "binary operation encoding is invalid",
                                                 .span = instruction.span});
                        }
                        const auto work = projected_binary_work(instruction, frame);
                        if (!work.has_value()) {
                            return fail(
                                VmError {.code = VmErrorCode::instruction_budget_exhausted,
                                         .message = "integer operation projected work overflows budget accounting",
                                         .span = instruction.span});
                        }
                        if (*work > 1U) {
                            if (const auto work_fault = charge_instructions(*work - 1U, instruction.span);
                                work_fault.has_value()) {
                                return fail(*work_fault);
                            }
                        }
                        auto value =
                            heap.binary(static_cast<BinaryOperation>(instruction.immediate),
                                        frame.registers[instruction.operand_a], frame.registers[instruction.operand_b]);
                        if (!value) {
                            return fail(value.error());
                        }
                        frame.registers[instruction.destination] = *value;
                        ++frame.pc;
                        break;
                    }
                    case Opcode::compare: {
                        if (!register_valid(frame, instruction.operand_a) ||
                            !register_valid(frame, instruction.operand_b) ||
                            !operation_in_range(instruction.immediate,
                                                static_cast<std::uint32_t>(CompareOperation::greater_equal))) {
                            return fail(VmError {.code = VmErrorCode::invalid_bytecode,
                                                 .message = "compare operation encoding is invalid",
                                                 .span = instruction.span});
                        }
                        auto compared = heap.compare_operation(static_cast<CompareOperation>(instruction.immediate),
                                                               frame.registers[instruction.operand_a],
                                                               frame.registers[instruction.operand_b]);
                        if (!compared) {
                            return fail(compared.error());
                        }
                        auto value = heap.allocate_bool(*compared);
                        if (!value) {
                            return fail(value.error());
                        }
                        frame.registers[instruction.destination] = *value;
                        ++frame.pc;
                        break;
                    }
                    case Opcode::jump:
                        if (instruction.immediate <= frame.pc) {
                            if (const auto loop_fault = charge_loop(instruction.span); loop_fault.has_value()) {
                                return fail(*loop_fault);
                            }
                        }
                        frame.pc = instruction.immediate;
                        break;
                    case Opcode::jump_if_false: {
                        if (!register_valid(frame, instruction.operand_a)) {
                            return fail(VmError {.code = VmErrorCode::invalid_bytecode,
                                                 .message = "conditional jump reads an uninitialized register",
                                                 .span = instruction.span});
                        }
                        auto condition = heap.truthy(frame.registers[instruction.operand_a]);
                        if (!condition) {
                            return fail(condition.error());
                        }
                        if (!*condition) {
                            if (instruction.immediate <= frame.pc) {
                                if (const auto loop_fault = charge_loop(instruction.span); loop_fault.has_value()) {
                                    return fail(*loop_fault);
                                }
                            }
                            frame.pc = instruction.immediate;
                        } else {
                            ++frame.pc;
                        }
                        break;
                    }
                    case Opcode::call: {
                        if (instruction.immediate >= pack.functions.size() ||
                            instruction.operand_b != pack.functions[instruction.immediate].parameter_count ||
                            instruction.operand_a > frame.registers.size() ||
                            instruction.operand_b > frame.registers.size() - instruction.operand_a) {
                            return fail(VmError {.code = VmErrorCode::invalid_bytecode,
                                                 .message = "static call encoding is invalid",
                                                 .span = instruction.span});
                        }
                        if (const auto frame_fault = charge_frame(instruction.span); frame_fault.has_value()) {
                            return fail(*frame_fault);
                        }
                        std::vector<PyValue> registers(pack.functions[instruction.immediate].register_count);
                        for (std::uint32_t index = 0; index < instruction.operand_b; ++index) {
                            const auto source = instruction.operand_a + index;
                            if (!register_valid(frame, source)) {
                                return fail(VmError {.code = VmErrorCode::invalid_bytecode,
                                                     .message = "static call reads an uninitialized argument register",
                                                     .span = instruction.span});
                            }
                            registers[index] = frame.registers[source];
                        }
                        ++frame.pc;
                        frames.push_back(Frame {.function_index = instruction.immediate,
                                                .pc = 0U,
                                                .registers = std::move(registers),
                                                .return_register = instruction.destination,
                                                .generator_state = GeneratorState::running});
                        counters.peak_frames =
                            std::max(counters.peak_frames, static_cast<std::uint32_t>(frames.size()));
                        break;
                    }
                    case Opcode::return_value: {
                        if (!register_valid(frame, instruction.operand_a)) {
                            return fail(VmError {.code = VmErrorCode::invalid_bytecode,
                                                 .message = "return reads an uninitialized register",
                                                 .span = instruction.span});
                        }
                        const auto value = frame.registers[instruction.operand_a];
                        const auto destination = frame.return_register;
                        frames.pop_back();
                        if (frames.empty()) {
                            return complete(value);
                        }
                        frames.back().registers[*destination] = value;
                        break;
                    }
                    case Opcode::raise_fault:
                        if (!register_valid(frame, instruction.operand_a)) {
                            return fail(VmError {.code = VmErrorCode::invalid_bytecode,
                                                 .message = "raise reads an uninitialized register",
                                                 .span = instruction.span});
                        }
                        if (!handle_author_fault(instruction, frame.registers[instruction.operand_a])) {
                            auto message = heap.unicode_utf8(frame.registers[instruction.operand_a]);
                            return fail(VmError {.code = VmErrorCode::value_error,
                                                 .message = message.value_or("uncaught Python fault"),
                                                 .span = instruction.span});
                        }
                        break;
                    case Opcode::enter_try:
                    case Opcode::leave_try: ++frame.pc; break;
                    case Opcode::yield_value:
                        if (!code.generator && !code.async) {
                            return fail(VmError {.code = VmErrorCode::invalid_bytecode,
                                                 .message = "yield opcode appears in a non-generator function",
                                                 .span = instruction.span});
                        }
                        if (!register_valid(frame, instruction.operand_a)) {
                            return fail(VmError {.code = VmErrorCode::invalid_bytecode,
                                                 .message = "yield reads an uninitialized register",
                                                 .span = instruction.span});
                        }
                        if (const auto loop_fault = charge_loop(instruction.span); loop_fault.has_value()) {
                            return fail(*loop_fault);
                        }
                        ++frame.pc;
                        frame.generator_state = GeneratorState::suspended;
                        return make_step(VmStepState::yielded, std::nullopt, frame.registers[instruction.operand_a]);
                    case Opcode::await_fact:
                        if (const auto fault = begin_fact(instruction, frame); fault.has_value()) {
                            return fail(*fault);
                        }
                        return make_step(VmStepState::waiting_for_facts);
                    case Opcode::await_capability:
                        if (const auto fault = begin_capability(instruction, frame); fault.has_value()) {
                            return fail(*fault);
                        }
                        return make_step(VmStepState::waiting_for_capabilities);
                    case Opcode::append_effect:
                        if (const auto fault = append_effect(instruction, frame); fault.has_value()) {
                            return fail(*fault);
                        }
                        break;
                    case Opcode::begin_transaction:
                        transaction_marks.push_back(journal.size());
                        ++frame.pc;
                        break;
                    case Opcode::commit_transaction:
                        if (transaction_marks.empty()) {
                            return fail(VmError {.code = VmErrorCode::invalid_bytecode,
                                                 .message = "commit_transaction has no open transaction",
                                                 .span = instruction.span});
                        }
                        transaction_marks.pop_back();
                        ++frame.pc;
                        break;
                    case Opcode::rollback_transaction:
                        if (transaction_marks.empty()) {
                            return fail(VmError {.code = VmErrorCode::invalid_bytecode,
                                                 .message = "rollback_transaction has no open transaction",
                                                 .span = instruction.span});
                        }
                        for (std::size_t index = transaction_marks.back(); index < journal.size(); ++index) {
                            journal[index].disposition = EffectDisposition::rolled_back;
                        }
                        transaction_marks.pop_back();
                        ++frame.pc;
                        break;
                    case Opcode::read_state:
                    case Opcode::write_state:
                        return fail(VmError {.code = VmErrorCode::invalid_bytecode,
                                             .message = "state opcode requires the state-runtime integration lane",
                                             .span = instruction.span});
                }

                if (quantum == cooperative_quantum) {
                    if ((counters.instructions % cooperative_quantum) == 0U) {
                        const auto collected = heap.collect(roots());
                        if (!collected) {
                            return fail(collected.error());
                        }
                    }
                    return make_step(VmStepState::yielded);
                }
            }
            return fail(VmError {.code = VmErrorCode::engine_fault,
                                 .message = "VM frame stack became empty without a result",
                                 .span = std::nullopt});
        }

        [[nodiscard]] VmStep step(HostResponses responses) {
            if (terminal_state.has_value()) {
                return make_step(*terminal_state, terminal_result);
            }
            if (responses.cancel) {
                return fail(VmError {.code = VmErrorCode::canceled,
                                     .message = "deployment cancellation requested",
                                     .span = std::nullopt},
                            VmStepState::canceled);
            }
            if (const auto time_fault = check_time(); time_fault.has_value()) {
                return fail(*time_fault);
            }
            if (const auto response_fault = apply_responses(responses); response_fault.has_value()) {
                return fail(*response_fault);
            }
            if (pending.has_value()) {
                return make_step(pending->kind == PendingKind::fact ? VmStepState::waiting_for_facts :
                                                                      VmStepState::waiting_for_capabilities);
            }
            if (!frames.empty() && frames.back().generator_state == GeneratorState::suspended) {
                frames.back().generator_state = GeneratorState::running;
            }
            return execute();
        }
    };

    RegisterVmSession::RegisterVmSession(Impl *const implementation) noexcept: impl_ {implementation} {}

    RegisterVmSession::~RegisterVmSession() { delete impl_; }

    VmStep RegisterVmSession::step(HostResponses responses) {
        impl_->active_step_started = std::chrono::steady_clock::now();
        impl_->active_step = true;
        auto result = impl_->step(std::move(responses));
        impl_->counters.active_time += std::chrono::steady_clock::now() - impl_->active_step_started;
        impl_->active_step = false;
        return result;
    }

    VmCounters RegisterVmSession::counters() const noexcept { return impl_->counters; }

    HeapStats RegisterVmSession::heap_stats() const noexcept { return impl_->heap.stats(); }

    std::size_t RegisterVmSession::logical_read_count() const noexcept { return impl_->logical_reads.size(); }

    std::size_t RegisterVmSession::journal_size() const noexcept { return impl_->journal.size(); }

    std::expected<FrozenValue, FreezeError> RegisterVmSession::freeze_value(const PyValue value) const {
        return impl_->heap.freeze(value);
    }

    std::expected<std::unique_ptr<RegisterVmSession>, DiagnosticSet>
    RegisterVmSession::create(const CompiledPack &pack, const VmInvocation &invocation) {
        if (auto verified = verify_bytecode(pack); !verified) {
            return std::unexpected(std::move(verified.error()));
        }
        DiagnosticSet diagnostics;
        if (invocation.execution.empty() || invocation.invocation.empty() || invocation.binding.empty() ||
            !invocation.subject.valid()) {
            diagnostics.push_back(diagnostic("PYVM0001", "VM invocation identity or subject is invalid"));
        }
        const auto binding = std::ranges::find(pack.bindings, invocation.binding, &OperatorBinding::id);
        if (binding == pack.bindings.end()) {
            diagnostics.push_back(diagnostic("PYVM0002", "VM invocation references an unknown binding"));
        }
        std::size_t entry_index {};
        if (binding != pack.bindings.end()) {
            const auto function = std::ranges::find(pack.functions, binding->executable, &BytecodeFunction::id);
            if (function == pack.functions.end()) {
                diagnostics.push_back(diagnostic("PYVM0003", "binding references an unknown bytecode function"));
            } else {
                entry_index = static_cast<std::size_t>(std::distance(pack.functions.begin(), function));
                if (function->parameter_count != 0U) {
                    diagnostics.push_back(diagnostic("PYVM0004", "bound entrypoint requires positional parameters"));
                }
            }
        }
        if (invocation.budget.name.empty()) {
            diagnostics.push_back(diagnostic("PYVM0005", "VM budget profile name is empty"));
        }
        if (!diagnostics.empty()) {
            return std::unexpected(std::move(diagnostics));
        }

        auto implementation = std::unique_ptr<Impl> {new Impl {pack, invocation}};
        implementation->constants.reserve(pack.constants.size());
        for (const auto &constant : pack.constants) {
            const auto *record = constant.valid() ? std::get_if<FactRecord>(&constant.node->data) : nullptr;
            const auto metadata = record != nullptr && (record->schema.value == fact_operand_schema ||
                                                        record->schema.value == capability_operand_schema);
            auto thawed = metadata ? implementation->heap.allocate_none() : implementation->heap.thaw(constant);
            if (!thawed) {
                diagnostics.push_back(
                    diagnostic("PYVM0006", "constant cannot be materialized: " + thawed.error().message));
                return std::unexpected(std::move(diagnostics));
            }
            implementation->constants.push_back(*thawed);
        }
        if (invocation.budget.normal.frames == 0U) {
            diagnostics.push_back(diagnostic("PYVM0007", "frame budget cannot admit the entrypoint"));
            return std::unexpected(std::move(diagnostics));
        }
        implementation->frames.push_back(Impl::Frame {
            .function_index = entry_index,
            .pc = 0U,
            .registers = std::vector<PyValue>(pack.functions[entry_index].register_count),
            .return_register = std::nullopt,
            .generator_state = GeneratorState::running,
        });
        implementation->counters.peak_frames = 1U;
        implementation->root_group = implementation->tasks.open_group();
        auto task = implementation->tasks.start(implementation->root_group);
        if (!task) {
            diagnostics.push_back(diagnostic("PYVM0008", task.error().message));
            return std::unexpected(std::move(diagnostics));
        }
        implementation->root_task = *task;
        static_cast<void>(implementation->tasks.set_state(*task, TaskState::running));
        return std::unique_ptr<RegisterVmSession> {new RegisterVmSession {implementation.release()}};
    }

    std::expected<std::unique_ptr<VmSession>, DiagnosticSet> RegisterVmFactory::start(const CompiledPack &pack,
                                                                                      const VmInvocation &invocation) {
        auto concrete = RegisterVmSession::create(pack, invocation);
        if (!concrete) {
            return std::unexpected(std::move(concrete.error()));
        }
        return std::unique_ptr<VmSession> {std::move(*concrete)};
    }

    std::unique_ptr<VmFactory> make_register_vm_factory() { return std::make_unique<RegisterVmFactory>(); }

} // namespace rule_engine::python::vm
