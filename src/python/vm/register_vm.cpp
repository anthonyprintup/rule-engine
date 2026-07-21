#include "rule_engine/python/vm/register_vm.hpp"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <limits>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#if defined(_WIN32)
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#else
#include <ctime>
#endif

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

        [[nodiscard]] bool valid_state_operand(const FactValue &value) {
            if (!value.valid()) {
                return false;
            }
            const auto *record = std::get_if<FactRecord>(&value.node->data);
            if (record == nullptr || record->schema.value != state_operand_schema || record->fields.size() != 3U) {
                return false;
            }
            for (std::uint32_t field = 1U; field <= 3U; ++field) {
                if (record->fields[field - 1U].field_id != field) {
                    return false;
                }
                const auto text = record_text_field(value, state_operand_schema, field);
                if (!text.has_value() || text->empty()) {
                    return false;
                }
            }
            return true;
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
                case VmErrorCode::state_budget_exhausted: return "PYVM4013";
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
                default: return "PYVM9001";
            }
        }

        [[nodiscard]] std::uint64_t deadline_after(const std::chrono::milliseconds duration) {
            const auto deadline = std::chrono::system_clock::now() + duration;
            return static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(deadline.time_since_epoch()).count());
        }

        [[nodiscard]] bool operation_in_range(const std::uint32_t value, const std::uint32_t last) noexcept {
            return value <= last;
        }

        [[nodiscard]] std::optional<std::chrono::nanoseconds> thread_cpu_now() noexcept {
#if defined(_WIN32)
            FILETIME created {};
            FILETIME exited {};
            FILETIME kernel {};
            FILETIME user {};
            if (GetThreadTimes(GetCurrentThread(), &created, &exited, &kernel, &user) == 0) {
                return std::nullopt;
            }
            const auto ticks = [](const FILETIME &value) {
                return (static_cast<std::uint64_t>(value.dwHighDateTime) << 32U) |
                       static_cast<std::uint64_t>(value.dwLowDateTime);
            };
            return std::chrono::nanoseconds {(ticks(kernel) + ticks(user)) * 100U};
#elif defined(CLOCK_THREAD_CPUTIME_ID)
            timespec value {};
            if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &value) != 0) {
                return std::nullopt;
            }
            return std::chrono::seconds {value.tv_sec} + std::chrono::nanoseconds {value.tv_nsec};
#else
            return std::nullopt;
#endif
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

    FactValue make_capability_operand(CapabilityId capability, SchemaId request_schema, SchemaId response_schema) {
        std::vector fields {
            FactRecordField {.field_id = 1U, .value = text_fact(std::move(capability.value))},
            FactRecordField {.field_id = 2U, .value = text_fact(std::move(request_schema.value))},
        };
        if (!response_schema.empty()) {
            fields.push_back(FactRecordField {.field_id = 3U, .value = text_fact(std::move(response_schema.value))});
        }
        return operand_record(capability_operand_schema, std::move(fields));
    }

    FactValue make_state_operand(std::string namespace_name, std::string key, SchemaId schema) {
        return operand_record(state_operand_schema,
                              {
                                  FactRecordField {.field_id = 1U, .value = text_fact(std::move(namespace_name))},
                                  FactRecordField {.field_id = 2U, .value = text_fact(std::move(key))},
                                  FactRecordField {.field_id = 3U, .value = text_fact(std::move(schema.value))},
                              });
    }

    FactValue make_handler_metadata(ExecutableId entrypoint, std::optional<ExecutableId> finalizer,
                                    std::optional<ExecutableId> on_fault, std::optional<ExecutableId> on_double_fault) {
        std::vector fields {
            FactRecordField {.field_id = 1U, .value = text_fact(std::move(entrypoint.value))},
        };
        if (finalizer.has_value()) {
            fields.push_back(FactRecordField {.field_id = 2U, .value = text_fact(std::move(finalizer->value))});
        }
        if (on_fault.has_value()) {
            fields.push_back(FactRecordField {.field_id = 3U, .value = text_fact(std::move(on_fault->value))});
        }
        if (on_double_fault.has_value()) {
            fields.push_back(FactRecordField {.field_id = 4U, .value = text_fact(std::move(on_double_fault->value))});
        }
        return operand_record(handler_metadata_schema, std::move(fields));
    }

    struct RegisterVmSession::Impl {
        enum struct ExecutorPhase : std::uint8_t { normal, recovery_retry, finalizer, on_fault, double_fault };
        enum struct UnwindKind : std::uint8_t { exception, return_value, jump, hard_fault };

        struct ActiveException {
            PythonFaultKind kind {PythonFaultKind::value_error};
            PyValue value;
            VmErrorCode code {VmErrorCode::value_error};
            SourceSpan span;
        };

        struct UnwindRecord {
            UnwindKind kind {UnwindKind::exception};
            std::optional<PyValue> value;
            std::optional<ActiveException> exception;
            std::optional<VmError> fault;
            std::optional<std::uint32_t> target_instruction;
            std::uint32_t origin_instruction {};
        };

        struct Frame {
            std::size_t function_index {};
            std::uint32_t pc {};
            std::vector<PyValue> registers;
            std::optional<std::uint32_t> return_register;
            std::optional<std::uint32_t> caller_instruction;
            GeneratorState generator_state {GeneratorState::running};
            std::optional<std::uint32_t> yield_destination;
            std::optional<UnwindRecord> unwind;
            std::vector<ActiveException> exception_stack;
            std::unordered_set<std::size_t> completed_cleanups;
        };

        enum struct PendingKind : std::uint8_t { fact, capability, state };

        struct PendingRequest {
            PendingKind kind {PendingKind::fact};
            RequestId id;
            std::size_t frame_index {};
            std::uint32_t destination {};
            std::uint32_t successor_pc {};
            SourceSpan span;
            std::optional<FactRequest> fact;
            std::optional<CapabilityRequest> capability;
            std::optional<StateReadRequest> state;
            std::optional<SchemaId> response_schema;
            std::string cache_key;
            bool emitted {};
        };

        struct CachedFactResponse {
            FactTerminalStatus status {FactTerminalStatus::failed};
            std::optional<FactValue> value;
        };

        struct CachedCapabilityResponse {
            FactTerminalStatus status {FactTerminalStatus::failed};
            std::optional<FrozenValue> value;
        };

        struct StateEntry {
            std::optional<FrozenValue> value;
            std::uint64_t version {};
            std::optional<std::string> error;
        };

        struct TransactionMark {
            std::size_t journal_size {};
            std::vector<StateMutation> state_mutations;
            std::unordered_map<std::string, StateEntry> state_overlay;
        };

        struct HandlerConfiguration {
            std::optional<std::size_t> finalizer;
            std::optional<std::size_t> on_fault;
            std::optional<std::size_t> on_double_fault;
        };

        CompiledPack pack;
        VmInvocation invocation;
        std::size_t entry_index {};
        ValueHeap heap;
        std::vector<PyValue> constants;
        std::vector<Frame> frames;
        std::optional<PendingRequest> pending;
        std::vector<std::string> logical_reads;
        std::unordered_map<std::string, CachedFactResponse> fact_responses;
        std::unordered_map<std::string, CachedCapabilityResponse> capability_responses;
        std::vector<EffectIntent> journal;
        std::vector<EffectIntent> journal_updates;
        std::vector<TransactionMark> transaction_marks;
        std::unordered_map<std::string, StateEntry> state_values;
        std::unordered_map<std::string, StateEntry> state_overlay;
        std::vector<StateMutation> state_mutations;
        std::unordered_set<std::string> charged_state_keys;
        std::size_t emitted_journal {};
        VmCounters counters;
        RecoveryCounters recovery;
        VmCounters tier_counters;
        ExecutorPhase phase {ExecutorPhase::normal};
        HandlerConfiguration handlers;
        std::optional<bool> candidate_verdict;
        std::vector<EffectIntent> candidate_journal;
        std::vector<StateMutation> candidate_state;
        std::vector<FaultFrame> fault_frames;
        bool retry_used {};
        bool forced_cleanup_active {};
        std::size_t forced_cleanup_heap_start {};
        std::uint32_t active_service_calls {};
        std::chrono::steady_clock::time_point started {std::chrono::steady_clock::now()};
        std::chrono::steady_clock::time_point phase_started {started};
        std::chrono::steady_clock::time_point active_step_started {};
        std::optional<std::chrono::nanoseconds> active_cpu_step_started;
        ExecutorPhase active_measurement_phase {ExecutorPhase::normal};
        bool active_measurement_forced {};
        bool tier_counters_finalized {};
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
                for (const auto &exception : frame.exception_stack) {
                    if (heap.valid(exception.value)) {
                        result.push_back(exception.value);
                    }
                }
                if (frame.unwind.has_value() && frame.unwind->exception.has_value() &&
                    heap.valid(frame.unwind->exception->value)) {
                    result.push_back(frame.unwind->exception->value);
                }
                if (frame.unwind.has_value() && frame.unwind->value.has_value() && heap.valid(*frame.unwind->value)) {
                    result.push_back(*frame.unwind->value);
                }
            }
            return result;
        }

        [[nodiscard]] VmCounters &current_counters() noexcept {
            if (forced_cleanup_active) {
                return recovery.forced_cleanup;
            }
            return phase == ExecutorPhase::normal || phase == ExecutorPhase::recovery_retry ? counters : tier_counters;
        }

        [[nodiscard]] const VmCounters &current_counters() const noexcept {
            if (forced_cleanup_active) {
                return recovery.forced_cleanup;
            }
            return phase == ExecutorPhase::normal || phase == ExecutorPhase::recovery_retry ? counters : tier_counters;
        }

        void begin_active_measurement() {
            active_step_started = std::chrono::steady_clock::now();
            active_cpu_step_started = thread_cpu_now();
            active_measurement_phase = phase;
            active_measurement_forced = forced_cleanup_active;
            active_step = true;
        }

        void settle_active_measurement() {
            if (!active_step) {
                return;
            }
            auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now() -
                                                                                active_step_started);
            if (active_cpu_step_started.has_value()) {
                if (const auto current = thread_cpu_now();
                    current.has_value() && *current >= *active_cpu_step_started) {
                    elapsed = *current - *active_cpu_step_started;
                }
            }
            if (active_measurement_forced) {
                recovery.forced_cleanup.active_time += elapsed;
            } else if (active_measurement_phase == ExecutorPhase::normal ||
                       active_measurement_phase == ExecutorPhase::recovery_retry) {
                counters.active_time += elapsed;
            } else if (tier_counters_finalized) {
                auto &destination = active_measurement_phase == ExecutorPhase::double_fault ?
                                        recovery.double_fault :
                                        recovery.finalizer_or_fault;
                destination.active_time += elapsed;
            } else {
                tier_counters.active_time += elapsed;
            }
            active_step_started = std::chrono::steady_clock::now();
            active_cpu_step_started = thread_cpu_now();
        }

        void rebind_active_measurement() {
            settle_active_measurement();
            active_measurement_phase = phase;
            active_measurement_forced = forced_cleanup_active;
        }

        void end_active_measurement() {
            settle_active_measurement();
            active_step = false;
            active_cpu_step_started.reset();
        }

        [[nodiscard]] const RecoveryBudget *recovery_budget() const noexcept {
            if (forced_cleanup_active) {
                return &invocation.budget.forced_cleanup;
            }
            if (phase == ExecutorPhase::finalizer || phase == ExecutorPhase::on_fault) {
                return &invocation.budget.finalizer_or_fault;
            }
            if (phase == ExecutorPhase::double_fault) {
                return &invocation.budget.double_fault;
            }
            return nullptr;
        }

        [[nodiscard]] std::chrono::nanoseconds current_active_time() const {
            const auto &phase_counter = current_counters();
            if (!active_step) {
                return phase_counter.active_time;
            }
            if (active_cpu_step_started.has_value()) {
                if (const auto current = thread_cpu_now();
                    current.has_value() && *current >= *active_cpu_step_started) {
                    return phase_counter.active_time + (*current - *active_cpu_step_started);
                }
            }
            return phase_counter.active_time + (std::chrono::steady_clock::now() - active_step_started);
        }

        [[nodiscard]] std::chrono::milliseconds remaining_elapsed() const {
            const auto deadline =
                recovery_budget() == nullptr ? invocation.budget.normal.elapsed : recovery_budget()->elapsed;
            const auto basis = recovery_budget() == nullptr ? started : phase_started;
            const auto elapsed =
                std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - basis);
            if (elapsed >= deadline) {
                return std::chrono::milliseconds::zero();
            }
            return deadline - elapsed;
        }

        [[nodiscard]] std::optional<VmError> check_time() const {
            const auto *recovery_limit = recovery_budget();
            const auto elapsed_limit =
                recovery_limit == nullptr ? invocation.budget.normal.elapsed : recovery_limit->elapsed;
            const auto active_limit =
                recovery_limit == nullptr ? invocation.budget.normal.active_cpu : recovery_limit->active_cpu;
            const auto basis = recovery_limit == nullptr ? started : phase_started;
            const auto elapsed = std::chrono::steady_clock::now() - basis;
            if (elapsed >= elapsed_limit) {
                return VmError {.code = VmErrorCode::elapsed_budget_exhausted,
                                .message = "balanced.v1 elapsed deadline exhausted",
                                .span = std::nullopt};
            }
            if (active_limit != std::chrono::milliseconds::zero() && current_active_time() >= active_limit) {
                return VmError {.code = VmErrorCode::elapsed_budget_exhausted,
                                .message = "balanced.v1 active VM time exhausted",
                                .span = std::nullopt};
            }
            return std::nullopt;
        }

        [[nodiscard]] std::optional<VmError> charge_instructions(const std::uint64_t amount, const SourceSpan &span) {
            const auto *recovery_limit = recovery_budget();
            const auto limit =
                recovery_limit == nullptr ? invocation.budget.normal.instructions : recovery_limit->instructions;
            auto &phase_counter = current_counters();
            if (amount > limit || phase_counter.instructions > limit - amount) {
                return VmError {.code = VmErrorCode::instruction_budget_exhausted,
                                .message = "balanced.v1 semantic instruction budget exhausted",
                                .span = span};
            }
            phase_counter.instructions += amount;
            return std::nullopt;
        }

        [[nodiscard]] std::optional<VmError> charge_loop(const SourceSpan &span) {
            auto &phase_counter = current_counters();
            if (recovery_budget() == nullptr &&
                phase_counter.loop_iterations_and_yields == invocation.budget.normal.loop_iterations_and_yields) {
                return VmError {.code = VmErrorCode::loop_budget_exhausted,
                                .message = "balanced.v1 loop iteration/yield budget exhausted",
                                .span = span};
            }
            ++phase_counter.loop_iterations_and_yields;
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

        void rollback_journal_from(const std::size_t first) {
            for (std::size_t index = first; index < journal.size(); ++index) {
                if (journal[index].disposition != EffectDisposition::pending) {
                    continue;
                }
                journal[index].disposition = EffectDisposition::rolled_back;
                if (index < emitted_journal) {
                    journal_updates.push_back(journal[index]);
                }
            }
        }

        static void add_counters(VmCounters &target, const VmCounters &source) {
            target.instructions += source.instructions;
            target.peak_frames = std::max(target.peak_frames, source.peak_frames);
            target.loop_iterations_and_yields += source.loop_iterations_and_yields;
            target.logical_facts += source.logical_facts;
            target.provider_rounds += source.provider_rounds;
            target.fact_bytes += source.fact_bytes;
            target.service_calls += source.service_calls;
            target.peak_active_service_calls =
                std::max(target.peak_active_service_calls, source.peak_active_service_calls);
            target.service_response_bytes += source.service_response_bytes;
            target.state_keys += source.state_keys;
            target.state_bytes += source.state_bytes;
            target.effect_intents += source.effect_intents;
            target.effect_bytes += source.effect_bytes;
            target.active_time += source.active_time;
        }

        void finish_tier_counters() {
            settle_active_measurement();
            if (phase == ExecutorPhase::finalizer || phase == ExecutorPhase::on_fault) {
                add_counters(recovery.finalizer_or_fault, tier_counters);
                tier_counters_finalized = true;
            } else if (phase == ExecutorPhase::double_fault) {
                add_counters(recovery.double_fault, tier_counters);
                tier_counters_finalized = true;
            }
            tier_counters = {};
        }

        [[nodiscard]] std::optional<VmError> materialize_constants() {
            constants.clear();
            constants.reserve(pack.constants.size());
            for (const auto &constant : pack.constants) {
                auto thawed = heap.thaw(constant);
                if (!thawed) {
                    return VmError {.code = thawed.error().code,
                                    .message = "constant cannot be materialized: " + thawed.error().message,
                                    .span = thawed.error().span};
                }
                constants.push_back(*thawed);
            }
            return std::nullopt;
        }

        [[nodiscard]] std::optional<VmError>
        start_executor(const std::size_t function_index, const ExecutorPhase next_phase, const std::size_t heap_limit) {
            finish_tier_counters();
            phase = next_phase;
            tier_counters_finalized = false;
            phase_started = std::chrono::steady_clock::now();
            rebind_active_measurement();
            heap = ValueHeap {heap_limit};
            frames.clear();
            pending.reset();
            journal.clear();
            transaction_marks.clear();
            state_overlay.clear();
            state_mutations.clear();
            emitted_journal = 0U;
            active_service_calls = 0U;
            tasks = StructuredTasks {};
            root_group = 0U;
            root_task = 0U;
            if (const auto fault = materialize_constants(); fault.has_value()) {
                return fault;
            }
            const auto entry_parameters = function_index == entry_index ? 1U : 0U;
            if (function_index >= pack.functions.size() ||
                pack.functions[function_index].parameter_count > entry_parameters) {
                return VmError {.code = VmErrorCode::invalid_bytecode,
                                .message = "executor entrypoint has an unsupported parameter ABI",
                                .span = std::nullopt};
            }
            frames.push_back(Frame {.function_index = function_index,
                                    .pc = 0U,
                                    .registers = std::vector<PyValue>(pack.functions[function_index].register_count),
                                    .return_register = std::nullopt,
                                    .caller_instruction = std::nullopt,
                                    .generator_state = GeneratorState::running,
                                    .yield_destination = std::nullopt,
                                    .unwind = std::nullopt,
                                    .exception_stack = {},
                                    .completed_cleanups = {}});
            if (pack.functions[function_index].parameter_count == 1U) {
                auto subject_value = heap.allocate_none();
                if (!subject_value) {
                    return subject_value.error();
                }
                frames.back().registers[0] = *subject_value;
            }
            current_counters().peak_frames = 1U;
            root_group = tasks.open_group();
            auto task = tasks.start(root_group);
            if (!task) {
                return task.error();
            }
            root_task = *task;
            static_cast<void>(tasks.set_state(*task, TaskState::running));
            return std::nullopt;
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

        [[nodiscard]] VmStep terminal_fault(const VmStepState state, const bool double_fault, const bool triple_fault) {
            finish_tier_counters();
            EvaluationResult result {
                .outcome = state == VmStepState::quarantined ? EvaluationOutcome::quarantined :
                           state == VmStepState::canceled    ? EvaluationOutcome::canceled :
                                                               EvaluationOutcome::faulted,
                .verdict = std::nullopt,
                .committed_effects = {},
                .state_mutations = {},
                .fault =
                    FaultChain {.frames = fault_frames, .double_fault = double_fault, .triple_fault = triple_fault},
            };
            return terminal(state, std::move(result));
        }

        [[nodiscard]] static bool integrity_fault(const VmErrorCode code) noexcept {
            return code == VmErrorCode::invalid_handle || code == VmErrorCode::stale_handle ||
                   code == VmErrorCode::invalid_bytecode || code == VmErrorCode::engine_fault;
        }

        [[nodiscard]] static bool hard_control_fault(const VmErrorCode code) noexcept {
            return code == VmErrorCode::heap_budget_exhausted || code == VmErrorCode::instruction_budget_exhausted ||
                   code == VmErrorCode::frame_budget_exhausted || code == VmErrorCode::loop_budget_exhausted ||
                   code == VmErrorCode::elapsed_budget_exhausted || code == VmErrorCode::fact_budget_exhausted ||
                   code == VmErrorCode::capability_budget_exhausted || code == VmErrorCode::state_budget_exhausted ||
                   code == VmErrorCode::effect_budget_exhausted || code == VmErrorCode::canceled;
        }

        [[nodiscard]] static bool author_exception(const VmErrorCode code) noexcept {
            return code == VmErrorCode::type_error || code == VmErrorCode::value_error ||
                   code == VmErrorCode::arithmetic_error;
        }

        void record_fault(VmError fault) {
            fault_frames.push_back(FaultFrame {
                .code = error_code(fault.code),
                .message = std::move(fault.message),
                .executable = frames.empty() ? ExecutableId {} : function(frames.back()).id,
                .span = fault.span.value_or(SourceSpan {}),
            });
        }

        [[nodiscard]] VmStep begin_double_fault(VmError fault) {
            record_fault(std::move(fault));
            ++recovery.double_faults;
            rollback_journal_from(0U);
            candidate_journal.clear();
            candidate_state.clear();
            if (!handlers.on_double_fault.has_value()) {
                ++recovery.triple_faults;
                finish_tier_counters();
                return terminal_fault(VmStepState::quarantined, true, true);
            }
            if (const auto start = start_executor(*handlers.on_double_fault, ExecutorPhase::double_fault,
                                                  invocation.budget.double_fault.heap_bytes);
                start.has_value()) {
                record_fault(*start);
                ++recovery.triple_faults;
                return terminal_fault(VmStepState::quarantined, true, true);
            }
            return make_step(VmStepState::yielded);
        }

        [[nodiscard]] VmStep fail(VmError fault, const VmStepState requested_state = VmStepState::faulted) {
            const auto code = fault.code;
            if (integrity_fault(code)) {
                record_fault(std::move(fault));
                return terminal_fault(VmStepState::quarantined, phase != ExecutorPhase::normal, false);
            }
            if (code == VmErrorCode::invalid_host_response) {
                record_fault(std::move(fault));
                return terminal_fault(VmStepState::faulted, phase != ExecutorPhase::normal, false);
            }
            if (forced_cleanup_active) {
                set_forced_cleanup(false);
                return begin_double_fault(std::move(fault));
            }
            if (author_exception(code) && !frames.empty()) {
                auto exception = heap.allocate_unicode(fault.message);
                if (exception && frames.back().pc < function(frames.back()).instructions.size()) {
                    const auto &current = function(frames.back()).instructions[frames.back().pc];
                    discard_pending_exception(frames.back());
                    frames.back().unwind.reset();
                    if (handle_author_fault(frames.back().pc,
                                            ActiveException {.kind = python_fault_kind(code),
                                                             .value = *exception,
                                                             .code = code,
                                                             .span = fault.span.value_or(current.span)})) {
                        return make_step(VmStepState::yielded);
                    }
                }
            }
            if (phase == ExecutorPhase::double_fault) {
                record_fault(std::move(fault));
                ++recovery.triple_faults;
                finish_tier_counters();
                return terminal_fault(VmStepState::quarantined, true, true);
            }
            if (phase == ExecutorPhase::finalizer || phase == ExecutorPhase::on_fault ||
                phase == ExecutorPhase::recovery_retry) {
                return begin_double_fault(std::move(fault));
            }

            if (hard_control_fault(code)) {
                pending.reset();
                if (begin_forced_cleanup(fault)) {
                    return make_step(VmStepState::yielded);
                }
            }

            record_fault(std::move(fault));
            ++recovery.primary_faults;
            rollback_journal_from(0U);
            state_mutations.clear();
            state_overlay.clear();
            if (requested_state == VmStepState::canceled) {
                return terminal_fault(VmStepState::canceled, false, false);
            }
            if (hard_control_fault(code)) {
                return terminal_fault(requested_state, false, false);
            }
            if (!handlers.on_fault.has_value()) {
                return terminal_fault(requested_state, false, false);
            }
            if (const auto start = start_executor(*handlers.on_fault, ExecutorPhase::on_fault,
                                                  invocation.budget.finalizer_or_fault.heap_bytes);
                start.has_value()) {
                return begin_double_fault(*start);
            }
            return make_step(VmStepState::yielded);
        }

        [[nodiscard]] std::optional<std::string> unicode_decision(const PyValue value) const {
            auto kind = heap.kind(value);
            if (!kind || *kind != ValueKind::unicode) {
                return std::nullopt;
            }
            auto text = heap.unicode_utf8(value);
            return text ? std::optional<std::string> {*text} : std::nullopt;
        }

        [[nodiscard]] VmStep finalize_candidate() {
            std::vector<EffectIntent> committed;
            committed.reserve(candidate_journal.size());
            for (auto intent : candidate_journal) {
                if (intent.disposition != EffectDisposition::pending &&
                    intent.disposition != EffectDisposition::committed) {
                    continue;
                }
                intent.disposition = EffectDisposition::committed;
                committed.push_back(std::move(intent));
            }
            const auto verdict = candidate_verdict.value_or(false);
            EvaluationResult result {
                .outcome = verdict ? EvaluationOutcome::match : EvaluationOutcome::no_match,
                .verdict = verdict,
                .committed_effects = std::move(committed),
                .state_mutations = candidate_state,
                .fault = std::nullopt,
            };
            finish_tier_counters();
            return terminal(VmStepState::complete, std::move(result));
        }

        [[nodiscard]] VmStep complete(const PyValue value) {
            if (phase == ExecutorPhase::double_fault) {
                const auto decision = unicode_decision(value);
                if (!decision.has_value() ||
                    (!decision->starts_with("abort") && !decision->starts_with("quarantine"))) {
                    return fail(VmError {.code = VmErrorCode::value_error,
                                         .message = "on_double_fault must return abort or quarantine",
                                         .span = std::nullopt});
                }
                finish_tier_counters();
                return terminal_fault(
                    decision->starts_with("quarantine") ? VmStepState::quarantined : VmStepState::faulted, true, false);
            }

            if (phase == ExecutorPhase::finalizer) {
                auto kind = heap.kind(value);
                if (!kind) {
                    return begin_double_fault(kind.error());
                }
                const auto decision = unicode_decision(value);
                if (*kind == ValueKind::boolean) {
                    auto replacement = heap.truthy(value);
                    candidate_verdict = replacement.value_or(false);
                } else if (*kind != ValueKind::none && (!decision.has_value() || !decision->starts_with("keep"))) {
                    if (decision.has_value() && decision->starts_with("abort")) {
                        record_fault(
                            VmError {.code = VmErrorCode::value_error, .message = *decision, .span = std::nullopt});
                        return terminal_fault(VmStepState::faulted, false, false);
                    }
                    return begin_double_fault(VmError {.code = VmErrorCode::value_error,
                                                       .message = "finalizer must return keep, replace(bool), or abort",
                                                       .span = std::nullopt});
                }
                candidate_journal.insert(candidate_journal.end(), journal.begin(), journal.end());
                return finalize_candidate();
            }

            if (phase == ExecutorPhase::on_fault) {
                auto kind = heap.kind(value);
                if (!kind) {
                    return begin_double_fault(kind.error());
                }
                const auto decision = unicode_decision(value);
                if (*kind == ValueKind::boolean) {
                    auto replacement = heap.truthy(value);
                    candidate_verdict = replacement.value_or(false);
                    candidate_journal = journal;
                    candidate_state.clear();
                } else if (decision.has_value() && decision->starts_with("retry_once")) {
                    if (retry_used) {
                        return begin_double_fault(VmError {.code = VmErrorCode::value_error,
                                                           .message = "fault recovery retry was already consumed",
                                                           .span = std::nullopt});
                    }
                    retry_used = true;
                    if (const auto start = start_executor(entry_index, ExecutorPhase::recovery_retry,
                                                          invocation.budget.normal.heap_bytes);
                        start.has_value()) {
                        return begin_double_fault(*start);
                    }
                    return make_step(VmStepState::yielded);
                } else if (decision.has_value() &&
                           (decision->starts_with("abort") || decision->starts_with("quarantine"))) {
                    finish_tier_counters();
                    return terminal_fault(decision->starts_with("quarantine") ? VmStepState::quarantined :
                                                                                VmStepState::faulted,
                                          false, false);
                } else {
                    return begin_double_fault(VmError {.code = VmErrorCode::value_error,
                                                       .message = "on_fault returned an invalid recovery decision",
                                                       .span = std::nullopt});
                }
            } else {
                auto verdict = heap.truthy(value);
                if (!verdict) {
                    return fail(verdict.error());
                }
                candidate_verdict = *verdict;
                candidate_journal = journal;
                candidate_state = state_mutations;
            }

            if (!transaction_marks.empty()) {
                const auto &root_mark = transaction_marks.front();
                rollback_journal_from(root_mark.journal_size);
                state_mutations = root_mark.state_mutations;
                state_overlay = root_mark.state_overlay;
                transaction_marks.clear();
                candidate_journal = journal;
                candidate_state = state_mutations;
            }
            if (handlers.finalizer.has_value()) {
                if (const auto start = start_executor(*handlers.finalizer, ExecutorPhase::finalizer,
                                                      invocation.budget.finalizer_or_fault.heap_bytes);
                    start.has_value()) {
                    return begin_double_fault(*start);
                }
                return make_step(VmStepState::yielded);
            }
            return finalize_candidate();
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
                } else if (pending->state.has_value()) {
                    step.state_requests.push_back(*pending->state);
                }
                pending->emitted = true;
            }
            if (emitted_journal < journal.size()) {
                step.journal_delta.insert(step.journal_delta.end(),
                                          journal.begin() + static_cast<std::ptrdiff_t>(emitted_journal),
                                          journal.end());
                emitted_journal = journal.size();
            }
            if (!journal_updates.empty()) {
                step.journal_delta.insert(step.journal_delta.end(), journal_updates.begin(), journal_updates.end());
                journal_updates.clear();
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
            if (total != 1U || !responses.scans.empty() || !responses.history.empty()) {
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
            if (pending->kind == PendingKind::state && responses.state.size() != 1U) {
                return VmError {.code = VmErrorCode::invalid_host_response,
                                .message = "non-state response cannot satisfy an outstanding state request",
                                .span = pending->span};
            }
            return std::nullopt;
        }

        [[nodiscard]] std::optional<VmError> raise_author_terminal(const Instruction &faulting, std::string message) {
            auto exception = heap.allocate_unicode(message);
            if (!exception) {
                return exception.error();
            }
            discard_pending_exception(frames.back());
            frames.back().unwind.reset();
            if (!handle_author_fault(frames.back().pc, ActiveException {.kind = PythonFaultKind::value_error,
                                                                        .value = *exception,
                                                                        .code = VmErrorCode::value_error,
                                                                        .span = faulting.span})) {
                return VmError {.code = VmErrorCode::value_error, .message = std::move(message), .span = faulting.span};
            }
            return std::nullopt;
        }

        [[nodiscard]] std::optional<VmError> raise_pending_terminal(std::string message) {
            const Instruction faulting {
                .opcode = Opcode::raise_fault,
                .destination = pending->destination,
                .operand_a = pending->destination,
                .operand_b = 0U,
                .immediate = 0U,
                .span = pending->span,
            };
            if (const auto fault = raise_author_terminal(faulting, std::move(message)); fault.has_value()) {
                return fault;
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
            if (pending->kind == PendingKind::state && responses.state.empty()) {
                return std::nullopt;
            }

            std::expected<PyValue, VmError> thawed =
                std::unexpected(VmError {.code = VmErrorCode::engine_fault,
                                         .message = "host response did not produce a VM value",
                                         .span = pending->span});
            if (pending->kind == PendingKind::fact) {
                const auto &response = responses.facts.front();
                if (response.request_id != pending->id ||
                    canonical_subject_key(response.subject) != canonical_subject_key(pending->fact->subject)) {
                    return VmError {.code = VmErrorCode::invalid_host_response,
                                    .message = "fact response identity does not match its request",
                                    .span = pending->span};
                }
                if ((response.status == FactTerminalStatus::value) != response.value.has_value()) {
                    return VmError {.code = VmErrorCode::invalid_host_response,
                                    .message = "fact response value does not match its terminal status",
                                    .span = pending->span};
                }
                if (response.status != FactTerminalStatus::value) {
                    fact_responses.insert_or_assign(
                        pending->cache_key, CachedFactResponse {.status = response.status, .value = std::nullopt});
                    return raise_pending_terminal("fact provider returned terminal status " +
                                                  std::to_string(static_cast<unsigned>(response.status)));
                }
                if (auto schema = ValueHeap::validate_schema(*response.value, *pending->response_schema, &pack.schemas);
                    !schema) {
                    return VmError {.code = VmErrorCode::invalid_host_response,
                                    .message = "fact response failed schema validation: " + schema.error().message,
                                    .span = pending->span};
                }
                fact_responses.insert_or_assign(
                    pending->cache_key, CachedFactResponse {.status = response.status, .value = *response.value});
                const auto bytes = fact_size(*response.value);
                if (bytes == std::numeric_limits<std::size_t>::max() || bytes > invocation.budget.normal.fact_bytes ||
                    counters.fact_bytes > invocation.budget.normal.fact_bytes - bytes) {
                    return VmError {.code = VmErrorCode::fact_budget_exhausted,
                                    .message = "balanced.v1 fact data budget exhausted",
                                    .span = pending->span};
                }
                counters.fact_bytes += bytes;
                thawed = heap.thaw(*response.value);
            } else if (pending->kind == PendingKind::capability) {
                const auto &response = responses.capabilities.front();
                if (response.request_id != pending->id) {
                    return VmError {.code = VmErrorCode::invalid_host_response,
                                    .message = "capability response identity does not match its request",
                                    .span = pending->span};
                }
                if ((response.status == FactTerminalStatus::value) != response.value.has_value()) {
                    return VmError {.code = VmErrorCode::invalid_host_response,
                                    .message = "capability response value does not match its terminal status",
                                    .span = pending->span};
                }
                if (response.status != FactTerminalStatus::value) {
                    if (active_service_calls == 0U) {
                        return VmError {.code = VmErrorCode::engine_fault,
                                        .message = "capability terminal underflowed active-call accounting",
                                        .span = pending->span};
                    }
                    --active_service_calls;
                    capability_responses.insert_or_assign(
                        pending->cache_key,
                        CachedCapabilityResponse {.status = response.status, .value = std::nullopt});
                    return raise_pending_terminal("capability returned a non-value terminal status");
                }
                const auto bytes = fact_size(response.value->value);
                if (bytes == std::numeric_limits<std::size_t>::max() ||
                    bytes > invocation.budget.normal.service_response_bytes ||
                    current_counters().service_response_bytes >
                        invocation.budget.normal.service_response_bytes - bytes) {
                    return VmError {.code = VmErrorCode::capability_budget_exhausted,
                                    .message = "balanced.v1 service response budget exhausted",
                                    .span = pending->span};
                }
                current_counters().service_response_bytes += bytes;
                if (active_service_calls == 0U) {
                    return VmError {.code = VmErrorCode::engine_fault,
                                    .message = "capability response underflowed active-call accounting",
                                    .span = pending->span};
                }
                --active_service_calls;
                auto validated = heap.validate_frozen(
                    response.value.value(), pending->response_schema, &pack.schemas,
                    FreezeLimits {.maximum_bytes = invocation.budget.normal.service_response_bytes});
                if (!validated) {
                    return VmError {.code = VmErrorCode::invalid_host_response,
                                    .message = "capability response failed canonical boundary validation: " +
                                               validated.error().message,
                                    .span = pending->span};
                }
                capability_responses.insert_or_assign(
                    pending->cache_key, CachedCapabilityResponse {.status = response.status, .value = *response.value});
                thawed = *validated;
            } else {
                const auto &response = responses.state.front();
                if (response.request_id != pending->id) {
                    return VmError {.code = VmErrorCode::invalid_host_response,
                                    .message = "state response identity does not match its request",
                                    .span = pending->span};
                }
                const auto key = pending->state->namespace_name + "\x1f" + pending->state->key + "\x1f" +
                                 pending->state->schema.value;
                if (response.diagnostic.has_value()) {
                    state_values.insert_or_assign(
                        key, StateEntry {.value = std::nullopt,
                                         .version = response.version,
                                         .error = "state read failed: " + response.diagnostic->message});
                    return raise_pending_terminal("state read failed: " + response.diagnostic->message);
                }
                if (response.value.has_value()) {
                    const auto bytes = fact_size(response.value->value);
                    if (bytes == std::numeric_limits<std::size_t>::max() ||
                        bytes > invocation.budget.normal.state_bytes ||
                        counters.state_bytes > invocation.budget.normal.state_bytes - bytes) {
                        return VmError {.code = VmErrorCode::state_budget_exhausted,
                                        .message = "balanced.v1 state data budget exhausted",
                                        .span = pending->span};
                    }
                    auto validated =
                        heap.validate_frozen(*response.value, pending->response_schema, &pack.schemas,
                                             FreezeLimits {.maximum_bytes = invocation.budget.normal.state_bytes});
                    if (!validated) {
                        return VmError {.code = VmErrorCode::invalid_host_response,
                                        .message = "state response failed canonical boundary validation: " +
                                                   validated.error().message,
                                        .span = pending->span};
                    }
                    counters.state_bytes += bytes;
                    thawed = *validated;
                } else {
                    thawed = heap.allocate_none();
                }
                state_values.insert_or_assign(
                    key, StateEntry {.value = response.value, .version = response.version, .error = std::nullopt});
            }

            if (!thawed && thawed.error().code == VmErrorCode::heap_budget_exhausted) {
                const auto gc = heap.collect(roots());
                if (!gc) {
                    return gc.error();
                }
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
            const auto cache_key =
                canonical_subject_key(invocation.subject) + "\x1f" + *provider + "\x1f" + *fact + "\x1f" + *schema;
            if (const auto cached = fact_responses.find(cache_key); cached != fact_responses.end()) {
                if (cached->second.status != FactTerminalStatus::value || !cached->second.value.has_value()) {
                    return raise_author_terminal(instruction,
                                                 "fact provider returned terminal status " +
                                                     std::to_string(static_cast<unsigned>(cached->second.status)));
                }
                if (auto valid = ValueHeap::validate_schema(*cached->second.value, SchemaId {*schema}, &pack.schemas);
                    !valid) {
                    return VmError {.code = VmErrorCode::engine_fault,
                                    .message = "cached fact response no longer satisfies its schema",
                                    .span = instruction.span};
                }
                auto value = heap.thaw(*cached->second.value);
                if (!value) {
                    return value.error();
                }
                frame.registers[instruction.destination] = *value;
                ++frame.pc;
                return std::nullopt;
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
                .state = std::nullopt,
                .response_schema = SchemaId {*schema},
                .cache_key = cache_key,
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
            const auto response_schema =
                record_text_field(pack.constants[instruction.immediate], capability_operand_schema, 3U);
            if (!capability.has_value() || !schema.has_value() || capability->empty() || schema->empty()) {
                return VmError {.code = VmErrorCode::invalid_bytecode,
                                .message = "await_capability constant is not a valid capability operand",
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
            const auto cache_key = *capability + "\x1f" + *schema + "\x1f" + response_schema.value_or(std::string {}) +
                                   "\x1f" + arguments->canonical_digest;
            if (const auto cached = capability_responses.find(cache_key); cached != capability_responses.end()) {
                if (cached->second.status != FactTerminalStatus::value || !cached->second.value.has_value()) {
                    return raise_author_terminal(instruction, "capability returned a non-value terminal status");
                }
                auto validated = heap.validate_frozen(
                    *cached->second.value,
                    response_schema.has_value() ? std::optional<SchemaId> {SchemaId {*response_schema}} : std::nullopt,
                    &pack.schemas, FreezeLimits {.maximum_bytes = invocation.budget.normal.service_response_bytes});
                if (!validated) {
                    return VmError {.code = VmErrorCode::engine_fault,
                                    .message = "cached capability response is no longer canonical",
                                    .span = instruction.span};
                }
                frame.registers[instruction.destination] = *validated;
                ++frame.pc;
                return std::nullopt;
            }
            const auto *recovery_limit = recovery_budget();
            const auto service_limit =
                recovery_limit == nullptr ? invocation.budget.normal.service_calls : recovery_limit->service_calls;
            auto &phase_counter = current_counters();
            if (phase_counter.service_calls == service_limit ||
                active_service_calls == invocation.budget.normal.active_service_calls) {
                return VmError {.code = VmErrorCode::capability_budget_exhausted,
                                .message = "balanced.v1 service call budget exhausted",
                                .span = instruction.span};
            }
            ++phase_counter.service_calls;
            ++active_service_calls;
            phase_counter.peak_active_service_calls =
                std::max(phase_counter.peak_active_service_calls, active_service_calls);
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
                .state = std::nullopt,
                .response_schema =
                    response_schema.has_value() ? std::optional<SchemaId> {SchemaId {*response_schema}} : std::nullopt,
                .cache_key = cache_key,
                .emitted = false,
            };
            return std::nullopt;
        }

        [[nodiscard]] std::optional<VmError> charge_state_key(const std::string &key, const SourceSpan &span) {
            if (charged_state_keys.contains(key)) {
                return std::nullopt;
            }
            if (counters.state_keys == invocation.budget.normal.state_keys) {
                return VmError {.code = VmErrorCode::state_budget_exhausted,
                                .message = "balanced.v1 state key budget exhausted",
                                .span = span};
            }
            charged_state_keys.insert(key);
            ++counters.state_keys;
            return std::nullopt;
        }

        [[nodiscard]] std::optional<VmError> begin_state_read(const Instruction &instruction, Frame &frame) {
            if (instruction.immediate >= pack.constants.size()) {
                return VmError {.code = VmErrorCode::invalid_bytecode,
                                .message = "read_state constant index is out of range",
                                .span = instruction.span};
            }
            const auto namespace_name =
                record_text_field(pack.constants[instruction.immediate], state_operand_schema, 1U);
            const auto name = record_text_field(pack.constants[instruction.immediate], state_operand_schema, 2U);
            const auto schema = record_text_field(pack.constants[instruction.immediate], state_operand_schema, 3U);
            if (!namespace_name.has_value() || !name.has_value() || !schema.has_value() || namespace_name->empty() ||
                name->empty() || schema->empty()) {
                return VmError {.code = VmErrorCode::invalid_bytecode,
                                .message = "read_state constant is not a valid state operand",
                                .span = instruction.span};
            }
            const auto key = *namespace_name + "\x1f" + *name + "\x1f" + *schema;
            if (const auto fault = charge_state_key(key, instruction.span); fault.has_value()) {
                return fault;
            }
            const auto cached_overlay = state_overlay.find(key);
            const auto cached_read = state_values.find(key);
            const auto *cached = cached_overlay != state_overlay.end() ? &cached_overlay->second :
                                 cached_read != state_values.end()     ? &cached_read->second :
                                                                         nullptr;
            if (cached != nullptr) {
                if (cached->error.has_value()) {
                    return raise_author_terminal(instruction, *cached->error);
                }
                auto value = cached->value.has_value() ? heap.thaw(cached->value->value) : heap.allocate_none();
                if (!value) {
                    return value.error();
                }
                frame.registers[instruction.destination] = *value;
                ++frame.pc;
                return std::nullopt;
            }

            const auto id = next_request_id();
            StateReadRequest request {
                .request_id = id,
                .owner = function(frame).id,
                .namespace_name = *namespace_name,
                .key = *name,
                .schema = SchemaId {*schema},
            };
            logical_reads.push_back(id.value + ":state:" + key);
            pending = PendingRequest {
                .kind = PendingKind::state,
                .id = id,
                .frame_index = frames.size() - 1U,
                .destination = instruction.destination,
                .successor_pc = frame.pc + 1U,
                .span = instruction.span,
                .fact = std::nullopt,
                .capability = std::nullopt,
                .state = std::move(request),
                .response_schema = SchemaId {*schema},
                .cache_key = key,
                .emitted = false,
            };
            return std::nullopt;
        }

        [[nodiscard]] std::optional<VmError> write_state(const Instruction &instruction, Frame &frame) {
            if (forced_cleanup_active || (phase != ExecutorPhase::normal && phase != ExecutorPhase::recovery_retry)) {
                return VmError {.code = VmErrorCode::state_budget_exhausted,
                                .message = "state mutation is forbidden in recovery executors",
                                .span = instruction.span};
            }
            if (instruction.immediate >= pack.constants.size() || !register_valid(frame, instruction.operand_a)) {
                return VmError {.code = VmErrorCode::invalid_bytecode,
                                .message = "write_state operand is invalid",
                                .span = instruction.span};
            }
            const auto namespace_name =
                record_text_field(pack.constants[instruction.immediate], state_operand_schema, 1U);
            const auto name = record_text_field(pack.constants[instruction.immediate], state_operand_schema, 2U);
            const auto schema = record_text_field(pack.constants[instruction.immediate], state_operand_schema, 3U);
            if (!namespace_name.has_value() || !name.has_value() || !schema.has_value() || namespace_name->empty() ||
                name->empty() || schema->empty()) {
                return VmError {.code = VmErrorCode::invalid_bytecode,
                                .message = "write_state constant is not a valid state operand",
                                .span = instruction.span};
            }
            const auto key = *namespace_name + "\x1f" + *name + "\x1f" + *schema;
            if (const auto fault = charge_state_key(key, instruction.span); fault.has_value()) {
                return fault;
            }
            const auto remaining = invocation.budget.normal.state_bytes - counters.state_bytes;
            auto frozen =
                heap.freeze(frame.registers[instruction.operand_a], {}, FreezeLimits {.maximum_bytes = remaining});
            if (!frozen) {
                return VmError {.code = VmErrorCode::state_budget_exhausted,
                                .message = "state value failed boundary freezing: " + frozen.error().message,
                                .span = instruction.span};
            }
            if (auto valid = ValueHeap::validate_schema(frozen->value, SchemaId {*schema}, &pack.schemas); !valid) {
                return VmError {.code = VmErrorCode::state_budget_exhausted,
                                .message = "state value failed schema validation: " + valid.error().message,
                                .span = instruction.span};
            }
            const auto bytes = fact_size(frozen->value);
            if (bytes == std::numeric_limits<std::size_t>::max() || bytes > remaining) {
                return VmError {.code = VmErrorCode::state_budget_exhausted,
                                .message = "balanced.v1 state data budget exhausted",
                                .span = instruction.span};
            }
            counters.state_bytes += bytes;
            const auto prior = state_values.find(key);
            const auto overlay = state_overlay.find(key);
            const auto version = overlay != state_overlay.end() ? overlay->second.version :
                                 prior != state_values.end()    ? prior->second.version :
                                                                  0U;
            StateMutation mutation {
                .owner = function(frame).id,
                .namespace_name = *namespace_name,
                .key = *name,
                .expected_version = version,
                .value = *frozen,
            };
            const auto existing = std::ranges::find_if(state_mutations, [&](const auto &candidate) {
                return candidate.owner == mutation.owner && candidate.namespace_name == mutation.namespace_name &&
                       candidate.key == mutation.key;
            });
            if (existing == state_mutations.end()) {
                state_mutations.push_back(std::move(mutation));
            } else {
                *existing = std::move(mutation);
            }
            state_overlay.insert_or_assign(key,
                                           StateEntry {.value = *frozen, .version = version, .error = std::nullopt});
            ++frame.pc;
            return std::nullopt;
        }

        [[nodiscard]] std::optional<VmError> delete_state(const Instruction &instruction, Frame &frame) {
            if (forced_cleanup_active || (phase != ExecutorPhase::normal && phase != ExecutorPhase::recovery_retry)) {
                return VmError {.code = VmErrorCode::state_budget_exhausted,
                                .message = "state mutation is forbidden in recovery executors",
                                .span = instruction.span};
            }
            if (instruction.immediate >= pack.constants.size()) {
                return VmError {.code = VmErrorCode::invalid_bytecode,
                                .message = "delete_state constant index is out of range",
                                .span = instruction.span};
            }
            const auto namespace_name =
                record_text_field(pack.constants[instruction.immediate], state_operand_schema, 1U);
            const auto name = record_text_field(pack.constants[instruction.immediate], state_operand_schema, 2U);
            const auto schema = record_text_field(pack.constants[instruction.immediate], state_operand_schema, 3U);
            if (!namespace_name.has_value() || !name.has_value() || !schema.has_value() || namespace_name->empty() ||
                name->empty() || schema->empty()) {
                return VmError {.code = VmErrorCode::invalid_bytecode,
                                .message = "delete_state constant is not a valid state operand",
                                .span = instruction.span};
            }
            const auto key = *namespace_name + "\x1f" + *name + "\x1f" + *schema;
            if (const auto fault = charge_state_key(key, instruction.span); fault.has_value()) {
                return fault;
            }
            const auto prior = state_values.find(key);
            const auto overlay = state_overlay.find(key);
            const auto version = overlay != state_overlay.end() ? overlay->second.version :
                                 prior != state_values.end()    ? prior->second.version :
                                                                  0U;
            StateMutation mutation {
                .owner = function(frame).id,
                .namespace_name = *namespace_name,
                .key = *name,
                .expected_version = version,
                .value = std::nullopt,
            };
            const auto existing = std::ranges::find_if(state_mutations, [&](const auto &candidate) {
                return candidate.owner == mutation.owner && candidate.namespace_name == mutation.namespace_name &&
                       candidate.key == mutation.key;
            });
            if (existing == state_mutations.end()) {
                state_mutations.push_back(std::move(mutation));
            } else {
                *existing = std::move(mutation);
            }
            state_overlay.insert_or_assign(
                key, StateEntry {.value = std::nullopt, .version = version, .error = std::nullopt});
            ++frame.pc;
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
            const auto *recovery_limit = recovery_budget();
            const auto intent_limit =
                recovery_limit == nullptr ? invocation.budget.normal.effect_intents : recovery_limit->effect_intents;
            auto &phase_counter = current_counters();
            if (phase_counter.effect_intents == intent_limit) {
                return VmError {.code = VmErrorCode::effect_budget_exhausted,
                                .message = "balanced.v1 effect intent budget exhausted",
                                .span = instruction.span};
            }
            const auto remaining = invocation.budget.normal.effect_bytes - phase_counter.effect_bytes;
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
            ++phase_counter.effect_intents;
            phase_counter.effect_bytes += bytes;
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
            const auto operation = static_cast<BinaryOperation>(instruction.immediate);
            if (operation == BinaryOperation::multiply || operation == BinaryOperation::floor_divide ||
                operation == BinaryOperation::modulo) {
                if (right_digits != 0U && left_digits > std::numeric_limits<std::uint64_t>::max() / right_digits) {
                    return std::nullopt;
                }
                return std::max<std::uint64_t>(1U, left_digits * right_digits);
            }
            if (operation == BinaryOperation::power || operation == BinaryOperation::left_shift ||
                operation == BinaryOperation::right_shift) {
                if (right->starts_with('-')) {
                    return operation == BinaryOperation::power ? std::optional<std::uint64_t> {left_digits} :
                                                                 std::nullopt;
                }
                std::uint64_t count {};
                const auto [end, error] = std::from_chars(right->data(), right->data() + right->size(), count);
                if (error != std::errc {} || end != right->data() + right->size() || count > 1'000'000U ||
                    (count != 0U && left_digits > std::numeric_limits<std::uint64_t>::max() / count)) {
                    return std::nullopt;
                }
                return std::max<std::uint64_t>(1U, left_digits * std::max<std::uint64_t>(1U, count));
            }
            return std::max<std::uint64_t>(1U, std::max(left_digits, right_digits));
        }

        [[nodiscard]] static PythonFaultKind python_fault_kind(const VmErrorCode code) noexcept {
            if (code == VmErrorCode::type_error) {
                return PythonFaultKind::type_error;
            }
            if (code == VmErrorCode::arithmetic_error) {
                return PythonFaultKind::arithmetic_error;
            }
            return PythonFaultKind::value_error;
        }

        [[nodiscard]] static VmErrorCode vm_error_code(const PythonFaultKind kind) noexcept {
            switch (kind) {
                case PythonFaultKind::value_error: return VmErrorCode::value_error;
                case PythonFaultKind::type_error: return VmErrorCode::type_error;
                case PythonFaultKind::arithmetic_error: return VmErrorCode::arithmetic_error;
                case PythonFaultKind::exception: return VmErrorCode::value_error;
                default: return VmErrorCode::engine_fault;
            }
        }

        [[nodiscard]] static bool exception_matches(const PythonFaultKind filter,
                                                    const PythonFaultKind raised) noexcept {
            return filter == PythonFaultKind::exception || filter == raised;
        }

        [[nodiscard]] static bool contains_instruction(const ExceptionRegion &region,
                                                       const std::uint32_t instruction) noexcept {
            return instruction >= region.begin_instruction && instruction < region.end_instruction;
        }

        static void discard_pending_exception(Frame &frame) {
            if (frame.unwind.has_value() && frame.unwind->kind == UnwindKind::exception &&
                !frame.exception_stack.empty()) {
                frame.exception_stack.pop_back();
            }
        }

        [[nodiscard]] std::optional<std::size_t>
        next_cleanup(const Frame &frame, const std::uint32_t origin,
                     const std::optional<std::uint32_t> target = std::nullopt) const {
            const auto &regions = function(frame).exception_regions;
            std::optional<std::size_t> selected;
            for (std::size_t index = 0U; index < regions.size(); ++index) {
                const auto &region = regions[index];
                if (region.kind != ExceptionRegionKind::cleanup || !contains_instruction(region, origin) ||
                    frame.completed_cleanups.contains(index) ||
                    (target.has_value() && contains_instruction(region, *target))) {
                    continue;
                }
                if (!selected.has_value() ||
                    region.end_instruction - region.begin_instruction <
                        regions[*selected].end_instruction - regions[*selected].begin_instruction) {
                    selected = index;
                }
            }
            return selected;
        }

        [[nodiscard]] std::optional<std::size_t> next_exception_region(const Frame &frame,
                                                                       const std::uint32_t origin) const {
            const auto &regions = function(frame).exception_regions;
            std::optional<std::size_t> selected;
            for (std::size_t index = 0U; index < regions.size(); ++index) {
                const auto &region = regions[index];
                if (!contains_instruction(region, origin) ||
                    (region.kind == ExceptionRegionKind::cleanup && frame.completed_cleanups.contains(index))) {
                    continue;
                }
                if (!selected.has_value() ||
                    region.end_instruction - region.begin_instruction <
                        regions[*selected].end_instruction - regions[*selected].begin_instruction) {
                    selected = index;
                }
            }
            return selected;
        }

        [[nodiscard]] bool handle_author_fault(std::uint32_t fault_instruction, ActiveException exception) {
            while (!frames.empty()) {
                auto &frame = frames.back();
                const auto &regions = function(frame).exception_regions;
                if (const auto selected = next_exception_region(frame, fault_instruction); selected.has_value()) {
                    const auto &region = regions[*selected];
                    frame.exception_stack.push_back(exception);
                    if (region.kind == ExceptionRegionKind::cleanup) {
                        frame.completed_cleanups.insert(*selected);
                        frame.unwind = UnwindRecord {.kind = UnwindKind::exception,
                                                     .value = std::nullopt,
                                                     .exception = exception,
                                                     .fault = std::nullopt,
                                                     .target_instruction = region.handler_instruction,
                                                     .origin_instruction = fault_instruction};
                        frame.pc = region.cleanup_instruction;
                    } else {
                        frame.unwind.reset();
                        frame.pc = region.handler_instruction;
                    }
                    return true;
                }
                if (frames.size() == 1U) {
                    return false;
                }
                const auto child = std::move(frames.back());
                frames.pop_back();
                fault_instruction = child.caller_instruction.value_or(frames.back().pc);
            }
            return false;
        }

        void set_forced_cleanup(const bool active) {
            settle_active_measurement();
            forced_cleanup_active = active;
            if (active) {
                forced_cleanup_heap_start = heap.stats().logical_allocated_bytes;
            }
            active_measurement_phase = phase;
            active_measurement_forced = active;
        }

        [[nodiscard]] bool continue_forced_cleanup(const VmError &fault, std::uint32_t origin_instruction) {
            while (!frames.empty()) {
                auto &frame = frames.back();
                const auto &regions = function(frame).exception_regions;
                if (const auto selected = next_cleanup(frame, origin_instruction); selected.has_value()) {
                    const auto &region = regions[*selected];
                    frame.completed_cleanups.insert(*selected);
                    frame.unwind = UnwindRecord {.kind = UnwindKind::hard_fault,
                                                 .value = std::nullopt,
                                                 .exception = std::nullopt,
                                                 .fault = fault,
                                                 .target_instruction = std::nullopt,
                                                 .origin_instruction = origin_instruction};
                    frame.pc = region.cleanup_instruction;
                    if (!forced_cleanup_active) {
                        set_forced_cleanup(true);
                        phase_started = std::chrono::steady_clock::now();
                    }
                    return true;
                }
                if (frames.size() == 1U) {
                    return false;
                }
                const auto child = std::move(frames.back());
                frames.pop_back();
                origin_instruction = child.caller_instruction.value_or(frames.back().pc);
            }
            return false;
        }

        [[nodiscard]] bool begin_forced_cleanup(const VmError &fault) {
            return !frames.empty() && continue_forced_cleanup(fault, frames.back().pc);
        }

        [[nodiscard]] std::optional<VmError> check_forced_cleanup_heap(const SourceSpan &span) const {
            if (!forced_cleanup_active) {
                return std::nullopt;
            }
            const auto allocated = heap.stats().logical_allocated_bytes;
            const auto limit = invocation.budget.forced_cleanup.heap_bytes;
            if (allocated >= forced_cleanup_heap_start && allocated - forced_cleanup_heap_start <= limit) {
                return std::nullopt;
            }
            return VmError {.code = VmErrorCode::heap_budget_exhausted,
                            .message = "balanced.v1 forced-cleanup heap budget exhausted",
                            .span = span};
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
                for (std::size_t region = 0U; region < code.exception_regions.size(); ++region) {
                    if (code.exception_regions[region].begin_instruction == frame.pc) {
                        frame.completed_cleanups.erase(region);
                    }
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
                    case Opcode::build_list:
                    case Opcode::build_tuple: {
                        if (instruction.operand_a > frame.registers.size() ||
                            instruction.operand_b > frame.registers.size() - instruction.operand_a) {
                            return fail(VmError {.code = VmErrorCode::invalid_bytecode,
                                                 .message = "container build register range is invalid",
                                                 .span = instruction.span});
                        }
                        const auto values =
                            std::span {frame.registers}.subspan(instruction.operand_a, instruction.operand_b);
                        if (!std::ranges::all_of(values, [&](const auto value) { return heap.valid(value); })) {
                            return fail(VmError {.code = VmErrorCode::invalid_bytecode,
                                                 .message = "container build reads an uninitialized register",
                                                 .span = instruction.span});
                        }
                        if (const auto work_fault = charge_instructions(instruction.operand_b, instruction.span);
                            work_fault.has_value()) {
                            return fail(*work_fault);
                        }
                        auto result = instruction.opcode == Opcode::build_list ? heap.allocate_list(values) :
                                                                                 heap.allocate_tuple(values);
                        if (!result) {
                            return fail(result.error());
                        }
                        frame.registers[instruction.destination] = *result;
                        ++frame.pc;
                        break;
                    }
                    case Opcode::build_dict: {
                        if (instruction.operand_a > frame.registers.size() ||
                            instruction.operand_b > (frame.registers.size() - instruction.operand_a) / 2U) {
                            return fail(VmError {.code = VmErrorCode::invalid_bytecode,
                                                 .message = "dictionary build register range is invalid",
                                                 .span = instruction.span});
                        }
                        for (std::uint32_t pair = 0U; pair < instruction.operand_b; ++pair) {
                            const auto key_register = instruction.operand_a + pair * 2U;
                            if (!register_valid(frame, key_register) || !register_valid(frame, key_register + 1U)) {
                                return fail(VmError {.code = VmErrorCode::invalid_bytecode,
                                                     .message = "dictionary build reads an uninitialized register",
                                                     .span = instruction.span});
                            }
                        }
                        if (const auto work_fault = charge_instructions(
                                static_cast<std::uint64_t>(instruction.operand_b) * 2U, instruction.span);
                            work_fault.has_value()) {
                            return fail(*work_fault);
                        }
                        auto result = heap.allocate_map();
                        if (!result) {
                            return fail(result.error());
                        }
                        for (std::uint32_t pair = 0U; pair < instruction.operand_b; ++pair) {
                            const auto key_register = instruction.operand_a + pair * 2U;
                            const auto value_register = key_register + 1U;
                            auto inserted = heap.map_insert(*result, frame.registers[key_register],
                                                            frame.registers[value_register]);
                            if (!inserted) {
                                return fail(inserted.error());
                            }
                        }
                        frame.registers[instruction.destination] = *result;
                        ++frame.pc;
                        break;
                    }
                    case Opcode::get_iter: {
                        if (!register_valid(frame, instruction.operand_a)) {
                            return fail(VmError {.code = VmErrorCode::invalid_bytecode,
                                                 .message = "get_iter reads an uninitialized register",
                                                 .span = instruction.span});
                        }
                        auto iterator = heap.get_iterator(frame.registers[instruction.operand_a]);
                        if (!iterator) {
                            return fail(iterator.error());
                        }
                        frame.registers[instruction.destination] = *iterator;
                        ++frame.pc;
                        break;
                    }
                    case Opcode::iter_next: {
                        if (!register_valid(frame, instruction.operand_a)) {
                            return fail(VmError {.code = VmErrorCode::invalid_bytecode,
                                                 .message = "iter_next reads an uninitialized iterator register",
                                                 .span = instruction.span});
                        }
                        auto exhausted = heap.iterator_exhausted(frame.registers[instruction.operand_a]);
                        if (!exhausted) {
                            return fail(exhausted.error());
                        }
                        if (*exhausted) {
                            frame.pc = instruction.immediate;
                            break;
                        }
                        if (const auto loop_fault = charge_loop(instruction.span); loop_fault.has_value()) {
                            return fail(*loop_fault);
                        }
                        auto value = heap.iterator_next(frame.registers[instruction.operand_a]);
                        if (!value) {
                            return fail(value.error());
                        }
                        frame.registers[instruction.destination] = *value;
                        ++frame.pc;
                        break;
                    }
                    case Opcode::load_subscript: {
                        if (!register_valid(frame, instruction.operand_a) ||
                            !register_valid(frame, instruction.operand_b)) {
                            return fail(VmError {.code = VmErrorCode::invalid_bytecode,
                                                 .message = "load_subscript reads an uninitialized register",
                                                 .span = instruction.span});
                        }
                        auto value = heap.load_subscript(frame.registers[instruction.operand_a],
                                                         frame.registers[instruction.operand_b]);
                        if (!value) {
                            return fail(value.error());
                        }
                        frame.registers[instruction.destination] = *value;
                        ++frame.pc;
                        break;
                    }
                    case Opcode::store_subscript:
                        if (!register_valid(frame, instruction.destination) ||
                            !register_valid(frame, instruction.operand_a) ||
                            !register_valid(frame, instruction.operand_b)) {
                            return fail(VmError {.code = VmErrorCode::invalid_bytecode,
                                                 .message = "store_subscript reads an uninitialized register",
                                                 .span = instruction.span});
                        }
                        if (auto stored = heap.store_subscript(frame.registers[instruction.operand_a],
                                                               frame.registers[instruction.operand_b],
                                                               frame.registers[instruction.destination]);
                            !stored) {
                            return fail(stored.error());
                        }
                        ++frame.pc;
                        break;
                    case Opcode::unary_op: {
                        if (!register_valid(frame, instruction.operand_a) ||
                            !operation_in_range(instruction.immediate,
                                                static_cast<std::uint32_t>(UnaryOperation::invert))) {
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
                                                static_cast<std::uint32_t>(BinaryOperation::bit_and))) {
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
                                                static_cast<std::uint32_t>(CompareOperation::not_contains))) {
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
                        if (instruction.immediate <= frame.pc &&
                            code.instructions[instruction.immediate].opcode != Opcode::iter_next) {
                            if (const auto loop_fault = charge_loop(instruction.span); loop_fault.has_value()) {
                                return fail(*loop_fault);
                            }
                        }
                        frame.pc = instruction.immediate;
                        break;
                    case Opcode::unwind_jump: {
                        if (forced_cleanup_active) {
                            return fail(VmError {.code = VmErrorCode::loop_budget_exhausted,
                                                 .message = "hard cleanup cannot replace its controlling fault",
                                                 .span = instruction.span});
                        }
                        if (instruction.immediate >= code.instructions.size()) {
                            return fail(VmError {.code = VmErrorCode::invalid_bytecode,
                                                 .message = "unwind jump target is out of range",
                                                 .span = instruction.span});
                        }
                        if (instruction.immediate <= frame.pc) {
                            if (const auto loop_fault = charge_loop(instruction.span); loop_fault.has_value()) {
                                return fail(*loop_fault);
                            }
                        }
                        discard_pending_exception(frame);
                        frame.unwind.reset();
                        if (const auto cleanup = next_cleanup(frame, frame.pc, instruction.immediate);
                            cleanup.has_value()) {
                            frame.completed_cleanups.insert(*cleanup);
                            frame.unwind = UnwindRecord {.kind = UnwindKind::jump,
                                                         .value = std::nullopt,
                                                         .exception = std::nullopt,
                                                         .fault = std::nullopt,
                                                         .target_instruction = instruction.immediate,
                                                         .origin_instruction = frame.pc};
                            frame.pc = code.exception_regions[*cleanup].cleanup_instruction;
                            break;
                        }
                        frame.pc = instruction.immediate;
                        break;
                    }
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
                            if (instruction.immediate <= frame.pc &&
                                code.instructions[instruction.immediate].opcode != Opcode::iter_next) {
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
                        const auto caller_instruction = frame.pc;
                        ++frame.pc;
                        frames.push_back(Frame {.function_index = instruction.immediate,
                                                .pc = 0U,
                                                .registers = std::move(registers),
                                                .return_register = instruction.destination,
                                                .caller_instruction = caller_instruction,
                                                .generator_state = GeneratorState::running,
                                                .yield_destination = std::nullopt,
                                                .unwind = std::nullopt,
                                                .exception_stack = {},
                                                .completed_cleanups = {}});
                        current_counters().peak_frames =
                            std::max(current_counters().peak_frames, static_cast<std::uint32_t>(frames.size()));
                        break;
                    }
                    case Opcode::return_value: {
                        if (forced_cleanup_active && frame.unwind.has_value() &&
                            frame.unwind->kind == UnwindKind::hard_fault) {
                            return fail(VmError {.code = VmErrorCode::heap_budget_exhausted,
                                                 .message = "hard cleanup cannot replace its controlling fault",
                                                 .span = instruction.span});
                        }
                        if (!register_valid(frame, instruction.operand_a)) {
                            return fail(VmError {.code = VmErrorCode::invalid_bytecode,
                                                 .message = "return reads an uninitialized register",
                                                 .span = instruction.span});
                        }
                        const auto value = frame.registers[instruction.operand_a];
                        discard_pending_exception(frame);
                        frame.unwind.reset();
                        if (const auto cleanup = next_cleanup(frame, frame.pc); cleanup.has_value()) {
                            frame.completed_cleanups.insert(*cleanup);
                            frame.unwind = UnwindRecord {.kind = UnwindKind::return_value,
                                                         .value = value,
                                                         .exception = std::nullopt,
                                                         .fault = std::nullopt,
                                                         .target_instruction = std::nullopt,
                                                         .origin_instruction = frame.pc};
                            frame.pc = code.exception_regions[*cleanup].cleanup_instruction;
                            break;
                        }
                        const auto destination = frame.return_register;
                        frames.pop_back();
                        if (frames.empty()) {
                            return complete(value);
                        }
                        frames.back().registers[*destination] = value;
                        break;
                    }
                    case Opcode::raise_fault:
                        if (forced_cleanup_active) {
                            return fail(VmError {.code = VmErrorCode::value_error,
                                                 .message = "hard cleanup raised a secondary fault",
                                                 .span = instruction.span});
                        }
                        if (!register_valid(frame, instruction.operand_a)) {
                            return fail(VmError {.code = VmErrorCode::invalid_bytecode,
                                                 .message = "raise reads an uninitialized register",
                                                 .span = instruction.span});
                        }
                        {
                            const auto raised_value = frame.registers[instruction.operand_a];
                            const auto kind = static_cast<PythonFaultKind>(instruction.immediate);
                            const auto code_value = vm_error_code(kind);
                            discard_pending_exception(frame);
                            frame.unwind.reset();
                            if (!handle_author_fault(frame.pc, ActiveException {.kind = kind,
                                                                                .value = raised_value,
                                                                                .code = code_value,
                                                                                .span = instruction.span})) {
                                auto message = heap.unicode_utf8(raised_value);
                                return fail(VmError {.code = code_value,
                                                     .message = message.value_or("uncaught Python fault"),
                                                     .span = instruction.span});
                            }
                        }
                        break;
                    case Opcode::load_current_exception:
                        if (frame.exception_stack.empty()) {
                            return fail(VmError {.code = VmErrorCode::invalid_bytecode,
                                                 .message = "current-exception access has no active exception",
                                                 .span = instruction.span});
                        }
                        frame.registers[instruction.destination] = frame.exception_stack.back().value;
                        ++frame.pc;
                        break;
                    case Opcode::match_exception:
                        if (frame.exception_stack.empty() ||
                            instruction.immediate > std::to_underlying(PythonFaultKind::exception) ||
                            instruction.operand_a >= code.instructions.size() ||
                            instruction.operand_b >= code.instructions.size()) {
                            return fail(VmError {.code = VmErrorCode::invalid_bytecode,
                                                 .message = "exception filter state or encoding is invalid",
                                                 .span = instruction.span});
                        }
                        if (exception_matches(static_cast<PythonFaultKind>(instruction.immediate),
                                              frame.exception_stack.back().kind)) {
                            frame.registers[instruction.destination] = frame.exception_stack.back().value;
                            frame.pc = instruction.operand_a;
                        } else {
                            frame.pc = instruction.operand_b;
                        }
                        break;
                    case Opcode::reraise: {
                        if (forced_cleanup_active) {
                            return fail(VmError {.code = VmErrorCode::value_error,
                                                 .message = "hard cleanup attempted to re-raise a Python exception",
                                                 .span = instruction.span});
                        }
                        if (frame.exception_stack.empty()) {
                            return fail(VmError {.code = VmErrorCode::invalid_bytecode,
                                                 .message = "re-raise has no active exception",
                                                 .span = instruction.span});
                        }
                        auto exception = frame.exception_stack.back();
                        frame.exception_stack.pop_back();
                        frame.unwind.reset();
                        if (handle_author_fault(frame.pc, exception)) {
                            break;
                        }
                        auto message = heap.unicode_utf8(exception.value);
                        return fail(VmError {.code = exception.code,
                                             .message = message.value_or("uncaught re-raised Python fault"),
                                             .span = exception.span});
                    }
                    case Opcode::leave_except:
                        if (frame.exception_stack.empty()) {
                            return fail(VmError {.code = VmErrorCode::invalid_bytecode,
                                                 .message = "leave_except has no active handler exception",
                                                 .span = instruction.span});
                        }
                        frame.exception_stack.pop_back();
                        ++frame.pc;
                        break;
                    case Opcode::enter_try: ++frame.pc; break;
                    case Opcode::leave_try:
                        if (!frame.unwind.has_value()) {
                            ++frame.pc;
                            break;
                        } else {
                            auto unwind = std::move(*frame.unwind);
                            frame.unwind.reset();
                            if (unwind.kind == UnwindKind::exception) {
                                if (!unwind.target_instruction.has_value() || !unwind.exception.has_value()) {
                                    return fail(VmError {.code = VmErrorCode::engine_fault,
                                                         .message = "exception cleanup continuation is malformed",
                                                         .span = instruction.span});
                                }
                                frame.pc = *unwind.target_instruction;
                                break;
                            }
                            if (unwind.kind == UnwindKind::hard_fault) {
                                if (!unwind.fault.has_value()) {
                                    return fail(VmError {.code = VmErrorCode::engine_fault,
                                                         .message = "hard cleanup continuation is malformed",
                                                         .span = instruction.span});
                                }
                                if (continue_forced_cleanup(*unwind.fault, unwind.origin_instruction)) {
                                    break;
                                }
                                set_forced_cleanup(false);
                                const auto requested_state = unwind.fault->code == VmErrorCode::canceled ?
                                                                 VmStepState::canceled :
                                                                 VmStepState::faulted;
                                return fail(std::move(*unwind.fault), requested_state);
                            }
                            if (unwind.kind == UnwindKind::jump) {
                                if (!unwind.target_instruction.has_value()) {
                                    return fail(VmError {.code = VmErrorCode::engine_fault,
                                                         .message = "jump cleanup continuation is malformed",
                                                         .span = instruction.span});
                                }
                                if (const auto cleanup =
                                        next_cleanup(frame, unwind.origin_instruction, *unwind.target_instruction);
                                    cleanup.has_value()) {
                                    frame.completed_cleanups.insert(*cleanup);
                                    frame.unwind = std::move(unwind);
                                    frame.pc = code.exception_regions[*cleanup].cleanup_instruction;
                                    break;
                                }
                                frame.pc = *unwind.target_instruction;
                                break;
                            }
                            if (const auto cleanup = next_cleanup(frame, unwind.origin_instruction);
                                cleanup.has_value()) {
                                frame.completed_cleanups.insert(*cleanup);
                                frame.unwind = std::move(unwind);
                                frame.pc = code.exception_regions[*cleanup].cleanup_instruction;
                                break;
                            }
                            if (!unwind.value.has_value()) {
                                return fail(VmError {.code = VmErrorCode::engine_fault,
                                                     .message = "return cleanup continuation is malformed",
                                                     .span = instruction.span});
                            }
                            const auto destination = frame.return_register;
                            const auto value = *unwind.value;
                            frames.pop_back();
                            if (frames.empty()) {
                                return complete(value);
                            }
                            frames.back().registers[*destination] = value;
                            break;
                        }
                    case Opcode::yield_value:
                        if (forced_cleanup_active) {
                            return fail(VmError {.code = VmErrorCode::loop_budget_exhausted,
                                                 .message = "hard cleanup cannot suspend",
                                                 .span = instruction.span});
                        }
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
                        frame.yield_destination = instruction.destination;
                        return make_step(VmStepState::yielded, std::nullopt, frame.registers[instruction.operand_a]);
                    case Opcode::await_fact:
                        if (forced_cleanup_active) {
                            return fail(VmError {.code = VmErrorCode::fact_budget_exhausted,
                                                 .message = "hard cleanup cannot request facts",
                                                 .span = instruction.span});
                        }
                        if (const auto fault = begin_fact(instruction, frame); fault.has_value()) {
                            return fail(*fault);
                        }
                        if (pending.has_value()) {
                            return make_step(VmStepState::waiting_for_facts);
                        }
                        break;
                    case Opcode::await_capability:
                        if (forced_cleanup_active) {
                            return fail(VmError {.code = VmErrorCode::capability_budget_exhausted,
                                                 .message = "hard cleanup cannot request capabilities",
                                                 .span = instruction.span});
                        }
                        if (const auto fault = begin_capability(instruction, frame); fault.has_value()) {
                            return fail(*fault);
                        }
                        if (pending.has_value()) {
                            return make_step(VmStepState::waiting_for_capabilities);
                        }
                        break;
                    case Opcode::read_state:
                        if (forced_cleanup_active) {
                            return fail(VmError {.code = VmErrorCode::state_budget_exhausted,
                                                 .message = "hard cleanup cannot read state",
                                                 .span = instruction.span});
                        }
                        if (const auto fault = begin_state_read(instruction, frame); fault.has_value()) {
                            return fail(*fault);
                        }
                        if (pending.has_value()) {
                            return make_step(VmStepState::yielded);
                        }
                        break;
                    case Opcode::write_state:
                        if (const auto fault = write_state(instruction, frame); fault.has_value()) {
                            return fail(*fault);
                        }
                        break;
                    case Opcode::delete_state:
                        if (const auto fault = delete_state(instruction, frame); fault.has_value()) {
                            return fail(*fault);
                        }
                        break;
                    case Opcode::append_effect:
                        if (const auto fault = append_effect(instruction, frame); fault.has_value()) {
                            return fail(*fault);
                        }
                        break;
                    case Opcode::begin_transaction:
                        transaction_marks.push_back(TransactionMark {
                            .journal_size = journal.size(),
                            .state_mutations = state_mutations,
                            .state_overlay = state_overlay,
                        });
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
                        rollback_journal_from(transaction_marks.back().journal_size);
                        state_mutations = std::move(transaction_marks.back().state_mutations);
                        state_overlay = std::move(transaction_marks.back().state_overlay);
                        transaction_marks.pop_back();
                        ++frame.pc;
                        break;
                    default:
                        return fail(VmError {.code = VmErrorCode::invalid_bytecode,
                                             .message = "instruction opcode is invalid",
                                             .span = instruction.span});
                }

                if (const auto heap_fault = check_forced_cleanup_heap(instruction.span); heap_fault.has_value()) {
                    return fail(*heap_fault);
                }

                if (quantum == cooperative_quantum) {
                    if ((current_counters().instructions % cooperative_quantum) == 0U) {
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
                const auto state = pending->kind == PendingKind::fact       ? VmStepState::waiting_for_facts :
                                   pending->kind == PendingKind::capability ? VmStepState::waiting_for_capabilities :
                                                                              VmStepState::yielded;
                return make_step(state);
            }
            if (!frames.empty() && frames.back().generator_state == GeneratorState::suspended) {
                return resume_generator(std::nullopt);
            }
            return execute();
        }

        [[nodiscard]] VmStep resume_generator(const std::optional<PyValue> value) {
            if (terminal_state.has_value()) {
                return make_step(*terminal_state, terminal_result);
            }
            if (pending.has_value() || frames.empty() || frames.back().generator_state != GeneratorState::suspended ||
                !frames.back().yield_destination.has_value()) {
                return fail(VmError {.code = VmErrorCode::value_error,
                                     .message = "generator is not suspended at a yield point",
                                     .span = std::nullopt});
            }
            auto sent = value.has_value() ? std::expected<PyValue, VmError> {*value} : heap.allocate_none();
            if (!sent || !heap.valid(*sent)) {
                return fail(!sent ? sent.error() :
                                    VmError {.code = VmErrorCode::invalid_handle,
                                             .message = "generator send value does not belong to this VM session",
                                             .span = std::nullopt});
            }
            auto &frame = frames.back();
            if (*frame.yield_destination >= frame.registers.size()) {
                return fail(VmError {.code = VmErrorCode::invalid_bytecode,
                                     .message = "generator yield destination is out of range",
                                     .span = std::nullopt});
            }
            frame.registers[*frame.yield_destination] = *sent;
            frame.yield_destination.reset();
            frame.generator_state = GeneratorState::running;
            return execute();
        }

        [[nodiscard]] VmStep throw_generator(const PyValue exception) {
            if (terminal_state.has_value()) {
                return make_step(*terminal_state, terminal_result);
            }
            if (!heap.valid(exception) || frames.empty() ||
                frames.back().generator_state != GeneratorState::suspended) {
                return fail(VmError {.code = VmErrorCode::value_error,
                                     .message = "generator throw requires a suspended generator and local value",
                                     .span = std::nullopt});
            }
            auto &frame = frames.back();
            frame.generator_state = GeneratorState::running;
            frame.yield_destination.reset();
            if (frame.pc != 0U) {
                --frame.pc;
            }
            const auto instruction = function(frame).instructions[frame.pc];
            discard_pending_exception(frame);
            frame.unwind.reset();
            if (handle_author_fault(frame.pc, ActiveException {.kind = PythonFaultKind::value_error,
                                                               .value = exception,
                                                               .code = VmErrorCode::value_error,
                                                               .span = instruction.span})) {
                return execute();
            }
            return fail(VmError {.code = VmErrorCode::value_error,
                                 .message = "exception thrown into generator was not handled",
                                 .span = instruction.span});
        }

        [[nodiscard]] VmStep close_generator() {
            if (terminal_state.has_value()) {
                return make_step(*terminal_state, terminal_result);
            }
            if (frames.empty() || frames.back().generator_state != GeneratorState::suspended) {
                return fail(VmError {.code = VmErrorCode::value_error,
                                     .message = "generator close requires a suspended generator",
                                     .span = std::nullopt});
            }
            auto &frame = frames.back();
            frame.generator_state = GeneratorState::closed;
            frame.yield_destination.reset();
            if (frame.pc != 0U) {
                --frame.pc;
            }
            static_cast<void>(tasks.close_all());
            return fail(VmError {.code = VmErrorCode::canceled,
                                 .message = "generator was closed",
                                 .span = function(frame).instructions[frame.pc].span},
                        VmStepState::canceled);
        }
    };

    RegisterVmSession::RegisterVmSession(Impl *const implementation) noexcept: impl_ {implementation} {}

    RegisterVmSession::~RegisterVmSession() { delete impl_; }

    VmStep RegisterVmSession::step(HostResponses responses) {
        impl_->begin_active_measurement();
        auto result = impl_->step(std::move(responses));
        impl_->end_active_measurement();
        return result;
    }

    VmStep RegisterVmSession::send_generator(const std::optional<PyValue> value) {
        impl_->begin_active_measurement();
        auto result = impl_->resume_generator(value);
        impl_->end_active_measurement();
        return result;
    }

    VmStep RegisterVmSession::throw_generator(const PyValue exception) {
        impl_->begin_active_measurement();
        auto result = impl_->throw_generator(exception);
        impl_->end_active_measurement();
        return result;
    }

    VmStep RegisterVmSession::close_generator() {
        impl_->begin_active_measurement();
        auto result = impl_->close_generator();
        impl_->end_active_measurement();
        return result;
    }

    VmCounters RegisterVmSession::counters() const noexcept { return impl_->counters; }

    RecoveryCounters RegisterVmSession::recovery_counters() const noexcept { return impl_->recovery; }

    HeapStats RegisterVmSession::heap_stats() const noexcept { return impl_->heap.stats(); }

    std::size_t RegisterVmSession::logical_read_count() const noexcept { return impl_->logical_reads.size(); }

    std::size_t RegisterVmSession::journal_size() const noexcept { return impl_->journal.size(); }

    std::size_t RegisterVmSession::state_mutation_count() const noexcept { return impl_->state_mutations.size(); }

    std::expected<FrozenValue, FreezeError> RegisterVmSession::freeze_value(const PyValue value) const {
        return impl_->heap.freeze(value);
    }

    std::expected<std::unique_ptr<RegisterVmSession>, DiagnosticSet>
    RegisterVmSession::create(const CompiledPack &pack, const VmInvocation &invocation) {
        if (auto verified = verify_bytecode(pack); !verified) {
            return std::unexpected(std::move(verified.error()));
        }
        DiagnosticSet diagnostics;
        for (const auto &function : pack.functions) {
            for (const auto &instruction : function.instructions) {
                if (instruction.opcode == Opcode::delete_state &&
                    !valid_state_operand(pack.constants[instruction.immediate])) {
                    diagnostics.push_back(diagnostic(
                        "PYVM0010", "delete_state constant is not a canonical state operand", instruction.span));
                }
            }
        }
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
                if (function->parameter_count > 1U) {
                    diagnostics.push_back(diagnostic("PYVM0004", "bound entrypoint exceeds the subject-parameter ABI"));
                }
            }
        }
        if (invocation.budget.name.empty()) {
            diagnostics.push_back(diagnostic("PYVM0005", "VM budget profile name is empty"));
        }
        if (!diagnostics.empty()) {
            return std::unexpected(std::move(diagnostics));
        }

        if (invocation.budget.normal.frames == 0U) {
            diagnostics.push_back(diagnostic("PYVM0007", "frame budget cannot admit the entrypoint"));
            return std::unexpected(std::move(diagnostics));
        }

        auto implementation = std::unique_ptr<Impl> {new Impl {pack, invocation}};
        implementation->entry_index = entry_index;
        const auto find_function = [&](const std::string &id) -> std::optional<std::size_t> {
            const auto found = std::ranges::find(pack.functions, ExecutableId {id}, &BytecodeFunction::id);
            if (found == pack.functions.end()) {
                return std::nullopt;
            }
            return static_cast<std::size_t>(std::distance(pack.functions.begin(), found));
        };
        for (const auto &constant : pack.constants) {
            const auto *record = constant.valid() ? std::get_if<FactRecord>(&constant.node->data) : nullptr;
            if (record == nullptr || record->schema.value != handler_metadata_schema) {
                continue;
            }
            const auto metadata_entry = record_text_field(constant, handler_metadata_schema, 1U);
            if (!metadata_entry.has_value() || binding == pack.bindings.end() ||
                *metadata_entry != binding->executable.value) {
                continue;
            }
            const auto bind_handler = [&](const std::uint32_t field, std::optional<std::size_t> &destination) {
                const auto id = record_text_field(constant, handler_metadata_schema, field);
                if (!id.has_value()) {
                    return;
                }
                const auto index = find_function(*id);
                if (!index.has_value() || pack.functions[*index].parameter_count != 0U) {
                    diagnostics.push_back(diagnostic("PYVM0009", "handler metadata references an invalid function"));
                    return;
                }
                destination = *index;
            };
            bind_handler(2U, implementation->handlers.finalizer);
            bind_handler(3U, implementation->handlers.on_fault);
            bind_handler(4U, implementation->handlers.on_double_fault);
        }
        if (!diagnostics.empty()) {
            return std::unexpected(std::move(diagnostics));
        }
        if (const auto started = implementation->start_executor(entry_index, Impl::ExecutorPhase::normal,
                                                                invocation.budget.normal.heap_bytes);
            started.has_value()) {
            diagnostics.push_back(diagnostic("PYVM0006", started->message));
            return std::unexpected(std::move(diagnostics));
        }
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
