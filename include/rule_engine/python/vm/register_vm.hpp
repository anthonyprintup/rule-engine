#pragma once

#include "rule_engine/python/contract.hpp"
#include "rule_engine/python/vm/value.hpp"

#include <chrono>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace rule_engine::python::vm {

    inline constexpr std::string_view fact_operand_schema = "rule-engine.vm.fact-operand.v1";
    inline constexpr std::string_view capability_operand_schema = "rule-engine.vm.capability-operand.v1";
    inline constexpr std::string_view state_operand_schema = "rule-engine.vm.state-operand.v1";
    inline constexpr std::string_view handler_metadata_schema = "rule-engine.vm.handler-metadata.v1";

    // Instruction operand encoding used by the C++ compiler and the exact VM.
    // - load_const: immediate is the constant index.
    // - build_list/build_tuple: destination receives a new container built from operand_b
    //   consecutive registers beginning at operand_a; immediate is zero.
    // - build_dict: destination receives a new insertion-ordered dictionary built from operand_b
    //   key/value pairs in consecutive registers beginning at operand_a; immediate is zero.
    // - get_iter: destination receives an iterator over operand_a; operand_b and immediate are zero.
    // - iter_next: operand_a is an iterator. A produced item is stored in destination and execution
    //   continues at the successor; exhaustion branches to the absolute instruction index in immediate.
    //   operand_b is zero, and each produced item charges one loop iteration before advancing; a backward
    //   jump targeting iter_next does not charge the same iteration again.
    // - load_subscript: destination receives operand_a[operand_b]; immediate is zero.
    // - store_subscript: operand_a[operand_b] is assigned from destination; immediate is zero.
    // - unary/binary/compare: immediate is the corresponding operation enum.
    // - call: immediate is the function index, operand_a is the first argument register,
    //   and operand_b is the argument count.
    // - return/yield/raise: operand_a is the value register.
    //   raise immediate is a concrete PythonFaultKind (zero is value_error).
    // - load_current_exception: destination receives the active exception value; all other operands are zero.
    // - match_exception: an exception-filter node. immediate is PythonFaultKind, destination receives the
    //   exception value on a match, operand_a is the matching handler target, and operand_b is the next
    //   filter node (or reraise terminator). Filters are evaluated in linked order.
    // - reraise: propagate the frame's active exception; all operands are zero.
    // - leave_except: pop the active handler exception and restore any enclosing handler exception;
    //   all operands are zero. Normal handler exits must execute it before joining non-handler control flow.
    // - unwind_jump: immediate is an absolute normal/break/continue target. The VM runs every cleanup region
    //   exited by that edge, from inner to outer, before reaching the target; all register operands are zero.
    // - await_fact: immediate names a fact operand constant; the invocation subject is used.
    // - await_capability: immediate names a capability operand constant and operand_a is the argument register.
    // - read_state: immediate names a state operand constant.
    // - write_state: immediate names a state operand constant and operand_a is the value register.
    // - delete_state: immediate names a state operand constant; all register operands are zero.
    // - append_effect: immediate names a Unicode effect-kind constant and operand_a is the payload register.
    // - emit_event: immediate names a canonical event operand record containing the event schema ID and exact
    //   descriptor hash; operand_a is the record payload register. destination and operand_b are zero. Execution
    //   appends a typed frozen intent to the VM-owned journal; it never dispatches or writes a durable event.
    // ExceptionRegionKind::handler routes faults to handler_instruction (a catch-all body, reraise, or the
    // first match_exception filter) and requires cleanup_instruction == handler_instruction.
    // ExceptionRegionKind::cleanup routes every exit through cleanup_instruction and resumes Python exceptions
    // at a reraise handler_instruction. Cleanup code terminates with leave_try. Protected regions must be
    // disjoint or properly nested; ordinary control-flow edges may not jump out of a cleanup region.
    [[nodiscard]] FactValue make_fact_operand(FactRoute route, SchemaId expected_schema);
    [[nodiscard]] FactValue make_capability_operand(CapabilityId capability, SchemaId request_schema,
                                                    SchemaId response_schema = {});
    [[nodiscard]] FactValue make_state_operand(std::string namespace_name, std::string key, SchemaId schema);
    [[nodiscard]] FactValue make_event_operand(SchemaId schema, std::string schema_hash);
    [[nodiscard]] FactValue make_handler_metadata(ExecutableId entrypoint, std::optional<ExecutableId> finalizer,
                                                  std::optional<ExecutableId> on_fault,
                                                  std::optional<ExecutableId> on_double_fault);

    struct VmCounters {
        std::uint64_t instructions {};
        std::uint32_t peak_frames {};
        std::uint64_t loop_iterations_and_yields {};
        std::uint32_t logical_facts {};
        std::uint32_t provider_rounds {};
        std::size_t fact_bytes {};
        std::uint32_t service_calls {};
        std::uint32_t peak_active_service_calls {};
        std::size_t service_response_bytes {};
        std::uint32_t history_queries {};
        std::uint32_t history_rows {};
        std::size_t history_bytes {};
        std::uint32_t state_keys {};
        std::size_t state_bytes {};
        std::uint32_t effect_intents {};
        std::size_t effect_bytes {};
        std::uint32_t recorder_events {};
        std::size_t recorder_bytes {};
        std::uint32_t event_intents {};
        std::size_t event_bytes {};
        std::chrono::nanoseconds active_time {};
    };

    struct RecoveryCounters {
        VmCounters finalizer_or_fault;
        VmCounters double_fault;
        VmCounters forced_cleanup;
        std::uint32_t primary_faults {};
        std::uint32_t double_faults {};
        std::uint32_t triple_faults {};
    };

    enum struct GeneratorState : std::uint8_t { created, running, suspended, closed, faulted };
    enum struct TaskState : std::uint8_t { cold, ready, running, waiting, complete, canceled, faulted };
    enum struct TaskGroupExitMode : std::uint8_t { cancel_pending, wait_pending };

    using TaskId = std::uint64_t;
    using TaskGroupId = std::uint64_t;

    struct StructuredTask {
        TaskId id {};
        TaskGroupId owner {};
        TaskState state {TaskState::cold};
        std::optional<PyValue> coroutine;
    };

    struct StructuredTaskGroup {
        TaskGroupId id {};
        std::optional<TaskGroupId> parent;
        bool open {true};
    };

    struct StructuredTasks {
        [[nodiscard]] TaskGroupId open_group(std::optional<TaskGroupId> parent = std::nullopt);
        [[nodiscard]] std::expected<TaskId, VmError> start(TaskGroupId owner,
                                                           std::optional<PyValue> coroutine = std::nullopt);
        [[nodiscard]] std::expected<void, VmError> set_state(TaskId task, TaskState state);
        [[nodiscard]] std::optional<TaskId> next_ready() const noexcept;
        [[nodiscard]] std::expected<void, VmError> close(TaskGroupId group, TaskGroupExitMode mode);
        [[nodiscard]] std::expected<void, VmError> cancel_group(TaskGroupId group);
        [[nodiscard]] std::expected<void, VmError> close_all();
        [[nodiscard]] bool owns(TaskGroupId group, TaskId task) const noexcept;
        [[nodiscard]] bool has_live_tasks(TaskGroupId group) const noexcept;
        [[nodiscard]] bool group_open(TaskGroupId group) const noexcept;
        [[nodiscard]] std::span<const StructuredTask> tasks() const noexcept;

    private:
        std::uint64_t next_group_id_ {1U};
        std::uint64_t next_task_id_ {1U};
        std::vector<StructuredTaskGroup> groups_;
        std::vector<StructuredTask> tasks_;
    };

    struct RegisterVmSession final: VmSession {
        RegisterVmSession(const RegisterVmSession &) = delete;
        RegisterVmSession &operator=(const RegisterVmSession &) = delete;
        ~RegisterVmSession() override;

        [[nodiscard]] VmStep step(HostResponses responses) override;
        [[nodiscard]] VmResourceUsage resource_usage() const noexcept override;
        [[nodiscard]] VmStep send_generator(std::optional<PyValue> value = std::nullopt);
        [[nodiscard]] VmStep throw_generator(PyValue exception);
        [[nodiscard]] VmStep close_generator();
        [[nodiscard]] VmCounters counters() const noexcept;
        [[nodiscard]] RecoveryCounters recovery_counters() const noexcept;
        [[nodiscard]] HeapStats heap_stats() const noexcept;
        [[nodiscard]] std::size_t logical_read_count() const noexcept;
        [[nodiscard]] std::size_t journal_size() const noexcept;
        [[nodiscard]] std::size_t event_journal_size() const noexcept;
        [[nodiscard]] std::size_t state_mutation_count() const noexcept;
        [[nodiscard]] std::expected<FrozenValue, FreezeError> freeze_value(PyValue value) const;

        [[nodiscard]] static std::expected<std::unique_ptr<RegisterVmSession>, DiagnosticSet>
        create(const CompiledPack &pack, const VmInvocation &invocation);

    private:
        struct Impl;
        explicit RegisterVmSession(Impl *implementation) noexcept;
        Impl *impl_ {};
    };

    struct RegisterVmFactory final: VmFactory {
        [[nodiscard]] std::expected<std::unique_ptr<VmSession>, DiagnosticSet>
        start(const CompiledPack &pack, const VmInvocation &invocation) override;
    };

    [[nodiscard]] std::unique_ptr<VmFactory> make_register_vm_factory();

} // namespace rule_engine::python::vm
