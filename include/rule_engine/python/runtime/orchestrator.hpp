#pragma once

#include "rule_engine/python/effects/common.hpp"
#include "rule_engine/python/engine.hpp"

#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <variant>
#include <vector>

namespace rule_engine::python::runtime {

    enum struct PortErrorCode : std::uint8_t { unavailable, invalid_request, invalid_response, canceled };

    struct PortError {
        PortErrorCode code {PortErrorCode::unavailable};
        std::string message;
    };

    struct IProviderResponsePort {
        IProviderResponsePort() = default;
        IProviderResponsePort(const IProviderResponsePort &) = default;
        IProviderResponsePort(IProviderResponsePort &&) = default;
        IProviderResponsePort &operator=(const IProviderResponsePort &) = default;
        IProviderResponsePort &operator=(IProviderResponsePort &&) = default;
        virtual ~IProviderResponsePort() = default;
        [[nodiscard]] virtual std::expected<std::vector<FactResponse>, PortError>
        resolve_facts(std::span<const FactRequest> requests) noexcept = 0;
        [[nodiscard]] virtual std::expected<std::vector<ScanResponse>, PortError>
        resolve_scans(std::span<const ScanRequest> requests) noexcept = 0;
        virtual void cancel(std::span<const RequestId> requests) noexcept = 0;
    };

    struct ICapabilityResponsePort {
        virtual ~ICapabilityResponsePort() = default;
        [[nodiscard]] virtual std::expected<std::vector<CapabilityResponse>, PortError>
        resolve(std::span<const CapabilityRequest> requests) noexcept = 0;
        virtual void cancel(std::span<const RequestId> requests) noexcept = 0;
    };

    struct IStateResponsePort {
        virtual ~IStateResponsePort() = default;
        [[nodiscard]] virtual std::expected<std::vector<StateReadResponse>, PortError>
        read(std::span<const StateReadRequest> requests) noexcept = 0;
    };

    struct IHistoryResponsePort {
        virtual ~IHistoryResponsePort() = default;
        [[nodiscard]] virtual std::expected<std::vector<HistoryResponse>, PortError>
        query(std::span<const HistoryRequest> requests) noexcept = 0;
        virtual void cancel(std::span<const RequestId> requests) noexcept = 0;
    };

    struct HostResponsePorts {
        IProviderResponsePort &providers;
        ICapabilityResponsePort &capabilities;
        IStateResponsePort &state;
        IHistoryResponsePort &history;
    };

    struct ResidentWorkIdentity {
        std::string work_id;
        std::string node_id;
        std::string serial_domain;
        PackId pack;
        // CompiledPack does not currently carry the activation generation.
        // The resident checks the pack ID; the cluster transaction/work-control
        // adapters must authoritatively fence this generation.
        std::uint64_t generation {};
        std::uint64_t attempt {};
        std::uint64_t fence {};
        std::uint64_t lease_until_unix_ms {};
    };

    enum struct WorkControlState : std::uint8_t { current, canceled, stale };

    struct IWorkControlPort {
        virtual ~IWorkControlPort() = default;
        [[nodiscard]] virtual std::expected<WorkControlState, PortError>
        observe(const ResidentWorkIdentity &work) noexcept = 0;
    };

    struct ITransactionPort {
        virtual ~ITransactionPort() = default;
        [[nodiscard]] virtual std::expected<TransactionReceipt, StoreError>
        commit(const ResidentWorkIdentity &work, const RuntimeTransaction &transaction) noexcept = 0;
    };

    struct ResidentVmDriverError {
        std::string message;
    };

    // The resident orchestrator deliberately depends on a VM-only step surface.
    // RuntimeEngine::advance also dispatches provider work and therefore must not
    // be reachable from diagnostic replay or sealed MVCC retries.
    struct IResidentVmDriver {
        virtual ~IResidentVmDriver() = default;
        [[nodiscard]] virtual std::expected<EvaluationHandle, DiagnosticSet> start(const VmInvocation &invocation) = 0;
        [[nodiscard]] virtual std::expected<VmStep, ResidentVmDriverError> step(EvaluationHandle &evaluation,
                                                                                HostResponses responses) = 0;
        [[nodiscard]] virtual std::expected<VmResourceUsage, ResidentVmDriverError>
        resource_usage(const EvaluationHandle &evaluation) const noexcept = 0;
    };

    struct DispatchFreeRuntimeEngineDriver final: IResidentVmDriver {
        explicit DispatchFreeRuntimeEngineDriver(RuntimeEngine &engine) noexcept: engine_ {engine} {}

        [[nodiscard]] std::expected<EvaluationHandle, DiagnosticSet> start(const VmInvocation &invocation) override;
        [[nodiscard]] std::expected<VmStep, ResidentVmDriverError> step(EvaluationHandle &evaluation,
                                                                        HostResponses responses) override;
        [[nodiscard]] std::expected<VmResourceUsage, ResidentVmDriverError>
        resource_usage(const EvaluationHandle &evaluation) const noexcept override;

    private:
        RuntimeEngine &engine_;
    };

    // Minimal adapter for stores that enforce the serial-domain fence inside
    // transact_event. A cluster coordinator can implement ITransactionPort
    // directly when it must also validate work-attempt and generation identity.
    struct RuntimeStoreTransactionPort final: ITransactionPort {
        explicit RuntimeStoreTransactionPort(IRuntimeStore &store): store_ {store} {}

        [[nodiscard]] std::expected<TransactionReceipt, StoreError>
        commit(const ResidentWorkIdentity &work, const RuntimeTransaction &transaction) noexcept override;

    private:
        IRuntimeStore &store_;
    };

    enum struct CapturedHostInputKind : std::uint8_t { fact, scan, capability, state, history };

    using CapturedHostResponse =
        std::variant<FactResponse, ScanResponse, CapabilityResponse, StateReadResponse, HistoryResponse>;

    struct CapturedHostInput {
        std::string key;
        CapturedHostInputKind kind {CapturedHostInputKind::fact};
        CapturedHostResponse response;
    };

    struct ResidentEvaluationRequest {
        ResidentWorkIdentity work;
        VmInvocation invocation;
        EventEnvelope input;
        CursorAdvance cursor;
        effects::ExecutionMode mode {effects::ExecutionMode::live};
        std::vector<CapturedHostInput> replay_inputs;
        // State is refreshed on each live MVCC attempt. Diagnostic replay names
        // the captured attempt whose state snapshot should be restored.
        std::uint32_t replay_state_attempt {1};
    };

    enum struct ResidentRuntimeErrorCode : std::uint8_t {
        invalid_work,
        start_failed,
        invalid_vm_step,
        event_projection_failure,
        port_failure,
        invalid_response,
        replay_input_missing,
        replay_input_mismatch,
        state_conflict_exhausted,
        stale_fence,
        commit_failure,
        cancellation_failed,
        host_turn_limit,
        invalid_resource_usage,
    };

    struct ResidentRuntimeError {
        ResidentRuntimeErrorCode code {ResidentRuntimeErrorCode::invalid_work};
        std::string message;
        std::optional<PortError> port;
        std::optional<StoreError> store;
        DiagnosticSet diagnostics;
    };

    // Shared retry primitives used by both the synchronous resident runtime and
    // the asynchronous agent-backed resident scheduler. External inputs are
    // replayed by their canonical request identity; state is deliberately not.
    inline constexpr std::uint32_t maximum_mvcc_attempts = 3U;
    [[nodiscard]] std::string captured_fact_input_key(const FactRequest &request);
    [[nodiscard]] std::string captured_scan_input_key(const ScanRequest &request);
    [[nodiscard]] std::expected<void, ResidentRuntimeError>
    accumulate_vm_retry_usage(VmResourceUsage &total, std::chrono::nanoseconds &reported_elapsed,
                              const VmResourceUsage &attempt, const BudgetProfile &attempt_budget);
    [[nodiscard]] BudgetProfile remaining_vm_retry_budget(const BudgetProfile &original,
                                                          const VmResourceUsage &usage) noexcept;

    struct ResidentEvaluationReceipt {
        std::uint32_t attempts {};
        std::uint64_t host_turns {};
        VmResourceUsage resource_usage;
        effects::ExecutionMode mode {effects::ExecutionMode::live};
        EvaluationResult evaluation;
        std::optional<RuntimeTransaction> candidate;
        std::optional<TransactionReceipt> transaction;
        std::vector<CapturedHostInput> captured_inputs;

        [[nodiscard]] bool committed() const noexcept { return transaction.has_value(); }
    };

    struct ResidentRuntimeOptions {
        // This is an orchestration guard, not a replacement for balanced.v1 VM
        // instruction accounting.
        std::uint64_t maximum_host_turns {1'000'000};
    };

    struct ResidentRuntime {
        ResidentRuntime(IResidentVmDriver &vm, HostResponsePorts ports, IWorkControlPort &control,
                        ITransactionPort &transactions, ResidentRuntimeOptions options = {}) noexcept;

        [[nodiscard]] std::expected<ResidentEvaluationReceipt, ResidentRuntimeError>
        evaluate(ResidentEvaluationRequest request);

    private:
        IResidentVmDriver &vm_;
        HostResponsePorts ports_;
        IWorkControlPort &control_;
        ITransactionPort &transactions_;
        ResidentRuntimeOptions options_;
    };

} // namespace rule_engine::python::runtime
