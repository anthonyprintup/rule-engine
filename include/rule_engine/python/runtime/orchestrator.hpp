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
        std::vector<EventEnvelope> emitted_events;
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
        port_failure,
        invalid_response,
        replay_input_missing,
        replay_input_mismatch,
        state_conflict_exhausted,
        stale_fence,
        commit_failure,
        cancellation_failed,
        host_turn_limit,
    };

    struct ResidentRuntimeError {
        ResidentRuntimeErrorCode code {ResidentRuntimeErrorCode::invalid_work};
        std::string message;
        std::optional<PortError> port;
        std::optional<StoreError> store;
        DiagnosticSet diagnostics;
    };

    struct ResidentEvaluationReceipt {
        std::uint32_t attempts {};
        std::uint64_t host_turns {};
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
        ResidentRuntime(RuntimeEngine &engine, HostResponsePorts ports, IWorkControlPort &control,
                        ITransactionPort &transactions, ResidentRuntimeOptions options = {}) noexcept;

        [[nodiscard]] std::expected<ResidentEvaluationReceipt, ResidentRuntimeError>
        evaluate(ResidentEvaluationRequest request);

    private:
        RuntimeEngine &engine_;
        HostResponsePorts ports_;
        IWorkControlPort &control_;
        ITransactionPort &transactions_;
        ResidentRuntimeOptions options_;
    };

} // namespace rule_engine::python::runtime
