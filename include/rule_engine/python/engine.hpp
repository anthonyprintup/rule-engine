#pragma once

#include "rule_engine/python/contract.hpp"

#include <expected>
#include <memory>
#include <optional>
#include <set>
#include <string>

namespace rule_engine::python {

    enum struct EngineErrorCode : std::uint8_t {
        no_active_pack,
        invocation_rejected,
        not_terminal,
        already_committed,
        event_projection_failure,
        store_failure,
    };

    struct EngineError {
        EngineErrorCode code {};
        std::string message;
        std::optional<StoreError> store;
        std::optional<EventProjectionError> event;
    };

    struct EvaluationHandle {
        std::shared_ptr<const CompiledPack> pack;
        VmInvocation invocation;
        std::unique_ptr<VmSession> session;
        std::optional<EvaluationResult> terminal_result;
        std::set<std::string> dispatched_requests;
        bool committed {};
    };

    // Pure server-boundary projection shared by RuntimeEngine and resident
    // cluster scheduling. It validates emitted events and materializes state,
    // journal, and outbox rows without performing persistence.
    [[nodiscard]] std::expected<RuntimeTransaction, EngineError>
    project_runtime_transaction(EventEnvelope input, CursorAdvance cursor, const VmInvocation &invocation,
                                const CompiledPack &pack, const EvaluationResult &evaluation,
                                std::uint64_t fence_token);

    struct RuntimeEngine {
        RuntimeEngine(PackCompiler &compiler, VmFactory &vm_factory, IProviderDispatcher &providers,
                      IRuntimeStore &store) noexcept;

        [[nodiscard]] std::expected<void, DiagnosticSet>
        activate(const VerifiedRulePack &pack, const SchemaCatalog &schemas, const OperatorBindings &bindings);
        [[nodiscard]] std::expected<EvaluationHandle, DiagnosticSet> start(const VmInvocation &invocation);
        [[nodiscard]] VmStep advance(EvaluationHandle &evaluation, HostResponses responses);
        [[nodiscard]] std::expected<TransactionReceipt, EngineError>
        commit(EvaluationHandle &evaluation, EventEnvelope input, CursorAdvance cursor, std::uint64_t fence_token);

        [[nodiscard]] const std::shared_ptr<const CompiledPack> &active_pack() const noexcept { return active_pack_; }

    private:
        PackCompiler &compiler_;
        VmFactory &vm_factory_;
        IProviderDispatcher &providers_;
        IRuntimeStore &store_;
        std::shared_ptr<const CompiledPack> active_pack_;
    };

} // namespace rule_engine::python
