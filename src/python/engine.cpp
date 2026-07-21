#include "rule_engine/python/engine.hpp"

#include <utility>

namespace rule_engine::python {
    namespace {

        Diagnostic engine_diagnostic(std::string code, std::string message) {
            return Diagnostic {.code = std::move(code),
                               .severity = DiagnosticSeverity::error,
                               .message = std::move(message),
                               .span = std::nullopt,
                               .related = {}};
        }

        bool is_terminal(const VmStepState state) noexcept {
            return state == VmStepState::complete || state == VmStepState::faulted ||
                   state == VmStepState::quarantined || state == VmStepState::canceled;
        }

    } // namespace

    RuntimeEngine::RuntimeEngine(PackCompiler &compiler, VmFactory &vm_factory, IProviderDispatcher &providers,
                                 IRuntimeStore &store) noexcept:
        compiler_(compiler), vm_factory_(vm_factory), providers_(providers), store_(store) {}

    std::expected<void, DiagnosticSet> RuntimeEngine::activate(const VerifiedRulePack &pack,
                                                               const SchemaCatalog &schemas,
                                                               const OperatorBindings &bindings) {
        auto compiled = compiler_.compile(pack, schemas, bindings);
        if (!compiled) {
            return std::unexpected(std::move(compiled.error()));
        }
        auto verified = verify_bytecode(*compiled);
        if (!verified) {
            return std::unexpected(std::move(verified.error()));
        }
        active_pack_ = std::make_shared<const CompiledPack>(std::move(*compiled));
        return {};
    }

    std::expected<EvaluationHandle, DiagnosticSet> RuntimeEngine::start(const VmInvocation &invocation) {
        if (!active_pack_) {
            return std::unexpected(DiagnosticSet {engine_diagnostic("PYE0001", "no Python rule pack is active")});
        }
        auto session = vm_factory_.start(*active_pack_, invocation);
        if (!session) {
            return std::unexpected(std::move(session.error()));
        }
        return EvaluationHandle {.pack = active_pack_,
                                 .invocation = invocation,
                                 .session = std::move(*session),
                                 .terminal_result = std::nullopt,
                                 .dispatched_requests = {},
                                 .committed = false};
    }

    VmStep RuntimeEngine::advance(EvaluationHandle &evaluation, HostResponses responses) {
        if (!evaluation.session) {
            VmStep step;
            step.state = VmStepState::faulted;
            EvaluationResult result;
            result.outcome = EvaluationOutcome::faulted;
            FaultFrame frame;
            frame.code = "PYE0002";
            frame.message = "evaluation has no VM session";
            result.fault = FaultChain {.frames = {std::move(frame)}};
            step.result = std::move(result);
            return step;
        }

        auto step = evaluation.session->step(std::move(responses));
        std::vector<FactRequest> new_fact_requests;
        for (const auto &request : step.fact_requests) {
            if (evaluation.dispatched_requests.insert(request.request_id.value).second) {
                new_fact_requests.push_back(request);
            }
        }
        if (!new_fact_requests.empty()) {
            providers_.request_facts(std::move(new_fact_requests));
        }

        std::vector<ScanRequest> new_scan_requests;
        for (const auto &request : step.scan_requests) {
            if (evaluation.dispatched_requests.insert(request.request_id.value).second) {
                new_scan_requests.push_back(request);
            }
        }
        if (!new_scan_requests.empty()) {
            providers_.request_scans(std::move(new_scan_requests));
        }

        if (is_terminal(step.state) && step.result.has_value()) {
            evaluation.terminal_result = step.result;
        }
        return step;
    }

    std::expected<TransactionReceipt, EngineError> RuntimeEngine::commit(EvaluationHandle &evaluation,
                                                                         EventEnvelope input, CursorAdvance cursor,
                                                                         const std::uint64_t fence_token) {
        if (evaluation.committed) {
            return std::unexpected(EngineError {.code = EngineErrorCode::already_committed,
                                                .message = "evaluation was already committed",
                                                .store = std::nullopt,
                                                .event = std::nullopt});
        }
        if (!evaluation.terminal_result.has_value()) {
            return std::unexpected(EngineError {.code = EngineErrorCode::not_terminal,
                                                .message = "evaluation is not terminal",
                                                .store = std::nullopt,
                                                .event = std::nullopt});
        }

        std::vector<EventEnvelope> emitted_events;
        if (!evaluation.terminal_result->committed_events.empty()) {
            auto projected = project_committed_events(input, evaluation.invocation, evaluation.pack->schemas,
                                                      evaluation.terminal_result->committed_events);
            if (!projected) {
                return std::unexpected(EngineError {.code = EngineErrorCode::event_projection_failure,
                                                    .message = projected.error().message,
                                                    .store = std::nullopt,
                                                    .event = std::move(projected.error())});
            }
            emitted_events = std::move(*projected);
        }

        RuntimeTransaction transaction {
            .input = std::move(input),
            .cursor = std::move(cursor),
            .evaluation = *evaluation.terminal_result,
            .state = evaluation.terminal_result->state_mutations,
            .emitted_events = std::move(emitted_events),
            .journal = evaluation.terminal_result->committed_effects,
            .outbox = {},
            .fence_token = fence_token,
        };
        transaction.outbox.reserve(transaction.journal.size());
        for (const auto &intent : transaction.journal) {
            if (intent.disposition != EffectDisposition::committed) {
                continue;
            }
            transaction.outbox.push_back(OutboxRecord {.intent = intent.id,
                                                       .destination = intent.kind,
                                                       .payload = intent.payload,
                                                       .idempotency_key = intent.idempotency_key,
                                                       .not_before_unix_ms = 0});
        }

        auto receipt = store_.transact_event(transaction);
        if (!receipt) {
            return std::unexpected(EngineError {.code = EngineErrorCode::store_failure,
                                                .message = receipt.error().message,
                                                .store = std::move(receipt.error()),
                                                .event = std::nullopt});
        }
        evaluation.committed = true;
        return std::move(*receipt);
    }

} // namespace rule_engine::python
