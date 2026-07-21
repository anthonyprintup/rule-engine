#include "rule_engine/python/runtime/orchestrator.hpp"

#include "rule_engine/python/contract/subject.hpp"

#include <algorithm>
#include <limits>
#include <map>
#include <ranges>
#include <set>
#include <string_view>
#include <utility>

namespace rule_engine::python::runtime {
    namespace {

        constexpr std::uint32_t maximum_mvcc_attempts = 3U;

        [[nodiscard]] ResidentRuntimeError runtime_error(const ResidentRuntimeErrorCode code, std::string message) {
            return ResidentRuntimeError {
                .code = code,
                .message = std::move(message),
                .port = std::nullopt,
                .store = std::nullopt,
                .diagnostics = {},
            };
        }

        [[nodiscard]] ResidentRuntimeError port_error(PortError error, const std::string_view operation) {
            auto message = std::string {operation};
            message += ": ";
            message += error.message;
            return ResidentRuntimeError {
                .code = ResidentRuntimeErrorCode::port_failure,
                .message = std::move(message),
                .port = std::move(error),
                .store = std::nullopt,
                .diagnostics = {},
            };
        }

        [[nodiscard]] ResidentRuntimeError store_error(StoreError error, const ResidentRuntimeErrorCode code,
                                                       const std::string_view operation) {
            auto message = std::string {operation};
            message += ": ";
            message += error.message;
            return ResidentRuntimeError {
                .code = code,
                .message = std::move(message),
                .port = std::nullopt,
                .store = std::move(error),
                .diagnostics = {},
            };
        }

        void append_component(std::string &target, const std::string_view value) {
            target += std::to_string(value.size());
            target.push_back(':');
            target.append(value);
            target.push_back(';');
        }

        template<typename Value> void append_number(std::string &target, const Value value) {
            append_component(target, std::to_string(value));
        }

        [[nodiscard]] std::string fact_key(const FactRequest &request) {
            std::string key;
            append_component(key, "fact-v1");
            append_component(key, request.request_id.value);
            append_component(key, canonical_subject_key(request.subject));
            append_component(key, request.route.provider);
            append_component(key, request.route.fact);
            append_component(key, request.expected_schema.value);
            append_component(key, request.expected_schema_hash);
            return key;
        }

        [[nodiscard]] std::string scan_key(const ScanRequest &request) {
            std::string key;
            append_component(key, "scan-v1");
            append_component(key, request.request_id.value);
            append_component(key, canonical_subject_key(request.subject));
            append_component(key, request.space.kind);
            append_number(key, request.space.begin);
            append_number(key, request.space.size);
            append_number(key, request.space.permissions);
            append_component(key, request.plan.plan_id);
            append_component(key, request.plan.encoded_pattern);
            append_number(key, request.plan.maximum_bytes);
            append_number(key, request.plan.maximum_matches);
            return key;
        }

        [[nodiscard]] std::string capability_key(const CapabilityRequest &request) {
            std::string key;
            append_component(key, "capability-v1");
            append_component(key, request.request_id.value);
            append_component(key, request.capability.value);
            append_component(key, request.request_schema.value);
            append_component(key, request.arguments.canonical_digest);
            return key;
        }

        [[nodiscard]] std::string state_key(const StateReadRequest &request, const std::uint32_t attempt) {
            std::string key;
            append_component(key, "state-v1");
            append_number(key, attempt);
            append_component(key, request.request_id.value);
            append_component(key, request.owner.value);
            append_component(key, request.namespace_name);
            append_component(key, request.key);
            append_component(key, request.schema.value);
            return key;
        }

        [[nodiscard]] std::string history_key(const HistoryRequest &request) {
            std::string key;
            append_component(key, "history-v1");
            append_component(key, request.request_id.value);
            append_component(key, request.tenant.value);
            append_component(key, request.peer.value);
            append_component(key, request.event_schema.value);
            append_number(key, request.begin_ingest_unix_ms);
            append_number(key, request.end_ingest_unix_ms);
            append_number(key, request.limit);
            return key;
        }

        [[nodiscard]] bool kind_matches(const CapturedHostInput &capture) {
            switch (capture.kind) {
                case CapturedHostInputKind::fact: return std::holds_alternative<FactResponse>(capture.response);
                case CapturedHostInputKind::scan: return std::holds_alternative<ScanResponse>(capture.response);
                case CapturedHostInputKind::capability:
                    return std::holds_alternative<CapabilityResponse>(capture.response);
                case CapturedHostInputKind::state: return std::holds_alternative<StateReadResponse>(capture.response);
                case CapturedHostInputKind::history: return std::holds_alternative<HistoryResponse>(capture.response);
                default: return false;
            }
        }

        struct Transcript {
            [[nodiscard]] static std::expected<Transcript, ResidentRuntimeError>
            create(std::vector<CapturedHostInput> captures) {
                Transcript result;
                for (auto &capture : captures) {
                    if (capture.key.empty() || !kind_matches(capture) || result.index_.contains(capture.key)) {
                        return std::unexpected(runtime_error(ResidentRuntimeErrorCode::replay_input_mismatch,
                                                             "captured input is malformed or duplicated"));
                    }
                    result.index_.emplace(capture.key, result.captures_.size());
                    result.captures_.push_back(std::move(capture));
                }
                return result;
            }

            [[nodiscard]] const CapturedHostInput *find(const std::string_view key,
                                                        const CapturedHostInputKind kind) const noexcept {
                const auto found = index_.find(key);
                if (found == index_.end()) {
                    return nullptr;
                }
                const auto &capture = captures_[found->second];
                return capture.kind == kind ? &capture : nullptr;
            }

            [[nodiscard]] std::expected<const CapturedHostInput *, ResidentRuntimeError>
            insert(CapturedHostInput capture) {
                if (capture.key.empty() || !kind_matches(capture)) {
                    return std::unexpected(runtime_error(ResidentRuntimeErrorCode::invalid_response,
                                                         "host port produced an invalid captured response"));
                }
                if (const auto *existing = find(capture.key, capture.kind); existing != nullptr) {
                    return existing;
                }
                if (index_.contains(capture.key)) {
                    return std::unexpected(runtime_error(ResidentRuntimeErrorCode::replay_input_mismatch,
                                                         "one capture key changed response kind"));
                }
                const auto index = captures_.size();
                index_.emplace(capture.key, index);
                captures_.push_back(std::move(capture));
                return &captures_.back();
            }

            [[nodiscard]] const std::vector<CapturedHostInput> &captures() const noexcept { return captures_; }

        private:
            std::vector<CapturedHostInput> captures_;
            std::map<std::string, std::size_t, std::less<>> index_;
        };

        [[nodiscard]] std::expected<void, ResidentRuntimeError>
        validate_request(const ResidentEvaluationRequest &request) {
            const auto &work = request.work;
            if (work.work_id.empty() || work.node_id.empty() || work.serial_domain.empty() || work.pack.empty() ||
                work.generation == 0U || work.attempt == 0U || work.fence == 0U ||
                request.invocation.execution.empty() || request.invocation.invocation.empty() ||
                request.invocation.binding.empty() || !request.invocation.subject.valid() || request.input.id.empty() ||
                request.input.tenant.empty() || request.input.peer.empty() ||
                request.input.peer != request.invocation.subject.peer ||
                request.cursor.consumer != work.serial_domain ||
                request.cursor.expected_position == std::numeric_limits<std::uint64_t>::max() ||
                request.cursor.new_position != request.cursor.expected_position + 1U ||
                request.replay_state_attempt == 0U || request.replay_state_attempt > maximum_mvcc_attempts) {
                return std::unexpected(runtime_error(ResidentRuntimeErrorCode::invalid_work,
                                                     "resident evaluation work identity or cursor is invalid"));
            }
            return {};
        }

        [[nodiscard]] bool terminal_state(const VmStepState state) noexcept {
            return state == VmStepState::complete || state == VmStepState::faulted ||
                   state == VmStepState::quarantined || state == VmStepState::canceled;
        }

        [[nodiscard]] bool terminal_matches_result(const VmStep &step) noexcept {
            if (!step.result) {
                return false;
            }
            switch (step.state) {
                case VmStepState::complete:
                    return step.result->outcome == EvaluationOutcome::match ||
                           step.result->outcome == EvaluationOutcome::no_match;
                case VmStepState::faulted: return step.result->outcome == EvaluationOutcome::faulted;
                case VmStepState::quarantined: return step.result->outcome == EvaluationOutcome::quarantined;
                case VmStepState::canceled: return step.result->outcome == EvaluationOutcome::canceled;
                case VmStepState::yielded:
                case VmStepState::waiting_for_facts:
                case VmStepState::waiting_for_capabilities: return false;
                default: return false;
            }
        }

        void cancel_requests(const VmStep &step, HostResponsePorts ports) noexcept {
            std::vector<RequestId> provider;
            provider.reserve(step.fact_requests.size() + step.scan_requests.size());
            for (const auto &request : step.fact_requests) { provider.push_back(request.request_id); }
            for (const auto &request : step.scan_requests) { provider.push_back(request.request_id); }
            if (!provider.empty()) {
                ports.providers.cancel(provider);
            }

            std::vector<RequestId> capabilities;
            capabilities.reserve(step.capability_requests.size());
            for (const auto &request : step.capability_requests) { capabilities.push_back(request.request_id); }
            if (!capabilities.empty()) {
                ports.capabilities.cancel(capabilities);
            }

            std::vector<RequestId> history;
            history.reserve(step.history_requests.size());
            for (const auto &request : step.history_requests) { history.push_back(request.request_id); }
            if (!history.empty()) {
                ports.history.cancel(history);
            }
        }

        [[nodiscard]] std::expected<WorkControlState, ResidentRuntimeError>
        observe_work(IWorkControlPort &control, const ResidentWorkIdentity &work) {
            auto observed = control.observe(work);
            if (!observed) {
                return std::unexpected(port_error(std::move(observed.error()), "work-control observation"));
            }
            return *observed;
        }

        [[nodiscard]] std::expected<void, ResidentRuntimeError> validate_fact_response(const FactRequest &request,
                                                                                       const FactResponse &response) {
            if (response.request_id != request.request_id ||
                canonical_subject_key(response.subject) != canonical_subject_key(request.subject) ||
                !fact_response_schema_matches(request, response)) {
                return std::unexpected(runtime_error(ResidentRuntimeErrorCode::invalid_response,
                                                     "fact response identity, terminal shape, or schema is invalid"));
            }
            return {};
        }

        [[nodiscard]] std::expected<void, ResidentRuntimeError> validate_scan_response(const ScanRequest &request,
                                                                                       const ScanResponse &response) {
            if (response.request_id != request.request_id ||
                canonical_subject_key(response.subject) != canonical_subject_key(request.subject) ||
                response.matches.size() > request.plan.maximum_matches ||
                (response.status != FactTerminalStatus::value && !response.matches.empty())) {
                return std::unexpected(runtime_error(ResidentRuntimeErrorCode::invalid_response,
                                                     "scan response identity or match bound is invalid"));
            }
            return {};
        }

        [[nodiscard]] std::expected<void, ResidentRuntimeError>
        validate_capability_response(const CapabilityRequest &request, const CapabilityResponse &response) {
            if (response.request_id != request.request_id ||
                (response.status == FactTerminalStatus::value) != response.value.has_value() ||
                (response.value && (!response.value->value.valid() || response.value->canonical_digest.empty()))) {
                return std::unexpected(runtime_error(ResidentRuntimeErrorCode::invalid_response,
                                                     "capability response identity or value/status shape is invalid"));
            }
            return {};
        }

        [[nodiscard]] std::expected<void, ResidentRuntimeError>
        validate_state_response(const StateReadRequest &request, const StateReadResponse &response) {
            if (response.request_id != request.request_id ||
                (response.value && (!response.value->value.valid() || response.value->canonical_digest.empty()))) {
                return std::unexpected(
                    runtime_error(ResidentRuntimeErrorCode::invalid_response, "state response identity is invalid"));
            }
            return {};
        }

        [[nodiscard]] std::expected<void, ResidentRuntimeError>
        validate_history_response(const HistoryRequest &request, const HistoryResponse &response) {
            if (response.request_id != request.request_id || response.rows.size() > request.limit ||
                std::ranges::any_of(response.rows, [](const FrozenValue &row) {
                    return !row.value.valid() || row.canonical_digest.empty();
                })) {
                return std::unexpected(runtime_error(ResidentRuntimeErrorCode::invalid_response,
                                                     "history response identity or row bound is invalid"));
            }
            return {};
        }

        template<typename Response> [[nodiscard]] std::expected<Response, ResidentRuntimeError>
        replay_response(const Transcript &transcript, const std::string &key, const CapturedHostInputKind kind) {
            const auto *capture = transcript.find(key, kind);
            if (capture == nullptr || !std::holds_alternative<Response>(capture->response)) {
                return std::unexpected(runtime_error(ResidentRuntimeErrorCode::replay_input_missing,
                                                     "sealed replay transcript does not contain a requested input"));
            }
            return std::get<Response>(capture->response);
        }

        [[nodiscard]] std::expected<FactResponse, ResidentRuntimeError> resolve_fact(const FactRequest &request,
                                                                                     const bool live_dispatch,
                                                                                     Transcript &transcript,
                                                                                     IProviderResponsePort &port) {
            const auto key = fact_key(request);
            if (const auto *capture = transcript.find(key, CapturedHostInputKind::fact); capture != nullptr) {
                return std::get<FactResponse>(capture->response);
            }
            if (!live_dispatch) {
                return replay_response<FactResponse>(transcript, key, CapturedHostInputKind::fact);
            }
            auto resolved = port.resolve_facts(std::span {&request, 1U});
            if (!resolved) {
                return std::unexpected(port_error(std::move(resolved.error()), "fact resolution"));
            }
            if (resolved->size() != 1U) {
                return std::unexpected(runtime_error(ResidentRuntimeErrorCode::invalid_response,
                                                     "fact port did not return exactly one response"));
            }
            if (auto valid = validate_fact_response(request, resolved->front()); !valid) {
                return std::unexpected(valid.error());
            }
            auto inserted = transcript.insert(
                CapturedHostInput {.key = key, .kind = CapturedHostInputKind::fact, .response = resolved->front()});
            if (!inserted) {
                return std::unexpected(inserted.error());
            }
            return std::get<FactResponse>((*inserted)->response);
        }

        [[nodiscard]] std::expected<ScanResponse, ResidentRuntimeError> resolve_scan(const ScanRequest &request,
                                                                                     const bool live_dispatch,
                                                                                     Transcript &transcript,
                                                                                     IProviderResponsePort &port) {
            const auto key = scan_key(request);
            if (const auto *capture = transcript.find(key, CapturedHostInputKind::scan); capture != nullptr) {
                return std::get<ScanResponse>(capture->response);
            }
            if (!live_dispatch) {
                return replay_response<ScanResponse>(transcript, key, CapturedHostInputKind::scan);
            }
            auto resolved = port.resolve_scans(std::span {&request, 1U});
            if (!resolved) {
                return std::unexpected(port_error(std::move(resolved.error()), "scan resolution"));
            }
            if (resolved->size() != 1U) {
                return std::unexpected(runtime_error(ResidentRuntimeErrorCode::invalid_response,
                                                     "scan port did not return exactly one response"));
            }
            if (auto valid = validate_scan_response(request, resolved->front()); !valid) {
                return std::unexpected(valid.error());
            }
            auto inserted = transcript.insert(
                CapturedHostInput {.key = key, .kind = CapturedHostInputKind::scan, .response = resolved->front()});
            if (!inserted) {
                return std::unexpected(inserted.error());
            }
            return std::get<ScanResponse>((*inserted)->response);
        }

        [[nodiscard]] std::expected<CapabilityResponse, ResidentRuntimeError>
        resolve_capability(const CapabilityRequest &request, const bool live_dispatch, Transcript &transcript,
                           ICapabilityResponsePort &port) {
            const auto key = capability_key(request);
            if (const auto *capture = transcript.find(key, CapturedHostInputKind::capability); capture != nullptr) {
                return std::get<CapabilityResponse>(capture->response);
            }
            if (!live_dispatch) {
                return replay_response<CapabilityResponse>(transcript, key, CapturedHostInputKind::capability);
            }
            auto resolved = port.resolve(std::span {&request, 1U});
            if (!resolved) {
                return std::unexpected(port_error(std::move(resolved.error()), "capability resolution"));
            }
            if (resolved->size() != 1U) {
                return std::unexpected(runtime_error(ResidentRuntimeErrorCode::invalid_response,
                                                     "capability port did not return exactly one response"));
            }
            if (auto valid = validate_capability_response(request, resolved->front()); !valid) {
                return std::unexpected(valid.error());
            }
            auto inserted = transcript.insert(CapturedHostInput {
                .key = key, .kind = CapturedHostInputKind::capability, .response = resolved->front()});
            if (!inserted) {
                return std::unexpected(inserted.error());
            }
            return std::get<CapabilityResponse>((*inserted)->response);
        }

        [[nodiscard]] std::expected<StateReadResponse, ResidentRuntimeError>
        resolve_state(const StateReadRequest &request, const std::uint32_t live_attempt,
                      const std::uint32_t replay_attempt, const bool replay, Transcript &transcript,
                      IStateResponsePort &port) {
            const auto selected_attempt = replay ? replay_attempt : live_attempt;
            const auto key = state_key(request, selected_attempt);
            if (const auto *capture = transcript.find(key, CapturedHostInputKind::state); capture != nullptr) {
                return std::get<StateReadResponse>(capture->response);
            }
            if (replay) {
                return replay_response<StateReadResponse>(transcript, key, CapturedHostInputKind::state);
            }
            auto resolved = port.read(std::span {&request, 1U});
            if (!resolved) {
                return std::unexpected(port_error(std::move(resolved.error()), "state read"));
            }
            if (resolved->size() != 1U) {
                return std::unexpected(runtime_error(ResidentRuntimeErrorCode::invalid_response,
                                                     "state port did not return exactly one response"));
            }
            if (auto valid = validate_state_response(request, resolved->front()); !valid) {
                return std::unexpected(valid.error());
            }
            auto inserted = transcript.insert(
                CapturedHostInput {.key = key, .kind = CapturedHostInputKind::state, .response = resolved->front()});
            if (!inserted) {
                return std::unexpected(inserted.error());
            }
            return std::get<StateReadResponse>((*inserted)->response);
        }

        [[nodiscard]] std::expected<HistoryResponse, ResidentRuntimeError>
        resolve_history(const HistoryRequest &request, const bool live_dispatch, Transcript &transcript,
                        IHistoryResponsePort &port) {
            const auto key = history_key(request);
            if (const auto *capture = transcript.find(key, CapturedHostInputKind::history); capture != nullptr) {
                return std::get<HistoryResponse>(capture->response);
            }
            if (!live_dispatch) {
                return replay_response<HistoryResponse>(transcript, key, CapturedHostInputKind::history);
            }
            auto resolved = port.query(std::span {&request, 1U});
            if (!resolved) {
                return std::unexpected(port_error(std::move(resolved.error()), "history query"));
            }
            if (resolved->size() != 1U) {
                return std::unexpected(runtime_error(ResidentRuntimeErrorCode::invalid_response,
                                                     "history port did not return exactly one response"));
            }
            if (auto valid = validate_history_response(request, resolved->front()); !valid) {
                return std::unexpected(valid.error());
            }
            auto inserted = transcript.insert(
                CapturedHostInput {.key = key, .kind = CapturedHostInputKind::history, .response = resolved->front()});
            if (!inserted) {
                return std::unexpected(inserted.error());
            }
            return std::get<HistoryResponse>((*inserted)->response);
        }

        [[nodiscard]] std::expected<HostResponses, ResidentRuntimeError>
        resolve_host_responses(const VmStep &step, const std::uint32_t attempt,
                               const ResidentEvaluationRequest &request, Transcript &transcript,
                               const HostResponsePorts ports) {
            HostResponses responses;
            const auto replay = request.mode == effects::ExecutionMode::replay;
            const auto live_external_dispatch = !replay && attempt == 1U;
            for (const auto &fact : step.fact_requests) {
                auto resolved = resolve_fact(fact, live_external_dispatch, transcript, ports.providers);
                if (!resolved) {
                    return std::unexpected(resolved.error());
                }
                if (auto valid = validate_fact_response(fact, *resolved); !valid) {
                    return std::unexpected(valid.error());
                }
                responses.facts.push_back(std::move(*resolved));
            }
            for (const auto &scan : step.scan_requests) {
                auto resolved = resolve_scan(scan, live_external_dispatch, transcript, ports.providers);
                if (!resolved) {
                    return std::unexpected(resolved.error());
                }
                if (auto valid = validate_scan_response(scan, *resolved); !valid) {
                    return std::unexpected(valid.error());
                }
                responses.scans.push_back(std::move(*resolved));
            }
            for (const auto &capability : step.capability_requests) {
                auto resolved = resolve_capability(capability, live_external_dispatch, transcript, ports.capabilities);
                if (!resolved) {
                    return std::unexpected(resolved.error());
                }
                if (auto valid = validate_capability_response(capability, *resolved); !valid) {
                    return std::unexpected(valid.error());
                }
                responses.capabilities.push_back(std::move(*resolved));
            }
            for (const auto &state : step.state_requests) {
                auto resolved =
                    resolve_state(state, attempt, request.replay_state_attempt, replay, transcript, ports.state);
                if (!resolved) {
                    return std::unexpected(resolved.error());
                }
                if (auto valid = validate_state_response(state, *resolved); !valid) {
                    return std::unexpected(valid.error());
                }
                responses.state.push_back(std::move(*resolved));
            }
            for (const auto &history : step.history_requests) {
                auto resolved = resolve_history(history, live_external_dispatch, transcript, ports.history);
                if (!resolved) {
                    return std::unexpected(resolved.error());
                }
                if (auto valid = validate_history_response(history, *resolved); !valid) {
                    return std::unexpected(valid.error());
                }
                responses.history.push_back(std::move(*resolved));
            }
            if (responses.facts.empty() && responses.scans.empty() && responses.capabilities.empty() &&
                responses.state.empty() && responses.history.empty()) {
                return std::unexpected(runtime_error(ResidentRuntimeErrorCode::invalid_vm_step,
                                                     "waiting VM step contains no host request"));
            }
            return responses;
        }

        [[nodiscard]] std::expected<EvaluationResult, ResidentRuntimeError>
        cancel_evaluation(IResidentVmDriver &vm, EvaluationHandle &evaluation, const VmStep &outstanding) {
            HostResponses cancellation;
            cancellation.cancel = true;
            auto canceled = vm.step(evaluation, std::move(cancellation));
            if (!canceled || canceled->state != VmStepState::canceled || !canceled->result) {
                return std::unexpected(runtime_error(ResidentRuntimeErrorCode::cancellation_failed,
                                                     "VM did not terminate through its cancellation path"));
            }
            static_cast<void>(outstanding);
            return *canceled->result;
        }

        [[nodiscard]] std::expected<RuntimeTransaction, ResidentRuntimeError>
        make_transaction(const ResidentEvaluationRequest &request, const EvaluationResult &result) {
            auto durable = result;
            durable.committed_effects.clear();
            durable.committed_effects.reserve(result.committed_effects.size());
            for (const auto &intent : result.committed_effects) {
                if (intent.disposition == EffectDisposition::pending) {
                    return std::unexpected(runtime_error(ResidentRuntimeErrorCode::invalid_vm_step,
                                                         "terminal VM result contains a pending effect"));
                }
                if (intent.disposition != EffectDisposition::rolled_back) {
                    durable.committed_effects.push_back(intent);
                }
            }

            RuntimeTransaction transaction {
                .input = request.input,
                .cursor = request.cursor,
                .evaluation = durable,
                .state = durable.state_mutations,
                .emitted_events = request.emitted_events,
                .journal = durable.committed_effects,
                .outbox = {},
                .fence_token = request.work.fence,
            };
            for (const auto &intent : transaction.journal) {
                if (intent.kind != "post" || intent.disposition != EffectDisposition::committed ||
                    intent.policy.dry_run) {
                    continue;
                }
                transaction.outbox.push_back(OutboxRecord {
                    .intent = intent.id,
                    .destination = intent.kind,
                    .payload = intent.payload,
                    .idempotency_key = intent.idempotency_key,
                    .not_before_unix_ms = 0U,
                });
            }
            return transaction;
        }

    } // namespace

    std::expected<EvaluationHandle, DiagnosticSet>
    DispatchFreeRuntimeEngineDriver::start(const VmInvocation &invocation) {
        return engine_.start(invocation);
    }

    std::expected<VmStep, ResidentVmDriverError> DispatchFreeRuntimeEngineDriver::step(EvaluationHandle &evaluation,
                                                                                       HostResponses responses) {
        if (!evaluation.session) {
            return std::unexpected(ResidentVmDriverError {.message = "evaluation has no VM session"});
        }
        auto step = evaluation.session->step(std::move(responses));
        if (terminal_state(step.state)) {
            if (!terminal_matches_result(step)) {
                return std::unexpected(
                    ResidentVmDriverError {.message = "terminal VM state has no matching evaluation result"});
            }
            evaluation.terminal_result = step.result;
        }
        return step;
    }

    std::expected<TransactionReceipt, StoreError>
    RuntimeStoreTransactionPort::commit(const ResidentWorkIdentity &work,
                                        const RuntimeTransaction &transaction) noexcept {
        if (transaction.cursor.consumer != work.serial_domain || transaction.fence_token != work.fence) {
            return std::unexpected(StoreError {
                .code = StoreErrorCode::stale_fence,
                .message = "runtime transaction does not match the resident work serial domain and fence",
                .retryable = false,
            });
        }
        return store_.transact_event(transaction);
    }

    ResidentRuntime::ResidentRuntime(IResidentVmDriver &vm, const HostResponsePorts ports, IWorkControlPort &control,
                                     ITransactionPort &transactions, const ResidentRuntimeOptions options) noexcept:
        vm_ {vm}, ports_ {ports}, control_ {control}, transactions_ {transactions}, options_ {options} {}

    std::expected<ResidentEvaluationReceipt, ResidentRuntimeError>
    ResidentRuntime::evaluate(ResidentEvaluationRequest request) {
        if (auto valid = validate_request(request); !valid) {
            return std::unexpected(valid.error());
        }
        if (options_.maximum_host_turns == 0U) {
            return std::unexpected(
                runtime_error(ResidentRuntimeErrorCode::invalid_work, "resident host-turn guard must be positive"));
        }
        auto transcript = Transcript::create(std::move(request.replay_inputs));
        if (!transcript) {
            return std::unexpected(transcript.error());
        }

        std::uint64_t host_turns {};
        const auto replay = request.mode == effects::ExecutionMode::replay;
        const auto attempt_limit = replay ? 1U : maximum_mvcc_attempts;
        for (std::uint32_t attempt = 1U; attempt <= attempt_limit; ++attempt) {
            if (!replay) {
                auto control = observe_work(control_, request.work);
                if (!control) {
                    return std::unexpected(control.error());
                }
                if (*control == WorkControlState::stale) {
                    return std::unexpected(
                        runtime_error(ResidentRuntimeErrorCode::stale_fence, "resident work fence is stale"));
                }
                if (*control == WorkControlState::canceled) {
                    return ResidentEvaluationReceipt {
                        .attempts = attempt,
                        .host_turns = host_turns,
                        .mode = request.mode,
                        .evaluation =
                            EvaluationResult {
                                .outcome = EvaluationOutcome::canceled,
                                .verdict = std::nullopt,
                                .committed_effects = {},
                                .state_mutations = {},
                                .fault = std::nullopt,
                            },
                        .candidate = std::nullopt,
                        .transaction = std::nullopt,
                        .captured_inputs = transcript->captures(),
                    };
                }
            }

            auto evaluation = vm_.start(request.invocation);
            if (!evaluation) {
                return std::unexpected(ResidentRuntimeError {
                    .code = ResidentRuntimeErrorCode::start_failed,
                    .message = "runtime engine could not start the resident VM session",
                    .port = std::nullopt,
                    .store = std::nullopt,
                    .diagnostics = std::move(evaluation.error()),
                });
            }
            if (!evaluation->pack || evaluation->pack->pack != request.work.pack) {
                return std::unexpected(runtime_error(ResidentRuntimeErrorCode::invalid_work,
                                                     "active VM pack does not match the resident work identity"));
            }

            HostResponses responses;
            VmStep last_step;
            std::optional<EvaluationResult> terminal;
            while (!terminal) {
                if (host_turns == options_.maximum_host_turns) {
                    cancel_requests(last_step, ports_);
                    return std::unexpected(runtime_error(ResidentRuntimeErrorCode::host_turn_limit,
                                                         "resident host-turn guard was exhausted"));
                }
                ++host_turns;

                auto step = vm_.step(*evaluation, std::move(responses));
                responses = {};
                if (!step) {
                    return std::unexpected(
                        runtime_error(ResidentRuntimeErrorCode::invalid_vm_step, std::move(step.error().message)));
                }
                last_step = std::move(*step);
                if (terminal_state(last_step.state)) {
                    terminal = *last_step.result;
                    break;
                }

                if (!replay) {
                    auto control = observe_work(control_, request.work);
                    if (!control) {
                        cancel_requests(last_step, ports_);
                        return std::unexpected(control.error());
                    }
                    if (*control != WorkControlState::current) {
                        cancel_requests(last_step, ports_);
                        auto canceled = cancel_evaluation(vm_, *evaluation, last_step);
                        if (!canceled) {
                            return std::unexpected(canceled.error());
                        }
                        if (*control == WorkControlState::stale) {
                            return std::unexpected(runtime_error(ResidentRuntimeErrorCode::stale_fence,
                                                                 "resident work fence became stale"));
                        }
                        return ResidentEvaluationReceipt {
                            .attempts = attempt,
                            .host_turns = host_turns,
                            .mode = request.mode,
                            .evaluation = std::move(*canceled),
                            .candidate = std::nullopt,
                            .transaction = std::nullopt,
                            .captured_inputs = transcript->captures(),
                        };
                    }
                }

                auto resolved = resolve_host_responses(last_step, attempt, request, *transcript, ports_);
                if (!resolved) {
                    cancel_requests(last_step, ports_);
                    return std::unexpected(resolved.error());
                }
                responses = std::move(*resolved);
            }

            auto transaction = make_transaction(request, *terminal);
            if (!transaction) {
                return std::unexpected(transaction.error());
            }
            if (terminal->outcome == EvaluationOutcome::canceled) {
                return ResidentEvaluationReceipt {
                    .attempts = attempt,
                    .host_turns = host_turns,
                    .mode = request.mode,
                    .evaluation = std::move(*terminal),
                    .candidate = std::move(*transaction),
                    .transaction = std::nullopt,
                    .captured_inputs = transcript->captures(),
                };
            }
            if (replay) {
                return ResidentEvaluationReceipt {
                    .attempts = attempt,
                    .host_turns = host_turns,
                    .mode = request.mode,
                    .evaluation = std::move(*terminal),
                    .candidate = std::move(*transaction),
                    .transaction = std::nullopt,
                    .captured_inputs = transcript->captures(),
                };
            }

            auto control = observe_work(control_, request.work);
            if (!control) {
                return std::unexpected(control.error());
            }
            if (*control == WorkControlState::stale) {
                return std::unexpected(
                    runtime_error(ResidentRuntimeErrorCode::stale_fence, "resident work fence is stale at commit"));
            }
            if (*control == WorkControlState::canceled) {
                return ResidentEvaluationReceipt {
                    .attempts = attempt,
                    .host_turns = host_turns,
                    .mode = request.mode,
                    .evaluation =
                        EvaluationResult {
                            .outcome = EvaluationOutcome::canceled,
                            .verdict = std::nullopt,
                            .committed_effects = {},
                            .state_mutations = {},
                            .fault = std::nullopt,
                        },
                    .candidate = std::nullopt,
                    .transaction = std::nullopt,
                    .captured_inputs = transcript->captures(),
                };
            }

            auto committed = transactions_.commit(request.work, *transaction);
            if (committed) {
                return ResidentEvaluationReceipt {
                    .attempts = attempt,
                    .host_turns = host_turns,
                    .mode = request.mode,
                    .evaluation = std::move(*terminal),
                    .candidate = std::move(*transaction),
                    .transaction = std::move(*committed),
                    .captured_inputs = transcript->captures(),
                };
            }
            if (committed.error().code == StoreErrorCode::stale_fence) {
                return std::unexpected(store_error(std::move(committed.error()), ResidentRuntimeErrorCode::stale_fence,
                                                   "resident transaction commit"));
            }
            if (committed.error().code != StoreErrorCode::conflict) {
                return std::unexpected(store_error(std::move(committed.error()),
                                                   ResidentRuntimeErrorCode::commit_failure,
                                                   "resident transaction commit"));
            }
            if (attempt == maximum_mvcc_attempts) {
                return std::unexpected(store_error(std::move(committed.error()),
                                                   ResidentRuntimeErrorCode::state_conflict_exhausted,
                                                   "resident MVCC retry"));
            }
        }
        return std::unexpected(runtime_error(ResidentRuntimeErrorCode::state_conflict_exhausted,
                                             "resident MVCC retry loop terminated unexpectedly"));
    }

} // namespace rule_engine::python::runtime
