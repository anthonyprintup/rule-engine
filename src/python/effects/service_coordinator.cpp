#include "rule_engine/python/effects/service_coordinator.hpp"

#include <algorithm>
#include <utility>

namespace rule_engine::python::effects {
    namespace {

        bool valid_binding(const ServiceBindingPolicy &policy) noexcept {
            return !policy.binding_key.empty() && !policy.capability.empty() && !policy.request_schema.empty() &&
                   policy.retry.maximum_attempts > 0 && policy.retry.maximum_attempts <= 2U &&
                   policy.retry.base_delay_ms <= policy.retry.maximum_delay_ms &&
                   (!policy.cache.has_value() || (!policy.cache->scope_key.empty() && policy.cache->ttl_ms > 0));
        }

        bool same_request(const CapabilityRequest &left, const CapabilityRequest &right) noexcept {
            return left.request_id == right.request_id && left.capability == right.capability &&
                   left.request_schema == right.request_schema && same_frozen_value(left.arguments, right.arguments) &&
                   left.deadline_unix_ms == right.deadline_unix_ms;
        }

        bool same_result(const ServiceResult &left, const ServiceResult &right) noexcept {
            const auto same_value = left.value.has_value() == right.value.has_value() &&
                                    (!left.value.has_value() || same_frozen_value(*left.value, *right.value));
            return left.status == right.status && same_value && left.retry_after_ms == right.retry_after_ms &&
                   left.diagnostic_code == right.diagnostic_code;
        }

        std::string call_key(const ServiceBindingPolicy &binding, const CapabilityRequest &request) {
            return stable_domain_key("service-request-v1",
                                     {binding.binding_key, request.capability.value, request.request_schema.value,
                                      request.arguments.canonical_digest});
        }

        std::string capture_key(const ServiceCallSpec &spec) {
            return stable_domain_key("service-capture-v1", {spec.canonical_key, spec.request.request_id.value});
        }

        FactTerminalStatus terminal_status(const ServiceStatus status) noexcept {
            switch (status) {
                case ServiceStatus::ok: return FactTerminalStatus::value;
                case ServiceStatus::request_timeout: return FactTerminalStatus::timed_out;
                case ServiceStatus::canceled: return FactTerminalStatus::canceled;
                case ServiceStatus::client_error: return FactTerminalStatus::denied;
                case ServiceStatus::transport_error:
                case ServiceStatus::too_early:
                case ServiceStatus::rate_limited:
                case ServiceStatus::server_error:
                case ServiceStatus::malformed_response: return FactTerminalStatus::failed;
                default: return FactTerminalStatus::failed;
            }
        }

        CapabilityResponse capability_response(const CapabilityRequest &request, const ServiceResult &result) {
            CapabilityResponse response {
                .request_id = request.request_id,
                .status = terminal_status(result.status),
                .value = result.status == ServiceStatus::ok ? result.value : std::nullopt,
                .diagnostic = std::nullopt,
            };
            if (result.status != ServiceStatus::ok) {
                response.diagnostic = Diagnostic {
                    .code = result.diagnostic_code.empty() ? "SERVICE_TERMINAL" : result.diagnostic_code,
                    .severity = DiagnosticSeverity::error,
                    .message = "service capability completed with terminal status " +
                               std::to_string(static_cast<std::uint32_t>(result.status)),
                    .span = std::nullopt,
                    .related = {},
                };
            }
            return response;
        }

        ServiceResult canceled_result() {
            return ServiceResult {.status = ServiceStatus::canceled,
                                  .value = std::nullopt,
                                  .retry_after_ms = std::nullopt,
                                  .diagnostic_code = "SERVICE_CANCELED"};
        }

        bool same_attempt(const ServiceAttempt &left, const ServiceAttempt &right) noexcept {
            return left.task == right.task && left.request == right.request && left.attempt == right.attempt &&
                   left.deadline_unix_ms == right.deadline_unix_ms && left.idempotency_key == right.idempotency_key;
        }

    } // namespace

    StaticServiceBindingResolver::StaticServiceBindingResolver(std::vector<ServiceBindingPolicy> policies) noexcept:
        policies_ {std::move(policies)} {}

    std::expected<StaticServiceBindingResolver, ServiceError>
    StaticServiceBindingResolver::create(std::vector<ServiceBindingPolicy> policies) {
        for (std::size_t index = 0; index < policies.size(); ++index) {
            if (!valid_binding(policies[index])) {
                return std::unexpected(ServiceError {.code = ServiceErrorCode::invalid_specification,
                                                     .message = "a static service binding is incomplete or unbounded"});
            }
            for (std::size_t prior = 0; prior < index; ++prior) {
                if (policies[prior].capability == policies[index].capability &&
                    policies[prior].request_schema == policies[index].request_schema) {
                    return std::unexpected(
                        ServiceError {.code = ServiceErrorCode::invalid_specification,
                                      .message = "service bindings must be unique by capability and schema"});
                }
            }
        }
        return StaticServiceBindingResolver {std::move(policies)};
    }

    std::expected<ServiceBindingPolicy, ServiceError>
    StaticServiceBindingResolver::resolve(const CapabilityRequest &request) const {
        const auto found = std::ranges::find_if(policies_, [&](const ServiceBindingPolicy &policy) {
            return policy.capability == request.capability && policy.request_schema == request.request_schema;
        });
        if (found == policies_.end()) {
            return std::unexpected(ServiceError {.code = ServiceErrorCode::binding_not_found,
                                                 .message = "the requested capability/schema has no active binding"});
        }
        return *found;
    }

    struct ServiceCoordinator::Implementation {
        struct TrackedCall {
            ServiceCallSpec spec;
            std::string capture_key;
            TaskHandle task;
            std::optional<ServiceAttempt> current_attempt;
            std::optional<std::uint64_t> retry_at_unix_ms;
            std::vector<CapturedServiceAttempt> captured_attempts;
            const ServiceCapture *pending_cancel_capture {};
            bool terminal {};
        };

        ExecutionMode mode {ExecutionMode::live};
        const IServiceBindingResolver &bindings;
        IServiceTransport *transport {};
        ServiceTaskGroup group;
        ServiceCache cache;
        std::vector<ServiceCapture> replay_captures;
        std::vector<ServiceCapture> recorded_captures;
        std::vector<TrackedCall> calls;
        std::vector<CapabilityResponse> responses;
        std::uint64_t next_completion_order {1U};
        std::uint64_t live_dispatch_count {};
        std::uint64_t blocked_dispatch_count {};

        Implementation(ExecutionMode selected_mode, const IServiceBindingResolver &selected_bindings,
                       IServiceTransport *selected_transport, ServiceTaskGroup selected_group):
            mode {selected_mode},
            bindings {selected_bindings},
            transport {selected_transport},
            group {std::move(selected_group)} {}

        [[nodiscard]] TrackedCall *find(const RequestId &request) noexcept {
            const auto found =
                std::ranges::find(calls, request, [](const TrackedCall &call) { return call.spec.request.request_id; });
            return found == calls.end() ? nullptr : &*found;
        }

        [[nodiscard]] const TrackedCall *find(const RequestId &request) const noexcept {
            const auto found =
                std::ranges::find(calls, request, [](const TrackedCall &call) { return call.spec.request.request_id; });
            return found == calls.end() ? nullptr : &*found;
        }

        [[nodiscard]] TrackedCall *find(const TaskHandle task) noexcept {
            const auto found = std::ranges::find(calls, task, &TrackedCall::task);
            return found == calls.end() ? nullptr : &*found;
        }

        [[nodiscard]] const ServiceCapture *replay_capture(const std::string_view key) const noexcept {
            const auto found = std::ranges::find(replay_captures, key, &ServiceCapture::canonical_key);
            return found == replay_captures.end() ? nullptr : &*found;
        }

        void terminalize(TrackedCall &call, const ServiceResult &result, const bool cache_hit) {
            if (call.terminal) {
                return;
            }
            call.terminal = true;
            call.current_attempt.reset();
            call.retry_at_unix_ms.reset();
            responses.push_back(capability_response(call.spec.request, result));
            if (mode == ExecutionMode::live) {
                recorded_captures.push_back(ServiceCapture {
                    .canonical_key = call.capture_key,
                    .request = call.spec.request,
                    .cache_hit = cache_hit,
                    .attempts = call.captured_attempts,
                    .terminal_result = result,
                    .completion_order = next_completion_order++,
                });
            }
        }
    };

    namespace {

        std::expected<void, ServiceError> accept_result(ServiceCoordinator::Implementation &implementation,
                                                        ServiceCoordinator::Implementation::TrackedCall &call,
                                                        const ServiceAttempt &attempt, ServiceResult result,
                                                        const std::uint64_t completed_unix_ms,
                                                        const bool record_attempt) {
            if (!call.current_attempt.has_value() || !same_attempt(*call.current_attempt, attempt)) {
                return std::unexpected(
                    ServiceError {.code = ServiceErrorCode::stale_attempt,
                                  .message = "the service completion does not match the active attempt"});
            }
            const auto captured_result = result;
            auto transition = implementation.group.accept(call.task, attempt.attempt, std::move(result),
                                                          completed_unix_ms, &implementation.cache);
            if (record_attempt) {
                call.captured_attempts.push_back(CapturedServiceAttempt {
                    .attempt = attempt.attempt,
                    .completed_unix_ms = completed_unix_ms,
                    .result = captured_result,
                });
            }
            call.current_attempt.reset();
            if (!transition.has_value()) {
                if (transition.error().code != ServiceErrorCode::malformed_response &&
                    transition.error().code != ServiceErrorCode::response_label_rejected) {
                    return std::unexpected(transition.error());
                }
                const auto terminal = implementation.group.result(call.task);
                if (!terminal.has_value()) {
                    return std::unexpected(transition.error());
                }
                implementation.terminalize(call, *terminal, false);
                return {};
            }
            call.retry_at_unix_ms = transition->retry_at_unix_ms;
            if (transition->result.has_value()) {
                implementation.terminalize(call, *transition->result, false);
            }
            return {};
        }

        std::expected<void, ServiceError> dispatch_attempt(ServiceCoordinator::Implementation &implementation,
                                                           ServiceCoordinator::Implementation::TrackedCall &call,
                                                           ServiceAttempt attempt, const std::uint64_t now_unix_ms,
                                                           std::vector<ServiceAttempt> *dispatched = nullptr) {
            call.current_attempt = attempt;
            if (dispatched != nullptr) {
                dispatched->push_back(attempt);
            }
            if (implementation.mode == ExecutionMode::replay) {
                ++implementation.blocked_dispatch_count;
                return {};
            }
            ++implementation.live_dispatch_count;
            auto accepted = implementation.transport->dispatch(attempt);
            if (accepted.has_value()) {
                return {};
            }
            return accept_result(implementation, call, attempt, std::move(accepted.error()), now_unix_ms, true);
        }

        std::expected<void, ServiceError> replay_one(ServiceCoordinator::Implementation &implementation,
                                                     ServiceCoordinator::Implementation::TrackedCall &call,
                                                     const ServiceCapture &capture, const std::uint64_t now_unix_ms) {
            if (!same_request(call.spec.request, capture.request)) {
                return std::unexpected(ServiceError {.code = ServiceErrorCode::capture_mismatch,
                                                     .message = "the service capture request identity does not match"});
            }
            if (capture.cache_hit) {
                if (!capture.attempts.empty() || capture.terminal_result.status != ServiceStatus::ok ||
                    !call.spec.cache.has_value()) {
                    return std::unexpected(ServiceError {.code = ServiceErrorCode::capture_mismatch,
                                                         .message = "a captured cache hit has invalid task semantics"});
                }
                const auto stored = implementation.cache.store(call.spec, capture.terminal_result, now_unix_ms);
                if (!stored.has_value()) {
                    return std::unexpected(stored.error());
                }
                const auto started = implementation.group.start(call.task, now_unix_ms, &implementation.cache);
                if (!started.has_value() || !started->cache_hit || !started->result.has_value()) {
                    return std::unexpected(
                        ServiceError {.code = ServiceErrorCode::capture_mismatch,
                                      .message = "the captured service cache hit could not be restored"});
                }
                implementation.terminalize(call, *started->result, true);
                return {};
            }

            const auto started = implementation.group.start(call.task, now_unix_ms, nullptr);
            if (!started.has_value()) {
                return std::unexpected(started.error());
            }
            if (!started->attempt.has_value()) {
                return std::unexpected(ServiceError {.code = ServiceErrorCode::capture_mismatch,
                                                     .message = "a non-cache service capture requires an attempt"});
            }
            call.current_attempt = *started->attempt;
            ++implementation.blocked_dispatch_count;

            const auto canceled_by_owner =
                capture.terminal_result.status == ServiceStatus::canceled &&
                (capture.attempts.empty() || capture.attempts.back().result.status != ServiceStatus::canceled);
            if (canceled_by_owner) {
                call.pending_cancel_capture = &capture;
                implementation.blocked_dispatch_count += capture.attempts.size();
                return {};
            }

            for (std::size_t index = 0; index < capture.attempts.size(); ++index) {
                const auto &captured_attempt = capture.attempts[index];
                if (!call.current_attempt.has_value() || call.current_attempt->attempt != captured_attempt.attempt) {
                    return std::unexpected(ServiceError {.code = ServiceErrorCode::capture_mismatch,
                                                         .message = "captured service attempts are not contiguous"});
                }
                const auto accepted = accept_result(implementation, call, *call.current_attempt,
                                                    captured_attempt.result, captured_attempt.completed_unix_ms, false);
                if (!accepted.has_value()) {
                    return accepted;
                }
                if (call.terminal) {
                    if (index + 1U != capture.attempts.size()) {
                        return std::unexpected(
                            ServiceError {.code = ServiceErrorCode::capture_mismatch,
                                          .message = "a service capture continues after terminal completion"});
                    }
                    break;
                }
                if (!call.retry_at_unix_ms.has_value()) {
                    return std::unexpected(ServiceError {.code = ServiceErrorCode::capture_mismatch,
                                                         .message = "a non-terminal capture did not schedule a retry"});
                }
                auto retried = implementation.group.resume_retry(call.task, *call.retry_at_unix_ms);
                if (!retried.has_value()) {
                    return std::unexpected(retried.error());
                }
                call.current_attempt = *retried;
                ++implementation.blocked_dispatch_count;
            }
            if (!call.terminal) {
                return std::unexpected(ServiceError {.code = ServiceErrorCode::capture_mismatch,
                                                     .message = "the service capture ended before a terminal result"});
            }
            const auto terminal = implementation.group.result(call.task);
            if (!terminal.has_value() || !same_result(*terminal, capture.terminal_result)) {
                return std::unexpected(ServiceError {.code = ServiceErrorCode::capture_mismatch,
                                                     .message = "the replayed service terminal result diverged"});
            }
            return {};
        }

    } // namespace

    std::expected<ServiceCoordinator, ServiceError> ServiceCoordinator::create(ServiceCoordinatorConfig config,
                                                                               const IServiceBindingResolver &bindings,
                                                                               IServiceTransport *const transport) {
        if (config.mode == ExecutionMode::live && transport == nullptr) {
            return std::unexpected(ServiceError {.code = ServiceErrorCode::dispatcher_required,
                                                 .message = "live service coordination requires a transport"});
        }
        if (config.mode == ExecutionMode::live && !config.replay_captures.empty()) {
            return std::unexpected(
                ServiceError {.code = ServiceErrorCode::invalid_specification,
                              .message = "live service coordination cannot consume replay captures"});
        }
        for (std::size_t index = 0; index < config.replay_captures.size(); ++index) {
            const auto &capture = config.replay_captures[index];
            if (capture.canonical_key.empty() || capture.request.request_id.empty() || capture.completion_order == 0 ||
                (capture.terminal_result.status == ServiceStatus::ok && !capture.terminal_result.value.has_value())) {
                return std::unexpected(ServiceError {.code = ServiceErrorCode::capture_mismatch,
                                                     .message = "a replay service capture is incomplete"});
            }
            for (std::size_t prior = 0; prior < index; ++prior) {
                if (config.replay_captures[prior].canonical_key == capture.canonical_key ||
                    config.replay_captures[prior].completion_order == capture.completion_order) {
                    return std::unexpected(
                        ServiceError {.code = ServiceErrorCode::capture_mismatch,
                                      .message = "service capture keys and completion order must be unique"});
                }
            }
        }
        auto group = ServiceTaskGroup::create(config.group_id, config.exit_policy, config.deterministic_seed,
                                              config.maximum_active);
        if (!group.has_value()) {
            return std::unexpected(group.error());
        }
        auto implementation = std::make_unique<Implementation>(config.mode, bindings, transport, std::move(*group));
        implementation->replay_captures = std::move(config.replay_captures);
        return ServiceCoordinator {std::move(implementation)};
    }

    ServiceCoordinator::ServiceCoordinator(std::unique_ptr<Implementation> implementation) noexcept:
        implementation_ {std::move(implementation)} {}
    ServiceCoordinator::ServiceCoordinator(ServiceCoordinator &&other) noexcept = default;
    ServiceCoordinator &ServiceCoordinator::operator=(ServiceCoordinator &&other) noexcept = default;
    ServiceCoordinator::~ServiceCoordinator() = default;

    std::expected<ServiceSchedule, ServiceError>
    ServiceCoordinator::schedule(const std::span<const CapabilityRequest> requests, const std::uint64_t now_unix_ms) {
        ServiceSchedule scheduled;
        std::vector<std::pair<Implementation::TrackedCall *, const ServiceCapture *>> replay_work;
        implementation_->calls.reserve(implementation_->calls.size() + requests.size());
        for (const auto &request : requests) {
            if (auto *existing = implementation_->find(request.request_id); existing != nullptr) {
                if (!same_request(existing->spec.request, request)) {
                    return std::unexpected(
                        ServiceError {.code = ServiceErrorCode::duplicate_request_mismatch,
                                      .message = "a capability request ID was reused with new semantics"});
                }
                ++scheduled.duplicate_requests;
                continue;
            }
            const auto binding = implementation_->bindings.resolve(request);
            if (!binding.has_value()) {
                return std::unexpected(binding.error());
            }
            ServiceCallSpec spec {
                .canonical_key = call_key(*binding, request),
                .request = request,
                .retry = binding->retry,
                .cache = binding->cache,
                .request_ceiling = binding->request_ceiling,
                .response_ceiling = binding->response_ceiling,
            };
            const auto task = implementation_->group.add_call(spec);
            if (!task.has_value()) {
                return std::unexpected(task.error());
            }
            implementation_->calls.push_back(Implementation::TrackedCall {
                .spec = std::move(spec),
                .capture_key = {},
                .task = *task,
                .current_attempt = std::nullopt,
                .retry_at_unix_ms = std::nullopt,
                .captured_attempts = {},
                .pending_cancel_capture = nullptr,
                .terminal = false,
            });
            auto &call = implementation_->calls.back();
            call.capture_key = capture_key(call.spec);

            if (implementation_->mode == ExecutionMode::replay) {
                const auto *capture = implementation_->replay_capture(call.capture_key);
                if (capture == nullptr) {
                    return std::unexpected(
                        ServiceError {.code = ServiceErrorCode::capture_missing,
                                      .message = "diagnostic replay has no captured service result"});
                }
                replay_work.emplace_back(&call, capture);
                continue;
            }

            auto started = implementation_->group.start(call.task, now_unix_ms, &implementation_->cache);
            if (!started.has_value()) {
                return std::unexpected(started.error());
            }
            if (started->cache_hit) {
                ++scheduled.cache_hits;
                implementation_->terminalize(call, *started->result, true);
                continue;
            }
            if (started->attempt.has_value()) {
                const auto dispatched =
                    dispatch_attempt(*implementation_, call, *started->attempt, now_unix_ms, &scheduled.attempts);
                if (!dispatched.has_value()) {
                    return std::unexpected(dispatched.error());
                }
            } else if (started->result.has_value()) {
                implementation_->terminalize(call, *started->result, false);
            }
        }

        std::ranges::sort(replay_work, [](const auto &left, const auto &right) {
            return left.second->completion_order < right.second->completion_order;
        });
        for (const auto &[call, capture] : replay_work) {
            const auto replayed = replay_one(*implementation_, *call, *capture, now_unix_ms);
            if (!replayed.has_value()) {
                return std::unexpected(replayed.error());
            }
            scheduled.cache_hits += capture->cache_hit ? 1U : 0U;
        }
        return scheduled;
    }

    std::expected<void, ServiceError> ServiceCoordinator::complete(const ServiceAttempt &attempt, ServiceResult result,
                                                                   const std::uint64_t completed_unix_ms) {
        auto *call = implementation_->find(attempt.task);
        if (call == nullptr) {
            return std::unexpected(ServiceError {.code = ServiceErrorCode::unknown_task,
                                                 .message = "the service attempt belongs to no coordinated task"});
        }
        if (implementation_->mode == ExecutionMode::replay) {
            return std::unexpected(ServiceError {.code = ServiceErrorCode::invalid_state,
                                                 .message = "replay service results come only from captures"});
        }
        return accept_result(*implementation_, *call, attempt, std::move(result), completed_unix_ms, true);
    }

    std::expected<std::vector<ServiceAttempt>, ServiceError> ServiceCoordinator::poll(const std::uint64_t now_unix_ms) {
        std::vector<ServiceAttempt> attempts;
        if (implementation_->mode == ExecutionMode::replay) {
            return attempts;
        }
        for (auto &call : implementation_->calls) {
            if (call.terminal || !call.retry_at_unix_ms.has_value() || now_unix_ms < *call.retry_at_unix_ms) {
                continue;
            }
            auto retried = implementation_->group.resume_retry(call.task, now_unix_ms);
            if (!retried.has_value()) {
                if (retried.error().code == ServiceErrorCode::deadline_exhausted) {
                    const auto terminal = implementation_->group.result(call.task);
                    if (terminal.has_value()) {
                        implementation_->terminalize(call, *terminal, false);
                        continue;
                    }
                }
                return std::unexpected(retried.error());
            }
            call.retry_at_unix_ms.reset();
            const auto dispatched = dispatch_attempt(*implementation_, call, *retried, now_unix_ms, &attempts);
            if (!dispatched.has_value()) {
                return std::unexpected(dispatched.error());
            }
        }
        return attempts;
    }

    std::expected<TaskGroupClose, ServiceError> ServiceCoordinator::close(const std::uint64_t now_unix_ms,
                                                                          const bool exceptional_exit) {
        std::vector<std::pair<TaskHandle, ServiceAttempt>> running;
        for (const auto &call : implementation_->calls) {
            if (call.current_attempt.has_value()) {
                running.emplace_back(call.task, *call.current_attempt);
            }
        }
        auto closed = implementation_->group.close(now_unix_ms, exceptional_exit);
        if (!closed.has_value()) {
            return std::unexpected(closed.error());
        }
        for (const auto task : closed->canceled) {
            auto *call = implementation_->find(task);
            if (call == nullptr || call->terminal) {
                continue;
            }
            const auto running_attempt =
                std::ranges::find(running, task, [](const auto &entry) { return entry.first; });
            if (implementation_->mode == ExecutionMode::live && running_attempt != running.end()) {
                implementation_->transport->cancel(running_attempt->second);
            }
            implementation_->terminalize(*call, canceled_result(), false);
            if (implementation_->mode == ExecutionMode::replay && call->pending_cancel_capture != nullptr &&
                !same_result(call->pending_cancel_capture->terminal_result, canceled_result())) {
                return std::unexpected(ServiceError {.code = ServiceErrorCode::capture_mismatch,
                                                     .message = "the replayed cancellation terminal diverged"});
            }
            call->pending_cancel_capture = nullptr;
        }
        return *closed;
    }

    std::vector<CapabilityResponse> ServiceCoordinator::take_responses() {
        auto result = std::move(implementation_->responses);
        implementation_->responses.clear();
        return result;
    }

    std::span<const ServiceCapture> ServiceCoordinator::captures() const noexcept {
        return implementation_->recorded_captures;
    }

    std::expected<ServiceTaskState, ServiceError> ServiceCoordinator::state(const RequestId &request) const {
        const auto *call = implementation_->find(request);
        if (call == nullptr) {
            return std::unexpected(ServiceError {.code = ServiceErrorCode::unknown_task,
                                                 .message = "the service request belongs to no coordinated task"});
        }
        return implementation_->group.state(call->task);
    }

    std::uint64_t ServiceCoordinator::live_dispatches() const noexcept { return implementation_->live_dispatch_count; }

    std::uint64_t ServiceCoordinator::blocked_replay_dispatches() const noexcept {
        return implementation_->blocked_dispatch_count;
    }

} // namespace rule_engine::python::effects
