#include "rule_engine/python/effects/service.hpp"

#include <algorithm>
#include <limits>
#include <utility>

namespace rule_engine::python::effects {
    namespace {

        std::string cache_key(const ServiceCallSpec &spec) {
            if (!spec.cache.has_value()) {
                return {};
            }
            return stable_domain_key("service-cache-v1", {spec.cache->scope_key, spec.canonical_key});
        }

        std::uint64_t saturating_add(const std::uint64_t left, const std::uint64_t right) noexcept {
            if (right > std::numeric_limits<std::uint64_t>::max() - left) {
                return std::numeric_limits<std::uint64_t>::max();
            }
            return left + right;
        }

        std::uint64_t stable_hash(const std::string_view value) noexcept {
            std::uint64_t hash = 1469598103934665603ULL;
            for (const auto character : value) {
                hash ^= static_cast<std::uint8_t>(character);
                hash *= 1099511628211ULL;
            }
            return hash;
        }

        bool valid_specification(const ServiceCallSpec &spec) noexcept {
            if (spec.canonical_key.empty() || spec.request.request_id.empty() || spec.request.capability.empty() ||
                spec.request.request_schema.empty() || !spec.request.arguments.value.valid() ||
                spec.request.arguments.canonical_digest.empty() || spec.request.deadline_unix_ms == 0 ||
                spec.retry.maximum_attempts == 0 || spec.retry.maximum_attempts > 2 ||
                spec.retry.base_delay_ms > spec.retry.maximum_delay_ms) {
                return false;
            }
            if (spec.cache.has_value() && (spec.cache->scope_key.empty() || spec.cache->ttl_ms == 0)) {
                return false;
            }
            return true;
        }

        ServiceResult timeout_result() {
            return ServiceResult {
                .status = ServiceStatus::request_timeout,
                .value = std::nullopt,
                .retry_after_ms = std::nullopt,
                .diagnostic_code = "SERVICE_DEADLINE_EXHAUSTED",
            };
        }

        ServiceResult canceled_result() {
            return ServiceResult {
                .status = ServiceStatus::canceled,
                .value = std::nullopt,
                .retry_after_ms = std::nullopt,
                .diagnostic_code = "SERVICE_TASK_CANCELED",
            };
        }

    } // namespace

    bool service_status_is_transient(const ServiceStatus status) noexcept {
        return status == ServiceStatus::transport_error || status == ServiceStatus::request_timeout ||
               status == ServiceStatus::too_early || status == ServiceStatus::rate_limited ||
               status == ServiceStatus::server_error;
    }

    std::optional<ServiceResult> ServiceCache::lookup(const ServiceCallSpec &spec,
                                                      const std::uint64_t now_unix_ms) const {
        const auto key = cache_key(spec);
        if (key.empty()) {
            return std::nullopt;
        }
        const auto found = std::ranges::find(entries_, key, &Entry::key);
        if (found == entries_.end() || found->expires_unix_ms <= now_unix_ms) {
            return std::nullopt;
        }
        return found->result;
    }

    std::expected<void, ServiceError> ServiceCache::store(const ServiceCallSpec &spec, const ServiceResult &result,
                                                          const std::uint64_t now_unix_ms) {
        if (!spec.cache.has_value() || result.status != ServiceStatus::ok || !result.value.has_value()) {
            return std::unexpected(ServiceError {
                .code = ServiceErrorCode::cache_policy_mismatch,
                .message = "only successful typed responses with an explicit cache policy can be cached",
            });
        }
        const auto key = cache_key(spec);
        const auto expiry = saturating_add(now_unix_ms, spec.cache->ttl_ms);
        const auto found = std::ranges::find(entries_, key, &Entry::key);
        if (found != entries_.end()) {
            found->result = result;
            found->expires_unix_ms = expiry;
            return {};
        }
        entries_.push_back(Entry {.key = key, .result = result, .expires_unix_ms = expiry});
        return {};
    }

    void ServiceCache::expire(const std::uint64_t now_unix_ms) {
        std::erase_if(entries_, [&](const Entry &entry) { return entry.expires_unix_ms <= now_unix_ms; });
    }

    std::size_t ServiceCache::size() const noexcept { return entries_.size(); }

    struct ServiceTaskGroup::Implementation {
        struct Call {
            TaskHandle handle;
            ServiceCallSpec spec;
            ServiceTaskState state {ServiceTaskState::cold};
            std::uint64_t effective_deadline_unix_ms {};
            std::uint64_t retry_at_unix_ms {};
            std::uint32_t attempts_started {};
            std::optional<ServiceResult> result;
        };

        std::uint64_t group_id {};
        TaskGroupExitPolicy exit_policy {TaskGroupExitPolicy::cancel_pending};
        std::uint64_t deterministic_seed {};
        std::uint32_t maximum_active {};
        std::uint32_t active {};
        std::uint64_t next_call {1};
        bool closing {};
        bool closed {};
        std::vector<Call> calls;

        [[nodiscard]] Call *find(const TaskHandle handle) noexcept {
            if (handle.group != group_id) {
                return nullptr;
            }
            const auto found = std::ranges::find(calls, handle, &Call::handle);
            return found == calls.end() ? nullptr : &*found;
        }

        [[nodiscard]] const Call *find(const TaskHandle handle) const noexcept {
            if (handle.group != group_id) {
                return nullptr;
            }
            const auto found = std::ranges::find(calls, handle, &Call::handle);
            return found == calls.end() ? nullptr : &*found;
        }

        [[nodiscard]] std::uint64_t retry_delay(const Call &call) const noexcept {
            if (call.result.has_value() && call.result->retry_after_ms.has_value()) {
                return std::min(*call.result->retry_after_ms, call.spec.retry.maximum_delay_ms);
            }

            const auto exponent = call.attempts_started == 0 ? 0U : call.attempts_started - 1U;
            const auto shift = std::min(exponent, 20U);
            const auto multiplier = std::uint64_t {1} << shift;
            const auto unclamped =
                call.spec.retry.base_delay_ms > std::numeric_limits<std::uint64_t>::max() / multiplier ?
                    std::numeric_limits<std::uint64_t>::max() :
                    call.spec.retry.base_delay_ms * multiplier;
            const auto ceiling = std::min(unclamped, call.spec.retry.maximum_delay_ms);
            const auto seed_text =
                stable_domain_key("service-jitter-v1", {call.spec.canonical_key, std::to_string(call.attempts_started),
                                                        std::to_string(deterministic_seed)});
            return ceiling == 0 ? 0 : stable_hash(seed_text) % (ceiling + 1U);
        }

        [[nodiscard]] ServiceAttempt begin_attempt(Call &call) {
            ++call.attempts_started;
            ++active;
            call.state = ServiceTaskState::running;
            auto envelope = call.spec.request;
            envelope.deadline_unix_ms = call.effective_deadline_unix_ms;
            return ServiceAttempt {
                .task = call.handle,
                .request = call.spec.request.request_id,
                .attempt = call.attempts_started,
                .deadline_unix_ms = call.effective_deadline_unix_ms,
                .idempotency_key =
                    stable_domain_key("service-call-v1", {call.spec.canonical_key, call.spec.request.request_id.value}),
                .envelope = std::move(envelope),
            };
        }

        [[nodiscard]] bool has_pending() const noexcept {
            return std::ranges::any_of(calls, [](const Call &call) {
                return call.state == ServiceTaskState::running || call.state == ServiceTaskState::retry_wait;
            });
        }

        void finish_waiting_close_if_ready() noexcept {
            if (closing && exit_policy == TaskGroupExitPolicy::wait_pending && !has_pending()) {
                closed = true;
            }
        }
    };

    std::expected<ServiceTaskGroup, ServiceError> ServiceTaskGroup::create(const std::uint64_t group_id,
                                                                           const TaskGroupExitPolicy exit_policy,
                                                                           const std::uint64_t deterministic_seed,
                                                                           const std::uint32_t maximum_active) {
        if (group_id == 0 || maximum_active == 0 || maximum_active > balanced_v1.normal.active_service_calls) {
            return std::unexpected(ServiceError {
                .code = ServiceErrorCode::invalid_specification,
                .message = "a task group requires a non-zero ID and active limit within the selected profile",
            });
        }
        auto implementation = std::make_unique<Implementation>();
        implementation->group_id = group_id;
        implementation->exit_policy = exit_policy;
        implementation->deterministic_seed = deterministic_seed;
        implementation->maximum_active = maximum_active;
        return ServiceTaskGroup {std::move(implementation)};
    }

    ServiceTaskGroup::ServiceTaskGroup(std::unique_ptr<Implementation> implementation) noexcept:
        implementation_ {std::move(implementation)} {}

    ServiceTaskGroup::ServiceTaskGroup(ServiceTaskGroup &&other) noexcept = default;
    ServiceTaskGroup &ServiceTaskGroup::operator=(ServiceTaskGroup &&other) noexcept = default;
    ServiceTaskGroup::~ServiceTaskGroup() = default;

    std::expected<TaskHandle, ServiceError> ServiceTaskGroup::add_call(ServiceCallSpec spec) {
        if (implementation_->closing || implementation_->closed) {
            return std::unexpected(ServiceError {.code = ServiceErrorCode::group_closing,
                                                 .message = "no task can be added after task-group close begins"});
        }
        if (!valid_specification(spec) || implementation_->calls.size() >= balanced_v1.normal.service_calls) {
            return std::unexpected(ServiceError {
                .code = ServiceErrorCode::invalid_specification,
                .message = "the service call is invalid or the scheduled-call limit is exhausted",
            });
        }
        if (!may_flow_to(spec.request.arguments.label, spec.request_ceiling)) {
            return std::unexpected(ServiceError {
                .code = ServiceErrorCode::request_label_rejected,
                .message = "the service request exceeds the capability classification ceiling",
            });
        }
        const TaskHandle handle {.group = implementation_->group_id, .call = implementation_->next_call++};
        implementation_->calls.push_back(Implementation::Call {
            .handle = handle,
            .spec = std::move(spec),
            .state = ServiceTaskState::cold,
            .effective_deadline_unix_ms = 0,
            .retry_at_unix_ms = 0,
            .attempts_started = 0,
            .result = std::nullopt,
        });
        return handle;
    }

    std::expected<ServiceStart, ServiceError>
    ServiceTaskGroup::start(const TaskHandle task, const std::uint64_t now_unix_ms, ServiceCache *const cache) {
        auto *call = implementation_->find(task);
        if (call == nullptr) {
            return std::unexpected(ServiceError {.code = task.group == implementation_->group_id ?
                                                             ServiceErrorCode::unknown_task :
                                                             ServiceErrorCode::wrong_group,
                                                 .message = "the task handle does not belong to this task group"});
        }
        if (implementation_->closing || implementation_->closed) {
            return std::unexpected(ServiceError {.code = ServiceErrorCode::group_closing,
                                                 .message = "a task cannot start after task-group close begins"});
        }
        if (call->state != ServiceTaskState::cold) {
            return std::unexpected(ServiceError {.code = ServiceErrorCode::invalid_state,
                                                 .message = "only a cold service task can start"});
        }

        if (cache != nullptr) {
            const auto cached = cache->lookup(call->spec, now_unix_ms);
            if (cached.has_value()) {
                call->state = ServiceTaskState::completed;
                call->result = *cached;
                return ServiceStart {
                    .state = call->state,
                    .attempt = std::nullopt,
                    .result = call->result,
                    .cache_hit = true,
                };
            }
        }

        const auto profile_deadline = saturating_add(
            now_unix_ms, static_cast<std::uint64_t>(balanced_v1.normal.maximum_service_deadline.count()));
        call->effective_deadline_unix_ms = std::min(call->spec.request.deadline_unix_ms, profile_deadline);
        if (now_unix_ms >= call->effective_deadline_unix_ms) {
            call->state = ServiceTaskState::failed;
            call->result = timeout_result();
            return ServiceStart {
                .state = call->state, .attempt = std::nullopt, .result = call->result, .cache_hit = false};
        }
        if (implementation_->active >= implementation_->maximum_active) {
            return std::unexpected(ServiceError {.code = ServiceErrorCode::active_limit_exhausted,
                                                 .message = "the task-group active service limit is exhausted"});
        }
        return ServiceStart {
            .state = ServiceTaskState::running,
            .attempt = implementation_->begin_attempt(*call),
            .result = std::nullopt,
            .cache_hit = false,
        };
    }

    std::expected<ServiceTransition, ServiceError>
    ServiceTaskGroup::accept(const TaskHandle task, const std::uint32_t attempt, ServiceResult result,
                             const std::uint64_t now_unix_ms, ServiceCache *const cache) {
        auto *call = implementation_->find(task);
        if (call == nullptr) {
            return std::unexpected(ServiceError {.code = task.group == implementation_->group_id ?
                                                             ServiceErrorCode::unknown_task :
                                                             ServiceErrorCode::wrong_group,
                                                 .message = "the task handle does not belong to this task group"});
        }
        if (call->state != ServiceTaskState::running) {
            return std::unexpected(ServiceError {.code = ServiceErrorCode::invalid_state,
                                                 .message = "only a running task can accept a transport result"});
        }
        if (attempt != call->attempts_started) {
            return std::unexpected(ServiceError {.code = ServiceErrorCode::stale_attempt,
                                                 .message = "a stale service attempt cannot complete the task"});
        }
        --implementation_->active;

        if (now_unix_ms >= call->effective_deadline_unix_ms) {
            result = timeout_result();
        }
        if (result.status == ServiceStatus::ok && !result.value.has_value()) {
            call->state = ServiceTaskState::failed;
            call->result = ServiceResult {.status = ServiceStatus::malformed_response,
                                          .value = std::nullopt,
                                          .retry_after_ms = std::nullopt,
                                          .diagnostic_code = "SERVICE_OK_WITHOUT_VALUE"};
            implementation_->finish_waiting_close_if_ready();
            return std::unexpected(ServiceError {.code = ServiceErrorCode::malformed_response,
                                                 .message = "a successful service response requires a typed value"});
        }
        if (result.value.has_value() && !may_flow_to(result.value->label, call->spec.response_ceiling)) {
            call->state = ServiceTaskState::failed;
            call->result = ServiceResult {.status = ServiceStatus::malformed_response,
                                          .value = std::nullopt,
                                          .retry_after_ms = std::nullopt,
                                          .diagnostic_code = "SERVICE_RESPONSE_LABEL_REJECTED"};
            implementation_->finish_waiting_close_if_ready();
            return std::unexpected(ServiceError {
                .code = ServiceErrorCode::response_label_rejected,
                .message = "the service response exceeds the capability classification ceiling",
            });
        }

        call->result = result;
        if (result.status == ServiceStatus::ok) {
            call->state = ServiceTaskState::completed;
            if (cache != nullptr && call->spec.cache.has_value()) {
                const auto stored = cache->store(call->spec, result, now_unix_ms);
                if (!stored.has_value()) {
                    implementation_->finish_waiting_close_if_ready();
                    return std::unexpected(stored.error());
                }
            }
            implementation_->finish_waiting_close_if_ready();
            return ServiceTransition {.state = call->state, .retry_at_unix_ms = std::nullopt, .result = call->result};
        }

        if (service_status_is_transient(result.status) && call->attempts_started < call->spec.retry.maximum_attempts) {
            const auto retry_at = saturating_add(now_unix_ms, implementation_->retry_delay(*call));
            if (retry_at < call->effective_deadline_unix_ms) {
                call->state = ServiceTaskState::retry_wait;
                call->retry_at_unix_ms = retry_at;
                return ServiceTransition {.state = call->state, .retry_at_unix_ms = retry_at, .result = std::nullopt};
            }
        }

        call->state = ServiceTaskState::failed;
        implementation_->finish_waiting_close_if_ready();
        return ServiceTransition {.state = call->state, .retry_at_unix_ms = std::nullopt, .result = call->result};
    }

    std::expected<ServiceAttempt, ServiceError> ServiceTaskGroup::resume_retry(const TaskHandle task,
                                                                               const std::uint64_t now_unix_ms) {
        auto *call = implementation_->find(task);
        if (call == nullptr) {
            return std::unexpected(ServiceError {.code = task.group == implementation_->group_id ?
                                                             ServiceErrorCode::unknown_task :
                                                             ServiceErrorCode::wrong_group,
                                                 .message = "the task handle does not belong to this task group"});
        }
        if (call->state != ServiceTaskState::retry_wait) {
            return std::unexpected(
                ServiceError {.code = ServiceErrorCode::invalid_state, .message = "only a retry-wait task can resume"});
        }
        if (now_unix_ms < call->retry_at_unix_ms) {
            return std::unexpected(ServiceError {.code = ServiceErrorCode::invalid_state,
                                                 .message = "the deterministic retry deadline has not arrived"});
        }
        if (now_unix_ms >= call->effective_deadline_unix_ms) {
            call->state = ServiceTaskState::failed;
            call->result = timeout_result();
            implementation_->finish_waiting_close_if_ready();
            return std::unexpected(ServiceError {.code = ServiceErrorCode::deadline_exhausted,
                                                 .message = "the original service deadline is exhausted"});
        }
        if (implementation_->active >= implementation_->maximum_active) {
            return std::unexpected(ServiceError {.code = ServiceErrorCode::active_limit_exhausted,
                                                 .message = "the task-group active service limit is exhausted"});
        }
        return implementation_->begin_attempt(*call);
    }

    std::expected<TaskGroupClose, ServiceError> ServiceTaskGroup::close(const std::uint64_t now_unix_ms,
                                                                        const bool exceptional_exit) {
        (void) now_unix_ms;
        if (implementation_->closed) {
            return TaskGroupClose {.closed = true, .canceled = {}, .waiting = {}};
        }
        implementation_->closing = true;
        TaskGroupClose result;

        for (auto &call : implementation_->calls) {
            if (call.state == ServiceTaskState::cold) {
                call.state = ServiceTaskState::canceled;
                call.result = canceled_result();
                result.canceled.push_back(call.handle);
                continue;
            }
            const auto pending = call.state == ServiceTaskState::running || call.state == ServiceTaskState::retry_wait;
            if (!pending) {
                continue;
            }
            if (!exceptional_exit && implementation_->exit_policy == TaskGroupExitPolicy::wait_pending) {
                result.waiting.push_back(call.handle);
                continue;
            }
            if (call.state == ServiceTaskState::running) {
                --implementation_->active;
            }
            call.state = ServiceTaskState::canceled;
            call.result = canceled_result();
            result.canceled.push_back(call.handle);
        }

        result.closed = result.waiting.empty();
        implementation_->closed = result.closed;
        return result;
    }

    std::expected<ServiceTaskState, ServiceError> ServiceTaskGroup::state(const TaskHandle task) const {
        const auto *call = implementation_->find(task);
        if (call == nullptr) {
            return std::unexpected(ServiceError {.code = task.group == implementation_->group_id ?
                                                             ServiceErrorCode::unknown_task :
                                                             ServiceErrorCode::wrong_group,
                                                 .message = "the task handle does not belong to this task group"});
        }
        return call->state;
    }

    std::expected<ServiceResult, ServiceError> ServiceTaskGroup::result(const TaskHandle task) const {
        const auto *call = implementation_->find(task);
        if (call == nullptr) {
            return std::unexpected(ServiceError {.code = task.group == implementation_->group_id ?
                                                             ServiceErrorCode::unknown_task :
                                                             ServiceErrorCode::wrong_group,
                                                 .message = "the task handle does not belong to this task group"});
        }
        if (!call->result.has_value()) {
            return std::unexpected(ServiceError {.code = ServiceErrorCode::invalid_state,
                                                 .message = "the service task has no terminal result"});
        }
        return *call->result;
    }

    bool ServiceTaskGroup::closed() const noexcept { return implementation_->closed; }

    std::uint32_t ServiceTaskGroup::active_count() const noexcept { return implementation_->active; }

} // namespace rule_engine::python::effects
