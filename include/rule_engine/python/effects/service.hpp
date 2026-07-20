#pragma once

#include "rule_engine/python/effects/common.hpp"

#include <compare>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace rule_engine::python::effects {

    enum struct ServiceStatus : std::uint8_t {
        ok,
        transport_error,
        request_timeout,
        too_early,
        rate_limited,
        server_error,
        client_error,
        malformed_response,
        canceled,
    };

    [[nodiscard]] bool service_status_is_transient(ServiceStatus status) noexcept;

    struct ServiceResult {
        ServiceStatus status {ServiceStatus::transport_error};
        std::optional<FrozenValue> value;
        std::optional<std::uint64_t> retry_after_ms;
        std::string diagnostic_code;
    };

    struct ServiceRetryPolicy {
        std::uint32_t maximum_attempts {2};
        std::uint64_t base_delay_ms {100};
        std::uint64_t maximum_delay_ms {1'000};
    };

    struct ServiceCachePolicy {
        std::string scope_key;
        std::uint64_t ttl_ms {};
    };

    struct ServiceCallSpec {
        std::string canonical_key;
        CapabilityRequest request;
        ServiceRetryPolicy retry;
        std::optional<ServiceCachePolicy> cache;
        DataLabel request_ceiling;
        DataLabel response_ceiling;
    };

    struct TaskHandle {
        std::uint64_t group {};
        std::uint64_t call {};
        auto operator<=>(const TaskHandle &) const = default;
    };

    enum struct ServiceTaskState : std::uint8_t { cold, running, retry_wait, completed, failed, canceled };
    enum struct TaskGroupExitPolicy : std::uint8_t { cancel_pending, wait_pending };

    struct ServiceAttempt {
        TaskHandle task;
        RequestId request;
        std::uint32_t attempt {};
        std::uint64_t deadline_unix_ms {};
        std::string idempotency_key;
        CapabilityRequest envelope;
    };

    enum struct ServiceErrorCode : std::uint8_t {
        invalid_specification,
        wrong_group,
        unknown_task,
        invalid_state,
        group_closing,
        active_limit_exhausted,
        deadline_exhausted,
        stale_attempt,
        request_label_rejected,
        response_label_rejected,
        malformed_response,
        cache_policy_mismatch,
    };

    struct ServiceError {
        ServiceErrorCode code {};
        std::string message;
    };

    struct ServiceStart {
        ServiceTaskState state {ServiceTaskState::cold};
        std::optional<ServiceAttempt> attempt;
        std::optional<ServiceResult> result;
        bool cache_hit {};
    };

    struct ServiceTransition {
        ServiceTaskState state {ServiceTaskState::failed};
        std::optional<std::uint64_t> retry_at_unix_ms;
        std::optional<ServiceResult> result;
    };

    struct TaskGroupClose {
        bool closed {};
        std::vector<TaskHandle> canceled;
        std::vector<TaskHandle> waiting;
    };

    struct ServiceCache {
        struct Entry {
            std::string key;
            ServiceResult result;
            std::uint64_t expires_unix_ms {};
        };

        [[nodiscard]] std::optional<ServiceResult> lookup(const ServiceCallSpec &spec, std::uint64_t now_unix_ms) const;
        [[nodiscard]] std::expected<void, ServiceError> store(const ServiceCallSpec &spec, const ServiceResult &result,
                                                              std::uint64_t now_unix_ms);
        void expire(std::uint64_t now_unix_ms);
        [[nodiscard]] std::size_t size() const noexcept;

    private:
        std::vector<Entry> entries_;
    };

    struct ServiceTaskGroup {
        struct Implementation;

        [[nodiscard]] static std::expected<ServiceTaskGroup, ServiceError>
        create(std::uint64_t group_id, TaskGroupExitPolicy exit_policy, std::uint64_t deterministic_seed,
               std::uint32_t maximum_active = balanced_v1.normal.active_service_calls);

        ServiceTaskGroup(ServiceTaskGroup &&other) noexcept;
        ServiceTaskGroup &operator=(ServiceTaskGroup &&other) noexcept;
        ServiceTaskGroup(const ServiceTaskGroup &) = delete;
        ServiceTaskGroup &operator=(const ServiceTaskGroup &) = delete;
        ~ServiceTaskGroup();

        [[nodiscard]] std::expected<TaskHandle, ServiceError> add_call(ServiceCallSpec spec);
        [[nodiscard]] std::expected<ServiceStart, ServiceError> start(TaskHandle task, std::uint64_t now_unix_ms,
                                                                      ServiceCache *cache = nullptr);
        [[nodiscard]] std::expected<ServiceTransition, ServiceError> accept(TaskHandle task, std::uint32_t attempt,
                                                                            ServiceResult result,
                                                                            std::uint64_t now_unix_ms,
                                                                            ServiceCache *cache = nullptr);
        [[nodiscard]] std::expected<ServiceAttempt, ServiceError> resume_retry(TaskHandle task,
                                                                               std::uint64_t now_unix_ms);
        [[nodiscard]] std::expected<TaskGroupClose, ServiceError> close(std::uint64_t now_unix_ms,
                                                                        bool exceptional_exit);

        [[nodiscard]] std::expected<ServiceTaskState, ServiceError> state(TaskHandle task) const;
        [[nodiscard]] std::expected<ServiceResult, ServiceError> result(TaskHandle task) const;
        [[nodiscard]] bool closed() const noexcept;
        [[nodiscard]] std::uint32_t active_count() const noexcept;

    private:
        explicit ServiceTaskGroup(std::unique_ptr<Implementation> implementation) noexcept;

        std::unique_ptr<Implementation> implementation_;
    };

} // namespace rule_engine::python::effects
