#pragma once

#include "rule_engine/python/effects/service.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace rule_engine::python::effects {

    struct ServiceBindingPolicy {
        std::string binding_key;
        CapabilityId capability;
        SchemaId request_schema;
        ServiceRetryPolicy retry;
        std::optional<ServiceCachePolicy> cache;
        DataLabel request_ceiling;
        DataLabel response_ceiling;
    };

    struct IServiceBindingResolver {
        IServiceBindingResolver() = default;
        IServiceBindingResolver(IServiceBindingResolver &&) noexcept = default;
        IServiceBindingResolver &operator=(IServiceBindingResolver &&) noexcept = default;
        IServiceBindingResolver(const IServiceBindingResolver &) = delete;
        IServiceBindingResolver &operator=(const IServiceBindingResolver &) = delete;
        virtual ~IServiceBindingResolver() = default;
        [[nodiscard]] virtual std::expected<ServiceBindingPolicy, ServiceError>
        resolve(const CapabilityRequest &request) const = 0;
    };

    struct StaticServiceBindingResolver final: IServiceBindingResolver {
        [[nodiscard]] static std::expected<StaticServiceBindingResolver, ServiceError>
        create(std::vector<ServiceBindingPolicy> policies);

        [[nodiscard]] std::expected<ServiceBindingPolicy, ServiceError>
        resolve(const CapabilityRequest &request) const override;

    private:
        explicit StaticServiceBindingResolver(std::vector<ServiceBindingPolicy> policies) noexcept;
        std::vector<ServiceBindingPolicy> policies_;
    };

    // Dispatch starts a transport attempt but cannot resolve policy or mutate VM
    // state. Immediate refusal is represented as a typed ServiceResult.
    struct IServiceTransport {
        IServiceTransport() = default;
        IServiceTransport(const IServiceTransport &) = delete;
        IServiceTransport &operator=(const IServiceTransport &) = delete;
        virtual ~IServiceTransport() = default;
        [[nodiscard]] virtual std::expected<void, ServiceResult> dispatch(const ServiceAttempt &attempt) = 0;
        virtual void cancel(const ServiceAttempt &attempt) noexcept = 0;
    };

    struct CapturedServiceAttempt {
        std::uint32_t attempt {};
        std::uint64_t completed_unix_ms {};
        ServiceResult result;
    };

    struct ServiceCapture {
        std::string canonical_key;
        CapabilityRequest request;
        bool cache_hit {};
        std::vector<CapturedServiceAttempt> attempts;
        ServiceResult terminal_result;
        std::uint64_t completion_order {};
    };

    struct ServiceCoordinatorConfig {
        std::uint64_t group_id {};
        TaskGroupExitPolicy exit_policy {TaskGroupExitPolicy::cancel_pending};
        std::uint64_t deterministic_seed {};
        std::uint32_t maximum_active {balanced_v1.normal.active_service_calls};
        ExecutionMode mode {ExecutionMode::live};
        std::vector<ServiceCapture> replay_captures;
    };

    struct ServiceSchedule {
        std::vector<ServiceAttempt> attempts;
        std::size_t duplicate_requests {};
        std::size_t cache_hits {};
    };

    struct ServiceCoordinator {
        struct Implementation;

        [[nodiscard]] static std::expected<ServiceCoordinator, ServiceError>
        create(ServiceCoordinatorConfig config, const IServiceBindingResolver &bindings,
               IServiceTransport *transport = nullptr);

        ServiceCoordinator(ServiceCoordinator &&other) noexcept;
        ServiceCoordinator &operator=(ServiceCoordinator &&other) noexcept;
        ServiceCoordinator(const ServiceCoordinator &) = delete;
        ServiceCoordinator &operator=(const ServiceCoordinator &) = delete;
        ~ServiceCoordinator();

        [[nodiscard]] std::expected<ServiceSchedule, ServiceError> schedule(std::span<const CapabilityRequest> requests,
                                                                            std::uint64_t now_unix_ms);
        [[nodiscard]] std::expected<void, ServiceError> complete(const ServiceAttempt &attempt, ServiceResult result,
                                                                 std::uint64_t completed_unix_ms);
        [[nodiscard]] std::expected<std::vector<ServiceAttempt>, ServiceError> poll(std::uint64_t now_unix_ms);
        [[nodiscard]] std::expected<TaskGroupClose, ServiceError> close(std::uint64_t now_unix_ms,
                                                                        bool exceptional_exit);

        [[nodiscard]] std::vector<CapabilityResponse> take_responses();
        [[nodiscard]] std::span<const ServiceCapture> captures() const noexcept;
        [[nodiscard]] std::expected<ServiceTaskState, ServiceError> state(const RequestId &request) const;
        [[nodiscard]] std::uint64_t live_dispatches() const noexcept;
        [[nodiscard]] std::uint64_t blocked_replay_dispatches() const noexcept;

    private:
        explicit ServiceCoordinator(std::unique_ptr<Implementation> implementation) noexcept;
        std::unique_ptr<Implementation> implementation_;
    };

} // namespace rule_engine::python::effects
