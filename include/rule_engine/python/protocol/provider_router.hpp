#pragma once

#include "rule_engine/python/protocol/types.hpp"

#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace rule_engine::python::protocol_v2 {

    enum struct ProviderDispatchErrorCode : std::uint8_t {
        unknown_route,
        duplicate_route,
        invalid_request,
        provider_failure,
        provider_violation,
        canceled,
    };

    struct ProviderDispatchError {
        ProviderDispatchErrorCode code {ProviderDispatchErrorCode::provider_failure};
        std::string message;
    };

    struct IWindowsAgentProvider {
        virtual ~IWindowsAgentProvider() = default;
        [[nodiscard]] virtual std::expected<std::vector<FactResponse>, ProviderDispatchError>
        resolve_facts(std::span<const FactRequest> requests) noexcept = 0;
        [[nodiscard]] virtual std::expected<std::vector<ScanResponse>, ProviderDispatchError>
        resolve_scans(std::span<const ScanRequest> requests) noexcept = 0;
        virtual void cancel(std::span<const RequestId> requests) noexcept = 0;
    };

    struct WindowsAgentProviderRouter {
        [[nodiscard]] std::expected<void, ProviderDispatchError> bind(std::string route,
                                                                      IWindowsAgentProvider &provider);

        [[nodiscard]] std::expected<WorkResultMessage, ProviderDispatchError>
        dispatch(const WorkLeaseMessage &work, const ProtocolLimits &limits = {}) const;

        [[nodiscard]] std::expected<void, ProviderDispatchError> cancel(const CancelWorkMessage &message) const;

    private:
        struct Binding {
            std::string route;
            IWindowsAgentProvider *provider {};
        };

        [[nodiscard]] IWindowsAgentProvider *find(std::string_view route) const noexcept;

        std::vector<Binding> bindings_;
    };

} // namespace rule_engine::python::protocol_v2
