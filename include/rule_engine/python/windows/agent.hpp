#pragma once

#include "rule_engine/python/protocol/network.hpp"
#include "rule_engine/python/windows/runtime.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <vector>

namespace rule_engine::python::windows {

    inline constexpr std::string_view agent_version = "1.0.0";
    inline constexpr auto minimum_inventory_refresh_interval = std::chrono::seconds {1};
    inline constexpr auto maximum_inventory_refresh_interval = std::chrono::hours {24};

    enum struct AgentFailureCode : std::uint8_t {
        configuration,
        dependency,
        transport,
        authentication,
        protocol,
        persistence,
        provider,
        canceled,
        invariant,
    };

    struct AgentFailure {
        AgentFailureCode code {AgentFailureCode::configuration};
        std::string message;
        std::size_t line {};
    };

    struct WindowsAgentConfig {
        std::filesystem::path spool_path;
        std::filesystem::path certificate_path;
        std::filesystem::path private_key_path;
        std::filesystem::path ca_path;
        std::filesystem::path crl_path;
        std::vector<protocol_v2::TcpEndpoint> endpoints;
        std::string server_name;
        std::string server_uri;
        std::string server_fingerprint_sha256;
        PeerId peer;
        std::uint64_t active_generation {};
        bool require_hard_resolver_bounds {true};
        bool require_crl {};
        protocol_v2::ProtocolLimits protocol_limits;
        protocol_v2::AgentSpoolLimits spool_limits;
        protocol_v2::SocketTimeouts socket_timeouts;
        protocol_v2::ReconnectPolicy reconnect_policy;
        std::chrono::milliseconds maximum_work_horizon {60'000};
        std::chrono::milliseconds inventory_refresh_interval {300'000};
    };

    [[nodiscard]] std::expected<WindowsAgentConfig, AgentFailure>
    parse_windows_agent_config(std::string_view source) noexcept;
    [[nodiscard]] std::expected<WindowsAgentConfig, AgentFailure>
    load_windows_agent_config(const std::filesystem::path &path) noexcept;
    [[nodiscard]] std::expected<void, AgentFailure>
    validate_windows_agent_config_files(const WindowsAgentConfig &configuration) noexcept;
    [[nodiscard]] std::expected<void, AgentFailure>
    validate_windows_agent_dependencies(const WindowsAgentConfig &configuration) noexcept;

    enum struct AgentCommandMode : std::uint8_t { run, validate_config, help, version };

    struct AgentCommand {
        AgentCommandMode mode {AgentCommandMode::run};
        std::filesystem::path configuration_path;
    };

    [[nodiscard]] std::expected<AgentCommand, AgentFailure>
    parse_windows_agent_command(std::span<const std::string_view> arguments) noexcept;
    [[nodiscard]] std::string_view windows_agent_help() noexcept;

    struct AgentSessionHandshake {
        protocol_v2::ServerHelloMessage server_hello;
        std::size_t replayed_records {};
    };

    // Injectable transport seam used by the production TLS session and by
    // deterministic loop tests. The protocol spool remains the only source of
    // outbound durable messages across reconnects.
    struct IWindowsAgentSession {
        virtual ~IWindowsAgentSession() = default;
        [[nodiscard]] virtual std::expected<AgentSessionHandshake, protocol_v2::ProtocolError>
        reconnect(protocol_v2::PersistentAgentSession &session, protocol_v2::AgentHelloMessage hello,
                  std::stop_token cancellation) noexcept = 0;
        [[nodiscard]] virtual std::expected<protocol_v2::PeerEnvelope, protocol_v2::ProtocolError>
        receive(std::stop_token cancellation) noexcept = 0;
        // Returns false at the deadline without consuming TLS or frame bytes.
        [[nodiscard]] virtual std::expected<bool, protocol_v2::ProtocolError>
        wait_readable_until(std::chrono::steady_clock::time_point deadline, std::stop_token cancellation) noexcept = 0;
        [[nodiscard]] virtual std::expected<void, protocol_v2::ProtocolError>
        send(const protocol_v2::PeerEnvelope &envelope, std::stop_token cancellation) noexcept = 0;
        virtual void shutdown() noexcept = 0;
    };

    [[nodiscard]] std::expected<std::unique_ptr<IWindowsAgentSession>, AgentFailure>
    make_tls_windows_agent_session(const WindowsAgentConfig &configuration) noexcept;

    struct IWindowsAgentProviderRuntime {
        virtual ~IWindowsAgentProviderRuntime() = default;
        [[nodiscard]] virtual std::expected<protocol_v2::WorkResultMessage, AgentRuntimeError>
        dispatch(const protocol_v2::WorkLeaseMessage &work) = 0;
        [[nodiscard]] virtual std::expected<void, AgentRuntimeError>
        cancel(const protocol_v2::CancelWorkMessage &message) = 0;
        [[nodiscard]] virtual std::expected<std::optional<InventoryProjection>, AgentRuntimeError>
        process_inventory(std::string snapshot_id, std::uint64_t inventory_generation) = 0;
    };

    struct IWindowsAgentProviderFactory {
        virtual ~IWindowsAgentProviderFactory() = default;
        [[nodiscard]] virtual std::expected<std::unique_ptr<IWindowsAgentProviderRuntime>, AgentFailure>
        create(WindowsAgentRuntimeIdentity identity) noexcept = 0;
    };

    [[nodiscard]] std::unique_ptr<IWindowsAgentProviderFactory> make_windows_agent_provider_factory();

    struct AgentRunStats {
        std::size_t successful_connections {};
        std::size_t replayed_records {};
        std::size_t accepted_leases {};
        std::size_t duplicate_leases {};
        std::size_t canceled_work {};
        std::size_t work_results_spooled {};
        std::size_t snapshot_records_spooled {};
        std::size_t inventory_refreshes_attempted {};
        std::size_t inventory_generations_spooled {};
        std::size_t inventory_refreshes_without_authority {};
        std::size_t acknowledgements {};
        std::size_t rejections {};
    };

    struct WindowsAgentService {
        WindowsAgentService(WindowsAgentConfig configuration, protocol_v2::SqliteAgentSpool &spool,
                            std::unique_ptr<IWindowsAgentSession> session,
                            std::unique_ptr<IWindowsAgentProviderFactory> providers) noexcept;

        [[nodiscard]] std::expected<AgentRunStats, AgentFailure> run(std::stop_token cancellation) noexcept;

    private:
        [[nodiscard]] std::expected<void, AgentFailure> flush(std::stop_token cancellation) noexcept;
        [[nodiscard]] std::expected<void, AgentFailure> process(const protocol_v2::PeerEnvelope &envelope,
                                                                IWindowsAgentProviderRuntime &provider) noexcept;
        [[nodiscard]] std::expected<void, AgentFailure>
        publish_process_inventory(IWindowsAgentProviderRuntime &provider) noexcept;
        [[nodiscard]] std::expected<bool, AgentFailure>
        result_is_pending(const protocol_v2::WorkLeaseMessage &work) const noexcept;
        [[nodiscard]] std::expected<bool, AgentFailure>
        snapshot_is_pending(std::string_view snapshot_id) const noexcept;

        WindowsAgentConfig configuration_;
        protocol_v2::SqliteAgentSpool *spool_ {};
        protocol_v2::PersistentAgentSession persistent_session_;
        std::unique_ptr<IWindowsAgentSession> session_;
        std::unique_ptr<IWindowsAgentProviderFactory> providers_;
        AgentRunStats stats_;
        bool inventory_started_ {};
        std::optional<std::chrono::steady_clock::time_point> next_inventory_refresh_;
        std::optional<SessionId> active_session_;
        std::uint64_t active_session_fence_ {};
    };

    [[nodiscard]] protocol_v2::AgentHelloMessage make_windows_agent_hello() noexcept;

} // namespace rule_engine::python::windows
