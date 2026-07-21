#pragma once

#include "rule_engine/python/cluster/store.hpp"
#include "rule_engine/python/packaging/runtime.hpp"
#include "rule_engine/python/protocol/transport.hpp"
#include "rule_engine/python/tools/common.hpp"

#include <chrono>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace rule_engine::python::tools {

    inline constexpr std::uint32_t server_config_schema_version = 1U;

    enum struct ServerDeploymentMode : std::uint8_t { production_cluster, single_node_dev };
    enum struct ServerStoreKind : std::uint8_t { postgresql17, sqlite_dev };

    struct ServerStoreConfig {
        ServerStoreKind kind {ServerStoreKind::postgresql17};
        std::string connection_reference;
        std::filesystem::path sqlite_path;
        std::uint16_t server_major {17U};
        std::uint32_t server_processes {1U};
        std::size_t pool_size {16U};
        std::chrono::milliseconds statement_timeout {5'000};
        std::chrono::milliseconds busy_timeout {5'000};
        bool verify_tls_peer {true};
        bool external_ha_configured {};
    };

    struct ServerTlsConfig {
        std::filesystem::path trust_anchors_pem;
        std::filesystem::path certificate_chain_pem;
        std::filesystem::path private_key_pem;
        std::filesystem::path crl_pem;
        bool require_crl {};
    };

    struct ServerConfig {
        std::uint32_t schema_version {server_config_schema_version};
        ServerDeploymentMode mode {ServerDeploymentMode::production_cluster};
        std::string node_id;
        std::string platform_abi;
        std::chrono::milliseconds lease_duration {30'000};
        std::chrono::milliseconds lease_renew_interval {10'000};
        ServerStoreConfig store;
        std::string agent_endpoint;
        std::string admin_endpoint;
        ServerTlsConfig tls;
        std::filesystem::path runtime_root;
        std::filesystem::path pack_registry_path;
        std::filesystem::path trusted_signers_path;
        std::filesystem::path revocations_path;
        std::filesystem::path peer_enrollment_path;
        std::filesystem::path operator_bindings_path;
        std::filesystem::path schema_catalog_path;
        std::filesystem::path budget_profiles_path;
        std::filesystem::path retention_profiles_path;
        std::filesystem::path trace_profiles_path;
        std::filesystem::path capture_profiles_path;
        std::filesystem::path service_profiles_path;
        std::filesystem::path sink_profiles_path;
        std::string prometheus_endpoint;
        std::filesystem::path json_log_path;
        std::filesystem::path audit_path;
        std::optional<std::string> otlp_endpoint;
        bool allow_unsigned_packs {};
        bool allow_loopback_plaintext {};
        bool allow_empty_activation {};
    };

    struct ServerConfigError {
        std::string code;
        std::string message;
        std::size_t line {};
    };

    // The schema is an intentionally small, flat TOML-compatible assignment
    // surface. Sections, arrays, implicit defaults for security-critical fields,
    // duplicate keys, and unknown keys are rejected.
    [[nodiscard]] std::expected<ServerConfig, ServerConfigError> parse_server_config(std::string_view text);
    [[nodiscard]] std::expected<ServerConfig, ServerConfigError> load_server_config(const std::filesystem::path &path);
    [[nodiscard]] std::expected<void, ServerConfigError> validate_server_config(const ServerConfig &config);

    struct ResidentServerContext {
        const ServerConfig &config;
        cluster::IClusterRuntimeStore &store;
        const packaging::PrivatePythonRuntime &runtime;
        const protocol_v2::OpenSslTlsContext *tls;
    };

    // Socket acceptance and durable activation hydration belong behind this
    // seam. The current protocol component exposes TLS for an already-connected
    // socket but no listener/acceptor, and the store contract exposes no durable
    // active-generation loader. The production backend therefore fails closed.
    struct ResidentServerBackend {
        virtual ~ResidentServerBackend() = default;
        [[nodiscard]] virtual std::expected<void, ToolFailure>
        qualify_activation(const ResidentServerContext &context) noexcept = 0;
        [[nodiscard]] virtual std::expected<void, ToolFailure> serve(const ResidentServerContext &context) noexcept = 0;
    };

    struct UnavailableResidentServerBackend final: ResidentServerBackend {
        [[nodiscard]] std::expected<void, ToolFailure>
        qualify_activation(const ResidentServerContext &context) noexcept override;
        [[nodiscard]] std::expected<void, ToolFailure> serve(const ResidentServerContext &context) noexcept override;
    };

    [[nodiscard]] std::string_view server_help() noexcept;
    [[nodiscard]] CommandOutput run_rule_engine_server(std::span<const std::string_view> arguments,
                                                       ResidentServerBackend &backend);

} // namespace rule_engine::python::tools
