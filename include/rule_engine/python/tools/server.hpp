#pragma once

#include "rule_engine/python/cluster/control_plane.hpp"
#include "rule_engine/python/cluster/readiness.hpp"
#include "rule_engine/python/cluster/store.hpp"
#include "rule_engine/python/packaging/runtime.hpp"
#include "rule_engine/python/packaging/source_pack.hpp"
#include "rule_engine/python/protocol/network.hpp"
#include "rule_engine/python/protocol/session.hpp"
#include "rule_engine/python/tools/common.hpp"
#include "rule_engine/python/tools/pack_upload.hpp"
#include "rule_engine/python/tools/resident_service.hpp"

#include <chrono>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace rule_engine::python::tools {

    inline constexpr std::uint32_t server_config_schema_version = 3U;

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

    struct ServerListenerConfig {
        std::chrono::milliseconds accept_timeout {1'000};
        std::chrono::milliseconds handshake_timeout {5'000};
        std::chrono::milliseconds read_timeout {30'000};
        std::chrono::milliseconds write_timeout {30'000};
        std::size_t backlog {128U};
        std::size_t maximum_consecutive_failures {16U};
        bool require_hard_resolver_bounds {true};
    };

    struct ServerConfig {
        std::uint32_t schema_version {server_config_schema_version};
        ServerDeploymentMode mode {ServerDeploymentMode::production_cluster};
        std::string node_id;
        std::string platform_abi;
        std::filesystem::path resident_capabilities_path;
        std::chrono::milliseconds lease_duration {30'000};
        std::chrono::milliseconds lease_renew_interval {10'000};
        ServerStoreConfig store;
        std::string agent_endpoint;
        std::string admin_endpoint;
        ServerListenerConfig listener;
        ResidentServiceLimits service;
        ServerTlsConfig tls;
        std::filesystem::path runtime_root;
        std::filesystem::path pack_registry_path;
        PackRegistryLimits pack_registry_limits;
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
    [[nodiscard]] std::expected<cluster::ActivationPolicySnapshot, ToolFailure>
    snapshot_activation_policy(const ServerConfig &config);
    [[nodiscard]] std::expected<std::vector<std::string>, ToolFailure>
    load_resident_capability_inventory(const std::filesystem::path &path);

    struct ResidentServerContext {
        const ServerConfig &config;
        cluster::IClusterRuntimeStore &store;
        cluster::IActivationControlStore &activation_store;
        const cluster::StoreBackendCapabilities &store_capabilities;
        const packaging::PrivatePythonRuntime &runtime;
        const packaging::TrustPolicy &pack_trust_policy;
        const cluster::ActivationPolicySnapshot &activation_policy;
        const std::vector<std::string> &resident_capabilities;
        const protocol_v2::ITrustPolicy &peer_trust_policy;
        protocol_v2::OpenSslTlsContext *agent_tls;
        protocol_v2::OpenSslTlsContext *admin_tls;
        IResidentAgentBackend *agent_backend {};
        IResidentAdminBackend *admin_backend {};
        IResidentPackUploadBackend *pack_registry {};
    };

    // The backend seam keeps process tests injectable while production owns the
    // durable activation, fenced lease, and authenticated listener lifecycle.
    struct ResidentServerBackend {
        virtual ~ResidentServerBackend() = default;
        [[nodiscard]] virtual std::expected<void, ToolFailure>
        qualify_activation(const ResidentServerContext &context) noexcept = 0;
        [[nodiscard]] virtual std::expected<void, ToolFailure> serve(const ResidentServerContext &context) noexcept = 0;
        virtual void request_stop() noexcept = 0;
    };

    // Owns the authenticated listeners, fixed worker pool, bounded session
    // queue, application handlers, node lease, and deterministic shutdown.
    struct ProductionResidentServerBackend final: ResidentServerBackend {
        ProductionResidentServerBackend();
        ~ProductionResidentServerBackend() override;

        ProductionResidentServerBackend(const ProductionResidentServerBackend &) = delete;
        ProductionResidentServerBackend &operator=(const ProductionResidentServerBackend &) = delete;

        [[nodiscard]] std::expected<void, ToolFailure>
        qualify_activation(const ResidentServerContext &context) noexcept override;
        [[nodiscard]] std::expected<void, ToolFailure> serve(const ResidentServerContext &context) noexcept override;
        void request_stop() noexcept override;

    private:
        struct Impl;
        std::unique_ptr<Impl> impl_;
    };

    [[nodiscard]] std::string_view server_help() noexcept;
    [[nodiscard]] CommandOutput run_rule_engine_server(std::span<const std::string_view> arguments,
                                                       ResidentServerBackend &backend);

} // namespace rule_engine::python::tools
