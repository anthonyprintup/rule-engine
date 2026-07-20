#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>
#include <variant>

namespace rule_engine::python::cluster {

    enum struct DeploymentMode : std::uint8_t { production_cluster, single_node_dev, reference_test };
    enum struct StoreBackendKind : std::uint8_t { postgresql17, sqlite_dev, in_memory_reference };

    struct PostgreSql17Config {
        std::string connection_reference;
        std::uint16_t server_major {17};
        std::uint32_t server_processes {2};
        std::size_t pool_size {16};
        std::chrono::milliseconds statement_timeout {5'000};
        bool verify_tls_peer {true};
        bool external_ha_configured {true};
        DeploymentMode deployment_mode {DeploymentMode::production_cluster};
    };

    struct SqliteDevConfig {
        std::string database_path;
        std::uint32_t server_processes {1};
        std::chrono::milliseconds busy_timeout {5'000};
        bool wal {true};
        bool foreign_keys {true};
        bool remote_cluster {false};
        bool high_availability {false};
        DeploymentMode deployment_mode {DeploymentMode::single_node_dev};
    };

    struct InMemoryReferenceConfig {
        std::uint32_t server_processes {1};
        DeploymentMode deployment_mode {DeploymentMode::reference_test};
    };

    using StoreBackendConfig = std::variant<PostgreSql17Config, SqliteDevConfig, InMemoryReferenceConfig>;

    enum struct ConfigurationErrorCode : std::uint8_t {
        invalid_mode,
        invalid_version,
        invalid_connection,
        invalid_pool,
        insecure_transport,
        clustered_sqlite,
        unavailable_driver,
    };

    struct ConfigurationError {
        ConfigurationErrorCode code {};
        std::string message;
    };

    struct StoreBackendCapabilities {
        StoreBackendKind kind {};
        bool implementation_available {};
        bool production_allowed {};
        bool active_active {};
        bool multi_process {};
        bool atomic_event_transaction {};
        bool row_fences {};
        bool outbox_leases {};
        bool database_time_leases {};
        std::string required_driver;
        std::string limitation;
    };

    // Validates the deployment contract and reports compile-time adapter
    // availability. Connectivity and migration compatibility remain separate
    // fail-closed readiness gates.
    [[nodiscard]] std::expected<StoreBackendCapabilities, ConfigurationError>
    validate_store_backend(const StoreBackendConfig &config);

} // namespace rule_engine::python::cluster
