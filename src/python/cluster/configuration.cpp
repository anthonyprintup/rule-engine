#include "rule_engine/python/cluster/configuration.hpp"

#include <type_traits>

namespace rule_engine::python::cluster {
    namespace {

        ConfigurationError error(const ConfigurationErrorCode code, std::string message) {
            return ConfigurationError {.code = code, .message = std::move(message)};
        }

        std::expected<StoreBackendCapabilities, ConfigurationError>
        validate_postgresql(const PostgreSql17Config &config) {
            if (config.deployment_mode != DeploymentMode::production_cluster) {
                return std::unexpected(
                    error(ConfigurationErrorCode::invalid_mode, "PostgreSQL requires production_cluster mode"));
            }
            if (config.server_major < 17) {
                return std::unexpected(
                    error(ConfigurationErrorCode::invalid_version, "PostgreSQL server major must be 17 or newer"));
            }
            if (config.connection_reference.empty()) {
                return std::unexpected(error(ConfigurationErrorCode::invalid_connection,
                                             "PostgreSQL requires a secret-backed connection reference"));
            }
            if (config.pool_size == 0 || config.statement_timeout.count() <= 0) {
                return std::unexpected(error(ConfigurationErrorCode::invalid_pool,
                                             "PostgreSQL pool size and statement timeout must be positive"));
            }
            if (!config.verify_tls_peer) {
                return std::unexpected(error(ConfigurationErrorCode::insecure_transport,
                                             "production PostgreSQL requires TLS peer verification"));
            }
            if (config.server_processes > 1 && !config.external_ha_configured) {
                return std::unexpected(error(ConfigurationErrorCode::invalid_mode,
                                             "active-active servers require externally managed PostgreSQL HA"));
            }

            return StoreBackendCapabilities {
                .kind = StoreBackendKind::postgresql17,
#if defined(RULE_ENGINE_HAS_POSTGRESQL)
                .implementation_available = true,
#else
                .implementation_available = false,
#endif
                .production_allowed = true,
                .active_active = true,
                .multi_process = true,
                .atomic_event_transaction = true,
                .row_fences = true,
                .outbox_leases = true,
                .database_time_leases = true,
                .required_driver = "libpq/PostgreSQL 17+",
#if defined(RULE_ENGINE_HAS_POSTGRESQL)
                .limitation = "Driver is compiled; readiness still requires PostgreSQL 17 connectivity and migrations.",
#else
                .limitation = "libpq was not discovered; production readiness is impossible in this build.",
#endif
            };
        }

        std::expected<StoreBackendCapabilities, ConfigurationError> validate_sqlite(const SqliteDevConfig &config) {
            if (config.deployment_mode != DeploymentMode::single_node_dev || config.server_processes != 1 ||
                config.remote_cluster || config.high_availability) {
                return std::unexpected(error(ConfigurationErrorCode::clustered_sqlite,
                                             "SQLite is restricted to one single_node_dev server process"));
            }
            if (config.database_path.empty()) {
                return std::unexpected(
                    error(ConfigurationErrorCode::invalid_connection, "SQLite requires an explicit database path"));
            }
            if (!config.wal || !config.foreign_keys || config.busy_timeout.count() <= 0) {
                return std::unexpected(error(ConfigurationErrorCode::invalid_mode,
                                             "SQLite development mode requires WAL, foreign keys, and busy timeout"));
            }

            return StoreBackendCapabilities {
                .kind = StoreBackendKind::sqlite_dev,
#if defined(RULE_ENGINE_HAS_SQLITE)
                .implementation_available = true,
#else
                .implementation_available = false,
#endif
                .production_allowed = false,
                .active_active = false,
                .multi_process = false,
                .atomic_event_transaction = true,
                .row_fences = true,
                .outbox_leases = true,
                .database_time_leases = false,
                .required_driver = "SQLite3 or Windows SDK winsqlite3",
                .limitation =
                    "Implemented for one development process with a deterministic caller clock; it cannot qualify "
                    "clustering or database-time leases.",
            };
        }

        std::expected<StoreBackendCapabilities, ConfigurationError>
        validate_reference(const InMemoryReferenceConfig &config) {
            if (config.deployment_mode != DeploymentMode::reference_test || config.server_processes != 1) {
                return std::unexpected(error(ConfigurationErrorCode::invalid_mode,
                                             "the in-memory backend is restricted to one reference_test process"));
            }
            return StoreBackendCapabilities {
                .kind = StoreBackendKind::in_memory_reference,
                .implementation_available = true,
                .production_allowed = false,
                .active_active = false,
                .multi_process = false,
                .atomic_event_transaction = true,
                .row_fences = true,
                .outbox_leases = true,
                .database_time_leases = false,
                .required_driver = "none",
                .limitation =
                    "Deterministic semantic reference only; it does not model SQL isolation, I/O, or failover.",
            };
        }

    } // namespace

    std::expected<StoreBackendCapabilities, ConfigurationError>
    validate_store_backend(const StoreBackendConfig &config) {
        return std::visit(
            [](const auto &selected) -> std::expected<StoreBackendCapabilities, ConfigurationError> {
                using Config = std::remove_cvref_t<decltype(selected)>;
                if constexpr (std::is_same_v<Config, PostgreSql17Config>) {
                    return validate_postgresql(selected);
                } else if constexpr (std::is_same_v<Config, SqliteDevConfig>) {
                    return validate_sqlite(selected);
                } else {
                    return validate_reference(selected);
                }
            },
            config);
    }

} // namespace rule_engine::python::cluster
