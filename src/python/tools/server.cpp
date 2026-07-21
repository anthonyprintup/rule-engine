#include "rule_engine/python/tools/server.hpp"

#include "rule_engine/python/cluster/configuration.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstdlib>
#include <fstream>
#include <limits>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace rule_engine::python::tools {
    namespace {

        constexpr std::size_t maximum_config_bytes = 1U * mebibyte;
        constexpr std::size_t maximum_config_line_bytes = 4U * kibibyte;
        constexpr std::size_t maximum_config_entries = 128U;
        constexpr std::size_t maximum_public_diagnostic_bytes = 2U * kibibyte;

        constexpr std::string_view help_text = R"(Usage: rule_engine_server --config PATH [--validate-config]

Run the resident Python rule-engine server from one explicit configuration file.
No source, rule, listener, fixture, or compatibility option is accepted on the command line.

Options:
  --config PATH       Flat TOML-compatible server configuration
  --validate-config   Validate syntax and cross-field policy without contacting dependencies
  --help              Show this help
  --version           Show the tool API version

Required common configuration keys:
  schema.version, deployment.mode, node.id, node.platform_abi,
  node.lease_duration_ms, node.lease_renew_interval_ms, store.backend,
  store.server_processes, listener.agent_endpoint, listener.admin_endpoint,
  runtime.root, pack.registry_path, bindings.operator_path,
  schemas.catalog_path, profiles.budget_path, profiles.retention_path,
  observability.prometheus_endpoint, observability.json_log_path,
  observability.audit_path.

Production additionally requires PostgreSQL 17 settings, TLS/CRL material,
trusted signer/revocation/peer policy, and trace/capture/service/sink profiles.
Development permits only one SQLite process and optional plaintext only on
loopback listener and metrics endpoints. Signed development packs require
signer/revocation policy; development mTLS also requires peer enrollment.
Secret values are not accepted inline; PostgreSQL currently supports only
connection references of the form env:VARIABLE_NAME.
)";

        enum struct ValueKind : std::uint8_t { text, integer, boolean };
        using ParsedValue = std::variant<std::string, std::uint64_t, bool>;

        struct ParsedEntry {
            ParsedValue value;
            std::size_t line {};
        };

        using ParsedEntries = std::map<std::string, ParsedEntry, std::less<>>;

        [[nodiscard]] ServerConfigError config_error(std::string code, std::string message,
                                                     const std::size_t line = 0U) {
            return {.code = std::move(code), .message = std::move(message), .line = line};
        }

        [[nodiscard]] ToolFailure unavailable(std::string code, std::string message) {
            return {
                .kind = ToolFailureKind::unavailable_dependency,
                .code = std::move(code),
                .message = std::move(message),
                .diagnostics = {},
            };
        }

        [[nodiscard]] ToolFailure unavailable_transport(std::string code, std::string message) {
            return {
                .kind = ToolFailureKind::unavailable_transport,
                .code = std::move(code),
                .message = std::move(message),
                .diagnostics = {},
            };
        }

        [[nodiscard]] std::string public_diagnostic(const std::string_view input) {
            std::string result;
            result.reserve(std::min(input.size(), maximum_public_diagnostic_bytes) + 3U);
            const auto size = std::min(input.size(), maximum_public_diagnostic_bytes);
            for (const auto character : input.substr(0U, size)) {
                const auto byte = static_cast<unsigned char>(character);
                result.push_back(byte < 0x20U || byte == 0x7fU ? ' ' : character);
            }
            if (input.size() > maximum_public_diagnostic_bytes) {
                result += "...";
            }
            return result;
        }

        [[nodiscard]] std::string_view trim(const std::string_view value) noexcept {
            auto begin = std::size_t {};
            while (begin < value.size() && (value[begin] == ' ' || value[begin] == '\t' || value[begin] == '\r')) {
                ++begin;
            }
            auto end = value.size();
            while (end > begin && (value[end - 1U] == ' ' || value[end - 1U] == '\t' || value[end - 1U] == '\r')) {
                --end;
            }
            return value.substr(begin, end - begin);
        }

        [[nodiscard]] std::optional<ValueKind> key_kind(const std::string_view key) noexcept {
            static constexpr std::pair<std::string_view, ValueKind> keys[] {
                {"schema.version", ValueKind::integer},
                {"deployment.mode", ValueKind::text},
                {"node.id", ValueKind::text},
                {"node.platform_abi", ValueKind::text},
                {"node.lease_duration_ms", ValueKind::integer},
                {"node.lease_renew_interval_ms", ValueKind::integer},
                {"store.backend", ValueKind::text},
                {"store.connection_reference", ValueKind::text},
                {"store.sqlite_path", ValueKind::text},
                {"store.server_major", ValueKind::integer},
                {"store.server_processes", ValueKind::integer},
                {"store.pool_size", ValueKind::integer},
                {"store.statement_timeout_ms", ValueKind::integer},
                {"store.busy_timeout_ms", ValueKind::integer},
                {"store.verify_tls_peer", ValueKind::boolean},
                {"store.external_ha_configured", ValueKind::boolean},
                {"listener.agent_endpoint", ValueKind::text},
                {"listener.admin_endpoint", ValueKind::text},
                {"tls.trust_anchors_pem", ValueKind::text},
                {"tls.certificate_chain_pem", ValueKind::text},
                {"tls.private_key_pem", ValueKind::text},
                {"tls.crl_pem", ValueKind::text},
                {"tls.require_crl", ValueKind::boolean},
                {"runtime.root", ValueKind::text},
                {"pack.registry_path", ValueKind::text},
                {"trust.trusted_signers_path", ValueKind::text},
                {"trust.revocations_path", ValueKind::text},
                {"trust.peer_enrollment_path", ValueKind::text},
                {"bindings.operator_path", ValueKind::text},
                {"schemas.catalog_path", ValueKind::text},
                {"profiles.budget_path", ValueKind::text},
                {"profiles.retention_path", ValueKind::text},
                {"profiles.trace_path", ValueKind::text},
                {"profiles.capture_path", ValueKind::text},
                {"profiles.service_path", ValueKind::text},
                {"profiles.sink_path", ValueKind::text},
                {"observability.prometheus_endpoint", ValueKind::text},
                {"observability.json_log_path", ValueKind::text},
                {"observability.audit_path", ValueKind::text},
                {"observability.otlp_endpoint", ValueKind::text},
                {"development.allow_unsigned_packs", ValueKind::boolean},
                {"development.allow_loopback_plaintext", ValueKind::boolean},
                {"development.allow_empty_activation", ValueKind::boolean},
            };
            const auto found = std::ranges::find(keys, key, &std::pair<std::string_view, ValueKind>::first);
            return found == std::end(keys) ? std::nullopt : std::optional<ValueKind> {found->second};
        }

        [[nodiscard]] std::expected<std::string, ServerConfigError> parse_quoted_string(const std::string_view raw,
                                                                                        const std::size_t line) {
            if (raw.size() < 2U || raw.front() != '"') {
                return std::unexpected(config_error("SRV-CONFIG-TYPE", "string values must be double quoted", line));
            }
            std::string result;
            result.reserve(raw.size() - 2U);
            bool escaped {};
            std::size_t end_quote {};
            for (std::size_t index = 1U; index < raw.size(); ++index) {
                const auto character = raw[index];
                if (escaped) {
                    switch (character) {
                        case '"': result.push_back('"'); break;
                        case '\\': result.push_back('\\'); break;
                        case 'n': result.push_back('\n'); break;
                        case 'r': result.push_back('\r'); break;
                        case 't': result.push_back('\t'); break;
                        default:
                            return std::unexpected(
                                config_error("SRV-CONFIG-ESCAPE", "unsupported string escape in configuration", line));
                    }
                    escaped = false;
                    continue;
                }
                if (character == '\\') {
                    escaped = true;
                    continue;
                }
                if (character == '"') {
                    end_quote = index;
                    break;
                }
                if (static_cast<unsigned char>(character) < 0x20U) {
                    return std::unexpected(
                        config_error("SRV-CONFIG-STRING", "configuration strings contain a control byte", line));
                }
                result.push_back(character);
            }
            if (escaped || end_quote == 0U) {
                return std::unexpected(
                    config_error("SRV-CONFIG-STRING", "configuration string is not terminated", line));
            }
            auto suffix = trim(raw.substr(end_quote + 1U));
            if (!suffix.empty() && suffix.front() != '#') {
                return std::unexpected(
                    config_error("SRV-CONFIG-SYNTAX", "unexpected content after string value", line));
            }
            return result;
        }

        [[nodiscard]] std::expected<ParsedValue, ServerConfigError>
        parse_value(const ValueKind kind, const std::string_view raw, const std::size_t line) {
            if (kind == ValueKind::text) {
                auto text = parse_quoted_string(raw, line);
                if (!text) {
                    return std::unexpected(std::move(text.error()));
                }
                return ParsedValue {std::move(*text)};
            }
            const auto comment = raw.find('#');
            const auto value = trim(raw.substr(0U, comment));
            if (kind == ValueKind::boolean) {
                if (value == "true") {
                    return ParsedValue {true};
                }
                if (value == "false") {
                    return ParsedValue {false};
                }
                return std::unexpected(config_error("SRV-CONFIG-TYPE", "boolean values must be true or false", line));
            }
            std::uint64_t integer {};
            const auto parsed = std::from_chars(value.data(), value.data() + value.size(), integer);
            if (value.empty() || parsed.ec != std::errc {} || parsed.ptr != value.data() + value.size()) {
                return std::unexpected(
                    config_error("SRV-CONFIG-TYPE", "integer values must be unsigned decimal", line));
            }
            return ParsedValue {integer};
        }

        [[nodiscard]] std::expected<ParsedEntries, ServerConfigError> parse_entries(const std::string_view text) {
            if (text.empty() || text.size() > maximum_config_bytes || text.find('\0') != std::string_view::npos) {
                return std::unexpected(
                    config_error("SRV-CONFIG-SIZE", "configuration must be non-empty and at most one MiB"));
            }
            ParsedEntries entries;
            std::size_t offset {};
            std::size_t line_number {1U};
            while (offset <= text.size()) {
                const auto newline = text.find('\n', offset);
                const auto line_end = newline == std::string_view::npos ? text.size() : newline;
                const auto raw_line = text.substr(offset, line_end - offset);
                if (raw_line.size() > maximum_config_line_bytes) {
                    return std::unexpected(
                        config_error("SRV-CONFIG-LINE-LIMIT", "configuration line exceeds four KiB", line_number));
                }
                const auto line = trim(raw_line);
                if (!line.empty() && line.front() != '#') {
                    if (line.front() == '[') {
                        return std::unexpected(config_error("SRV-CONFIG-SECTIONS",
                                                            "configuration sections are not supported", line_number));
                    }
                    const auto equals = line.find('=');
                    if (equals == std::string_view::npos) {
                        return std::unexpected(
                            config_error("SRV-CONFIG-SYNTAX", "configuration entry requires key = value", line_number));
                    }
                    const auto key = trim(line.substr(0U, equals));
                    const auto raw_value = trim(line.substr(equals + 1U));
                    const auto kind = key_kind(key);
                    if (!kind) {
                        return std::unexpected(config_error("SRV-CONFIG-UNKNOWN-KEY",
                                                            "configuration contains an unknown key", line_number));
                    }
                    if (entries.contains(key)) {
                        return std::unexpected(config_error("SRV-CONFIG-DUPLICATE-KEY",
                                                            "duplicate configuration key: " + std::string {key},
                                                            line_number));
                    }
                    auto value = parse_value(*kind, raw_value, line_number);
                    if (!value) {
                        return std::unexpected(std::move(value.error()));
                    }
                    entries.emplace(std::string {key}, ParsedEntry {.value = std::move(*value), .line = line_number});
                    if (entries.size() > maximum_config_entries) {
                        return std::unexpected(
                            config_error("SRV-CONFIG-ENTRY-LIMIT", "configuration has too many entries", line_number));
                    }
                }
                if (newline == std::string_view::npos) {
                    break;
                }
                offset = newline + 1U;
                ++line_number;
            }
            return entries;
        }

        [[nodiscard]] std::expected<void, ServerConfigError>
        require_keys(const ParsedEntries &entries, const std::span<const std::string_view> keys) {
            for (const auto key : keys) {
                if (!entries.contains(key)) {
                    return std::unexpected(config_error("SRV-CONFIG-MISSING-KEY",
                                                        "required configuration key is missing: " + std::string {key}));
                }
            }
            return {};
        }

        template<typename T>
        [[nodiscard]] std::optional<T> entry_value(const ParsedEntries &entries, const std::string_view key) {
            const auto found = entries.find(key);
            if (found == entries.end()) {
                return std::nullopt;
            }
            return std::get<T>(found->second.value);
        }

        [[nodiscard]] std::expected<std::uint32_t, ServerConfigError>
        uint32_value(const ParsedEntries &entries, const std::string_view key, const std::uint32_t fallback = 0U) {
            const auto value = entry_value<std::uint64_t>(entries, key).value_or(fallback);
            if (value > std::numeric_limits<std::uint32_t>::max()) {
                return std::unexpected(
                    config_error("SRV-CONFIG-RANGE", "configuration integer exceeds uint32: " + std::string {key}));
            }
            return static_cast<std::uint32_t>(value);
        }

        [[nodiscard]] std::expected<std::uint16_t, ServerConfigError>
        uint16_value(const ParsedEntries &entries, const std::string_view key, const std::uint16_t fallback = 0U) {
            const auto value = entry_value<std::uint64_t>(entries, key).value_or(fallback);
            if (value > std::numeric_limits<std::uint16_t>::max()) {
                return std::unexpected(
                    config_error("SRV-CONFIG-RANGE", "configuration integer exceeds uint16: " + std::string {key}));
            }
            return static_cast<std::uint16_t>(value);
        }

        [[nodiscard]] std::expected<std::chrono::milliseconds, ServerConfigError>
        milliseconds_value(const ParsedEntries &entries, const std::string_view key,
                           const std::uint64_t fallback = 0U) {
            const auto value = entry_value<std::uint64_t>(entries, key).value_or(fallback);
            if (value > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
                return std::unexpected(
                    config_error("SRV-CONFIG-RANGE", "configuration duration exceeds int64: " + std::string {key}));
            }
            return std::chrono::milliseconds {static_cast<std::int64_t>(value)};
        }

        [[nodiscard]] bool valid_environment_reference(const std::string_view reference) noexcept {
            constexpr std::string_view prefix = "env:";
            if (!reference.starts_with(prefix) || reference.size() == prefix.size()) {
                return false;
            }
            const auto name = reference.substr(prefix.size());
            return (std::isalpha(static_cast<unsigned char>(name.front())) != 0 || name.front() == '_') &&
                   std::ranges::all_of(name, [](const char character) {
                       return std::isalnum(static_cast<unsigned char>(character)) != 0 || character == '_';
                   });
        }

        struct Endpoint {
            std::string host;
            std::uint16_t port {};
        };

        [[nodiscard]] std::optional<Endpoint> parse_endpoint(const std::string_view text) {
            if (text.empty() || text.find_first_of(" \t\r\n") != std::string_view::npos) {
                return std::nullopt;
            }
            std::string_view host;
            std::string_view port_text;
            if (text.front() == '[') {
                const auto close = text.find(']');
                if (close == std::string_view::npos || close + 1U >= text.size() || text[close + 1U] != ':') {
                    return std::nullopt;
                }
                host = text.substr(1U, close - 1U);
                port_text = text.substr(close + 2U);
            } else {
                const auto colon = text.rfind(':');
                if (colon == std::string_view::npos || text.find(':') != colon) {
                    return std::nullopt;
                }
                host = text.substr(0U, colon);
                port_text = text.substr(colon + 1U);
            }
            std::uint16_t port {};
            const auto parsed = std::from_chars(port_text.data(), port_text.data() + port_text.size(), port);
            if (host.empty() || port_text.empty() || parsed.ec != std::errc {} ||
                parsed.ptr != port_text.data() + port_text.size() || port == 0U) {
                return std::nullopt;
            }
            return Endpoint {.host = std::string {host}, .port = port};
        }

        [[nodiscard]] bool loopback_host(std::string host) {
            std::ranges::transform(host, host.begin(), [](const unsigned char character) {
                return static_cast<char>(std::tolower(character));
            });
            return host == "127.0.0.1" || host == "::1";
        }

        [[nodiscard]] std::expected<void, ServerConfigError> require_nonempty(const std::filesystem::path &path,
                                                                              const std::string_view key) {
            if (path.empty()) {
                return std::unexpected(config_error("SRV-CONFIG-MISSING-VALUE",
                                                    "configuration path must not be empty: " + std::string {key}));
            }
            return {};
        }

        [[nodiscard]] std::expected<void, ToolFailure> require_existing_file(const std::filesystem::path &path,
                                                                             const std::string_view key) {
            std::error_code error;
            const auto regular = std::filesystem::is_regular_file(path, error);
            if (error || !regular) {
                return std::unexpected(unavailable("SRV-LOCAL-REFERENCE-UNAVAILABLE",
                                                   "required local reference is unavailable: " + std::string {key}));
            }
            const auto size = std::filesystem::file_size(path, error);
            if (error || size == 0U) {
                return std::unexpected(unavailable("SRV-LOCAL-REFERENCE-EMPTY",
                                                   "required local reference is empty: " + std::string {key}));
            }
            return {};
        }

        [[nodiscard]] std::expected<void, ToolFailure> qualify_local_references(const ServerConfig &config) {
            const std::pair<const std::filesystem::path *, std::string_view> common[] {
                {&config.operator_bindings_path, "bindings.operator_path"},
                {&config.schema_catalog_path, "schemas.catalog_path"},
                {&config.budget_profiles_path, "profiles.budget_path"},
                {&config.retention_profiles_path, "profiles.retention_path"},
            };
            for (const auto &[path, key] : common) {
                if (auto present = require_existing_file(*path, key); !present) {
                    return present;
                }
            }
            std::error_code registry_error;
            if (!std::filesystem::is_directory(config.pack_registry_path, registry_error) || registry_error) {
                return std::unexpected(
                    unavailable("SRV-PACK-REGISTRY-UNAVAILABLE", "pack registry directory is unavailable"));
            }
            const std::pair<const std::filesystem::path *, std::string_view> optional[] {
                {&config.trusted_signers_path, "trust.trusted_signers_path"},
                {&config.revocations_path, "trust.revocations_path"},
                {&config.peer_enrollment_path, "trust.peer_enrollment_path"},
                {&config.trace_profiles_path, "profiles.trace_path"},
                {&config.capture_profiles_path, "profiles.capture_path"},
                {&config.service_profiles_path, "profiles.service_path"},
                {&config.sink_profiles_path, "profiles.sink_path"},
            };
            for (const auto &[path, key] : optional) {
                if (!path->empty()) {
                    if (auto present = require_existing_file(*path, key); !present) {
                        return present;
                    }
                }
            }
            return {};
        }

        [[nodiscard]] std::optional<std::string> environment_value(const std::string_view name) {
#if defined(_WIN32)
            char *raw {};
            std::size_t length {};
            const auto copied = _dupenv_s(&raw, &length, std::string {name}.c_str());
            if (copied != 0 || raw == nullptr) {
                return std::nullopt;
            }
            std::string value {raw};
            std::free(raw);
            return value;
#else
            const auto *raw = std::getenv(std::string {name}.c_str());
            return raw == nullptr ? std::nullopt : std::optional<std::string> {raw};
#endif
        }

        [[nodiscard]] std::expected<std::unique_ptr<cluster::IClusterRuntimeStore>, ToolFailure>
        open_store(const ServerConfig &config, cluster::AuditTrail &audit) {
            if (config.store.kind == ServerStoreKind::sqlite_dev) {
                cluster::SqliteDevConfig store_config {
                    .database_path = config.store.sqlite_path.string(),
                    .server_processes = config.store.server_processes,
                    .busy_timeout = config.store.busy_timeout,
                    .wal = true,
                    .foreign_keys = true,
                    .remote_cluster = false,
                    .high_availability = false,
                    .deployment_mode = cluster::DeploymentMode::single_node_dev,
                };
                auto store = cluster::SqliteRuntimeStore::open(store_config, audit);
                if (!store) {
                    return std::unexpected(unavailable("SRV-SQLITE-UNAVAILABLE", store.error().message));
                }
                return std::unique_ptr<cluster::IClusterRuntimeStore> {std::move(*store)};
            }

            cluster::PostgreSql17Config store_config {
                .connection_reference = config.store.connection_reference,
                .server_major = config.store.server_major,
                .server_processes = config.store.server_processes,
                .pool_size = config.store.pool_size,
                .statement_timeout = config.store.statement_timeout,
                .verify_tls_peer = config.store.verify_tls_peer,
                .external_ha_configured = config.store.external_ha_configured,
                .deployment_mode = cluster::DeploymentMode::production_cluster,
            };
            const auto environment_name = std::string_view {config.store.connection_reference}.substr(4U);
            auto connection = environment_value(environment_name);
            if (!connection || connection->empty()) {
                return std::unexpected(unavailable("SRV-POSTGRES-SECRET-UNAVAILABLE",
                                                   "PostgreSQL connection reference could not be resolved"));
            }
            auto store = cluster::PostgreSqlRuntimeStore::open_resolved(store_config, *connection, audit);
            std::ranges::fill(*connection, '\0');
            if (!store) {
                return std::unexpected(unavailable(
                    "SRV-POSTGRES-UNAVAILABLE",
                    "PostgreSQL connectivity, verified TLS, server version, or migrations could not be qualified"));
            }
            return std::unique_ptr<cluster::IClusterRuntimeStore> {std::move(*store)};
        }

        [[nodiscard]] std::expected<cluster::StoreBackendCapabilities, ToolFailure>
        backend_capabilities(const ServerConfig &config) {
            cluster::StoreBackendConfig selected;
            if (config.store.kind == ServerStoreKind::postgresql17) {
                selected = cluster::PostgreSql17Config {
                    .connection_reference = config.store.connection_reference,
                    .server_major = config.store.server_major,
                    .server_processes = config.store.server_processes,
                    .pool_size = config.store.pool_size,
                    .statement_timeout = config.store.statement_timeout,
                    .verify_tls_peer = config.store.verify_tls_peer,
                    .external_ha_configured = config.store.external_ha_configured,
                    .deployment_mode = cluster::DeploymentMode::production_cluster,
                };
            } else {
                selected = cluster::SqliteDevConfig {
                    .database_path = config.store.sqlite_path.string(),
                    .server_processes = config.store.server_processes,
                    .busy_timeout = config.store.busy_timeout,
                    .wal = true,
                    .foreign_keys = true,
                    .remote_cluster = false,
                    .high_availability = false,
                    .deployment_mode = cluster::DeploymentMode::single_node_dev,
                };
            }
            auto capabilities = cluster::validate_store_backend(selected);
            if (!capabilities) {
                return std::unexpected(ToolFailure {
                    .kind = ToolFailureKind::operation,
                    .code = "SRV-STORE-CONFIGURATION",
                    .message = capabilities.error().message,
                    .diagnostics = {},
                });
            }
            if (!capabilities->implementation_available) {
                const auto code = config.store.kind == ServerStoreKind::postgresql17 ?
                                      "SRV-POSTGRES-DRIVER-UNAVAILABLE" :
                                      "SRV-SQLITE-DRIVER-UNAVAILABLE";
                return std::unexpected(unavailable(code, capabilities->limitation));
            }
            return *capabilities;
        }

        [[nodiscard]] std::expected<std::optional<protocol_v2::OpenSslTlsContext>, ToolFailure>
        create_tls(const ServerConfig &config) {
            if (config.allow_loopback_plaintext) {
                return std::optional<protocol_v2::OpenSslTlsContext> {};
            }
            const auto status = protocol_v2::tls_backend_status();
            if (!status.available) {
                return std::unexpected(unavailable_transport("SRV-TLS-BACKEND-UNAVAILABLE", status.diagnostic));
            }
            protocol_v2::TlsConfiguration tls_config {
                .role = protocol_v2::TlsEndpointRole::server,
                .trust_anchors_pem = config.tls.trust_anchors_pem.string(),
                .certificate_chain_pem = config.tls.certificate_chain_pem.string(),
                .private_key_pem = config.tls.private_key_pem.string(),
                .crl_pem = config.tls.crl_pem.string(),
                .expected_server_name = {},
                .require_crl = config.tls.require_crl,
                .verification_time_unix_seconds = std::nullopt,
                .protocol_limits = {},
            };
            auto context = protocol_v2::OpenSslTlsContext::create(std::move(tls_config));
            if (!context) {
                return std::unexpected(unavailable_transport("SRV-TLS-CONFIGURATION", context.error().message));
            }
            return std::optional<protocol_v2::OpenSslTlsContext> {std::move(*context)};
        }

        [[nodiscard]] CommandOutput failure_output(const ToolFailure &failure) {
            return {
                .exit_code = exit_code_for(failure),
                .standard_output = {},
                .standard_error = failure.code + ": " + public_diagnostic(failure.message) + '\n',
            };
        }

        [[nodiscard]] CommandOutput config_failure_output(const ServerConfigError &failure) {
            auto message = failure.code + ": " + public_diagnostic(failure.message);
            if (failure.line != 0U) {
                message += " (line " + std::to_string(failure.line) + ')';
            }
            message.push_back('\n');
            return {
                .exit_code = ExitCode::command_line_error,
                .standard_output = {},
                .standard_error = std::move(message),
            };
        }

        struct ParsedServerArguments {
            std::filesystem::path config;
            bool validate_only {};
        };

        [[nodiscard]] std::expected<ParsedServerArguments, std::string>
        parse_server_arguments(const std::span<const std::string_view> arguments) {
            ParsedServerArguments parsed;
            bool config_seen {};
            for (std::size_t index = 0U; index < arguments.size(); ++index) {
                const auto argument = arguments[index];
                if (argument == "--validate-config") {
                    if (parsed.validate_only) {
                        return std::unexpected("--validate-config was provided more than once");
                    }
                    parsed.validate_only = true;
                    continue;
                }
                if (argument == "--config") {
                    if (config_seen || index + 1U >= arguments.size() || arguments[index + 1U].starts_with("--")) {
                        return std::unexpected("--config requires exactly one path");
                    }
                    parsed.config = std::filesystem::path {arguments[++index]};
                    config_seen = true;
                    continue;
                }
                return std::unexpected("unknown option");
            }
            if (!config_seen) {
                return std::unexpected("--config PATH is required");
            }
            return parsed;
        }

    } // namespace

    std::expected<ServerConfig, ServerConfigError> parse_server_config(const std::string_view text) {
        auto entries = parse_entries(text);
        if (!entries) {
            return std::unexpected(std::move(entries.error()));
        }
        static constexpr std::string_view common_keys[] {
            "schema.version",
            "deployment.mode",
            "node.id",
            "node.platform_abi",
            "node.lease_duration_ms",
            "node.lease_renew_interval_ms",
            "store.backend",
            "store.server_processes",
            "listener.agent_endpoint",
            "listener.admin_endpoint",
            "runtime.root",
            "pack.registry_path",
            "bindings.operator_path",
            "schemas.catalog_path",
            "profiles.budget_path",
            "profiles.retention_path",
            "observability.prometheus_endpoint",
            "observability.json_log_path",
            "observability.audit_path",
        };
        if (auto required = require_keys(*entries, common_keys); !required) {
            return std::unexpected(std::move(required.error()));
        }

        const auto mode_text = *entry_value<std::string>(*entries, "deployment.mode");
        const auto store_text = *entry_value<std::string>(*entries, "store.backend");
        ServerConfig result;
        if (mode_text == "production_cluster") {
            result.mode = ServerDeploymentMode::production_cluster;
        } else if (mode_text == "single_node_dev") {
            result.mode = ServerDeploymentMode::single_node_dev;
        } else {
            return std::unexpected(
                config_error("SRV-CONFIG-MODE", "deployment.mode must be production_cluster or single_node_dev"));
        }
        if (store_text == "postgresql17") {
            result.store.kind = ServerStoreKind::postgresql17;
        } else if (store_text == "sqlite_dev") {
            result.store.kind = ServerStoreKind::sqlite_dev;
        } else {
            return std::unexpected(
                config_error("SRV-CONFIG-STORE", "store.backend must be postgresql17 or sqlite_dev"));
        }

        const auto schema_version = uint32_value(*entries, "schema.version");
        const auto processes = uint32_value(*entries, "store.server_processes");
        const auto server_major = uint16_value(*entries, "store.server_major", 17U);
        const auto pool_size = uint32_value(*entries, "store.pool_size", 16U);
        const auto lease_duration = milliseconds_value(*entries, "node.lease_duration_ms");
        const auto lease_renew_interval = milliseconds_value(*entries, "node.lease_renew_interval_ms");
        const auto statement_timeout = milliseconds_value(*entries, "store.statement_timeout_ms", 5'000U);
        const auto busy_timeout = milliseconds_value(*entries, "store.busy_timeout_ms", 5'000U);
        if (!schema_version || !processes || !server_major || !pool_size || !lease_duration || !lease_renew_interval ||
            !statement_timeout || !busy_timeout) {
            return std::unexpected(!schema_version       ? std::move(schema_version.error()) :
                                   !processes            ? std::move(processes.error()) :
                                   !server_major         ? std::move(server_major.error()) :
                                   !pool_size            ? std::move(pool_size.error()) :
                                   !lease_duration       ? std::move(lease_duration.error()) :
                                   !lease_renew_interval ? std::move(lease_renew_interval.error()) :
                                   !statement_timeout    ? std::move(statement_timeout.error()) :
                                                           std::move(busy_timeout.error()));
        }
        result.schema_version = *schema_version;
        result.node_id = *entry_value<std::string>(*entries, "node.id");
        result.platform_abi = *entry_value<std::string>(*entries, "node.platform_abi");
        result.lease_duration = *lease_duration;
        result.lease_renew_interval = *lease_renew_interval;
        result.store.connection_reference =
            entry_value<std::string>(*entries, "store.connection_reference").value_or("");
        result.store.sqlite_path = entry_value<std::string>(*entries, "store.sqlite_path").value_or("");
        result.store.server_major = *server_major;
        result.store.server_processes = *processes;
        result.store.pool_size = *pool_size;
        result.store.statement_timeout = *statement_timeout;
        result.store.busy_timeout = *busy_timeout;
        result.store.verify_tls_peer = entry_value<bool>(*entries, "store.verify_tls_peer").value_or(true);
        result.store.external_ha_configured =
            entry_value<bool>(*entries, "store.external_ha_configured").value_or(false);
        result.agent_endpoint = *entry_value<std::string>(*entries, "listener.agent_endpoint");
        result.admin_endpoint = *entry_value<std::string>(*entries, "listener.admin_endpoint");
        result.tls.trust_anchors_pem = entry_value<std::string>(*entries, "tls.trust_anchors_pem").value_or("");
        result.tls.certificate_chain_pem = entry_value<std::string>(*entries, "tls.certificate_chain_pem").value_or("");
        result.tls.private_key_pem = entry_value<std::string>(*entries, "tls.private_key_pem").value_or("");
        result.tls.crl_pem = entry_value<std::string>(*entries, "tls.crl_pem").value_or("");
        result.tls.require_crl = entry_value<bool>(*entries, "tls.require_crl").value_or(false);
        result.runtime_root = *entry_value<std::string>(*entries, "runtime.root");
        result.pack_registry_path = *entry_value<std::string>(*entries, "pack.registry_path");
        result.trusted_signers_path = entry_value<std::string>(*entries, "trust.trusted_signers_path").value_or("");
        result.revocations_path = entry_value<std::string>(*entries, "trust.revocations_path").value_or("");
        result.peer_enrollment_path = entry_value<std::string>(*entries, "trust.peer_enrollment_path").value_or("");
        result.operator_bindings_path = *entry_value<std::string>(*entries, "bindings.operator_path");
        result.schema_catalog_path = *entry_value<std::string>(*entries, "schemas.catalog_path");
        result.budget_profiles_path = *entry_value<std::string>(*entries, "profiles.budget_path");
        result.retention_profiles_path = *entry_value<std::string>(*entries, "profiles.retention_path");
        result.trace_profiles_path = entry_value<std::string>(*entries, "profiles.trace_path").value_or("");
        result.capture_profiles_path = entry_value<std::string>(*entries, "profiles.capture_path").value_or("");
        result.service_profiles_path = entry_value<std::string>(*entries, "profiles.service_path").value_or("");
        result.sink_profiles_path = entry_value<std::string>(*entries, "profiles.sink_path").value_or("");
        result.prometheus_endpoint = *entry_value<std::string>(*entries, "observability.prometheus_endpoint");
        result.json_log_path = *entry_value<std::string>(*entries, "observability.json_log_path");
        result.audit_path = *entry_value<std::string>(*entries, "observability.audit_path");
        result.otlp_endpoint = entry_value<std::string>(*entries, "observability.otlp_endpoint");
        result.allow_unsigned_packs = entry_value<bool>(*entries, "development.allow_unsigned_packs").value_or(false);
        result.allow_loopback_plaintext =
            entry_value<bool>(*entries, "development.allow_loopback_plaintext").value_or(false);
        result.allow_empty_activation =
            entry_value<bool>(*entries, "development.allow_empty_activation").value_or(false);

        if (result.mode == ServerDeploymentMode::production_cluster) {
            static constexpr std::string_view production_keys[] {
                "store.connection_reference",
                "store.server_major",
                "store.pool_size",
                "store.statement_timeout_ms",
                "store.verify_tls_peer",
                "store.external_ha_configured",
                "tls.trust_anchors_pem",
                "tls.certificate_chain_pem",
                "tls.private_key_pem",
                "tls.crl_pem",
                "tls.require_crl",
                "trust.trusted_signers_path",
                "trust.revocations_path",
                "trust.peer_enrollment_path",
                "profiles.trace_path",
                "profiles.capture_path",
                "profiles.service_path",
                "profiles.sink_path",
            };
            if (auto required = require_keys(*entries, production_keys); !required) {
                return std::unexpected(std::move(required.error()));
            }
            static constexpr std::string_view development_store_keys[] {
                "store.sqlite_path",
                "store.busy_timeout_ms",
            };
            for (const auto key : development_store_keys) {
                if (const auto found = entries->find(key); found != entries->end()) {
                    return std::unexpected(config_error(
                        "SRV-CONFIG-INAPPLICABLE-KEY",
                        "development store key is forbidden in production: " + std::string {key}, found->second.line));
                }
            }
        } else {
            static constexpr std::string_view development_keys[] {"store.sqlite_path", "store.busy_timeout_ms"};
            if (auto required = require_keys(*entries, development_keys); !required) {
                return std::unexpected(std::move(required.error()));
            }
            static constexpr std::string_view production_store_keys[] {
                "store.connection_reference", "store.server_major",    "store.pool_size",
                "store.statement_timeout_ms", "store.verify_tls_peer", "store.external_ha_configured",
            };
            for (const auto key : production_store_keys) {
                if (const auto found = entries->find(key); found != entries->end()) {
                    return std::unexpected(config_error(
                        "SRV-CONFIG-INAPPLICABLE-KEY",
                        "production store key is forbidden in development: " + std::string {key}, found->second.line));
                }
            }
        }
        if (auto valid = validate_server_config(result); !valid) {
            return std::unexpected(std::move(valid.error()));
        }
        return result;
    }

    std::expected<ServerConfig, ServerConfigError> load_server_config(const std::filesystem::path &path) {
        std::error_code size_error;
        const auto size = std::filesystem::file_size(path, size_error);
        if (size_error || size == 0U || size > maximum_config_bytes) {
            return std::unexpected(
                config_error("SRV-CONFIG-READ", "configuration file is absent, empty, or larger than one MiB"));
        }
        std::ifstream input {path, std::ios::binary};
        if (!input) {
            return std::unexpected(config_error("SRV-CONFIG-READ", "configuration file could not be opened"));
        }
        std::string text(static_cast<std::size_t>(size), '\0');
        input.read(text.data(), static_cast<std::streamsize>(text.size()));
        if (!input || input.gcount() != static_cast<std::streamsize>(text.size())) {
            return std::unexpected(config_error("SRV-CONFIG-READ", "configuration file could not be read fully"));
        }
        return parse_server_config(text);
    }

    std::expected<void, ServerConfigError> validate_server_config(const ServerConfig &config) {
        if (config.schema_version != server_config_schema_version) {
            return std::unexpected(
                config_error("SRV-CONFIG-VERSION", "only server configuration schema version 1 is supported"));
        }
        if (config.node_id.empty() || config.platform_abi.empty() || config.lease_duration.count() <= 0 ||
            config.lease_renew_interval.count() <= 0 || config.lease_renew_interval >= config.lease_duration) {
            return std::unexpected(config_error("SRV-CONFIG-NODE", "node identity and lease timings are invalid"));
        }
        const auto agent = parse_endpoint(config.agent_endpoint);
        const auto admin = parse_endpoint(config.admin_endpoint);
        const auto prometheus = parse_endpoint(config.prometheus_endpoint);
        if (!agent || !admin || !prometheus || config.agent_endpoint == config.admin_endpoint ||
            config.agent_endpoint == config.prometheus_endpoint ||
            config.admin_endpoint == config.prometheus_endpoint) {
            return std::unexpected(config_error(
                "SRV-CONFIG-ENDPOINT", "agent, admin, and Prometheus endpoints must be valid host:port values"));
        }
        const std::pair<const std::filesystem::path *, std::string_view> common_paths[] {
            {&config.runtime_root, "runtime.root"},
            {&config.pack_registry_path, "pack.registry_path"},
            {&config.operator_bindings_path, "bindings.operator_path"},
            {&config.schema_catalog_path, "schemas.catalog_path"},
            {&config.budget_profiles_path, "profiles.budget_path"},
            {&config.retention_profiles_path, "profiles.retention_path"},
            {&config.json_log_path, "observability.json_log_path"},
            {&config.audit_path, "observability.audit_path"},
        };
        for (const auto &[path, key] : common_paths) {
            if (auto nonempty = require_nonempty(*path, key); !nonempty) {
                return nonempty;
            }
        }

        if (config.mode == ServerDeploymentMode::production_cluster) {
            if (config.store.kind != ServerStoreKind::postgresql17 || config.store.server_major < 17U ||
                config.store.server_processes == 0U || config.store.pool_size == 0U ||
                config.store.statement_timeout.count() <= 0 || !config.store.verify_tls_peer ||
                (config.store.server_processes > 1U && !config.store.external_ha_configured) ||
                !valid_environment_reference(config.store.connection_reference)) {
                return std::unexpected(config_error(
                    "SRV-CONFIG-POSTGRES", "production requires secure PostgreSQL 17 and an env: secret reference"));
            }
            if (config.allow_unsigned_packs || config.allow_loopback_plaintext || config.allow_empty_activation) {
                return std::unexpected(
                    config_error("SRV-CONFIG-DEVELOPMENT-SWITCH", "development switches are forbidden in production"));
            }
            const std::pair<const std::filesystem::path *, std::string_view> production_paths[] {
                {&config.tls.trust_anchors_pem, "tls.trust_anchors_pem"},
                {&config.tls.certificate_chain_pem, "tls.certificate_chain_pem"},
                {&config.tls.private_key_pem, "tls.private_key_pem"},
                {&config.tls.crl_pem, "tls.crl_pem"},
                {&config.trusted_signers_path, "trust.trusted_signers_path"},
                {&config.revocations_path, "trust.revocations_path"},
                {&config.peer_enrollment_path, "trust.peer_enrollment_path"},
                {&config.trace_profiles_path, "profiles.trace_path"},
                {&config.capture_profiles_path, "profiles.capture_path"},
                {&config.service_profiles_path, "profiles.service_path"},
                {&config.sink_profiles_path, "profiles.sink_path"},
            };
            for (const auto &[path, key] : production_paths) {
                if (auto nonempty = require_nonempty(*path, key); !nonempty) {
                    return nonempty;
                }
            }
            if (!config.tls.require_crl) {
                return std::unexpected(config_error("SRV-CONFIG-CRL", "production TLS requires revocation checking"));
            }
            return {};
        }

        if (config.store.kind != ServerStoreKind::sqlite_dev || config.store.server_processes != 1U ||
            config.store.sqlite_path.empty() || config.store.busy_timeout.count() <= 0) {
            return std::unexpected(
                config_error("SRV-CONFIG-SQLITE", "single_node_dev requires one SQLite development process"));
        }
        if (config.allow_loopback_plaintext &&
            (!loopback_host(agent->host) || !loopback_host(admin->host) || !loopback_host(prometheus->host))) {
            return std::unexpected(
                config_error("SRV-CONFIG-PLAINTEXT", "development plaintext endpoints must all use loopback literals"));
        }
        if (!config.allow_loopback_plaintext &&
            (config.tls.trust_anchors_pem.empty() || config.tls.certificate_chain_pem.empty() ||
             config.tls.private_key_pem.empty())) {
            return std::unexpected(
                config_error("SRV-CONFIG-TLS", "development without loopback plaintext requires TLS material"));
        }
        if (!config.allow_unsigned_packs && (config.trusted_signers_path.empty() || config.revocations_path.empty())) {
            return std::unexpected(config_error(
                "SRV-CONFIG-TRUST", "signed development packs require trusted signer and revocation policies"));
        }
        if (!config.allow_loopback_plaintext && config.peer_enrollment_path.empty()) {
            return std::unexpected(
                config_error("SRV-CONFIG-PEER-TRUST", "development mTLS requires a peer enrollment policy"));
        }
        return {};
    }

    std::expected<void, ToolFailure>
    UnavailableResidentServerBackend::qualify_activation(const ResidentServerContext &) noexcept {
        return std::unexpected(unavailable(
            "SRV-ACTIVATION-UNAVAILABLE",
            "the current runtime-store contract has no durable active-generation loader; startup is fenced"));
    }

    std::expected<void, ToolFailure> UnavailableResidentServerBackend::serve(const ResidentServerContext &) noexcept {
        return std::unexpected(unavailable_transport(
            "SRV-NETWORK-UNAVAILABLE",
            "protocol v2 exposes TLS for connected sockets but no resident listener/acceptor API"));
    }

    std::string_view server_help() noexcept { return help_text; }

    CommandOutput run_rule_engine_server(const std::span<const std::string_view> arguments,
                                         ResidentServerBackend &backend) {
        if (arguments.size() == 1U && arguments.front() == "--help") {
            return {
                .exit_code = ExitCode::success,
                .standard_output = std::string {help_text},
                .standard_error = {},
            };
        }
        if (arguments.size() == 1U && arguments.front() == "--version") {
            return {
                .exit_code = ExitCode::success,
                .standard_output = "rule_engine_server " + std::string {tools_api_version} + '\n',
                .standard_error = {},
            };
        }
        if (std::ranges::find(arguments, "--help") != arguments.end() ||
            std::ranges::find(arguments, "--version") != arguments.end()) {
            return {
                .exit_code = ExitCode::command_line_error,
                .standard_output = {},
                .standard_error = "SRV-CLI-USAGE: --help and --version must be used alone\n",
            };
        }
        auto parsed = parse_server_arguments(arguments);
        if (!parsed) {
            return {
                .exit_code = ExitCode::command_line_error,
                .standard_output = {},
                .standard_error = "SRV-CLI-USAGE: " + parsed.error() + '\n',
            };
        }
        auto config = load_server_config(parsed->config);
        if (!config) {
            return config_failure_output(config.error());
        }
        if (parsed->validate_only) {
            const auto mode =
                config->mode == ServerDeploymentMode::production_cluster ? "production_cluster" : "single_node_dev";
            const auto store = config->store.kind == ServerStoreKind::postgresql17 ? "postgresql17" : "sqlite_dev";
            return {
                .exit_code = ExitCode::success,
                .standard_output =
                    "configuration valid\nschema: rule-engine.server-config.v1\nmode: " + std::string {mode} +
                    "\nstore: " + std::string {store} + "\nstartup qualification: not run\n",
                .standard_error = {},
            };
        }

        auto capabilities = backend_capabilities(*config);
        if (!capabilities) {
            return failure_output(capabilities.error());
        }
        if (auto references = qualify_local_references(*config); !references) {
            return failure_output(references.error());
        }
        auto runtime = packaging::load_exact_private_runtime(config->runtime_root);
        if (!runtime) {
            return failure_output(unavailable("SRV-RUNTIME-UNAVAILABLE", runtime.error().message));
        }
        auto tls = create_tls(*config);
        if (!tls) {
            return failure_output(tls.error());
        }
        cluster::AuditTrail audit;
        auto store = open_store(*config, audit);
        if (!store) {
            return failure_output(store.error());
        }
        const auto health = (*store)->health();
        if (!health.driver_available || !health.connected || !health.migrations_compatible) {
            return failure_output(unavailable("SRV-STORE-NOT-READY", health.detail));
        }
        const ResidentServerContext context {
            .config = *config,
            .store = **store,
            .runtime = *runtime,
            .tls = tls->has_value() ? std::addressof(**tls) : nullptr,
        };
        if (!config->allow_empty_activation) {
            if (auto active = backend.qualify_activation(context); !active) {
                return failure_output(active.error());
            }
        }
        if (auto served = backend.serve(context); !served) {
            return failure_output(served.error());
        }
        return {
            .exit_code = ExitCode::internal_invariant_failed,
            .standard_output = {},
            .standard_error = "SRV-INVARIANT: resident backend returned without a terminal failure\n",
        };
    }

} // namespace rule_engine::python::tools
