#include "rule_engine/python/tools/server.hpp"

#include "rule_engine/python/cluster/configuration.hpp"

#include <asio/ip/address.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <stop_token>
#include <string>
#include <thread>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

namespace rule_engine::python::tools {
    namespace {

        constexpr std::size_t maximum_config_bytes = 1U * mebibyte;
        constexpr std::size_t maximum_config_line_bytes = 4U * kibibyte;
        constexpr std::size_t maximum_config_entries = 128U;
        constexpr std::size_t maximum_public_diagnostic_bytes = 2U * kibibyte;
        constexpr std::size_t maximum_policy_bytes = 1U * mebibyte;
        constexpr std::size_t maximum_policy_line_bytes = 4U * kibibyte;
        constexpr std::size_t maximum_policy_entries = 4'096U;

        [[nodiscard]] std::uint64_t now_unix_ms() noexcept;

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
  listener.accept_timeout_ms, listener.handshake_timeout_ms,
  listener.read_timeout_ms, listener.write_timeout_ms, listener.backlog,
  listener.maximum_consecutive_failures, network.require_hard_resolver_bounds,
  service.worker_threads, service.maximum_queued_sessions,
  service.maximum_memory_bytes, service.maximum_frame_bytes,
  service.maximum_messages_per_session, service.maximum_inflight_work_per_session,
  service.maximum_session_duration_ms, service.inbound_credit_bytes,
  service.inbound_credit_messages, service.inbound_credit_work_attempts,
  service.inbound_credit_snapshot_chunks,
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

Listener hosts are numeric literals; resident startup performs no DNS lookup.
Policy snapshots are bounded, versioned tab-separated UTF-8 files. The peer
snapshot header is rule-engine.peer-enrollment.v1; signer and revocation headers
are rule-engine.trusted-signers.v1 and rule-engine.revocations.v1.

Authenticated application sessions run on a fixed owned worker pool with a
bounded queue and memory reservation. Agent ACKs require a backend-declared
durable receipt. The current production composition has no durable agent-receipt
table or activated event-to-work scheduler, so it establishes fenced sessions
with zero work and zero durable-message credit; a peer that ignores credit is
transiently NACKed without advancing ACK. The
bounded admin wire surface currently supports pack/operation reads and the
final activation flip; other control-plane operations remain CLI/backend work.
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
                {"listener.accept_timeout_ms", ValueKind::integer},
                {"listener.handshake_timeout_ms", ValueKind::integer},
                {"listener.read_timeout_ms", ValueKind::integer},
                {"listener.write_timeout_ms", ValueKind::integer},
                {"listener.backlog", ValueKind::integer},
                {"listener.maximum_consecutive_failures", ValueKind::integer},
                {"network.require_hard_resolver_bounds", ValueKind::boolean},
                {"service.worker_threads", ValueKind::integer},
                {"service.maximum_queued_sessions", ValueKind::integer},
                {"service.maximum_memory_bytes", ValueKind::integer},
                {"service.maximum_frame_bytes", ValueKind::integer},
                {"service.maximum_messages_per_session", ValueKind::integer},
                {"service.maximum_inflight_work_per_session", ValueKind::integer},
                {"service.maximum_session_duration_ms", ValueKind::integer},
                {"service.inbound_credit_bytes", ValueKind::integer},
                {"service.inbound_credit_messages", ValueKind::integer},
                {"service.inbound_credit_work_attempts", ValueKind::integer},
                {"service.inbound_credit_snapshot_chunks", ValueKind::integer},
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

        [[nodiscard]] bool numeric_host(const std::string_view host) noexcept {
            asio::error_code error;
            static_cast<void>(asio::ip::make_address(host, error));
            return !error;
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

        struct SensitiveValue {
            explicit SensitiveValue(std::string input): value {std::move(input)} {}
            SensitiveValue(SensitiveValue &&) noexcept = default;
            SensitiveValue &operator=(SensitiveValue &&) noexcept = delete;
            SensitiveValue(const SensitiveValue &) = delete;
            SensitiveValue &operator=(const SensitiveValue &) = delete;
            ~SensitiveValue() { wipe(); }

            void wipe() noexcept {
                std::ranges::fill(value, '\0');
                value.clear();
            }

            std::string value;
        };

        [[nodiscard]] cluster::SqliteDevConfig sqlite_store_config(const ServerConfig &config) {
            return {
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

        [[nodiscard]] cluster::PostgreSql17Config postgresql_store_config(const ServerConfig &config) {
            return {
                .connection_reference = config.store.connection_reference,
                .server_major = config.store.server_major,
                .server_processes = config.store.server_processes,
                .pool_size = config.store.pool_size,
                .statement_timeout = config.store.statement_timeout,
                .verify_tls_peer = config.store.verify_tls_peer,
                .external_ha_configured = config.store.external_ha_configured,
                .deployment_mode = cluster::DeploymentMode::production_cluster,
            };
        }

        [[nodiscard]] std::expected<SensitiveValue, ToolFailure> resolve_store_connection(const ServerConfig &config) {
            if (config.store.kind == ServerStoreKind::sqlite_dev) {
                return SensitiveValue {std::string {}};
            }
            const auto environment_name = std::string_view {config.store.connection_reference}.substr(4U);
            auto connection = environment_value(environment_name);
            if (!connection || connection->empty()) {
                return std::unexpected(unavailable("SRV-POSTGRES-SECRET-UNAVAILABLE",
                                                   "PostgreSQL connection reference could not be resolved"));
            }
            return SensitiveValue {std::move(*connection)};
        }

        [[nodiscard]] std::expected<std::unique_ptr<cluster::IClusterRuntimeStore>, ToolFailure>
        open_store(const ServerConfig &config, cluster::AuditTrail &audit, const std::string_view connection) {
            if (config.store.kind == ServerStoreKind::sqlite_dev) {
                auto store = cluster::SqliteRuntimeStore::open(sqlite_store_config(config), audit);
                if (!store) {
                    return std::unexpected(unavailable("SRV-SQLITE-UNAVAILABLE", store.error().message));
                }
                return std::unique_ptr<cluster::IClusterRuntimeStore> {std::move(*store)};
            }

            auto store =
                cluster::PostgreSqlRuntimeStore::open_resolved(postgresql_store_config(config), connection, audit);
            if (!store) {
                return std::unexpected(unavailable(
                    "SRV-POSTGRES-UNAVAILABLE",
                    "PostgreSQL connectivity, verified TLS, server version, or migrations could not be qualified"));
            }
            return std::unique_ptr<cluster::IClusterRuntimeStore> {std::move(*store)};
        }

        [[nodiscard]] std::expected<std::unique_ptr<cluster::IActivationControlStore>, ToolFailure>
        open_activation_store(const ServerConfig &config, const std::string_view connection) {
            if (config.store.kind == ServerStoreKind::sqlite_dev) {
                auto store = cluster::SqliteActivationControlStore::open(sqlite_store_config(config));
                if (!store) {
                    return std::unexpected(unavailable("SRV-ACTIVATION-SQLITE-UNAVAILABLE", store.error().message));
                }
                return std::unique_ptr<cluster::IActivationControlStore> {std::move(*store)};
            }

            auto store =
                cluster::PostgreSqlActivationControlStore::open_resolved(postgresql_store_config(config), connection);
            if (!store) {
                return std::unexpected(
                    unavailable("SRV-ACTIVATION-POSTGRES-UNAVAILABLE",
                                "durable activation connectivity or migrations could not be qualified"));
            }
            return std::unique_ptr<cluster::IActivationControlStore> {std::move(*store)};
        }

        [[nodiscard]] std::expected<std::vector<std::string>, ToolFailure>
        read_policy_lines(const std::filesystem::path &path, const std::string_view expected_header) {
            std::error_code size_error;
            const auto size = std::filesystem::file_size(path, size_error);
            if (size_error || size == 0U || size > maximum_policy_bytes) {
                return std::unexpected(unavailable("SRV-TRUST-POLICY-READ",
                                                   "trust policy snapshot is absent, empty, or larger than one MiB"));
            }
            std::ifstream input {path, std::ios::binary};
            if (!input) {
                return std::unexpected(
                    unavailable("SRV-TRUST-POLICY-READ", "trust policy snapshot could not be opened"));
            }
            std::string text(static_cast<std::size_t>(size), '\0');
            input.read(text.data(), static_cast<std::streamsize>(text.size()));
            if (!input || input.gcount() != static_cast<std::streamsize>(text.size()) ||
                text.find('\0') != std::string::npos) {
                return std::unexpected(
                    unavailable("SRV-TRUST-POLICY-READ", "trust policy snapshot could not be read safely"));
            }

            std::vector<std::string> lines;
            std::size_t offset {};
            std::size_t physical_line {};
            bool header_seen {};
            while (offset <= text.size()) {
                ++physical_line;
                const auto newline = text.find('\n', offset);
                const auto line_end = newline == std::string::npos ? text.size() : newline;
                auto line = std::string_view {text}.substr(offset, line_end - offset);
                if (!line.empty() && line.back() == '\r') {
                    line.remove_suffix(1U);
                }
                if (line.size() > maximum_policy_line_bytes) {
                    return std::unexpected(
                        unavailable("SRV-TRUST-POLICY-LINE-LIMIT", "trust policy snapshot line exceeds four KiB"));
                }
                if (!header_seen) {
                    if (physical_line != 1U || line != expected_header) {
                        return std::unexpected(
                            unavailable("SRV-TRUST-POLICY-VERSION", "trust policy snapshot has an unsupported header"));
                    }
                    header_seen = true;
                } else if (!line.empty() && line.front() != '#') {
                    lines.emplace_back(line);
                    if (lines.size() > maximum_policy_entries) {
                        return std::unexpected(
                            unavailable("SRV-TRUST-POLICY-ENTRY-LIMIT", "trust policy snapshot has too many entries"));
                    }
                }
                if (newline == std::string_view::npos) {
                    break;
                }
                offset = newline + 1U;
            }
            return lines;
        }

        [[nodiscard]] std::vector<std::string_view> split_fields(const std::string_view value, const char separator) {
            std::vector<std::string_view> fields;
            std::size_t offset {};
            while (offset <= value.size()) {
                const auto next = value.find(separator, offset);
                const auto end = next == std::string_view::npos ? value.size() : next;
                fields.push_back(value.substr(offset, end - offset));
                if (next == std::string_view::npos) {
                    break;
                }
                offset = next + 1U;
            }
            return fields;
        }

        [[nodiscard]] bool safe_policy_atom(const std::string_view value, const std::size_t maximum = 512U) noexcept {
            return !value.empty() && value.size() <= maximum && std::ranges::all_of(value, [](const char character) {
                const auto byte = static_cast<unsigned char>(character);
                return byte >= 0x21U && byte <= 0x7eU && character != '\t';
            });
        }

        [[nodiscard]] bool lowercase_hex(const std::string_view value, const std::size_t size) noexcept {
            return value.size() == size && std::ranges::all_of(value, [](const char character) {
                       return (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f');
                   });
        }

        [[nodiscard]] std::expected<std::vector<std::byte>, ToolFailure>
        decode_public_key(const std::string_view encoded) {
            if (!lowercase_hex(encoded, 64U)) {
                return std::unexpected(unavailable("SRV-TRUST-SIGNER-MALFORMED",
                                                   "trusted signer public key must be canonical 32-byte hexadecimal"));
            }
            std::vector<std::byte> result;
            result.reserve(32U);
            const auto nibble = [](const char character) -> std::optional<unsigned char> {
                if (character >= '0' && character <= '9') {
                    return static_cast<unsigned char>(character - '0');
                }
                if (character >= 'a' && character <= 'f') {
                    return static_cast<unsigned char>(character - 'a' + 10);
                }
                return std::nullopt;
            };
            for (std::size_t index = 0U; index < encoded.size(); index += 2U) {
                const auto high = nibble(encoded[index]);
                const auto low = nibble(encoded[index + 1U]);
                if (!high || !low) {
                    return std::unexpected(
                        unavailable("SRV-TRUST-SIGNER-MALFORMED", "trusted signer public key is not hexadecimal"));
                }
                result.push_back(static_cast<std::byte>((*high << 4U) | *low));
            }
            return result;
        }

        [[nodiscard]] std::expected<packaging::TrustPolicy, ToolFailure>
        load_pack_trust_policy(const ServerConfig &config) {
            packaging::TrustPolicy policy {
                .mode = config.mode == ServerDeploymentMode::production_cluster ? packaging::TrustMode::production :
                                                                                  packaging::TrustMode::development,
                .allow_unsigned_packs = config.allow_unsigned_packs,
                .allow_unsigned_generators = false,
                .signers = {},
            };
            if (config.trusted_signers_path.empty()) {
                return policy;
            }

            auto revocation_lines = read_policy_lines(config.revocations_path, "rule-engine.revocations.v1");
            auto signer_lines = read_policy_lines(config.trusted_signers_path, "rule-engine.trusted-signers.v1");
            if (!revocation_lines || !signer_lines) {
                return std::unexpected(!revocation_lines ? std::move(revocation_lines.error()) :
                                                           std::move(signer_lines.error()));
            }
            std::unordered_set<std::string> revoked;
            for (const auto &line : *revocation_lines) {
                if (!safe_policy_atom(line, 128U) || !revoked.insert(line).second) {
                    return std::unexpected(unavailable("SRV-TRUST-REVOCATION-MALFORMED",
                                                       "revocation snapshot contains an invalid or duplicate key"));
                }
            }

            std::unordered_set<std::string> signer_ids;
            for (const auto &line : *signer_lines) {
                const auto fields = split_fields(line, '\t');
                if (fields.size() != 3U || !safe_policy_atom(fields[0], 128U) ||
                    !signer_ids.insert(std::string {fields[0]}).second) {
                    return std::unexpected(
                        unavailable("SRV-TRUST-SIGNER-MALFORMED", "trusted signer snapshot contains an invalid entry"));
                }
                auto public_key = decode_public_key(fields[1]);
                if (!public_key) {
                    return std::unexpected(std::move(public_key.error()));
                }
                auto prefixes = split_fields(fields[2], ',');
                if (prefixes.empty() || std::ranges::any_of(prefixes, [](const std::string_view prefix) {
                        return !safe_policy_atom(prefix, 256U);
                    })) {
                    return std::unexpected(
                        unavailable("SRV-TRUST-SIGNER-MALFORMED", "trusted signer pack prefixes are invalid"));
                }
                packaging::TrustedSigner signer {
                    .key_id = std::string {fields[0]},
                    .public_key = std::move(*public_key),
                    .allowed_pack_prefixes = {},
                    .revoked = revoked.contains(std::string {fields[0]}),
                };
                signer.allowed_pack_prefixes.reserve(prefixes.size());
                for (const auto prefix : prefixes) { signer.allowed_pack_prefixes.emplace_back(prefix); }
                policy.signers.push_back(std::move(signer));
            }
            if (std::ranges::any_of(revoked,
                                    [&signer_ids](const std::string &key) { return !signer_ids.contains(key); })) {
                return std::unexpected(
                    unavailable("SRV-TRUST-REVOCATION-UNKNOWN", "revocation snapshot references an unknown signer"));
            }
            if (!config.allow_unsigned_packs &&
                std::ranges::none_of(policy.signers,
                                     [](const packaging::TrustedSigner &signer) { return !signer.revoked; })) {
                return std::unexpected(
                    unavailable("SRV-TRUST-NO-ACTIVE-SIGNER", "signed pack trust policy has no active signer"));
            }
            return policy;
        }

        [[nodiscard]] std::expected<std::vector<protocol_v2::CapabilityPermission>, ToolFailure>
        parse_capability_permissions(const std::string_view encoded) {
            std::vector<protocol_v2::CapabilityPermission> result;
            if (encoded == "-") {
                return result;
            }
            const auto permissions = split_fields(encoded, ';');
            if (permissions.size() > 256U) {
                return std::unexpected(
                    unavailable("SRV-TRUST-PEER-MALFORMED", "peer enrollment contains too many capabilities"));
            }
            for (const auto permission : permissions) {
                const auto fields = split_fields(permission, '|');
                std::uint32_t maximum_version {};
                if (fields.size() != 4U || !safe_policy_atom(fields[0], 128U) || !safe_policy_atom(fields[2], 128U) ||
                    !safe_policy_atom(fields[3], 128U)) {
                    return std::unexpected(
                        unavailable("SRV-TRUST-PEER-MALFORMED", "peer capability permission is malformed"));
                }
                const auto parsed =
                    std::from_chars(fields[1].data(), fields[1].data() + fields[1].size(), maximum_version);
                if (maximum_version == 0U || parsed.ec != std::errc {} ||
                    parsed.ptr != fields[1].data() + fields[1].size()) {
                    return std::unexpected(
                        unavailable("SRV-TRUST-PEER-MALFORMED", "peer capability version is invalid"));
                }
                result.push_back({
                    .capability = CapabilityId {std::string {fields[0]}},
                    .maximum_version = maximum_version,
                    .request_schema = SchemaId {std::string {fields[2]}},
                    .response_schema = SchemaId {std::string {fields[3]}},
                });
            }
            return result;
        }

        [[nodiscard]] std::expected<std::unique_ptr<protocol_v2::OperatorTrustPolicy>, ToolFailure>
        load_peer_trust_policy(const ServerConfig &config) {
            auto policy = std::make_unique<protocol_v2::OperatorTrustPolicy>();
            if (config.peer_enrollment_path.empty()) {
                return policy;
            }
            auto lines = read_policy_lines(config.peer_enrollment_path, "rule-engine.peer-enrollment.v1");
            if (!lines) {
                return std::unexpected(std::move(lines.error()));
            }
            std::size_t enabled {};
            for (const auto &line : *lines) {
                const auto fields = split_fields(line, '\t');
                if (fields.size() != 6U || !safe_policy_atom(fields[0], 1'024U) ||
                    (fields[1] != "-" && !lowercase_hex(fields[1], 64U)) || !safe_policy_atom(fields[2], 128U) ||
                    !safe_policy_atom(fields[3], 128U) || (fields[4] != "true" && fields[4] != "false")) {
                    return std::unexpected(
                        unavailable("SRV-TRUST-PEER-MALFORMED", "peer enrollment snapshot contains an invalid entry"));
                }
                auto capabilities = parse_capability_permissions(fields[5]);
                if (!capabilities) {
                    return std::unexpected(std::move(capabilities.error()));
                }
                const auto disabled = fields[4] == "true";
                protocol_v2::PeerEnrollment enrollment {
                    .canonical_uri_san = std::string {fields[0]},
                    .certificate_sha256 = fields[1] == "-" ? std::string {} : std::string {fields[1]},
                    .identity = {.tenant = TenantId {std::string {fields[2]}},
                                 .peer = PeerId {std::string {fields[3]}}},
                    .disabled = disabled,
                    .capabilities = std::move(*capabilities),
                };
                if (auto enrolled = policy->enroll(std::move(enrollment)); !enrolled) {
                    return std::unexpected(unavailable("SRV-TRUST-PEER-MALFORMED",
                                                       "peer enrollment snapshot contains duplicate identities"));
                }
                enabled += disabled ? 0U : 1U;
            }
            if (!config.allow_loopback_plaintext && enabled == 0U) {
                return std::unexpected(
                    unavailable("SRV-TRUST-NO-ACTIVE-PEER", "mTLS peer policy has no active enrollment"));
            }
            return policy;
        }

        [[nodiscard]] std::string admin_capability(const cluster::AdminControlOperation operation) {
            using enum cluster::AdminControlOperation;
            switch (operation) {
                case pack_read: return "pack.read";
                case operation_read: return "operation.read";
                case activation_flip: return "pack.activate";
                case stage_preview:
                case stage_apply:
                case activation_preview:
                case activation_drain:
                case activation_fence:
                case rollback_preview:
                case rollback_stage_apply:
                case pack_inspect: return {};
                default: return {};
            }
        }

        struct OperatorBindingPolicy final: IResidentAdminAccessPolicy {
            struct Binding {
                protocol_v2::AuthenticatedPeer peer;
                cluster::AuthenticatedAdminPrincipal principal;
                std::string pack_prefix;
                std::set<std::string, std::less<>> capabilities;
            };

            [[nodiscard]] std::expected<cluster::AuthenticatedAdminPrincipal, cluster::AuthorizedAdminError>
            principal_for(const protocol_v2::AuthenticatedPeer &peer) const noexcept override {
                const auto found = std::ranges::find_if(bindings, [&](const Binding &binding) {
                    return binding.peer.tenant == peer.tenant && binding.peer.peer == peer.peer;
                });
                if (found == bindings.end()) {
                    return std::unexpected(cluster::AuthorizedAdminError {
                        .code = cluster::AuthorizedAdminErrorCode::unauthenticated,
                        .message = "authenticated TLS peer has no administrator binding",
                        .retryable = false,
                        .store_code = std::nullopt,
                    });
                }
                return found->principal;
            }

            [[nodiscard]] std::expected<cluster::AdminAuthorizationDecision, cluster::AdminAuthorizerFailure>
            authorize(const cluster::AuthenticatedAdminPrincipal &principal,
                      const cluster::AdminAuthorizationRequest &request) const override {
                const auto found = std::ranges::find_if(bindings, [&](const Binding &binding) {
                    return binding.principal.principal_id == principal.principal_id;
                });
                if (found == bindings.end()) {
                    return cluster::AdminAuthorizationDecision {
                        .outcome = cluster::AdminAuthorizationOutcome::denied,
                        .decision_id = "operator-binding-missing",
                        .detail = "principal binding is no longer current",
                    };
                }
                const auto capability = admin_capability(request.operation);
                const auto tenant_matches = request.resource.tenant == found->principal.home_tenant;
                const auto pack_matches = request.resource.pack.value.starts_with(found->pack_prefix);
                const auto allowed =
                    !capability.empty() && found->capabilities.contains(capability) && tenant_matches && pack_matches;
                return cluster::AdminAuthorizationDecision {
                    .outcome = allowed ? cluster::AdminAuthorizationOutcome::allowed :
                                         cluster::AdminAuthorizationOutcome::denied,
                    .decision_id = allowed ? "operator-binding-allowed" : "operator-binding-denied",
                    .detail = allowed ? "named operator capability matched" :
                                        "tenant, pack prefix, or named capability did not match",
                };
            }

            std::vector<Binding> bindings;
        };

        [[nodiscard]] std::expected<std::unique_ptr<OperatorBindingPolicy>, ToolFailure>
        load_operator_bindings(const ServerConfig &config) {
            auto lines = read_policy_lines(config.operator_bindings_path, "rule-engine.operator-bindings.v1");
            if (!lines) {
                return std::unexpected(std::move(lines.error()));
            }
            auto policy = std::make_unique<OperatorBindingPolicy>();
            std::unordered_set<std::string> peers;
            std::unordered_set<std::string> principals;
            for (const auto &line : *lines) {
                const auto fields = split_fields(line, '\t');
                if (fields.size() != 7U || !safe_policy_atom(fields[0], 128U) || !safe_policy_atom(fields[1], 128U) ||
                    !safe_policy_atom(fields[2], 128U) || !safe_policy_atom(fields[4], 128U) ||
                    !safe_policy_atom(fields[5], 256U)) {
                    return std::unexpected(unavailable("SRV-OPERATOR-BINDING-MALFORMED",
                                                       "operator binding snapshot contains an invalid entry"));
                }
                cluster::AdminPrincipalKind kind {};
                if (fields[3] == "administrator") {
                    kind = cluster::AdminPrincipalKind::administrator;
                } else if (fields[3] == "automation") {
                    kind = cluster::AdminPrincipalKind::automation;
                } else if (fields[3] == "pack_signer") {
                    kind = cluster::AdminPrincipalKind::pack_signer;
                } else {
                    return std::unexpected(
                        unavailable("SRV-OPERATOR-BINDING-MALFORMED", "operator binding principal kind is invalid"));
                }
                const auto peer_key = std::string {fields[0]} + '\n' + std::string {fields[1]};
                if (!peers.insert(peer_key).second || !principals.insert(std::string {fields[2]}).second) {
                    return std::unexpected(unavailable("SRV-OPERATOR-BINDING-DUPLICATE",
                                                       "operator binding peer or principal is duplicated"));
                }
                auto capabilities = split_fields(fields[6], ',');
                std::set<std::string, std::less<>> named;
                for (const auto capability : capabilities) {
                    if ((capability != "pack.read" && capability != "operation.read" &&
                         capability != "pack.activate") ||
                        !named.insert(std::string {capability}).second) {
                        return std::unexpected(unavailable("SRV-OPERATOR-BINDING-MALFORMED",
                                                           "operator binding capability is unknown or duplicated"));
                    }
                }
                policy->bindings.push_back(OperatorBindingPolicy::Binding {
                    .peer = {.tenant = TenantId {std::string {fields[0]}}, .peer = PeerId {std::string {fields[1]}}},
                    .principal = {.principal_id = std::string {fields[2]},
                                  .home_tenant = TenantId {std::string {fields[4]}},
                                  .kind = kind,
                                  .authentication_id = peer_key},
                    .pack_prefix = std::string {fields[5]},
                    .capabilities = std::move(named),
                });
            }
            if (policy->bindings.empty()) {
                return std::unexpected(
                    unavailable("SRV-OPERATOR-BINDING-EMPTY", "operator binding snapshot has no explicit principals"));
            }
            return policy;
        }

        struct FileAdminSecurityAudit final: cluster::IAdminSecurityAuditSink {
            explicit FileAdminSecurityAudit(std::filesystem::path path): path_ {std::move(path)} {}

            void record(const cluster::AdminSecurityAuditEvent &event) noexcept override {
                std::scoped_lock lock {mutex_};
                std::ofstream output {path_, std::ios::binary | std::ios::app};
                if (!output) {
                    return;
                }
                output << event.at_unix_ms << '\t' << static_cast<unsigned int>(event.outcome) << '\t'
                       << (event.principal_id ? *event.principal_id : "-") << '\t'
                       << event.request.resource.tenant.value << '\t' << event.request.resource.pack.value << '\n';
            }

        private:
            std::filesystem::path path_;
            std::mutex mutex_;
        };

        struct StoreBackedAgentSessionBackend final: IResidentAgentBackend {
            StoreBackedAgentSessionBackend(cluster::IClusterRuntimeStore &store, std::string node_id,
                                           const std::chrono::milliseconds lease_duration) noexcept:
                store_ {store}, node_id_ {std::move(node_id)}, lease_duration_ {lease_duration} {}

            [[nodiscard]] std::expected<ResidentAgentSession, protocol_v2::ProtocolError>
            establish(const protocol_v2::AuthenticatedPeer &peer, const protocol_v2::AgentHelloMessage &hello,
                      const std::stop_token cancellation) noexcept override {
                if (cancellation.stop_requested()) {
                    return std::unexpected(
                        protocol_v2::ProtocolError {.code = protocol_v2::ProtocolErrorCode::canceled,
                                                    .message = "agent session establishment canceled"});
                }
                const auto serial = next_session_.fetch_add(1U, std::memory_order_relaxed) + 1U;
                const auto session_id = "session:" + node_id_ + ':' + std::to_string(serial);
                const cluster::LeaseResource resource {
                    .scope = "agent-session",
                    .key = peer.tenant.value + "/" + peer.peer.value,
                };
                auto lease = store_.claim_lease(resource, session_id, now_unix_ms(),
                                                static_cast<std::uint64_t>(lease_duration_.count()));
                if (!lease) {
                    return std::unexpected(protocol_v2::ProtocolError {
                        .code = protocol_v2::ProtocolErrorCode::backpressured,
                        .message = "current peer session lease has not expired",
                    });
                }
                const auto consumer = receipt_key(peer, hello.agent_epoch);
                auto acknowledged = store_.load_consumer_fence(consumer);
                if (!acknowledged) {
                    static_cast<void>(store_.release_lease(*lease, now_unix_ms()));
                    return std::unexpected(protocol_v2::ProtocolError {
                        .code = protocol_v2::ProtocolErrorCode::persistence_error,
                        .message = "durable agent receipt could not be loaded",
                    });
                }
                {
                    std::scoped_lock lock {mutex_};
                    sessions_.emplace(session_id, *lease);
                }
                return ResidentAgentSession {
                    .authenticated_peer = peer,
                    .session = SessionId {session_id},
                    .session_fence = lease->fence,
                    .agent_epoch = hello.agent_epoch,
                    .acknowledged_through = *acknowledged,
                    .credit = {},
                };
            }

            [[nodiscard]] std::expected<std::vector<protocol_v2::WorkLeaseMessage>, protocol_v2::ProtocolError>
            take_work(const ResidentAgentSession &, const std::size_t,
                      const std::stop_token cancellation) noexcept override {
                if (cancellation.stop_requested()) {
                    return std::unexpected(protocol_v2::ProtocolError {.code = protocol_v2::ProtocolErrorCode::canceled,
                                                                       .message = "agent work poll canceled"});
                }
                // No event-to-compiled-pack scheduler exists in the current
                // composition. Returning no work is safe and keeps C++ as the
                // only future owner of semantic requests.
                return std::vector<protocol_v2::WorkLeaseMessage> {};
            }

            [[nodiscard]] std::expected<DurableAgentReceipt, protocol_v2::ProtocolError>
            persist(const ResidentAgentSession &, const std::uint64_t, const protocol_v2::DurableAgentBody &,
                    const std::stop_token) noexcept override {
                // IClusterRuntimeStore has no peer_sessions/agent_receipts
                // transaction and no authoritative snapshot persistence seam.
                // Never manufacture a cumulative ACK from an in-memory result.
                return std::unexpected(protocol_v2::ProtocolError {
                    .code = protocol_v2::ProtocolErrorCode::dependency_unavailable,
                    .message = "durable protocol-v2 agent receipt backend is not implemented",
                });
            }

            void close(const ResidentAgentSession &session) noexcept override {
                std::optional<cluster::FencedLease> lease;
                {
                    std::scoped_lock lock {mutex_};
                    const auto found = sessions_.find(session.session.value);
                    if (found != sessions_.end()) {
                        lease = found->second;
                        sessions_.erase(found);
                    }
                }
                if (lease) {
                    static_cast<void>(store_.release_lease(*lease, now_unix_ms()));
                }
            }

        private:
            [[nodiscard]] static std::string receipt_key(const protocol_v2::AuthenticatedPeer &peer,
                                                         const std::string_view epoch) {
                return "agent-receipt/" + peer.tenant.value + '/' + peer.peer.value + '/' + std::string {epoch};
            }

            cluster::IClusterRuntimeStore &store_;
            std::string node_id_;
            std::chrono::milliseconds lease_duration_;
            std::atomic<std::uint64_t> next_session_ {};
            std::mutex mutex_;
            std::map<std::string, cluster::FencedLease, std::less<>> sessions_;
        };

        [[nodiscard]] std::expected<cluster::StoreBackendCapabilities, ToolFailure>
        backend_capabilities(const ServerConfig &config) {
            cluster::StoreBackendConfig selected;
            if (config.store.kind == ServerStoreKind::postgresql17) {
                selected = postgresql_store_config(config);
            } else {
                selected = sqlite_store_config(config);
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
                .protocol_limits = {.maximum_frame_bytes = config.service.maximum_frame_bytes},
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

        [[nodiscard]] std::uint64_t now_unix_ms() noexcept {
            const auto elapsed = std::chrono::system_clock::now().time_since_epoch();
            return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count());
        }

        struct ActivationQualification {
            bool active_generation_compiled {true};
            bool schemas_compatible {true};
            bool required_capabilities_available {true};
        };

        [[nodiscard]] ActivationQualification qualify_control_state(const cluster::DurableControlState &state,
                                                                    const ServerConfig &config,
                                                                    const std::uint64_t node_lease_fence) {
            ActivationQualification result;
            if (state.packs.empty()) {
                result.active_generation_compiled = config.allow_empty_activation;
                result.schemas_compatible = config.allow_empty_activation;
                result.required_capabilities_available = config.allow_empty_activation;
                return result;
            }

            for (const auto &pack : state.packs) {
                if (pack.resource_version == 0U || pack.assignment_fence == 0U || !pack.active_generation ||
                    !pack.accepting_assignments || pack.drain_target) {
                    result.active_generation_compiled = false;
                    continue;
                }
                const auto generation = std::ranges::find_if(state.generations, [&pack](const auto &candidate) {
                    return candidate.request.pack == pack.pack &&
                           candidate.request.generation == *pack.active_generation;
                });
                if (generation == state.generations.end() || generation->phase != cluster::GenerationPhase::active ||
                    !generation->request.signature_verified) {
                    result.active_generation_compiled = false;
                    continue;
                }
                if (!generation->target_nodes.empty() &&
                    std::ranges::find(generation->target_nodes, config.node_id) == generation->target_nodes.end()) {
                    result.active_generation_compiled = false;
                    continue;
                }
                if (generation->semantic_hash.empty() || generation->binding_hash.empty() ||
                    generation->request.state_schema_hash.empty()) {
                    result.schemas_compatible = false;
                }
                const auto report = std::ranges::find_if(generation->reports, [&config](const auto &candidate) {
                    return candidate.node_id == config.node_id;
                });
                if (report == generation->reports.end() || !report->success ||
                    report->node_lease_fence != node_lease_fence || report->executable_hash.empty() ||
                    report->semantic_hash != generation->semantic_hash ||
                    report->binding_hash != generation->binding_hash) {
                    result.active_generation_compiled = false;
                    continue;
                }
                for (const auto &required : generation->request.required_capability_hashes) {
                    if (std::ranges::find(report->capability_hashes, required) == report->capability_hashes.end()) {
                        result.required_capabilities_available = false;
                    }
                }
            }
            return result;
        }

        [[nodiscard]] bool pack_trust_ready(const packaging::TrustPolicy &policy) noexcept {
            return policy.allow_unsigned_packs ||
                   std::ranges::any_of(policy.signers, [](const packaging::TrustedSigner &signer) {
                       return !signer.revoked && signer.public_key.size() == 32U && !signer.key_id.empty();
                   });
        }

        [[nodiscard]] std::string readiness_failure(const cluster::ReadinessSnapshot &readiness) {
            std::string message {"resident startup readiness is blocked"};
            for (const auto &blocker : readiness.blockers) {
                message += "; ";
                message += blocker;
            }
            return message;
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
            "listener.accept_timeout_ms",
            "listener.handshake_timeout_ms",
            "listener.read_timeout_ms",
            "listener.write_timeout_ms",
            "listener.backlog",
            "listener.maximum_consecutive_failures",
            "network.require_hard_resolver_bounds",
            "service.worker_threads",
            "service.maximum_queued_sessions",
            "service.maximum_memory_bytes",
            "service.maximum_frame_bytes",
            "service.maximum_messages_per_session",
            "service.maximum_inflight_work_per_session",
            "service.maximum_session_duration_ms",
            "service.inbound_credit_bytes",
            "service.inbound_credit_messages",
            "service.inbound_credit_work_attempts",
            "service.inbound_credit_snapshot_chunks",
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
        const auto accept_timeout = milliseconds_value(*entries, "listener.accept_timeout_ms");
        const auto handshake_timeout = milliseconds_value(*entries, "listener.handshake_timeout_ms");
        const auto read_timeout = milliseconds_value(*entries, "listener.read_timeout_ms");
        const auto write_timeout = milliseconds_value(*entries, "listener.write_timeout_ms");
        const auto listen_backlog = uint32_value(*entries, "listener.backlog");
        const auto maximum_consecutive_failures = uint32_value(*entries, "listener.maximum_consecutive_failures");
        const auto worker_threads = uint32_value(*entries, "service.worker_threads");
        const auto maximum_queued_sessions = uint32_value(*entries, "service.maximum_queued_sessions");
        const auto maximum_memory_bytes = uint32_value(*entries, "service.maximum_memory_bytes");
        const auto maximum_frame_bytes = uint32_value(*entries, "service.maximum_frame_bytes");
        const auto maximum_messages_per_session = uint32_value(*entries, "service.maximum_messages_per_session");
        const auto maximum_inflight_work = uint32_value(*entries, "service.maximum_inflight_work_per_session");
        const auto maximum_session_duration = milliseconds_value(*entries, "service.maximum_session_duration_ms");
        const auto inbound_credit_bytes = uint32_value(*entries, "service.inbound_credit_bytes");
        const auto inbound_credit_messages = uint32_value(*entries, "service.inbound_credit_messages");
        const auto inbound_credit_work = uint32_value(*entries, "service.inbound_credit_work_attempts");
        const auto inbound_credit_snapshots = uint32_value(*entries, "service.inbound_credit_snapshot_chunks");
        if (!schema_version || !processes || !server_major || !pool_size || !lease_duration || !lease_renew_interval ||
            !statement_timeout || !busy_timeout || !accept_timeout || !handshake_timeout || !read_timeout ||
            !write_timeout || !listen_backlog || !maximum_consecutive_failures || !worker_threads ||
            !maximum_queued_sessions || !maximum_memory_bytes || !maximum_frame_bytes ||
            !maximum_messages_per_session || !maximum_inflight_work || !maximum_session_duration ||
            !inbound_credit_bytes || !inbound_credit_messages || !inbound_credit_work || !inbound_credit_snapshots) {
            return std::unexpected(!schema_version               ? std::move(schema_version.error()) :
                                   !processes                    ? std::move(processes.error()) :
                                   !server_major                 ? std::move(server_major.error()) :
                                   !pool_size                    ? std::move(pool_size.error()) :
                                   !lease_duration               ? std::move(lease_duration.error()) :
                                   !lease_renew_interval         ? std::move(lease_renew_interval.error()) :
                                   !statement_timeout            ? std::move(statement_timeout.error()) :
                                   !busy_timeout                 ? std::move(busy_timeout.error()) :
                                   !accept_timeout               ? std::move(accept_timeout.error()) :
                                   !handshake_timeout            ? std::move(handshake_timeout.error()) :
                                   !read_timeout                 ? std::move(read_timeout.error()) :
                                   !write_timeout                ? std::move(write_timeout.error()) :
                                   !listen_backlog               ? std::move(listen_backlog.error()) :
                                   !maximum_consecutive_failures ? std::move(maximum_consecutive_failures.error()) :
                                   !worker_threads               ? std::move(worker_threads.error()) :
                                   !maximum_queued_sessions      ? std::move(maximum_queued_sessions.error()) :
                                   !maximum_memory_bytes         ? std::move(maximum_memory_bytes.error()) :
                                   !maximum_frame_bytes          ? std::move(maximum_frame_bytes.error()) :
                                   !maximum_messages_per_session ? std::move(maximum_messages_per_session.error()) :
                                   !maximum_inflight_work        ? std::move(maximum_inflight_work.error()) :
                                   !maximum_session_duration     ? std::move(maximum_session_duration.error()) :
                                   !inbound_credit_bytes         ? std::move(inbound_credit_bytes.error()) :
                                   !inbound_credit_messages      ? std::move(inbound_credit_messages.error()) :
                                   !inbound_credit_work          ? std::move(inbound_credit_work.error()) :
                                                                   std::move(inbound_credit_snapshots.error()));
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
        result.listener.accept_timeout = *accept_timeout;
        result.listener.handshake_timeout = *handshake_timeout;
        result.listener.read_timeout = *read_timeout;
        result.listener.write_timeout = *write_timeout;
        result.listener.backlog = *listen_backlog;
        result.listener.maximum_consecutive_failures = *maximum_consecutive_failures;
        result.service.worker_threads = *worker_threads;
        result.service.maximum_queued_sessions = *maximum_queued_sessions;
        result.service.maximum_memory_bytes = *maximum_memory_bytes;
        result.service.maximum_frame_bytes = *maximum_frame_bytes;
        result.service.maximum_messages_per_session = *maximum_messages_per_session;
        result.service.maximum_inflight_work_per_session = *maximum_inflight_work;
        result.service.maximum_session_duration = *maximum_session_duration;
        result.service.inbound_credit = {
            .bytes = *inbound_credit_bytes,
            .messages = *inbound_credit_messages,
            .work_attempts = *inbound_credit_work,
            .snapshot_chunks = *inbound_credit_snapshots,
        };
        result.listener.require_hard_resolver_bounds =
            *entry_value<bool>(*entries, "network.require_hard_resolver_bounds");
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
        if (!numeric_host(agent->host) || !numeric_host(admin->host) || !numeric_host(prometheus->host)) {
            return std::unexpected(config_error("SRV-CONFIG-NUMERIC-ENDPOINT",
                                                "listener and Prometheus hosts must be numeric address literals"));
        }
        if (config.listener.accept_timeout < std::chrono::milliseconds {10} ||
            config.listener.accept_timeout > std::chrono::seconds {60} ||
            config.listener.handshake_timeout <= std::chrono::milliseconds::zero() ||
            config.listener.handshake_timeout > std::chrono::minutes {5} ||
            config.listener.read_timeout <= std::chrono::milliseconds::zero() ||
            config.listener.read_timeout > std::chrono::minutes {5} ||
            config.listener.write_timeout <= std::chrono::milliseconds::zero() ||
            config.listener.write_timeout > std::chrono::minutes {5} || config.listener.backlog == 0U ||
            config.listener.backlog > 4'096U || config.listener.maximum_consecutive_failures == 0U ||
            config.listener.maximum_consecutive_failures > 1'024U || !config.listener.require_hard_resolver_bounds) {
            return std::unexpected(
                config_error("SRV-CONFIG-LISTENER-BOUNDS",
                             "listener timeouts, backlog, failure bound, or hard-resolver policy is invalid"));
        }
        auto lease_window_remaining = config.lease_duration.count();
        for (const auto blocking_interval :
             {config.lease_renew_interval, config.listener.accept_timeout, config.listener.handshake_timeout}) {
            if (blocking_interval.count() <= 0 || blocking_interval.count() >= lease_window_remaining) {
                return std::unexpected(config_error(
                    "SRV-CONFIG-LISTENER-BOUNDS",
                    "lease renewal plus listener accept and TLS handshake bounds must be shorter than the lease"));
            }
            lease_window_remaining -= blocking_interval.count();
        }
        if (auto service = validate_resident_service_limits(config.service);
            !service || config.service.maximum_session_duration > config.lease_duration ||
            config.service.inbound_credit.work_attempts > config.service.maximum_inflight_work_per_session) {
            return std::unexpected(
                config_error("SRV-CONFIG-SERVICE-BOUNDS",
                             "service worker, queue, frame, memory, credit, or session bounds are invalid"));
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

    struct ProductionResidentServerBackend::Impl {
        std::stop_source stop;
        std::optional<protocol_v2::TlsSessionListener> agent_listener;
        std::optional<protocol_v2::TlsSessionListener> admin_listener;
        std::optional<cluster::FencedLease> node_lease;
        std::unique_ptr<ResidentApplicationService> application;
        std::unique_ptr<ResidentServiceScheduler> scheduler;
        cluster::IClusterRuntimeStore *runtime_store {};
        const protocol_v2::ITrustPolicy *peer_trust_policy {};
        std::chrono::steady_clock::time_point renew_at {};
        bool qualified {};
        bool accept_agent {true};

        ~Impl() {
            stop.request_stop();
            if (agent_listener) {
                agent_listener->cancel();
            }
            if (admin_listener) {
                admin_listener->cancel();
            }
            stop_services();
            static_cast<void>(release_node_lease());
        }

        [[nodiscard]] std::expected<void, ToolFailure> release_node_lease() noexcept {
            if (runtime_store == nullptr || !node_lease) {
                return {};
            }
            auto released = runtime_store->release_lease(*node_lease, now_unix_ms());
            node_lease.reset();
            if (!released) {
                return std::unexpected(
                    unavailable("SRV-NODE-LEASE-RELEASE", "the fenced node lease could not be released"));
            }
            return {};
        }

        void close_listeners() noexcept {
            if (agent_listener) {
                agent_listener->cancel();
            }
            if (admin_listener) {
                admin_listener->cancel();
            }
            agent_listener.reset();
            admin_listener.reset();
        }

        void stop_services() noexcept {
            if (scheduler) {
                scheduler->request_stop();
                scheduler->join();
                scheduler.reset();
            }
            application.reset();
        }
    };

    ProductionResidentServerBackend::ProductionResidentServerBackend(): impl_ {std::make_unique<Impl>()} {}
    ProductionResidentServerBackend::~ProductionResidentServerBackend() = default;

    std::expected<void, ToolFailure>
    ProductionResidentServerBackend::qualify_activation(const ResidentServerContext &context) noexcept {
        if (impl_->qualified || impl_->node_lease || impl_->agent_listener || impl_->admin_listener ||
            impl_->application || impl_->scheduler) {
            return std::unexpected(ToolFailure {
                .kind = ToolFailureKind::internal_invariant,
                .code = "SRV-BACKEND-STATE",
                .message = "resident backend qualification may run only once",
                .diagnostics = {},
            });
        }
        if (impl_->stop.stop_requested()) {
            return std::unexpected(unavailable_transport("SRV-STOPPED", "resident startup was canceled"));
        }
        if (context.config.allow_loopback_plaintext || context.agent_tls == nullptr || context.admin_tls == nullptr) {
            return std::unexpected(unavailable_transport(
                "SRV-PLAINTEXT-LISTENER-UNAVAILABLE",
                "the resident listener integration currently requires authenticated TLS, including in development"));
        }
        if (context.agent_backend == nullptr || context.admin_backend == nullptr) {
            return std::unexpected(ToolFailure {
                .kind = ToolFailureKind::internal_invariant,
                .code = "SRV-APPLICATION-BACKEND-MISSING",
                .message = "resident agent and admin application backends must be explicitly composed",
                .diagnostics = {},
            });
        }
        if (auto runtime = packaging::validate_exact_private_runtime(context.runtime); !runtime) {
            return std::unexpected(unavailable("SRV-RUNTIME-NOT-READY",
                                               "the exact private Python runtime no longer passes qualification"));
        }

        const auto runtime_health = context.store.health();
        const auto control_health = context.activation_store.health();
        if (!runtime_health.driver_available || !runtime_health.connected || !runtime_health.migrations_compatible ||
            !control_health.driver_available || !control_health.connected || !control_health.migrations_compatible ||
            runtime_health.backend != context.store_capabilities.kind ||
            control_health.backend != context.store_capabilities.kind) {
            return std::unexpected(
                unavailable("SRV-STORES-NOT-READY",
                            "runtime and durable activation stores must share a healthy compatible selected backend"));
        }

        impl_->runtime_store = std::addressof(context.store);
        const cluster::LeaseResource resource {.scope = "server-node", .key = context.config.node_id};
        auto lease = context.store.claim_lease(resource, context.config.node_id, now_unix_ms(),
                                               static_cast<std::uint64_t>(context.config.lease_duration.count()));
        if (!lease) {
            impl_->runtime_store = nullptr;
            return std::unexpected(
                unavailable("SRV-NODE-LEASE-UNAVAILABLE", "the durable node lease could not be claimed"));
        }
        impl_->node_lease = std::move(*lease);
        impl_->renew_at = std::chrono::steady_clock::now() + context.config.lease_renew_interval;

        auto control_state = context.activation_store.load_state();
        if (!control_state) {
            static_cast<void>(impl_->release_node_lease());
            return std::unexpected(
                unavailable("SRV-ACTIVATION-LOAD", "durable active-generation state could not be loaded"));
        }
        const auto activation = qualify_control_state(*control_state, context.config, impl_->node_lease->fence);
        auto current = context.store.lease_is_current(*impl_->node_lease, now_unix_ms());
        const auto node_lease_current = current && *current;

        protocol_v2::SocketTimeouts timeouts {
            .resolve = context.config.listener.handshake_timeout,
            .connect = context.config.listener.handshake_timeout,
            .accept = context.config.listener.accept_timeout,
            .handshake = context.config.listener.handshake_timeout,
            .read = context.config.listener.read_timeout,
            .write = context.config.listener.write_timeout,
            .total_dial = context.config.listener.handshake_timeout,
        };
        const auto agent_endpoint = parse_endpoint(context.config.agent_endpoint);
        const auto admin_endpoint = parse_endpoint(context.config.admin_endpoint);
        if (!agent_endpoint || !admin_endpoint) {
            static_cast<void>(impl_->release_node_lease());
            return std::unexpected(ToolFailure {
                .kind = ToolFailureKind::internal_invariant,
                .code = "SRV-ENDPOINT-INVARIANT",
                .message = "validated listener endpoint could not be reconstructed",
                .diagnostics = {},
            });
        }
        auto agent_listener = protocol_v2::TlsSessionListener::bind(
            std::move(*context.agent_tls),
            protocol_v2::TcpEndpoint {.host = agent_endpoint->host, .port = agent_endpoint->port}, timeouts,
            context.config.listener.backlog);
        if (!agent_listener) {
            static_cast<void>(impl_->release_node_lease());
            return std::unexpected(unavailable_transport("SRV-AGENT-LISTENER-UNAVAILABLE",
                                                         "the authenticated agent listener could not be bound"));
        }
        impl_->agent_listener.emplace(std::move(*agent_listener));
        auto admin_listener = protocol_v2::TlsSessionListener::bind(
            std::move(*context.admin_tls),
            protocol_v2::TcpEndpoint {.host = admin_endpoint->host, .port = admin_endpoint->port}, timeouts,
            context.config.listener.backlog);
        if (!admin_listener) {
            impl_->close_listeners();
            static_cast<void>(impl_->release_node_lease());
            return std::unexpected(unavailable_transport("SRV-ADMIN-LISTENER-UNAVAILABLE",
                                                         "the authenticated admin listener could not be bound"));
        }
        impl_->admin_listener.emplace(std::move(*admin_listener));

        const cluster::ReadinessInput readiness_input {
            .process_responsive = true,
            .database_reachable = runtime_health.connected && control_health.connected,
            .backend_driver_ready = runtime_health.driver_available && control_health.driver_available,
            .migrations_compatible = runtime_health.migrations_compatible && control_health.migrations_compatible,
            .node_lease_current = node_lease_current,
            .trust_policy_loaded = pack_trust_ready(context.pack_trust_policy),
            .retention_profiles_loaded = !context.config.retention_profiles_path.empty(),
            .active_generation_compiled = activation.active_generation_compiled,
            .schemas_compatible = activation.schemas_compatible,
            .required_capabilities_available = activation.required_capabilities_available,
            .backend = context.store_capabilities,
        };
        const auto readiness = cluster::evaluate_readiness(readiness_input, runtime_health);
        if (!readiness.ready) {
            impl_->close_listeners();
            static_cast<void>(impl_->release_node_lease());
            return std::unexpected(unavailable("SRV-NOT-READY", readiness_failure(readiness)));
        }

        impl_->application = std::make_unique<ResidentApplicationService>(
            context.config.service, context.peer_trust_policy, *context.agent_backend, *context.admin_backend);
        auto scheduler = ResidentServiceScheduler::create(context.config.service, *impl_->application);
        if (!scheduler) {
            impl_->application.reset();
            impl_->close_listeners();
            static_cast<void>(impl_->release_node_lease());
            return std::unexpected(unavailable_transport("SRV-SCHEDULER-UNAVAILABLE",
                                                         "the bounded resident scheduler could not be started"));
        }
        impl_->scheduler = std::move(*scheduler);

        impl_->peer_trust_policy = std::addressof(context.peer_trust_policy);
        impl_->qualified = true;
        return {};
    }

    std::expected<void, ToolFailure>
    ProductionResidentServerBackend::serve(const ResidentServerContext &context) noexcept {
        if (!impl_->qualified || !impl_->agent_listener || !impl_->admin_listener || !impl_->node_lease ||
            !impl_->application || !impl_->scheduler || impl_->runtime_store != std::addressof(context.store) ||
            impl_->peer_trust_policy == nullptr) {
            return std::unexpected(ToolFailure {
                .kind = ToolFailureKind::internal_invariant,
                .code = "SRV-BACKEND-NOT-QUALIFIED",
                .message = "resident serving requires successful qualification",
                .diagnostics = {},
            });
        }

        std::size_t consecutive_failures {};
        while (!impl_->stop.stop_requested()) {
            if (std::chrono::steady_clock::now() >= impl_->renew_at) {
                const auto at = now_unix_ms();
                auto current = context.store.lease_is_current(*impl_->node_lease, at);
                if (!current || !*current) {
                    impl_->close_listeners();
                    impl_->stop_services();
                    static_cast<void>(impl_->release_node_lease());
                    impl_->qualified = false;
                    return std::unexpected(
                        unavailable("SRV-NODE-LEASE-LOST", "the durable node lease is no longer current"));
                }
                auto renewed = context.store.renew_lease(
                    *impl_->node_lease, at, static_cast<std::uint64_t>(context.config.lease_duration.count()));
                if (!renewed) {
                    impl_->close_listeners();
                    impl_->stop_services();
                    static_cast<void>(impl_->release_node_lease());
                    impl_->qualified = false;
                    return std::unexpected(
                        unavailable("SRV-NODE-LEASE-RENEWAL", "the durable node lease could not be renewed"));
                }
                impl_->node_lease = std::move(*renewed);
                impl_->renew_at = std::chrono::steady_clock::now() + context.config.lease_renew_interval;
            }

            const auto role = impl_->accept_agent ? ResidentSessionRole::agent : ResidentSessionRole::administrator;
            auto &listener = impl_->accept_agent ? *impl_->agent_listener : *impl_->admin_listener;
            impl_->accept_agent = !impl_->accept_agent;
            auto peer = listener.accept(*impl_->peer_trust_policy, impl_->stop.get_token());
            if (peer) {
                ResidentSessionJob job {
                    .role = role,
                    .peer = std::move(peer->peer),
                    .channel = make_resident_tls_channel(std::move(peer->connection)),
                };
                static_cast<void>(impl_->scheduler->submit(std::move(job)));
                consecutive_failures = 0U;
                continue;
            }
            if (peer.error().code == protocol_v2::ProtocolErrorCode::timed_out) {
                continue;
            }
            if (peer.error().code == protocol_v2::ProtocolErrorCode::unauthenticated) {
                continue;
            }
            if (peer.error().code == protocol_v2::ProtocolErrorCode::canceled && impl_->stop.stop_requested()) {
                break;
            }
            if (peer.error().code == protocol_v2::ProtocolErrorCode::dependency_unavailable) {
                impl_->close_listeners();
                impl_->stop_services();
                static_cast<void>(impl_->release_node_lease());
                impl_->qualified = false;
                return std::unexpected(unavailable_transport(
                    "SRV-LISTENER-DEPENDENCY-UNAVAILABLE", "the authenticated listener dependency became unavailable"));
            }
            ++consecutive_failures;
            if (consecutive_failures >= context.config.listener.maximum_consecutive_failures) {
                impl_->close_listeners();
                impl_->stop_services();
                static_cast<void>(impl_->release_node_lease());
                impl_->qualified = false;
                return std::unexpected(unavailable_transport(
                    "SRV-LISTENER-FAILURE-LIMIT", "the resident listener reached its consecutive failure bound"));
            }
        }

        impl_->close_listeners();
        impl_->stop_services();
        auto released = impl_->release_node_lease();
        impl_->qualified = false;
        if (!released) {
            return released;
        }
        return {};
    }

    void ProductionResidentServerBackend::request_stop() noexcept {
        impl_->stop.request_stop();
        if (impl_->agent_listener) {
            impl_->agent_listener->cancel();
        }
        if (impl_->admin_listener) {
            impl_->admin_listener->cancel();
        }
        if (impl_->scheduler) {
            impl_->scheduler->request_stop();
        }
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
        auto pack_trust_policy = load_pack_trust_policy(*config);
        if (!pack_trust_policy) {
            return failure_output(pack_trust_policy.error());
        }
        auto peer_trust_policy = load_peer_trust_policy(*config);
        if (!peer_trust_policy) {
            return failure_output(peer_trust_policy.error());
        }
        auto operator_bindings = load_operator_bindings(*config);
        if (!operator_bindings) {
            return failure_output(operator_bindings.error());
        }
        auto agent_tls = create_tls(*config);
        if (!agent_tls) {
            return failure_output(agent_tls.error());
        }
        auto admin_tls = create_tls(*config);
        if (!admin_tls) {
            return failure_output(admin_tls.error());
        }
        cluster::AuditTrail audit;
        auto connection = resolve_store_connection(*config);
        if (!connection) {
            return failure_output(connection.error());
        }
        auto store = open_store(*config, audit, connection->value);
        if (!store) {
            return failure_output(store.error());
        }
        auto activation_store = open_activation_store(*config, connection->value);
        connection->wipe();
        if (!activation_store) {
            return failure_output(activation_store.error());
        }
        const auto health = (*store)->health();
        if (!health.driver_available || !health.connected || !health.migrations_compatible) {
            return failure_output(unavailable("SRV-STORE-NOT-READY", health.detail));
        }
        StoreBackedAgentSessionBackend agent_backend {**store, config->node_id, config->lease_duration};
        FileAdminSecurityAudit admin_security_audit {config->audit_path};
        AuthorizedResidentAdminBackend admin_backend {**activation_store, **operator_bindings, &admin_security_audit};
        const ResidentServerContext context {
            .config = *config,
            .store = **store,
            .activation_store = **activation_store,
            .store_capabilities = *capabilities,
            .runtime = *runtime,
            .pack_trust_policy = *pack_trust_policy,
            .peer_trust_policy = **peer_trust_policy,
            .agent_tls = agent_tls->has_value() ? std::addressof(**agent_tls) : nullptr,
            .admin_tls = admin_tls->has_value() ? std::addressof(**admin_tls) : nullptr,
            .agent_backend = std::addressof(agent_backend),
            .admin_backend = std::addressof(admin_backend),
        };
        if (auto active = backend.qualify_activation(context); !active) {
            return failure_output(active.error());
        }
        if (auto served = backend.serve(context); !served) {
            return failure_output(served.error());
        }
        return {
            .exit_code = ExitCode::success,
            .standard_output = {},
            .standard_error = {},
        };
    }

} // namespace rule_engine::python::tools
