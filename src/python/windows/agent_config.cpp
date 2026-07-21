#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <WS2tcpip.h>
#include <WinSock2.h>

#include "rule_engine/python/windows/agent.hpp"

#include "rule_engine/python/protocol/transport.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <fstream>
#include <optional>
#include <ranges>
#include <system_error>
#include <utility>

namespace rule_engine::python::windows {
    namespace {

        constexpr std::size_t maximum_configuration_bytes = 64U * 1024U;
        constexpr std::size_t maximum_configuration_lines = 256U;
        constexpr std::size_t maximum_line_bytes = 2U * 1024U;
        constexpr std::size_t maximum_path_bytes = 1U * 1024U;
        constexpr std::size_t maximum_endpoints = 8U;

        [[nodiscard]] AgentFailure configuration_error(std::string message, const std::size_t line = 0U) {
            return AgentFailure {.code = AgentFailureCode::configuration, .message = std::move(message), .line = line};
        }

        [[nodiscard]] std::string_view trim(const std::string_view value) noexcept {
            const auto whitespace = [](const char character) {
                return character == ' ' || character == '\t' || character == '\r';
            };
            const auto begin = std::ranges::find_if_not(value, whitespace);
            const auto end = std::ranges::find_if_not(value | std::views::reverse, whitespace).base();
            if (begin >= end) {
                return {};
            }
            return {begin, end};
        }

        [[nodiscard]] bool bounded_text(const std::string_view value, const std::size_t maximum) noexcept {
            return !value.empty() && value.size() <= maximum &&
                   std::ranges::none_of(value, [](const unsigned char character) {
                       return character == 0U || character < 0x20U || character == 0x7fU;
                   });
        }

        [[nodiscard]] bool key_text(const std::string_view key) noexcept {
            return !key.empty() && key.size() <= 64U && std::ranges::all_of(key, [](const unsigned char character) {
                return std::islower(character) != 0 || std::isdigit(character) != 0 || character == '_';
            });
        }

        template<typename Integer>
        [[nodiscard]] std::optional<Integer> parse_integer(const std::string_view value) noexcept {
            Integer result {};
            const auto parsed = std::from_chars(value.data(), value.data() + value.size(), result);
            if (parsed.ec != std::errc {} || parsed.ptr != value.data() + value.size()) {
                return std::nullopt;
            }
            return result;
        }

        [[nodiscard]] bool numeric_address(const std::string_view host) noexcept {
            if (!bounded_text(host, 64U)) {
                return false;
            }
            const auto text = std::string {host};
            in_addr address4 {};
            if (InetPtonA(AF_INET, text.c_str(), &address4) == 1) {
                return true;
            }
            in6_addr address6 {};
            return InetPtonA(AF_INET6, text.c_str(), &address6) == 1;
        }

        [[nodiscard]] std::expected<protocol_v2::TcpEndpoint, AgentFailure> parse_endpoint(const std::string_view value,
                                                                                           const std::size_t line) {
            std::string_view host;
            std::string_view port_text;
            if (value.starts_with('[')) {
                const auto close = value.find(']');
                if (close == std::string_view::npos || close + 2U >= value.size() || value[close + 1U] != ':') {
                    return std::unexpected(configuration_error("server_endpoint must use [IPv6]:port", line));
                }
                host = value.substr(1U, close - 1U);
                port_text = value.substr(close + 2U);
            } else {
                const auto separator = value.rfind(':');
                if (separator == std::string_view::npos || separator == 0U || separator + 1U >= value.size() ||
                    value.find(':') != separator) {
                    return std::unexpected(configuration_error("server_endpoint must use IPv4:port", line));
                }
                host = value.substr(0U, separator);
                port_text = value.substr(separator + 1U);
            }
            const auto port = parse_integer<std::uint32_t>(port_text);
            if (!numeric_address(host) || !port.has_value() || *port == 0U || *port > 65'535U) {
                return std::unexpected(
                    configuration_error("server_endpoint requires a numeric IP address and nonzero TCP port", line));
            }
            return protocol_v2::TcpEndpoint {.host = std::string {host}, .port = static_cast<std::uint16_t>(*port)};
        }

        [[nodiscard]] bool lowercase_sha256(const std::string_view value) noexcept {
            return value.size() == 64U && std::ranges::all_of(value, [](const unsigned char character) {
                       return std::isdigit(character) != 0 || (character >= 'a' && character <= 'f');
                   });
        }

        [[nodiscard]] bool exact_identity_text(const std::string_view value, const std::size_t maximum) noexcept {
            return bounded_text(value, maximum) && std::ranges::none_of(value, [](const unsigned char character) {
                       return std::isspace(character) != 0;
                   });
        }

        [[nodiscard]] std::expected<std::filesystem::path, AgentFailure>
        absolute_path(const std::string_view value, const std::size_t line, const std::string_view key) {
            if (!bounded_text(value, maximum_path_bytes)) {
                return std::unexpected(configuration_error(std::string {key} + " is empty or too long", line));
            }
            auto path = std::filesystem::path {std::string {value}};
            if (!path.is_absolute() || !path.has_filename()) {
                return std::unexpected(configuration_error(std::string {key} + " must be an absolute file path", line));
            }
            return path;
        }

        [[nodiscard]] bool same_endpoint(const protocol_v2::TcpEndpoint &left,
                                         const protocol_v2::TcpEndpoint &right) noexcept {
            return left.host == right.host && left.port == right.port;
        }

        [[nodiscard]] AgentFailure protocol_failure(const protocol_v2::ProtocolError &error) {
            AgentFailureCode code = AgentFailureCode::dependency;
            if (error.code == protocol_v2::ProtocolErrorCode::unauthenticated) {
                code = AgentFailureCode::authentication;
            }
            return AgentFailure {.code = code, .message = error.message};
        }

    } // namespace

    std::expected<WindowsAgentConfig, AgentFailure> parse_windows_agent_config(const std::string_view source) noexcept {
        if (source.empty() || source.size() > maximum_configuration_bytes ||
            source.find('\0') != std::string_view::npos) {
            return std::unexpected(configuration_error("configuration is empty, oversized, or contains NUL bytes"));
        }

        WindowsAgentConfig configuration;
        configuration.reconnect_policy.require_hard_resolver_bounds = true;
        std::vector<std::string> seen;
        std::optional<std::uint32_t> schema_version;
        std::size_t line_number {};
        std::size_t offset {};
        while (offset <= source.size()) {
            if (++line_number > maximum_configuration_lines) {
                return std::unexpected(configuration_error("configuration line count exceeds the limit", line_number));
            }
            const auto newline = source.find('\n', offset);
            const auto length = newline == std::string_view::npos ? source.size() - offset : newline - offset;
            if (length > maximum_line_bytes) {
                return std::unexpected(configuration_error("configuration line exceeds the byte limit", line_number));
            }
            const auto line = trim(source.substr(offset, length));
            offset = newline == std::string_view::npos ? source.size() + 1U : newline + 1U;
            if (line.empty() || line.starts_with('#')) {
                continue;
            }
            const auto separator = line.find('=');
            if (separator == std::string_view::npos) {
                return std::unexpected(configuration_error("configuration entries must use key = value", line_number));
            }
            const auto key = trim(line.substr(0U, separator));
            const auto value = trim(line.substr(separator + 1U));
            if (!key_text(key) || value.empty()) {
                return std::unexpected(configuration_error("configuration key or value is invalid", line_number));
            }
            if (key != "server_endpoint") {
                if (std::ranges::find(seen, key) != seen.end()) {
                    return std::unexpected(
                        configuration_error("duplicate configuration key: " + std::string {key}, line_number));
                }
                seen.emplace_back(key);
            }

            if (key == "schema_version") {
                schema_version = parse_integer<std::uint32_t>(value);
                if (!schema_version.has_value() || *schema_version != 1U) {
                    return std::unexpected(configuration_error("schema_version must be exactly 1", line_number));
                }
            } else if (key == "spool_path") {
                auto parsed = absolute_path(value, line_number, key);
                if (!parsed) {
                    return std::unexpected(std::move(parsed.error()));
                }
                configuration.spool_path = std::move(*parsed);
            } else if (key == "certificate_path") {
                auto parsed = absolute_path(value, line_number, key);
                if (!parsed) {
                    return std::unexpected(std::move(parsed.error()));
                }
                configuration.certificate_path = std::move(*parsed);
            } else if (key == "private_key_path") {
                auto parsed = absolute_path(value, line_number, key);
                if (!parsed) {
                    return std::unexpected(std::move(parsed.error()));
                }
                configuration.private_key_path = std::move(*parsed);
            } else if (key == "ca_path") {
                auto parsed = absolute_path(value, line_number, key);
                if (!parsed) {
                    return std::unexpected(std::move(parsed.error()));
                }
                configuration.ca_path = std::move(*parsed);
            } else if (key == "server_endpoint") {
                if (configuration.endpoints.size() >= maximum_endpoints) {
                    return std::unexpected(configuration_error("server_endpoint count exceeds eight", line_number));
                }
                auto endpoint = parse_endpoint(value, line_number);
                if (!endpoint) {
                    return std::unexpected(std::move(endpoint.error()));
                }
                if (std::ranges::any_of(configuration.endpoints,
                                        [&](const auto &existing) { return same_endpoint(existing, *endpoint); })) {
                    return std::unexpected(configuration_error("duplicate server_endpoint", line_number));
                }
                configuration.endpoints.push_back(std::move(*endpoint));
            } else if (key == "server_name") {
                if (!exact_identity_text(value, 253U)) {
                    return std::unexpected(configuration_error("server_name is invalid", line_number));
                }
                configuration.server_name = value;
            } else if (key == "server_uri") {
                if (!exact_identity_text(value, 1'024U) || value.find(':') == std::string_view::npos) {
                    return std::unexpected(configuration_error("server_uri must be an exact bounded URI", line_number));
                }
                configuration.server_uri = value;
            } else if (key == "server_fingerprint_sha256") {
                if (!lowercase_sha256(value)) {
                    return std::unexpected(configuration_error(
                        "server_fingerprint_sha256 must be 64 lowercase hexadecimal digits", line_number));
                }
                configuration.server_fingerprint_sha256 = value;
            } else if (key == "peer_id") {
                if (!exact_identity_text(value, 256U)) {
                    return std::unexpected(configuration_error("peer_id is invalid", line_number));
                }
                configuration.peer = PeerId {std::string {value}};
            } else if (key == "active_generation") {
                const auto generation = parse_integer<std::uint64_t>(value);
                if (!generation.has_value() || *generation == 0U) {
                    return std::unexpected(configuration_error("active_generation must be nonzero", line_number));
                }
                configuration.active_generation = *generation;
            } else if (key == "require_hard_resolver_bounds") {
                if (value != "true" && value != "false") {
                    return std::unexpected(
                        configuration_error("require_hard_resolver_bounds must be true or false", line_number));
                }
                configuration.require_hard_resolver_bounds = value == "true";
                configuration.reconnect_policy.require_hard_resolver_bounds = value == "true";
            } else {
                return std::unexpected(
                    configuration_error("unknown configuration key: " + std::string {key}, line_number));
            }
        }

        if (!schema_version.has_value() || configuration.spool_path.empty() || configuration.certificate_path.empty() ||
            configuration.private_key_path.empty() || configuration.ca_path.empty() ||
            configuration.endpoints.empty() || configuration.server_name.empty() || configuration.server_uri.empty() ||
            configuration.server_fingerprint_sha256.empty() || configuration.peer.empty() ||
            configuration.active_generation == 0U) {
            return std::unexpected(configuration_error("configuration is missing one or more required keys"));
        }
        if (!configuration.require_hard_resolver_bounds) {
            return std::unexpected(
                configuration_error("production agent requires require_hard_resolver_bounds = true"));
        }
        return configuration;
    }

    std::expected<WindowsAgentConfig, AgentFailure>
    load_windows_agent_config(const std::filesystem::path &path) noexcept {
        std::error_code filesystem_error;
        const auto size = std::filesystem::file_size(path, filesystem_error);
        if (filesystem_error || size == 0U || size > maximum_configuration_bytes) {
            return std::unexpected(configuration_error("configuration file is missing, empty, or oversized"));
        }
        std::ifstream input {path, std::ios::binary};
        if (!input) {
            return std::unexpected(configuration_error("configuration file cannot be opened"));
        }
        std::string source(static_cast<std::size_t>(size), '\0');
        input.read(source.data(), static_cast<std::streamsize>(source.size()));
        if (!input || static_cast<std::size_t>(input.gcount()) != source.size()) {
            return std::unexpected(configuration_error("configuration file could not be read completely"));
        }
        return parse_windows_agent_config(source);
    }

    std::expected<void, AgentFailure>
    validate_windows_agent_config_files(const WindowsAgentConfig &configuration) noexcept {
        const std::array tls_files {&configuration.certificate_path, &configuration.private_key_path,
                                    &configuration.ca_path};
        for (const auto *path : tls_files) {
            std::error_code error;
            if (!std::filesystem::is_regular_file(*path, error) || error) {
                return std::unexpected(
                    configuration_error("a configured TLS file is missing or is not a regular file"));
            }
        }
        std::error_code error;
        if (std::filesystem::exists(configuration.spool_path, error)) {
            if (error || !std::filesystem::is_regular_file(configuration.spool_path, error) || error) {
                return std::unexpected(configuration_error("spool_path exists but is not a regular file"));
            }
        } else {
            error.clear();
            const auto parent = configuration.spool_path.parent_path();
            if (parent.empty() || !std::filesystem::is_directory(parent, error) || error) {
                return std::unexpected(configuration_error("spool_path parent directory does not exist"));
            }
        }
        return {};
    }

    std::expected<void, AgentFailure>
    validate_windows_agent_dependencies(const WindowsAgentConfig &configuration) noexcept {
        const auto tls = protocol_v2::tls_backend_status();
        if (!tls.available) {
            return std::unexpected(AgentFailure {.code = AgentFailureCode::dependency, .message = tls.diagnostic});
        }
        const auto spool = protocol_v2::spool_backend_status();
        if (!spool.available) {
            return std::unexpected(AgentFailure {.code = AgentFailureCode::dependency, .message = spool.diagnostic});
        }
        auto context = protocol_v2::OpenSslTlsContext::create(protocol_v2::TlsConfiguration {
            .role = protocol_v2::TlsEndpointRole::client,
            .trust_anchors_pem = configuration.ca_path.string(),
            .certificate_chain_pem = configuration.certificate_path.string(),
            .private_key_pem = configuration.private_key_path.string(),
            .crl_pem = {},
            .expected_server_name = configuration.server_name,
            .require_crl = false,
            .verification_time_unix_seconds = std::nullopt,
            .protocol_limits = configuration.protocol_limits,
        });
        if (!context) {
            return std::unexpected(protocol_failure(context.error()));
        }
        return {};
    }

    std::expected<AgentCommand, AgentFailure>
    parse_windows_agent_command(const std::span<const std::string_view> arguments) noexcept {
        if (arguments.size() == 1U && arguments.front() == "--help") {
            return AgentCommand {.mode = AgentCommandMode::help, .configuration_path = {}};
        }
        if (arguments.size() == 1U && arguments.front() == "--version") {
            return AgentCommand {.mode = AgentCommandMode::version, .configuration_path = {}};
        }
        if ((arguments.size() != 2U && arguments.size() != 3U) || arguments.front() != "--config" ||
            arguments[1U].empty() || arguments[1U].starts_with("--") ||
            (arguments.size() == 3U && arguments[2U] != "--validate-config")) {
            return std::unexpected(
                configuration_error("expected --config PATH, optionally followed by --validate-config"));
        }
        return AgentCommand {.mode = arguments.size() == 3U ? AgentCommandMode::validate_config : AgentCommandMode::run,
                             .configuration_path = std::filesystem::path {std::string {arguments[1U]}}};
    }

    std::string_view windows_agent_help() noexcept {
        return R"(Usage: rule_engine_agent --config PATH [--validate-config]

Run the Windows fact and scan provider agent. Rule predicates and verdicts are never accepted or evaluated here.

Options:
  --config PATH        Strict agent configuration file
  --validate-config    Validate configuration, TLS credentials, and required backends, then exit
  --help               Show this help
  --version            Show the tool API version
)";
    }

} // namespace rule_engine::python::windows
