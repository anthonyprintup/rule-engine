#include <rule_engine/module_config.hpp>

#include <charconv>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {
    [[nodiscard]] std::string_view trim(std::string_view value) noexcept {
        while (!value.empty() && (value.front() == ' ' || value.front() == '\t' || value.front() == '\r')) {
            value.remove_prefix(1u);
        }
        while (!value.empty() && (value.back() == ' ' || value.back() == '\t' || value.back() == '\r')) {
            value.remove_suffix(1u);
        }
        return value;
    }

    [[nodiscard]] std::vector<std::string> split_ws(const std::string_view line) {
        std::istringstream stream {std::string {line}};
        std::vector<std::string> tokens;
        std::string token;
        while (stream >> token) {
            tokens.push_back(std::move(token));
        }
        return tokens;
    }

    [[nodiscard]] std::optional<rule_engine::ValueType> parse_value_type(const std::string_view token) noexcept {
        if (token == "boolean") {
            return rule_engine::ValueType::boolean;
        }
        if (token == "integer") {
            return rule_engine::ValueType::integer;
        }
        if (token == "floating") {
            return rule_engine::ValueType::floating;
        }
        if (token == "string") {
            return rule_engine::ValueType::string;
        }
        if (token == "bytes") {
            return rule_engine::ValueType::bytes;
        }
        if (token == "array") {
            return rule_engine::ValueType::array;
        }
        if (token == "pattern") {
            return rule_engine::ValueType::pattern;
        }
        if (token == "object") {
            return rule_engine::ValueType::object;
        }
        if (token == "undefined") {
            return rule_engine::ValueType::undefined;
        }
        return std::nullopt;
    }

    [[nodiscard]] std::optional<std::chrono::seconds> parse_seconds(const std::string_view token) noexcept {
        std::int64_t value {};
        const auto *first = token.data();
        const auto *last = first + token.size();
        const auto [ptr, ec] = std::from_chars(first, last, value);
        if (ec != std::errc {} || ptr != last || value < 0) {
            return std::nullopt;
        }
        return std::chrono::seconds {value};
    }

    [[nodiscard]] std::optional<bool> parse_bool(const std::string_view token) noexcept {
        if (token == "true" || token == "1") {
            return true;
        }
        if (token == "false" || token == "0") {
            return false;
        }
        return std::nullopt;
    }

    [[nodiscard]] std::optional<std::vector<rule_engine::ValueType>>
    parse_parameter_types(const std::string_view token) {
        std::vector<rule_engine::ValueType> out;
        if (token == "-") {
            return out;
        }

        std::size_t offset {};
        while (offset <= token.size()) {
            const auto comma = token.find(',', offset);
            const auto end = comma == std::string_view::npos ? token.size() : comma;
            const auto part = token.substr(offset, end - offset);
            const auto type = parse_value_type(part);
            if (!type.has_value()) {
                return std::nullopt;
            }
            out.push_back(*type);
            if (comma == std::string_view::npos) {
                break;
            }
            offset = comma + 1u;
        }
        return out;
    }

    void add_error(rule_engine::ErrorSet &errors,
                   const std::filesystem::path &path,
                   const std::size_t line,
                   std::string message) {
        errors.diagnostics.push_back(rule_engine::Diagnostic {
            .source = path.string(),
            .message = "line " + std::to_string(line) + ": " + std::move(message),
        });
    }
} // namespace

namespace rule_engine {
    std::expected<void, ErrorSet> load_module_config_file(const std::filesystem::path &path, ModuleRegistry &registry) {
        std::ifstream input {path};
        if (!input) {
            return std::unexpected(single_error(path.string(), "failed to open module config"));
        }

        ErrorSet errors;
        std::optional<std::size_t> module_index;
        std::string line;
        std::size_t line_number {};
        while (std::getline(input, line)) {
            ++line_number;
            auto view = std::string_view {line};
            if (const auto comment = view.find('#'); comment != std::string_view::npos) {
                view = view.substr(0u, comment);
            }
            view = trim(view);
            if (view.empty()) {
                continue;
            }

            const auto tokens = split_ws(view);
            if (tokens.empty()) {
                continue;
            }

            if (tokens[0] == "module") {
                if (tokens.size() != 2u) {
                    add_error(errors, path, line_number, "module line expects: module <name>");
                    continue;
                }
                registry.modules.push_back(ModuleDescriptor {
                    .name = tokens[1],
                    .fields = {},
                    .functions = {},
                });
                module_index = registry.modules.size() - 1u;
                continue;
            }

            if (tokens[0] == "function") {
                if (!module_index.has_value()) {
                    add_error(errors, path, line_number, "function line must follow a module line");
                    continue;
                }
                if (tokens.size() != 8u && tokens.size() != 9u) {
                    add_error(errors,
                              path,
                              line_number,
                              "function line expects: function <name> <return-type> <arg-types|-> <route> "
                              "<key-prefix> <ttl-seconds> <cheap> [timeout-seconds]");
                    continue;
                }
                const auto return_type = parse_value_type(tokens[2]);
                const auto parameters = parse_parameter_types(tokens[3]);
                const auto ttl = parse_seconds(tokens[6]);
                const auto cheap = parse_bool(tokens[7]);
                std::optional<std::chrono::seconds> timeout = std::chrono::seconds {5};
                if (tokens.size() == 9u) {
                    timeout = parse_seconds(tokens[8]);
                }
                if (!return_type.has_value() || !parameters.has_value() || !ttl.has_value() || !cheap.has_value() ||
                    !timeout.has_value()) {
                    add_error(errors,
                              path,
                              line_number,
                              "function line contains an invalid type, ttl, boolean, or timeout");
                    continue;
                }
                registry.modules[*module_index].functions.push_back(FunctionDescriptor {
                    .name = tokens[1],
                    .parameters = *parameters,
                    .return_type = *return_type,
                    .key_prefix = tokens[5],
                    .route = tokens[4],
                    .ttl = *ttl,
                    .timeout = *timeout,
                    .cheap_prefetch = *cheap,
                });
                continue;
            }

            if (tokens[0] == "field") {
                if (!module_index.has_value()) {
                    add_error(errors, path, line_number, "field line must follow a module line");
                    continue;
                }
                if (tokens.size() != 6u && tokens.size() != 7u) {
                    add_error(errors,
                              path,
                              line_number,
                              "field line expects: field <key> <type> <route> <ttl> <cheap> [timeout]");
                    continue;
                }
                const auto type = parse_value_type(tokens[2]);
                const auto ttl = parse_seconds(tokens[4]);
                const auto cheap = parse_bool(tokens[5]);
                std::optional<std::chrono::seconds> timeout = std::chrono::seconds {5};
                if (tokens.size() == 7u) {
                    timeout = parse_seconds(tokens[6]);
                }
                if (!type.has_value() || !ttl.has_value() || !cheap.has_value() || !timeout.has_value()) {
                    add_error(errors, path, line_number, "field line contains an invalid type, ttl, boolean, or timeout");
                    continue;
                }
                registry.modules[*module_index].fields.push_back(FieldDescriptor {
                    .key = tokens[1],
                    .type = *type,
                    .route = tokens[3],
                    .ttl = *ttl,
                    .timeout = *timeout,
                    .cheap_prefetch = *cheap,
                });
                continue;
            }

            if (tokens[0] == "global") {
                if (tokens.size() != 7u && tokens.size() != 8u) {
                    add_error(errors,
                              path,
                              line_number,
                              "global line expects: global <name> <type> <key> <route> <ttl> <cheap> [timeout]");
                    continue;
                }
                const auto type = parse_value_type(tokens[2]);
                const auto ttl = parse_seconds(tokens[5]);
                const auto cheap = parse_bool(tokens[6]);
                std::optional<std::chrono::seconds> timeout = std::chrono::seconds {5};
                if (tokens.size() == 8u) {
                    timeout = parse_seconds(tokens[7]);
                }
                if (!type.has_value() || !ttl.has_value() || !cheap.has_value() || !timeout.has_value()) {
                    add_error(errors, path, line_number, "global line contains an invalid type, ttl, boolean, or timeout");
                    continue;
                }
                registry.globals.push_back(GlobalDescriptor {
                    .name = tokens[1],
                    .type = *type,
                    .key = tokens[3],
                    .route = tokens[4],
                    .ttl = *ttl,
                    .timeout = *timeout,
                    .cheap_prefetch = *cheap,
                });
                continue;
            }

            add_error(errors, path, line_number, "unknown module config directive " + tokens[0]);
        }

        if (!errors.empty()) {
            return std::unexpected(std::move(errors));
        }
        return {};
    }
} // namespace rule_engine
