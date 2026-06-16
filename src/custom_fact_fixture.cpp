#include <rule_engine/custom_fact_fixture.hpp>

#include <algorithm>
#include <charconv>
#include <cstddef>
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

    [[nodiscard]] std::optional<std::int64_t> parse_i64(const std::string_view token) noexcept {
        std::int64_t value {};
        const auto *first = token.data();
        const auto *last = first + token.size();
        const auto [ptr, ec] = std::from_chars(first, last, value);
        if (ec != std::errc {} || ptr != last) {
            return std::nullopt;
        }
        return value;
    }

    [[nodiscard]] std::optional<double> parse_f64(const std::string_view token) noexcept {
        double value {};
        const auto *first = token.data();
        const auto *last = first + token.size();
        const auto [ptr, ec] = std::from_chars(first, last, value);
        if (ec != std::errc {} || ptr != last) {
            return std::nullopt;
        }
        return value;
    }

    [[nodiscard]] std::optional<std::uint8_t> from_hex_char(const char c) noexcept {
        if (c >= '0' && c <= '9') {
            return static_cast<std::uint8_t>(c - '0');
        }
        if (c >= 'a' && c <= 'f') {
            return static_cast<std::uint8_t>(10 + c - 'a');
        }
        if (c >= 'A' && c <= 'F') {
            return static_cast<std::uint8_t>(10 + c - 'A');
        }
        return std::nullopt;
    }

    [[nodiscard]] std::optional<std::vector<std::byte>> parse_hex_bytes(const std::string_view token) {
        if ((token.size() % 2u) != 0u) {
            return std::nullopt;
        }
        std::vector<std::byte> out;
        out.reserve(token.size() / 2u);
        for (std::size_t index = 0; index < token.size(); index += 2u) {
            const auto high = from_hex_char(token[index]);
            const auto low = from_hex_char(token[index + 1u]);
            if (!high.has_value() || !low.has_value()) {
                return std::nullopt;
            }
            out.push_back(static_cast<std::byte>((*high << 4u) | *low));
        }
        return out;
    }

    [[nodiscard]] std::optional<std::string> parse_hex_string(const std::string_view token) {
        auto bytes = parse_hex_bytes(token);
        if (!bytes.has_value()) {
            return std::nullopt;
        }
        std::string out;
        out.reserve(bytes->size());
        for (const auto byte : *bytes) {
            out.push_back(static_cast<char>(std::to_integer<std::uint8_t>(byte)));
        }
        return out;
    }

    [[nodiscard]] std::optional<rule_engine::Value> parse_value(const std::string_view type,
                                                                const std::string_view token) {
        if (type == "undefined") {
            return rule_engine::Value::undefined();
        }
        if (type == "boolean") {
            if (token == "true" || token == "1") {
                return rule_engine::Value::boolean(true);
            }
            if (token == "false" || token == "0") {
                return rule_engine::Value::boolean(false);
            }
            return std::nullopt;
        }
        if (type == "integer") {
            const auto value = parse_i64(token);
            if (!value.has_value()) {
                return std::nullopt;
            }
            return rule_engine::Value::integer(*value);
        }
        if (type == "floating") {
            const auto value = parse_f64(token);
            if (!value.has_value()) {
                return std::nullopt;
            }
            return rule_engine::Value::number(*value);
        }
        if (type == "string") {
            const auto value = parse_hex_string(token);
            if (!value.has_value()) {
                return std::nullopt;
            }
            return rule_engine::Value::string(*value);
        }
        if (type == "bytes") {
            const auto value = parse_hex_bytes(token);
            if (!value.has_value()) {
                return std::nullopt;
            }
            return rule_engine::Value::bytes(*value);
        }
        return std::nullopt;
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

    void add_capability(std::vector<rule_engine::protocol::Capability> &capabilities, std::string route) {
        if (route.empty()) {
            return;
        }
        const auto exists = std::ranges::any_of(capabilities, [&](const auto &capability) {
            return capability.route == route;
        });
        if (exists) {
            return;
        }
        capabilities.push_back(rule_engine::protocol::Capability {.route = std::move(route)});
    }

    [[nodiscard]] bool has_capability(const rule_engine::custom_facts::CustomFactFixtureSet &fixtures,
                                      const std::string_view route) {
        return std::ranges::any_of(fixtures.capabilities, [&](const auto &capability) {
            return capability.route == route;
        });
    }
} // namespace

namespace rule_engine::custom_facts {
    std::expected<CustomFactFixtureSet, ErrorSet> load_custom_fact_fixture_file(const std::filesystem::path &path) {
        std::ifstream input {path};
        if (!input) {
            return std::unexpected(single_error(path.string(), "failed to open custom fact fixture"));
        }

        ErrorSet errors;
        CustomFactFixtureSet out;
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

            if (tokens[0] == "capability") {
                if (tokens.size() != 2u) {
                    add_error(errors, path, line_number, "capability line expects: capability <route>");
                    continue;
                }
                add_capability(out.capabilities, tokens[1]);
                continue;
            }

            if (tokens[0] == "fact") {
                if (tokens.size() != 6u) {
                    add_error(errors, path, line_number, "fact line expects: fact <route> <key> <type> <value> <ttl>");
                    continue;
                }
                const auto value = parse_value(tokens[3], tokens[4]);
                const auto ttl = parse_seconds(tokens[5]);
                if (!value.has_value() || !ttl.has_value()) {
                    add_error(errors, path, line_number, "fact line contains an invalid value or ttl");
                    continue;
                }
                add_capability(out.capabilities, tokens[1]);
                out.facts.push_back(CustomFactFixture {
                    .route = tokens[1],
                    .key = tokens[2],
                    .value = *value,
                    .ttl = *ttl,
                });
                continue;
            }

            add_error(errors, path, line_number, "unknown custom fact fixture directive " + tokens[0]);
        }

        if (!errors.empty()) {
            return std::unexpected(std::move(errors));
        }
        return out;
    }

    std::optional<protocol::FactBatchResponseMessage>
    read_custom_fact_fixture_response(const protocol::FactBatchRequestMessage &request,
                                      const CustomFactFixtureSet &fixtures) {
        if (!has_capability(fixtures, request.route)) {
            return std::nullopt;
        }

        protocol::FactBatchResponseMessage response;
        response.route = request.route;
        response.values.reserve(request.keys.size());
        for (const auto &key : request.keys) {
            const auto found = std::ranges::find_if(fixtures.facts, [&](const auto &fact) {
                return fact.route == request.route && fact.key == key.key;
            });
            if (found == fixtures.facts.end()) {
                response.values.push_back(Fact {
                    .subject_id = key.subject_id,
                    .key = key.key,
                    .value = Value::undefined(),
                    .status = FactStatus::unavailable,
                    .diagnostic = "custom fixture fact not configured",
                    .ttl = std::chrono::seconds {0},
                });
                continue;
            }
            response.values.push_back(Fact {
                .subject_id = key.subject_id,
                .key = key.key,
                .value = found->value,
                .status = FactStatus::available,
                .diagnostic = {},
                .ttl = found->ttl,
            });
        }
        return response;
    }
} // namespace rule_engine::custom_facts
