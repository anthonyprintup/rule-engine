#include "rule_engine/python/tools/redaction.hpp"

#include "rendering.hpp"

#include <algorithm>
#include <array>
#include <sstream>

namespace rule_engine::python::tools {
    namespace {

        [[nodiscard]] bool ascii_space(const char value) noexcept {
            return value == ' ' || value == '\t' || value == '\n' || value == '\r' || value == '\f' || value == '\v';
        }

        [[nodiscard]] char ascii_lower(const char value) noexcept {
            if (value >= 'A' && value <= 'Z') {
                return static_cast<char>(value + ('a' - 'A'));
            }
            return value;
        }

        [[nodiscard]] std::string lowercase(const std::string_view value) {
            std::string result;
            result.reserve(value.size());
            for (const char character : value) { result.push_back(ascii_lower(character)); }
            return result;
        }

        [[nodiscard]] bool identifier_byte(const char value) noexcept {
            return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') || (value >= '0' && value <= '9') ||
                   value == '_' || value == '-';
        }

        void redact_private_key_blocks(std::string &value) {
            constexpr std::string_view begin_marker = "-----BEGIN ";
            constexpr std::string_view private_marker = "PRIVATE KEY-----";
            constexpr std::string_view end_marker = "-----END ";

            std::size_t search_from {};
            while (true) {
                const auto begin = value.find(begin_marker, search_from);
                if (begin == std::string::npos) {
                    return;
                }
                const auto header_end = value.find('\n', begin);
                const auto header_limit = header_end == std::string::npos ? value.size() : header_end;
                if (value.find(private_marker, begin) >= header_limit) {
                    search_from = header_limit;
                    continue;
                }
                const auto end = value.find(end_marker, header_limit);
                const auto block_end =
                    end == std::string::npos ? value.size() : value.find("-----", end + end_marker.size());
                const auto replacement_end = block_end == std::string::npos ? value.size() : block_end + 5U;
                value.replace(begin, replacement_end - begin, redacted_value);
                search_from = begin + std::string_view {redacted_value}.size();
            }
        }

        void redact_bearer_tokens(std::string &value) {
            auto lower = lowercase(value);
            std::size_t search_from {};
            while (true) {
                const auto begin = lower.find("bearer ", search_from);
                if (begin == std::string::npos) {
                    return;
                }
                const auto token_begin = begin + 7U;
                auto token_end = token_begin;
                while (token_end < value.size()) {
                    if (ascii_space(value[token_end]) || value[token_end] == ',' || value[token_end] == ';') {
                        break;
                    }
                    ++token_end;
                }
                value.replace(token_begin, token_end - token_begin, redacted_value);
                lower = lowercase(value);
                search_from = token_begin + std::string_view {redacted_value}.size();
            }
        }

        void redact_uri_passwords(std::string &value) {
            std::size_t search_from {};
            while (true) {
                const auto scheme = value.find("://", search_from);
                if (scheme == std::string::npos) {
                    return;
                }
                const auto authority_begin = scheme + 3U;
                auto authority_end = value.find_first_of("/?# ", authority_begin);
                if (authority_end == std::string::npos) {
                    authority_end = value.size();
                }
                const auto at = value.find('@', authority_begin);
                if (at == std::string::npos || at >= authority_end) {
                    search_from = authority_end;
                    continue;
                }
                const auto colon = value.find(':', authority_begin);
                if (colon == std::string::npos || colon >= at) {
                    search_from = at + 1U;
                    continue;
                }
                value.replace(colon + 1U, at - colon - 1U, redacted_value);
                search_from = colon + 1U + std::string_view {redacted_value}.size();
            }
        }

        void redact_assignments(std::string &value) {
            constexpr std::array keys {
                std::string_view {"password"},      std::string_view {"passphrase"},
                std::string_view {"secret"},        std::string_view {"token"},
                std::string_view {"authorization"}, std::string_view {"connection_string"},
                std::string_view {"private_key"},   std::string_view {"credential"},
            };

            auto lower = lowercase(value);
            for (const auto key : keys) {
                std::size_t search_from {};
                while (true) {
                    const auto begin = lower.find(key, search_from);
                    if (begin == std::string::npos) {
                        break;
                    }
                    const auto after_key = begin + key.size();
                    if ((begin > 0 && identifier_byte(lower[begin - 1U])) ||
                        (after_key < lower.size() && identifier_byte(lower[after_key]))) {
                        search_from = after_key;
                        continue;
                    }
                    auto separator = after_key;
                    while (separator < value.size() && ascii_space(value[separator])) { ++separator; }
                    if (separator >= value.size() || (value[separator] != '=' && value[separator] != ':')) {
                        search_from = after_key;
                        continue;
                    }
                    auto secret_begin = separator + 1U;
                    while (secret_begin < value.size() && ascii_space(value[secret_begin])) { ++secret_begin; }
                    const char quote =
                        secret_begin < value.size() && (value[secret_begin] == '\'' || value[secret_begin] == '"') ?
                            value[secret_begin] :
                            '\0';
                    if (quote != '\0') {
                        ++secret_begin;
                    }
                    auto secret_end = secret_begin;
                    while (secret_end < value.size()) {
                        const char byte = value[secret_end];
                        if ((quote != '\0' && byte == quote) ||
                            (quote == '\0' && (ascii_space(byte) || byte == ',' || byte == ';' || byte == '}'))) {
                            break;
                        }
                        ++secret_end;
                    }
                    value.replace(secret_begin, secret_end - secret_begin, redacted_value);
                    lower = lowercase(value);
                    search_from = secret_begin + std::string_view {redacted_value}.size();
                }
            }
        }

    } // namespace

    bool field_name_is_sensitive(const std::string_view name) noexcept {
        const auto lower = lowercase(name);
        constexpr std::array sensitive_fragments {
            std::string_view {"password"},         std::string_view {"passphrase"},
            std::string_view {"secret"},           std::string_view {"token"},
            std::string_view {"authorization"},    std::string_view {"connection"},
            std::string_view {"private_key"},      std::string_view {"credential"},
            std::string_view {"signer_reference"}, std::string_view {"key_provider"},
        };
        return std::ranges::any_of(sensitive_fragments, [&lower](const std::string_view fragment) {
            return lower.find(fragment) != std::string::npos;
        });
    }

    std::string redact_text(const std::string_view text) {
        std::string result {text};
        redact_private_key_blocks(result);
        redact_bearer_tokens(result);
        redact_uri_passwords(result);
        redact_assignments(result);
        return result;
    }

    std::string display_value(const DisplayField &field) {
        if (field.secret_reference || field_name_is_sensitive(field.name) ||
            field.label.classification == Classification::sensitive ||
            field.label.classification == Classification::secret) {
            return redacted_value;
        }
        return redact_text(field.value);
    }

    std::string render_fields_text(const std::span<const DisplayField> fields) {
        std::ostringstream output;
        for (const auto &field : fields) { output << redact_text(field.name) << ": " << display_value(field) << '\n'; }
        return output.str();
    }

    std::string render_fields_json(const std::span<const DisplayField> fields) {
        std::ostringstream output;
        output << '{';
        for (std::size_t index = 0; index < fields.size(); ++index) {
            if (index != 0) {
                output << ',';
            }
            output << detail::json_quote(redact_text(fields[index].name)) << ':'
                   << detail::json_quote(display_value(fields[index]));
        }
        output << '}';
        return output.str();
    }

} // namespace rule_engine::python::tools
