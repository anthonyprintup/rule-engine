#pragma once

#include <string>
#include <string_view>

namespace rule_engine::python::tools::detail {

    [[nodiscard]] inline std::string json_escape(const std::string_view value) {
        std::string result;
        result.reserve(value.size());
        constexpr char hexadecimal[] = "0123456789abcdef";
        for (const char character : value) {
            const auto byte = static_cast<unsigned char>(character);
            switch (byte) {
                case '"': result += "\\\""; break;
                case '\\': result += "\\\\"; break;
                case '\b': result += "\\b"; break;
                case '\f': result += "\\f"; break;
                case '\n': result += "\\n"; break;
                case '\r': result += "\\r"; break;
                case '\t': result += "\\t"; break;
                default:
                    if (byte < 0x20U) {
                        result += "\\u00";
                        result.push_back(hexadecimal[(byte >> 4U) & 0x0FU]);
                        result.push_back(hexadecimal[byte & 0x0FU]);
                        break;
                    }
                    result.push_back(static_cast<char>(byte));
                    break;
            }
        }
        return result;
    }

    [[nodiscard]] inline std::string json_quote(const std::string_view value) { return '"' + json_escape(value) + '"'; }

} // namespace rule_engine::python::tools::detail
