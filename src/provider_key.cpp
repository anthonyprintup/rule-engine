#include <rule_engine/provider_key.hpp>

#include <bit>
#include <cstddef>
#include <cstdint>
#include <string>

namespace {
    constexpr char hex_digits[] = "0123456789abcdef";

    void append_hex_byte(std::string &out, const std::uint8_t value) {
        out.push_back(hex_digits[(value >> 4u) & 0x0fu]);
        out.push_back(hex_digits[value & 0x0fu]);
    }

    void append_hex_bytes(std::string &out, const std::span<const std::byte> bytes) {
        for (const auto byte : bytes) {
            append_hex_byte(out, std::to_integer<std::uint8_t>(byte));
        }
    }

    [[nodiscard]] std::string hex_bytes(const std::span<const std::byte> bytes) {
        std::string out;
        out.reserve(bytes.size() * 2u);
        append_hex_bytes(out, bytes);
        return out;
    }

    [[nodiscard]] std::string hex_string(const std::string_view value) {
        std::string out;
        out.reserve(value.size() * 2u);
        for (const auto c : value) {
            append_hex_byte(out, static_cast<std::uint8_t>(c));
        }
        return out;
    }

    [[nodiscard]] std::string hex_u64(const std::uint64_t value) {
        std::string out;
        out.reserve(16u);
        for (std::uint32_t shift = 60u; shift != 0xffffffffu; shift -= 4u) {
            out.push_back(hex_digits[(value >> shift) & 0x0fu]);
            if (shift == 0u) {
                break;
            }
        }
        return out;
    }

    void append_pattern_key(std::string &out, const rule_engine::PatternValue &pattern) {
        out += "p:";
        out += pattern.matched ? "true" : "false";
        out.push_back(':');
        out += std::to_string(pattern.matches.size());
        out.push_back('[');
        for (std::size_t index = 0; index < pattern.matches.size(); ++index) {
            if (index != 0u) {
                out.push_back(';');
            }
            const auto &match = pattern.matches[index];
            out += std::to_string(match.offset);
            out.push_back(':');
            out += std::to_string(match.length);
            out.push_back(':');
            append_hex_bytes(out, match.bytes);
            out.push_back(':');
            append_hex_bytes(out, match.before);
            out.push_back(':');
            append_hex_bytes(out, match.after);
            out.push_back(':');
            out += hex_string(match.scan_space);
            out.push_back(':');
            out += hex_string(match.region_permissions);
        }
        out.push_back(']');
    }

    void append_argument_key(std::string &out, const rule_engine::Value &value);

    void append_array_key(std::string &out, const rule_engine::ArrayValue &array) {
        out += "a:";
        out += std::to_string(array.values.size());
        out.push_back('[');
        for (std::size_t index = 0; index < array.values.size(); ++index) {
            if (index != 0u) {
                out.push_back(',');
            }
            append_argument_key(out, array.values[index]);
        }
        out.push_back(']');
    }

    void append_object_key(std::string &out, const rule_engine::ObjectValue &object) {
        out += "o:";
        out += std::to_string(object.entries.size());
        out.push_back('{');
        for (std::size_t index = 0; index < object.entries.size(); ++index) {
            if (index != 0u) {
                out.push_back(',');
            }
            const auto &entry = object.entries[index];
            out += "s:";
            out += hex_string(entry.key);
            out.push_back('=');
            append_argument_key(out, entry.value);
        }
        out.push_back('}');
    }

    void append_argument_key(std::string &out, const rule_engine::Value &value) {
        if (const auto boolean = value.as_bool(); boolean.has_value()) {
            out += *boolean ? "b:true" : "b:false";
            return;
        }
        if (const auto integer = value.as_i64(); integer.has_value()) {
            out += "i:";
            out += std::to_string(*integer);
            return;
        }
        if (const auto number = value.as_f64(); number.has_value()) {
            out += "f:";
            out += hex_u64(std::bit_cast<std::uint64_t>(*number));
            return;
        }
        if (const auto *string = value.as_string(); string != nullptr) {
            out += "s:";
            out += hex_string(*string);
            return;
        }
        if (const auto *bytes = value.as_bytes(); bytes != nullptr) {
            out += "x:";
            out += hex_bytes(*bytes);
            return;
        }
        if (const auto *array = value.as_array(); array != nullptr) {
            append_array_key(out, *array);
            return;
        }
        if (const auto *object = value.as_object(); object != nullptr) {
            append_object_key(out, *object);
            return;
        }
        if (const auto *pattern = value.as_pattern(); pattern != nullptr) {
            append_pattern_key(out, *pattern);
            return;
        }
        out += "u";
    }
} // namespace

namespace rule_engine {
    std::string provider_argument_key(const Value &value) {
        std::string out;
        append_argument_key(out, value);
        return out;
    }

    std::string provider_function_key(const std::string_view key_prefix, const std::span<const Value> arguments) {
        std::string out {key_prefix};
        out.push_back('(');
        for (std::size_t index = 0; index < arguments.size(); ++index) {
            if (index != 0u) {
                out.push_back(',');
            }
            append_argument_key(out, arguments[index]);
        }
        out.push_back(')');
        return out;
    }
} // namespace rule_engine
