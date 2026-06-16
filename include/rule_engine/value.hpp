#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace rule_engine {
    struct PatternMatchContext {
        std::uint64_t offset {};
        std::uint64_t length {};
        std::vector<std::byte> bytes;
        std::vector<std::byte> before;
        std::vector<std::byte> after;
        std::string scan_space;
        std::string region_permissions;
    };

    struct PatternValue {
        bool matched {};
        std::vector<PatternMatchContext> matches;
    };

    struct ArrayValue;
    struct ObjectEntry;
    struct ObjectValue;

    struct Value {
        using ArrayPtr = std::shared_ptr<const ArrayValue>;
        using ObjectPtr = std::shared_ptr<const ObjectValue>;
        using Storage =
            std::variant<std::monostate, bool, std::int64_t, double, std::string, PatternValue, ArrayPtr, ObjectPtr>;

        Storage storage {};

        static Value undefined() noexcept { return {}; }
        static Value boolean(const bool value) { return Value {.storage = value}; }
        static Value integer(const std::int64_t value) { return Value {.storage = value}; }
        static Value number(const double value) { return Value {.storage = value}; }
        static Value string(std::string value) { return Value {.storage = std::move(value)}; }
        static Value pattern(PatternValue value) { return Value {.storage = std::move(value)}; }
        static Value array(std::vector<Value> values);
        static Value object(std::vector<ObjectEntry> entries);

        [[nodiscard]] bool is_undefined() const noexcept { return std::holds_alternative<std::monostate>(storage); }
        [[nodiscard]] std::optional<bool> as_bool() const noexcept;
        [[nodiscard]] std::optional<std::int64_t> as_i64() const noexcept;
        [[nodiscard]] std::optional<double> as_f64() const noexcept;
        [[nodiscard]] const std::string *as_string() const noexcept;
        [[nodiscard]] const PatternValue *as_pattern() const noexcept;
        [[nodiscard]] const ArrayValue *as_array() const noexcept;
        [[nodiscard]] const ObjectValue *as_object() const noexcept;
    };

    struct ArrayValue {
        std::vector<Value> values;
    };

    struct ObjectEntry {
        std::string key;
        Value value;
    };

    struct ObjectValue {
        std::vector<ObjectEntry> entries;
    };
} // namespace rule_engine
