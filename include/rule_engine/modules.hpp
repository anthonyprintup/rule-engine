#pragma once

#include <chrono>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace rule_engine {
    enum struct ValueType {
        boolean,
        integer,
        floating,
        string,
        bytes,
        array,
        pattern,
        object,
        undefined,
    };

    struct FieldDescriptor {
        std::string key;
        ValueType type {ValueType::undefined};
        std::string route;
        std::chrono::seconds ttl {};
        std::chrono::seconds timeout {5};
        bool cheap_prefetch {};
    };

    struct FunctionDescriptor {
        std::string name;
        std::vector<ValueType> parameters;
        ValueType return_type {ValueType::undefined};
        std::string key_prefix;
        std::string route;
        std::chrono::seconds ttl {};
        std::chrono::seconds timeout {5};
        bool cheap_prefetch {};
    };

    struct ModuleDescriptor {
        std::string name;
        std::vector<FieldDescriptor> fields;
        std::vector<FunctionDescriptor> functions;
    };

    struct GlobalDescriptor {
        std::string name;
        ValueType type {ValueType::undefined};
        std::string key;
        std::string route;
        std::chrono::seconds ttl {};
        std::chrono::seconds timeout {5};
        bool cheap_prefetch {};
    };

    struct ModuleRegistry {
        std::vector<ModuleDescriptor> modules;
        std::vector<GlobalDescriptor> globals;

        [[nodiscard]] const ModuleDescriptor *find_module(std::string_view name) const noexcept;
        [[nodiscard]] const FieldDescriptor *find_field(std::string_view key) const noexcept;
        [[nodiscard]] const FunctionDescriptor *find_function(std::string_view key) const noexcept;
        [[nodiscard]] const GlobalDescriptor *find_global(std::string_view name) const noexcept;
    };

    [[nodiscard]] ModuleRegistry default_module_registry();
} // namespace rule_engine
