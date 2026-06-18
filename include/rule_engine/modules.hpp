#pragma once

#include <chrono>
#include <cstdint>
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

    enum struct FactCostClass {
        inventory,
        cheap_process_snapshot,
        static_image_header,
        process_array,
        broad_image_array,
        handle_signer,
        memory_region,
        pattern_scan,
        custom,
    };

    enum struct ProviderRetryPolicy {
        none,
        timed_out,
    };

    [[nodiscard]] std::string_view fact_cost_class_name(FactCostClass cost_class) noexcept;
    [[nodiscard]] std::string_view provider_retry_policy_name(ProviderRetryPolicy retry_policy) noexcept;

    struct FieldDescriptor {
        std::string key;
        ValueType type {ValueType::undefined};
        std::string route;
        std::chrono::seconds ttl {};
        std::chrono::seconds timeout {5};
        ProviderRetryPolicy retry_policy {ProviderRetryPolicy::none};
        std::uint8_t retry_budget {};
        std::string cancellation_diagnostic {};
        bool cheap_prefetch {};
        FactCostClass cost_class {FactCostClass::custom};
    };

    struct FunctionDescriptor {
        std::string name;
        std::vector<ValueType> parameters;
        ValueType return_type {ValueType::undefined};
        std::string key_prefix;
        std::string route;
        std::chrono::seconds ttl {};
        std::chrono::seconds timeout {5};
        ProviderRetryPolicy retry_policy {ProviderRetryPolicy::none};
        std::uint8_t retry_budget {};
        std::string cancellation_diagnostic {};
        bool cheap_prefetch {};
        FactCostClass cost_class {FactCostClass::custom};
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
        ProviderRetryPolicy retry_policy {ProviderRetryPolicy::none};
        std::uint8_t retry_budget {};
        std::string cancellation_diagnostic {};
        bool cheap_prefetch {};
        FactCostClass cost_class {FactCostClass::custom};
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
