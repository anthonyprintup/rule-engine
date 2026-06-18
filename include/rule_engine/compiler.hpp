#pragma once

#include <rule_engine/ast.hpp>
#include <rule_engine/diagnostic.hpp>
#include <rule_engine/modules.hpp>

#include <cstddef>
#include <chrono>
#include <expected>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace rule_engine {
    struct PatternScanPlan {
        std::string pattern_key;
        std::vector<std::byte> literal;
    };

    struct ParseOptions {
        std::vector<std::filesystem::path> include_dirs;
        std::string namespace_name {"default"};
    };

    struct SourceUnit {
        std::string source_name;
        std::string namespace_name {"default"};
        std::string source;
    };

    struct RequiredFact {
        std::string key;
        std::string route;
        std::chrono::seconds ttl {};
        std::chrono::seconds timeout {5};
        ProviderRetryPolicy retry_policy {ProviderRetryPolicy::none};
        std::uint8_t retry_budget {};
        std::string cancellation_diagnostic {};
        bool cheap_prefetch {};
        ValueType type {ValueType::undefined};
        std::optional<PatternScanPlan> scan_plan;
        FactCostClass cost_class {FactCostClass::custom};
    };

    struct VerifiedRule {
        std::string identifier;
        std::string namespace_name;
        std::string qualified_identifier;
        bool is_private {};
        bool is_global {};
        SourceSpan span {};
        Expression condition;
        std::vector<std::string> rule_dependencies;
        std::vector<RequiredFact> facts;
    };

    struct VerifiedProgram {
        std::vector<std::string> sources;
        std::vector<VerifiedRule> rules;
        std::vector<Diagnostic> diagnostics;

        [[nodiscard]] std::string ir_dump() const;
        [[nodiscard]] std::string schedule_plan_dump() const;
        [[nodiscard]] std::vector<std::byte> ir_artifact() const;
        [[nodiscard]] std::vector<std::byte> schedule_plan_artifact() const;
    };

    [[nodiscard]] std::expected<ParsedRuleSet, ErrorSet> parse_source(std::string_view source_name,
                                                                      std::string_view source);
    [[nodiscard]] std::expected<ParsedRuleSet, ErrorSet> parse_sources(std::span<const SourceUnit> sources);
    [[nodiscard]] std::expected<ParsedRuleSet, ErrorSet> parse_file(const std::filesystem::path &path,
                                                                    const ParseOptions &options = {});
    [[nodiscard]] std::expected<VerifiedProgram, ErrorSet> verify(const ParsedRuleSet &rules,
                                                                  const ModuleRegistry &registry);
    [[nodiscard]] std::vector<std::string> required_provider_routes(const VerifiedProgram &program);
} // namespace rule_engine
