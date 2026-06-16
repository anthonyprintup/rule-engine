#pragma once

#include <rule_engine/diagnostic.hpp>

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace rule_engine {
    enum struct ExpressionKind {
        true_expr,
        false_expr,
        and_expr,
        or_expr,
        of_expr,
        with_expr,
        for_of_expr,
        for_in_expr,
        range_expr,
        tuple_expr,
        iterable_expr,
        lookup_expr,
        not_expr,
        negate,
        add,
        subtract,
        multiply,
        divide,
        modulo,
        bitwise_not,
        shift_left,
        shift_right,
        bitwise_and,
        bitwise_or,
        bitwise_xor,
        equal,
        not_equal,
        greater,
        greater_equal,
        less,
        less_equal,
        contains,
        icontains,
        starts_with,
        istarts_with,
        ends_with,
        iends_with,
        iequals,
        field,
        pattern_match,
        pattern_count,
        pattern_offset,
        pattern_length,
        literal_string,
        literal_integer,
        literal_float,
        identifier,
        function_call,
        global,
        defined,
        unsupported,
    };

    struct Expression {
        ExpressionKind kind {ExpressionKind::unsupported};
        std::string text;
        std::int64_t integer {};
        double floating {};
        std::vector<std::string> names;
        std::vector<Expression> children;
        std::string bound_key_prefix;
        std::string bound_route;
        std::chrono::seconds bound_ttl {};
        bool bound_cheap_prefetch {};
        SourceSpan span {};
    };

    struct ParsedPattern {
        std::string identifier;
        std::string kind;
        std::string literal;
        std::vector<std::string> modifiers;
    };

    struct ParsedRule {
        std::string identifier;
        std::string namespace_name;
        std::string qualified_identifier;
        bool is_private {};
        bool is_global {};
        std::vector<std::string> tags;
        std::vector<ParsedPattern> patterns;
        Expression condition;
        SourceSpan span {};
    };

    struct ParsedRuleSet {
        std::string source_name;
        std::vector<std::string> sources;
        std::vector<std::string> imports;
        std::vector<std::string> includes;
        std::vector<ParsedRule> rules;
    };
} // namespace rule_engine
