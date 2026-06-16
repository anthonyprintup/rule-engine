#include <rule_engine/compiler.hpp>

#include <rule_engine/provider_key.hpp>
#include <rule_engine/value.hpp>
#include <rule_engine/yara_bridge.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace {
    namespace bridge = rule_engine::yara_bridge;

    struct OwnedBridgeParse {
        bridge::ReParseResult result {};

        explicit OwnedBridgeParse(bridge::ReParseResult value) noexcept: result {value} {}

        ~OwnedBridgeParse() noexcept {
            if (result.rules != nullptr) {
                bridge::re_yara_bridge_free(result.rules);
            }
        }

        OwnedBridgeParse(const OwnedBridgeParse &) = delete;
        OwnedBridgeParse &operator=(const OwnedBridgeParse &) = delete;
        OwnedBridgeParse(OwnedBridgeParse &&) = delete;
        OwnedBridgeParse &operator=(OwnedBridgeParse &&) = delete;
    };

    [[nodiscard]] rule_engine::ExpressionKind expression_kind(const bridge::ReNodeKind kind) noexcept {
        using enum rule_engine::ExpressionKind;
        switch (kind) {
            case bridge::ReNodeKind::True: return true_expr;
            case bridge::ReNodeKind::False: return false_expr;
            case bridge::ReNodeKind::And: return and_expr;
            case bridge::ReNodeKind::Or: return or_expr;
            case bridge::ReNodeKind::Of: return of_expr;
            case bridge::ReNodeKind::With: return with_expr;
            case bridge::ReNodeKind::ForIn: return for_in_expr;
            case bridge::ReNodeKind::ForOf: return for_of_expr;
            case bridge::ReNodeKind::Range: return range_expr;
            case bridge::ReNodeKind::Tuple: return tuple_expr;
            case bridge::ReNodeKind::IterableExpr: return iterable_expr;
            case bridge::ReNodeKind::Lookup: return lookup_expr;
            case bridge::ReNodeKind::Not: return not_expr;
            case bridge::ReNodeKind::Negate: return negate;
            case bridge::ReNodeKind::Add: return add;
            case bridge::ReNodeKind::Subtract: return subtract;
            case bridge::ReNodeKind::Multiply: return multiply;
            case bridge::ReNodeKind::Divide: return divide;
            case bridge::ReNodeKind::Modulo: return modulo;
            case bridge::ReNodeKind::BitwiseNot: return bitwise_not;
            case bridge::ReNodeKind::ShiftLeft: return shift_left;
            case bridge::ReNodeKind::ShiftRight: return shift_right;
            case bridge::ReNodeKind::BitwiseAnd: return bitwise_and;
            case bridge::ReNodeKind::BitwiseOr: return bitwise_or;
            case bridge::ReNodeKind::BitwiseXor: return bitwise_xor;
            case bridge::ReNodeKind::Equal: return equal;
            case bridge::ReNodeKind::NotEqual: return not_equal;
            case bridge::ReNodeKind::Greater: return greater;
            case bridge::ReNodeKind::GreaterEqual: return greater_equal;
            case bridge::ReNodeKind::Less: return less;
            case bridge::ReNodeKind::LessEqual: return less_equal;
            case bridge::ReNodeKind::Contains: return contains;
            case bridge::ReNodeKind::IContains: return icontains;
            case bridge::ReNodeKind::StartsWith: return starts_with;
            case bridge::ReNodeKind::IStartsWith: return istarts_with;
            case bridge::ReNodeKind::EndsWith: return ends_with;
            case bridge::ReNodeKind::IEndsWith: return iends_with;
            case bridge::ReNodeKind::IEquals: return iequals;
            case bridge::ReNodeKind::Field: return field;
            case bridge::ReNodeKind::PatternMatch: return pattern_match;
            case bridge::ReNodeKind::PatternCount: return pattern_count;
            case bridge::ReNodeKind::PatternOffset: return pattern_offset;
            case bridge::ReNodeKind::PatternLength: return pattern_length;
            case bridge::ReNodeKind::LiteralString: return literal_string;
            case bridge::ReNodeKind::LiteralInteger: return literal_integer;
            case bridge::ReNodeKind::LiteralFloat: return literal_float;
            case bridge::ReNodeKind::Identifier: return identifier;
            case bridge::ReNodeKind::FunctionCall: return function_call;
            case bridge::ReNodeKind::Defined: return defined;
            case bridge::ReNodeKind::Unsupported:
            default: return unsupported;
        }
    }

    [[nodiscard]] std::string kind_text(const bridge::ReNodeKind kind) {
        switch (kind) {
            case bridge::ReNodeKind::True: return "true";
            case bridge::ReNodeKind::False: return "false";
            case bridge::ReNodeKind::And: return "and";
            case bridge::ReNodeKind::Or: return "or";
            case bridge::ReNodeKind::Of: return "of";
            case bridge::ReNodeKind::With: return "with";
            case bridge::ReNodeKind::ForIn: return "for_in";
            case bridge::ReNodeKind::ForOf: return "for_of";
            case bridge::ReNodeKind::Range: return "range";
            case bridge::ReNodeKind::Tuple: return "tuple";
            case bridge::ReNodeKind::IterableExpr: return "iterable_expr";
            case bridge::ReNodeKind::Lookup: return "lookup";
            case bridge::ReNodeKind::Not: return "not";
            case bridge::ReNodeKind::Negate: return "minus";
            case bridge::ReNodeKind::Add: return "add";
            case bridge::ReNodeKind::Subtract: return "sub";
            case bridge::ReNodeKind::Multiply: return "mul";
            case bridge::ReNodeKind::Divide: return "div";
            case bridge::ReNodeKind::Modulo: return "mod";
            case bridge::ReNodeKind::BitwiseNot: return "bitwise_not";
            case bridge::ReNodeKind::ShiftLeft: return "shl";
            case bridge::ReNodeKind::ShiftRight: return "shr";
            case bridge::ReNodeKind::BitwiseAnd: return "bitwise_and";
            case bridge::ReNodeKind::BitwiseOr: return "bitwise_or";
            case bridge::ReNodeKind::BitwiseXor: return "bitwise_xor";
            case bridge::ReNodeKind::Equal: return "eq";
            case bridge::ReNodeKind::NotEqual: return "ne";
            case bridge::ReNodeKind::Greater: return "gt";
            case bridge::ReNodeKind::GreaterEqual: return "ge";
            case bridge::ReNodeKind::Less: return "lt";
            case bridge::ReNodeKind::LessEqual: return "le";
            case bridge::ReNodeKind::Contains: return "contains";
            case bridge::ReNodeKind::IContains: return "icontains";
            case bridge::ReNodeKind::StartsWith: return "startswith";
            case bridge::ReNodeKind::IStartsWith: return "istartswith";
            case bridge::ReNodeKind::EndsWith: return "endswith";
            case bridge::ReNodeKind::IEndsWith: return "iendswith";
            case bridge::ReNodeKind::IEquals: return "iequals";
            case bridge::ReNodeKind::Field: return "field";
            case bridge::ReNodeKind::PatternMatch: return "pattern";
            case bridge::ReNodeKind::PatternCount: return "pattern_count";
            case bridge::ReNodeKind::PatternOffset: return "pattern_offset";
            case bridge::ReNodeKind::PatternLength: return "pattern_length";
            case bridge::ReNodeKind::LiteralString: return "str";
            case bridge::ReNodeKind::LiteralInteger: return "int";
            case bridge::ReNodeKind::LiteralFloat: return "float";
            case bridge::ReNodeKind::Identifier: return "ident";
            case bridge::ReNodeKind::FunctionCall: return "function_call";
            case bridge::ReNodeKind::Defined: return "defined";
            case bridge::ReNodeKind::Unsupported:
            default: return "unsupported";
        }
    }

    [[nodiscard]] std::string to_string(const bridge::ReStringView value) {
        if (value.data == nullptr || value.len == 0u) {
            return {};
        }
        return std::string {reinterpret_cast<const char *>(value.data), value.len};
    }

    [[nodiscard]] std::string normalize_namespace_name(const std::string_view namespace_name) {
        if (namespace_name.empty()) {
            return "default";
        }
        return std::string {namespace_name};
    }

    [[nodiscard]] std::string qualified_rule_identifier(const std::string_view namespace_name,
                                                        const std::string_view identifier) {
        const auto normalized = normalize_namespace_name(namespace_name);
        if (normalized == "default") {
            return std::string {identifier};
        }
        auto out = normalized;
        out.push_back('.');
        out.append(identifier);
        return out;
    }

    [[nodiscard]] std::string join_names(const std::vector<std::string> &names) {
        std::string out;
        for (const auto &name : names) {
            if (!out.empty()) {
                out.push_back('.');
            }
            out += name;
        }
        return out;
    }

    [[nodiscard]] rule_engine::SourceSpan bridge_span(const bridge::ReSpan span,
                                                      const std::string_view source_name,
                                                      const std::uint32_t source_id) {
        return rule_engine::SourceSpan {
            .source_id = source_id,
            .start = static_cast<std::size_t>(span.start),
            .end = static_cast<std::size_t>(span.end),
            .source = std::string {source_name},
        };
    }

    [[nodiscard]] std::string diagnostic_source(const rule_engine::SourceSpan &span,
                                                const std::string_view fallback) {
        if (!span.source.empty()) {
            return span.source;
        }
        return std::string {fallback};
    }

    [[nodiscard]] rule_engine::Diagnostic bridge_diagnostic(const bridge::ReDiagnosticView diagnostic,
                                                            const std::string_view source_name,
                                                            const std::uint32_t source_id) {
        auto source = to_string(diagnostic.source);
        if (source.empty()) {
            source = std::string {source_name};
        }
        return rule_engine::Diagnostic {
            .source = std::move(source),
            .span = bridge_span(diagnostic.span, source_name, source_id),
            .message = to_string(diagnostic.message),
        };
    }

    [[nodiscard]] rule_engine::Expression bridge_expression(const bridge::ReParsedRuleSet *rules,
                                                            const bridge::ReNode *node,
                                                            const std::string_view source_name,
                                                            const std::uint32_t source_id) {
        const auto view = bridge::re_yara_bridge_node_view(rules, node);
        rule_engine::Expression out;
        out.kind = expression_kind(view.kind);
        out.text = to_string(view.text);
        if (out.text.empty()) {
            out.text = kind_text(view.kind);
        }
        out.integer = view.int_value;
        out.floating = view.float_value;
        out.span = bridge_span(view.span, source_name, source_id);

        for (std::size_t index = 0; index < view.names_len; ++index) {
            out.names.push_back(to_string(bridge::re_yara_bridge_node_name_at(rules, node, index)));
        }
        for (std::size_t index = 0; index < view.children_len; ++index) {
            const auto *child = bridge::re_yara_bridge_node_child_at(rules, node, index);
            if (child != nullptr) {
                out.children.push_back(bridge_expression(rules, child, source_name, source_id));
            }
        }
        return out;
    }

    [[nodiscard]] std::string pattern_kind_name(const bridge::RePatternKind kind) {
        switch (kind) {
            case bridge::RePatternKind::Text: return "text";
            case bridge::RePatternKind::Hex: return "hex";
            case bridge::RePatternKind::Regexp: return "regexp";
            case bridge::RePatternKind::Unknown:
            default: return "unknown";
        }
    }

    [[nodiscard]] rule_engine::ParsedPattern bridge_pattern(const bridge::ReParsedRuleSet *rules,
                                                            const bridge::RePatternView pattern) {
        rule_engine::ParsedPattern out;
        out.identifier = to_string(pattern.identifier);
        out.kind = pattern_kind_name(pattern.kind);
        out.literal = to_string(pattern.literal);
        for (std::size_t index = 0; index < pattern.modifiers_len; ++index) {
            out.modifiers.push_back(to_string(bridge::re_yara_bridge_pattern_modifier_at(rules, pattern, index)));
        }
        return out;
    }

    [[nodiscard]] rule_engine::ParsedRule bridge_rule(const bridge::ReParsedRuleSet *rules,
                                                      const bridge::ReRuleView rule,
                                                      const std::string_view source_name,
                                                      const std::uint32_t source_id) {
        rule_engine::ParsedRule out;
        out.identifier = to_string(rule.identifier);
        out.is_private = rule.is_private;
        out.is_global = rule.is_global;
        out.span = bridge_span(rule.span, source_name, source_id);
        for (std::size_t index = 0; index < rule.tags_len; ++index) {
            out.tags.push_back(to_string(bridge::re_yara_bridge_rule_tag_at(rules, rule, index)));
        }
        for (std::size_t index = 0; index < rule.patterns_len; ++index) {
            out.patterns.push_back(bridge_pattern(rules, bridge::re_yara_bridge_rule_pattern_at(rules, rule, index)));
        }
        if (const auto *condition = bridge::re_yara_bridge_rule_condition(rules, rule); condition != nullptr) {
            out.condition = bridge_expression(rules, condition, source_name, source_id);
        }
        return out;
    }

    [[nodiscard]] bool contains_name(const std::vector<std::string> &values, const std::string_view value) {
        return std::ranges::any_of(values, [&](const auto &candidate) { return candidate == value; });
    }

    struct RuleSymbol {
        std::string namespace_name;
        std::string identifier;
        std::string qualified_identifier;
    };

    [[nodiscard]] bool contains_rule_symbol(const std::vector<RuleSymbol> &symbols,
                                            const std::string_view qualified_identifier) {
        return std::ranges::any_of(symbols, [&](const auto &symbol) {
            return symbol.qualified_identifier == qualified_identifier;
        });
    }

    [[nodiscard]] std::optional<std::string>
    resolve_rule_reference(const std::vector<RuleSymbol> &symbols,
                           const std::string_view current_namespace,
                           const std::string_view name) {
        if (name.empty()) {
            return std::nullopt;
        }
        const auto candidate =
            name.find('.') != std::string_view::npos ? std::string {name}
                                                     : qualified_rule_identifier(current_namespace, name);
        if (!contains_rule_symbol(symbols, candidate)) {
            return std::nullopt;
        }
        return candidate;
    }

    [[nodiscard]] std::optional<std::string>
    resolve_rule_reference(const std::vector<RuleSymbol> &symbols,
                           const std::string_view current_namespace,
                           const std::vector<std::string> &names) {
        if (names.size() == 1u) {
            return resolve_rule_reference(symbols, current_namespace, names[0]);
        }
        if (names.size() != 2u) {
            return std::nullopt;
        }

        const auto candidate = qualified_rule_identifier(names[0], names[1]);
        if (!contains_rule_symbol(symbols, candidate)) {
            return std::nullopt;
        }
        return candidate;
    }

    void add_fact(std::vector<rule_engine::RequiredFact> &facts, rule_engine::RequiredFact fact) {
        const auto duplicate = std::ranges::any_of(facts, [&](const auto &existing) { return existing.key == fact.key; });
        if (duplicate) {
            return;
        }
        facts.push_back(std::move(fact));
    }

    void add_route(std::vector<std::string> &routes, const std::string_view route) {
        if (route.empty()) {
            return;
        }
        const auto duplicate = std::ranges::any_of(routes, [&](const auto &existing) { return existing == route; });
        if (duplicate) {
            return;
        }
        routes.emplace_back(route);
    }

    void collect_expression_routes(const rule_engine::Expression &expr, std::vector<std::string> &routes) {
        if (expr.kind == rule_engine::ExpressionKind::function_call) {
            add_route(routes, expr.bound_route);
        }
        for (const auto &child : expr.children) {
            collect_expression_routes(child, routes);
        }
    }

    [[nodiscard]] std::string pattern_identifier_key(std::string value) {
        if (value.empty()) {
            return "$";
        }
        if (value.ends_with('*')) {
            value.pop_back();
        }
        if (value.starts_with('$')) {
            return value;
        }
        if (value.starts_with('#') || value.starts_with('@') || value.starts_with('!')) {
            value.erase(value.begin());
        }
        if (value.empty()) {
            return "$";
        }
        value.insert(value.begin(), '$');
        return value;
    }

    [[nodiscard]] std::vector<std::string> expand_pattern_names(const std::vector<std::string> &names,
                                                                const std::vector<std::string> &rule_patterns) {
        std::vector<std::string> out;
        const auto add_pattern = [&](std::string value) {
            if (!contains_name(out, value)) {
                out.push_back(std::move(value));
            }
        };
        for (const auto &name : names) {
            if (name == "them") {
                for (const auto &pattern : rule_patterns) {
                    add_pattern(pattern_identifier_key(pattern));
                }
                continue;
            }

            if (name.ends_with('*')) {
                auto prefix = pattern_identifier_key(name);
                for (const auto &pattern : rule_patterns) {
                    const auto key = pattern_identifier_key(pattern);
                    if (key.starts_with(prefix)) {
                        add_pattern(key);
                    }
                }
                continue;
            }

            add_pattern(pattern_identifier_key(name));
        }
        return out;
    }

    [[nodiscard]] std::optional<rule_engine::PatternScanPlan>
    pattern_scan_plan_for(const std::vector<rule_engine::ParsedPattern> &patterns, const std::string_view pattern_key) {
        const auto found = std::ranges::find_if(patterns, [&](const auto &pattern) {
            return pattern_identifier_key(pattern.identifier) == pattern_key;
        });
        if (found == patterns.end() || found->kind != "text" || found->literal.empty()) {
            return std::nullopt;
        }

        rule_engine::PatternScanPlan plan;
        plan.pattern_key = std::string {pattern_key};
        plan.literal.reserve(found->literal.size());
        for (const auto ch : found->literal) {
            plan.literal.push_back(static_cast<std::byte>(static_cast<unsigned char>(ch)));
        }
        return plan;
    }

    [[nodiscard]] rule_engine::RequiredFact pattern_required_fact(
        const std::string_view pattern_name,
        const std::string_view suffix,
        const rule_engine::ValueType type,
        const std::vector<rule_engine::ParsedPattern> &rule_patterns) {
        auto pattern_key = pattern_identifier_key(std::string {pattern_name});
        rule_engine::RequiredFact fact {
            .key = pattern_key + std::string {suffix},
            .route = "endpoint.scan.patterns",
            .ttl = std::chrono::seconds {30},
            .cheap_prefetch = false,
            .type = type,
            .scan_plan = std::nullopt,
        };
        fact.scan_plan = pattern_scan_plan_for(rule_patterns, pattern_key);
        return fact;
    }

    [[nodiscard]] bool is_pattern_placeholder(const rule_engine::Expression &expr) {
        const auto name = !expr.names.empty() ? std::string_view {expr.names[0]} : std::string_view {expr.text};
        return name == "$";
    }

    [[nodiscard]] std::string value_type_name(const rule_engine::ValueType type) {
        switch (type) {
            case rule_engine::ValueType::boolean: return "boolean";
            case rule_engine::ValueType::integer: return "integer";
            case rule_engine::ValueType::floating: return "floating";
            case rule_engine::ValueType::string: return "string";
            case rule_engine::ValueType::bytes: return "bytes";
            case rule_engine::ValueType::array: return "array";
            case rule_engine::ValueType::pattern: return "pattern";
            case rule_engine::ValueType::object: return "object";
            case rule_engine::ValueType::undefined: return "undefined";
            default: return "unknown";
        }
    }

    [[nodiscard]] std::optional<rule_engine::ValueType>
    static_expression_type(const rule_engine::Expression &expr,
                           const rule_engine::ModuleRegistry &registry,
                           const std::vector<std::string> &local_names);

    [[nodiscard]] std::optional<std::int64_t> checked_add(const std::int64_t lhs,
                                                          const std::int64_t rhs) noexcept {
        std::int64_t out {};
        if (__builtin_add_overflow(lhs, rhs, &out)) {
            return std::nullopt;
        }
        return out;
    }

    [[nodiscard]] std::optional<std::int64_t> checked_subtract(const std::int64_t lhs,
                                                               const std::int64_t rhs) noexcept {
        std::int64_t out {};
        if (__builtin_sub_overflow(lhs, rhs, &out)) {
            return std::nullopt;
        }
        return out;
    }

    [[nodiscard]] std::optional<std::int64_t> checked_multiply(const std::int64_t lhs,
                                                               const std::int64_t rhs) noexcept {
        std::int64_t out {};
        if (__builtin_mul_overflow(lhs, rhs, &out)) {
            return std::nullopt;
        }
        return out;
    }

    [[nodiscard]] std::optional<std::int64_t> checked_divide(const std::int64_t lhs,
                                                             const std::int64_t rhs) noexcept {
        if (rhs == 0) {
            return std::nullopt;
        }
        if (lhs == std::numeric_limits<std::int64_t>::min() && rhs == -1) {
            return std::nullopt;
        }
        return lhs / rhs;
    }

    [[nodiscard]] std::optional<std::int64_t> checked_modulo(const std::int64_t lhs,
                                                             const std::int64_t rhs) noexcept {
        if (rhs == 0) {
            return std::nullopt;
        }
        if (lhs == std::numeric_limits<std::int64_t>::min() && rhs == -1) {
            return std::nullopt;
        }
        return lhs % rhs;
    }

    struct StaticNumericValue {
        bool floating {};
        std::int64_t integer {};
        double number {};
    };

    [[nodiscard]] std::optional<StaticNumericValue> static_numeric_value(const rule_engine::Value &value) noexcept {
        if (const auto integer = value.as_i64(); integer.has_value()) {
            return StaticNumericValue {
                .floating = false,
                .integer = *integer,
                .number = static_cast<double>(*integer),
            };
        }
        if (const auto number = value.as_f64(); number.has_value()) {
            return StaticNumericValue {.floating = true, .integer = {}, .number = *number};
        }
        return std::nullopt;
    }

    [[nodiscard]] std::optional<rule_engine::Value> static_expression_value(const rule_engine::Expression &expr);

    [[nodiscard]] std::optional<rule_engine::Value> static_arithmetic_value(const rule_engine::Expression &expr) {
        using enum rule_engine::ExpressionKind;
        if (expr.children.empty()) {
            return std::nullopt;
        }

        const auto first_value = static_expression_value(expr.children[0]);
        if (!first_value.has_value()) {
            return std::nullopt;
        }
        auto accumulator = static_numeric_value(*first_value);
        if (!accumulator.has_value()) {
            return std::nullopt;
        }

        if (expr.kind == negate) {
            if (expr.children.size() != 1u) {
                return std::nullopt;
            }
            if (accumulator->floating) {
                return rule_engine::Value::number(-accumulator->number);
            }
            if (accumulator->integer == std::numeric_limits<std::int64_t>::min()) {
                return std::nullopt;
            }
            return rule_engine::Value::integer(-accumulator->integer);
        }

        auto floating = accumulator->floating;
        auto number = accumulator->number;
        auto integer = accumulator->integer;

        for (std::size_t index = 1; index < expr.children.size(); ++index) {
            const auto child_value = static_expression_value(expr.children[index]);
            if (!child_value.has_value()) {
                return std::nullopt;
            }
            const auto operand = static_numeric_value(*child_value);
            if (!operand.has_value()) {
                return std::nullopt;
            }

            if (floating || operand->floating) {
                floating = true;
                if (expr.kind == add) {
                    number += operand->number;
                } else if (expr.kind == subtract) {
                    number -= operand->number;
                } else if (expr.kind == multiply) {
                    number *= operand->number;
                } else if (expr.kind == divide) {
                    if (operand->number == 0.0) {
                        return std::nullopt;
                    }
                    number /= operand->number;
                } else {
                    return std::nullopt;
                }
                continue;
            }

            std::optional<std::int64_t> next;
            if (expr.kind == add) {
                next = checked_add(integer, operand->integer);
            } else if (expr.kind == subtract) {
                next = checked_subtract(integer, operand->integer);
            } else if (expr.kind == multiply) {
                next = checked_multiply(integer, operand->integer);
            } else if (expr.kind == divide) {
                next = checked_divide(integer, operand->integer);
            } else if (expr.kind == modulo) {
                next = checked_modulo(integer, operand->integer);
            }
            if (!next.has_value()) {
                return std::nullopt;
            }
            integer = *next;
            number = static_cast<double>(integer);
        }

        if (floating) {
            return rule_engine::Value::number(number);
        }
        return rule_engine::Value::integer(integer);
    }

    [[nodiscard]] std::optional<rule_engine::Value> static_bitwise_value(const rule_engine::Expression &expr) {
        using enum rule_engine::ExpressionKind;
        if (expr.children.empty()) {
            return std::nullopt;
        }

        const auto lhs_value = static_expression_value(expr.children[0]);
        if (!lhs_value.has_value()) {
            return std::nullopt;
        }
        const auto left = lhs_value->as_i64();
        if (!left.has_value()) {
            return std::nullopt;
        }

        if (expr.kind == bitwise_not) {
            if (expr.children.size() != 1u) {
                return std::nullopt;
            }
            return rule_engine::Value::integer(static_cast<std::int64_t>(~static_cast<std::uint64_t>(*left)));
        }

        if (expr.children.size() != 2u) {
            return std::nullopt;
        }
        const auto rhs_value = static_expression_value(expr.children[1]);
        if (!rhs_value.has_value()) {
            return std::nullopt;
        }
        const auto right = rhs_value->as_i64();
        if (!right.has_value()) {
            return std::nullopt;
        }

        const auto left_bits = static_cast<std::uint64_t>(*left);
        const auto right_bits = static_cast<std::uint64_t>(*right);
        if (expr.kind == bitwise_and) {
            return rule_engine::Value::integer(static_cast<std::int64_t>(left_bits & right_bits));
        }
        if (expr.kind == bitwise_or) {
            return rule_engine::Value::integer(static_cast<std::int64_t>(left_bits | right_bits));
        }
        if (expr.kind == bitwise_xor) {
            return rule_engine::Value::integer(static_cast<std::int64_t>(left_bits ^ right_bits));
        }
        if (*right < 0 || *right >= 64) {
            return std::nullopt;
        }
        if (expr.kind == shift_left) {
            return rule_engine::Value::integer(static_cast<std::int64_t>(left_bits << *right));
        }
        if (expr.kind == shift_right) {
            return rule_engine::Value::integer(static_cast<std::int64_t>(left_bits >> *right));
        }
        return std::nullopt;
    }

    [[nodiscard]] std::optional<rule_engine::Value> static_expression_value(const rule_engine::Expression &expr) {
        using enum rule_engine::ExpressionKind;
        if (expr.kind == true_expr) {
            return rule_engine::Value::boolean(true);
        }
        if (expr.kind == false_expr) {
            return rule_engine::Value::boolean(false);
        }
        if (expr.kind == literal_string) {
            return rule_engine::Value::string(expr.text);
        }
        if (expr.kind == literal_integer) {
            return rule_engine::Value::integer(expr.integer);
        }
        if (expr.kind == literal_float) {
            return rule_engine::Value::number(expr.floating);
        }
        if (expr.kind == negate || expr.kind == add || expr.kind == subtract || expr.kind == multiply ||
            expr.kind == divide || expr.kind == modulo) {
            return static_arithmetic_value(expr);
        }
        if (expr.kind == bitwise_not || expr.kind == shift_left || expr.kind == shift_right ||
            expr.kind == bitwise_and || expr.kind == bitwise_or || expr.kind == bitwise_xor) {
            return static_bitwise_value(expr);
        }
        return std::nullopt;
    }

    [[nodiscard]] std::optional<std::vector<rule_engine::Value>>
    static_function_arguments(const rule_engine::Expression &expr) {
        std::vector<rule_engine::Value> arguments;
        arguments.reserve(expr.children.size());
        for (const auto &child : expr.children) {
            auto value = static_expression_value(child);
            if (!value.has_value()) {
                return std::nullopt;
            }
            arguments.push_back(std::move(*value));
        }
        return arguments;
    }

    [[nodiscard]] std::optional<rule_engine::ValueType>
    numeric_expression_type(const rule_engine::Expression &expr,
                            const rule_engine::ModuleRegistry &registry,
                            const std::vector<std::string> &local_names) {
        bool saw_floating {};
        for (const auto &child : expr.children) {
            const auto child_type = static_expression_type(child, registry, local_names);
            if (!child_type.has_value()) {
                return std::nullopt;
            }
            if (*child_type == rule_engine::ValueType::floating) {
                saw_floating = true;
                continue;
            }
            if (*child_type != rule_engine::ValueType::integer) {
                return std::nullopt;
            }
        }
        return saw_floating ? rule_engine::ValueType::floating : rule_engine::ValueType::integer;
    }

    [[nodiscard]] std::optional<rule_engine::ValueType>
    static_expression_type(const rule_engine::Expression &expr,
                           const rule_engine::ModuleRegistry &registry,
                           const std::vector<std::string> &local_names) {
        using enum rule_engine::ExpressionKind;

        switch (expr.kind) {
            case true_expr:
            case false_expr:
            case and_expr:
            case or_expr:
            case of_expr:
            case for_of_expr:
            case for_in_expr:
            case not_expr:
            case equal:
            case not_equal:
            case greater:
            case greater_equal:
            case less:
            case less_equal:
            case contains:
            case icontains:
            case starts_with:
            case istarts_with:
            case ends_with:
            case iends_with:
            case iequals:
            case pattern_match:
            case defined:
                return rule_engine::ValueType::boolean;
            case literal_string:
                return rule_engine::ValueType::string;
            case literal_integer:
            case bitwise_not:
            case shift_left:
            case shift_right:
            case bitwise_and:
            case bitwise_or:
            case bitwise_xor:
            case pattern_count:
            case pattern_offset:
            case pattern_length:
                return rule_engine::ValueType::integer;
            case literal_float:
                return rule_engine::ValueType::floating;
            case negate:
            case add:
            case subtract:
            case multiply:
            case divide:
            case modulo:
                return numeric_expression_type(expr, registry, local_names);
            case range_expr:
            case tuple_expr:
            case iterable_expr:
                return rule_engine::ValueType::array;
            case field: {
                const auto *field = registry.find_field(join_names(expr.names));
                if (field == nullptr) {
                    return std::nullopt;
                }
                return field->type;
            }
            case identifier: {
                const auto name = !expr.names.empty() ? std::string_view {expr.names[0]} : std::string_view {expr.text};
                if (contains_name(local_names, name)) {
                    return std::nullopt;
                }
                const auto *global = registry.find_global(name);
                if (global == nullptr) {
                    return std::nullopt;
                }
                return global->type;
            }
            case function_call: {
                const auto key = !expr.names.empty() ? join_names(expr.names) : expr.text;
                const auto *function = registry.find_function(key);
                if (function == nullptr || function->return_type == rule_engine::ValueType::undefined) {
                    return std::nullopt;
                }
                return function->return_type;
            }
            case global: {
                if (expr.names.empty()) {
                    return std::nullopt;
                }
                const auto *global = registry.find_global(expr.names[0]);
                if (global == nullptr) {
                    return std::nullopt;
                }
                return global->type;
            }
            case with_expr:
            case lookup_expr:
            case unsupported:
            default:
                return std::nullopt;
        }
    }

    void validate_function_arguments(const std::string &key,
                                     const rule_engine::Expression &expr,
                                     const rule_engine::FunctionDescriptor &function,
                                     const rule_engine::ModuleRegistry &registry,
                                     rule_engine::ErrorSet &errors,
                                     const std::string_view source,
                                     const std::vector<std::string> &local_names) {
        for (std::size_t index = 0; index < expr.children.size(); ++index) {
            const auto actual_type = static_expression_type(expr.children[index], registry, local_names);
            if (!actual_type.has_value()) {
                continue;
            }
            const auto expected_type = function.parameters[index];
            if (expected_type == rule_engine::ValueType::undefined || expected_type == *actual_type) {
                continue;
            }
            errors.diagnostics.push_back(rule_engine::Diagnostic {
                .source = diagnostic_source(expr.children[index].span, source),
                .span = expr.children[index].span,
                .message = "function " + key + " argument " + std::to_string(index + 1u) + " expects " +
                           value_type_name(expected_type) + " but got " + value_type_name(*actual_type),
            });
        }
    }

    void collect_requirements(rule_engine::Expression &expr,
                              const rule_engine::ModuleRegistry &registry,
                              const std::vector<RuleSymbol> &rule_symbols,
                              const std::string_view current_namespace,
                              const std::vector<rule_engine::ParsedPattern> &rule_patterns,
                              std::vector<rule_engine::RequiredFact> &facts,
                              std::vector<std::string> &rule_dependencies,
                              rule_engine::ErrorSet &errors,
                              std::string_view source,
                              const std::vector<std::string> &local_names = {},
                              const bool for_of_body = false) {
        if (expr.kind == rule_engine::ExpressionKind::unsupported) {
            errors.diagnostics.push_back(rule_engine::Diagnostic {
                .source = diagnostic_source(expr.span, source),
                .span = expr.span,
                .message = expr.text.empty() ? std::string {"unsupported YARA expression"}
                                             : "unsupported YARA expression " + expr.text,
            });
            return;
        }

        if (expr.kind == rule_engine::ExpressionKind::for_of_expr) {
            const auto quantifier_children = (expr.text == "expr" || expr.text == "percentage") ? 1u : 0u;
            if (expr.children.size() != quantifier_children + 1u) {
                errors.diagnostics.push_back(rule_engine::Diagnostic {
                    .source = diagnostic_source(expr.span, source),
                    .span = expr.span,
                    .message = "invalid for-of expression shape",
                });
                return;
            }

            if (quantifier_children == 1u) {
                collect_requirements(expr.children[0],
                                     registry,
                                     rule_symbols,
                                     current_namespace,
                                     rule_patterns,
                                     facts,
                                     rule_dependencies,
                                     errors,
                                     source,
                                     local_names,
                                     for_of_body);
            }

            std::vector<std::string> rule_pattern_names;
            rule_pattern_names.reserve(rule_patterns.size());
            for (const auto &pattern : rule_patterns) {
                rule_pattern_names.push_back(pattern.identifier);
            }
            expr.names = expand_pattern_names(expr.names, rule_pattern_names);
            for (const auto &name : expr.names) {
                add_fact(facts,
                         pattern_required_fact(name, ".pattern", rule_engine::ValueType::pattern, rule_patterns));
            }

            collect_requirements(expr.children[quantifier_children],
                                 registry,
                                 rule_symbols,
                                 current_namespace,
                                 rule_patterns,
                                 facts,
                                 rule_dependencies,
                                 errors,
                                 source,
                                 local_names,
                                 true);
            return;
        }

        if (expr.kind == rule_engine::ExpressionKind::for_in_expr) {
            const auto quantifier_children = (expr.text == "expr" || expr.text == "percentage") ? 1u : 0u;
            if (expr.children.size() != quantifier_children + 2u) {
                errors.diagnostics.push_back(rule_engine::Diagnostic {
                    .source = diagnostic_source(expr.span, source),
                    .span = expr.span,
                    .message = "invalid for-in expression shape",
                });
                return;
            }

            if (quantifier_children == 1u) {
                collect_requirements(expr.children[0],
                                     registry,
                                     rule_symbols,
                                     current_namespace,
                                     rule_patterns,
                                     facts,
                                     rule_dependencies,
                                     errors,
                                     source,
                                     local_names,
                                     for_of_body);
            }

            collect_requirements(expr.children[quantifier_children],
                                 registry,
                                 rule_symbols,
                                 current_namespace,
                                 rule_patterns,
                                 facts,
                                 rule_dependencies,
                                 errors,
                                 source,
                                 local_names,
                                 for_of_body);

            auto loop_locals = local_names;
            for (const auto &name : expr.names) {
                if (!contains_name(loop_locals, name)) {
                    loop_locals.push_back(name);
                }
            }
            collect_requirements(expr.children[quantifier_children + 1u],
                                 registry,
                                 rule_symbols,
                                 current_namespace,
                                 rule_patterns,
                                 facts,
                                 rule_dependencies,
                                 errors,
                                 source,
                                 loop_locals,
                                 for_of_body);
            return;
        }

        if (expr.kind == rule_engine::ExpressionKind::with_expr) {
            if (expr.children.size() != expr.names.size() + 1u) {
                errors.diagnostics.push_back(rule_engine::Diagnostic {
                    .source = diagnostic_source(expr.span, source),
                    .span = expr.span,
                    .message = "invalid with expression shape",
                });
                return;
            }

            auto with_locals = local_names;
            for (std::size_t index = 0; index < expr.names.size(); ++index) {
                collect_requirements(expr.children[index],
                                     registry,
                                     rule_symbols,
                                     current_namespace,
                                     rule_patterns,
                                     facts,
                                     rule_dependencies,
                                     errors,
                                     source,
                                     with_locals,
                                     for_of_body);
                if (!contains_name(with_locals, expr.names[index])) {
                    with_locals.push_back(expr.names[index]);
                }
            }

            collect_requirements(expr.children.back(),
                                 registry,
                                 rule_symbols,
                                 current_namespace,
                                 rule_patterns,
                                 facts,
                                 rule_dependencies,
                                 errors,
                                 source,
                                 with_locals,
                                 for_of_body);
            return;
        }

        if (expr.kind == rule_engine::ExpressionKind::function_call) {
            const auto key = join_names(expr.names);
            const auto *function = registry.find_function(key);
            if (function == nullptr) {
                errors.diagnostics.push_back(rule_engine::Diagnostic {
                    .source = diagnostic_source(expr.span, source),
                    .span = expr.span,
                    .message = "unknown function " + key,
                });
                return;
            }
            if (function->parameters.size() != expr.children.size()) {
                errors.diagnostics.push_back(rule_engine::Diagnostic {
                    .source = diagnostic_source(expr.span, source),
                    .span = expr.span,
                    .message = "function " + key + " expects " + std::to_string(function->parameters.size()) +
                               " argument(s)",
                });
                return;
            }

            expr.text = key;
            expr.bound_key_prefix = function->key_prefix.empty() ? key : function->key_prefix;
            expr.bound_route = function->route;
            expr.bound_ttl = function->ttl;
            expr.bound_timeout = function->timeout;
            expr.bound_cheap_prefetch = function->cheap_prefetch;
            expr.bound_return_type = function->return_type;

            for (auto &child : expr.children) {
                collect_requirements(child,
                                     registry,
                                     rule_symbols,
                                     current_namespace,
                                     rule_patterns,
                                     facts,
                                     rule_dependencies,
                                     errors,
                                     source,
                                     local_names,
                                     for_of_body);
            }
            validate_function_arguments(key, expr, *function, registry, errors, source, local_names);
            if (function->cheap_prefetch) {
                const auto arguments = static_function_arguments(expr);
                if (arguments.has_value()) {
                    add_fact(facts, rule_engine::RequiredFact {
                                        .key = rule_engine::provider_function_key(expr.bound_key_prefix, *arguments),
                                        .route = function->route,
                                        .ttl = function->ttl,
                                        .timeout = function->timeout,
                                        .cheap_prefetch = true,
                                        .type = function->return_type,
                                        .scan_plan = std::nullopt,
                                    });
                }
            }
            return;
        }

        if (expr.kind == rule_engine::ExpressionKind::field) {
            const auto key = join_names(expr.names);
            const auto *field = registry.find_field(key);
            if (field != nullptr) {
                add_fact(facts, rule_engine::RequiredFact {
                                    .key = field->key,
                                    .route = field->route,
                                    .ttl = field->ttl,
                                    .timeout = field->timeout,
                                    .cheap_prefetch = field->cheap_prefetch,
                                    .type = field->type,
                                    .scan_plan = std::nullopt,
                                });
                return;
            }

            if (const auto rule_reference = resolve_rule_reference(rule_symbols, current_namespace, expr.names);
                rule_reference.has_value()) {
                expr.kind = rule_engine::ExpressionKind::identifier;
                expr.text = *rule_reference;
                expr.names = {*rule_reference};
                if (!contains_name(rule_dependencies, *rule_reference)) {
                    rule_dependencies.push_back(*rule_reference);
                }
                return;
            }

            errors.diagnostics.push_back(rule_engine::Diagnostic {
                .source = diagnostic_source(expr.span, source),
                .span = expr.span,
                .message = "unknown field " + key,
            });
            return;
        }

        if (expr.kind == rule_engine::ExpressionKind::pattern_match && !expr.names.empty() &&
            !(for_of_body && is_pattern_placeholder(expr))) {
            add_fact(facts,
                     pattern_required_fact(expr.names[0], ".matches", rule_engine::ValueType::boolean, rule_patterns));
        }

        if ((expr.kind == rule_engine::ExpressionKind::pattern_count ||
             expr.kind == rule_engine::ExpressionKind::pattern_offset ||
             expr.kind == rule_engine::ExpressionKind::pattern_length) &&
            !expr.names.empty() && !(for_of_body && is_pattern_placeholder(expr))) {
            add_fact(facts,
                     pattern_required_fact(expr.names[0], ".pattern", rule_engine::ValueType::pattern, rule_patterns));
        }

        if (expr.kind == rule_engine::ExpressionKind::of_expr && !expr.names.empty()) {
            std::vector<std::string> rule_pattern_names;
            rule_pattern_names.reserve(rule_patterns.size());
            for (const auto &pattern : rule_patterns) {
                rule_pattern_names.push_back(pattern.identifier);
            }
            expr.names = expand_pattern_names(expr.names, rule_pattern_names);
            for (const auto &name : expr.names) {
                add_fact(facts,
                         pattern_required_fact(name, ".pattern", rule_engine::ValueType::pattern, rule_patterns));
            }
        }

        if (expr.kind == rule_engine::ExpressionKind::identifier) {
            const auto name = !expr.names.empty() ? std::string_view {expr.names[0]} : std::string_view {expr.text};
            if (contains_name(local_names, name)) {
                return;
            }
            if (const auto rule_reference = resolve_rule_reference(rule_symbols, current_namespace, name);
                rule_reference.has_value()) {
                expr.text = *rule_reference;
                expr.names = {*rule_reference};
                if (!contains_name(rule_dependencies, *rule_reference)) {
                    rule_dependencies.push_back(*rule_reference);
                }
            } else if (const auto *global = registry.find_global(name); global != nullptr) {
                expr.kind = rule_engine::ExpressionKind::global;
                expr.text = global->key;
                expr.names = {global->name};
                add_fact(facts, rule_engine::RequiredFact {
                                    .key = global->key,
                                    .route = global->route,
                                    .ttl = global->ttl,
                                    .timeout = global->timeout,
                                    .cheap_prefetch = global->cheap_prefetch,
                                    .type = global->type,
                                    .scan_plan = std::nullopt,
                                });
            } else {
                errors.diagnostics.push_back(rule_engine::Diagnostic {
                    .source = diagnostic_source(expr.span, source),
                    .span = expr.span,
                    .message = "unknown rule or global reference " + std::string {name},
                });
            }
        }

        for (auto &child : expr.children) {
            collect_requirements(
                child,
                registry,
                rule_symbols,
                current_namespace,
                rule_patterns,
                facts,
                rule_dependencies,
                errors,
                source,
                local_names,
                for_of_body);
        }
    }

    [[nodiscard]] std::optional<std::size_t> rule_index_by_name(const rule_engine::VerifiedProgram &program,
                                                                const std::string_view name) {
        const auto found = std::ranges::find_if(program.rules, [&](const auto &rule) {
            const auto rule_key = rule.qualified_identifier.empty() ? std::string_view {rule.identifier}
                                                                    : std::string_view {rule.qualified_identifier};
            return rule_key == name;
        });
        if (found == program.rules.end()) {
            return std::nullopt;
        }
        return static_cast<std::size_t>(std::distance(program.rules.begin(), found));
    }

    enum struct VisitState {
        unvisited,
        visiting,
        visited,
    };

    bool visit_rule_dependencies(const std::size_t index,
                                 const rule_engine::VerifiedProgram &program,
                                 std::vector<VisitState> &states,
                                 rule_engine::ErrorSet &errors,
                                 const std::string_view source) {
        if (states[index] == VisitState::visiting) {
            errors.diagnostics.push_back(rule_engine::Diagnostic {
                .source = std::string {source},
                .message = "rule reference cycle involving " + program.rules[index].qualified_identifier,
            });
            return false;
        }
        if (states[index] == VisitState::visited) {
            return true;
        }

        states[index] = VisitState::visiting;
        for (const auto &dependency : program.rules[index].rule_dependencies) {
            const auto dep_index = rule_index_by_name(program, dependency);
            if (!dep_index.has_value()) {
                continue;
            }
            if (!visit_rule_dependencies(*dep_index, program, states, errors, source)) {
                return false;
            }
        }
        states[index] = VisitState::visited;
        return true;
    }

    void propagate_dependency_facts(rule_engine::VerifiedProgram &program) {
        bool changed {true};
        while (changed) {
            changed = false;
            for (auto &rule : program.rules) {
                for (const auto &dependency : rule.rule_dependencies) {
                    const auto dep_index = rule_index_by_name(program, dependency);
                    if (!dep_index.has_value()) {
                        continue;
                    }
                    for (const auto &fact : program.rules[*dep_index].facts) {
                        const auto before = rule.facts.size();
                        add_fact(rule.facts, fact);
                        changed = changed || rule.facts.size() != before;
                    }
                }
            }
        }
    }

    [[nodiscard]] std::filesystem::path normalize_path(const std::filesystem::path &path) {
        std::error_code ec;
        auto absolute = std::filesystem::absolute(path, ec);
        if (ec) {
            absolute = path;
        }
        auto canonical = std::filesystem::weakly_canonical(absolute, ec);
        if (ec) {
            return absolute.lexically_normal();
        }
        return canonical;
    }

    [[nodiscard]] std::expected<std::string, rule_engine::ErrorSet> read_text_file(const std::filesystem::path &path) {
        std::ifstream file {path, std::ios::binary};
        if (!file) {
            return std::unexpected(rule_engine::single_error(path.string(), "failed to open source file"));
        }
        std::ostringstream buffer;
        buffer << file.rdbuf();
        if (file.bad()) {
            return std::unexpected(rule_engine::single_error(path.string(), "failed to read source file"));
        }
        return buffer.str();
    }

    void add_unique(std::vector<std::string> &values, std::string value) {
        if (contains_name(values, value)) {
            return;
        }
        values.push_back(std::move(value));
    }

    void append_magic(std::vector<std::byte> &out, const std::string_view value) {
        for (const auto byte : value) {
            out.push_back(static_cast<std::byte>(static_cast<unsigned char>(byte)));
        }
    }

    void append_u8(std::vector<std::byte> &out, const std::uint8_t value) {
        out.push_back(static_cast<std::byte>(value));
    }

    void append_u32(std::vector<std::byte> &out, const std::uint32_t value) {
        out.push_back(static_cast<std::byte>(value & 0xffu));
        out.push_back(static_cast<std::byte>((value >> 8u) & 0xffu));
        out.push_back(static_cast<std::byte>((value >> 16u) & 0xffu));
        out.push_back(static_cast<std::byte>((value >> 24u) & 0xffu));
    }

    void append_string(std::vector<std::byte> &out, const std::string_view value) {
        append_u32(out, static_cast<std::uint32_t>(value.size()));
        for (const auto byte : value) {
            out.push_back(static_cast<std::byte>(static_cast<unsigned char>(byte)));
        }
    }

    void merge_ruleset(rule_engine::ParsedRuleSet &target, rule_engine::ParsedRuleSet source) {
        for (auto &source_name : source.sources) {
            add_unique(target.sources, std::move(source_name));
        }
        for (auto &import_name : source.imports) {
            add_unique(target.imports, std::move(import_name));
        }
        for (auto &include_name : source.includes) {
            add_unique(target.includes, std::move(include_name));
        }
        for (auto &rule : source.rules) {
            target.rules.push_back(std::move(rule));
        }
    }

    [[nodiscard]] std::expected<rule_engine::ParsedRuleSet, rule_engine::ErrorSet>
    parse_source_with_id(const std::string_view source_name,
                         const std::string_view source,
                         const std::uint32_t source_id,
                         const std::string_view namespace_name) {
        OwnedBridgeParse owned {bridge::re_yara_bridge_parse(reinterpret_cast<const std::uint8_t *>(source.data()),
                                                             source.size())};
        if (owned.result.rules == nullptr) {
            return std::unexpected(rule_engine::single_error(std::string {source_name},
                                                             "YARA bridge returned a null parse handle"));
        }

        if (bridge::re_yara_bridge_version(owned.result.rules) != 1u) {
            return std::unexpected(rule_engine::single_error(std::string {source_name},
                                                             "unsupported YARA bridge ABI version"));
        }

        rule_engine::ErrorSet errors;
        const auto diagnostic_count = bridge::re_yara_bridge_diagnostic_count(owned.result.rules);
        for (std::size_t index = 0; index < diagnostic_count; ++index) {
            errors.diagnostics.push_back(
                bridge_diagnostic(bridge::re_yara_bridge_diagnostic_at(owned.result.rules, index),
                                  source_name,
                                  source_id));
        }
        if (owned.result.status != bridge::ReParseStatus::Ok && errors.empty()) {
            errors.diagnostics.push_back(rule_engine::Diagnostic {
                .source = std::string {source_name},
                .message = "YARA bridge parse failed without diagnostics",
            });
        }
        if (!errors.empty()) {
            return std::unexpected(std::move(errors));
        }

        const auto normalized_namespace = normalize_namespace_name(namespace_name);
        rule_engine::ParsedRuleSet out;
        out.source_name = std::string {source_name};
        out.sources.push_back(std::string {source_name});
        const auto import_count = bridge::re_yara_bridge_import_count(owned.result.rules);
        for (std::size_t index = 0; index < import_count; ++index) {
            out.imports.push_back(to_string(bridge::re_yara_bridge_import_at(owned.result.rules, index)));
        }
        const auto include_count = bridge::re_yara_bridge_include_count(owned.result.rules);
        for (std::size_t index = 0; index < include_count; ++index) {
            out.includes.push_back(to_string(bridge::re_yara_bridge_include_at(owned.result.rules, index)));
        }
        const auto rule_count = bridge::re_yara_bridge_rule_count(owned.result.rules);
        for (std::size_t index = 0; index < rule_count; ++index) {
            auto parsed_rule =
                bridge_rule(owned.result.rules,
                            bridge::re_yara_bridge_rule_at(owned.result.rules, index),
                            source_name,
                            source_id);
            parsed_rule.namespace_name = normalized_namespace;
            parsed_rule.qualified_identifier =
                qualified_rule_identifier(parsed_rule.namespace_name, parsed_rule.identifier);
            out.rules.push_back(std::move(parsed_rule));
        }
        return out;
    }

    struct IncludeResolver {
        const rule_engine::ParseOptions &options;
        std::vector<std::filesystem::path> stack;
        std::vector<std::filesystem::path> parsed_files;
        rule_engine::ParsedRuleSet merged;
        rule_engine::ErrorSet errors;

        explicit IncludeResolver(const rule_engine::ParseOptions &value) noexcept: options {value} {}

        [[nodiscard]] bool parse_root(const std::filesystem::path &path) {
            const auto normalized = normalize_path(path);
            merged.source_name = normalized.string();
            static_cast<void>(source_id_for_path(normalized));
            return parse_path(path);
        }

        [[nodiscard]] bool parse_path(const std::filesystem::path &path) {
            const auto normalized = normalize_path(path);
            const auto source_id = source_id_for_path(normalized);
            if (std::ranges::contains(stack, normalized)) {
                errors.diagnostics.push_back(rule_engine::Diagnostic {
                    .source = normalized.string(),
                    .message = "include cycle involving " + normalized.string(),
                });
                return false;
            }
            if (std::ranges::contains(parsed_files, normalized)) {
                return true;
            }

            auto source = read_text_file(normalized);
            if (!source) {
                append_errors(source.error());
                return false;
            }

            stack.push_back(normalized);
            auto parsed = parse_source_with_id(normalized.string(), *source, source_id, options.namespace_name);
            if (!parsed) {
                append_errors(parsed.error());
                stack.pop_back();
                return false;
            }

            bool ok {true};
            for (const auto &include_name : parsed->includes) {
                auto include_path = resolve_include(include_name, normalized.parent_path());
                if (!include_path) {
                    errors.diagnostics.push_back(rule_engine::Diagnostic {
                        .source = normalized.string(),
                        .message = "failed to resolve include " + include_name,
                    });
                    ok = false;
                    continue;
                }
                ok = parse_path(*include_path) && ok;
            }
            stack.pop_back();
            if (!ok) {
                return false;
            }

            parsed_files.push_back(normalized);
            merge_ruleset(merged, std::move(*parsed));
            return true;
        }

        [[nodiscard]] std::uint32_t source_id_for_path(const std::filesystem::path &path) {
            const auto source_name = path.string();
            const auto found = std::ranges::find(merged.sources, source_name);
            if (found != merged.sources.end()) {
                return static_cast<std::uint32_t>(std::distance(merged.sources.begin(), found) + 1);
            }

            merged.sources.push_back(source_name);
            return static_cast<std::uint32_t>(merged.sources.size());
        }

        [[nodiscard]] std::optional<std::filesystem::path> resolve_include(const std::string_view include_name,
                                                                           const std::filesystem::path &parent_dir) const {
            const std::filesystem::path include_path {include_name};
            if (include_path.is_absolute() && exists_file(include_path)) {
                return include_path;
            }

            const auto sibling = parent_dir / include_path;
            if (exists_file(sibling)) {
                return sibling;
            }

            for (const auto &dir : options.include_dirs) {
                const auto candidate = dir / include_path;
                if (exists_file(candidate)) {
                    return candidate;
                }
            }
            return std::nullopt;
        }

        [[nodiscard]] static bool exists_file(const std::filesystem::path &path) {
            std::error_code ec;
            return std::filesystem::is_regular_file(path, ec) && !ec;
        }

        void append_errors(const rule_engine::ErrorSet &source) {
            for (const auto &diagnostic : source.diagnostics) {
                errors.diagnostics.push_back(diagnostic);
            }
        }
    };
} // namespace

namespace rule_engine {
    std::expected<ParsedRuleSet, ErrorSet> parse_source(const std::string_view source_name, const std::string_view source) {
        return parse_source_with_id(source_name, source, 1u, "default");
    }

    std::expected<ParsedRuleSet, ErrorSet> parse_sources(const std::span<const SourceUnit> sources) {
        ParsedRuleSet merged;
        ErrorSet errors;
        for (std::size_t index = 0; index < sources.size(); ++index) {
            const auto &source_unit = sources[index];
            if (source_unit.source_name.empty()) {
                errors.diagnostics.push_back(Diagnostic {
                    .source = {},
                    .message = "source unit is missing a source name",
                });
                continue;
            }

            if (merged.source_name.empty()) {
                merged.source_name = source_unit.source_name;
            }

            const auto source_id = static_cast<std::uint32_t>(index + 1u);
            auto parsed = parse_source_with_id(source_unit.source_name,
                                               source_unit.source,
                                               source_id,
                                               source_unit.namespace_name);
            if (!parsed) {
                for (const auto &diagnostic : parsed.error().diagnostics) {
                    errors.diagnostics.push_back(diagnostic);
                }
                continue;
            }

            merge_ruleset(merged, std::move(*parsed));
        }

        if (!errors.empty()) {
            return std::unexpected(std::move(errors));
        }
        return merged;
    }

    std::expected<ParsedRuleSet, ErrorSet> parse_file(const std::filesystem::path &path, const ParseOptions &options) {
        IncludeResolver resolver {options};
        if (!resolver.parse_root(path)) {
            return std::unexpected(std::move(resolver.errors));
        }
        return std::move(resolver.merged);
    }

    std::expected<VerifiedProgram, ErrorSet> verify(const ParsedRuleSet &rules, const ModuleRegistry &registry) {
        ErrorSet errors;
        for (const auto &import_name : rules.imports) {
            if (registry.find_module(import_name) == nullptr) {
                errors.diagnostics.push_back(Diagnostic {
                    .source = rules.source_name,
                    .message = "unknown module import " + import_name,
                });
            }
        }

        std::vector<RuleSymbol> rule_symbols;
        for (const auto &rule : rules.rules) {
            const auto qualified_identifier = rule.qualified_identifier.empty()
                                                  ? qualified_rule_identifier(rule.namespace_name, rule.identifier)
                                                  : rule.qualified_identifier;
            if (contains_rule_symbol(rule_symbols, qualified_identifier)) {
                errors.diagnostics.push_back(Diagnostic {
                    .source = diagnostic_source(rule.span, rules.source_name),
                    .span = rule.span,
                    .message = "duplicate rule " + qualified_identifier,
                });
                continue;
            }
            rule_symbols.push_back(RuleSymbol {
                .namespace_name = normalize_namespace_name(rule.namespace_name),
                .identifier = rule.identifier,
                .qualified_identifier = qualified_identifier,
            });
        }

        VerifiedProgram program;
        program.sources = rules.sources;
        if (program.sources.empty() && !rules.source_name.empty()) {
            program.sources.push_back(rules.source_name);
        }
        for (const auto &rule : rules.rules) {
            VerifiedRule verified;
            verified.identifier = rule.identifier;
            verified.namespace_name = normalize_namespace_name(rule.namespace_name);
            verified.qualified_identifier = rule.qualified_identifier.empty()
                                                ? qualified_rule_identifier(verified.namespace_name, rule.identifier)
                                                : rule.qualified_identifier;
            verified.is_private = rule.is_private;
            verified.is_global = rule.is_global;
            verified.span = rule.span;
            verified.condition = rule.condition;
            collect_requirements(verified.condition,
                                 registry,
                                 rule_symbols,
                                 verified.namespace_name,
                                 rule.patterns,
                                 verified.facts,
                                 verified.rule_dependencies,
                                 errors,
                                 rules.source_name);
            program.rules.push_back(std::move(verified));
        }

        for (const auto &rule : program.rules) {
            if (!rule.is_global) {
                continue;
            }
            for (const auto &dependency : rule.rule_dependencies) {
                const auto dep_index = rule_index_by_name(program, dependency);
                if (!dep_index.has_value() || program.rules[*dep_index].is_global) {
                    continue;
                }
                errors.diagnostics.push_back(Diagnostic {
                    .source = rules.source_name,
                    .message = "global rule " + rule.qualified_identifier + " depends on non-global rule " + dependency,
                });
            }
        }

        std::vector<VisitState> states(program.rules.size(), VisitState::unvisited);
        for (std::size_t index = 0; index < program.rules.size(); ++index) {
            if (states[index] == VisitState::unvisited) {
                static_cast<void>(visit_rule_dependencies(index, program, states, errors, rules.source_name));
            }
        }

        if (!errors.empty()) {
            return std::unexpected(std::move(errors));
        }
        propagate_dependency_facts(program);
        return program;
    }

    std::vector<std::string> required_provider_routes(const VerifiedProgram &program) {
        std::vector<std::string> routes;
        for (const auto &rule : program.rules) {
            for (const auto &fact : rule.facts) {
                add_route(routes, fact.route);
            }
            collect_expression_routes(rule.condition, routes);
        }
        std::ranges::sort(routes);
        return routes;
    }

    std::string VerifiedProgram::ir_dump() const {
        std::ostringstream out;
        out << "rule_engine_ir version=2\n";
        for (std::size_t index = 0; index < sources.size(); ++index) {
            out << "source id=" << (index + 1u) << " name=" << sources[index] << '\n';
        }
        for (const auto &rule : rules) {
            out << "rule " << rule.qualified_identifier << " namespace=" << rule.namespace_name
                << " source_id=" << rule.span.source_id << " facts=" << rule.facts.size() << '\n';
        }
        return out.str();
    }

    std::vector<std::byte> VerifiedProgram::ir_artifact() const {
        std::vector<std::byte> out;
        append_magic(out, "REIR");
        append_u32(out, 2u);
        append_u32(out, static_cast<std::uint32_t>(sources.size()));
        for (const auto &source : sources) {
            append_string(out, source);
        }
        append_u32(out, static_cast<std::uint32_t>(rules.size()));
        for (const auto &rule : rules) {
            append_string(out, rule.identifier);
            append_string(out, rule.namespace_name);
            append_string(out, rule.qualified_identifier);
            append_u32(out, rule.span.source_id);
            append_u8(out, rule.is_private ? 1u : 0u);
            append_u8(out, rule.is_global ? 1u : 0u);
            append_u32(out, static_cast<std::uint32_t>(rule.facts.size()));
            for (const auto &fact : rule.facts) {
                append_string(out, fact.key);
                append_string(out, fact.route);
                append_u32(out, static_cast<std::uint32_t>(fact.ttl.count()));
                append_u32(out, static_cast<std::uint32_t>(fact.timeout.count()));
                append_u8(out, fact.cheap_prefetch ? 1u : 0u);
            }
        }
        return out;
    }

    std::string VerifiedProgram::schedule_plan_dump() const {
        std::ostringstream out;
        out << "schedule version=2\n";
        for (const auto &rule : rules) {
            for (const auto &fact : rule.facts) {
                out << rule.qualified_identifier << " namespace=" << rule.namespace_name
                    << " source_id=" << rule.span.source_id << " -> " << fact.route << " :: " << fact.key
                    << " ttl=" << fact.ttl.count() << "s timeout=" << fact.timeout.count()
                    << "s cheap=" << (fact.cheap_prefetch ? "true" : "false") << '\n';
            }
        }
        return out.str();
    }

    std::vector<std::byte> VerifiedProgram::schedule_plan_artifact() const {
        std::vector<std::byte> out;
        append_magic(out, "RESC");
        append_u32(out, 2u);
        std::uint32_t edge_count {};
        for (const auto &rule : rules) {
            edge_count += static_cast<std::uint32_t>(rule.facts.size());
        }
        append_u32(out, edge_count);
        for (const auto &rule : rules) {
            for (const auto &fact : rule.facts) {
                append_string(out, rule.identifier);
                append_string(out, rule.namespace_name);
                append_string(out, rule.qualified_identifier);
                append_u32(out, rule.span.source_id);
                append_string(out, fact.route);
                append_string(out, fact.key);
                append_u32(out, static_cast<std::uint32_t>(fact.ttl.count()));
                append_u32(out, static_cast<std::uint32_t>(fact.timeout.count()));
                append_u8(out, fact.cheap_prefetch ? 1u : 0u);
            }
        }
        return out;
    }
} // namespace rule_engine
