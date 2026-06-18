#include <rule_engine/evaluator.hpp>
#include <rule_engine/provider_key.hpp>

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {
    enum struct EvalStatus {
        value,
        missing,
        diagnostic,
    };

    struct EvalValue {
        EvalStatus status {EvalStatus::value};
        rule_engine::Value value;
        std::string missing_key;
        std::optional<rule_engine::RequiredFact> missing_fact;
        rule_engine::Diagnostic diagnostic;
    };

    struct LocalBinding {
        std::string name;
        rule_engine::Value value;
    };

    [[nodiscard]] EvalValue value_result(rule_engine::Value value) {
        EvalValue out;
        out.value = std::move(value);
        return out;
    }

    [[nodiscard]] EvalValue bool_result(const bool value) { return value_result(rule_engine::Value::boolean(value)); }

    [[nodiscard]] EvalValue missing_result(std::string key) {
        EvalValue out;
        out.status = EvalStatus::missing;
        out.missing_key = std::move(key);
        return out;
    }

    [[nodiscard]] EvalValue missing_result(rule_engine::RequiredFact fact) {
        EvalValue out;
        out.status = EvalStatus::missing;
        out.missing_key = fact.key;
        out.missing_fact = std::move(fact);
        return out;
    }

    [[nodiscard]] EvalValue diagnostic_result(std::string message) {
        EvalValue out;
        out.status = EvalStatus::diagnostic;
        out.value = rule_engine::Value::undefined();
        out.diagnostic.message = std::move(message);
        return out;
    }

    [[nodiscard]] EvalValue undefined_result() { return value_result(rule_engine::Value::undefined()); }

    constexpr std::string_view process_image_bytes_key {"process.image.bytes"};
    constexpr std::string_view scan_pattern_route {"endpoint.scan.patterns"};

    struct IntegerReaderSpec {
        std::size_t width {};
        bool signed_value {};
        bool big_endian {};
    };

    [[nodiscard]] std::optional<IntegerReaderSpec> integer_reader_spec(const std::string_view name) noexcept {
        if (name == "uint8") {
            return IntegerReaderSpec {.width = 1u, .signed_value = false, .big_endian = false};
        }
        if (name == "int8") {
            return IntegerReaderSpec {.width = 1u, .signed_value = true, .big_endian = false};
        }
        if (name == "uint16" || name == "uint16le") {
            return IntegerReaderSpec {.width = 2u, .signed_value = false, .big_endian = false};
        }
        if (name == "int16" || name == "int16le") {
            return IntegerReaderSpec {.width = 2u, .signed_value = true, .big_endian = false};
        }
        if (name == "uint32" || name == "uint32le") {
            return IntegerReaderSpec {.width = 4u, .signed_value = false, .big_endian = false};
        }
        if (name == "int32" || name == "int32le") {
            return IntegerReaderSpec {.width = 4u, .signed_value = true, .big_endian = false};
        }
        if (name == "uint16be") {
            return IntegerReaderSpec {.width = 2u, .signed_value = false, .big_endian = true};
        }
        if (name == "int16be") {
            return IntegerReaderSpec {.width = 2u, .signed_value = true, .big_endian = true};
        }
        if (name == "uint32be") {
            return IntegerReaderSpec {.width = 4u, .signed_value = false, .big_endian = true};
        }
        if (name == "int32be") {
            return IntegerReaderSpec {.width = 4u, .signed_value = true, .big_endian = true};
        }
        return std::nullopt;
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

    [[nodiscard]] bool value_matches_type(const rule_engine::Value &value, const rule_engine::ValueType type) {
        switch (type) {
            case rule_engine::ValueType::boolean: return value.as_bool().has_value();
            case rule_engine::ValueType::integer: return value.as_i64().has_value();
            case rule_engine::ValueType::floating: return value.as_f64().has_value();
            case rule_engine::ValueType::string: return value.as_string() != nullptr;
            case rule_engine::ValueType::bytes: return value.as_bytes() != nullptr;
            case rule_engine::ValueType::array: return value.as_array() != nullptr;
            case rule_engine::ValueType::pattern: return value.as_pattern() != nullptr;
            case rule_engine::ValueType::object: return value.as_object() != nullptr;
            case rule_engine::ValueType::undefined: return true;
            default: return false;
        }
    }

    [[nodiscard]] std::optional<EvalValue> type_mismatch_result(const std::string_view key,
                                                                const rule_engine::Value &value,
                                                                const rule_engine::ValueType expected_type) {
        if (expected_type == rule_engine::ValueType::undefined || value_matches_type(value, expected_type)) {
            return std::nullopt;
        }
        return diagnostic_result("cached fact " + std::string {key} + " has wrong type; expected " +
                                 value_type_name(expected_type));
    }

    [[nodiscard]] EvalValue numeric_quantifier_result(const std::int64_t matched, const std::int64_t threshold) {
        if (threshold == 0) {
            return bool_result(matched == 0);
        }
        if (threshold < 0) {
            return bool_result(false);
        }
        return bool_result(matched >= threshold);
    }

    struct NumericValue {
        bool floating {};
        std::int64_t integer {};
        double number {};
    };

    [[nodiscard]] std::optional<NumericValue> numeric_value(const rule_engine::Value &value) noexcept {
        if (const auto integer = value.as_i64(); integer.has_value()) {
            return NumericValue {.floating = false, .integer = *integer, .number = static_cast<double>(*integer)};
        }
        if (const auto number = value.as_f64(); number.has_value()) {
            return NumericValue {.floating = true, .integer = {}, .number = *number};
        }
        return std::nullopt;
    }

    [[nodiscard]] bool values_equal(const rule_engine::Value &lhs, const rule_engine::Value &rhs) {
        if (const auto lb = lhs.as_bool(); lb.has_value()) {
            const auto rb = rhs.as_bool();
            return rb.has_value() && *lb == *rb;
        }
        const auto ln = numeric_value(lhs);
        const auto rn = numeric_value(rhs);
        if (ln.has_value() && rn.has_value()) {
            if (ln->floating || rn->floating) {
                return !std::isunordered(ln->number, rn->number) && !std::islessgreater(ln->number, rn->number);
            }
            return ln->integer == rn->integer;
        }
        const auto *ls = lhs.as_string();
        const auto *rs = rhs.as_string();
        return ls != nullptr && rs != nullptr && *ls == *rs;
    }

    [[nodiscard]] char ascii_lower(const char value) noexcept {
        if (value >= 'A' && value <= 'Z') {
            return static_cast<char>(value - 'A' + 'a');
        }
        return value;
    }

    [[nodiscard]] std::string ascii_lower_copy(const std::string_view value) {
        std::string out;
        out.reserve(value.size());
        for (const auto c : value) { out.push_back(ascii_lower(c)); }
        return out;
    }

    [[nodiscard]] bool string_contains(const std::string &lhs, const std::string &rhs, const bool case_insensitive) {
        if (!case_insensitive) {
            return lhs.find(rhs) != std::string::npos;
        }
        const auto folded_lhs = ascii_lower_copy(lhs);
        const auto folded_rhs = ascii_lower_copy(rhs);
        return folded_lhs.find(folded_rhs) != std::string::npos;
    }

    [[nodiscard]] bool string_starts_with(const std::string &lhs, const std::string &rhs, const bool case_insensitive) {
        if (!case_insensitive) {
            return lhs.starts_with(rhs);
        }
        const auto folded_lhs = ascii_lower_copy(lhs);
        const auto folded_rhs = ascii_lower_copy(rhs);
        return folded_lhs.starts_with(folded_rhs);
    }

    [[nodiscard]] bool string_ends_with(const std::string &lhs, const std::string &rhs, const bool case_insensitive) {
        if (!case_insensitive) {
            return lhs.ends_with(rhs);
        }
        const auto folded_lhs = ascii_lower_copy(lhs);
        const auto folded_rhs = ascii_lower_copy(rhs);
        return folded_lhs.ends_with(folded_rhs);
    }

    [[nodiscard]] bool string_iequals(const std::string &lhs, const std::string &rhs) {
        return ascii_lower_copy(lhs) == ascii_lower_copy(rhs);
    }

    [[nodiscard]] std::optional<std::int64_t> checked_add(const std::int64_t lhs, const std::int64_t rhs) noexcept {
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

    [[nodiscard]] std::optional<std::int64_t> checked_divide(const std::int64_t lhs, const std::int64_t rhs) noexcept {
        if (rhs == 0) {
            return std::nullopt;
        }
        if (lhs == std::numeric_limits<std::int64_t>::min() && rhs == -1) {
            return std::nullopt;
        }
        return lhs / rhs;
    }

    [[nodiscard]] std::optional<std::int64_t> checked_modulo(const std::int64_t lhs, const std::int64_t rhs) noexcept {
        if (rhs == 0) {
            return std::nullopt;
        }
        if (lhs == std::numeric_limits<std::int64_t>::min() && rhs == -1) {
            return std::nullopt;
        }
        return lhs % rhs;
    }

    [[nodiscard]] std::optional<std::int64_t> to_i64(const std::uint64_t value) noexcept {
        if (value > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
            return std::nullopt;
        }
        return static_cast<std::int64_t>(value);
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

    [[nodiscard]] std::string pattern_metadata_key(const rule_engine::Expression &expr,
                                                   const std::string_view current_pattern = {}) {
        auto name = expr.names.empty() ? std::string {expr.text} : expr.names[0];
        if (name == "$" && !current_pattern.empty()) {
            name = std::string {current_pattern};
        }
        auto key = pattern_identifier_key(std::move(name));
        key += ".pattern";
        return key;
    }

    [[nodiscard]] std::string pattern_fact_key(const std::string &name) {
        auto key = pattern_identifier_key(name);
        key += ".pattern";
        return key;
    }

    [[nodiscard]] std::string cache_index_key(const std::string_view subject_id, const std::string_view fact_key) {
        std::string out;
        out.reserve(subject_id.size() + fact_key.size() + 1u);
        out.append(subject_id);
        out.push_back('\0');
        out.append(fact_key);
        return out;
    }

    struct EvalContext {
        const rule_engine::VerifiedProgram &program;
        const rule_engine::Subject &subject;
        const rule_engine::FactCache &facts;
        std::vector<std::optional<EvalValue>> &memo;
        std::vector<bool> &active;
        std::vector<LocalBinding> locals;
        std::vector<std::string> current_patterns;
        std::vector<rule_engine::ExpressionTraceEvent> *expression_traces {};
        rule_engine::EvaluationInstrumentation *instrumentation {};
        std::string current_rule_identifier;
        std::optional<std::size_t> current_rule_index;
    };

    [[nodiscard]] std::optional<rule_engine::RequiredFact> find_required_fact(const rule_engine::VerifiedRule &rule,
                                                                              const std::string_view key) {
        const auto found = std::ranges::find_if(rule.facts, [&](const auto &fact) { return fact.key == key; });
        if (found == rule.facts.end()) {
            return std::nullopt;
        }
        return *found;
    }

    [[nodiscard]] std::optional<rule_engine::ValueType> expected_type_for_key(const EvalContext &ctx,
                                                                              const std::string_view key) {
        if (!ctx.current_rule_index.has_value() || *ctx.current_rule_index >= ctx.program.rules.size()) {
            return std::nullopt;
        }
        const auto fact = find_required_fact(ctx.program.rules[*ctx.current_rule_index], key);
        if (!fact.has_value()) {
            return std::nullopt;
        }
        return fact->type;
    }

    [[nodiscard]] std::optional<EvalValue> cached_fact_type_mismatch(const EvalContext &ctx, const std::string_view key,
                                                                     const rule_engine::Value &value) {
        const auto expected_type = expected_type_for_key(ctx, key);
        if (!expected_type.has_value()) {
            return std::nullopt;
        }
        return type_mismatch_result(key, value, *expected_type);
    }

    [[nodiscard]] const rule_engine::Value *find_local(const EvalContext &ctx, const std::string_view name) {
        for (auto binding = ctx.locals.rbegin(); binding != ctx.locals.rend(); ++binding) {
            if (binding->name == name) {
                return &binding->value;
            }
        }
        return nullptr;
    }

    [[nodiscard]] std::string_view current_pattern(const EvalContext &ctx) {
        if (ctx.current_patterns.empty()) {
            return {};
        }
        return ctx.current_patterns.back();
    }

    [[nodiscard]] std::optional<std::size_t> rule_index_by_name(const rule_engine::VerifiedProgram &program,
                                                                const std::string_view name) {
        const auto found = std::ranges::find_if(program.rules, [&](const auto &rule) {
            const auto rule_key = rule.qualified_identifier.empty() ? std::string_view {rule.identifier} :
                                                                      std::string_view {rule.qualified_identifier};
            return rule_key == name;
        });
        if (found == program.rules.end()) {
            return std::nullopt;
        }
        return static_cast<std::size_t>(std::distance(program.rules.begin(), found));
    }

    [[nodiscard]] rule_engine::ExpressionTraceStatus trace_status(const EvalValue &value) noexcept {
        if (value.status == EvalStatus::missing) {
            return rule_engine::ExpressionTraceStatus::missing;
        }
        if (value.status == EvalStatus::diagnostic) {
            return rule_engine::ExpressionTraceStatus::diagnostic;
        }
        return rule_engine::ExpressionTraceStatus::value;
    }

    [[nodiscard]] std::string value_summary(const rule_engine::Value &value) {
        if (value.is_undefined()) {
            return "undefined";
        }
        if (const auto boolean = value.as_bool(); boolean.has_value()) {
            return *boolean ? "bool:true" : "bool:false";
        }
        if (const auto integer = value.as_i64(); integer.has_value()) {
            return "int:" + std::to_string(*integer);
        }
        if (const auto floating = value.as_f64(); floating.has_value()) {
            std::ostringstream out;
            out << "float:" << *floating;
            return out.str();
        }
        if (const auto *string = value.as_string(); string != nullptr) {
            return "string:" + *string;
        }
        if (const auto *pattern = value.as_pattern(); pattern != nullptr) {
            return "pattern:" + std::string {pattern->matched ? "true" : "false"} + ":" +
                   std::to_string(pattern->matches.size());
        }
        if (const auto *array = value.as_array(); array != nullptr) {
            return "array:" + std::to_string(array->values.size());
        }
        if (const auto *object = value.as_object(); object != nullptr) {
            return "object:" + std::to_string(object->entries.size());
        }
        return "unknown";
    }

    [[nodiscard]] std::string trace_summary(const EvalValue &value) {
        if (value.status == EvalStatus::missing) {
            return "missing:" + value.missing_key;
        }
        if (value.status == EvalStatus::diagnostic) {
            return "diagnostic:" + value.diagnostic.message;
        }
        return value_summary(value.value);
    }

    [[nodiscard]] std::string trace_detail(const EvalValue &value) {
        if (value.status == EvalStatus::missing) {
            return value.missing_key;
        }
        if (value.status == EvalStatus::diagnostic) {
            return value.diagnostic.message;
        }
        return {};
    }

    [[nodiscard]] std::string expression_trace_text(const rule_engine::Expression &expr) {
        if (!expr.text.empty()) {
            return expr.text;
        }
        if (expr.names.empty()) {
            return {};
        }
        std::string out;
        for (const auto &name : expr.names) {
            if (!out.empty()) {
                out.push_back('.');
            }
            out += name;
        }
        return out;
    }

    void insert_expression_trace(EvalContext &ctx, const std::size_t index, const rule_engine::Expression &expr,
                                 const EvalValue &value) {
        if (ctx.expression_traces == nullptr) {
            return;
        }
        rule_engine::ExpressionTraceEvent event;
        event.rule_identifier = ctx.current_rule_identifier;
        event.expression_kind = expr.kind;
        event.span = expr.span;
        event.text = expression_trace_text(expr);
        event.status = trace_status(value);
        event.value_summary = trace_summary(value);
        event.detail = trace_detail(value);
        ctx.expression_traces->insert(ctx.expression_traces->begin() + static_cast<std::ptrdiff_t>(index),
                                      std::move(event));
    }

    [[nodiscard]] EvalValue eval_expr(const rule_engine::Expression &expr, EvalContext &ctx);
    [[nodiscard]] EvalValue eval_expr_impl(const rule_engine::Expression &expr, EvalContext &ctx);

    [[nodiscard]] EvalValue eval_arithmetic(const rule_engine::Expression &expr, EvalContext &ctx) {
        using enum rule_engine::ExpressionKind;
        if (expr.children.empty()) {
            return undefined_result();
        }

        auto first = eval_expr(expr.children[0], ctx);
        if (first.status != EvalStatus::value) {
            return first;
        }
        auto accumulator = numeric_value(first.value);
        if (!accumulator.has_value()) {
            return undefined_result();
        }

        if (expr.kind == negate) {
            if (expr.children.size() != 1u) {
                return undefined_result();
            }
            if (accumulator->floating) {
                return value_result(rule_engine::Value::number(-accumulator->number));
            }
            if (accumulator->integer == std::numeric_limits<std::int64_t>::min()) {
                return undefined_result();
            }
            return value_result(rule_engine::Value::integer(-accumulator->integer));
        }

        auto floating = accumulator->floating;
        auto number = accumulator->number;
        auto integer = accumulator->integer;

        for (std::size_t index = 1; index < expr.children.size(); ++index) {
            auto value = eval_expr(expr.children[index], ctx);
            if (value.status != EvalStatus::value) {
                return value;
            }

            const auto operand = numeric_value(value.value);
            if (!operand.has_value()) {
                return undefined_result();
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
                        return undefined_result();
                    }
                    number /= operand->number;
                } else {
                    return undefined_result();
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
                return undefined_result();
            }
            integer = *next;
            number = static_cast<double>(integer);
        }

        if (floating) {
            return value_result(rule_engine::Value::number(number));
        }
        return value_result(rule_engine::Value::integer(integer));
    }

    [[nodiscard]] EvalValue eval_bitwise(const rule_engine::Expression &expr, EvalContext &ctx) {
        using enum rule_engine::ExpressionKind;
        if (expr.children.empty()) {
            return undefined_result();
        }

        auto lhs = eval_expr(expr.children[0], ctx);
        if (lhs.status != EvalStatus::value) {
            return lhs;
        }
        const auto left = lhs.value.as_i64();
        if (!left.has_value()) {
            return undefined_result();
        }

        if (expr.kind == bitwise_not) {
            if (expr.children.size() != 1u) {
                return undefined_result();
            }
            return value_result(
                rule_engine::Value::integer(static_cast<std::int64_t>(~static_cast<std::uint64_t>(*left))));
        }

        if (expr.children.size() != 2u) {
            return undefined_result();
        }

        auto rhs = eval_expr(expr.children[1], ctx);
        if (rhs.status != EvalStatus::value) {
            return rhs;
        }
        const auto right = rhs.value.as_i64();
        if (!right.has_value()) {
            return undefined_result();
        }

        const auto left_bits = static_cast<std::uint64_t>(*left);
        const auto right_bits = static_cast<std::uint64_t>(*right);
        if (expr.kind == bitwise_and) {
            return value_result(rule_engine::Value::integer(static_cast<std::int64_t>(left_bits & right_bits)));
        }
        if (expr.kind == bitwise_or) {
            return value_result(rule_engine::Value::integer(static_cast<std::int64_t>(left_bits | right_bits)));
        }
        if (expr.kind == bitwise_xor) {
            return value_result(rule_engine::Value::integer(static_cast<std::int64_t>(left_bits ^ right_bits)));
        }
        if (*right < 0 || *right >= 64) {
            return undefined_result();
        }
        if (expr.kind == shift_left) {
            return value_result(rule_engine::Value::integer(static_cast<std::int64_t>(left_bits << *right)));
        }
        if (expr.kind == shift_right) {
            return value_result(rule_engine::Value::integer(static_cast<std::int64_t>(left_bits >> *right)));
        }
        return undefined_result();
    }

    [[nodiscard]] EvalValue eval_pattern_metadata(const rule_engine::Expression &expr, EvalContext &ctx) {
        using enum rule_engine::ExpressionKind;
        const auto key = pattern_metadata_key(expr, current_pattern(ctx));
        const auto fact = ctx.facts.lookup(ctx.subject.id, key);
        if (!fact.has_value()) {
            return missing_result(key);
        }
        if (fact->status != rule_engine::FactStatus::available) {
            return diagnostic_result(fact->diagnostic.empty() ? key + " unavailable" : fact->diagnostic);
        }
        if (const auto mismatch = cached_fact_type_mismatch(ctx, key, fact->value); mismatch.has_value()) {
            return *mismatch;
        }

        const auto *pattern = fact->value.as_pattern();
        if (pattern == nullptr) {
            return undefined_result();
        }

        if (expr.kind == pattern_count) {
            const auto count = to_i64(pattern->matches.size());
            if (!count.has_value()) {
                return undefined_result();
            }
            if (expr.children.size() == 2u) {
                auto lower = eval_expr(expr.children[0], ctx);
                if (lower.status != EvalStatus::value) {
                    return lower;
                }
                auto upper = eval_expr(expr.children[1], ctx);
                if (upper.status != EvalStatus::value) {
                    return upper;
                }
                const auto lower_i = lower.value.as_i64();
                const auto upper_i = upper.value.as_i64();
                if (!lower_i.has_value() || !upper_i.has_value()) {
                    return undefined_result();
                }

                std::int64_t in_range {};
                for (const auto &match : pattern->matches) {
                    const auto offset = to_i64(match.offset);
                    if (!offset.has_value()) {
                        return undefined_result();
                    }
                    if (*offset >= *lower_i && *offset <= *upper_i) {
                        ++in_range;
                    }
                }
                return value_result(rule_engine::Value::integer(in_range));
            }
            return value_result(rule_engine::Value::integer(*count));
        }

        std::int64_t index {1};
        if (!expr.children.empty()) {
            auto index_value = eval_expr(expr.children[0], ctx);
            if (index_value.status != EvalStatus::value) {
                return index_value;
            }
            const auto maybe_index = index_value.value.as_i64();
            if (!maybe_index.has_value()) {
                return undefined_result();
            }
            index = *maybe_index;
        }
        if (index <= 0) {
            return undefined_result();
        }

        const auto zero_based = static_cast<std::uint64_t>(index - 1);
        if (zero_based >= pattern->matches.size()) {
            return undefined_result();
        }

        const auto &match = pattern->matches[static_cast<std::size_t>(zero_based)];
        const auto value = expr.kind == pattern_offset ? to_i64(match.offset) : to_i64(match.length);
        if (!value.has_value()) {
            return undefined_result();
        }
        return value_result(rule_engine::Value::integer(*value));
    }

    [[nodiscard]] EvalValue eval_pattern_fact_match(const std::string &name, EvalContext &ctx,
                                                    const std::optional<std::int64_t> at_offset = std::nullopt,
                                                    const std::optional<std::int64_t> range_lower = std::nullopt,
                                                    const std::optional<std::int64_t> range_upper = std::nullopt) {
        auto pattern_name = name;
        if (pattern_name == "$" && !current_pattern(ctx).empty()) {
            pattern_name = std::string {current_pattern(ctx)};
        }
        const auto key = pattern_fact_key(pattern_name);
        const auto fact = ctx.facts.lookup(ctx.subject.id, key);
        if (!fact.has_value()) {
            return missing_result(key);
        }
        if (fact->status != rule_engine::FactStatus::available) {
            return diagnostic_result(fact->diagnostic.empty() ? key + " unavailable" : fact->diagnostic);
        }
        if (const auto mismatch = cached_fact_type_mismatch(ctx, key, fact->value); mismatch.has_value()) {
            return *mismatch;
        }

        const auto anchored = at_offset.has_value() || range_lower.has_value() || range_upper.has_value();
        if (anchored) {
            const auto *pattern = fact->value.as_pattern();
            if (pattern == nullptr) {
                return undefined_result();
            }
            for (const auto &match : pattern->matches) {
                const auto offset = to_i64(match.offset);
                if (!offset.has_value()) {
                    return undefined_result();
                }
                if (at_offset.has_value() && *offset == *at_offset) {
                    return bool_result(true);
                }
                if (range_lower.has_value() && range_upper.has_value() && *offset >= *range_lower &&
                    *offset <= *range_upper) {
                    return bool_result(true);
                }
            }
            return bool_result(false);
        }

        if (const auto value = fact->value.as_bool(); value.has_value()) {
            return bool_result(*value);
        }
        if (const auto *pattern = fact->value.as_pattern(); pattern != nullptr) {
            return bool_result(pattern->matched);
        }
        return undefined_result();
    }

    [[nodiscard]] EvalValue eval_for_of_expr(const rule_engine::Expression &expr, EvalContext &ctx) {
        const auto quantifier_children = (expr.text == "expr" || expr.text == "percentage") ? 1u : 0u;
        if (expr.children.size() != quantifier_children + 1u) {
            return undefined_result();
        }

        std::int64_t threshold {};
        if (quantifier_children == 1u) {
            auto value = eval_expr(expr.children[0], ctx);
            if (value.status != EvalStatus::value) {
                return value;
            }
            const auto integer = value.value.as_i64();
            if (!integer.has_value()) {
                return undefined_result();
            }
            threshold = *integer;
        }

        const auto base = ctx.current_patterns.size();
        std::int64_t matched {};
        for (const auto &name : expr.names) {
            ctx.current_patterns.resize(base);
            ctx.current_patterns.push_back(pattern_identifier_key(name));
            auto body = eval_expr(expr.children[quantifier_children], ctx);
            if (body.status != EvalStatus::value) {
                ctx.current_patterns.resize(base);
                return body;
            }
            if (body.value.as_bool().value_or(false)) {
                ++matched;
            }
        }
        ctx.current_patterns.resize(base);

        const auto total = static_cast<std::int64_t>(expr.names.size());
        if (expr.text == "all") {
            return bool_result(total > 0 && matched == total);
        }
        if (expr.text == "any") {
            return bool_result(matched > 0);
        }
        if (expr.text == "none") {
            return bool_result(matched == 0);
        }
        if (expr.text == "expr") {
            return numeric_quantifier_result(matched, threshold);
        }
        if (expr.text == "percentage") {
            if (total <= 0) {
                return undefined_result();
            }
            return bool_result((matched * 100) >= (threshold * total));
        }
        return undefined_result();
    }

    [[nodiscard]] EvalValue eval_of_expr(const rule_engine::Expression &expr, EvalContext &ctx) {
        if (expr.text.starts_with("bool_")) {
            const std::string_view quantifier {expr.text.data() + 5u, expr.text.size() - 5u};
            const auto quantifier_children = (quantifier == "expr" || quantifier == "percentage") ? 1u : 0u;
            if (expr.children.size() <= quantifier_children) {
                return undefined_result();
            }

            std::int64_t threshold {};
            if (quantifier_children == 1u) {
                auto value = eval_expr(expr.children[0], ctx);
                if (value.status != EvalStatus::value) {
                    return value;
                }
                const auto integer = value.value.as_i64();
                if (!integer.has_value()) {
                    return undefined_result();
                }
                threshold = *integer;
            }

            std::int64_t matched {};
            for (std::size_t index = quantifier_children; index < expr.children.size(); ++index) {
                auto value = eval_expr(expr.children[index], ctx);
                if (value.status != EvalStatus::value) {
                    return value;
                }
                if (value.value.as_bool().value_or(false)) {
                    ++matched;
                }
            }

            const auto total = static_cast<std::int64_t>(expr.children.size() - quantifier_children);
            if (quantifier == "all") {
                return bool_result(total > 0 && matched == total);
            }
            if (quantifier == "any") {
                return bool_result(matched > 0);
            }
            if (quantifier == "none") {
                return bool_result(matched == 0);
            }
            if (quantifier == "expr") {
                return numeric_quantifier_result(matched, threshold);
            }
            if (quantifier == "percentage") {
                if (total <= 0) {
                    return undefined_result();
                }
                return bool_result((matched * 100) >= (threshold * total));
            }
            return undefined_result();
        }

        std::string_view quantifier {expr.text};
        bool anchor_at {};
        bool anchor_in {};
        if (quantifier.starts_with("at_")) {
            quantifier.remove_prefix(3u);
            anchor_at = true;
        } else if (quantifier.starts_with("in_")) {
            quantifier.remove_prefix(3u);
            anchor_in = true;
        }

        const auto quantifier_children = (quantifier == "expr" || quantifier == "percentage") ? 1u : 0u;
        const auto anchor_children = anchor_at ? 1u : (anchor_in ? 2u : 0u);
        if (expr.children.size() < quantifier_children + anchor_children) {
            return undefined_result();
        }

        std::int64_t threshold {};
        if (quantifier_children == 1u) {
            auto threshold_value = eval_expr(expr.children[0], ctx);
            if (threshold_value.status != EvalStatus::value) {
                return threshold_value;
            }
            const auto integer = threshold_value.value.as_i64();
            if (!integer.has_value()) {
                return undefined_result();
            }
            threshold = *integer;
        }

        std::optional<std::int64_t> at_offset;
        std::optional<std::int64_t> range_lower;
        std::optional<std::int64_t> range_upper;
        if (anchor_at) {
            auto value = eval_expr(expr.children[quantifier_children], ctx);
            if (value.status != EvalStatus::value) {
                return value;
            }
            at_offset = value.value.as_i64();
            if (!at_offset.has_value()) {
                return undefined_result();
            }
        } else if (anchor_in) {
            auto lower = eval_expr(expr.children[quantifier_children], ctx);
            if (lower.status != EvalStatus::value) {
                return lower;
            }
            auto upper = eval_expr(expr.children[quantifier_children + 1u], ctx);
            if (upper.status != EvalStatus::value) {
                return upper;
            }
            range_lower = lower.value.as_i64();
            range_upper = upper.value.as_i64();
            if (!range_lower.has_value() || !range_upper.has_value()) {
                return undefined_result();
            }
        }

        std::int64_t matched {};
        for (const auto &name : expr.names) {
            auto value = eval_pattern_fact_match(name, ctx, at_offset, range_lower, range_upper);
            if (value.status != EvalStatus::value) {
                return value;
            }
            if (value.value.as_bool().value_or(false)) {
                ++matched;
            }
        }

        const auto total = static_cast<std::int64_t>(expr.names.size());
        if (quantifier == "all") {
            return bool_result(total > 0 && matched == total);
        }
        if (quantifier == "any") {
            return bool_result(matched > 0);
        }
        if (quantifier == "none") {
            return bool_result(matched == 0);
        }
        if (quantifier == "expr") {
            return numeric_quantifier_result(matched, threshold);
        }
        if (quantifier == "percentage") {
            if (total <= 0) {
                return undefined_result();
            }
            return bool_result((matched * 100) >= (threshold * total));
        }
        return undefined_result();
    }

    struct IterableItem {
        std::vector<rule_engine::Value> bindings;
    };

    struct IterableEval {
        EvalStatus status {EvalStatus::value};
        std::vector<IterableItem> items;
        EvalValue issue;
    };

    [[nodiscard]] IterableEval iterable_values(std::vector<rule_engine::Value> values) {
        IterableEval out;
        out.items.reserve(values.size());
        for (auto &value : values) { out.items.push_back(IterableItem {.bindings = {std::move(value)}}); }
        return out;
    }

    [[nodiscard]] IterableEval iterable_items(std::vector<IterableItem> items) {
        IterableEval out;
        out.items = std::move(items);
        return out;
    }

    [[nodiscard]] IterableEval iterable_issue(EvalValue issue) {
        IterableEval out;
        out.status = issue.status;
        out.issue = std::move(issue);
        return out;
    }

    [[nodiscard]] IterableEval eval_iterable(const rule_engine::Expression &expr, EvalContext &ctx,
                                             const std::size_t binding_count) {
        using enum rule_engine::ExpressionKind;
        if (binding_count == 0u || binding_count > 2u) {
            return iterable_issue(undefined_result());
        }
        if (expr.kind == range_expr) {
            if (binding_count != 1u) {
                return iterable_issue(undefined_result());
            }
            if (expr.children.size() != 2u) {
                return iterable_issue(undefined_result());
            }

            auto lower = eval_expr(expr.children[0], ctx);
            if (lower.status != EvalStatus::value) {
                return iterable_issue(std::move(lower));
            }
            auto upper = eval_expr(expr.children[1], ctx);
            if (upper.status != EvalStatus::value) {
                return iterable_issue(std::move(upper));
            }

            const auto lower_value = lower.value.as_i64();
            const auto upper_value = upper.value.as_i64();
            if (!lower_value.has_value() || !upper_value.has_value() || *lower_value > *upper_value) {
                return iterable_values({});
            }

            constexpr std::int64_t max_range_items {100000};
            const auto first_disallowed_upper = checked_add(*lower_value, max_range_items);
            if (!first_disallowed_upper.has_value() || *upper_value >= *first_disallowed_upper) {
                return iterable_issue(undefined_result());
            }

            const auto item_count = static_cast<std::size_t>(*upper_value - *lower_value + 1);
            std::vector<rule_engine::Value> values;
            values.reserve(item_count);
            for (auto value = *lower_value;; ++value) {
                values.push_back(rule_engine::Value::integer(value));
                if (value == *upper_value) {
                    break;
                }
            }
            return iterable_values(std::move(values));
        }

        if (expr.kind == tuple_expr) {
            if (binding_count != 1u) {
                return iterable_issue(undefined_result());
            }
            std::vector<rule_engine::Value> values;
            values.reserve(expr.children.size());
            for (const auto &child : expr.children) {
                auto value = eval_expr(child, ctx);
                if (value.status != EvalStatus::value) {
                    return iterable_issue(std::move(value));
                }
                values.push_back(std::move(value.value));
            }
            return iterable_values(std::move(values));
        }

        if (expr.kind == iterable_expr && expr.children.size() == 1u) {
            auto value = eval_expr(expr.children[0], ctx);
            if (value.status != EvalStatus::value) {
                return iterable_issue(std::move(value));
            }
            if (const auto *array = value.value.as_array(); array != nullptr) {
                std::vector<IterableItem> items;
                items.reserve(array->values.size());
                for (std::size_t index = 0; index < array->values.size(); ++index) {
                    if (binding_count == 1u) {
                        items.push_back(IterableItem {.bindings = {array->values[index]}});
                        continue;
                    }
                    items.push_back(IterableItem {
                        .bindings =
                            {
                                rule_engine::Value::integer(static_cast<std::int64_t>(index)),
                                array->values[index],
                            },
                    });
                }
                return iterable_items(std::move(items));
            }

            if (const auto *object = value.value.as_object(); object != nullptr) {
                std::vector<IterableItem> items;
                items.reserve(object->entries.size());
                for (const auto &entry : object->entries) {
                    if (binding_count == 1u) {
                        items.push_back(IterableItem {.bindings = {entry.value}});
                        continue;
                    }
                    items.push_back(IterableItem {
                        .bindings =
                            {
                                rule_engine::Value::string(entry.key),
                                entry.value,
                            },
                    });
                }
                return iterable_items(std::move(items));
            }
        }
        return iterable_issue(undefined_result());
    }

    [[nodiscard]] EvalValue eval_for_in_expr(const rule_engine::Expression &expr, EvalContext &ctx) {
        if (expr.names.empty() || expr.names.size() > 2u) {
            return undefined_result();
        }

        const auto quantifier_children = (expr.text == "expr" || expr.text == "percentage") ? 1u : 0u;
        if (expr.children.size() != quantifier_children + 2u) {
            return undefined_result();
        }

        std::int64_t threshold {};
        if (quantifier_children == 1u) {
            auto value = eval_expr(expr.children[0], ctx);
            if (value.status != EvalStatus::value) {
                return value;
            }
            const auto integer = value.value.as_i64();
            if (!integer.has_value()) {
                return undefined_result();
            }
            threshold = *integer;
        }

        auto iterable = eval_iterable(expr.children[quantifier_children], ctx, expr.names.size());
        if (iterable.status != EvalStatus::value) {
            return std::move(iterable.issue);
        }

        const auto base = ctx.locals.size();
        std::int64_t matched {};
        for (const auto &item : iterable.items) {
            if (item.bindings.size() != expr.names.size()) {
                ctx.locals.resize(base);
                return undefined_result();
            }
            ctx.locals.resize(base);
            for (std::size_t index = 0; index < expr.names.size(); ++index) {
                ctx.locals.push_back(LocalBinding {
                    .name = expr.names[index],
                    .value = item.bindings[index],
                });
            }
            auto body = eval_expr(expr.children[quantifier_children + 1u], ctx);
            if (body.status != EvalStatus::value) {
                ctx.locals.resize(base);
                return body;
            }
            if (body.value.as_bool().value_or(false)) {
                ++matched;
            }
        }
        ctx.locals.resize(base);

        const auto total = static_cast<std::int64_t>(iterable.items.size());
        if (expr.text == "all") {
            return bool_result(total > 0 && matched == total);
        }
        if (expr.text == "any") {
            return bool_result(matched > 0);
        }
        if (expr.text == "none") {
            return bool_result(matched == 0);
        }
        if (expr.text == "expr") {
            return bool_result(matched >= threshold);
        }
        if (expr.text == "percentage") {
            if (total <= 0) {
                return undefined_result();
            }
            return bool_result((matched * 100) >= (threshold * total));
        }
        return undefined_result();
    }

    [[nodiscard]] EvalValue eval_lookup_expr(const rule_engine::Expression &expr, EvalContext &ctx) {
        if (expr.children.size() != 2u) {
            return undefined_result();
        }

        auto primary = eval_expr(expr.children[0], ctx);
        if (primary.status != EvalStatus::value) {
            return primary;
        }
        auto index = eval_expr(expr.children[1], ctx);
        if (index.status != EvalStatus::value) {
            return index;
        }

        if (const auto *array = primary.value.as_array(); array != nullptr) {
            const auto offset = index.value.as_i64();
            if (!offset.has_value() || *offset < 0) {
                return undefined_result();
            }
            const auto position = static_cast<std::size_t>(*offset);
            if (position >= array->values.size()) {
                return undefined_result();
            }
            return value_result(array->values[position]);
        }

        if (const auto *object = primary.value.as_object(); object != nullptr) {
            const auto *key = index.value.as_string();
            if (key == nullptr) {
                return undefined_result();
            }
            const auto found =
                std::ranges::find_if(object->entries, [&](const auto &entry) { return entry.key == *key; });
            if (found == object->entries.end()) {
                return undefined_result();
            }
            return value_result(found->value);
        }

        return undefined_result();
    }

    [[nodiscard]] std::optional<std::int64_t> read_integer_value(const rule_engine::Value::Bytes &bytes,
                                                                 const std::int64_t offset,
                                                                 const IntegerReaderSpec spec) noexcept {
        if (offset < 0) {
            return std::nullopt;
        }

        const auto start = static_cast<std::size_t>(offset);
        if (start > bytes.size() || spec.width > bytes.size() - start) {
            return std::nullopt;
        }

        std::uint64_t raw {};
        for (std::size_t index = 0u; index < spec.width; ++index) {
            const auto byte_offset = spec.big_endian ? index : spec.width - index - 1u;
            raw <<= 8u;
            raw |= static_cast<std::uint64_t>(std::to_integer<unsigned int>(bytes[start + byte_offset]));
        }

        if (!spec.signed_value) {
            return static_cast<std::int64_t>(raw);
        }

        const auto bit_count = spec.width * 8u;
        const auto sign_bit = std::uint64_t {1} << (bit_count - 1u);
        if ((raw & sign_bit) == 0u) {
            return static_cast<std::int64_t>(raw);
        }

        const auto range = std::uint64_t {1} << bit_count;
        return static_cast<std::int64_t>(raw) - static_cast<std::int64_t>(range);
    }

    [[nodiscard]] EvalValue eval_integer_reader(const rule_engine::Expression &expr, EvalContext &ctx) {
        if (expr.children.size() != 1u) {
            return undefined_result();
        }

        const auto spec = integer_reader_spec(expr.text);
        if (!spec.has_value()) {
            return diagnostic_result("unsupported integer reader " + expr.text);
        }

        auto offset = eval_expr(expr.children[0], ctx);
        if (offset.status != EvalStatus::value) {
            return offset;
        }
        const auto offset_value = offset.value.as_i64();
        if (!offset_value.has_value()) {
            return undefined_result();
        }

        const auto key = expr.bound_key_prefix.empty() ? std::string {process_image_bytes_key} : expr.bound_key_prefix;
        const auto fact = ctx.facts.lookup(ctx.subject.id, key);
        if (!fact.has_value()) {
            return missing_result(rule_engine::RequiredFact {
                .key = key,
                .route = expr.bound_route.empty() ? std::string {scan_pattern_route} : expr.bound_route,
                .ttl = expr.bound_ttl,
                .timeout = expr.bound_timeout,
                .retry_policy = expr.bound_retry_policy,
                .retry_budget = expr.bound_retry_budget,
                .cancellation_diagnostic = expr.bound_cancellation_diagnostic,
                .cheap_prefetch = expr.bound_cheap_prefetch,
                .type = rule_engine::ValueType::bytes,
                .scan_plan = std::nullopt,
                .cost_class = expr.bound_cost_class,
            });
        }
        if (fact->status != rule_engine::FactStatus::available) {
            return diagnostic_result(fact->diagnostic.empty() ? key + " unavailable" : fact->diagnostic);
        }
        if (const auto mismatch = cached_fact_type_mismatch(ctx, key, fact->value); mismatch.has_value()) {
            return *mismatch;
        }

        const auto *bytes = fact->value.as_bytes();
        if (bytes == nullptr) {
            return diagnostic_result("cached fact " + key + " has wrong type; expected bytes");
        }

        const auto value = read_integer_value(*bytes, *offset_value, *spec);
        if (!value.has_value()) {
            return undefined_result();
        }
        return value_result(rule_engine::Value::integer(*value));
    }

    void attach_required_fact_for_missing(const rule_engine::VerifiedRule &rule, EvalValue &eval) {
        if (eval.status != EvalStatus::missing || eval.missing_fact.has_value() || eval.missing_key.empty()) {
            return;
        }
        eval.missing_fact = find_required_fact(rule, eval.missing_key);
    }

    [[nodiscard]] EvalValue eval_rule(const std::size_t index, EvalContext &ctx) {
        if (index >= ctx.program.rules.size()) {
            return bool_result(false);
        }
        if (ctx.memo[index].has_value()) {
            return *ctx.memo[index];
        }
        if (ctx.active[index]) {
            return diagnostic_result("rule dependency cycle reached during evaluation");
        }

        const auto saved_rule_identifier = ctx.current_rule_identifier;
        const auto saved_rule_index = ctx.current_rule_index;
        const auto &rule = ctx.program.rules[index];
        ctx.current_rule_identifier = rule.qualified_identifier.empty() ? rule.identifier : rule.qualified_identifier;
        ctx.current_rule_index = index;
        ctx.active[index] = true;
        auto result = eval_expr(rule.condition, ctx);
        ctx.active[index] = false;
        ctx.current_rule_index = saved_rule_index;
        ctx.current_rule_identifier = saved_rule_identifier;
        attach_required_fact_for_missing(rule, result);
        if (result.status == EvalStatus::value) {
            result = bool_result(result.value.as_bool().value_or(false));
        }
        ctx.memo[index] = result;
        return result;
    }

    [[nodiscard]] EvalValue eval_rule_reference(const std::size_t index, EvalContext &ctx) {
        auto saved_locals = std::move(ctx.locals);
        auto saved_patterns = std::move(ctx.current_patterns);
        ctx.locals = {};
        ctx.current_patterns = {};
        auto result = eval_rule(index, ctx);
        ctx.locals = std::move(saved_locals);
        ctx.current_patterns = std::move(saved_patterns);
        return result;
    }

    [[nodiscard]] EvalValue eval_with_expr(const rule_engine::Expression &expr, EvalContext &ctx) {
        if (expr.children.size() != expr.names.size() + 1u) {
            return undefined_result();
        }

        const auto base = ctx.locals.size();
        for (std::size_t index = 0; index < expr.names.size(); ++index) {
            auto value = eval_expr(expr.children[index], ctx);
            if (value.status != EvalStatus::value) {
                ctx.locals.resize(base);
                return value;
            }
            ctx.locals.push_back(LocalBinding {
                .name = expr.names[index],
                .value = std::move(value.value),
            });
        }

        auto result = eval_expr(expr.children.back(), ctx);
        ctx.locals.resize(base);
        return result;
    }

    [[nodiscard]] EvalValue eval_function_call(const rule_engine::Expression &expr, EvalContext &ctx) {
        if (expr.bound_route.empty()) {
            return diagnostic_result("unbound function call " + expr.text);
        }

        std::vector<rule_engine::Value> arguments;
        arguments.reserve(expr.children.size());
        for (const auto &child : expr.children) {
            auto value = eval_expr(child, ctx);
            if (value.status != EvalStatus::value) {
                return value;
            }
            arguments.push_back(std::move(value.value));
        }

        const auto key = rule_engine::provider_function_key(
            expr.bound_key_prefix.empty() ? expr.text : expr.bound_key_prefix, arguments);
        const auto fact = ctx.facts.lookup(ctx.subject.id, key);
        if (!fact.has_value()) {
            return missing_result(rule_engine::RequiredFact {
                .key = key,
                .route = expr.bound_route,
                .ttl = expr.bound_ttl,
                .timeout = expr.bound_timeout,
                .retry_policy = expr.bound_retry_policy,
                .retry_budget = expr.bound_retry_budget,
                .cancellation_diagnostic = expr.bound_cancellation_diagnostic,
                .cheap_prefetch = expr.bound_cheap_prefetch,
                .type = expr.bound_return_type,
                .scan_plan = std::nullopt,
                .cost_class = expr.bound_cost_class,
            });
        }
        if (fact->status != rule_engine::FactStatus::available) {
            return diagnostic_result(fact->diagnostic.empty() ? key + " unavailable" : fact->diagnostic);
        }
        if (const auto mismatch = type_mismatch_result(key, fact->value, expr.bound_return_type);
            mismatch.has_value()) {
            return *mismatch;
        }
        return value_result(fact->value);
    }

    [[nodiscard]] EvalValue eval_expr_impl(const rule_engine::Expression &expr, EvalContext &ctx) {
        using enum rule_engine::ExpressionKind;
        switch (expr.kind) {
            case true_expr: return bool_result(true);
            case false_expr: return bool_result(false);
            case literal_string: return value_result(rule_engine::Value::string(expr.text));
            case literal_integer: return value_result(rule_engine::Value::integer(expr.integer));
            case literal_float: return value_result(rule_engine::Value::number(expr.floating));
            case negate:
            case add:
            case subtract:
            case multiply:
            case divide:
            case modulo: return eval_arithmetic(expr, ctx);
            case bitwise_not:
            case shift_left:
            case shift_right:
            case bitwise_and:
            case bitwise_or:
            case bitwise_xor: return eval_bitwise(expr, ctx);
            case field: {
                std::string key;
                for (const auto &name : expr.names) {
                    if (!key.empty()) {
                        key.push_back('.');
                    }
                    key += name;
                }
                const auto fact = ctx.facts.lookup(ctx.subject.id, key);
                if (!fact.has_value()) {
                    return missing_result(std::move(key));
                }
                if (fact->status != rule_engine::FactStatus::available) {
                    return diagnostic_result(fact->diagnostic.empty() ? key + " unavailable" : fact->diagnostic);
                }
                if (const auto mismatch = cached_fact_type_mismatch(ctx, key, fact->value); mismatch.has_value()) {
                    return *mismatch;
                }
                return value_result(fact->value);
            }
            case global: {
                auto key = expr.text;
                if (key.empty() && !expr.names.empty()) {
                    key = expr.names[0];
                }
                const auto fact = ctx.facts.lookup(ctx.subject.id, key);
                if (!fact.has_value()) {
                    return missing_result(std::move(key));
                }
                if (fact->status != rule_engine::FactStatus::available) {
                    return diagnostic_result(fact->diagnostic.empty() ? key + " unavailable" : fact->diagnostic);
                }
                if (const auto mismatch = cached_fact_type_mismatch(ctx, key, fact->value); mismatch.has_value()) {
                    return *mismatch;
                }
                return value_result(fact->value);
            }
            case pattern_match: {
                auto key = expr.names.empty() ? expr.text : expr.names[0];
                if (key == "$" && !current_pattern(ctx).empty()) {
                    return eval_pattern_fact_match(key, ctx);
                }
                if (!key.starts_with('$')) {
                    key.insert(key.begin(), '$');
                }
                key += ".matches";
                const auto fact = ctx.facts.lookup(ctx.subject.id, key);
                if (!fact.has_value()) {
                    return missing_result(std::move(key));
                }
                if (fact->status != rule_engine::FactStatus::available) {
                    return diagnostic_result(fact->diagnostic.empty() ? key + " unavailable" : fact->diagnostic);
                }
                if (const auto mismatch = cached_fact_type_mismatch(ctx, key, fact->value); mismatch.has_value()) {
                    return *mismatch;
                }
                return value_result(fact->value);
            }
            case pattern_count:
            case pattern_offset:
            case pattern_length: return eval_pattern_metadata(expr, ctx);
            case of_expr: return eval_of_expr(expr, ctx);
            case for_of_expr: return eval_for_of_expr(expr, ctx);
            case with_expr: return eval_with_expr(expr, ctx);
            case for_in_expr: return eval_for_in_expr(expr, ctx);
            case range_expr:
            case tuple_expr:
            case iterable_expr: return undefined_result();
            case lookup_expr: return eval_lookup_expr(expr, ctx);
            case integer_reader: return eval_integer_reader(expr, ctx);
            case function_call: return eval_function_call(expr, ctx);
            case and_expr: {
                for (const auto &child : expr.children) {
                    auto value = eval_expr(child, ctx);
                    if (value.status != EvalStatus::value) {
                        return value;
                    }
                    const auto boolean = value.value.as_bool();
                    if (!boolean.value_or(false)) {
                        return bool_result(false);
                    }
                }
                return bool_result(true);
            }
            case or_expr: {
                std::optional<EvalValue> first_missing;
                for (const auto &child : expr.children) {
                    auto value = eval_expr(child, ctx);
                    if (value.status != EvalStatus::value) {
                        if (!first_missing.has_value()) {
                            first_missing = value;
                        }
                        continue;
                    }
                    if (value.value.as_bool().value_or(false)) {
                        return bool_result(true);
                    }
                }
                if (first_missing.has_value()) {
                    return *first_missing;
                }
                return bool_result(false);
            }
            case not_expr: {
                if (expr.children.empty()) {
                    return bool_result(false);
                }
                auto value = eval_expr(expr.children[0], ctx);
                if (value.status != EvalStatus::value) {
                    return value;
                }
                if (value.value.is_undefined()) {
                    return undefined_result();
                }
                return bool_result(!value.value.as_bool().value_or(false));
            }
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
            case iequals: {
                if (expr.children.size() != 2u) {
                    return bool_result(false);
                }
                auto lhs = eval_expr(expr.children[0], ctx);
                if (lhs.status != EvalStatus::value) {
                    return lhs;
                }
                auto rhs = eval_expr(expr.children[1], ctx);
                if (rhs.status != EvalStatus::value) {
                    return rhs;
                }
                if (lhs.value.is_undefined() || rhs.value.is_undefined()) {
                    return undefined_result();
                }
                bool result {};
                if (expr.kind == equal) {
                    result = values_equal(lhs.value, rhs.value);
                } else if (expr.kind == not_equal) {
                    result = !values_equal(lhs.value, rhs.value);
                } else if (expr.kind == contains) {
                    const auto *l = lhs.value.as_string();
                    const auto *r = rhs.value.as_string();
                    result = l != nullptr && r != nullptr && string_contains(*l, *r, false);
                } else if (expr.kind == icontains) {
                    const auto *l = lhs.value.as_string();
                    const auto *r = rhs.value.as_string();
                    result = l != nullptr && r != nullptr && string_contains(*l, *r, true);
                } else if (expr.kind == starts_with || expr.kind == istarts_with) {
                    const auto *l = lhs.value.as_string();
                    const auto *r = rhs.value.as_string();
                    result = l != nullptr && r != nullptr && string_starts_with(*l, *r, expr.kind == istarts_with);
                } else if (expr.kind == ends_with || expr.kind == iends_with) {
                    const auto *l = lhs.value.as_string();
                    const auto *r = rhs.value.as_string();
                    result = l != nullptr && r != nullptr && string_ends_with(*l, *r, expr.kind == iends_with);
                } else if (expr.kind == iequals) {
                    const auto *l = lhs.value.as_string();
                    const auto *r = rhs.value.as_string();
                    result = l != nullptr && r != nullptr && string_iequals(*l, *r);
                } else if (const auto li = numeric_value(lhs.value); li.has_value()) {
                    const auto ri = numeric_value(rhs.value);
                    if (ri.has_value()) {
                        if (expr.kind == greater) {
                            result = li->number > ri->number;
                        } else if (expr.kind == greater_equal) {
                            result = li->number >= ri->number;
                        } else if (expr.kind == less) {
                            result = li->number < ri->number;
                        } else if (expr.kind == less_equal) {
                            result = li->number <= ri->number;
                        }
                    }
                }
                return bool_result(result);
            }
            case defined: {
                if (expr.children.empty()) {
                    return bool_result(false);
                }
                auto value = eval_expr(expr.children[0], ctx);
                if (value.status == EvalStatus::missing) {
                    return value;
                }
                return bool_result(value.status == EvalStatus::value && !value.value.is_undefined());
            }
            case identifier: {
                const auto name = !expr.names.empty() ? std::string_view {expr.names[0]} : std::string_view {expr.text};
                if (const auto *local = find_local(ctx, name); local != nullptr) {
                    return value_result(*local);
                }
                const auto index = rule_index_by_name(ctx.program, name);
                if (!index.has_value()) {
                    return bool_result(false);
                }
                return eval_rule_reference(*index, ctx);
            }
            case unsupported:
            default: return bool_result(false);
        }
    }

    [[nodiscard]] EvalValue eval_expr(const rule_engine::Expression &expr, EvalContext &ctx) {
        if (ctx.instrumentation != nullptr) {
            ++ctx.instrumentation->expression_evaluations;
        }
        const auto trace_index = ctx.expression_traces == nullptr ? 0u : ctx.expression_traces->size();
        auto result = eval_expr_impl(expr, ctx);
        insert_expression_trace(ctx, trace_index, expr, result);
        return result;
    }

    void add_request(std::vector<rule_engine::FactRequestBatch> &requests, const rule_engine::RequiredFact &fact) {
        auto found = std::ranges::find_if(requests, [&](const auto &batch) { return batch.route == fact.route; });
        if (found == requests.end()) {
            rule_engine::FactRequestBatch batch;
            batch.route = fact.route;
            batch.keys = {fact.key};
            batch.types = {fact.type};
            batch.retry_policies = {fact.retry_policy};
            batch.retry_budgets = {fact.retry_budget};
            batch.cancellation_diagnostics = {fact.cancellation_diagnostic};
            if (fact.scan_plan.has_value()) {
                batch.scan_plans.push_back(*fact.scan_plan);
            }
            batch.timeout = fact.timeout;
            requests.push_back(std::move(batch));
            return;
        }
        if (found->timeout < fact.timeout) {
            found->timeout = fact.timeout;
        }
        const auto key_index = std::ranges::find(found->keys, fact.key);
        if (key_index == found->keys.end()) {
            found->keys.push_back(fact.key);
            found->types.push_back(fact.type);
            found->retry_policies.push_back(fact.retry_policy);
            found->retry_budgets.push_back(fact.retry_budget);
            found->cancellation_diagnostics.push_back(fact.cancellation_diagnostic);
        } else {
            const auto index = static_cast<std::size_t>(std::distance(found->keys.begin(), key_index));
            if (index < found->retry_budgets.size()) {
                found->retry_budgets[index] = std::max(found->retry_budgets[index], fact.retry_budget);
            }
            if (index < found->retry_policies.size() && found->retry_policies[index] == rule_engine::ProviderRetryPolicy::none) {
                found->retry_policies[index] = fact.retry_policy;
            }
            if (index < found->cancellation_diagnostics.size() && found->cancellation_diagnostics[index].empty()) {
                found->cancellation_diagnostics[index] = fact.cancellation_diagnostic;
            }
        }
        if (fact.scan_plan.has_value() && !std::ranges::any_of(found->scan_plans, [&](const auto &existing) {
                return existing.pattern_key == fact.scan_plan->pattern_key;
            })) {
            found->scan_plans.push_back(*fact.scan_plan);
        }
    }

    void add_missing_requests_for_rule(std::vector<rule_engine::FactRequestBatch> &requests,
                                       const rule_engine::VerifiedRule &rule, const rule_engine::Subject &subject,
                                       const rule_engine::FactCache &facts, const bool cheap_only) {
        for (const auto &fact : rule.facts) {
            if (cheap_only && !fact.cheap_prefetch) {
                continue;
            }
            if (!facts.lookup(subject.id, fact.key).has_value()) {
                add_request(requests, fact);
            }
        }
    }

    void add_missing_request_for_eval(std::vector<rule_engine::FactRequestBatch> &requests, const EvalValue &eval) {
        if (eval.status != EvalStatus::missing || !eval.missing_fact.has_value()) {
            return;
        }
        add_request(requests, *eval.missing_fact);
    }

    [[nodiscard]] rule_engine::RuleResult make_rule_result(const rule_engine::VerifiedRule &rule, EvalValue eval) {
        rule_engine::RuleResult result;
        result.identifier = rule.qualified_identifier.empty() ? rule.identifier : rule.qualified_identifier;
        if (eval.status == EvalStatus::diagnostic) {
            result.matched = false;
            result.diagnostics.push_back(std::move(eval.diagnostic));
            return result;
        }
        result.matched = eval.status == EvalStatus::value && eval.value.as_bool().value_or(false);
        return result;
    }

    [[nodiscard]] std::string rule_identifier(const rule_engine::VerifiedRule &rule) {
        return rule.qualified_identifier.empty() ? rule.identifier : rule.qualified_identifier;
    }

    [[nodiscard]] bool rule_enabled(const rule_engine::VerifiedRule &rule,
                                    const rule_engine::EvaluationOptions &options) {
        if (options.enabled_rule_identifiers == nullptr) {
            return true;
        }
        const auto identifier = rule_identifier(rule);
        return std::ranges::find(*options.enabled_rule_identifiers, identifier) !=
               options.enabled_rule_identifiers->end();
    }
} // namespace

namespace rule_engine {
    Value Value::array(std::vector<Value> values) {
        return Value {.storage = std::make_shared<ArrayValue>(ArrayValue {.values = std::move(values)})};
    }

    Value Value::object(std::vector<ObjectEntry> entries) {
        return Value {.storage = std::make_shared<ObjectValue>(ObjectValue {.entries = std::move(entries)})};
    }

    std::optional<bool> Value::as_bool() const noexcept {
        if (const auto *value = std::get_if<bool>(&storage); value != nullptr) {
            return *value;
        }
        return std::nullopt;
    }

    std::optional<std::int64_t> Value::as_i64() const noexcept {
        if (const auto *value = std::get_if<std::int64_t>(&storage); value != nullptr) {
            return *value;
        }
        return std::nullopt;
    }

    std::optional<double> Value::as_f64() const noexcept {
        if (const auto *value = std::get_if<double>(&storage); value != nullptr) {
            return *value;
        }
        return std::nullopt;
    }

    const std::string *Value::as_string() const noexcept { return std::get_if<std::string>(&storage); }

    const Value::Bytes *Value::as_bytes() const noexcept { return std::get_if<Bytes>(&storage); }

    const PatternValue *Value::as_pattern() const noexcept { return std::get_if<PatternValue>(&storage); }

    const ArrayValue *Value::as_array() const noexcept {
        const auto *value = std::get_if<ArrayPtr>(&storage);
        if (value == nullptr) {
            return nullptr;
        }
        return value->get();
    }

    const ObjectValue *Value::as_object() const noexcept {
        const auto *value = std::get_if<ObjectPtr>(&storage);
        if (value == nullptr) {
            return nullptr;
        }
        return value->get();
    }

    void FactCache::store(Fact fact) {
        const auto index_key = cache_index_key(fact.subject_id, fact.key);
        const auto found = fact_index_.find(index_key);
        if (found == fact_index_.end()) {
            fact_index_.emplace(index_key, facts_.size());
            facts_.push_back(std::move(fact));
            return;
        }
        facts_[found->second] = std::move(fact);
    }

    std::optional<Fact> FactCache::lookup(const std::string_view subject_id, const std::string_view key) const {
        ++stats_.lookups;
        ++stats_.lookup_probes;
        const auto found = fact_index_.find(cache_index_key(subject_id, key));
        if (found == fact_index_.end()) {
            ++stats_.misses;
            return std::nullopt;
        }
        ++stats_.hits;
        return facts_[found->second];
    }

    std::vector<Fact> FactCache::snapshot_for_subject(const std::string_view subject_id) const {
        std::vector<Fact> out;
        for (const auto &fact : facts_) {
            if (fact.subject_id == subject_id) {
                out.push_back(fact);
            }
        }
        return out;
    }

    void FactCache::expire_volatile() {
        std::erase_if(facts_, [](const auto &fact) { return fact.ttl.count() == 0; });
        fact_index_.clear();
        for (std::size_t index = 0; index < facts_.size(); ++index) {
            fact_index_.emplace(cache_index_key(facts_[index].subject_id, facts_[index].key), index);
        }
    }

    FactCacheStats FactCache::stats() const noexcept { return stats_; }

    EvaluationStep Evaluator::step(const Subject &subject) const {
        EvaluationStep out;
        std::vector<std::optional<EvalValue>> memo(program_.rules.size());
        std::vector<bool> active(program_.rules.size(), false);
        EvalContext ctx {
            .program = program_,
            .subject = subject,
            .facts = facts_,
            .memo = memo,
            .active = active,
            .locals = {},
            .current_patterns = {},
            .expression_traces = options_.trace_expressions ? &out.expression_traces : nullptr,
            .instrumentation = options_.instrumentation,
            .current_rule_identifier = {},
            .current_rule_index = std::nullopt,
        };

        for (const auto &rule : program_.rules) {
            if (rule.is_global) {
                add_missing_requests_for_rule(out.requests, rule, subject, facts_, true);
            }
        }
        if (!out.requests.empty()) {
            out.state = EvaluationState::waiting_for_facts;
            return out;
        }

        bool globals_satisfied {true};
        for (std::size_t index = 0; index < program_.rules.size(); ++index) {
            const auto &rule = program_.rules[index];
            if (!rule.is_global) {
                continue;
            }

            auto eval = eval_rule(index, ctx);
            if (eval.status == EvalStatus::missing) {
                add_missing_request_for_eval(out.requests, eval);
                out.state = EvaluationState::waiting_for_facts;
                return out;
            }
            const auto matched = eval.status == EvalStatus::value && eval.value.as_bool().value_or(false);
            globals_satisfied = globals_satisfied && matched;
            if (!rule.is_private) {
                out.rule_results.push_back(make_rule_result(rule, std::move(eval)));
            }
        }

        if (!globals_satisfied) {
            for (const auto &rule : program_.rules) {
                if (rule.is_global || rule.is_private || !rule_enabled(rule, options_)) {
                    continue;
                }
                RuleResult result;
                result.identifier = rule_identifier(rule);
                result.matched = false;
                out.rule_results.push_back(std::move(result));
            }
            out.state = EvaluationState::complete;
            return out;
        }

        for (const auto &rule : program_.rules) {
            if (!rule.is_global && !rule.is_private && rule_enabled(rule, options_)) {
                add_missing_requests_for_rule(out.requests, rule, subject, facts_, true);
            }
        }
        if (!out.requests.empty()) {
            out.state = EvaluationState::waiting_for_facts;
            out.rule_results.clear();
            return out;
        }

        for (std::size_t index = 0; index < program_.rules.size(); ++index) {
            const auto &rule = program_.rules[index];
            if (rule.is_global || rule.is_private || !rule_enabled(rule, options_)) {
                continue;
            }

            auto eval = eval_rule(index, ctx);
            if (eval.status == EvalStatus::missing) {
                add_missing_request_for_eval(out.requests, eval);
                out.state = EvaluationState::waiting_for_facts;
                out.rule_results.clear();
                return out;
            }
            out.rule_results.push_back(make_rule_result(rule, std::move(eval)));
        }

        out.state = EvaluationState::complete;
        return out;
    }
} // namespace rule_engine
