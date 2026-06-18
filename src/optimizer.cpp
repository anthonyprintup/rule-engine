#include <rule_engine/optimizer.hpp>
#include <rule_engine/protocol.hpp>

#include <algorithm>
#include <charconv>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {
    struct LiteralPredicateValue {
        std::string kind;
        std::string value;
    };

    struct FactOperand {
        std::string key;
        std::string route;
        rule_engine::FactCostClass cost_class {rule_engine::FactCostClass::custom};
    };

    struct ExtractedPredicate {
        std::string id;
        std::string fact_key;
        std::string route;
        rule_engine::FactCostClass cost_class {rule_engine::FactCostClass::custom};
        std::string operation;
        std::string literal_kind;
        std::string literal_value;
    };

    struct NumericValue {
        bool floating {};
        std::int64_t integer {};
        double number {};
    };

    enum struct PredicateEvaluationStatus {
        matched,
        not_matched,
        unknown,
    };

    struct PredicateEvaluation {
        PredicateEvaluationStatus status {PredicateEvaluationStatus::unknown};
        std::string reason;
    };

    [[nodiscard]] std::string rule_identifier(const rule_engine::VerifiedRule &rule) {
        return rule.qualified_identifier.empty() ? rule.identifier : rule.qualified_identifier;
    }

    [[nodiscard]] std::string_view operation_name(const rule_engine::ExpressionKind kind) noexcept {
        using enum rule_engine::ExpressionKind;
        if (kind == equal) {
            return "equal";
        }
        if (kind == not_equal) {
            return "not_equal";
        }
        if (kind == greater) {
            return "greater";
        }
        if (kind == greater_equal) {
            return "greater_equal";
        }
        if (kind == less) {
            return "less";
        }
        if (kind == less_equal) {
            return "less_equal";
        }
        if (kind == contains) {
            return "contains";
        }
        if (kind == icontains) {
            return "icontains";
        }
        if (kind == starts_with) {
            return "starts_with";
        }
        if (kind == istarts_with) {
            return "istarts_with";
        }
        if (kind == ends_with) {
            return "ends_with";
        }
        if (kind == iends_with) {
            return "iends_with";
        }
        if (kind == iequals) {
            return "iequals";
        }
        return "unsupported";
    }

    [[nodiscard]] std::optional<rule_engine::ExpressionKind>
    flipped_order_operation(const rule_engine::ExpressionKind kind) noexcept {
        using enum rule_engine::ExpressionKind;
        if (kind == equal || kind == not_equal || kind == iequals) {
            return kind;
        }
        if (kind == greater) {
            return less;
        }
        if (kind == greater_equal) {
            return less_equal;
        }
        if (kind == less) {
            return greater;
        }
        if (kind == less_equal) {
            return greater_equal;
        }
        return std::nullopt;
    }

    [[nodiscard]] bool is_predicate_operation(const rule_engine::ExpressionKind kind) noexcept {
        using enum rule_engine::ExpressionKind;
        return kind == equal || kind == not_equal || kind == greater || kind == greater_equal || kind == less ||
               kind == less_equal || kind == contains || kind == icontains || kind == starts_with ||
               kind == istarts_with || kind == ends_with || kind == iends_with || kind == iequals;
    }

    [[nodiscard]] std::optional<LiteralPredicateValue> literal_value(const rule_engine::Expression &expr) {
        using enum rule_engine::ExpressionKind;
        if (expr.kind == literal_string) {
            return LiteralPredicateValue {.kind = "string", .value = expr.text};
        }
        if (expr.kind == literal_integer) {
            return LiteralPredicateValue {.kind = "integer", .value = std::to_string(expr.integer)};
        }
        if (expr.kind == literal_float) {
            return LiteralPredicateValue {.kind = "floating", .value = std::to_string(expr.floating)};
        }
        if (expr.kind == true_expr) {
            return LiteralPredicateValue {.kind = "boolean", .value = "true"};
        }
        if (expr.kind == false_expr) {
            return LiteralPredicateValue {.kind = "boolean", .value = "false"};
        }
        return std::nullopt;
    }

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

    [[nodiscard]] std::optional<std::int64_t> parse_i64(const std::string_view value) noexcept {
        std::int64_t out {};
        const auto *first = value.data();
        const auto *last = value.data() + value.size();
        const auto parsed = std::from_chars(first, last, out);
        if (parsed.ec != std::errc {} || parsed.ptr != last) {
            return std::nullopt;
        }
        return out;
    }

    [[nodiscard]] std::optional<double> parse_f64(const std::string_view value) noexcept {
        double out {};
        const auto *first = value.data();
        const auto *last = value.data() + value.size();
        const auto parsed = std::from_chars(first, last, out);
        if (parsed.ec != std::errc {} || parsed.ptr != last) {
            return std::nullopt;
        }
        return out;
    }

    [[nodiscard]] std::optional<rule_engine::Value>
    predicate_literal_value(const rule_engine::optimizer::CanonicalPredicate &predicate) {
        if (predicate.literal_kind == "string") {
            return rule_engine::Value::string(predicate.literal_value);
        }
        if (predicate.literal_kind == "integer") {
            const auto value = parse_i64(predicate.literal_value);
            if (!value.has_value()) {
                return std::nullopt;
            }
            return rule_engine::Value::integer(*value);
        }
        if (predicate.literal_kind == "floating") {
            const auto value = parse_f64(predicate.literal_value);
            if (!value.has_value()) {
                return std::nullopt;
            }
            return rule_engine::Value::number(*value);
        }
        if (predicate.literal_kind == "boolean") {
            if (predicate.literal_value == "true") {
                return rule_engine::Value::boolean(true);
            }
            if (predicate.literal_value == "false") {
                return rule_engine::Value::boolean(false);
            }
        }
        return std::nullopt;
    }

    [[nodiscard]] std::optional<bool>
    evaluate_predicate_values(const rule_engine::optimizer::CanonicalPredicate &predicate,
                              const rule_engine::Value &fact_value, const rule_engine::Value &literal) {
        if (fact_value.is_undefined() || literal.is_undefined()) {
            return std::nullopt;
        }
        if (predicate.operation == "equal") {
            return values_equal(fact_value, literal);
        }
        if (predicate.operation == "not_equal") {
            return !values_equal(fact_value, literal);
        }
        if (predicate.operation == "contains" || predicate.operation == "icontains") {
            const auto *lhs = fact_value.as_string();
            const auto *rhs = literal.as_string();
            if (lhs == nullptr || rhs == nullptr) {
                return std::nullopt;
            }
            return string_contains(*lhs, *rhs, predicate.operation == "icontains");
        }
        if (predicate.operation == "starts_with" || predicate.operation == "istarts_with") {
            const auto *lhs = fact_value.as_string();
            const auto *rhs = literal.as_string();
            if (lhs == nullptr || rhs == nullptr) {
                return std::nullopt;
            }
            return string_starts_with(*lhs, *rhs, predicate.operation == "istarts_with");
        }
        if (predicate.operation == "ends_with" || predicate.operation == "iends_with") {
            const auto *lhs = fact_value.as_string();
            const auto *rhs = literal.as_string();
            if (lhs == nullptr || rhs == nullptr) {
                return std::nullopt;
            }
            return string_ends_with(*lhs, *rhs, predicate.operation == "iends_with");
        }
        if (predicate.operation == "iequals") {
            const auto *lhs = fact_value.as_string();
            const auto *rhs = literal.as_string();
            if (lhs == nullptr || rhs == nullptr) {
                return std::nullopt;
            }
            return string_iequals(*lhs, *rhs);
        }

        const auto lhs = numeric_value(fact_value);
        const auto rhs = numeric_value(literal);
        if (!lhs.has_value() || !rhs.has_value()) {
            return std::nullopt;
        }
        if (predicate.operation == "greater") {
            return lhs->number > rhs->number;
        }
        if (predicate.operation == "greater_equal") {
            return lhs->number >= rhs->number;
        }
        if (predicate.operation == "less") {
            return lhs->number < rhs->number;
        }
        if (predicate.operation == "less_equal") {
            return lhs->number <= rhs->number;
        }
        return std::nullopt;
    }

    [[nodiscard]] std::string predicate_false_reason(const rule_engine::optimizer::CanonicalPredicate &predicate) {
        return predicate.fact_key + " " + predicate.operation + " " + predicate.literal_kind + ":" +
               predicate.literal_value + " evaluated false";
    }

    [[nodiscard]] std::string fact_status_name(const rule_engine::FactStatus status) noexcept {
        using enum rule_engine::FactStatus;
        if (status == missing) {
            return "missing";
        }
        if (status == available) {
            return "available";
        }
        if (status == unavailable) {
            return "unavailable";
        }
        if (status == access_denied) {
            return "access_denied";
        }
        if (status == timed_out) {
            return "timed_out";
        }
        return "unknown";
    }

    [[nodiscard]] std::string value_type_name(const rule_engine::ValueType type) noexcept {
        using enum rule_engine::ValueType;
        if (type == boolean) {
            return "boolean";
        }
        if (type == integer) {
            return "integer";
        }
        if (type == floating) {
            return "floating";
        }
        if (type == string) {
            return "string";
        }
        if (type == bytes) {
            return "bytes";
        }
        if (type == array) {
            return "array";
        }
        if (type == pattern) {
            return "pattern";
        }
        if (type == object) {
            return "object";
        }
        return "undefined";
    }

    [[nodiscard]] std::uint8_t cost_class_rank(const rule_engine::FactCostClass cost_class) noexcept {
        using enum rule_engine::FactCostClass;
        switch (cost_class) {
            case inventory: return 0u;
            case cheap_process_snapshot: return 1u;
            case static_image_header: return 2u;
            case process_array: return 3u;
            case broad_image_array: return 4u;
            case handle_signer: return 5u;
            case memory_region: return 6u;
            case pattern_scan: return 7u;
            case custom: return 8u;
            default: return 8u;
        }
    }

    [[nodiscard]] std::uint64_t observed_selectivity_ppm(const std::size_t matched, const std::size_t total) noexcept {
        if (total == 0u) {
            return 0u;
        }
        return (static_cast<std::uint64_t>(matched) * 1'000'000u) / static_cast<std::uint64_t>(total);
    }

    [[nodiscard]] std::optional<std::uint64_t>
    selectivity_hint(const rule_engine::optimizer::PredicateSelectivityProfile &profile,
                     const std::string_view predicate_id) {
        const auto found = std::ranges::find_if(
            profile.predicates, [&](const auto &observation) { return observation.predicate_id == predicate_id; });
        if (found == profile.predicates.end()) {
            return std::nullopt;
        }
        return found->observed_selectivity_ppm;
    }

    [[nodiscard]] std::vector<const rule_engine::optimizer::CanonicalPredicate *>
    ordered_predicates(const std::span<const rule_engine::optimizer::CanonicalPredicate> predicates,
                       const rule_engine::optimizer::PredicateSelectivityProfile &profile = {}) {
        std::vector<const rule_engine::optimizer::CanonicalPredicate *> out;
        out.reserve(predicates.size());
        for (const auto &predicate : predicates) { out.push_back(&predicate); }
        std::ranges::stable_sort(out, [&](const auto *lhs, const auto *rhs) {
            const auto lhs_rank = cost_class_rank(lhs->cost_class);
            const auto rhs_rank = cost_class_rank(rhs->cost_class);
            if (lhs_rank != rhs_rank) {
                return lhs_rank < rhs_rank;
            }
            const auto lhs_selectivity = selectivity_hint(profile, lhs->id);
            const auto rhs_selectivity = selectivity_hint(profile, rhs->id);
            if (lhs_selectivity.has_value() && rhs_selectivity.has_value() && *lhs_selectivity != *rhs_selectivity) {
                return *lhs_selectivity < *rhs_selectivity;
            }
            return lhs->id < rhs->id;
        });
        return out;
    }

    [[nodiscard]] PredicateEvaluation
    evaluate_predicate_for_subject(const rule_engine::optimizer::CanonicalPredicate &predicate,
                                   const rule_engine::Subject &subject, const rule_engine::FactCache &facts) {
        const auto fact = facts.lookup(subject.id, predicate.fact_key);
        if (!fact.has_value()) {
            return PredicateEvaluation {
                .status = PredicateEvaluationStatus::unknown,
                .reason = "missing fact " + predicate.fact_key,
            };
        }
        if (fact->status != rule_engine::FactStatus::available) {
            return PredicateEvaluation {
                .status = PredicateEvaluationStatus::unknown,
                .reason = "fact " + predicate.fact_key + " status " + fact_status_name(fact->status),
            };
        }
        const auto literal = predicate_literal_value(predicate);
        if (!literal.has_value()) {
            return PredicateEvaluation {
                .status = PredicateEvaluationStatus::unknown,
                .reason = "unsupported literal " + predicate.literal_kind + ":" + predicate.literal_value,
            };
        }
        const auto result = evaluate_predicate_values(predicate, fact->value, *literal);
        if (!result.has_value()) {
            return PredicateEvaluation {
                .status = PredicateEvaluationStatus::unknown,
                .reason = "fact " + predicate.fact_key + " could not be safely evaluated by simulator",
            };
        }
        if (*result) {
            return PredicateEvaluation {.status = PredicateEvaluationStatus::matched, .reason = {}};
        }
        return PredicateEvaluation {
            .status = PredicateEvaluationStatus::not_matched,
            .reason = predicate_false_reason(predicate),
        };
    }

    [[nodiscard]] const rule_engine::RequiredFact *required_fact_for(const rule_engine::VerifiedRule &rule,
                                                                     const std::string_view key) {
        const auto found = std::ranges::find_if(rule.facts, [&](const auto &fact) { return fact.key == key; });
        if (found == rule.facts.end()) {
            return nullptr;
        }
        return &*found;
    }

    [[nodiscard]] std::string join_names(const std::vector<std::string> &names) {
        std::string out;
        for (std::size_t index = 0; index < names.size(); ++index) {
            if (index != 0u) {
                out.push_back('.');
            }
            out += names[index];
        }
        return out;
    }

    [[nodiscard]] std::optional<FactOperand> fact_operand(const rule_engine::VerifiedRule &rule,
                                                          const rule_engine::Expression &expr) {
        if (expr.kind != rule_engine::ExpressionKind::field && expr.kind != rule_engine::ExpressionKind::global) {
            return std::nullopt;
        }

        auto key = expr.bound_key_prefix;
        if (key.empty() && expr.kind == rule_engine::ExpressionKind::field) {
            key = join_names(expr.names);
        }
        if (key.empty() && !expr.text.empty()) {
            key = expr.text;
        }
        if (key.empty()) {
            key = join_names(expr.names);
        }
        if (key.empty()) {
            return std::nullopt;
        }

        const auto *required_fact = required_fact_for(rule, key);
        if (required_fact == nullptr && expr.bound_route.empty()) {
            return std::nullopt;
        }
        auto route = expr.bound_route.empty() ? required_fact->route : expr.bound_route;
        const auto cost_class = required_fact == nullptr ? expr.bound_cost_class : required_fact->cost_class;
        return FactOperand {.key = std::move(key), .route = std::move(route), .cost_class = cost_class};
    }

    [[nodiscard]] std::optional<ExtractedPredicate> extract_predicate(const rule_engine::VerifiedRule &rule,
                                                                      const rule_engine::Expression &expr) {
        if (!is_predicate_operation(expr.kind) || expr.children.size() != 2u) {
            return std::nullopt;
        }

        auto fact = fact_operand(rule, expr.children[0]);
        auto literal = literal_value(expr.children[1]);
        auto operation = std::optional<rule_engine::ExpressionKind> {expr.kind};
        if (!fact.has_value() || !literal.has_value()) {
            fact = fact_operand(rule, expr.children[1]);
            literal = literal_value(expr.children[0]);
            operation = flipped_order_operation(expr.kind);
        }
        if (!fact.has_value() || !literal.has_value() || !operation.has_value()) {
            return std::nullopt;
        }

        ExtractedPredicate out;
        out.fact_key = std::move(fact->key);
        out.route = std::move(fact->route);
        out.cost_class = fact->cost_class;
        out.operation = std::string {operation_name(*operation)};
        out.literal_kind = std::move(literal->kind);
        out.literal_value = std::move(literal->value);
        out.id =
            out.route + "|" + out.fact_key + "|" + out.operation + "|" + out.literal_kind + ":" + out.literal_value;
        return out;
    }

    [[nodiscard]] std::optional<std::string_view> exact_only_reason(const rule_engine::ExpressionKind kind) noexcept {
        using enum rule_engine::ExpressionKind;
        if (kind == with_expr) {
            return "with expressions remain exact-VM-only";
        }
        if (kind == for_in_expr) {
            return "for-in expressions remain exact-VM-only";
        }
        if (kind == for_of_expr) {
            return "for-of expressions remain exact-VM-only";
        }
        if (kind == of_expr) {
            return "of expressions remain exact-VM-only";
        }
        if (kind == lookup_expr) {
            return "lookup expressions remain exact-VM-only";
        }
        if (kind == function_call) {
            return "dynamic function calls remain exact-VM-only";
        }
        return std::nullopt;
    }

    void append_json_string(std::string &out, const std::string_view value) {
        out.push_back('"');
        for (const auto raw : value) {
            const auto ch = static_cast<unsigned char>(raw);
            switch (ch) {
                case '"': out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\b': out += "\\b"; break;
                case '\f': out += "\\f"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default:
                    if (ch < 0x20u) {
                        constexpr char digits[] = "0123456789abcdef";
                        out += "\\u00";
                        out.push_back(digits[(ch >> 4u) & 0x0fu]);
                        out.push_back(digits[ch & 0x0fu]);
                        break;
                    }
                    out.push_back(static_cast<char>(ch));
                    break;
            }
        }
        out.push_back('"');
    }

    void append_key(std::string &out, const std::string_view key) {
        append_json_string(out, key);
        out.push_back(':');
    }

    void append_key_string(std::string &out, const std::string_view key, const std::string_view value) {
        append_key(out, key);
        append_json_string(out, value);
    }

    void append_key_size(std::string &out, const std::string_view key, const std::size_t value) {
        append_key(out, key);
        out += std::to_string(value);
    }

    void append_key_u64(std::string &out, const std::string_view key, const std::uint64_t value) {
        append_key(out, key);
        out += std::to_string(value);
    }

    void append_key_bool(std::string &out, const std::string_view key, const bool value) {
        append_key(out, key);
        out += value ? "true" : "false";
    }

    void append_string_array(std::string &out, const std::vector<std::string> &values) {
        out.push_back('[');
        for (std::size_t index = 0; index < values.size(); ++index) {
            if (index != 0u) {
                out.push_back(',');
            }
            append_json_string(out, values[index]);
        }
        out.push_back(']');
    }

    void append_source_span(std::string &out, const rule_engine::SourceSpan &span) {
        out.push_back('{');
        append_key_string(out, "source", span.source);
        out.push_back(',');
        append_key_u64(out, "sourceId", span.source_id);
        out.push_back(',');
        append_key_size(out, "start", span.start);
        out.push_back(',');
        append_key_size(out, "end", span.end);
        out.push_back('}');
    }

    void append_optimizer_trace_events(std::string &out,
                                       const std::vector<rule_engine::optimizer::OptimizerTraceEvent> &events) {
        out.push_back('[');
        for (std::size_t index = 0; index < events.size(); ++index) {
            if (index != 0u) {
                out.push_back(',');
            }
            const auto &event = events[index];
            out.push_back('{');
            append_key_string(out, "event", event.event);
            out.push_back(',');
            append_key_string(out, "predicateId", event.predicate_id);
            out.push_back(',');
            append_key_string(out, "rule", event.rule_identifier);
            out.push_back(',');
            append_key_string(out, "subject", event.subject_id);
            out.push_back(',');
            append_key_string(out, "reason", event.reason);
            out.push_back(',');
            append_key_string(out, "costClass", rule_engine::fact_cost_class_name(event.cost_class));
            out.push_back(',');
            append_key(out, "sourceSpan");
            append_source_span(out, event.span);
            out.push_back(',');
            append_key_u64(out, "matchedSubjectCount", event.matched_subject_count);
            out.push_back(',');
            append_key_u64(out, "candidateSubjectCount", event.candidate_subject_count);
            out.push_back(',');
            append_key_u64(out, "candidateSetBytes", event.candidate_set_bytes);
            out.push_back('}');
        }
        out.push_back(']');
    }

    void append_subject_reasons(std::string &out,
                                const std::vector<rule_engine::optimizer::PredicateSubjectReason> &subjects) {
        out.push_back('[');
        for (std::size_t index = 0; index < subjects.size(); ++index) {
            if (index != 0u) {
                out.push_back(',');
            }
            out.push_back('{');
            append_key_string(out, "subject", subjects[index].subject_id);
            out.push_back(',');
            append_key_string(out, "reason", subjects[index].reason);
            out.push_back('}');
        }
        out.push_back(']');
    }
} // namespace

namespace rule_engine::optimizer {
    StaticFactIdentityFactKeys pe_static_fact_identity_fact_keys() {
        return StaticFactIdentityFactKeys {
            .path = "pe.identity.path",
            .file_id = "pe.identity.file_id",
            .file_size = "pe.identity.file_size",
            .last_write_time = "pe.identity.last_write_time",
            .content_hash = {},
            .signature_identity = {},
            .scan_space_name = "pe.identity.scan_space_name",
            .scan_space_version = "pe.identity.scan_space_version",
        };
    }

    namespace {
        [[nodiscard]] std::vector<std::string> reportable_rule_ids(const VerifiedProgram &program) {
            std::vector<std::string> out;
            for (const auto &rule : program.rules) {
                if (rule.is_global || rule.is_private) {
                    continue;
                }
                out.push_back(rule_identifier(rule));
            }
            return out;
        }

        void add_owner(CanonicalPredicateReport &report, ExtractedPredicate predicate, CanonicalPredicateOwner owner) {
            auto found = std::ranges::find_if(report.predicates,
                                              [&](const auto &existing) { return existing.id == predicate.id; });
            if (found == report.predicates.end()) {
                CanonicalPredicate item;
                item.id = std::move(predicate.id);
                item.fact_key = std::move(predicate.fact_key);
                item.route = std::move(predicate.route);
                item.cost_class = predicate.cost_class;
                item.operation = std::move(predicate.operation);
                item.literal_kind = std::move(predicate.literal_kind);
                item.literal_value = std::move(predicate.literal_value);
                item.owners.push_back(std::move(owner));
                report.predicates.push_back(std::move(item));
                return;
            }
            found->owners.push_back(std::move(owner));
        }

        [[nodiscard]] bool expression_blocks_later_pruning(const VerifiedRule &rule, const Expression &expr) {
            if (extract_predicate(rule, expr).has_value()) {
                return false;
            }
            if (exact_only_reason(expr.kind).has_value()) {
                return true;
            }
            if (expr.kind == ExpressionKind::and_expr) {
                return std::ranges::any_of(
                    expr.children, [&](const auto &child) { return expression_blocks_later_pruning(rule, child); });
            }
            return !expr.children.empty();
        }

        void visit_expression(CanonicalPredicateReport &report, const VerifiedRule &rule, const Expression &expr,
                              const bool required_context) {
            if (const auto reason = exact_only_reason(expr.kind); reason.has_value()) {
                report.exact_vm_only.push_back(ExactVmOnlyExpression {
                    .rule_identifier = rule_identifier(rule),
                    .reason = std::string {*reason},
                    .expression_kind = expr.kind,
                    .span = expr.span,
                });
                return;
            }

            if (auto predicate = extract_predicate(rule, expr); predicate.has_value()) {
                add_owner(report, std::move(*predicate),
                          CanonicalPredicateOwner {
                              .rule_identifier = rule_identifier(rule),
                              .span = expr.span,
                              .prune_safe = required_context,
                          });
                return;
            }

            if (expr.kind == ExpressionKind::and_expr) {
                bool child_prune_safe = required_context;
                for (const auto &child : expr.children) {
                    visit_expression(report, rule, child, child_prune_safe);
                    if (expression_blocks_later_pruning(rule, child)) {
                        child_prune_safe = false;
                    }
                }
                return;
            }
            if (expr.kind == ExpressionKind::or_expr || expr.kind == ExpressionKind::not_expr) {
                for (const auto &child : expr.children) { visit_expression(report, rule, child, false); }
                return;
            }

            for (const auto &child : expr.children) { visit_expression(report, rule, child, false); }
        }

        [[nodiscard]] std::size_t owner_count(const CanonicalPredicateReport &report) noexcept {
            std::size_t out {};
            for (const auto &predicate : report.predicates) { out += predicate.owners.size(); }
            return out;
        }

        [[nodiscard]] std::vector<std::string> subject_ids(const std::span<const Subject> subjects) {
            std::vector<std::string> out;
            out.reserve(subjects.size());
            for (const auto &subject : subjects) { out.push_back(subject.id); }
            return out;
        }

        struct CandidateSetStorageEstimate {
            rule_engine::optimizer::CandidateSetRepresentation representation {
                rule_engine::optimizer::CandidateSetRepresentation::dense_bitset};
            std::uint64_t bytes {};
        };

        [[nodiscard]] std::uint64_t dense_candidate_set_bytes(const std::size_t universe_size) noexcept {
            return static_cast<std::uint64_t>((universe_size + 7u) / 8u);
        }

        [[nodiscard]] std::uint64_t compact_subject_id_width_bytes(const std::size_t universe_size) noexcept {
            const auto max_subject_index = universe_size == 0u ? 0u : static_cast<std::uint64_t>(universe_size - 1u);
            if (max_subject_index <= std::numeric_limits<std::uint8_t>::max()) {
                return 1u;
            }
            if (max_subject_index <= std::numeric_limits<std::uint16_t>::max()) {
                return 2u;
            }
            if (max_subject_index <= std::numeric_limits<std::uint32_t>::max()) {
                return 4u;
            }
            return 8u;
        }

        [[nodiscard]] CandidateSetStorageEstimate
        estimate_candidate_set_storage(const std::size_t candidate_count, const std::size_t universe_size) noexcept {
            const auto dense_bytes = dense_candidate_set_bytes(universe_size);
            const auto sparse_bytes =
                static_cast<std::uint64_t>(candidate_count) * compact_subject_id_width_bytes(universe_size);
            if (sparse_bytes < dense_bytes) {
                return CandidateSetStorageEstimate {
                    .representation = rule_engine::optimizer::CandidateSetRepresentation::sparse_ids,
                    .bytes = sparse_bytes,
                };
            }
            return CandidateSetStorageEstimate {
                .representation = rule_engine::optimizer::CandidateSetRepresentation::dense_bitset,
                .bytes = dense_bytes,
            };
        }

        void refresh_candidate_set_storage(rule_engine::optimizer::RuleCandidateSet &candidate_set,
                                           const std::size_t universe_size) noexcept {
            const auto estimate =
                estimate_candidate_set_storage(candidate_set.candidate_subject_ids.size(), universe_size);
            candidate_set.representation = estimate.representation;
            candidate_set.candidate_set_bytes = estimate.bytes;
        }

        void refresh_candidate_set_stats(rule_engine::optimizer::SharedPredicateDagSimulation &simulation,
                                         const std::size_t universe_size) noexcept {
            simulation.dropped_rule_branches = 0u;
            for (auto &candidate_set : simulation.rule_candidates) {
                refresh_candidate_set_storage(candidate_set, universe_size);
                candidate_set.dropped = candidate_set.candidate_subject_ids.empty();
                if (candidate_set.dropped) {
                    ++simulation.dropped_rule_branches;
                }
                simulation.peak_candidate_set_subjects =
                    std::max(simulation.peak_candidate_set_subjects, candidate_set.candidate_subject_ids.size());
                simulation.peak_candidate_set_bytes =
                    std::max(simulation.peak_candidate_set_bytes, candidate_set.candidate_set_bytes);
            }
        }

        void finalize_predicate_node(rule_engine::optimizer::PredicateNodeSimulation &node,
                                     const std::size_t subject_count) noexcept {
            node.matched_subject_count = static_cast<std::uint64_t>(node.matched_subject_ids.size());
            node.observed_selectivity_ppm = observed_selectivity_ppm(node.matched_subject_ids.size(), subject_count);
            node.nonselective = subject_count != 0u && node.matched_subject_ids.size() == subject_count &&
                                node.pruned_subjects.empty() && node.unknown_subjects.empty();
            node.retained_matched_subjects = !node.nonselective;
            if (node.nonselective) {
                std::vector<std::string> {}.swap(node.matched_subject_ids);
            }
        }

        [[nodiscard]] SourceSpan first_owner_span(const rule_engine::optimizer::CanonicalPredicate &predicate) {
            if (predicate.owners.empty()) {
                return {};
            }
            return predicate.owners.front().span;
        }

        void trace_predicate_ordered(rule_engine::optimizer::SharedPredicateDagSimulation &simulation,
                                     const rule_engine::optimizer::CanonicalPredicate &predicate,
                                     std::string reason = "static descriptor cost order") {
            simulation.trace_events.push_back(OptimizerTraceEvent {
                .event = "predicate_ordered",
                .predicate_id = predicate.id,
                .rule_identifier = {},
                .subject_id = {},
                .reason = std::move(reason),
                .cost_class = predicate.cost_class,
                .span = first_owner_span(predicate),
                .matched_subject_count = 0u,
                .candidate_subject_count = 0u,
                .candidate_set_bytes = 0u,
            });
        }

        void trace_predicate_nonselective(rule_engine::optimizer::SharedPredicateDagSimulation &simulation,
                                          const rule_engine::optimizer::PredicateNodeSimulation &node,
                                          const rule_engine::optimizer::CanonicalPredicate &predicate) {
            simulation.trace_events.push_back(OptimizerTraceEvent {
                .event = "predicate_nonselective",
                .predicate_id = predicate.id,
                .rule_identifier = {},
                .subject_id = {},
                .reason = "predicate matched every subject; matched subjects elided",
                .cost_class = predicate.cost_class,
                .span = first_owner_span(predicate),
                .matched_subject_count = node.matched_subject_count,
                .candidate_subject_count = node.matched_subject_count,
                .candidate_set_bytes = 0u,
            });
        }

        [[nodiscard]] std::string
        candidate_provider_fallback_reason(const rule_engine::optimizer::CandidateProviderRequest &request,
                                           const rule_engine::optimizer::CandidateProviderResult *result) {
            std::string reason = "candidate provider " + request.filter_key + " unavailable: ";
            if (result == nullptr) {
                reason += "result missing";
            } else if (!result->diagnostic.empty()) {
                reason += result->diagnostic;
            } else {
                reason += "status " + fact_status_name(result->status);
            }
            reason += "; falling back to server-side predicate evaluation";
            return reason;
        }

        void trace_candidate_provider_fallback(rule_engine::optimizer::SharedPredicateDagSimulation &simulation,
                                               const rule_engine::optimizer::CanonicalPredicate &predicate,
                                               const rule_engine::optimizer::CandidateProviderRequest &request,
                                               const rule_engine::optimizer::CandidateProviderResult *result,
                                               const std::size_t subject_count) {
            const auto storage = estimate_candidate_set_storage(subject_count, subject_count);
            simulation.trace_events.push_back(OptimizerTraceEvent {
                .event = "candidate_provider_fallback",
                .predicate_id = predicate.id,
                .rule_identifier = {},
                .subject_id = {},
                .reason = candidate_provider_fallback_reason(request, result),
                .cost_class = predicate.cost_class,
                .span = first_owner_span(predicate),
                .matched_subject_count = 0u,
                .candidate_subject_count = static_cast<std::uint64_t>(subject_count),
                .candidate_set_bytes = storage.bytes,
            });
        }

        [[nodiscard]] RuleCandidateSet *find_rule_candidates(SharedPredicateDagSimulation &simulation,
                                                             const std::string_view rule) {
            const auto found = std::ranges::find_if(simulation.rule_candidates, [&](const auto &candidate_set) {
                return candidate_set.rule_identifier == rule;
            });
            if (found == simulation.rule_candidates.end()) {
                return nullptr;
            }
            return &*found;
        }

        void prune_rule_subject(SharedPredicateDagSimulation &simulation, const CanonicalPredicateOwner &owner,
                                const CanonicalPredicate &predicate, const std::string &subject_id,
                                const std::string &reason, const std::size_t universe_size) {
            if (!owner.prune_safe) {
                return;
            }
            auto *candidate_set = find_rule_candidates(simulation, owner.rule_identifier);
            if (candidate_set == nullptr) {
                return;
            }
            const auto before = candidate_set->candidate_subject_ids.size();
            std::erase(candidate_set->candidate_subject_ids, subject_id);
            if (candidate_set->candidate_subject_ids.size() == before) {
                return;
            }
            candidate_set->pruned_subjects.push_back(RulePrunedSubject {
                .subject_id = subject_id,
                .predicate_id = predicate.id,
                .reason = reason,
            });
            const auto storage =
                estimate_candidate_set_storage(candidate_set->candidate_subject_ids.size(), universe_size);
            simulation.trace_events.push_back(OptimizerTraceEvent {
                .event = "rule_subject_pruned",
                .predicate_id = predicate.id,
                .rule_identifier = owner.rule_identifier,
                .subject_id = subject_id,
                .reason = reason,
                .cost_class = predicate.cost_class,
                .span = owner.span,
                .matched_subject_count = 0u,
                .candidate_subject_count = static_cast<std::uint64_t>(candidate_set->candidate_subject_ids.size()),
                .candidate_set_bytes = storage.bytes,
            });
            ++simulation.pruned_rule_subjects;
        }

        void prune_rule_subject_by_set_operation(SharedPredicateDagSimulation &simulation,
                                                 const std::string_view rule_identifier,
                                                 const std::string &operation_id, const std::string &subject_id,
                                                 const std::string &reason, const std::size_t universe_size) {
            auto *candidate_set = find_rule_candidates(simulation, rule_identifier);
            if (candidate_set == nullptr) {
                return;
            }
            const auto before = candidate_set->candidate_subject_ids.size();
            std::erase(candidate_set->candidate_subject_ids, subject_id);
            if (candidate_set->candidate_subject_ids.size() == before) {
                return;
            }
            candidate_set->pruned_subjects.push_back(RulePrunedSubject {
                .subject_id = subject_id,
                .predicate_id = operation_id,
                .reason = reason,
            });
            const auto storage =
                estimate_candidate_set_storage(candidate_set->candidate_subject_ids.size(), universe_size);
            simulation.trace_events.push_back(OptimizerTraceEvent {
                .event = "rule_subject_pruned",
                .predicate_id = operation_id,
                .rule_identifier = std::string {rule_identifier},
                .subject_id = subject_id,
                .reason = reason,
                .cost_class = FactCostClass::custom,
                .span = {},
                .matched_subject_count = 0u,
                .candidate_subject_count = static_cast<std::uint64_t>(candidate_set->candidate_subject_ids.size()),
                .candidate_set_bytes = storage.bytes,
            });
            ++simulation.pruned_rule_subjects;
        }

        [[nodiscard]] bool contains_string(const std::vector<std::string> &values,
                                           const std::string_view value) noexcept {
            return std::ranges::find(values, value) != values.end();
        }

        [[nodiscard]] bool contains_rule_id(const std::span<const std::string> values,
                                            const std::string_view value) noexcept {
            return std::ranges::find(values, value) != values.end();
        }

        void append_unique(std::vector<std::string> &values, const std::string &value) {
            if (!contains_string(values, value)) {
                values.push_back(value);
            }
        }

        [[nodiscard]] bool same_provider_requirement(const OptimizerPlanProviderRequirement &requirement,
                                                     const RequiredFact &fact) noexcept {
            return requirement.route == fact.route && requirement.key == fact.key && requirement.type == fact.type &&
                   requirement.cost_class == fact.cost_class && requirement.cheap_prefetch == fact.cheap_prefetch;
        }

        void add_provider_requirement(OptimizerPlan &plan, const RequiredFact &fact, const std::string &rule_id) {
            auto found = std::ranges::find_if(plan.provider_requirements, [&](const auto &requirement) {
                return same_provider_requirement(requirement, fact);
            });
            if (found == plan.provider_requirements.end()) {
                plan.provider_requirements.push_back(OptimizerPlanProviderRequirement {
                    .route = fact.route,
                    .key = fact.key,
                    .type = fact.type,
                    .cost_class = fact.cost_class,
                    .cheap_prefetch = fact.cheap_prefetch,
                    .rule_identifiers = {rule_id},
                });
                return;
            }
            append_unique(found->rule_identifiers, rule_id);
        }

        [[nodiscard]] std::optional<DiscoveryGate>
        discovery_gate_for_predicate(const CanonicalPredicate &predicate,
                                     const std::span<const std::string> required_rule_ids) {
            if (required_rule_ids.empty()) {
                return std::nullopt;
            }

            std::vector<std::string> covered_rules;
            SourceSpan span;
            for (const auto &owner : predicate.owners) {
                if (!owner.prune_safe || !contains_rule_id(required_rule_ids, owner.rule_identifier)) {
                    continue;
                }
                if (covered_rules.empty()) {
                    span = owner.span;
                }
                append_unique(covered_rules, owner.rule_identifier);
            }

            for (const auto &rule_id : required_rule_ids) {
                if (!contains_string(covered_rules, rule_id)) {
                    return std::nullopt;
                }
            }

            return DiscoveryGate {
                .predicate_id = predicate.id,
                .fact_key = predicate.fact_key,
                .route = predicate.route,
                .cost_class = predicate.cost_class,
                .operation = predicate.operation,
                .literal_kind = predicate.literal_kind,
                .literal_value = predicate.literal_value,
                .span = span,
                .rule_identifiers = std::move(covered_rules),
            };
        }

        void trace_discovery_gate_ordered(DiscoveryGateSimulation &simulation, const DiscoveryGate &gate) {
            simulation.trace_events.push_back(OptimizerTraceEvent {
                .event = "discovery_gate_ordered",
                .predicate_id = gate.predicate_id,
                .rule_identifier = {},
                .subject_id = {},
                .reason = "pack-level predicate shared by all reportable rules",
                .cost_class = gate.cost_class,
                .span = gate.span,
                .matched_subject_count = 0u,
                .candidate_subject_count = 0u,
                .candidate_set_bytes = 0u,
            });
        }

        void trace_discovery_gate_pack_skipped(DiscoveryGateSimulation &simulation, const DiscoveryGate &gate) {
            simulation.trace_events.push_back(OptimizerTraceEvent {
                .event = "discovery_gate_pack_skipped",
                .predicate_id = gate.predicate_id,
                .rule_identifier = {},
                .subject_id = {},
                .reason = simulation.skip_reason,
                .cost_class = gate.cost_class,
                .span = gate.span,
                .matched_subject_count = 0u,
                .candidate_subject_count = 0u,
                .candidate_set_bytes = 0u,
            });
        }

        [[nodiscard]] std::vector<std::string> simulation_subject_ids(const SharedPredicateDagSimulation &simulation) {
            std::vector<std::string> out;
            for (const auto &candidate_set : simulation.rule_candidates) {
                for (const auto &subject_id : candidate_set.candidate_subject_ids) { append_unique(out, subject_id); }
                for (const auto &pruned : candidate_set.pruned_subjects) { append_unique(out, pruned.subject_id); }
            }
            return out;
        }

        [[nodiscard]] const RuleCandidateSet *find_rule_candidates(const SharedPredicateDagSimulation &simulation,
                                                                   const std::string_view rule) {
            const auto found = std::ranges::find_if(simulation.rule_candidates, [&](const auto &candidate_set) {
                return candidate_set.rule_identifier == rule;
            });
            if (found == simulation.rule_candidates.end()) {
                return nullptr;
            }
            return &*found;
        }

        [[nodiscard]] const PredicateNodeSimulation *find_predicate_node(const SharedPredicateDagSimulation &simulation,
                                                                         const std::string_view predicate_id) {
            const auto found = std::ranges::find_if(
                simulation.predicate_nodes, [&](const auto &node) { return node.predicate_id == predicate_id; });
            if (found == simulation.predicate_nodes.end()) {
                return nullptr;
            }
            return &*found;
        }

        [[nodiscard]] const CanonicalPredicate *find_predicate(const CanonicalPredicateReport &report,
                                                               const std::string_view predicate_id) {
            const auto found = std::ranges::find_if(
                report.predicates, [&](const auto &predicate) { return predicate.id == predicate_id; });
            if (found == report.predicates.end()) {
                return nullptr;
            }
            return &*found;
        }

        [[nodiscard]] std::optional<std::vector<std::string>>
        simple_or_predicate_ids(const VerifiedRule &rule, const CanonicalPredicateReport &report) {
            if (rule.condition.kind != ExpressionKind::or_expr || rule.condition.children.size() < 2u) {
                return std::nullopt;
            }

            std::vector<std::string> out;
            out.reserve(rule.condition.children.size());
            for (const auto &child : rule.condition.children) {
                auto predicate = extract_predicate(rule, child);
                if (!predicate.has_value() || find_predicate(report, predicate->id) == nullptr) {
                    return std::nullopt;
                }
                out.push_back(std::move(predicate->id));
            }
            return out;
        }

        [[nodiscard]] bool predicate_node_matched_subject(const PredicateNodeSimulation &node,
                                                          const std::string_view subject_id) noexcept {
            if (node.nonselective) {
                return true;
            }
            return contains_string(node.matched_subject_ids, subject_id);
        }

        [[nodiscard]] bool predicate_node_unknown_subject(const PredicateNodeSimulation &node,
                                                          const std::string_view subject_id) noexcept {
            return std::ranges::any_of(node.unknown_subjects,
                                       [&](const auto &unknown) { return unknown.subject_id == subject_id; });
        }

        [[nodiscard]] bool simple_or_union_can_prune_subject(const SharedPredicateDagSimulation &simulation,
                                                             const std::span<const std::string> predicate_ids,
                                                             const std::string_view subject_id) {
            bool any_match {};
            bool any_unknown {};
            for (const auto &predicate_id : predicate_ids) {
                const auto *node = find_predicate_node(simulation, predicate_id);
                if (node == nullptr) {
                    return false;
                }
                any_match = any_match || predicate_node_matched_subject(*node, subject_id);
                any_unknown = any_unknown || predicate_node_unknown_subject(*node, subject_id);
            }
            return !any_match && !any_unknown;
        }

        void apply_simple_or_union_pruning(const VerifiedProgram &program, const CanonicalPredicateReport &report,
                                           const std::span<const Subject> subjects,
                                           SharedPredicateDagSimulation &simulation) {
            constexpr std::string_view reason {"all lifted OR alternatives evaluated false"};
            for (const auto &rule : program.rules) {
                auto predicate_ids = simple_or_predicate_ids(rule, report);
                if (!predicate_ids.has_value()) {
                    continue;
                }

                const auto rule_id = rule_identifier(rule);
                const auto operation_id = "or_union:" + rule_id;
                for (const auto &subject : subjects) {
                    if (simple_or_union_can_prune_subject(simulation, *predicate_ids, subject.id)) {
                        prune_rule_subject_by_set_operation(simulation, rule_id, operation_id, subject.id,
                                                            std::string {reason}, subjects.size());
                    }
                }
            }
            refresh_candidate_set_stats(simulation, subjects.size());
        }

        [[nodiscard]] LazyProviderExpansionRequest *find_lazy_request(LazyProviderExpansionPlan &plan,
                                                                      const RequiredFact &fact) {
            const auto found = std::ranges::find_if(plan.requests, [&](const auto &request) {
                return request.route == fact.route && request.key == fact.key && request.type == fact.type;
            });
            if (found == plan.requests.end()) {
                return nullptr;
            }
            return &*found;
        }

        [[nodiscard]] std::vector<std::string>
        avoided_subject_ids(const std::vector<std::string> &all_subject_ids,
                            const std::vector<std::string> &requested_subject_ids) {
            std::vector<std::string> out;
            for (const auto &subject_id : all_subject_ids) {
                if (!contains_string(requested_subject_ids, subject_id)) {
                    out.push_back(subject_id);
                }
            }
            return out;
        }

        [[nodiscard]] bool has_prune_safe_owner(const CanonicalPredicate &predicate) {
            return std::ranges::any_of(predicate.owners, [](const auto &owner) { return owner.prune_safe; });
        }

        [[nodiscard]] std::optional<CandidateProviderRequest>
        candidate_provider_request_for(const CanonicalPredicate &predicate) {
            if (!has_prune_safe_owner(predicate)) {
                return std::nullopt;
            }
            if (predicate.fact_key == "process.name" && predicate.operation == "equal" &&
                predicate.literal_kind == "string") {
                return CandidateProviderRequest {
                    .id = "process.inventory.by_image_name|string:" + predicate.literal_value,
                    .route = "endpoint.process.inventory",
                    .filter_key = "process.inventory.by_image_name",
                    .argument_kind = predicate.literal_kind,
                    .argument_value = predicate.literal_value,
                    .predicate_ids = {predicate.id},
                    .rule_identifiers = {},
                };
            }
            return std::nullopt;
        }

        [[nodiscard]] CandidateProviderRequest *find_candidate_request(CandidateProviderRequestPlan &plan,
                                                                       const std::string_view id) {
            const auto found =
                std::ranges::find_if(plan.requests, [&](const auto &request) { return request.id == id; });
            if (found == plan.requests.end()) {
                return nullptr;
            }
            return &*found;
        }

        [[nodiscard]] const CandidateProviderRequest *
        find_candidate_request_for_predicate(const CandidateProviderRequestPlan &plan,
                                             const std::string_view predicate_id) {
            const auto found = std::ranges::find_if(plan.requests, [&](const auto &request) {
                return contains_string(request.predicate_ids, predicate_id);
            });
            if (found == plan.requests.end()) {
                return nullptr;
            }
            return &*found;
        }

        [[nodiscard]] const CandidateProviderResult *
        find_candidate_result(const std::span<const CandidateProviderResult> results,
                              const std::string_view request_id) {
            const auto found =
                std::ranges::find_if(results, [&](const auto &result) { return result.request_id == request_id; });
            if (found == results.end()) {
                return nullptr;
            }
            return &*found;
        }

        [[nodiscard]] bool candidate_provider_result_available(const CandidateProviderResult &result) noexcept {
            return result.available || result.status == FactStatus::available;
        }

        [[nodiscard]] bool candidate_provider_result_covers_subjects(const CandidateProviderResult &result,
                                                                     const std::span<const Subject> subjects) {
            if (subjects.empty()) {
                return false;
            }
            return std::ranges::all_of(
                subjects, [&](const auto &subject) { return contains_string(result.subject_ids, subject.id); });
        }

        void add_candidate_provider_subjects(CandidateProviderSimulation &simulation,
                                             const std::span<const CandidateProviderResult> provider_results,
                                             const std::span<const Subject> subjects) {
            simulation.provider_requests = static_cast<std::uint64_t>(simulation.request_plan.requests.size());
            for (const auto &request : simulation.request_plan.requests) {
                const auto *result = find_candidate_result(provider_results, request.id);
                if (result == nullptr || !candidate_provider_result_available(*result)) {
                    continue;
                }
                simulation.candidate_subjects_returned += static_cast<std::uint64_t>(result->subject_ids.size());
                if (candidate_provider_result_covers_subjects(*result, subjects)) {
                    ++simulation.broad_results;
                }
            }
        }

        [[nodiscard]] bool source_spans_equal(const SourceSpan &lhs, const SourceSpan &rhs) noexcept {
            return lhs.source_id == rhs.source_id && lhs.start == rhs.start && lhs.end == rhs.end &&
                   lhs.source == rhs.source;
        }

        [[nodiscard]] bool diagnostics_equal(const std::vector<Diagnostic> &lhs,
                                             const std::vector<Diagnostic> &rhs) noexcept {
            if (lhs.size() != rhs.size()) {
                return false;
            }
            for (std::size_t index = 0; index < lhs.size(); ++index) {
                if (lhs[index].source != rhs[index].source || lhs[index].message != rhs[index].message ||
                    !source_spans_equal(lhs[index].span, rhs[index].span)) {
                    return false;
                }
            }
            return true;
        }

        [[nodiscard]] bool rule_results_equal(const RuleResult &lhs, const RuleResult &rhs) noexcept {
            return lhs.identifier == rhs.identifier && lhs.matched == rhs.matched &&
                   diagnostics_equal(lhs.diagnostics, rhs.diagnostics);
        }

        [[nodiscard]] const RuleResult *find_rule_result(const std::vector<RuleResult> &results,
                                                         const std::string_view identifier) {
            const auto found =
                std::ranges::find_if(results, [&](const auto &result) { return result.identifier == identifier; });
            if (found == results.end()) {
                return nullptr;
            }
            return &*found;
        }

        [[nodiscard]] bool subject_pruned_by_rule(const RuleCandidateSet &candidate_set,
                                                  const std::string_view subject_id) {
            return std::ranges::any_of(candidate_set.pruned_subjects,
                                       [&](const auto &pruned) { return pruned.subject_id == subject_id; });
        }

        [[nodiscard]] const RulePrunedSubject *find_pruned_subject(const RuleCandidateSet &candidate_set,
                                                                   const std::string_view subject_id) {
            const auto found = std::ranges::find_if(
                candidate_set.pruned_subjects, [&](const auto &pruned) { return pruned.subject_id == subject_id; });
            if (found == candidate_set.pruned_subjects.end()) {
                return nullptr;
            }
            return &*found;
        }

        [[nodiscard]] std::optional<OptimizerTraceEvent>
        exact_vm_skip_trace_event(const CanonicalPredicateReport &report, const std::string &subject_id,
                                  const RuleCandidateSet &candidate_set) {
            const auto *pruned = find_pruned_subject(candidate_set, subject_id);
            if (pruned == nullptr) {
                return std::nullopt;
            }

            OptimizerTraceEvent event {
                .event = "exact_vm_rule_skipped",
                .predicate_id = pruned->predicate_id,
                .rule_identifier = candidate_set.rule_identifier,
                .subject_id = subject_id,
                .reason = "exact VM skipped because " + pruned->reason,
                .cost_class = FactCostClass::custom,
                .span = {},
                .matched_subject_count = 0u,
                .candidate_subject_count = static_cast<std::uint64_t>(candidate_set.candidate_subject_ids.size()),
                .candidate_set_bytes = candidate_set.candidate_set_bytes,
            };
            if (const auto *predicate = find_predicate(report, pruned->predicate_id); predicate != nullptr) {
                event.cost_class = predicate->cost_class;
                const auto owner = std::ranges::find_if(predicate->owners, [&](const auto &predicate_owner) {
                    return predicate_owner.rule_identifier == candidate_set.rule_identifier;
                });
                if (owner != predicate->owners.end()) {
                    event.span = owner->span;
                }
            }
            return event;
        }

        void append_exact_vm_skip_trace(PrefilteredEvaluationComparison &comparison,
                                        const CanonicalPredicateReport &report, const std::string &subject_id,
                                        const RuleCandidateSet &candidate_set) {
            auto event = exact_vm_skip_trace_event(report, subject_id, candidate_set);
            if (event.has_value()) {
                comparison.trace_events.push_back(std::move(*event));
            }
        }

        [[nodiscard]] std::vector<std::string>
        exact_vm_rule_ids_for_subject(const VerifiedProgram &program, const SharedPredicateDagSimulation &simulation,
                                      const std::string_view subject_id) {
            std::vector<std::string> out;
            for (const auto &rule : program.rules) {
                if (rule.is_global || rule.is_private) {
                    continue;
                }
                const auto id = rule_identifier(rule);
                const auto *candidate_set = find_rule_candidates(simulation, id);
                if (candidate_set == nullptr || contains_string(candidate_set->candidate_subject_ids, subject_id)) {
                    out.push_back(id);
                }
            }
            return out;
        }

        [[nodiscard]] std::uint64_t reportable_rule_result_count(const VerifiedProgram &program,
                                                                 const std::vector<RuleResult> &results) {
            const auto reportable_ids = reportable_rule_ids(program);
            std::uint64_t out {};
            for (const auto &result : results) {
                if (contains_string(reportable_ids, result.identifier)) {
                    ++out;
                }
            }
            return out;
        }

        [[nodiscard]] std::vector<std::string>
        pruned_rule_ids_for_subject(const VerifiedProgram &program, const SharedPredicateDagSimulation &simulation,
                                    const std::string_view subject_id) {
            std::vector<std::string> out;
            for (const auto &rule : program.rules) {
                if (rule.is_global || rule.is_private) {
                    continue;
                }
                const auto id = rule_identifier(rule);
                const auto *candidate_set = find_rule_candidates(simulation, id);
                if (candidate_set != nullptr && subject_pruned_by_rule(*candidate_set, subject_id)) {
                    out.push_back(id);
                }
            }
            return out;
        }

        [[nodiscard]] RuleResult pruned_rule_result(std::string identifier) {
            RuleResult out;
            out.identifier = std::move(identifier);
            out.matched = false;
            return out;
        }

        [[nodiscard]] std::vector<RuleResult>
        compose_prefiltered_results(const std::vector<RuleResult> &baseline_results,
                                    const std::vector<RuleResult> &exact_vm_results,
                                    const std::vector<std::string> &pruned_rule_identifiers) {
            std::vector<RuleResult> out;
            out.reserve(baseline_results.size());
            for (const auto &baseline : baseline_results) {
                if (const auto *exact = find_rule_result(exact_vm_results, baseline.identifier); exact != nullptr) {
                    out.push_back(*exact);
                    continue;
                }
                out.push_back(pruned_rule_result(baseline.identifier));
                if (!contains_string(pruned_rule_identifiers, baseline.identifier)) {
                    out.back().diagnostics.push_back(Diagnostic {
                        .source = "optimizer",
                        .message = "optimized exact VM did not produce unpruned rule result",
                    });
                }
            }
            return out;
        }

        [[nodiscard]] std::vector<RuleResult>
        compose_optimized_results(const VerifiedProgram &program, const std::vector<RuleResult> &exact_vm_results,
                                  const std::vector<std::string> &pruned_rule_identifiers) {
            std::vector<RuleResult> out;
            for (const auto &rule : program.rules) {
                if (rule.is_global || rule.is_private) {
                    continue;
                }
                const auto id = rule_identifier(rule);
                if (contains_string(pruned_rule_identifiers, id)) {
                    out.push_back(pruned_rule_result(id));
                    continue;
                }
                const auto found =
                    std::ranges::find_if(exact_vm_results, [&](const auto &result) { return result.identifier == id; });
                if (found != exact_vm_results.end()) {
                    out.push_back(*found);
                }
            }
            return out;
        }

        [[nodiscard]] std::uint64_t count_result_mismatches(const std::vector<RuleResult> &baseline,
                                                            const std::vector<RuleResult> &optimized) noexcept {
            if (baseline.size() != optimized.size()) {
                return static_cast<std::uint64_t>(std::max(baseline.size(), optimized.size()));
            }
            std::uint64_t out {};
            for (std::size_t index = 0; index < baseline.size(); ++index) {
                if (!rule_results_equal(baseline[index], optimized[index])) {
                    ++out;
                }
            }
            return out;
        }

        [[nodiscard]] CandidateProviderRequestPlan
        candidate_provider_request_plan_for_optimizer_plan(const OptimizerPlan &plan) {
            CandidateProviderRequestPlan out;
            out.requests = plan.candidate_provider_requests;
            return out;
        }

        [[nodiscard]] OptimizedEvaluationSweep evaluate_with_optimizer_plan_from_shared_dag(
            const VerifiedProgram &program, const CanonicalPredicateReport &canonical,
            const std::span<const Subject> subjects, const FactCache &facts, SharedPredicateDagSimulation shared_dag) {
            OptimizedEvaluationSweep out;
            out.shared_dag = std::move(shared_dag);
            out.baseline_exact_vm_rule_executions = static_cast<std::uint64_t>(reportable_rule_ids(program).size()) *
                                                    static_cast<std::uint64_t>(subjects.size());

            for (const auto &subject : subjects) {
                OptimizedEvaluationSubject subject_report;
                subject_report.subject_id = subject.id;
                subject_report.exact_vm_rule_identifiers =
                    exact_vm_rule_ids_for_subject(program, out.shared_dag, subject.id);
                subject_report.pruned_rule_identifiers =
                    pruned_rule_ids_for_subject(program, out.shared_dag, subject.id);

                const Evaluator filtered_evaluator {
                    program,
                    facts,
                    EvaluationOptions {.enabled_rule_identifiers = &subject_report.exact_vm_rule_identifiers},
                };
                const auto filtered_step = filtered_evaluator.step(subject);
                if (filtered_step.state != EvaluationState::complete) {
                    out.incomplete_subjects.push_back(subject.id);
                    out.subjects.push_back(std::move(subject_report));
                    continue;
                }

                out.optimized_exact_vm_rule_executions +=
                    reportable_rule_result_count(program, filtered_step.rule_results);
                for (const auto &rule_id : subject_report.pruned_rule_identifiers) {
                    const auto *candidate_set = find_rule_candidates(out.shared_dag, rule_id);
                    if (candidate_set == nullptr) {
                        continue;
                    }
                    auto event = exact_vm_skip_trace_event(canonical, subject.id, *candidate_set);
                    if (event.has_value()) {
                        out.trace_events.push_back(std::move(*event));
                    }
                }
                subject_report.rule_results = compose_optimized_results(program, filtered_step.rule_results,
                                                                        subject_report.pruned_rule_identifiers);
                out.subjects.push_back(std::move(subject_report));
            }

            if (out.baseline_exact_vm_rule_executions > out.optimized_exact_vm_rule_executions) {
                out.exact_vm_rule_executions_avoided =
                    out.baseline_exact_vm_rule_executions - out.optimized_exact_vm_rule_executions;
            }
            return out;
        }
    } // namespace

    CanonicalPredicateReport extract_canonical_predicates(const VerifiedProgram &program) {
        CanonicalPredicateReport report;
        for (const auto &rule : program.rules) { visit_expression(report, rule, rule.condition, true); }
        return report;
    }

    std::string canonical_predicate_report_json(const CanonicalPredicateReport &report) {
        std::string out;
        out.push_back('{');
        append_key_string(out, "schema", "rule-engine-canonical-predicates.v1");
        out.push_back(',');
        append_key_size(out, "predicateCount", report.predicates.size());
        out.push_back(',');
        append_key_size(out, "ownerCount", owner_count(report));
        out.push_back(',');
        append_key_size(out, "exactVmOnlyCount", report.exact_vm_only.size());
        out.push_back(',');
        append_key(out, "predicates");
        out.push_back('[');
        for (std::size_t index = 0; index < report.predicates.size(); ++index) {
            if (index != 0u) {
                out.push_back(',');
            }
            const auto &predicate = report.predicates[index];
            out.push_back('{');
            append_key_string(out, "id", predicate.id);
            out.push_back(',');
            append_key_string(out, "route", predicate.route);
            out.push_back(',');
            append_key_string(out, "factKey", predicate.fact_key);
            out.push_back(',');
            append_key_string(out, "costClass", fact_cost_class_name(predicate.cost_class));
            out.push_back(',');
            append_key_string(out, "operation", predicate.operation);
            out.push_back(',');
            append_key_string(out, "literalKind", predicate.literal_kind);
            out.push_back(',');
            append_key_string(out, "literalValue", predicate.literal_value);
            out.push_back(',');
            append_key(out, "owners");
            out.push_back('[');
            for (std::size_t owner_index = 0; owner_index < predicate.owners.size(); ++owner_index) {
                if (owner_index != 0u) {
                    out.push_back(',');
                }
                out.push_back('{');
                append_key_string(out, "rule", predicate.owners[owner_index].rule_identifier);
                out.push_back(',');
                append_key_bool(out, "pruneSafe", predicate.owners[owner_index].prune_safe);
                out.push_back('}');
            }
            out.push_back(']');
            out.push_back('}');
        }
        out.push_back(']');
        out.push_back(',');
        append_key(out, "exactVmOnly");
        out.push_back('[');
        for (std::size_t index = 0; index < report.exact_vm_only.size(); ++index) {
            if (index != 0u) {
                out.push_back(',');
            }
            const auto &exact = report.exact_vm_only[index];
            out.push_back('{');
            append_key_string(out, "rule", exact.rule_identifier);
            out.push_back(',');
            append_key_string(out, "reason", exact.reason);
            out.push_back('}');
        }
        out.push_back(']');
        out.push_back('}');
        return out;
    }

    OptimizerPlan build_optimizer_plan(const VerifiedProgram &program) {
        auto canonical = extract_canonical_predicates(program);
        OptimizerPlan plan;
        plan.predicate_nodes = std::move(canonical.predicates);
        plan.exact_vm_fallbacks = std::move(canonical.exact_vm_only);

        const auto ordered = ordered_predicates(plan.predicate_nodes);
        plan.predicate_order.reserve(ordered.size());
        for (const auto *predicate : ordered) { plan.predicate_order.push_back(predicate->id); }

        for (const auto &rule : program.rules) {
            const auto rule_id = rule_identifier(rule);
            for (const auto &fact : rule.facts) { add_provider_requirement(plan, fact, rule_id); }
        }

        const auto request_plan = plan_candidate_provider_requests(CanonicalPredicateReport {
            .predicates = plan.predicate_nodes,
            .exact_vm_only = {},
        });
        plan.candidate_provider_requests = request_plan.requests;
        return plan;
    }

    std::string optimizer_plan_json(const OptimizerPlan &plan) {
        std::string out;
        out.push_back('{');
        append_key_string(out, "schema", "rule-engine-optimizer-plan.v1");
        out.push_back(',');
        append_key_size(out, "predicateCount", plan.predicate_nodes.size());
        out.push_back(',');
        append_key_size(out, "exactVmFallbackCount", plan.exact_vm_fallbacks.size());
        out.push_back(',');
        append_key_size(out, "providerRequirementCount", plan.provider_requirements.size());
        out.push_back(',');
        append_key_size(out, "candidateProviderRequestCount", plan.candidate_provider_requests.size());
        out.push_back(',');
        append_key(out, "predicateOrder");
        append_string_array(out, plan.predicate_order);
        out.push_back(',');
        append_key(out, "predicateNodes");
        out.push_back('[');
        for (std::size_t index = 0; index < plan.predicate_nodes.size(); ++index) {
            if (index != 0u) {
                out.push_back(',');
            }
            const auto &predicate = plan.predicate_nodes[index];
            out.push_back('{');
            append_key_string(out, "id", predicate.id);
            out.push_back(',');
            append_key_string(out, "route", predicate.route);
            out.push_back(',');
            append_key_string(out, "factKey", predicate.fact_key);
            out.push_back(',');
            append_key_string(out, "costClass", fact_cost_class_name(predicate.cost_class));
            out.push_back(',');
            append_key_string(out, "operation", predicate.operation);
            out.push_back(',');
            append_key_string(out, "literalKind", predicate.literal_kind);
            out.push_back(',');
            append_key_string(out, "literalValue", predicate.literal_value);
            out.push_back(',');
            append_key(out, "owners");
            out.push_back('[');
            for (std::size_t owner_index = 0; owner_index < predicate.owners.size(); ++owner_index) {
                if (owner_index != 0u) {
                    out.push_back(',');
                }
                const auto &owner = predicate.owners[owner_index];
                out.push_back('{');
                append_key_string(out, "rule", owner.rule_identifier);
                out.push_back(',');
                append_key_bool(out, "pruneSafe", owner.prune_safe);
                out.push_back(',');
                append_key(out, "sourceSpan");
                append_source_span(out, owner.span);
                out.push_back('}');
            }
            out.push_back(']');
            out.push_back('}');
        }
        out.push_back(']');
        out.push_back(',');
        append_key(out, "exactVmFallbacks");
        out.push_back('[');
        for (std::size_t index = 0; index < plan.exact_vm_fallbacks.size(); ++index) {
            if (index != 0u) {
                out.push_back(',');
            }
            const auto &fallback = plan.exact_vm_fallbacks[index];
            out.push_back('{');
            append_key_string(out, "rule", fallback.rule_identifier);
            out.push_back(',');
            append_key_string(out, "reason", fallback.reason);
            out.push_back(',');
            append_key(out, "sourceSpan");
            append_source_span(out, fallback.span);
            out.push_back('}');
        }
        out.push_back(']');
        out.push_back(',');
        append_key(out, "providerRequirements");
        out.push_back('[');
        for (std::size_t index = 0; index < plan.provider_requirements.size(); ++index) {
            if (index != 0u) {
                out.push_back(',');
            }
            const auto &requirement = plan.provider_requirements[index];
            out.push_back('{');
            append_key_string(out, "route", requirement.route);
            out.push_back(',');
            append_key_string(out, "key", requirement.key);
            out.push_back(',');
            append_key_string(out, "type", value_type_name(requirement.type));
            out.push_back(',');
            append_key_string(out, "costClass", fact_cost_class_name(requirement.cost_class));
            out.push_back(',');
            append_key_bool(out, "cheapPrefetch", requirement.cheap_prefetch);
            out.push_back(',');
            append_key(out, "rules");
            append_string_array(out, requirement.rule_identifiers);
            out.push_back('}');
        }
        out.push_back(']');
        out.push_back(',');
        append_key(out, "candidateProviderRequests");
        out.push_back('[');
        for (std::size_t index = 0; index < plan.candidate_provider_requests.size(); ++index) {
            if (index != 0u) {
                out.push_back(',');
            }
            const auto &request = plan.candidate_provider_requests[index];
            out.push_back('{');
            append_key_string(out, "id", request.id);
            out.push_back(',');
            append_key_string(out, "route", request.route);
            out.push_back(',');
            append_key_string(out, "filterKey", request.filter_key);
            out.push_back(',');
            append_key_string(out, "argumentKind", request.argument_kind);
            out.push_back(',');
            append_key_string(out, "argumentValue", request.argument_value);
            out.push_back(',');
            append_key(out, "predicateIds");
            append_string_array(out, request.predicate_ids);
            out.push_back('}');
        }
        out.push_back(']');
        out.push_back('}');
        return out;
    }

    OptimizedEvaluationSweep evaluate_with_optimizer_plan(const VerifiedProgram &program, const OptimizerPlan &plan,
                                                          const std::span<const Subject> subjects,
                                                          const FactCache &facts) {
        const auto canonical = CanonicalPredicateReport {
            .predicates = plan.predicate_nodes,
            .exact_vm_only = plan.exact_vm_fallbacks,
        };
        return evaluate_with_optimizer_plan_from_shared_dag(
            program, canonical, subjects, facts, simulate_shared_predicate_dag(program, canonical, subjects, facts));
    }

    OptimizedEvaluationSweep
    evaluate_with_optimizer_plan(const VerifiedProgram &program, const OptimizerPlan &plan,
                                 const std::span<const Subject> subjects, const FactCache &facts,
                                 const std::span<const CandidateProviderResult> candidate_provider_results) {
        const auto canonical = CanonicalPredicateReport {
            .predicates = plan.predicate_nodes,
            .exact_vm_only = plan.exact_vm_fallbacks,
        };
        const auto request_plan = candidate_provider_request_plan_for_optimizer_plan(plan);
        const auto candidate_simulation = simulate_candidate_provider_filter(program, canonical, subjects, request_plan,
                                                                             candidate_provider_results, facts);
        auto out = evaluate_with_optimizer_plan_from_shared_dag(program, canonical, subjects, facts,
                                                                candidate_simulation.shared_dag);
        out.candidate_provider_requests = candidate_simulation.provider_requests;
        out.candidate_provider_subjects_returned = candidate_simulation.candidate_subjects_returned;
        out.candidate_provider_broad_results = candidate_simulation.broad_results;
        out.candidate_provider_fallback_predicate_evaluations =
            candidate_simulation.server_fallback_predicate_evaluations;
        return out;
    }

    std::string_view candidate_set_representation_name(const CandidateSetRepresentation representation) noexcept {
        using enum CandidateSetRepresentation;
        switch (representation) {
            case dense_bitset: return "dense_bitset";
            case sparse_ids: return "sparse_ids";
            default: return "dense_bitset";
        }
    }

    DiscoveryGatePlan plan_discovery_gates(const VerifiedProgram &program, const CanonicalPredicateReport &report) {
        DiscoveryGatePlan plan;
        const auto rule_ids = reportable_rule_ids(program);
        const auto ordered = ordered_predicates(report.predicates);
        for (const auto *predicate : ordered) {
            auto gate = discovery_gate_for_predicate(*predicate, rule_ids);
            if (gate.has_value()) {
                plan.gates.push_back(std::move(*gate));
            }
        }
        return plan;
    }

    DiscoveryGateSimulation simulate_discovery_gates(const VerifiedProgram &, const DiscoveryGatePlan &plan,
                                                     const std::span<const Subject> subjects, const FactCache &facts) {
        DiscoveryGateSimulation simulation;
        simulation.plan = plan;

        for (const auto &gate : plan.gates) {
            trace_discovery_gate_ordered(simulation, gate);
            DiscoveryGateResult result;
            result.gate = gate;

            const CanonicalPredicate predicate {
                .id = gate.predicate_id,
                .fact_key = gate.fact_key,
                .route = gate.route,
                .cost_class = gate.cost_class,
                .operation = gate.operation,
                .literal_kind = gate.literal_kind,
                .literal_value = gate.literal_value,
                .owners = {},
            };

            for (const auto &subject : subjects) {
                ++simulation.gate_evaluations;
                const auto evaluated = evaluate_predicate_for_subject(predicate, subject, facts);
                if (evaluated.status == PredicateEvaluationStatus::matched) {
                    result.matched_subject_ids.push_back(subject.id);
                    continue;
                }
                if (evaluated.status == PredicateEvaluationStatus::unknown) {
                    result.unknown_subjects.push_back(PredicateSubjectReason {
                        .subject_id = subject.id,
                        .reason = evaluated.reason,
                    });
                    continue;
                }
                result.rejected_subjects.push_back(PredicateSubjectReason {
                    .subject_id = subject.id,
                    .reason = evaluated.reason,
                });
            }

            if (result.matched_subject_ids.empty() && result.unknown_subjects.empty()) {
                result.pack_skipped = true;
                result.reason = "discovery gate " + gate.predicate_id + " rejected every subject";
                simulation.pack_skipped = true;
                simulation.skip_reason = result.reason;
                trace_discovery_gate_pack_skipped(simulation, gate);
                simulation.gate_results.push_back(std::move(result));
                break;
            }

            simulation.gate_results.push_back(std::move(result));
        }

        return simulation;
    }

    std::string discovery_gate_simulation_json(const DiscoveryGateSimulation &simulation) {
        std::string out;
        out.push_back('{');
        append_key_string(out, "schema", "rule-engine-discovery-gate-simulation.v1");
        out.push_back(',');
        append_key_size(out, "gateCount", simulation.plan.gates.size());
        out.push_back(',');
        append_key_u64(out, "gateEvaluations", simulation.gate_evaluations);
        out.push_back(',');
        append_key_bool(out, "packSkipped", simulation.pack_skipped);
        out.push_back(',');
        append_key_string(out, "skipReason", simulation.skip_reason);
        out.push_back(',');
        append_key(out, "gates");
        out.push_back('[');
        for (std::size_t index = 0; index < simulation.plan.gates.size(); ++index) {
            if (index != 0u) {
                out.push_back(',');
            }
            const auto &gate = simulation.plan.gates[index];
            out.push_back('{');
            append_key_string(out, "predicateId", gate.predicate_id);
            out.push_back(',');
            append_key_string(out, "route", gate.route);
            out.push_back(',');
            append_key_string(out, "factKey", gate.fact_key);
            out.push_back(',');
            append_key_string(out, "costClass", fact_cost_class_name(gate.cost_class));
            out.push_back(',');
            append_key_string(out, "operation", gate.operation);
            out.push_back(',');
            append_key_string(out, "literalKind", gate.literal_kind);
            out.push_back(',');
            append_key_string(out, "literalValue", gate.literal_value);
            out.push_back(',');
            append_key(out, "sourceSpan");
            append_source_span(out, gate.span);
            out.push_back(',');
            append_key(out, "rules");
            append_string_array(out, gate.rule_identifiers);
            out.push_back('}');
        }
        out.push_back(']');
        out.push_back(',');
        append_key(out, "gateResults");
        out.push_back('[');
        for (std::size_t index = 0; index < simulation.gate_results.size(); ++index) {
            if (index != 0u) {
                out.push_back(',');
            }
            const auto &result = simulation.gate_results[index];
            out.push_back('{');
            append_key_string(out, "predicateId", result.gate.predicate_id);
            out.push_back(',');
            append_key_bool(out, "packSkipped", result.pack_skipped);
            out.push_back(',');
            append_key_string(out, "reason", result.reason);
            out.push_back(',');
            append_key(out, "matchedSubjects");
            append_string_array(out, result.matched_subject_ids);
            out.push_back(',');
            append_key(out, "rejectedSubjects");
            append_subject_reasons(out, result.rejected_subjects);
            out.push_back(',');
            append_key(out, "unknownSubjects");
            append_subject_reasons(out, result.unknown_subjects);
            out.push_back('}');
        }
        out.push_back(']');
        out.push_back(',');
        append_key(out, "traceEvents");
        append_optimizer_trace_events(out, simulation.trace_events);
        out.push_back('}');
        return out;
    }

    SharedPredicateDagSimulation simulate_shared_predicate_dag(const VerifiedProgram &program,
                                                               const CanonicalPredicateReport &report,
                                                               const std::span<const Subject> subjects,
                                                               const FactCache &facts) {
        return simulate_shared_predicate_dag(program, report, subjects, facts, PredicateSelectivityProfile {});
    }

    SharedPredicateDagSimulation simulate_shared_predicate_dag(const VerifiedProgram &program,
                                                               const CanonicalPredicateReport &report,
                                                               const std::span<const Subject> subjects,
                                                               const FactCache &facts,
                                                               const PredicateSelectivityProfile &profile) {
        SharedPredicateDagSimulation simulation;
        const auto all_subject_ids = subject_ids(subjects);
        for (const auto &rule : program.rules) {
            simulation.rule_candidates.push_back(RuleCandidateSet {
                .rule_identifier = rule_identifier(rule),
                .candidate_subject_ids = all_subject_ids,
                .pruned_subjects = {},
            });
        }
        refresh_candidate_set_stats(simulation, subjects.size());

        const auto ordered = ordered_predicates(report.predicates, profile);
        const auto uses_feedback = !profile.predicates.empty();
        for (const auto *predicate_ptr : ordered) {
            const auto &predicate = *predicate_ptr;
            simulation.predicate_order.push_back(predicate.id);
            trace_predicate_ordered(simulation, predicate,
                                    uses_feedback && selectivity_hint(profile, predicate.id).has_value() ?
                                        "observed selectivity feedback within descriptor cost order" :
                                        "static descriptor cost order");
            PredicateNodeSimulation node;
            node.predicate_id = predicate.id;
            node.cost_class = predicate.cost_class;
            for (const auto &subject : subjects) {
                ++simulation.predicate_evaluations;
                const auto evaluated = evaluate_predicate_for_subject(predicate, subject, facts);
                if (evaluated.status == PredicateEvaluationStatus::matched) {
                    node.matched_subject_ids.push_back(subject.id);
                    continue;
                }
                if (evaluated.status == PredicateEvaluationStatus::unknown) {
                    node.unknown_subjects.push_back(PredicateSubjectReason {
                        .subject_id = subject.id,
                        .reason = evaluated.reason,
                    });
                    continue;
                }

                node.pruned_subjects.push_back(PredicateSubjectReason {
                    .subject_id = subject.id,
                    .reason = evaluated.reason,
                });
                for (const auto &owner : predicate.owners) {
                    prune_rule_subject(simulation, owner, predicate, subject.id, evaluated.reason, subjects.size());
                }
            }
            finalize_predicate_node(node, subjects.size());
            if (node.nonselective) {
                trace_predicate_nonselective(simulation, node, predicate);
            }
            simulation.predicate_nodes.push_back(std::move(node));
            refresh_candidate_set_stats(simulation, subjects.size());
        }
        apply_simple_or_union_pruning(program, report, subjects, simulation);
        return simulation;
    }

    PredicateSelectivityProfile build_selectivity_profile(const SharedPredicateDagSimulation &simulation) {
        PredicateSelectivityProfile profile;
        profile.predicates.reserve(simulation.predicate_nodes.size());
        for (const auto &node : simulation.predicate_nodes) {
            profile.predicates.push_back(PredicateSelectivityObservation {
                .predicate_id = node.predicate_id,
                .observed_selectivity_ppm = node.observed_selectivity_ppm,
                .matched_subject_count = node.matched_subject_count,
            });
        }
        return profile;
    }

    std::string shared_predicate_dag_simulation_json(const SharedPredicateDagSimulation &simulation) {
        std::string out;
        out.push_back('{');
        append_key_string(out, "schema", "rule-engine-shared-predicate-dag-simulation.v1");
        out.push_back(',');
        append_key_size(out, "predicateNodeCount", simulation.predicate_nodes.size());
        out.push_back(',');
        append_key_u64(out, "predicateEvaluations", simulation.predicate_evaluations);
        out.push_back(',');
        append_key_u64(out, "prunedRuleSubjects", simulation.pruned_rule_subjects);
        out.push_back(',');
        append_key_u64(out, "droppedRuleBranches", simulation.dropped_rule_branches);
        out.push_back(',');
        append_key_size(out, "peakCandidateSetSubjects", simulation.peak_candidate_set_subjects);
        out.push_back(',');
        append_key_u64(out, "peakCandidateSetBytes", simulation.peak_candidate_set_bytes);
        out.push_back(',');
        append_key(out, "predicateOrder");
        append_string_array(out, simulation.predicate_order);
        out.push_back(',');
        append_key(out, "traceEvents");
        append_optimizer_trace_events(out, simulation.trace_events);
        out.push_back(',');
        append_key(out, "predicateNodes");
        out.push_back('[');
        for (std::size_t index = 0; index < simulation.predicate_nodes.size(); ++index) {
            if (index != 0u) {
                out.push_back(',');
            }
            const auto &node = simulation.predicate_nodes[index];
            out.push_back('{');
            append_key_string(out, "id", node.predicate_id);
            out.push_back(',');
            append_key_string(out, "costClass", fact_cost_class_name(node.cost_class));
            out.push_back(',');
            append_key_u64(out, "observedSelectivityPpm", node.observed_selectivity_ppm);
            out.push_back(',');
            append_key_u64(out, "matchedSubjectCount", node.matched_subject_count);
            out.push_back(',');
            append_key_bool(out, "nonselective", node.nonselective);
            out.push_back(',');
            append_key_bool(out, "retainedMatchedSubjects", node.retained_matched_subjects);
            out.push_back(',');
            append_key(out, "matchedSubjects");
            append_string_array(out, node.matched_subject_ids);
            out.push_back(',');
            append_key(out, "prunedSubjects");
            out.push_back('[');
            for (std::size_t pruned_index = 0; pruned_index < node.pruned_subjects.size(); ++pruned_index) {
                if (pruned_index != 0u) {
                    out.push_back(',');
                }
                out.push_back('{');
                append_key_string(out, "subject", node.pruned_subjects[pruned_index].subject_id);
                out.push_back(',');
                append_key_string(out, "reason", node.pruned_subjects[pruned_index].reason);
                out.push_back('}');
            }
            out.push_back(']');
            out.push_back(',');
            append_key(out, "unknownSubjects");
            out.push_back('[');
            for (std::size_t unknown_index = 0; unknown_index < node.unknown_subjects.size(); ++unknown_index) {
                if (unknown_index != 0u) {
                    out.push_back(',');
                }
                out.push_back('{');
                append_key_string(out, "subject", node.unknown_subjects[unknown_index].subject_id);
                out.push_back(',');
                append_key_string(out, "reason", node.unknown_subjects[unknown_index].reason);
                out.push_back('}');
            }
            out.push_back(']');
            out.push_back('}');
        }
        out.push_back(']');
        out.push_back(',');
        append_key(out, "ruleCandidates");
        out.push_back('[');
        for (std::size_t index = 0; index < simulation.rule_candidates.size(); ++index) {
            if (index != 0u) {
                out.push_back(',');
            }
            const auto &candidate_set = simulation.rule_candidates[index];
            out.push_back('{');
            append_key_string(out, "rule", candidate_set.rule_identifier);
            out.push_back(',');
            append_key_bool(out, "dropped", candidate_set.dropped);
            out.push_back(',');
            append_key_string(out, "candidateSetRepresentation",
                              candidate_set_representation_name(candidate_set.representation));
            out.push_back(',');
            append_key_u64(out, "candidateSetBytes", candidate_set.candidate_set_bytes);
            out.push_back(',');
            append_key(out, "candidateSubjects");
            append_string_array(out, candidate_set.candidate_subject_ids);
            out.push_back(',');
            append_key(out, "prunedSubjects");
            out.push_back('[');
            for (std::size_t pruned_index = 0; pruned_index < candidate_set.pruned_subjects.size(); ++pruned_index) {
                if (pruned_index != 0u) {
                    out.push_back(',');
                }
                out.push_back('{');
                append_key_string(out, "subject", candidate_set.pruned_subjects[pruned_index].subject_id);
                out.push_back(',');
                append_key_string(out, "predicateId", candidate_set.pruned_subjects[pruned_index].predicate_id);
                out.push_back(',');
                append_key_string(out, "reason", candidate_set.pruned_subjects[pruned_index].reason);
                out.push_back('}');
            }
            out.push_back(']');
            out.push_back('}');
        }
        out.push_back(']');
        out.push_back('}');
        return out;
    }

    LazyProviderExpansionPlan plan_lazy_provider_expansion(const VerifiedProgram &program,
                                                           const SharedPredicateDagSimulation &simulation) {
        LazyProviderExpansionPlan plan;
        const auto all_subject_ids = simulation_subject_ids(simulation);

        for (const auto &rule : program.rules) {
            const auto *candidate_set = find_rule_candidates(simulation, rule_identifier(rule));
            if (candidate_set == nullptr) {
                continue;
            }
            if (candidate_set->dropped || candidate_set->candidate_subject_ids.empty()) {
                continue;
            }

            for (const auto &fact : rule.facts) {
                if (fact.cheap_prefetch) {
                    continue;
                }

                auto *request = find_lazy_request(plan, fact);
                if (request == nullptr) {
                    plan.requests.push_back(LazyProviderExpansionRequest {
                        .route = fact.route,
                        .key = fact.key,
                        .type = fact.type,
                        .cheap_prefetch = fact.cheap_prefetch,
                        .subject_ids = {},
                        .avoided_subject_ids = {},
                        .rule_identifiers = {},
                    });
                    request = &plan.requests.back();
                }

                append_unique(request->rule_identifiers, rule_identifier(rule));
                for (const auto &subject_id : candidate_set->candidate_subject_ids) {
                    append_unique(request->subject_ids, subject_id);
                }
            }
        }

        plan.provider_batches = static_cast<std::uint64_t>(plan.requests.size());
        for (auto &request : plan.requests) {
            request.avoided_subject_ids = avoided_subject_ids(all_subject_ids, request.subject_ids);
            plan.facts_requested += static_cast<std::uint64_t>(request.subject_ids.size());
            plan.facts_avoided += static_cast<std::uint64_t>(request.avoided_subject_ids.size());
            if (!request.cheap_prefetch) {
                plan.expensive_facts_requested += static_cast<std::uint64_t>(request.subject_ids.size());
                plan.expensive_facts_avoided += static_cast<std::uint64_t>(request.avoided_subject_ids.size());
            }
        }

        return plan;
    }

    std::string lazy_provider_expansion_plan_json(const LazyProviderExpansionPlan &plan) {
        std::string out;
        out.push_back('{');
        append_key_string(out, "schema", "rule-engine-lazy-provider-expansion-plan.v1");
        out.push_back(',');
        append_key_u64(out, "providerBatches", plan.provider_batches);
        out.push_back(',');
        append_key_u64(out, "factsRequested", plan.facts_requested);
        out.push_back(',');
        append_key_u64(out, "factsAvoided", plan.facts_avoided);
        out.push_back(',');
        append_key_u64(out, "expensiveFactsRequested", plan.expensive_facts_requested);
        out.push_back(',');
        append_key_u64(out, "expensiveFactsAvoided", plan.expensive_facts_avoided);
        out.push_back(',');
        append_key(out, "requests");
        out.push_back('[');
        for (std::size_t index = 0; index < plan.requests.size(); ++index) {
            if (index != 0u) {
                out.push_back(',');
            }
            const auto &request = plan.requests[index];
            out.push_back('{');
            append_key_string(out, "route", request.route);
            out.push_back(',');
            append_key_string(out, "key", request.key);
            out.push_back(',');
            append_key_string(out, "type", value_type_name(request.type));
            out.push_back(',');
            append_key_bool(out, "cheapPrefetch", request.cheap_prefetch);
            out.push_back(',');
            append_key(out, "subjects");
            append_string_array(out, request.subject_ids);
            out.push_back(',');
            append_key(out, "avoidedSubjects");
            append_string_array(out, request.avoided_subject_ids);
            out.push_back(',');
            append_key(out, "rules");
            append_string_array(out, request.rule_identifiers);
            out.push_back('}');
        }
        out.push_back(']');
        out.push_back('}');
        return out;
    }

    WatchdogBudgetSimulation simulate_watchdog_budgets(const SharedPredicateDagSimulation &simulation,
                                                       const LazyProviderExpansionPlan &lazy_plan,
                                                       const WatchdogBudgetPolicy &policy) {
        WatchdogBudgetSimulation out;
        const auto append_diagnostic = [&](WatchdogBudgetAction action, std::string predicate_id, std::string route,
                                           std::string key, std::string message,
                                           const std::uint64_t affected_subject_count) {
            if (action == WatchdogBudgetAction::trace_only) {
                return;
            }
            ++out.explicit_budget_diagnostics;
            switch (action) {
                case WatchdogBudgetAction::defer_branch: ++out.deferred_branch_diagnostics; break;
                case WatchdogBudgetAction::substitute_gate: ++out.substituted_gate_diagnostics; break;
                case WatchdogBudgetAction::timeout_branch: ++out.timeout_diagnostics; break;
                case WatchdogBudgetAction::unavailable_branch: ++out.unavailable_diagnostics; break;
                case WatchdogBudgetAction::trace_only: break;
                default: break;
            }
            out.budget_diagnostics.push_back(WatchdogBudgetDiagnostic {
                .action = action,
                .predicate_id = std::move(predicate_id),
                .route = std::move(route),
                .key = std::move(key),
                .diagnostic =
                    Diagnostic {
                        .source = "optimizer.watchdog",
                        .message = std::move(message),
                    },
                .affected_subject_count = affected_subject_count,
            });
        };
        const auto predicate_diagnostic_message = [](const WatchdogBudgetAction action, const std::string &reason) {
            switch (action) {
                case WatchdogBudgetAction::defer_branch: return "optimizer watchdog deferred branch because " + reason;
                case WatchdogBudgetAction::substitute_gate:
                    return "optimizer watchdog requested substitute gate because " + reason;
                case WatchdogBudgetAction::timeout_branch:
                    return "optimizer watchdog timed out branch because " + reason;
                case WatchdogBudgetAction::unavailable_branch:
                    return "optimizer watchdog marked branch unavailable because " + reason;
                case WatchdogBudgetAction::trace_only: return std::string {};
                default: return std::string {};
            }
        };
        const auto route_diagnostic_message = [](const WatchdogBudgetAction action, const std::string &route,
                                                 const std::string &key, const std::string &reason) {
            switch (action) {
                case WatchdogBudgetAction::defer_branch:
                    return "optimizer watchdog deferred route " + route + " key " + key + " because " + reason;
                case WatchdogBudgetAction::substitute_gate:
                    return "optimizer watchdog requested substitute gate for route " + route + " key " + key +
                           " because " + reason;
                case WatchdogBudgetAction::timeout_branch:
                    return "optimizer watchdog timed out route " + route + " key " + key + " because " + reason;
                case WatchdogBudgetAction::unavailable_branch:
                    return "optimizer watchdog marked route " + route + " key " + key + " unavailable because " +
                           reason;
                case WatchdogBudgetAction::trace_only: return std::string {};
                default: return std::string {};
            }
        };

        for (const auto &node : simulation.predicate_nodes) {
            ++out.evaluations;
            if (node.observed_selectivity_ppm < policy.low_selectivity_budget_ppm) {
                continue;
            }
            ++out.budget_events;
            ++out.predicate_budget_events;
            const auto reason = "predicate selectivity " + std::to_string(node.observed_selectivity_ppm) +
                                " ppm exceeded low-selectivity budget " +
                                std::to_string(policy.low_selectivity_budget_ppm) + " ppm";
            out.trace_events.push_back(OptimizerTraceEvent {
                .event = "predicate_budget_classified",
                .predicate_id = node.predicate_id,
                .rule_identifier = {},
                .subject_id = {},
                .reason = reason,
                .cost_class = node.cost_class,
                .span = {},
                .matched_subject_count = node.matched_subject_count,
                .candidate_subject_count = node.matched_subject_count,
                .candidate_set_bytes = 0u,
            });
            append_diagnostic(policy.predicate_budget_action, node.predicate_id, {}, {},
                              predicate_diagnostic_message(policy.predicate_budget_action, reason),
                              node.matched_subject_count);
        }

        for (const auto &request : lazy_plan.requests) {
            ++out.evaluations;
            if (request.subject_ids.size() <= policy.route_request_budget) {
                continue;
            }
            ++out.budget_events;
            ++out.route_budget_events;
            const auto overage_reason = std::to_string(request.subject_ids.size()) +
                                        " requested facts exceeded request budget " +
                                        std::to_string(policy.route_request_budget);
            out.trace_events.push_back(OptimizerTraceEvent {
                .event = "route_budget_classified",
                .predicate_id = request.route + "|" + request.key,
                .rule_identifier = {},
                .subject_id = {},
                .reason = "route " + request.route + " key " + request.key + " requested " +
                          std::to_string(request.subject_ids.size()) + " facts exceeded request budget " +
                          std::to_string(policy.route_request_budget),
                .cost_class = FactCostClass::custom,
                .span = {},
                .matched_subject_count = 0u,
                .candidate_subject_count = static_cast<std::uint64_t>(request.subject_ids.size()),
                .candidate_set_bytes = 0u,
            });
            append_diagnostic(
                policy.route_budget_action, request.route + "|" + request.key, request.route, request.key,
                route_diagnostic_message(policy.route_budget_action, request.route, request.key, overage_reason),
                static_cast<std::uint64_t>(request.subject_ids.size()));
        }
        return out;
    }

    namespace {
        [[nodiscard]] bool cacheable_static_fact(const StaticFactCacheCandidate &candidate) noexcept {
            if (!candidate.content_addressable) {
                return false;
            }
            switch (candidate.cost_class) {
                case FactCostClass::static_image_header:
                case FactCostClass::broad_image_array:
                case FactCostClass::handle_signer:
                case FactCostClass::pattern_scan: return true;
                case FactCostClass::inventory:
                case FactCostClass::cheap_process_snapshot:
                case FactCostClass::process_array:
                case FactCostClass::memory_region:
                case FactCostClass::custom: return false;
                default: return false;
            }
        }

        [[nodiscard]] std::string static_fact_locator(const StaticFactCacheCandidate &candidate) {
            return candidate.route + "|" + candidate.key + "|" + candidate.identity.path + "|" +
                   candidate.identity.scan_space_name;
        }

        [[nodiscard]] std::string static_fact_fingerprint(const StaticFactCacheCandidate &candidate) {
            return static_fact_locator(candidate) + "|file_id:" + candidate.identity.file_id +
                   "|size:" + std::to_string(candidate.identity.file_size) +
                   "|mtime:" + std::to_string(candidate.identity.last_write_time) +
                   "|hash:" + candidate.identity.content_hash + "|signature:" + candidate.identity.signature_identity +
                   "|scan_version:" + candidate.identity.scan_space_version;
        }

        [[nodiscard]] OptimizerTraceEvent static_fact_cache_trace_event(const StaticFactCacheCandidate &candidate,
                                                                        std::string event, std::string reason) {
            return OptimizerTraceEvent {
                .event = std::move(event),
                .predicate_id = candidate.route + "|" + candidate.key,
                .rule_identifier = {},
                .subject_id = candidate.subject_id,
                .reason = std::move(reason),
                .cost_class = candidate.cost_class,
                .span = {},
                .matched_subject_count = 0u,
                .candidate_subject_count = 1u,
                .candidate_set_bytes = 0u,
            };
        }

        [[nodiscard]] std::optional<std::string>
        required_identity_string(const FactCache &facts, const std::string_view subject_id, const std::string &key) {
            if (key.empty()) {
                return std::nullopt;
            }
            const auto fact = facts.lookup(subject_id, key);
            if (!fact.has_value() || fact->status != FactStatus::available) {
                return std::nullopt;
            }
            const auto *value = fact->value.as_string();
            if (value == nullptr || value->empty()) {
                return std::nullopt;
            }
            return *value;
        }

        [[nodiscard]] std::optional<std::uint64_t>
        required_identity_u64(const FactCache &facts, const std::string_view subject_id, const std::string &key) {
            if (key.empty()) {
                return std::nullopt;
            }
            const auto fact = facts.lookup(subject_id, key);
            if (!fact.has_value() || fact->status != FactStatus::available) {
                return std::nullopt;
            }
            const auto value = fact->value.as_i64();
            if (!value.has_value() || *value < 0) {
                return std::nullopt;
            }
            return static_cast<std::uint64_t>(*value);
        }

        [[nodiscard]] std::string optional_identity_string(const FactCache &facts, const std::string_view subject_id,
                                                           const std::string &key) {
            if (key.empty()) {
                return {};
            }
            const auto fact = facts.lookup(subject_id, key);
            if (!fact.has_value() || fact->status != FactStatus::available) {
                return {};
            }
            const auto *value = fact->value.as_string();
            if (value == nullptr) {
                return {};
            }
            return *value;
        }

        [[nodiscard]] std::optional<StaticFactCacheIdentity>
        static_fact_identity_from_facts(const FactCache &facts, const Subject &subject,
                                        const StaticFactIdentityFactKeys &keys) {
            const auto path = required_identity_string(facts, subject.id, keys.path);
            const auto file_id = required_identity_string(facts, subject.id, keys.file_id);
            const auto file_size = required_identity_u64(facts, subject.id, keys.file_size);
            const auto last_write_time = required_identity_u64(facts, subject.id, keys.last_write_time);
            if (!path.has_value() || !file_id.has_value() || !file_size.has_value() || !last_write_time.has_value()) {
                return std::nullopt;
            }

            return StaticFactCacheIdentity {
                .path = *path,
                .file_id = *file_id,
                .file_size = *file_size,
                .last_write_time = *last_write_time,
                .content_hash = optional_identity_string(facts, subject.id, keys.content_hash),
                .signature_identity = optional_identity_string(facts, subject.id, keys.signature_identity),
                .scan_space_name = optional_identity_string(facts, subject.id, keys.scan_space_name),
                .scan_space_version = optional_identity_string(facts, subject.id, keys.scan_space_version),
            };
        }
    } // namespace

    std::vector<StaticFactCacheCandidate>
    derive_static_fact_cache_candidates(const std::span<const OptimizerPlanProviderRequirement> requirements,
                                        const std::span<const Subject> subjects, const FactCache &identity_facts,
                                        const StaticFactIdentityFactKeys &identity_fact_keys) {
        std::vector<StaticFactCacheCandidate> out;
        out.reserve(requirements.size() * subjects.size());

        for (const auto &subject : subjects) {
            const auto identity = static_fact_identity_from_facts(identity_facts, subject, identity_fact_keys);
            if (!identity.has_value()) {
                continue;
            }
            for (const auto &requirement : requirements) {
                StaticFactCacheCandidate candidate {
                    .subject_id = subject.id,
                    .route = requirement.route,
                    .key = requirement.key,
                    .cost_class = requirement.cost_class,
                    .identity = *identity,
                    .content_addressable = true,
                };
                if (!cacheable_static_fact(candidate)) {
                    continue;
                }
                out.push_back(std::move(candidate));
            }
        }
        return out;
    }

    StaticFactCacheLookup StaticFactCache::lookup(const StaticFactCacheCandidate &candidate) {
        if (!cacheable_static_fact(candidate)) {
            return StaticFactCacheLookup {
                .status = StaticFactCacheLookupStatus::unsupported,
                .fact = std::nullopt,
                .trace_event = std::nullopt,
            };
        }

        ++stats_.lookups;
        const auto locator = static_fact_locator(candidate);
        const auto fingerprint = static_fact_fingerprint(candidate);
        const auto found = std::ranges::find_if(entries_, [&](const auto &entry) { return entry.locator == locator; });
        if (found == entries_.end()) {
            ++stats_.cache_misses;
            return StaticFactCacheLookup {
                .status = StaticFactCacheLookupStatus::miss,
                .fact = std::nullopt,
                .trace_event = std::nullopt,
            };
        }

        if (found->fingerprint != fingerprint) {
            ++stats_.cache_misses;
            ++stats_.rejected_reuses;
            ++stats_.invalidations;
            const auto trace =
                static_fact_cache_trace_event(candidate, "static_fact_cache_rejected",
                                              "static fact cache rejected " + candidate.key + " for " +
                                                  candidate.identity.path + " because file identity changed");
            entries_.erase(found);
            return StaticFactCacheLookup {
                .status = StaticFactCacheLookupStatus::invalidated,
                .fact = std::nullopt,
                .trace_event = trace,
            };
        }

        ++stats_.cache_hits;
        ++stats_.accepted_reuses;
        auto fact = found->fact;
        fact.subject_id = candidate.subject_id;
        fact.key = candidate.key;
        return StaticFactCacheLookup {
            .status = StaticFactCacheLookupStatus::hit,
            .fact = std::move(fact),
            .trace_event = static_fact_cache_trace_event(candidate, "static_fact_cache_reused",
                                                         "static fact cache reused " + candidate.key + " for " +
                                                             candidate.identity.path),
        };
    }

    StaticFactCacheStoreResult StaticFactCache::store(const StaticFactCacheCandidate &candidate, Fact fact) {
        if (!cacheable_static_fact(candidate)) {
            ++stats_.subject_scoped_facts;
            return StaticFactCacheStoreResult {
                .stored = false,
                .subject_scoped = true,
            };
        }

        const auto locator = static_fact_locator(candidate);
        const auto fingerprint = static_fact_fingerprint(candidate);
        fact.key = candidate.key;

        const auto found = std::ranges::find_if(entries_, [&](const auto &entry) { return entry.locator == locator; });
        if (found == entries_.end()) {
            entries_.push_back(Entry {
                .locator = locator,
                .fingerprint = fingerprint,
                .fact = std::move(fact),
            });
        } else {
            found->fingerprint = fingerprint;
            found->fact = std::move(fact);
        }

        return StaticFactCacheStoreResult {
            .stored = true,
            .subject_scoped = false,
        };
    }

    StaticFactCacheStats StaticFactCache::stats() const noexcept { return stats_; }

    StaticFactCacheSimulation simulate_static_fact_cache(const std::span<const StaticFactCacheCandidate> candidates) {
        StaticFactCacheSimulation out;
        StaticFactCache cache;

        for (const auto &candidate : candidates) {
            const auto lookup = cache.lookup(candidate);
            if (lookup.trace_event.has_value()) {
                out.trace_events.push_back(*lookup.trace_event);
            }
            if (lookup.status == StaticFactCacheLookupStatus::hit) {
                continue;
            }

            const auto store_result = cache.store(candidate, Fact {
                                                                 .subject_id = candidate.subject_id,
                                                                 .key = candidate.key,
                                                                 .value = Value::undefined(),
                                                                 .status = FactStatus::available,
                                                                 .diagnostic = {},
                                                                 .ttl = std::chrono::seconds {30},
                                                             });
            static_cast<void>(store_result);
        }
        const auto stats = cache.stats();
        out.lookups = stats.lookups;
        out.cache_hits = stats.cache_hits;
        out.cache_misses = stats.cache_misses;
        out.accepted_reuses = stats.accepted_reuses;
        out.rejected_reuses = stats.rejected_reuses;
        out.invalidations = stats.invalidations;
        out.subject_scoped_facts = stats.subject_scoped_facts;
        return out;
    }

    CandidateProviderRequestPlan plan_candidate_provider_requests(const CanonicalPredicateReport &report) {
        CandidateProviderRequestPlan plan;
        for (const auto &predicate : report.predicates) {
            auto request = candidate_provider_request_for(predicate);
            if (!request.has_value()) {
                continue;
            }

            if (auto *existing = find_candidate_request(plan, request->id); existing != nullptr) {
                for (const auto &predicate_id : request->predicate_ids) {
                    append_unique(existing->predicate_ids, predicate_id);
                }
                continue;
            }
            plan.requests.push_back(std::move(*request));
        }
        return plan;
    }

    CandidateProviderSimulation simulate_candidate_provider_filter(
        const VerifiedProgram &program, const CanonicalPredicateReport &report, const std::span<const Subject> subjects,
        const CandidateProviderRequestPlan &request_plan,
        const std::span<const CandidateProviderResult> provider_results, const FactCache &fallback_facts) {
        CandidateProviderSimulation simulation;
        simulation.request_plan = request_plan;
        add_candidate_provider_subjects(simulation, provider_results, subjects);

        const auto all_subject_ids = subject_ids(subjects);
        for (const auto &rule : program.rules) {
            simulation.shared_dag.rule_candidates.push_back(RuleCandidateSet {
                .rule_identifier = rule_identifier(rule),
                .candidate_subject_ids = all_subject_ids,
                .pruned_subjects = {},
            });
        }
        refresh_candidate_set_stats(simulation.shared_dag, subjects.size());

        const auto ordered = ordered_predicates(report.predicates);
        for (const auto *predicate_ptr : ordered) {
            const auto &predicate = *predicate_ptr;
            simulation.shared_dag.predicate_order.push_back(predicate.id);
            trace_predicate_ordered(simulation.shared_dag, predicate);
            PredicateNodeSimulation node;
            node.predicate_id = predicate.id;
            node.cost_class = predicate.cost_class;
            const auto *request = find_candidate_request_for_predicate(request_plan, predicate.id);
            const auto *result = request == nullptr ? nullptr : find_candidate_result(provider_results, request->id);
            const auto use_provider = result != nullptr && candidate_provider_result_available(*result);
            if (request != nullptr && !use_provider) {
                trace_candidate_provider_fallback(simulation.shared_dag, predicate, *request, result, subjects.size());
            }

            for (const auto &subject : subjects) {
                ++simulation.shared_dag.predicate_evaluations;
                if (use_provider) {
                    if (contains_string(result->subject_ids, subject.id)) {
                        node.matched_subject_ids.push_back(subject.id);
                        continue;
                    }

                    const auto reason = "candidate provider " + request->filter_key + " excluded subject";
                    node.pruned_subjects.push_back(PredicateSubjectReason {
                        .subject_id = subject.id,
                        .reason = reason,
                    });
                    for (const auto &owner : predicate.owners) {
                        prune_rule_subject(simulation.shared_dag, owner, predicate, subject.id, reason,
                                           subjects.size());
                    }
                    continue;
                }

                ++simulation.server_fallback_predicate_evaluations;
                const auto evaluated = evaluate_predicate_for_subject(predicate, subject, fallback_facts);
                if (evaluated.status == PredicateEvaluationStatus::matched) {
                    node.matched_subject_ids.push_back(subject.id);
                    continue;
                }
                if (evaluated.status == PredicateEvaluationStatus::unknown) {
                    node.unknown_subjects.push_back(PredicateSubjectReason {
                        .subject_id = subject.id,
                        .reason = evaluated.reason,
                    });
                    continue;
                }

                node.pruned_subjects.push_back(PredicateSubjectReason {
                    .subject_id = subject.id,
                    .reason = evaluated.reason,
                });
                for (const auto &owner : predicate.owners) {
                    prune_rule_subject(simulation.shared_dag, owner, predicate, subject.id, evaluated.reason,
                                       subjects.size());
                }
            }

            finalize_predicate_node(node, subjects.size());
            if (node.nonselective) {
                trace_predicate_nonselective(simulation.shared_dag, node, predicate);
            }
            simulation.shared_dag.predicate_nodes.push_back(std::move(node));
            refresh_candidate_set_stats(simulation.shared_dag, subjects.size());
        }
        apply_simple_or_union_pruning(program, report, subjects, simulation.shared_dag);

        return simulation;
    }

    std::vector<CandidateProviderResult> candidate_provider_results_from_protocol(
        const std::span<const rule_engine::protocol::CandidateProviderSubjectSet> results) {
        std::vector<CandidateProviderResult> out;
        out.reserve(results.size());
        for (const auto &result : results) {
            out.push_back(CandidateProviderResult {
                .request_id = result.request_id,
                .subject_ids = result.subject_ids,
                .available = result.status == FactStatus::available,
                .status = result.status,
                .diagnostic = result.diagnostic,
                .ttl = result.ttl,
            });
        }
        return out;
    }

    std::string candidate_provider_simulation_json(const CandidateProviderSimulation &simulation) {
        std::string out;
        out.push_back('{');
        append_key_string(out, "schema", "rule-engine-candidate-provider-simulation.v1");
        out.push_back(',');
        append_key_u64(out, "providerRequests", simulation.provider_requests);
        out.push_back(',');
        append_key_u64(out, "candidateSubjectsReturned", simulation.candidate_subjects_returned);
        out.push_back(',');
        append_key_u64(out, "broadResults", simulation.broad_results);
        out.push_back(',');
        append_key_u64(out, "serverFallbackPredicateEvaluations", simulation.server_fallback_predicate_evaluations);
        out.push_back(',');
        append_key(out, "requests");
        out.push_back('[');
        for (std::size_t index = 0; index < simulation.request_plan.requests.size(); ++index) {
            if (index != 0u) {
                out.push_back(',');
            }
            const auto &request = simulation.request_plan.requests[index];
            out.push_back('{');
            append_key_string(out, "id", request.id);
            out.push_back(',');
            append_key_string(out, "route", request.route);
            out.push_back(',');
            append_key_string(out, "filterKey", request.filter_key);
            out.push_back(',');
            append_key_string(out, "argumentKind", request.argument_kind);
            out.push_back(',');
            append_key_string(out, "argumentValue", request.argument_value);
            out.push_back('}');
        }
        out.push_back(']');
        out.push_back('}');
        return out;
    }

    PrefilteredEvaluationComparison compare_prefiltered_evaluation(const VerifiedProgram &program,
                                                                   const CanonicalPredicateReport &report,
                                                                   const std::span<const Subject> subjects,
                                                                   const FactCache &facts) {
        PrefilteredEvaluationComparison out;
        out.shared_dag = simulate_shared_predicate_dag(program, report, subjects, facts);

        for (const auto &subject : subjects) {
            PrefilteredSubjectComparison subject_report;
            subject_report.subject_id = subject.id;
            subject_report.exact_vm_rule_identifiers =
                exact_vm_rule_ids_for_subject(program, out.shared_dag, subject.id);
            subject_report.pruned_rule_identifiers = pruned_rule_ids_for_subject(program, out.shared_dag, subject.id);

            const Evaluator baseline_evaluator {program, facts};
            const auto baseline_step = baseline_evaluator.step(subject);
            if (baseline_step.state != EvaluationState::complete) {
                out.incomplete_subjects.push_back(subject.id);
                out.subjects.push_back(std::move(subject_report));
                continue;
            }
            subject_report.baseline_results = baseline_step.rule_results;
            out.baseline_exact_vm_rule_executions +=
                reportable_rule_result_count(program, subject_report.baseline_results);

            const Evaluator filtered_evaluator {
                program,
                facts,
                EvaluationOptions {.enabled_rule_identifiers = &subject_report.exact_vm_rule_identifiers},
            };
            const auto filtered_step = filtered_evaluator.step(subject);
            if (filtered_step.state != EvaluationState::complete) {
                out.incomplete_subjects.push_back(subject.id);
                out.subjects.push_back(std::move(subject_report));
                continue;
            }
            out.prefiltered_exact_vm_rule_executions +=
                reportable_rule_result_count(program, filtered_step.rule_results);
            for (const auto &rule_id : subject_report.pruned_rule_identifiers) {
                const auto *candidate_set = find_rule_candidates(out.shared_dag, rule_id);
                if (candidate_set != nullptr) {
                    append_exact_vm_skip_trace(out, report, subject.id, *candidate_set);
                }
            }
            subject_report.optimized_results = compose_prefiltered_results(
                subject_report.baseline_results, filtered_step.rule_results, subject_report.pruned_rule_identifiers);
            out.result_mismatches +=
                count_result_mismatches(subject_report.baseline_results, subject_report.optimized_results);
            out.subjects.push_back(std::move(subject_report));
        }

        if (out.baseline_exact_vm_rule_executions > out.prefiltered_exact_vm_rule_executions) {
            out.exact_vm_rule_executions_avoided =
                out.baseline_exact_vm_rule_executions - out.prefiltered_exact_vm_rule_executions;
        }
        return out;
    }
} // namespace rule_engine::optimizer
