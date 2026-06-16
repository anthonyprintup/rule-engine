#include <rule_engine/compiler.hpp>
#include <rule_engine/yara_bridge.hpp>

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <filesystem>
#include <span>
#include <string_view>
#include <vector>

namespace {
    [[nodiscard]] std::filesystem::path fixture_path(const std::string_view relative_path) {
        return std::filesystem::path {RULE_ENGINE_SOURCE_DIR} / std::filesystem::path {relative_path};
    }

    [[nodiscard]] std::uint32_t source_id_for_suffix(const rule_engine::ParsedRuleSet &rules,
                                                     const std::string_view suffix) {
        for (std::size_t index = 0; index < rules.sources.size(); ++index) {
            if (rules.sources[index].ends_with(suffix)) {
                return static_cast<std::uint32_t>(index + 1u);
            }
        }
        return 0u;
    }

    using namespace rule_engine::yara_bridge;

    [[nodiscard]] std::string_view bridge_string(const ReStringView value) noexcept {
        return std::string_view {reinterpret_cast<const char *>(value.data), value.len};
    }

    struct OwnedBridgeParse {
        ReParseResult result {};

        explicit OwnedBridgeParse(ReParseResult value) noexcept: result {value} {}
        ~OwnedBridgeParse() noexcept { re_yara_bridge_free(result.rules); }
        OwnedBridgeParse(const OwnedBridgeParse &) = delete;
        OwnedBridgeParse &operator=(const OwnedBridgeParse &) = delete;
        OwnedBridgeParse(OwnedBridgeParse &&) = delete;
        OwnedBridgeParse &operator=(OwnedBridgeParse &&) = delete;
    };
} // namespace

TEST_CASE("YARA-X bridge exposes generated C++ ABI views") {
    constexpr std::string_view source = R"(
import "process"

rule encoded_powershell {
    condition:
        process.name == "powershell.exe"
}
)";

    const OwnedBridgeParse parsed {re_yara_bridge_parse(reinterpret_cast<const std::uint8_t *>(source.data()),
                                                        source.size())};
    REQUIRE(parsed.result.status == ReParseStatus::Ok);
    REQUIRE(parsed.result.rules != nullptr);
    CHECK(re_yara_bridge_version(parsed.result.rules) == 1u);
    REQUIRE(re_yara_bridge_import_count(parsed.result.rules) == 1u);
    CHECK(bridge_string(re_yara_bridge_import_at(parsed.result.rules, 0u)) == "process");
    REQUIRE(re_yara_bridge_rule_count(parsed.result.rules) == 1u);

    const auto rule = re_yara_bridge_rule_at(parsed.result.rules, 0u);
    CHECK(bridge_string(rule.identifier) == "encoded_powershell");
    CHECK_FALSE(rule.is_private);
    CHECK_FALSE(rule.is_global);
    const auto *condition = re_yara_bridge_rule_condition(parsed.result.rules, rule);
    REQUIRE(condition != nullptr);
    CHECK(re_yara_bridge_node_view(parsed.result.rules, condition).kind == ReNodeKind::Equal);
}

TEST_CASE("YARA-X bridge parses imports, patterns, and field conditions") {
    constexpr auto source = R"(
import "process"

rule encoded_powershell : process {
    strings:
        $enc = "-enc" ascii
    condition:
        process.name == "powershell.exe" and $enc
}
)";

    auto parsed = rule_engine::parse_source("process_rule.yar", source);
    REQUIRE(parsed.has_value());
    REQUIRE(parsed->imports.size() == 1u);
    CHECK(parsed->imports[0] == "process");
    REQUIRE(parsed->rules.size() == 1u);
    CHECK(parsed->rules[0].identifier == "encoded_powershell");
    REQUIRE(parsed->rules[0].patterns.size() == 1u);
    CHECK(parsed->rules[0].patterns[0].identifier == "$enc");
    CHECK(parsed->rules[0].condition.kind == rule_engine::ExpressionKind::and_expr);
}

TEST_CASE("YARA-X bridge assigns stable source ids to standalone sources") {
    constexpr auto source = R"(
rule single_source_rule {
    condition:
        true
}
)";

    auto parsed = rule_engine::parse_source("single.yar", source);
    REQUIRE(parsed.has_value());
    CHECK(parsed->sources == std::vector<std::string> {"single.yar"});
    REQUIRE(parsed->rules.size() == 1u);
    CHECK(parsed->rules[0].span.source == "single.yar");
    CHECK(parsed->rules[0].span.source_id == 1u);
    CHECK(parsed->rules[0].condition.span.source_id == 1u);
}

TEST_CASE("C++ parser assigns namespaces to multiple source units") {
    const std::vector<rule_engine::SourceUnit> sources {
        rule_engine::SourceUnit {
            .source_name = "helpers.yar",
            .namespace_name = "shared",
            .source = R"(
rule helper {
    condition:
        true
}
)",
        },
        rule_engine::SourceUnit {
            .source_name = "detections.yar",
            .namespace_name = "detect",
            .source = R"(
rule helper {
    condition:
        shared.helper
}
)",
        },
    };

    auto parsed = rule_engine::parse_sources(sources);
    REQUIRE(parsed.has_value());
    REQUIRE(parsed->rules.size() == 2u);
    CHECK(parsed->rules[0].namespace_name == "shared");
    CHECK(parsed->rules[0].qualified_identifier == "shared.helper");
    CHECK(parsed->rules[1].namespace_name == "detect");
    CHECK(parsed->rules[1].qualified_identifier == "detect.helper");
    CHECK(parsed->sources == std::vector<std::string> {"helpers.yar", "detections.yar"});
    CHECK(parsed->rules[0].span.source_id == 1u);
    CHECK(parsed->rules[1].span.source_id == 2u);
}

TEST_CASE("YARA-X bridge preserves arithmetic and bitwise expression nodes") {
    constexpr auto source = R"(
import "process"

rule numeric_filter {
    condition:
        process.pid + 4 * 2 == 50 and (process.pid & 15) == 10
}
)";

    auto parsed = rule_engine::parse_source("numeric_rule.yar", source);
    REQUIRE(parsed.has_value());
    REQUIRE(parsed->rules.size() == 1u);
    const auto &condition = parsed->rules[0].condition;
    REQUIRE(condition.kind == rule_engine::ExpressionKind::and_expr);
    REQUIRE(condition.children.size() == 2u);
    REQUIRE(condition.children[0].kind == rule_engine::ExpressionKind::equal);
    REQUIRE(condition.children[0].children.size() == 2u);
    CHECK(condition.children[0].children[0].kind == rule_engine::ExpressionKind::add);
    REQUIRE(condition.children[1].kind == rule_engine::ExpressionKind::equal);
    REQUIRE(condition.children[1].children.size() == 2u);
    CHECK(condition.children[1].children[0].kind == rule_engine::ExpressionKind::bitwise_and);
}

TEST_CASE("YARA-X bridge preserves pattern metadata expression nodes") {
    constexpr auto source = R"(
rule pattern_metadata {
    strings:
        $enc = "-enc" ascii
    condition:
        #enc >= 2 and @enc[1] == 16 and !enc[1] == 4
}
)";

    auto parsed = rule_engine::parse_source("pattern_metadata.yar", source);
    REQUIRE(parsed.has_value());
    REQUIRE(parsed->rules.size() == 1u);
    const auto &condition = parsed->rules[0].condition;
    REQUIRE(condition.kind == rule_engine::ExpressionKind::and_expr);
    REQUIRE(condition.children.size() == 3u);
    CHECK(condition.children[0].children[0].kind == rule_engine::ExpressionKind::pattern_count);
    CHECK(condition.children[1].children[0].kind == rule_engine::ExpressionKind::pattern_offset);
    CHECK(condition.children[2].children[0].kind == rule_engine::ExpressionKind::pattern_length);
}

TEST_CASE("YARA-X bridge preserves pattern-set of expressions") {
    constexpr auto source = R"(
rule pattern_sets {
    strings:
        $a = "alpha" ascii
        $b = "beta" ascii
    condition:
        all of them and 1 of ($a, $b)
}
)";

    auto parsed = rule_engine::parse_source("pattern_sets.yar", source);
    REQUIRE(parsed.has_value());
    REQUIRE(parsed->rules.size() == 1u);
    const auto &condition = parsed->rules[0].condition;
    REQUIRE(condition.kind == rule_engine::ExpressionKind::and_expr);
    REQUIRE(condition.children.size() == 2u);
    CHECK(condition.children[0].kind == rule_engine::ExpressionKind::of_expr);
    CHECK(condition.children[0].text == "all");
    CHECK(condition.children[0].names == std::vector<std::string> {"them"});
    CHECK(condition.children[1].kind == rule_engine::ExpressionKind::of_expr);
    CHECK(condition.children[1].text == "expr");
    CHECK(condition.children[1].names == std::vector<std::string> {"$a", "$b"});
    REQUIRE(condition.children[1].children.size() == 1u);
    CHECK(condition.children[1].children[0].kind == rule_engine::ExpressionKind::literal_integer);
}

TEST_CASE("YARA-X bridge preserves boolean tuple of expressions") {
    constexpr auto source = R"(
rule bool_tuple_sets {
    condition:
        any of (true, false, 1 == 1) and
        2 of (true, false, true)
}
)";

    auto parsed = rule_engine::parse_source("bool_tuple_sets.yar", source);
    REQUIRE(parsed.has_value());
    REQUIRE(parsed->rules.size() == 1u);
    const auto &condition = parsed->rules[0].condition;
    REQUIRE(condition.kind == rule_engine::ExpressionKind::and_expr);
    REQUIRE(condition.children.size() == 2u);
    CHECK(condition.children[0].kind == rule_engine::ExpressionKind::of_expr);
    CHECK(condition.children[0].text == "bool_any");
    CHECK(condition.children[0].names.empty());
    REQUIRE(condition.children[0].children.size() == 3u);
    CHECK(condition.children[0].children[0].kind == rule_engine::ExpressionKind::true_expr);
    CHECK(condition.children[0].children[1].kind == rule_engine::ExpressionKind::false_expr);
    CHECK(condition.children[0].children[2].kind == rule_engine::ExpressionKind::equal);

    CHECK(condition.children[1].kind == rule_engine::ExpressionKind::of_expr);
    CHECK(condition.children[1].text == "bool_expr");
    CHECK(condition.children[1].names.empty());
    REQUIRE(condition.children[1].children.size() == 4u);
    CHECK(condition.children[1].children[0].kind == rule_engine::ExpressionKind::literal_integer);
}

TEST_CASE("YARA-X bridge preserves anchored pattern-set of expressions") {
    constexpr auto source = R"(
rule anchored_pattern_sets {
    strings:
        $a = "alpha" ascii
        $b = "beta" ascii
    condition:
        any of ($a, $b) at 8 and
        all of them in (4..16)
}
)";

    auto parsed = rule_engine::parse_source("anchored_pattern_sets.yar", source);
    REQUIRE(parsed.has_value());
    REQUIRE(parsed->rules.size() == 1u);
    const auto &condition = parsed->rules[0].condition;
    REQUIRE(condition.kind == rule_engine::ExpressionKind::and_expr);
    REQUIRE(condition.children.size() == 2u);

    CHECK(condition.children[0].kind == rule_engine::ExpressionKind::of_expr);
    CHECK(condition.children[0].text == "at_any");
    CHECK(condition.children[0].names == std::vector<std::string> {"$a", "$b"});
    REQUIRE(condition.children[0].children.size() == 1u);
    CHECK(condition.children[0].children[0].kind == rule_engine::ExpressionKind::literal_integer);

    CHECK(condition.children[1].kind == rule_engine::ExpressionKind::of_expr);
    CHECK(condition.children[1].text == "in_all");
    CHECK(condition.children[1].names == std::vector<std::string> {"them"});
    REQUIRE(condition.children[1].children.size() == 2u);
    CHECK(condition.children[1].children[0].kind == rule_engine::ExpressionKind::literal_integer);
    CHECK(condition.children[1].children[1].kind == rule_engine::ExpressionKind::literal_integer);
}

TEST_CASE("YARA-X bridge preserves extended string operator nodes") {
    constexpr auto source = R"(
import "process"

rule string_ops {
    condition:
        process.command_line icontains "-ENC" and
        process.path startswith "fixtures/windows" and
        process.path endswith ".exe" and
        process.name iequals "POWERSHELL.EXE"
}
)";

    auto parsed = rule_engine::parse_source("string_ops.yar", source);
    REQUIRE(parsed.has_value());
    REQUIRE(parsed->rules.size() == 1u);
    const auto &condition = parsed->rules[0].condition;
    REQUIRE(condition.kind == rule_engine::ExpressionKind::and_expr);
    REQUIRE(condition.children.size() == 4u);
    CHECK(condition.children[0].kind == rule_engine::ExpressionKind::icontains);
    CHECK(condition.children[1].kind == rule_engine::ExpressionKind::starts_with);
    CHECK(condition.children[2].kind == rule_engine::ExpressionKind::ends_with);
    CHECK(condition.children[3].kind == rule_engine::ExpressionKind::iequals);
}

TEST_CASE("YARA-X bridge preserves with expression local bindings") {
    constexpr auto source = R"(
import "process"

rule alias_command_line {
    condition:
        with cmd = process.command_line : (cmd icontains "-ENC")
}
)";

    auto parsed = rule_engine::parse_source("with_expr.yar", source);
    REQUIRE(parsed.has_value());
    REQUIRE(parsed->rules.size() == 1u);
    const auto &condition = parsed->rules[0].condition;
    REQUIRE(condition.kind == rule_engine::ExpressionKind::with_expr);
    CHECK(condition.names == std::vector<std::string> {"cmd"});
    REQUIRE(condition.children.size() == 2u);
    CHECK(condition.children[0].kind == rule_engine::ExpressionKind::field);
    REQUIRE(condition.children[1].kind == rule_engine::ExpressionKind::icontains);
    REQUIRE(condition.children[1].children.size() == 2u);
    CHECK(condition.children[1].children[0].kind == rule_engine::ExpressionKind::identifier);
    CHECK(condition.children[1].children[0].names == std::vector<std::string> {"cmd"});
}

TEST_CASE("YARA-X bridge preserves for-in range and tuple expressions") {
    constexpr auto source = R"(
rule loop_filters {
    condition:
        for all i in (1..3) : (i > 0) and
        for any e in (1, 2, 3) : (e == 3)
}
)";

    auto parsed = rule_engine::parse_source("for_in_expr.yar", source);
    REQUIRE(parsed.has_value());
    REQUIRE(parsed->rules.size() == 1u);
    const auto &condition = parsed->rules[0].condition;
    REQUIRE(condition.kind == rule_engine::ExpressionKind::and_expr);
    REQUIRE(condition.children.size() == 2u);

    const auto &range_loop = condition.children[0];
    REQUIRE(range_loop.kind == rule_engine::ExpressionKind::for_in_expr);
    CHECK(range_loop.text == "all");
    CHECK(range_loop.names == std::vector<std::string> {"i"});
    REQUIRE(range_loop.children.size() == 2u);
    CHECK(range_loop.children[0].kind == rule_engine::ExpressionKind::range_expr);
    CHECK(range_loop.children[1].kind == rule_engine::ExpressionKind::greater);

    const auto &tuple_loop = condition.children[1];
    REQUIRE(tuple_loop.kind == rule_engine::ExpressionKind::for_in_expr);
    CHECK(tuple_loop.text == "any");
    CHECK(tuple_loop.names == std::vector<std::string> {"e"});
    REQUIRE(tuple_loop.children.size() == 2u);
    CHECK(tuple_loop.children[0].kind == rule_engine::ExpressionKind::tuple_expr);
    CHECK(tuple_loop.children[1].kind == rule_engine::ExpressionKind::equal);
}

TEST_CASE("YARA-X bridge preserves for-of pattern body expressions") {
    constexpr auto source = R"(
rule for_of_patterns {
    strings:
        $a = "alpha" ascii
        $b = "beta" ascii
    condition:
        for any of them : ( $ ) and
        for all of ($a, $b) : ( # >= 1 )
}
)";

    auto parsed = rule_engine::parse_source("for_of_expr.yar", source);
    REQUIRE(parsed.has_value());
    REQUIRE(parsed->rules.size() == 1u);
    const auto &condition = parsed->rules[0].condition;
    REQUIRE(condition.kind == rule_engine::ExpressionKind::and_expr);
    REQUIRE(condition.children.size() == 2u);

    const auto &any_loop = condition.children[0];
    REQUIRE(any_loop.kind == rule_engine::ExpressionKind::for_of_expr);
    CHECK(any_loop.text == "any");
    CHECK(any_loop.names == std::vector<std::string> {"them"});
    REQUIRE(any_loop.children.size() == 1u);
    CHECK(any_loop.children[0].kind == rule_engine::ExpressionKind::pattern_match);
    CHECK(any_loop.children[0].names == std::vector<std::string> {"$"});

    const auto &all_loop = condition.children[1];
    REQUIRE(all_loop.kind == rule_engine::ExpressionKind::for_of_expr);
    CHECK(all_loop.text == "all");
    CHECK(all_loop.names == std::vector<std::string> {"$a", "$b"});
    REQUIRE(all_loop.children.size() == 1u);
    REQUIRE(all_loop.children[0].kind == rule_engine::ExpressionKind::greater_equal);
    CHECK(all_loop.children[0].children[0].kind == rule_engine::ExpressionKind::pattern_count);
    CHECK(all_loop.children[0].children[0].names == std::vector<std::string> {"$"});
}

TEST_CASE("YARA-X bridge preserves lookup expressions") {
    constexpr auto source = R"(
rule lookup_values {
    condition:
        numbers[1] == 42 and proc["name"] == "powershell.exe"
}
)";

    auto parsed = rule_engine::parse_source("lookup_expr.yar", source);
    REQUIRE(parsed.has_value());
    REQUIRE(parsed->rules.size() == 1u);
    const auto &condition = parsed->rules[0].condition;
    REQUIRE(condition.kind == rule_engine::ExpressionKind::and_expr);
    REQUIRE(condition.children.size() == 2u);
    REQUIRE(condition.children[0].kind == rule_engine::ExpressionKind::equal);
    CHECK(condition.children[0].children[0].kind == rule_engine::ExpressionKind::lookup_expr);
    REQUIRE(condition.children[1].kind == rule_engine::ExpressionKind::equal);
    CHECK(condition.children[1].children[0].kind == rule_engine::ExpressionKind::lookup_expr);
}

TEST_CASE("YARA-X bridge preserves module function call expressions") {
    constexpr auto source = R"(
import "demo"

rule function_filter {
    condition:
        demo.score(process.pid, "alpha") > 7
}
)";

    auto parsed = rule_engine::parse_source("function_call.yar", source);
    REQUIRE(parsed.has_value());
    REQUIRE(parsed->rules.size() == 1u);
    const auto &condition = parsed->rules[0].condition;
    REQUIRE(condition.kind == rule_engine::ExpressionKind::greater);
    REQUIRE(condition.children.size() == 2u);
    const auto &call = condition.children[0];
    REQUIRE(call.kind == rule_engine::ExpressionKind::function_call);
    CHECK(call.text == "score");
    CHECK(call.names == std::vector<std::string> {"demo", "score"});
    REQUIRE(call.children.size() == 2u);
    CHECK(call.children[0].kind == rule_engine::ExpressionKind::field);
    CHECK(call.children[0].names == std::vector<std::string> {"process", "pid"});
    CHECK(call.children[1].kind == rule_engine::ExpressionKind::literal_string);
}

TEST_CASE("YARA-X bridge reports parse diagnostics without throwing") {
    auto parsed = rule_engine::parse_source("bad.yar", "rule broken { condition: and }");
    REQUIRE_FALSE(parsed.has_value());
    REQUIRE_FALSE(parsed.error().diagnostics.empty());
    CHECK(parsed.error().diagnostics[0].source == "bad.yar");
}

TEST_CASE("include resolver loads included rules through include directories") {
    rule_engine::ParseOptions options;
    options.include_dirs.push_back(fixture_path("tests/fixtures/includes/lib"));

    auto parsed = rule_engine::parse_file(fixture_path("tests/fixtures/includes/root.yar"), options);
    REQUIRE(parsed.has_value());
    REQUIRE(parsed->rules.size() == 2u);
    CHECK(parsed->rules[0].identifier == "powershell_process");
    CHECK(parsed->rules[1].identifier == "encoded_powershell");
    const auto root_source_id = source_id_for_suffix(*parsed, "root.yar");
    const auto common_source_id = source_id_for_suffix(*parsed, "common.yar");
    REQUIRE(root_source_id != 0u);
    REQUIRE(common_source_id != 0u);
    CHECK(root_source_id != common_source_id);
    CHECK(parsed->rules[0].span.source_id == common_source_id);
    CHECK(parsed->rules[1].span.source_id == root_source_id);

    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());
    REQUIRE(verified->rules.size() == 2u);
    CHECK(verified->rules[1].facts.size() == 2u);
}

TEST_CASE("include resolver reports include cycles with source file diagnostics") {
    auto parsed = rule_engine::parse_file(fixture_path("tests/fixtures/includes/cycle_a.yar"));
    REQUIRE_FALSE(parsed.has_value());
    REQUIRE_FALSE(parsed.error().diagnostics.empty());
    CHECK(parsed.error().diagnostics[0].source.find("cycle_a.yar") != std::string::npos);
    CHECK(parsed.error().diagnostics[0].message.find("include cycle") != std::string::npos);
}
