#include <rule_engine/compiler.hpp>
#include <rule_engine/evaluator.hpp>
#include <rule_engine/modules.hpp>

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <utility>
#include <vector>

namespace {
    [[nodiscard]] std::filesystem::path fixture_path(const std::string_view relative_path) {
        return std::filesystem::path {RULE_ENGINE_SOURCE_DIR} / std::filesystem::path {relative_path};
    }
} // namespace

TEST_CASE("semantic verification rejects unknown module fields before execution") {
    constexpr auto source = R"(
import "process"

rule bad_field {
    condition:
        process.no_such_field == "x"
}
)";

    auto parsed = rule_engine::parse_source("bad_field.yar", source);
    REQUIRE(parsed.has_value());

    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE_FALSE(verified.has_value());
    REQUIRE_FALSE(verified.error().diagnostics.empty());
    CHECK(verified.error().diagnostics[0].message.find("process.no_such_field") != std::string::npos);
}

TEST_CASE("semantic diagnostics preserve included source names") {
    rule_engine::ParseOptions options;
    options.include_dirs.push_back(fixture_path("tests/fixtures/includes/lib"));

    auto parsed = rule_engine::parse_file(fixture_path("tests/fixtures/includes/root_bad_field.yar"), options);
    REQUIRE(parsed.has_value());

    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE_FALSE(verified.has_value());
    REQUIRE_FALSE(verified.error().diagnostics.empty());
    CHECK(verified.error().diagnostics[0].source.find("bad_common.yar") != std::string::npos);
    CHECK(verified.error().diagnostics[0].message.find("process.no_such_field") != std::string::npos);
}

TEST_CASE("semantic verification rejects unknown rule references before execution") {
    constexpr auto source = R"(
rule bad_reference {
    condition:
        no_such_rule
}
)";

    auto parsed = rule_engine::parse_source("bad_reference.yar", source);
    REQUIRE(parsed.has_value());

    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE_FALSE(verified.has_value());
    REQUIRE_FALSE(verified.error().diagnostics.empty());
    CHECK(verified.error().diagnostics[0].message.find("no_such_rule") != std::string::npos);
}

TEST_CASE("descriptor-backed globals resolve to async facts") {
    constexpr auto source = R"(
import "process"

rule gated_by_scan_mode {
    condition:
        scan_mode == "process" and process.name == "powershell.exe"
}
)";

    auto registry = rule_engine::default_module_registry();
    registry.globals.push_back(rule_engine::GlobalDescriptor {
        .name = "scan_mode",
        .type = rule_engine::ValueType::string,
        .key = "global.scan_mode",
        .route = "endpoint.globals",
        .ttl = std::chrono::seconds {30},
        .cheap_prefetch = true,
    });

    auto parsed = rule_engine::parse_source("globals.yar", source);
    REQUIRE(parsed.has_value());

    auto verified = rule_engine::verify(*parsed, registry);
    REQUIRE(verified.has_value());
    REQUIRE(verified->rules.size() == 1u);
    REQUIRE(verified->rules[0].facts.size() == 2u);
    CHECK(verified->rules[0].facts[0].key == "global.scan_mode");
    CHECK(verified->rules[0].facts[0].route == "endpoint.globals");
    CHECK(verified->rules[0].condition.children[0].children[0].kind == rule_engine::ExpressionKind::global);

    rule_engine::FactCache facts;
    rule_engine::Evaluator evaluator {*verified, facts};
    const auto first = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(first.state == rule_engine::EvaluationState::waiting_for_facts);
    REQUIRE(first.requests.size() == 2u);
    CHECK(first.requests[0].route == "endpoint.globals");
    CHECK(first.requests[0].keys == std::vector<std::string> {"global.scan_mode"});
    CHECK(first.requests[1].route == "endpoint.process.snapshot");
    CHECK(first.requests[1].keys == std::vector<std::string> {"process.name"});

    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "global.scan_mode",
        .value = rule_engine::Value::string("process"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {30},
    });
    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "process.name",
        .value = rule_engine::Value::string("powershell.exe"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
    });

    const auto second = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(second.state == rule_engine::EvaluationState::complete);
    REQUIRE(second.rule_results.size() == 1u);
    CHECK(second.rule_results[0].identifier == "gated_by_scan_mode");
    CHECK(second.rule_results[0].matched);
}

TEST_CASE("descriptor-backed module functions resolve to async fact bindings") {
    constexpr auto source = R"(
import "process"
import "demo"

rule suspicious_score {
    condition:
        demo.score(process.pid, "alpha") > 7
}
)";

    auto registry = rule_engine::default_module_registry();
    registry.modules.push_back(rule_engine::ModuleDescriptor {
        .name = "demo",
        .fields = {},
        .functions = {
            rule_engine::FunctionDescriptor {
                .name = "score",
                .parameters = {rule_engine::ValueType::integer, rule_engine::ValueType::string},
                .return_type = rule_engine::ValueType::integer,
                .key_prefix = "demo.score",
                .route = "endpoint.demo.functions",
                .ttl = std::chrono::seconds {30},
                .cheap_prefetch = false,
            },
        },
    });

    auto parsed = rule_engine::parse_source("functions.yar", source);
    REQUIRE(parsed.has_value());

    auto verified = rule_engine::verify(*parsed, registry);
    REQUIRE(verified.has_value());
    REQUIRE(verified->rules.size() == 1u);
    REQUIRE(verified->rules[0].facts.size() == 1u);
    CHECK(verified->rules[0].facts[0].key == "process.pid");
    REQUIRE(verified->rules[0].condition.children[0].kind == rule_engine::ExpressionKind::function_call);
    CHECK(verified->rules[0].condition.children[0].text == "demo.score");
    CHECK(verified->rules[0].condition.children[0].names == std::vector<std::string> {"demo", "score"});
    CHECK(verified->rules[0].condition.children[0].bound_route == "endpoint.demo.functions");
    CHECK(verified->rules[0].condition.children[0].bound_key_prefix == "demo.score");

    rule_engine::FactCache facts;
    rule_engine::Evaluator evaluator {*verified, facts};
    const auto first = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(first.state == rule_engine::EvaluationState::waiting_for_facts);
    REQUIRE(first.requests.size() == 1u);
    CHECK(first.requests[0].route == "endpoint.process.snapshot");
    CHECK(first.requests[0].keys == std::vector<std::string> {"process.pid"});

    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "process.pid",
        .value = rule_engine::Value::integer(4242),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
    });

    const auto second = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(second.state == rule_engine::EvaluationState::waiting_for_facts);
    REQUIRE(second.requests.size() == 1u);
    CHECK(second.requests[0].route == "endpoint.demo.functions");
    CHECK(second.requests[0].keys == std::vector<std::string> {"demo.score(i:4242,s:alpha)"});

    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "demo.score(i:4242,s:alpha)",
        .value = rule_engine::Value::integer(9),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {30},
    });

    const auto third = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(third.state == rule_engine::EvaluationState::complete);
    REQUIRE(third.rule_results.size() == 1u);
    CHECK(third.rule_results[0].matched);
}

TEST_CASE("semantic verification rejects statically invalid module function argument types") {
    constexpr auto source = R"(
import "process"
import "demo"

rule bad_function_argument {
    condition:
        demo.score(process.name, "alpha") > 7
}
)";

    auto registry = rule_engine::default_module_registry();
    registry.modules.push_back(rule_engine::ModuleDescriptor {
        .name = "demo",
        .fields = {},
        .functions = {
            rule_engine::FunctionDescriptor {
                .name = "score",
                .parameters = {rule_engine::ValueType::integer, rule_engine::ValueType::string},
                .return_type = rule_engine::ValueType::integer,
                .key_prefix = "demo.score",
                .route = "endpoint.demo.functions",
                .ttl = std::chrono::seconds {30},
                .cheap_prefetch = false,
            },
        },
    });

    auto parsed = rule_engine::parse_source("bad_function_argument.yar", source);
    REQUIRE(parsed.has_value());

    auto verified = rule_engine::verify(*parsed, registry);
    REQUIRE_FALSE(verified.has_value());
    REQUIRE_FALSE(verified.error().diagnostics.empty());
    CHECK(verified.error().diagnostics[0].message.find("function demo.score argument 1 expects integer but got string") !=
          std::string::npos);
}

TEST_CASE("semantic verification rejects unknown and unsupported function calls") {
    constexpr auto unknown_source = R"(
import "process"

rule bad_function {
    condition:
        uint16(0) == 0
}
)";

    auto parsed = rule_engine::parse_source("unknown_function.yar", unknown_source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE_FALSE(verified.has_value());
    REQUIRE_FALSE(verified.error().diagnostics.empty());
    CHECK(verified.error().diagnostics[0].message.find("unknown function uint16") != std::string::npos);
}

TEST_CASE("VM follows YARA-X undefined operator semantics") {
    constexpr auto source = R"(
rule undefined_or_true {
    condition:
        maybe_bool or true
}

rule undefined_or_false {
    condition:
        maybe_bool or false
}

rule undefined_and_true {
    condition:
        maybe_bool and true
}

rule not_undefined {
    condition:
        not maybe_bool
}

rule undefined_equal {
    condition:
        maybe_int == 7
}

rule undefined_not_equal {
    condition:
        maybe_int != 7
}

rule not_undefined_comparison {
    condition:
        not (maybe_int == 7)
}
)";

    auto registry = rule_engine::default_module_registry();
    registry.globals.push_back(rule_engine::GlobalDescriptor {
        .name = "maybe_bool",
        .type = rule_engine::ValueType::boolean,
        .key = "global.maybe_bool",
        .route = "endpoint.globals",
        .ttl = std::chrono::seconds {30},
        .cheap_prefetch = true,
    });
    registry.globals.push_back(rule_engine::GlobalDescriptor {
        .name = "maybe_int",
        .type = rule_engine::ValueType::integer,
        .key = "global.maybe_int",
        .route = "endpoint.globals",
        .ttl = std::chrono::seconds {30},
        .cheap_prefetch = true,
    });

    auto parsed = rule_engine::parse_source("undefined_semantics.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, registry);
    REQUIRE(verified.has_value());

    rule_engine::FactCache facts;
    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "global.maybe_bool",
        .value = rule_engine::Value::undefined(),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {30},
    });
    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "global.maybe_int",
        .value = rule_engine::Value::undefined(),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {30},
    });

    const rule_engine::Evaluator evaluator {*verified, facts};
    const auto result = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(result.state == rule_engine::EvaluationState::complete);
    REQUIRE(result.rule_results.size() == 7u);
    CHECK(result.rule_results[0].identifier == "undefined_or_true");
    CHECK(result.rule_results[0].matched);
    for (std::size_t index = 1; index < result.rule_results.size(); ++index) {
        CHECK_FALSE(result.rule_results[index].matched);
    }
}

TEST_CASE("VM evaluates arithmetic and bitwise integer expressions") {
    constexpr auto source = R"(
import "process"

rule numeric_process_filter {
    condition:
        process.pid + 4 * 2 == 50 and (process.pid & 15) == 10
}
)";

    auto parsed = rule_engine::parse_source("numeric_vm.yar", source);
    REQUIRE(parsed.has_value());

    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());
    REQUIRE(verified->rules.size() == 1u);
    REQUIRE(verified->rules[0].facts.size() == 1u);
    CHECK(verified->rules[0].facts[0].key == "process.pid");

    rule_engine::FactCache facts;
    rule_engine::Evaluator evaluator {*verified, facts};
    const auto first = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(first.state == rule_engine::EvaluationState::waiting_for_facts);
    REQUIRE(first.requests.size() == 1u);
    CHECK(first.requests[0].route == "endpoint.process.snapshot");
    CHECK(first.requests[0].keys == std::vector<std::string> {"process.pid"});

    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "process.pid",
        .value = rule_engine::Value::integer(42),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
    });

    const auto second = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(second.state == rule_engine::EvaluationState::complete);
    REQUIRE(second.rule_results.size() == 1u);
    CHECK(second.rule_results[0].identifier == "numeric_process_filter");
    CHECK(second.rule_results[0].matched);
}

TEST_CASE("VM evaluates pattern count offset and length metadata") {
    constexpr auto source = R"(
rule pattern_metadata {
    strings:
        $enc = "-enc" ascii
    condition:
        #enc == 2 and @enc[1] == 16 and !enc[1] == 4
}
)";

    auto parsed = rule_engine::parse_source("pattern_metadata_vm.yar", source);
    REQUIRE(parsed.has_value());

    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());
    REQUIRE(verified->rules.size() == 1u);
    REQUIRE(verified->rules[0].facts.size() == 1u);
    CHECK(verified->rules[0].facts[0].key == "$enc.pattern");
    CHECK(verified->rules[0].facts[0].route == "endpoint.scan.patterns");

    rule_engine::FactCache facts;
    rule_engine::Evaluator evaluator {*verified, facts};
    const auto first = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(first.state == rule_engine::EvaluationState::waiting_for_facts);
    REQUIRE(first.requests.size() == 1u);
    CHECK(first.requests[0].keys == std::vector<std::string> {"$enc.pattern"});

    rule_engine::PatternValue pattern;
    pattern.matched = true;
    pattern.matches.push_back(rule_engine::PatternMatchContext {
        .offset = 16,
        .length = 4,
        .bytes = {},
        .before = {},
        .after = {},
        .scan_space = "process.memory",
        .region_permissions = "rx",
    });
    pattern.matches.push_back(rule_engine::PatternMatchContext {
        .offset = 64,
        .length = 4,
        .bytes = {},
        .before = {},
        .after = {},
        .scan_space = "process.memory",
        .region_permissions = "rx",
    });
    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "$enc.pattern",
        .value = rule_engine::Value::pattern(std::move(pattern)),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {30},
    });

    const auto second = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(second.state == rule_engine::EvaluationState::complete);
    REQUIRE(second.rule_results.size() == 1u);
    CHECK(second.rule_results[0].identifier == "pattern_metadata");
    CHECK(second.rule_results[0].matched);
}

TEST_CASE("VM evaluates pattern-set of expressions from pattern facts") {
    constexpr auto source = R"(
rule one_of_patterns {
    strings:
        $a = "alpha" ascii
        $b = "beta" ascii
    condition:
        1 of ($a, $b)
}

rule all_patterns {
    strings:
        $a = "alpha" ascii
        $b = "beta" ascii
    condition:
        all of them
}
)";

    auto parsed = rule_engine::parse_source("pattern_sets_vm.yar", source);
    REQUIRE(parsed.has_value());

    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());
    REQUIRE(verified->rules.size() == 2u);
    REQUIRE(verified->rules[0].facts.size() == 2u);
    CHECK(verified->rules[0].facts[0].key == "$a.pattern");
    CHECK(verified->rules[0].facts[1].key == "$b.pattern");
    REQUIRE(verified->rules[1].facts.size() == 2u);
    CHECK(verified->rules[1].facts[0].key == "$a.pattern");
    CHECK(verified->rules[1].facts[1].key == "$b.pattern");

    rule_engine::FactCache facts;
    rule_engine::Evaluator evaluator {*verified, facts};
    const auto first = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(first.state == rule_engine::EvaluationState::waiting_for_facts);
    REQUIRE(first.requests.size() == 1u);
    CHECK(first.requests[0].route == "endpoint.scan.patterns");
    CHECK(first.requests[0].keys == std::vector<std::string> {"$a.pattern", "$b.pattern"});

    rule_engine::PatternValue a;
    a.matched = true;
    a.matches.push_back(rule_engine::PatternMatchContext {
        .offset = 8,
        .length = 5,
        .bytes = {},
        .before = {},
        .after = {},
        .scan_space = "process.memory",
        .region_permissions = "r",
    });
    rule_engine::PatternValue b;
    b.matched = false;
    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "$a.pattern",
        .value = rule_engine::Value::pattern(std::move(a)),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {30},
    });
    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "$b.pattern",
        .value = rule_engine::Value::pattern(std::move(b)),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {30},
    });

    const auto second = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(second.state == rule_engine::EvaluationState::complete);
    REQUIRE(second.rule_results.size() == 2u);
    CHECK(second.rule_results[0].identifier == "one_of_patterns");
    CHECK(second.rule_results[0].matched);
    CHECK(second.rule_results[1].identifier == "all_patterns");
    CHECK_FALSE(second.rule_results[1].matched);
}

TEST_CASE("VM treats zero pattern quantifiers as exactly none matched") {
    constexpr auto source = R"(
rule zero_of_patterns {
    strings:
        $a = "alpha" ascii
        $b = "beta" ascii
    condition:
        0 of them
}

rule for_zero_of_patterns {
    strings:
        $a = "alpha" ascii
        $b = "beta" ascii
    condition:
        for 0 of them : ( $ )
}
)";

    auto parsed = rule_engine::parse_source("zero_quantifier_vm.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());

    rule_engine::FactCache no_matches;
    no_matches.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "$a.pattern",
        .value = rule_engine::Value::pattern(rule_engine::PatternValue {}),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {30},
    });
    no_matches.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "$b.pattern",
        .value = rule_engine::Value::pattern(rule_engine::PatternValue {}),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {30},
    });

    const rule_engine::Evaluator no_match_evaluator {*verified, no_matches};
    const auto no_match_result = no_match_evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(no_match_result.state == rule_engine::EvaluationState::complete);
    REQUIRE(no_match_result.rule_results.size() == 2u);
    CHECK(no_match_result.rule_results[0].matched);
    CHECK(no_match_result.rule_results[1].matched);

    rule_engine::PatternValue matched_pattern;
    matched_pattern.matched = true;
    matched_pattern.matches.push_back(rule_engine::PatternMatchContext {
        .offset = 16,
        .length = 5,
        .bytes = {},
        .before = {},
        .after = {},
        .scan_space = "process.memory",
        .region_permissions = "r",
    });
    rule_engine::FactCache one_match;
    one_match.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "$a.pattern",
        .value = rule_engine::Value::pattern(std::move(matched_pattern)),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {30},
    });
    one_match.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "$b.pattern",
        .value = rule_engine::Value::pattern(rule_engine::PatternValue {}),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {30},
    });

    const rule_engine::Evaluator one_match_evaluator {*verified, one_match};
    const auto one_match_result = one_match_evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(one_match_result.state == rule_engine::EvaluationState::complete);
    REQUIRE(one_match_result.rule_results.size() == 2u);
    CHECK_FALSE(one_match_result.rule_results[0].matched);
    CHECK_FALSE(one_match_result.rule_results[1].matched);
}

TEST_CASE("VM evaluates extended string operators") {
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

    auto parsed = rule_engine::parse_source("string_ops_vm.yar", source);
    REQUIRE(parsed.has_value());

    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());
    REQUIRE(verified->rules.size() == 1u);
    REQUIRE(verified->rules[0].facts.size() == 3u);
    CHECK(verified->rules[0].facts[0].key == "process.command_line");
    CHECK(verified->rules[0].facts[1].key == "process.path");
    CHECK(verified->rules[0].facts[2].key == "process.name");

    rule_engine::FactCache facts;
    rule_engine::Evaluator evaluator {*verified, facts};
    const auto first = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(first.state == rule_engine::EvaluationState::waiting_for_facts);
    REQUIRE(first.requests.size() == 1u);
    CHECK(first.requests[0].route == "endpoint.process.snapshot");
    CHECK(first.requests[0].keys ==
          std::vector<std::string> {"process.command_line", "process.path", "process.name"});

    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "process.command_line",
        .value = rule_engine::Value::string("powershell.exe -enc SQBFAFgA"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
    });
    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "process.path",
        .value = rule_engine::Value::string("fixtures/windows/system32/windowspowershell/v1.0/powershell.exe"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
    });
    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "process.name",
        .value = rule_engine::Value::string("powershell.exe"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
    });

    const auto second = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(second.state == rule_engine::EvaluationState::complete);
    REQUIRE(second.rule_results.size() == 1u);
    CHECK(second.rule_results[0].identifier == "string_ops");
    CHECK(second.rule_results[0].matched);
}

TEST_CASE("VM evaluates with expression local bindings") {
    constexpr auto source = R"(
import "process"

rule with_alias {
    condition:
        with cmd = process.command_line : (cmd icontains "-ENC")
}
)";

    auto parsed = rule_engine::parse_source("with_vm.yar", source);
    REQUIRE(parsed.has_value());

    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());
    REQUIRE(verified->rules.size() == 1u);
    REQUIRE(verified->rules[0].facts.size() == 1u);
    CHECK(verified->rules[0].facts[0].key == "process.command_line");

    rule_engine::FactCache facts;
    rule_engine::Evaluator evaluator {*verified, facts};
    const auto first = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(first.state == rule_engine::EvaluationState::waiting_for_facts);
    REQUIRE(first.requests.size() == 1u);
    CHECK(first.requests[0].route == "endpoint.process.snapshot");
    CHECK(first.requests[0].keys == std::vector<std::string> {"process.command_line"});

    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "process.command_line",
        .value = rule_engine::Value::string("powershell.exe -enc SQBFAFgA"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
    });

    const auto second = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(second.state == rule_engine::EvaluationState::complete);
    REQUIRE(second.rule_results.size() == 1u);
    CHECK(second.rule_results[0].identifier == "with_alias");
    CHECK(second.rule_results[0].matched);
}

TEST_CASE("VM evaluates for-in range and tuple local bindings") {
    constexpr auto source = R"(
rule range_loop {
    condition:
        for all i in (1..3) : (i > 0)
}

rule tuple_loop {
    condition:
        for any e in (1, 2, 3) : (e == 3)
}
)";

    auto parsed = rule_engine::parse_source("for_in_vm.yar", source);
    REQUIRE(parsed.has_value());

    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());
    REQUIRE(verified->rules.size() == 2u);
    CHECK(verified->rules[0].facts.empty());
    CHECK(verified->rules[1].facts.empty());

    rule_engine::FactCache facts;
    rule_engine::Evaluator evaluator {*verified, facts};
    const auto result = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(result.state == rule_engine::EvaluationState::complete);
    REQUIRE(result.rule_results.size() == 2u);
    CHECK(result.rule_results[0].identifier == "range_loop");
    CHECK(result.rule_results[0].matched);
    CHECK(result.rule_results[1].identifier == "tuple_loop");
    CHECK(result.rule_results[1].matched);
}

TEST_CASE("VM rejects oversized for-in ranges before materializing values") {
    constexpr auto source = R"(
rule oversized_range {
    condition:
        for any i in (lower..upper) : (i == upper)
}
)";

    rule_engine::ModuleRegistry registry = rule_engine::default_module_registry();
    registry.globals.push_back(rule_engine::GlobalDescriptor {
        .name = "lower",
        .type = rule_engine::ValueType::integer,
        .key = "global.lower",
        .route = "endpoint.globals",
        .ttl = std::chrono::seconds {30},
        .cheap_prefetch = true,
    });
    registry.globals.push_back(rule_engine::GlobalDescriptor {
        .name = "upper",
        .type = rule_engine::ValueType::integer,
        .key = "global.upper",
        .route = "endpoint.globals",
        .ttl = std::chrono::seconds {30},
        .cheap_prefetch = true,
    });

    auto parsed = rule_engine::parse_source("oversized_range.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, registry);
    REQUIRE(verified.has_value());

    rule_engine::FactCache facts;
    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "global.lower",
        .value = rule_engine::Value::integer(0),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {30},
    });
    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "global.upper",
        .value = rule_engine::Value::integer(100000),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {30},
    });

    rule_engine::Evaluator evaluator {*verified, facts};
    const auto result = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});

    REQUIRE(result.state == rule_engine::EvaluationState::complete);
    REQUIRE(result.rule_results.size() == 1u);
    CHECK(result.rule_results[0].identifier == "oversized_range");
    CHECK_FALSE(result.rule_results[0].matched);
}

TEST_CASE("VM evaluates for-in array and object iterables") {
    constexpr auto source = R"(
rule array_value_loop {
    condition:
        for any n in numbers : (n == 3)
}

rule array_pair_loop {
    condition:
        for any i, n in numbers : (i == 2 and n == 3)
}

rule object_value_loop {
    condition:
        for all value in counters : (value > 0)
}

rule object_pair_loop {
    condition:
        for any k, v in counters : (k == "critical" and v == 7)
}
)";

    auto parsed = rule_engine::parse_source("iterable_values.yar", source);
    REQUIRE(parsed.has_value());

    auto registry = rule_engine::default_module_registry();
    registry.globals.push_back(rule_engine::GlobalDescriptor {
        .name = "numbers",
        .type = rule_engine::ValueType::array,
        .key = "numbers",
        .route = "endpoint.globals",
    });
    registry.globals.push_back(rule_engine::GlobalDescriptor {
        .name = "counters",
        .type = rule_engine::ValueType::object,
        .key = "counters",
        .route = "endpoint.globals",
    });
    auto verified = rule_engine::verify(*parsed, registry);
    REQUIRE(verified.has_value());

    rule_engine::FactCache facts;
    rule_engine::Evaluator evaluator {*verified, facts};
    const auto first = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(first.state == rule_engine::EvaluationState::waiting_for_facts);
    REQUIRE(first.requests.size() == 1u);
    CHECK(first.requests[0].route == "endpoint.globals");

    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "numbers",
        .value = rule_engine::Value::array(std::vector<rule_engine::Value> {
            rule_engine::Value::integer(1),
            rule_engine::Value::integer(2),
            rule_engine::Value::integer(3),
        }),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
    });
    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "counters",
        .value = rule_engine::Value::object(std::vector<rule_engine::ObjectEntry> {
            rule_engine::ObjectEntry {.key = "minor", .value = rule_engine::Value::integer(1)},
            rule_engine::ObjectEntry {.key = "critical", .value = rule_engine::Value::integer(7)},
        }),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
    });

    const auto second = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(second.state == rule_engine::EvaluationState::complete);
    REQUIRE(second.rule_results.size() == 4u);
    CHECK(second.rule_results[0].matched);
    CHECK(second.rule_results[1].matched);
    CHECK(second.rule_results[2].matched);
    CHECK(second.rule_results[3].matched);
}

TEST_CASE("VM evaluates for-of pattern body placeholders") {
    constexpr auto source = R"(
rule any_pattern_body {
    strings:
        $a = "alpha" ascii
        $b = "beta" ascii
    condition:
        for any of them : ( $ )
}

rule all_pattern_counts {
    strings:
        $a = "alpha" ascii
        $b = "beta" ascii
    condition:
        for all of ($a, $b) : ( # >= 1 )
}

rule numeric_pattern_body {
    strings:
        $a = "alpha" ascii
        $b = "beta" ascii
    condition:
        for 2 of them : ( $ )
}

rule percentage_pattern_body {
    strings:
        $a = "alpha" ascii
        $b = "beta" ascii
    condition:
        for 50% of them : ( $ )
}
)";

    auto parsed = rule_engine::parse_source("for_of_vm.yar", source);
    REQUIRE(parsed.has_value());

    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());
    REQUIRE(verified->rules.size() == 4u);
    REQUIRE(verified->rules[0].facts.size() == 2u);
    CHECK(verified->rules[0].facts[0].key == "$a.pattern");
    CHECK(verified->rules[0].facts[1].key == "$b.pattern");
    REQUIRE(verified->rules[1].facts.size() == 2u);
    CHECK(verified->rules[1].facts[0].key == "$a.pattern");
    CHECK(verified->rules[1].facts[1].key == "$b.pattern");

    rule_engine::FactCache facts;
    rule_engine::Evaluator evaluator {*verified, facts};
    const auto first = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(first.state == rule_engine::EvaluationState::waiting_for_facts);
    REQUIRE(first.requests.size() == 1u);
    CHECK(first.requests[0].route == "endpoint.scan.patterns");
    CHECK(first.requests[0].keys == std::vector<std::string> {"$a.pattern", "$b.pattern"});

    rule_engine::PatternValue a;
    a.matched = true;
    a.matches.push_back(rule_engine::PatternMatchContext {
        .offset = 8,
        .length = 5,
        .bytes = {},
        .before = {},
        .after = {},
        .scan_space = "process.memory",
        .region_permissions = "r",
    });
    rule_engine::PatternValue b;
    b.matched = false;
    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "$a.pattern",
        .value = rule_engine::Value::pattern(std::move(a)),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {30},
    });
    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "$b.pattern",
        .value = rule_engine::Value::pattern(std::move(b)),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {30},
    });

    const auto second = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(second.state == rule_engine::EvaluationState::complete);
    REQUIRE(second.rule_results.size() == 4u);
    CHECK(second.rule_results[0].identifier == "any_pattern_body");
    CHECK(second.rule_results[0].matched);
    CHECK(second.rule_results[1].identifier == "all_pattern_counts");
    CHECK_FALSE(second.rule_results[1].matched);
    CHECK(second.rule_results[2].identifier == "numeric_pattern_body");
    CHECK_FALSE(second.rule_results[2].matched);
    CHECK(second.rule_results[3].identifier == "percentage_pattern_body");
    CHECK(second.rule_results[3].matched);
}

TEST_CASE("VM evaluates array and object lookup expressions") {
    constexpr auto source = R"(
rule lookup_values {
    condition:
        numbers[1] == 42 and proc["name"] == "powershell.exe"
}
)";

    auto registry = rule_engine::default_module_registry();
    registry.globals.push_back(rule_engine::GlobalDescriptor {
        .name = "numbers",
        .type = rule_engine::ValueType::array,
        .key = "global.numbers",
        .route = "endpoint.globals",
        .ttl = std::chrono::seconds {30},
        .cheap_prefetch = true,
    });
    registry.globals.push_back(rule_engine::GlobalDescriptor {
        .name = "proc",
        .type = rule_engine::ValueType::object,
        .key = "global.proc",
        .route = "endpoint.globals",
        .ttl = std::chrono::seconds {30},
        .cheap_prefetch = true,
    });

    auto parsed = rule_engine::parse_source("lookup_vm.yar", source);
    REQUIRE(parsed.has_value());

    auto verified = rule_engine::verify(*parsed, registry);
    REQUIRE(verified.has_value());
    REQUIRE(verified->rules.size() == 1u);
    REQUIRE(verified->rules[0].facts.size() == 2u);
    CHECK(verified->rules[0].facts[0].key == "global.numbers");
    CHECK(verified->rules[0].facts[1].key == "global.proc");

    rule_engine::FactCache facts;
    rule_engine::Evaluator evaluator {*verified, facts};
    const auto first = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(first.state == rule_engine::EvaluationState::waiting_for_facts);
    REQUIRE(first.requests.size() == 1u);
    CHECK(first.requests[0].route == "endpoint.globals");
    CHECK(first.requests[0].keys == std::vector<std::string> {"global.numbers", "global.proc"});

    std::vector<rule_engine::Value> numbers;
    numbers.push_back(rule_engine::Value::integer(7));
    numbers.push_back(rule_engine::Value::integer(42));
    std::vector<rule_engine::ObjectEntry> proc;
    proc.push_back(rule_engine::ObjectEntry {
        .key = "name",
        .value = rule_engine::Value::string("powershell.exe"),
    });

    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "global.numbers",
        .value = rule_engine::Value::array(std::move(numbers)),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {30},
    });
    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "global.proc",
        .value = rule_engine::Value::object(std::move(proc)),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {30},
    });

    const auto second = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(second.state == rule_engine::EvaluationState::complete);
    REQUIRE(second.rule_results.size() == 1u);
    CHECK(second.rule_results[0].identifier == "lookup_values");
    CHECK(second.rule_results[0].matched);
}

TEST_CASE("semantic verification rejects rule reference cycles") {
    constexpr auto source = R"(
rule a {
    condition:
        b
}

rule b {
    condition:
        a
}
)";

    auto parsed = rule_engine::parse_source("cycle.yar", source);
    REQUIRE(parsed.has_value());

    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE_FALSE(verified.has_value());
    REQUIRE_FALSE(verified.error().diagnostics.empty());
    CHECK(verified.error().diagnostics[0].message.find("cycle") != std::string::npos);
}

TEST_CASE("VM evaluates rule references and propagates referenced fact requirements") {
    constexpr auto source = R"(
import "process"

rule powershell_process {
    condition:
        process.name == "powershell.exe"
}

rule encoded_powershell {
    strings:
        $enc = "-enc" ascii
    condition:
        powershell_process and $enc
}
)";

    auto parsed = rule_engine::parse_source("rule_refs.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());
    REQUIRE(verified->rules.size() == 2u);
    CHECK(verified->rules[1].facts.size() == 2u);

    rule_engine::FactCache facts;
    rule_engine::Evaluator evaluator {*verified, facts};
    const auto first = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(first.state == rule_engine::EvaluationState::waiting_for_facts);
    REQUIRE(first.requests.size() == 2u);
    CHECK(first.requests[0].route == "endpoint.process.snapshot");
    CHECK(first.requests[1].route == "endpoint.scan.patterns");

    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "process.name",
        .value = rule_engine::Value::string("powershell.exe"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
    });
    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "$enc.matches",
        .value = rule_engine::Value::boolean(true),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
    });

    const auto second = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(second.state == rule_engine::EvaluationState::complete);
    REQUIRE(second.rule_results.size() == 2u);
    CHECK(second.rule_results[0].matched);
    CHECK(second.rule_results[1].matched);
}

TEST_CASE("VM evaluates qualified cross-namespace rule references") {
    const std::vector<rule_engine::SourceUnit> sources {
        rule_engine::SourceUnit {
            .source_name = "shared.yar",
            .namespace_name = "shared",
            .source = R"(
import "process"

rule powershell_process {
    condition:
        process.name == "powershell.exe"
}
)",
        },
        rule_engine::SourceUnit {
            .source_name = "detect.yar",
            .namespace_name = "detect",
            .source = R"(
rule encoded_powershell {
    strings:
        $enc = "-enc" ascii
    condition:
        shared.powershell_process and $enc
}
)",
        },
    };

    auto parsed = rule_engine::parse_sources(sources);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());
    REQUIRE(verified->rules.size() == 2u);
    CHECK(verified->rules[0].qualified_identifier == "shared.powershell_process");
    CHECK(verified->rules[1].qualified_identifier == "detect.encoded_powershell");
    CHECK(verified->rules[1].rule_dependencies == std::vector<std::string> {"shared.powershell_process"});
    CHECK(verified->rules[1].facts.size() == 2u);
    CHECK(verified->ir_dump().find("namespace=detect") != std::string::npos);

    rule_engine::FactCache facts;
    rule_engine::Evaluator evaluator {*verified, facts};
    const auto first = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(first.state == rule_engine::EvaluationState::waiting_for_facts);
    REQUIRE(first.requests.size() == 2u);
    CHECK(first.requests[0].route == "endpoint.process.snapshot");
    CHECK(first.requests[1].route == "endpoint.scan.patterns");

    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "process.name",
        .value = rule_engine::Value::string("powershell.exe"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
    });
    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "$enc.matches",
        .value = rule_engine::Value::boolean(true),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
    });

    const auto second = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(second.state == rule_engine::EvaluationState::complete);
    REQUIRE(second.rule_results.size() == 2u);
    CHECK(second.rule_results[0].identifier == "shared.powershell_process");
    CHECK(second.rule_results[0].matched);
    CHECK(second.rule_results[1].identifier == "detect.encoded_powershell");
    CHECK(second.rule_results[1].matched);
}

TEST_CASE("semantic verification rejects ambiguous duplicate rules in the same namespace") {
    const std::vector<rule_engine::SourceUnit> sources {
        rule_engine::SourceUnit {
            .source_name = "one.yar",
            .namespace_name = "shared",
            .source = "rule duplicate { condition: true }",
        },
        rule_engine::SourceUnit {
            .source_name = "two.yar",
            .namespace_name = "shared",
            .source = "rule duplicate { condition: false }",
        },
    };

    auto parsed = rule_engine::parse_sources(sources);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE_FALSE(verified.has_value());
    REQUIRE_FALSE(verified.error().diagnostics.empty());
    CHECK(verified.error().diagnostics[0].message.find("shared.duplicate") != std::string::npos);
}

TEST_CASE("private rules can be referenced but are not reported") {
    constexpr auto source = R"(
import "process"

private rule powershell_process {
    condition:
        process.name == "powershell.exe"
}

rule visible_detection {
    condition:
        powershell_process
}
)";

    auto parsed = rule_engine::parse_source("private_rule.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());
    REQUIRE(verified->rules.size() == 2u);
    CHECK(verified->rules[0].is_private);

    rule_engine::FactCache facts;
    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "process.name",
        .value = rule_engine::Value::string("powershell.exe"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
    });

    rule_engine::Evaluator evaluator {*verified, facts};
    const auto result = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(result.state == rule_engine::EvaluationState::complete);
    REQUIRE(result.rule_results.size() == 1u);
    CHECK(result.rule_results[0].identifier == "visible_detection");
    CHECK(result.rule_results[0].matched);
}

TEST_CASE("global rules gate non-global rule evaluation and avoid unnecessary fact requests") {
    constexpr auto source = R"(
import "process"

global rule powershell_only {
    condition:
        process.name == "powershell.exe"
}

rule encoded_command {
    strings:
        $enc = "-enc" ascii
    condition:
        $enc
}
)";

    auto parsed = rule_engine::parse_source("global_gate.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());
    REQUIRE(verified->rules.size() == 2u);
    CHECK(verified->rules[0].is_global);

    rule_engine::FactCache facts;
    rule_engine::Evaluator evaluator {*verified, facts};
    const auto first = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(first.state == rule_engine::EvaluationState::waiting_for_facts);
    REQUIRE(first.requests.size() == 1u);
    CHECK(first.requests[0].route == "endpoint.process.snapshot");
    CHECK(first.requests[0].keys.size() == 1u);
    CHECK(first.requests[0].keys[0] == "process.name");

    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "process.name",
        .value = rule_engine::Value::string("cmd.exe"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
    });

    const auto second = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(second.state == rule_engine::EvaluationState::complete);
    REQUIRE(second.rule_results.size() == 2u);
    CHECK(second.rule_results[0].identifier == "powershell_only");
    CHECK_FALSE(second.rule_results[0].matched);
    CHECK(second.rule_results[1].identifier == "encoded_command");
    CHECK_FALSE(second.rule_results[1].matched);
}

TEST_CASE("global rules may not depend on non-global rules") {
    constexpr auto source = R"(
rule helper {
    condition:
        true
}

global rule invalid_gate {
    condition:
        helper
}
)";

    auto parsed = rule_engine::parse_source("invalid_global_reference.yar", source);
    REQUIRE(parsed.has_value());

    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE_FALSE(verified.has_value());
    REQUIRE_FALSE(verified.error().diagnostics.empty());
    CHECK(verified.error().diagnostics[0].message.find("global rule") != std::string::npos);
    CHECK(verified.error().diagnostics[0].message.find("non-global rule") != std::string::npos);
}

TEST_CASE("VM pauses for missing facts and resumes when provider facts arrive") {
    constexpr auto source = R"(
import "process"

rule encoded_powershell {
    strings:
        $enc = "-enc" ascii
    condition:
        process.name == "powershell.exe" and $enc
}
)";

    auto parsed = rule_engine::parse_source("vm.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());

    rule_engine::FactCache facts;
    rule_engine::Evaluator evaluator {*verified, facts};
    const auto first = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(first.state == rule_engine::EvaluationState::waiting_for_facts);
    REQUIRE(first.requests.size() == 2u);
    CHECK(first.requests[0].route == "endpoint.process.snapshot");
    CHECK(first.requests[1].route == "endpoint.scan.patterns");

    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "process.name",
        .value = rule_engine::Value::string("powershell.exe"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
    });
    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "$enc.matches",
        .value = rule_engine::Value::boolean(true),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
    });

    const auto second = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(second.state == rule_engine::EvaluationState::complete);
    REQUIRE(second.rule_results.size() == 1u);
    CHECK(second.rule_results[0].matched);
}

TEST_CASE("provider diagnostics produce no-match results") {
    constexpr auto source = R"(
import "process"

rule unavailable_command_line {
    condition:
        process.command_line contains "-enc"
}
)";

    auto parsed = rule_engine::parse_source("diag.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());

    rule_engine::FactCache facts;
    facts.store(rule_engine::Fact {
        .subject_id = "pid:7",
        .key = "process.command_line",
        .value = rule_engine::Value::undefined(),
        .status = rule_engine::FactStatus::access_denied,
        .diagnostic = "command line unavailable",
    });

    rule_engine::Evaluator evaluator {*verified, facts};
    const auto result = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:7"});
    REQUIRE(result.state == rule_engine::EvaluationState::complete);
    REQUIRE(result.rule_results.size() == 1u);
    CHECK_FALSE(result.rule_results[0].matched);
    REQUIRE_FALSE(result.rule_results[0].diagnostics.empty());
}
