#include <rule_engine/compiler.hpp>
#include <rule_engine/evaluator.hpp>
#include <rule_engine/module_config.hpp>
#include <rule_engine/modules.hpp>
#include <rule_engine/provider_key.hpp>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
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

TEST_CASE("rule corpus examples match documented support status") {
    auto supported = rule_engine::parse_file(fixture_path("examples/rule_corpus/supported_process_pe.yar"));
    REQUIRE(supported.has_value());
    auto supported_verified = rule_engine::verify(*supported, rule_engine::default_module_registry());
    REQUIRE(supported_verified.has_value());

    constexpr std::array unsupported {
        "examples/rule_corpus/unsupported_builtin_reader.yar",
        "examples/rule_corpus/unsupported_unknown_field.yar",
    };
    for (const auto *path : unsupported) {
        auto parsed = rule_engine::parse_file(fixture_path(path));
        REQUIRE(parsed.has_value());
        auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
        REQUIRE_FALSE(verified.has_value());
        REQUIRE_FALSE(verified.error().diagnostics.empty());
    }
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
    CHECK(second.requests[0].keys == std::vector<std::string> {"demo.score(i:4242,s:616c706861)"});

    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "demo.score(i:4242,s:616c706861)",
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

TEST_CASE("cheap static module functions are prefetched before expensive facts") {
    constexpr auto source = R"(
import "demo"

rule static_score_then_scan {
    strings:
        $enc = "-enc" ascii
    condition:
        $enc and demo.score(42, "alpha") > 7
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
                .cheap_prefetch = true,
            },
        },
    });

    auto parsed = rule_engine::parse_source("static_score_then_scan.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, registry);
    REQUIRE(verified.has_value());
    REQUIRE(verified->rules.size() == 1u);

    const auto function_fact = std::ranges::find_if(verified->rules[0].facts, [](const auto &fact) {
        return fact.key == "demo.score(i:42,s:616c706861)";
    });
    REQUIRE(function_fact != verified->rules[0].facts.end());
    CHECK(function_fact->route == "endpoint.demo.functions");
    CHECK(function_fact->cheap_prefetch);
    CHECK(function_fact->type == rule_engine::ValueType::integer);

    rule_engine::FactCache facts;
    rule_engine::Evaluator evaluator {*verified, facts};
    const auto first = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(first.state == rule_engine::EvaluationState::waiting_for_facts);
    REQUIRE(first.requests.size() == 1u);
    CHECK(first.requests[0].route == "endpoint.demo.functions");
    CHECK(first.requests[0].keys == std::vector<std::string> {"demo.score(i:42,s:616c706861)"});
    CHECK(first.requests[0].types == std::vector<rule_engine::ValueType> {rule_engine::ValueType::integer});

    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "demo.score(i:42,s:616c706861)",
        .value = rule_engine::Value::integer(9),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {30},
    });

    const auto second = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(second.state == rule_engine::EvaluationState::waiting_for_facts);
    REQUIRE(second.requests.size() == 1u);
    CHECK(second.requests[0].route == "endpoint.scan.patterns");
    CHECK(second.requests[0].keys == std::vector<std::string> {"$enc.matches"});
}

TEST_CASE("descriptor timeouts flow into evaluator request batches") {
    constexpr auto source = R"(
import "demo"

rule descriptor_timeouts {
    condition:
        demo.weight > 2 and fast_flag and slow_flag and demo.score(42, "alpha") > 7
}
)";

    auto registry = rule_engine::default_module_registry();
    registry.modules.push_back(rule_engine::ModuleDescriptor {
        .name = "demo",
        .fields = {
            rule_engine::FieldDescriptor {
                .key = "demo.weight",
                .type = rule_engine::ValueType::integer,
                .route = "endpoint.demo.fields",
                .ttl = std::chrono::seconds {30},
                .timeout = std::chrono::seconds {19},
                .cheap_prefetch = true,
            },
        },
        .functions = {
            rule_engine::FunctionDescriptor {
                .name = "score",
                .parameters = {rule_engine::ValueType::integer, rule_engine::ValueType::string},
                .return_type = rule_engine::ValueType::integer,
                .key_prefix = "demo.score",
                .route = "endpoint.demo.functions",
                .ttl = std::chrono::seconds {30},
                .timeout = std::chrono::seconds {13},
                .cheap_prefetch = true,
            },
        },
    });
    registry.globals.push_back(rule_engine::GlobalDescriptor {
        .name = "fast_flag",
        .type = rule_engine::ValueType::boolean,
        .key = "global.fast_flag",
        .route = "endpoint.globals",
        .ttl = std::chrono::seconds {30},
        .timeout = std::chrono::seconds {3},
        .cheap_prefetch = true,
    });
    registry.globals.push_back(rule_engine::GlobalDescriptor {
        .name = "slow_flag",
        .type = rule_engine::ValueType::boolean,
        .key = "global.slow_flag",
        .route = "endpoint.globals",
        .ttl = std::chrono::seconds {30},
        .timeout = std::chrono::seconds {17},
        .cheap_prefetch = true,
    });

    auto parsed = rule_engine::parse_source("descriptor_timeouts.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, registry);
    REQUIRE(verified.has_value());

    rule_engine::FactCache facts;
    rule_engine::Evaluator evaluator {*verified, facts};
    const auto first = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(first.state == rule_engine::EvaluationState::waiting_for_facts);
    REQUIRE(first.requests.size() == 3u);

    const auto fields = std::ranges::find_if(first.requests, [](const auto &request) {
        return request.route == "endpoint.demo.fields";
    });
    REQUIRE(fields != first.requests.end());
    CHECK(fields->timeout == std::chrono::seconds {19});
    CHECK(fields->keys == std::vector<std::string> {"demo.weight"});

    const auto globals = std::ranges::find_if(first.requests, [](const auto &request) {
        return request.route == "endpoint.globals";
    });
    REQUIRE(globals != first.requests.end());
    CHECK(globals->timeout == std::chrono::seconds {17});
    CHECK(globals->keys == std::vector<std::string> {"global.fast_flag", "global.slow_flag"});

    const auto functions = std::ranges::find_if(first.requests, [](const auto &request) {
        return request.route == "endpoint.demo.functions";
    });
    REQUIRE(functions != first.requests.end());
    CHECK(functions->timeout == std::chrono::seconds {13});
    CHECK(functions->keys == std::vector<std::string> {"demo.score(i:42,s:616c706861)"});
}

TEST_CASE("module config file registers custom module functions for verification") {
    auto registry = rule_engine::default_module_registry();
    auto loaded = rule_engine::load_module_config_file(fixture_path("tests/fixtures/custom_binding/demo.module"), registry);
    REQUIRE(loaded.has_value());

    auto parsed = rule_engine::parse_file(fixture_path("tests/fixtures/custom_binding/demo_rule.yar"));
    REQUIRE(parsed.has_value());

    auto verified = rule_engine::verify(*parsed, registry);
    REQUIRE(verified.has_value());
    REQUIRE(verified->rules.size() == 1u);
    REQUIRE(verified->rules[0].condition.children[0].kind == rule_engine::ExpressionKind::function_call);
    CHECK(verified->rules[0].condition.children[0].bound_route == "endpoint.demo.functions");
    CHECK(verified->rules[0].condition.children[0].bound_key_prefix == "demo.score");
    CHECK(verified->rules[0].condition.children[0].bound_timeout == std::chrono::seconds {12});
    CHECK(rule_engine::required_provider_routes(*verified) ==
          std::vector<std::string> {"endpoint.demo.functions"});
}

TEST_CASE("provider function keys encode every value shape with stable v1 tokens") {
    rule_engine::PatternValue pattern;
    pattern.matched = true;
    pattern.matches.push_back(rule_engine::PatternMatchContext {
        .offset = 1,
        .length = 2,
        .bytes = {std::byte {0x41}},
        .before = {},
        .after = {std::byte {0xff}},
        .scan_space = "image",
        .region_permissions = "r-x",
    });

    const auto array = rule_engine::Value::array(std::vector<rule_engine::Value> {
        rule_engine::Value::integer(7),
        rule_engine::Value::string("x"),
        rule_engine::Value::undefined(),
    });
    const auto object = rule_engine::Value::object(std::vector<rule_engine::ObjectEntry> {
        rule_engine::ObjectEntry {
            .key = "k",
            .value = rule_engine::Value::boolean(false),
        },
        rule_engine::ObjectEntry {
            .key = "weird,key",
            .value = rule_engine::Value::bytes(std::vector<std::byte> {std::byte {0x2a}}),
        },
    });

    CHECK(rule_engine::provider_argument_key(rule_engine::Value::undefined()) == "u");
    CHECK(rule_engine::provider_argument_key(rule_engine::Value::boolean(true)) == "b:true");
    CHECK(rule_engine::provider_argument_key(rule_engine::Value::integer(-42)) == "i:-42");
    CHECK(rule_engine::provider_argument_key(rule_engine::Value::number(1.5)) == "f:3ff8000000000000");
    CHECK(rule_engine::provider_argument_key(rule_engine::Value::string("a,b)\\")) == "s:612c62295c");
    CHECK(rule_engine::provider_argument_key(
              rule_engine::Value::bytes(std::vector<std::byte> {std::byte {0x00}, std::byte {0x41}, std::byte {0xff}})) ==
          "x:0041ff");
    CHECK(rule_engine::provider_argument_key(array) == "a:3[i:7,s:78,u]");
    CHECK(rule_engine::provider_argument_key(object) == "o:2{s:6b=b:false,s:77656972642c6b6579=x:2a}");
    CHECK(rule_engine::provider_argument_key(rule_engine::Value::pattern(std::move(pattern))) ==
          "p:true:1[1:2:41::ff:696d616765:722d78]");
    CHECK(rule_engine::provider_function_key("demo.complex",
                                             std::vector<rule_engine::Value> {
                                                 rule_engine::Value::string("alpha"),
                                                 array,
                                                 object,
                                                 rule_engine::Value::undefined(),
                                             }) ==
          "demo.complex(s:616c706861,a:3[i:7,s:78,u],o:2{s:6b=b:false,s:77656972642c6b6579=x:2a},u)");
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
    CHECK(first.requests[0].keys == std::vector<std::string> {"$a.pattern"});

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

TEST_CASE("VM evaluates boolean tuple of expressions") {
    constexpr auto source = R"(
rule bool_tuple_of {
    condition:
        any of (false, true, 1 == 2) and
        all of (true, 1 == 1) and
        none of (false, 1 == 2) and
        2 of (true, false, true) and
        50% of (true, false)
}

rule bool_tuple_zero {
    condition:
        0 of (false, false) and not (0 of (false, true))
}
)";

    auto parsed = rule_engine::parse_source("bool_tuple_of_vm.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());

    rule_engine::FactCache facts;
    rule_engine::Evaluator evaluator {*verified, facts};
    const auto step = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(step.state == rule_engine::EvaluationState::complete);
    REQUIRE(step.rule_results.size() == 2u);
    CHECK(step.rule_results[0].identifier == "bool_tuple_of");
    CHECK(step.rule_results[0].matched);
    CHECK(step.rule_results[1].identifier == "bool_tuple_zero");
    CHECK(step.rule_results[1].matched);
}

TEST_CASE("VM evaluates anchored pattern-set of expressions") {
    constexpr auto source = R"(
rule anchored_pattern_of {
    strings:
        $a = "alpha" ascii
        $b = "beta" ascii
    condition:
        any of ($a, $b) at 8 and
        2 of them in (4..16) and
        none of them at 20
}
)";

    auto parsed = rule_engine::parse_source("anchored_pattern_of_vm.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());
    REQUIRE(verified->rules.size() == 1u);
    REQUIRE(verified->rules[0].facts.size() == 2u);

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
    b.matched = true;
    b.matches.push_back(rule_engine::PatternMatchContext {
        .offset = 12,
        .length = 4,
        .bytes = {},
        .before = {},
        .after = {},
        .scan_space = "process.memory",
        .region_permissions = "r",
    });

    rule_engine::FactCache facts;
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

    rule_engine::Evaluator evaluator {*verified, facts};
    const auto step = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(step.state == rule_engine::EvaluationState::complete);
    REQUIRE(step.rule_results.size() == 1u);
    CHECK(step.rule_results[0].identifier == "anchored_pattern_of");
    CHECK(step.rule_results[0].matched);
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
    CHECK(first.requests[0].keys == std::vector<std::string> {"process.path", "process.name"});

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

TEST_CASE("process user detail fields resolve to snapshot facts") {
    constexpr auto source = R"(
import "process"

rule process_user_details {
    condition:
        process.user.sid startswith "S-" and process.user.name != ""
}
)";

    auto parsed = rule_engine::parse_source("process_user_details.yar", source);
    REQUIRE(parsed.has_value());

    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());
    REQUIRE(verified->rules.size() == 1u);
    REQUIRE(verified->rules[0].facts.size() == 2u);
    CHECK(verified->rules[0].facts[0].key == "process.user.sid");
    CHECK(verified->rules[0].facts[1].key == "process.user.name");

    rule_engine::FactCache facts;
    rule_engine::Evaluator evaluator {*verified, facts};
    const auto first = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(first.state == rule_engine::EvaluationState::waiting_for_facts);
    REQUIRE(first.requests.size() == 1u);
    CHECK(first.requests[0].route == "endpoint.process.snapshot");
    CHECK(first.requests[0].keys == std::vector<std::string> {"process.user.sid", "process.user.name"});

    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "process.user.sid",
        .value = rule_engine::Value::string("S-1-5-21-1-2-3-1001"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
    });
    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "process.user.name",
        .value = rule_engine::Value::string("DOMAIN\\user"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
    });

    const auto second = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(second.state == rule_engine::EvaluationState::complete);
    REQUIRE(second.rule_results.size() == 1u);
    CHECK(second.rule_results[0].identifier == "process_user_details");
    CHECK(second.rule_results[0].matched);
}

TEST_CASE("process token metadata fields resolve to snapshot facts") {
    constexpr auto source = R"(
import "process"

rule process_token_metadata {
    condition:
        process.token.elevated and process.token.type == "primary"
}
)";

    auto parsed = rule_engine::parse_source("process_token_metadata.yar", source);
    REQUIRE(parsed.has_value());

    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());
    REQUIRE(verified->rules.size() == 1u);
    REQUIRE(verified->rules[0].facts.size() == 2u);
    CHECK(verified->rules[0].facts[0].key == "process.token.elevated");
    CHECK(verified->rules[0].facts[1].key == "process.token.type");

    rule_engine::FactCache facts;
    rule_engine::Evaluator evaluator {*verified, facts};
    const auto first = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(first.state == rule_engine::EvaluationState::waiting_for_facts);
    REQUIRE(first.requests.size() == 1u);
    CHECK(first.requests[0].route == "endpoint.process.snapshot");
    CHECK(first.requests[0].keys == std::vector<std::string> {"process.token.elevated", "process.token.type"});

    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "process.token.elevated",
        .value = rule_engine::Value::boolean(true),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
    });
    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "process.token.type",
        .value = rule_engine::Value::string("primary"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
    });

    const auto second = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(second.state == rule_engine::EvaluationState::complete);
    REQUIRE(second.rule_results.size() == 1u);
    CHECK(second.rule_results[0].identifier == "process_token_metadata");
    CHECK(second.rule_results[0].matched);
}

TEST_CASE("process loaded module fields resolve to snapshot facts") {
    constexpr auto source = R"(
import "process"

rule process_loaded_modules {
    condition:
        process.modules.count > 0 and
        for any module_name in process.modules.names : (module_name == "kernel32.dll")
}
)";

    auto parsed = rule_engine::parse_source("process_loaded_modules.yar", source);
    REQUIRE(parsed.has_value());

    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());
    REQUIRE(verified->rules.size() == 1u);
    REQUIRE(verified->rules[0].facts.size() == 2u);
    CHECK(verified->rules[0].facts[0].key == "process.modules.count");
    CHECK(verified->rules[0].facts[1].key == "process.modules.names");

    rule_engine::FactCache facts;
    rule_engine::Evaluator evaluator {*verified, facts};
    const auto first = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(first.state == rule_engine::EvaluationState::waiting_for_facts);
    REQUIRE(first.requests.size() == 1u);
    CHECK(first.requests[0].route == "endpoint.process.snapshot");
    CHECK(first.requests[0].keys == std::vector<std::string> {"process.modules.count"});

    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "process.modules.count",
        .value = rule_engine::Value::integer(2),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
    });
    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "process.modules.names",
        .value = rule_engine::Value::array(std::vector<rule_engine::Value> {
            rule_engine::Value::string("rule_engine_tests.exe"),
            rule_engine::Value::string("kernel32.dll"),
        }),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
    });

    const auto second = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(second.state == rule_engine::EvaluationState::complete);
    REQUIRE(second.rule_results.size() == 1u);
    CHECK(second.rule_results[0].identifier == "process_loaded_modules");
    CHECK(second.rule_results[0].matched);
}

TEST_CASE("process memory region count fields resolve to snapshot facts") {
    constexpr auto source = R"(
import "process"

rule process_memory_regions {
    condition:
        process.memory.regions.count > 0 and process.memory.regions.readable_count > 0
}
)";

    auto parsed = rule_engine::parse_source("process_memory_regions.yar", source);
    REQUIRE(parsed.has_value());

    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());
    REQUIRE(verified->rules.size() == 1u);
    REQUIRE(verified->rules[0].facts.size() == 2u);
    CHECK(verified->rules[0].facts[0].key == "process.memory.regions.count");
    CHECK(verified->rules[0].facts[1].key == "process.memory.regions.readable_count");

    rule_engine::FactCache facts;
    rule_engine::Evaluator evaluator {*verified, facts};
    const auto first = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(first.state == rule_engine::EvaluationState::waiting_for_facts);
    REQUIRE(first.requests.size() == 1u);
    CHECK(first.requests[0].route == "endpoint.process.snapshot");
    CHECK(first.requests[0].keys == std::vector<std::string> {"process.memory.regions.count"});

    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "process.memory.regions.count",
        .value = rule_engine::Value::integer(8),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
    });
    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "process.memory.regions.readable_count",
        .value = rule_engine::Value::integer(4),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
    });

    const auto second = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(second.state == rule_engine::EvaluationState::complete);
    REQUIRE(second.rule_results.size() == 1u);
    CHECK(second.rule_results[0].identifier == "process_memory_regions");
    CHECK(second.rule_results[0].matched);
}

TEST_CASE("process memory region arrays resolve to snapshot facts") {
    constexpr auto source = R"(
import "process"

rule process_memory_region_array {
    condition:
        for any region in process.memory.regions : (
            region["scan_space"] == "process.memory" and
            region["readable"] and
            region["size"] > 0
        )
}
)";

    auto parsed = rule_engine::parse_source("process_memory_region_array.yar", source);
    REQUIRE(parsed.has_value());

    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());
    REQUIRE(verified->rules.size() == 1u);
    REQUIRE(verified->rules[0].facts.size() == 1u);
    CHECK(verified->rules[0].facts[0].key == "process.memory.regions");

    rule_engine::FactCache facts;
    rule_engine::Evaluator evaluator {*verified, facts};
    const auto first = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(first.state == rule_engine::EvaluationState::waiting_for_facts);
    REQUIRE(first.requests.size() == 1u);
    CHECK(first.requests[0].route == "endpoint.process.snapshot");
    CHECK(first.requests[0].keys == std::vector<std::string> {"process.memory.regions"});

    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "process.memory.regions",
        .value = rule_engine::Value::array(std::vector<rule_engine::Value> {
            rule_engine::Value::object(std::vector<rule_engine::ObjectEntry> {
                rule_engine::ObjectEntry {.key = "base", .value = rule_engine::Value::integer(4096)},
                rule_engine::ObjectEntry {.key = "size", .value = rule_engine::Value::integer(8192)},
                rule_engine::ObjectEntry {.key = "state", .value = rule_engine::Value::string("commit")},
                rule_engine::ObjectEntry {.key = "protection", .value = rule_engine::Value::string("rw")},
                rule_engine::ObjectEntry {.key = "type", .value = rule_engine::Value::string("private")},
                rule_engine::ObjectEntry {.key = "readable", .value = rule_engine::Value::boolean(true)},
                rule_engine::ObjectEntry {.key = "scan_space", .value = rule_engine::Value::string("process.memory")},
            }),
        }),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
    });

    const auto second = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(second.state == rule_engine::EvaluationState::complete);
    REQUIRE(second.rule_results.size() == 1u);
    CHECK(second.rule_results[0].identifier == "process_memory_region_array");
    CHECK(second.rule_results[0].matched);
}

TEST_CASE("PE section array resolves to image facts") {
    constexpr auto source = R"(
import "pe"

rule pe_section_array {
    condition:
        pe.number_of_sections > 0 and
        for any section in pe.sections : (
            section["name"] != "" and
            section["virtual_size"] > 0 and
            section["readable"]
        )
}
)";

    auto parsed = rule_engine::parse_source("pe_section_array.yar", source);
    REQUIRE(parsed.has_value());

    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());
    REQUIRE(verified->rules.size() == 1u);
    REQUIRE(verified->rules[0].facts.size() == 2u);
    CHECK(verified->rules[0].facts[0].key == "pe.number_of_sections");
    CHECK(verified->rules[0].facts[1].key == "pe.sections");

    rule_engine::FactCache facts;
    rule_engine::Evaluator evaluator {*verified, facts};
    const auto first = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(first.state == rule_engine::EvaluationState::waiting_for_facts);
    REQUIRE(first.requests.size() == 1u);
    CHECK(first.requests[0].route == "endpoint.process.image.pe");
    CHECK(first.requests[0].keys == std::vector<std::string> {"pe.number_of_sections"});

    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "pe.number_of_sections",
        .value = rule_engine::Value::integer(1),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
    });
    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "pe.sections",
        .value = rule_engine::Value::array(std::vector<rule_engine::Value> {
            rule_engine::Value::object(std::vector<rule_engine::ObjectEntry> {
                rule_engine::ObjectEntry {.key = "name", .value = rule_engine::Value::string(".text")},
                rule_engine::ObjectEntry {.key = "virtual_address", .value = rule_engine::Value::integer(4096)},
                rule_engine::ObjectEntry {.key = "virtual_size", .value = rule_engine::Value::integer(8192)},
                rule_engine::ObjectEntry {.key = "raw_data_offset", .value = rule_engine::Value::integer(1024)},
                rule_engine::ObjectEntry {.key = "raw_data_size", .value = rule_engine::Value::integer(8192)},
                rule_engine::ObjectEntry {.key = "characteristics", .value = rule_engine::Value::integer(0x60000020)},
                rule_engine::ObjectEntry {.key = "readable", .value = rule_engine::Value::boolean(true)},
                rule_engine::ObjectEntry {.key = "writable", .value = rule_engine::Value::boolean(false)},
                rule_engine::ObjectEntry {.key = "executable", .value = rule_engine::Value::boolean(true)},
            }),
        }),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
    });

    const auto second = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(second.state == rule_engine::EvaluationState::complete);
    REQUIRE(second.rule_results.size() == 1u);
    CHECK(second.rule_results[0].identifier == "pe_section_array");
    CHECK(second.rule_results[0].matched);
}

TEST_CASE("PE header fields resolve to image facts") {
    constexpr auto source = R"(
import "pe"

rule pe_header_fields {
    condition:
        pe.subsystem > 0 and
        pe.characteristics > 0 and
        pe.dll_characteristics >= 0 and
        pe.timestamp >= 0
}
)";

    auto parsed = rule_engine::parse_source("pe_header_fields.yar", source);
    REQUIRE(parsed.has_value());

    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());
    REQUIRE(verified->rules.size() == 1u);
    REQUIRE(verified->rules[0].facts.size() == 4u);
    CHECK(verified->rules[0].facts[0].key == "pe.subsystem");
    CHECK(verified->rules[0].facts[1].key == "pe.characteristics");
    CHECK(verified->rules[0].facts[2].key == "pe.dll_characteristics");
    CHECK(verified->rules[0].facts[3].key == "pe.timestamp");

    rule_engine::FactCache facts;
    rule_engine::Evaluator evaluator {*verified, facts};
    const auto first = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(first.state == rule_engine::EvaluationState::waiting_for_facts);
    REQUIRE(first.requests.size() == 1u);
    CHECK(first.requests[0].route == "endpoint.process.image.pe");
    CHECK(first.requests[0].keys == std::vector<std::string> {
                                      "pe.subsystem",
                                      "pe.characteristics",
                                      "pe.dll_characteristics",
                                      "pe.timestamp",
                                  });

    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "pe.subsystem",
        .value = rule_engine::Value::integer(3),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {30},
    });
    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "pe.characteristics",
        .value = rule_engine::Value::integer(0x22),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {30},
    });
    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "pe.dll_characteristics",
        .value = rule_engine::Value::integer(0x8160),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {30},
    });
    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "pe.timestamp",
        .value = rule_engine::Value::integer(0),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {30},
    });

    const auto second = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(second.state == rule_engine::EvaluationState::complete);
    REQUIRE(second.rule_results.size() == 1u);
    CHECK(second.rule_results[0].identifier == "pe_header_fields");
    CHECK(second.rule_results[0].matched);
}

TEST_CASE("PE import array resolves to image facts") {
    constexpr auto source = R"(
import "pe"

rule pe_import_array {
    condition:
        for any imp in pe.imports : (
            imp["dll"] != "" and
            imp["name"] == "CreateFileW" and
            imp["hint"] >= 0 and
            imp["lookup_rva"] > 0 and
            imp["iat_rva"] > 0
        )
}
)";

    auto parsed = rule_engine::parse_source("pe_import_array.yar", source);
    REQUIRE(parsed.has_value());

    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());
    REQUIRE(verified->rules.size() == 1u);
    REQUIRE(verified->rules[0].facts.size() == 1u);
    CHECK(verified->rules[0].facts[0].key == "pe.imports");

    rule_engine::FactCache facts;
    rule_engine::Evaluator evaluator {*verified, facts};
    const auto first = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(first.state == rule_engine::EvaluationState::waiting_for_facts);
    REQUIRE(first.requests.size() == 1u);
    CHECK(first.requests[0].route == "endpoint.process.image.pe");
    CHECK(first.requests[0].keys == std::vector<std::string> {"pe.imports"});

    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "pe.imports",
        .value = rule_engine::Value::array(std::vector<rule_engine::Value> {
            rule_engine::Value::object(std::vector<rule_engine::ObjectEntry> {
                rule_engine::ObjectEntry {.key = "dll", .value = rule_engine::Value::string("KERNEL32.dll")},
                rule_engine::ObjectEntry {.key = "name", .value = rule_engine::Value::string("CreateFileW")},
                rule_engine::ObjectEntry {.key = "ordinal", .value = rule_engine::Value::undefined()},
                rule_engine::ObjectEntry {.key = "hint", .value = rule_engine::Value::integer(128)},
                rule_engine::ObjectEntry {.key = "lookup_rva", .value = rule_engine::Value::integer(8192)},
                rule_engine::ObjectEntry {.key = "iat_rva", .value = rule_engine::Value::integer(12288)},
            }),
        }),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {30},
    });

    const auto second = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(second.state == rule_engine::EvaluationState::complete);
    REQUIRE(second.rule_results.size() == 1u);
    CHECK(second.rule_results[0].identifier == "pe_import_array");
    CHECK(second.rule_results[0].matched);
}

TEST_CASE("PE export array resolves to image facts") {
    constexpr auto source = R"(
import "pe"

rule pe_export_array {
    condition:
        for any exp in pe.exports : (
            exp["module"] != "" and
            exp["name"] == "GetLastError" and
            exp["ordinal"] > 0 and
            exp["rva"] > 0 and
            not exp["forwarded"]
        )
}
)";

    auto parsed = rule_engine::parse_source("pe_export_array.yar", source);
    REQUIRE(parsed.has_value());

    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());
    REQUIRE(verified->rules.size() == 1u);
    REQUIRE(verified->rules[0].facts.size() == 1u);
    CHECK(verified->rules[0].facts[0].key == "pe.exports");

    rule_engine::FactCache facts;
    rule_engine::Evaluator evaluator {*verified, facts};
    const auto first = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(first.state == rule_engine::EvaluationState::waiting_for_facts);
    REQUIRE(first.requests.size() == 1u);
    CHECK(first.requests[0].route == "endpoint.process.image.pe");
    CHECK(first.requests[0].keys == std::vector<std::string> {"pe.exports"});

    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "pe.exports",
        .value = rule_engine::Value::array(std::vector<rule_engine::Value> {
            rule_engine::Value::object(std::vector<rule_engine::ObjectEntry> {
                rule_engine::ObjectEntry {.key = "module", .value = rule_engine::Value::string("KERNEL32.dll")},
                rule_engine::ObjectEntry {.key = "name", .value = rule_engine::Value::string("GetLastError")},
                rule_engine::ObjectEntry {.key = "ordinal", .value = rule_engine::Value::integer(512)},
                rule_engine::ObjectEntry {.key = "rva", .value = rule_engine::Value::integer(4096)},
                rule_engine::ObjectEntry {.key = "forwarded", .value = rule_engine::Value::boolean(false)},
                rule_engine::ObjectEntry {.key = "forwarder", .value = rule_engine::Value::undefined()},
            }),
        }),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {30},
    });

    const auto second = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(second.state == rule_engine::EvaluationState::complete);
    REQUIRE(second.rule_results.size() == 1u);
    CHECK(second.rule_results[0].identifier == "pe_export_array");
    CHECK(second.rule_results[0].matched);
}

TEST_CASE("PE debug entries resolve to image facts") {
    constexpr auto source = R"(
import "pe"

rule pe_debug_entries {
    condition:
        for any entry in pe.debug_entries : (
            entry["type"] == 2 and
            entry["size"] > 0 and
            entry["address_of_raw_data"] > 0
        )
}
)";

    auto parsed = rule_engine::parse_source("pe_debug_entries.yar", source);
    REQUIRE(parsed.has_value());

    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());
    REQUIRE(verified->rules.size() == 1u);
    REQUIRE(verified->rules[0].facts.size() == 1u);
    CHECK(verified->rules[0].facts[0].key == "pe.debug_entries");

    rule_engine::FactCache facts;
    rule_engine::Evaluator evaluator {*verified, facts};
    const auto first = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(first.state == rule_engine::EvaluationState::waiting_for_facts);
    REQUIRE(first.requests.size() == 1u);
    CHECK(first.requests[0].route == "endpoint.process.image.pe");
    CHECK(first.requests[0].keys == std::vector<std::string> {"pe.debug_entries"});

    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "pe.debug_entries",
        .value = rule_engine::Value::array(std::vector<rule_engine::Value> {
            rule_engine::Value::object(std::vector<rule_engine::ObjectEntry> {
                rule_engine::ObjectEntry {.key = "type", .value = rule_engine::Value::integer(2)},
                rule_engine::ObjectEntry {.key = "timestamp", .value = rule_engine::Value::integer(0)},
                rule_engine::ObjectEntry {.key = "major_version", .value = rule_engine::Value::integer(0)},
                rule_engine::ObjectEntry {.key = "minor_version", .value = rule_engine::Value::integer(0)},
                rule_engine::ObjectEntry {.key = "size", .value = rule_engine::Value::integer(128)},
                rule_engine::ObjectEntry {.key = "address_of_raw_data", .value = rule_engine::Value::integer(4096)},
                rule_engine::ObjectEntry {.key = "pointer_to_raw_data", .value = rule_engine::Value::integer(8192)},
            }),
        }),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {30},
    });

    const auto second = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(second.state == rule_engine::EvaluationState::complete);
    REQUIRE(second.rule_results.size() == 1u);
    CHECK(second.rule_results[0].identifier == "pe_debug_entries");
    CHECK(second.rule_results[0].matched);
}

TEST_CASE("PE resource entries resolve to image facts") {
    constexpr auto source = R"(
import "pe"

rule pe_resource_entries {
    condition:
        for any resource in pe.resources : (
            resource["type_id"] == 16 and
            resource["language_id"] >= 0 and
            resource["rva"] > 0 and
            resource["size"] > 0
        )
}
)";

    auto parsed = rule_engine::parse_source("pe_resource_entries.yar", source);
    REQUIRE(parsed.has_value());

    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());
    REQUIRE(verified->rules.size() == 1u);
    REQUIRE(verified->rules[0].facts.size() == 1u);
    CHECK(verified->rules[0].facts[0].key == "pe.resources");

    rule_engine::FactCache facts;
    rule_engine::Evaluator evaluator {*verified, facts};
    const auto first = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(first.state == rule_engine::EvaluationState::waiting_for_facts);
    REQUIRE(first.requests.size() == 1u);
    CHECK(first.requests[0].route == "endpoint.process.image.pe");
    CHECK(first.requests[0].keys == std::vector<std::string> {"pe.resources"});

    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "pe.resources",
        .value = rule_engine::Value::array(std::vector<rule_engine::Value> {
            rule_engine::Value::object(std::vector<rule_engine::ObjectEntry> {
                rule_engine::ObjectEntry {.key = "type_id", .value = rule_engine::Value::integer(16)},
                rule_engine::ObjectEntry {.key = "type_name", .value = rule_engine::Value::undefined()},
                rule_engine::ObjectEntry {.key = "name_id", .value = rule_engine::Value::integer(1)},
                rule_engine::ObjectEntry {.key = "name", .value = rule_engine::Value::undefined()},
                rule_engine::ObjectEntry {.key = "language_id", .value = rule_engine::Value::integer(1033)},
                rule_engine::ObjectEntry {.key = "rva", .value = rule_engine::Value::integer(4096)},
                rule_engine::ObjectEntry {.key = "size", .value = rule_engine::Value::integer(512)},
                rule_engine::ObjectEntry {.key = "code_page", .value = rule_engine::Value::integer(0)},
            }),
        }),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {30},
    });

    const auto second = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(second.state == rule_engine::EvaluationState::complete);
    REQUIRE(second.rule_results.size() == 1u);
    CHECK(second.rule_results[0].identifier == "pe_resource_entries");
    CHECK(second.rule_results[0].matched);
}

TEST_CASE("PE certificate entries resolve to image facts") {
    constexpr auto source = R"(
import "pe"

rule pe_certificate_entries {
    condition:
        for any certificate in pe.certificates : (
            certificate["type"] == 2 and
            certificate["revision"] == 512 and
            certificate["file_offset"] > 0 and
            certificate["payload_size"] > 0
        )
}
)";

    auto parsed = rule_engine::parse_source("pe_certificate_entries.yar", source);
    REQUIRE(parsed.has_value());

    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());
    REQUIRE(verified->rules.size() == 1u);
    REQUIRE(verified->rules[0].facts.size() == 1u);
    CHECK(verified->rules[0].facts[0].key == "pe.certificates");

    rule_engine::FactCache facts;
    rule_engine::Evaluator evaluator {*verified, facts};
    const auto first = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(first.state == rule_engine::EvaluationState::waiting_for_facts);
    REQUIRE(first.requests.size() == 1u);
    CHECK(first.requests[0].route == "endpoint.process.image.pe");
    CHECK(first.requests[0].keys == std::vector<std::string> {"pe.certificates"});

    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "pe.certificates",
        .value = rule_engine::Value::array(std::vector<rule_engine::Value> {
            rule_engine::Value::object(std::vector<rule_engine::ObjectEntry> {
                rule_engine::ObjectEntry {.key = "file_offset", .value = rule_engine::Value::integer(1024)},
                rule_engine::ObjectEntry {.key = "size", .value = rule_engine::Value::integer(32)},
                rule_engine::ObjectEntry {.key = "revision", .value = rule_engine::Value::integer(512)},
                rule_engine::ObjectEntry {.key = "type", .value = rule_engine::Value::integer(2)},
                rule_engine::ObjectEntry {.key = "payload_size", .value = rule_engine::Value::integer(24)},
            }),
        }),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {30},
    });

    const auto second = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(second.state == rule_engine::EvaluationState::complete);
    REQUIRE(second.rule_results.size() == 1u);
    CHECK(second.rule_results[0].identifier == "pe_certificate_entries");
    CHECK(second.rule_results[0].matched);
}

TEST_CASE("PE TLS callbacks resolve to image facts") {
    constexpr auto source = R"(
import "pe"

rule pe_tls_callbacks {
    condition:
        for any callback in pe.tls_callbacks : (
            callback["index"] == 0 and
            callback["va"] > callback["rva"] and
            callback["rva"] == 4660
        )
}
)";

    auto parsed = rule_engine::parse_source("pe_tls_callbacks.yar", source);
    REQUIRE(parsed.has_value());

    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());
    REQUIRE(verified->rules.size() == 1u);
    REQUIRE(verified->rules[0].facts.size() == 1u);
    CHECK(verified->rules[0].facts[0].key == "pe.tls_callbacks");

    rule_engine::FactCache facts;
    rule_engine::Evaluator evaluator {*verified, facts};
    const auto first = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(first.state == rule_engine::EvaluationState::waiting_for_facts);
    REQUIRE(first.requests.size() == 1u);
    CHECK(first.requests[0].route == "endpoint.process.image.pe");
    CHECK(first.requests[0].keys == std::vector<std::string> {"pe.tls_callbacks"});

    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "pe.tls_callbacks",
        .value = rule_engine::Value::array(std::vector<rule_engine::Value> {
            rule_engine::Value::object(std::vector<rule_engine::ObjectEntry> {
                rule_engine::ObjectEntry {.key = "index", .value = rule_engine::Value::integer(0)},
                rule_engine::ObjectEntry {.key = "va", .value = rule_engine::Value::integer(0x0040'1234)},
                rule_engine::ObjectEntry {.key = "rva", .value = rule_engine::Value::integer(0x1234)},
            }),
        }),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {30},
    });

    const auto second = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(second.state == rule_engine::EvaluationState::complete);
    REQUIRE(second.rule_results.size() == 1u);
    CHECK(second.rule_results[0].identifier == "pe_tls_callbacks");
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
    CHECK(first.requests[0].keys == std::vector<std::string> {"$a.pattern"});

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
    REQUIRE(first.requests.size() == 1u);
    CHECK(first.requests[0].route == "endpoint.process.snapshot");
    CHECK(first.requests[0].keys == std::vector<std::string> {"process.name"});

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
    REQUIRE(first.requests.size() == 1u);
    CHECK(first.requests[0].route == "endpoint.process.snapshot");
    CHECK(first.requests[0].keys == std::vector<std::string> {"process.name"});

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

TEST_CASE("scheduler defers expensive scan facts behind cheap filters") {
    constexpr auto source = R"(
import "process"

rule staged_scan {
    strings:
        $enc = "-enc" ascii
    condition:
        process.name == "cmd.exe" and $enc
}
)";

    auto parsed = rule_engine::parse_source("staged_scan.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());
    REQUIRE(verified->rules.size() == 1u);
    REQUIRE(verified->rules[0].facts.size() == 2u);

    rule_engine::FactCache rejected_facts;
    rule_engine::Evaluator rejected_evaluator {*verified, rejected_facts};
    const auto rejected_first = rejected_evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(rejected_first.state == rule_engine::EvaluationState::waiting_for_facts);
    REQUIRE(rejected_first.requests.size() == 1u);
    CHECK(rejected_first.requests[0].route == "endpoint.process.snapshot");
    CHECK(rejected_first.requests[0].keys == std::vector<std::string> {"process.name"});

    rejected_facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "process.name",
        .value = rule_engine::Value::string("powershell.exe"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
    });

    const auto rejected_second = rejected_evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(rejected_second.state == rule_engine::EvaluationState::complete);
    REQUIRE(rejected_second.rule_results.size() == 1u);
    CHECK_FALSE(rejected_second.rule_results[0].matched);
    CHECK(rejected_second.requests.empty());

    rule_engine::FactCache accepted_facts;
    rule_engine::Evaluator accepted_evaluator {*verified, accepted_facts};
    const auto accepted_first = accepted_evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:43"});
    REQUIRE(accepted_first.state == rule_engine::EvaluationState::waiting_for_facts);
    REQUIRE(accepted_first.requests.size() == 1u);
    CHECK(accepted_first.requests[0].route == "endpoint.process.snapshot");
    CHECK(accepted_first.requests[0].keys == std::vector<std::string> {"process.name"});

    accepted_facts.store(rule_engine::Fact {
        .subject_id = "pid:43",
        .key = "process.name",
        .value = rule_engine::Value::string("cmd.exe"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
    });

    const auto accepted_second = accepted_evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:43"});
    REQUIRE(accepted_second.state == rule_engine::EvaluationState::waiting_for_facts);
    REQUIRE(accepted_second.requests.size() == 1u);
    CHECK(accepted_second.requests[0].route == "endpoint.scan.patterns");
    CHECK(accepted_second.requests[0].keys == std::vector<std::string> {"$enc.matches"});
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
    REQUIRE(first.requests.size() == 1u);
    CHECK(first.requests[0].route == "endpoint.process.snapshot");
    CHECK(first.requests[0].keys == std::vector<std::string> {"process.name"});

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

TEST_CASE("VM rejects cached field facts with descriptor type mismatches") {
    constexpr auto source = R"(
import "process"

rule typed_pid {
    condition:
        process.pid > 0
}
)";

    auto parsed = rule_engine::parse_source("typed_pid.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());

    rule_engine::FactCache facts;
    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "process.pid",
        .value = rule_engine::Value::string("not-an-integer"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
    });

    rule_engine::Evaluator evaluator {*verified, facts};
    const auto result = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(result.state == rule_engine::EvaluationState::complete);
    REQUIRE(result.rule_results.size() == 1u);
    CHECK_FALSE(result.rule_results[0].matched);
    REQUIRE_FALSE(result.rule_results[0].diagnostics.empty());
    CHECK(result.rule_results[0].diagnostics[0].message.find("process.pid") != std::string::npos);
    CHECK(result.rule_results[0].diagnostics[0].message.find("integer") != std::string::npos);
}

TEST_CASE("VM rejects cached function facts with descriptor return type mismatches") {
    constexpr auto source = R"(
import "demo"

rule typed_score {
    condition:
        demo.score(42, "alpha") > 7
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

    auto parsed = rule_engine::parse_source("typed_score.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, registry);
    REQUIRE(verified.has_value());

    rule_engine::FactCache facts;
    facts.store(rule_engine::Fact {
        .subject_id = "pid:42",
        .key = "demo.score(i:42,s:616c706861)",
        .value = rule_engine::Value::string("not-an-integer"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {30},
    });

    rule_engine::Evaluator evaluator {*verified, facts};
    const auto result = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:42"});
    REQUIRE(result.state == rule_engine::EvaluationState::complete);
    REQUIRE(result.rule_results.size() == 1u);
    CHECK_FALSE(result.rule_results[0].matched);
    REQUIRE_FALSE(result.rule_results[0].diagnostics.empty());
    CHECK(result.rule_results[0].diagnostics[0].message.find("demo.score") != std::string::npos);
    CHECK(result.rule_results[0].diagnostics[0].message.find("integer") != std::string::npos);
}
