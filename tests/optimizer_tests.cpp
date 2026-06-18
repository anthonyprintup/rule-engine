#include <rule_engine/compiler.hpp>
#include <rule_engine/evaluator.hpp>
#include <rule_engine/modules.hpp>
#include <rule_engine/optimizer.hpp>
#include <rule_engine/protocol.hpp>

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace {
    [[nodiscard]] bool contains(const std::string_view text, const std::string_view needle) {
        return text.find(needle) != std::string_view::npos;
    }

    [[nodiscard]] const rule_engine::optimizer::StaticFactCacheCandidate *
    find_static_candidate(const std::vector<rule_engine::optimizer::StaticFactCacheCandidate> &candidates,
                          const std::string_view subject_id, const std::string_view key) {
        for (const auto &candidate : candidates) {
            if (candidate.subject_id == subject_id && candidate.key == key) {
                return &candidate;
            }
        }
        return nullptr;
    }
} // namespace

TEST_CASE("canonical predicate extraction deduplicates descriptor comparisons") {
    constexpr std::string_view source = R"(
import "process"

rule first {
    condition:
        process.name == "powershell.exe"
}

rule second {
    condition:
        "powershell.exe" == process.name
}

rule exact_only {
    condition:
        with name = process.name : (name == "powershell.exe")
}
)";

    auto parsed = rule_engine::parse_source("optimizer.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());

    const auto report = rule_engine::optimizer::extract_canonical_predicates(*verified);

    REQUIRE(report.predicates.size() == 1u);
    CHECK(report.predicates[0].id == "endpoint.process.snapshot|process.name|equal|string:powershell.exe");
    CHECK(report.predicates[0].fact_key == "process.name");
    CHECK(report.predicates[0].route == "endpoint.process.snapshot");
    CHECK(report.predicates[0].cost_class == rule_engine::FactCostClass::inventory);
    CHECK(report.predicates[0].operation == "equal");
    CHECK(report.predicates[0].literal_kind == "string");
    CHECK(report.predicates[0].literal_value == "powershell.exe");
    REQUIRE(report.predicates[0].owners.size() == 2u);
    CHECK(report.predicates[0].owners[0].rule_identifier == "first");
    CHECK(report.predicates[0].owners[1].rule_identifier == "second");

    REQUIRE(report.exact_vm_only.size() == 1u);
    CHECK(report.exact_vm_only[0].rule_identifier == "exact_only");
    CHECK(report.exact_vm_only[0].reason == "with expressions remain exact-VM-only");

    const auto json = rule_engine::optimizer::canonical_predicate_report_json(report);
    CHECK(contains(json, R"("schema":"rule-engine-canonical-predicates.v1")"));
    CHECK(contains(json, R"("predicateCount":1)"));
    CHECK(contains(json, R"("ownerCount":2)"));
    CHECK(contains(json, R"("exactVmOnlyCount":1)"));
    CHECK(contains(json, R"("id":"endpoint.process.snapshot|process.name|equal|string:powershell.exe")"));
    CHECK(contains(json, R"("costClass":"inventory")"));
}

TEST_CASE("optimizer plan captures ordered predicates fallbacks and provider requirements") {
    constexpr std::string_view source = R"(
import "process"
import "pe"

rule cheap_first {
    condition:
        process.name == "powershell.exe" and
        for any imported in pe.imports : (imported["dll"] contains "KERNEL32.dll")
}

rule exact_vm {
    condition:
        with pname = process.name : (pname == "powershell.exe")
}
)";

    auto parsed = rule_engine::parse_source("optimizer-plan.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());

    const auto plan = rule_engine::optimizer::build_optimizer_plan(*verified);

    REQUIRE(plan.predicate_nodes.size() == 1u);
    CHECK(plan.predicate_nodes[0].id == "endpoint.process.snapshot|process.name|equal|string:powershell.exe");
    CHECK(plan.predicate_nodes[0].cost_class == rule_engine::FactCostClass::inventory);
    REQUIRE(plan.predicate_nodes[0].owners.size() == 1u);
    CHECK(plan.predicate_nodes[0].owners[0].rule_identifier == "cheap_first");
    CHECK(plan.predicate_nodes[0].owners[0].prune_safe);
    CHECK(plan.predicate_order ==
          std::vector<std::string> {"endpoint.process.snapshot|process.name|equal|string:powershell.exe"});

    REQUIRE(plan.exact_vm_fallbacks.size() == 2u);
    CHECK(plan.exact_vm_fallbacks[0].rule_identifier == "cheap_first");
    CHECK(plan.exact_vm_fallbacks[0].reason == "for-in expressions remain exact-VM-only");
    CHECK(plan.exact_vm_fallbacks[1].rule_identifier == "exact_vm");
    CHECK(plan.exact_vm_fallbacks[1].reason == "with expressions remain exact-VM-only");

    REQUIRE(plan.provider_requirements.size() == 2u);
    CHECK(plan.provider_requirements[0].route == "endpoint.process.snapshot");
    CHECK(plan.provider_requirements[0].key == "process.name");
    CHECK(plan.provider_requirements[0].type == rule_engine::ValueType::string);
    CHECK(plan.provider_requirements[0].cost_class == rule_engine::FactCostClass::inventory);
    CHECK(plan.provider_requirements[0].rule_identifiers == std::vector<std::string>({"cheap_first", "exact_vm"}));
    CHECK(plan.provider_requirements[1].key == "pe.imports");
    CHECK(plan.provider_requirements[1].cost_class == rule_engine::FactCostClass::broad_image_array);

    REQUIRE(plan.candidate_provider_requests.size() == 1u);
    CHECK(plan.candidate_provider_requests[0].route == "endpoint.process.inventory");
    CHECK(plan.candidate_provider_requests[0].filter_key == "process.inventory.by_image_name");
    CHECK(plan.candidate_provider_requests[0].argument_value == "powershell.exe");
    CHECK(plan.candidate_provider_requests[0].rule_identifiers.empty());
}

TEST_CASE("optimizer plan JSON keeps candidate provider requests generic") {
    constexpr std::string_view source = R"(
import "process"

rule internal_rule_name {
    condition:
        process.name == "powershell.exe"
}
)";

    auto parsed = rule_engine::parse_source("optimizer-plan-json.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());

    const auto plan = rule_engine::optimizer::build_optimizer_plan(*verified);
    const auto json = rule_engine::optimizer::optimizer_plan_json(plan);

    CHECK(contains(json, R"("schema":"rule-engine-optimizer-plan.v1")"));
    CHECK(contains(json, R"("predicateCount":1)"));
    CHECK(contains(json, R"("exactVmFallbackCount":0)"));
    CHECK(contains(json, R"("providerRequirementCount":1)"));
    CHECK(contains(json, R"("candidateProviderRequestCount":1)"));
    CHECK(contains(json, R"("predicateOrder":["endpoint.process.snapshot|process.name|equal|string:powershell.exe"])"));
    CHECK(contains(json, R"("owners":[{"rule":"internal_rule_name","pruneSafe":true)"));
    CHECK(contains(json,
                   R"("candidateProviderRequests":[{"id":"process.inventory.by_image_name|string:powershell.exe")"));
    CHECK(contains(json, R"("filterKey":"process.inventory.by_image_name")"));
    CHECK_FALSE(contains(json, R"("ruleIdentifiers")"));
    const auto request_section_start = json.find(R"("candidateProviderRequests")");
    REQUIRE(request_section_start != std::string::npos);
    CHECK_FALSE(contains(json.substr(request_section_start), "internal_rule_name"));
}

TEST_CASE("optimizer plan drives opt-in prefiltered exact VM execution") {
    constexpr std::string_view source = R"(
import "process"
import "pe"

rule cheap_name {
    condition:
        process.name == "powershell.exe"
}

rule expensive_after_name {
    condition:
        process.name == "powershell.exe" and pe.is_valid
}

rule broad_or {
    condition:
        process.name == "powershell.exe" or true
}
)";

    auto parsed = rule_engine::parse_source("optimizer-plan-prefilter.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());

    const std::vector<rule_engine::Subject> subjects {
        rule_engine::Subject {.kind = "process", .id = "pid:match"},
        rule_engine::Subject {.kind = "process", .id = "pid:miss"},
    };

    rule_engine::FactCache facts;
    facts.store(rule_engine::Fact {
        .subject_id = "pid:match",
        .key = "process.name",
        .value = rule_engine::Value::string("powershell.exe"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {0},
    });
    facts.store(rule_engine::Fact {
        .subject_id = "pid:match",
        .key = "pe.is_valid",
        .value = rule_engine::Value::boolean(true),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {0},
    });
    facts.store(rule_engine::Fact {
        .subject_id = "pid:miss",
        .key = "process.name",
        .value = rule_engine::Value::string("cmd.exe"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {0},
    });
    facts.store(rule_engine::Fact {
        .subject_id = "pid:miss",
        .key = "pe.is_valid",
        .value = rule_engine::Value::boolean(true),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {0},
    });

    const auto plan = rule_engine::optimizer::build_optimizer_plan(*verified);
    const auto sweep = rule_engine::optimizer::evaluate_with_optimizer_plan(*verified, plan, subjects, facts);

    CHECK(sweep.incomplete_subjects.empty());
    CHECK(sweep.baseline_exact_vm_rule_executions == 6u);
    CHECK(sweep.optimized_exact_vm_rule_executions == 4u);
    CHECK(sweep.exact_vm_rule_executions_avoided == 2u);
    CHECK(sweep.shared_dag.predicate_order ==
          std::vector<std::string> {"endpoint.process.snapshot|process.name|equal|string:powershell.exe"});
    REQUIRE(sweep.subjects.size() == 2u);

    CHECK(sweep.subjects[0].subject_id == "pid:match");
    CHECK(sweep.subjects[0].exact_vm_rule_identifiers ==
          std::vector<std::string>({"cheap_name", "expensive_after_name", "broad_or"}));
    CHECK(sweep.subjects[0].pruned_rule_identifiers.empty());
    REQUIRE(sweep.subjects[0].rule_results.size() == 3u);
    CHECK(sweep.subjects[0].rule_results[0].identifier == "cheap_name");
    CHECK(sweep.subjects[0].rule_results[0].matched);
    CHECK(sweep.subjects[0].rule_results[1].identifier == "expensive_after_name");
    CHECK(sweep.subjects[0].rule_results[1].matched);
    CHECK(sweep.subjects[0].rule_results[2].identifier == "broad_or");
    CHECK(sweep.subjects[0].rule_results[2].matched);

    CHECK(sweep.subjects[1].subject_id == "pid:miss");
    CHECK(sweep.subjects[1].exact_vm_rule_identifiers == std::vector<std::string> {"broad_or"});
    CHECK(sweep.subjects[1].pruned_rule_identifiers ==
          std::vector<std::string>({"cheap_name", "expensive_after_name"}));
    REQUIRE(sweep.subjects[1].rule_results.size() == 3u);
    CHECK(sweep.subjects[1].rule_results[0].identifier == "cheap_name");
    CHECK_FALSE(sweep.subjects[1].rule_results[0].matched);
    CHECK(sweep.subjects[1].rule_results[1].identifier == "expensive_after_name");
    CHECK_FALSE(sweep.subjects[1].rule_results[1].matched);
    CHECK(sweep.subjects[1].rule_results[2].identifier == "broad_or");
    CHECK(sweep.subjects[1].rule_results[2].matched);

    REQUIRE(sweep.trace_events.size() == 2u);
    CHECK(sweep.trace_events[0].event == "exact_vm_rule_skipped");
    CHECK(sweep.trace_events[0].rule_identifier == "cheap_name");
    CHECK(sweep.trace_events[0].subject_id == "pid:miss");
    CHECK(sweep.trace_events[0].reason ==
          "exact VM skipped because process.name equal string:powershell.exe evaluated false");
}

TEST_CASE("optimizer plan counts reportable exact VM work while preserving global gates") {
    constexpr std::string_view source = R"(
import "process"

global rule powershell_only {
    condition:
        process.name == "powershell.exe"
}

rule cheap_name {
    condition:
        process.name == "powershell.exe"
}

rule broad_rule {
    condition:
        true
}
)";

    auto parsed = rule_engine::parse_source("optimizer-plan-global-gate.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());

    const std::vector<rule_engine::Subject> subjects {
        rule_engine::Subject {.kind = "process", .id = "pid:match"},
        rule_engine::Subject {.kind = "process", .id = "pid:miss"},
    };

    rule_engine::FactCache facts;
    facts.store(rule_engine::Fact {
        .subject_id = "pid:match",
        .key = "process.name",
        .value = rule_engine::Value::string("powershell.exe"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {0},
    });
    facts.store(rule_engine::Fact {
        .subject_id = "pid:miss",
        .key = "process.name",
        .value = rule_engine::Value::string("cmd.exe"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {0},
    });

    const auto plan = rule_engine::optimizer::build_optimizer_plan(*verified);
    const auto sweep = rule_engine::optimizer::evaluate_with_optimizer_plan(*verified, plan, subjects, facts);

    CHECK(sweep.incomplete_subjects.empty());
    CHECK(sweep.baseline_exact_vm_rule_executions == 4u);
    CHECK(sweep.optimized_exact_vm_rule_executions == 3u);
    CHECK(sweep.exact_vm_rule_executions_avoided == 1u);
    REQUIRE(sweep.subjects.size() == 2u);

    CHECK(sweep.subjects[0].subject_id == "pid:match");
    CHECK(sweep.subjects[0].exact_vm_rule_identifiers == std::vector<std::string>({"cheap_name", "broad_rule"}));
    CHECK(sweep.subjects[0].pruned_rule_identifiers.empty());
    REQUIRE(sweep.subjects[0].rule_results.size() == 2u);
    CHECK(sweep.subjects[0].rule_results[0].identifier == "cheap_name");
    CHECK(sweep.subjects[0].rule_results[0].matched);
    CHECK(sweep.subjects[0].rule_results[1].identifier == "broad_rule");
    CHECK(sweep.subjects[0].rule_results[1].matched);

    CHECK(sweep.subjects[1].subject_id == "pid:miss");
    CHECK(sweep.subjects[1].exact_vm_rule_identifiers == std::vector<std::string> {"broad_rule"});
    CHECK(sweep.subjects[1].pruned_rule_identifiers == std::vector<std::string> {"cheap_name"});
    REQUIRE(sweep.subjects[1].rule_results.size() == 2u);
    CHECK(sweep.subjects[1].rule_results[0].identifier == "cheap_name");
    CHECK_FALSE(sweep.subjects[1].rule_results[0].matched);
    CHECK(sweep.subjects[1].rule_results[1].identifier == "broad_rule");
    CHECK_FALSE(sweep.subjects[1].rule_results[1].matched);
}

TEST_CASE("optimizer plan keeps diagnostic predicates on the exact VM path") {
    constexpr std::string_view source = R"(
import "process"

rule name_filter {
    condition:
        process.name == "powershell.exe"
}
)";

    auto parsed = rule_engine::parse_source("optimizer-plan-diagnostic.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());

    const std::vector<rule_engine::Subject> subjects {
        rule_engine::Subject {.kind = "process", .id = "pid:diagnostic"},
    };

    rule_engine::FactCache facts;
    facts.store(rule_engine::Fact {
        .subject_id = "pid:diagnostic",
        .key = "process.name",
        .value = rule_engine::Value::undefined(),
        .status = rule_engine::FactStatus::unavailable,
        .diagnostic = "snapshot unavailable",
        .ttl = std::chrono::seconds {0},
    });

    const auto plan = rule_engine::optimizer::build_optimizer_plan(*verified);
    const auto sweep = rule_engine::optimizer::evaluate_with_optimizer_plan(*verified, plan, subjects, facts);

    CHECK(sweep.incomplete_subjects.empty());
    CHECK(sweep.baseline_exact_vm_rule_executions == 1u);
    CHECK(sweep.optimized_exact_vm_rule_executions == 1u);
    CHECK(sweep.exact_vm_rule_executions_avoided == 0u);
    CHECK(sweep.trace_events.empty());
    REQUIRE(sweep.subjects.size() == 1u);
    CHECK(sweep.subjects[0].exact_vm_rule_identifiers == std::vector<std::string> {"name_filter"});
    CHECK(sweep.subjects[0].pruned_rule_identifiers.empty());
    REQUIRE(sweep.subjects[0].rule_results.size() == 1u);
    CHECK_FALSE(sweep.subjects[0].rule_results[0].matched);
    REQUIRE(sweep.subjects[0].rule_results[0].diagnostics.size() == 1u);
    CHECK(sweep.subjects[0].rule_results[0].diagnostics[0].message == "snapshot unavailable");
}

TEST_CASE("optimizer plan consumes generic candidate provider results before exact VM") {
    constexpr std::string_view source = R"(
import "process"
import "pe"

rule expensive_after_name {
    condition:
        process.name == "powershell.exe" and
        for any imported in pe.imports : (imported["dll"] contains "KERNEL32.dll")
}
)";

    auto parsed = rule_engine::parse_source("optimizer-plan-candidate-provider.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());

    const std::vector<rule_engine::Subject> subjects {
        rule_engine::Subject {.kind = "process", .id = "pid:match"},
        rule_engine::Subject {.kind = "process", .id = "pid:miss"},
    };
    const std::vector<rule_engine::optimizer::CandidateProviderResult> provider_results {
        rule_engine::optimizer::CandidateProviderResult {
            .request_id = "process.inventory.by_image_name|string:powershell.exe",
            .subject_ids = {"pid:match"},
            .available = true,
            .diagnostic = {},
        },
    };

    rule_engine::FactCache facts;
    facts.store(rule_engine::Fact {
        .subject_id = "pid:match",
        .key = "process.name",
        .value = rule_engine::Value::string("powershell.exe"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {0},
    });
    facts.store(rule_engine::Fact {
        .subject_id = "pid:match",
        .key = "pe.imports",
        .value = rule_engine::Value::array(std::vector<rule_engine::Value> {
            rule_engine::Value::object(std::vector<rule_engine::ObjectEntry> {
                rule_engine::ObjectEntry {.key = "dll", .value = rule_engine::Value::string("KERNEL32.dll")},
            }),
        }),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {30},
    });

    const auto plan = rule_engine::optimizer::build_optimizer_plan(*verified);
    const auto sweep =
        rule_engine::optimizer::evaluate_with_optimizer_plan(*verified, plan, subjects, facts, provider_results);

    CHECK(sweep.incomplete_subjects.empty());
    CHECK(sweep.candidate_provider_requests == 1u);
    CHECK(sweep.candidate_provider_subjects_returned == 1u);
    CHECK(sweep.candidate_provider_fallback_predicate_evaluations == 0u);
    CHECK(sweep.baseline_exact_vm_rule_executions == 2u);
    CHECK(sweep.optimized_exact_vm_rule_executions == 1u);
    CHECK(sweep.exact_vm_rule_executions_avoided == 1u);
    REQUIRE(sweep.subjects.size() == 2u);

    CHECK(sweep.subjects[0].subject_id == "pid:match");
    CHECK(sweep.subjects[0].exact_vm_rule_identifiers == std::vector<std::string> {"expensive_after_name"});
    REQUIRE(sweep.subjects[0].rule_results.size() == 1u);
    CHECK(sweep.subjects[0].rule_results[0].matched);

    CHECK(sweep.subjects[1].subject_id == "pid:miss");
    CHECK(sweep.subjects[1].exact_vm_rule_identifiers.empty());
    CHECK(sweep.subjects[1].pruned_rule_identifiers == std::vector<std::string> {"expensive_after_name"});
    REQUIRE(sweep.subjects[1].rule_results.size() == 1u);
    CHECK_FALSE(sweep.subjects[1].rule_results[0].matched);

    REQUIRE(sweep.trace_events.size() == 1u);
    CHECK(sweep.trace_events[0].event == "exact_vm_rule_skipped");
    CHECK(sweep.trace_events[0].reason ==
          "exact VM skipped because candidate provider process.inventory.by_image_name excluded subject");

    const auto lazy_plan = rule_engine::optimizer::plan_lazy_provider_expansion(*verified, sweep.shared_dag);
    REQUIRE(lazy_plan.requests.size() == 1u);
    CHECK(lazy_plan.requests[0].key == "pe.imports");
    CHECK(lazy_plan.requests[0].subject_ids == std::vector<std::string> {"pid:match"});
    CHECK(lazy_plan.requests[0].avoided_subject_ids == std::vector<std::string> {"pid:miss"});
}

TEST_CASE("optimizer plan reports broad candidate provider results without treating them as decisions") {
    constexpr std::string_view source = R"(
import "process"
import "pe"

rule expensive_after_name {
    condition:
        process.name == "powershell.exe" and
        for any imported in pe.imports : (imported["dll"] contains "KERNEL32.dll")
}
)";

    auto parsed = rule_engine::parse_source("optimizer-plan-broad-candidate-provider.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());

    const std::vector<rule_engine::Subject> subjects {
        rule_engine::Subject {.kind = "process", .id = "pid:match"},
        rule_engine::Subject {.kind = "process", .id = "pid:miss"},
    };
    const std::vector<rule_engine::optimizer::CandidateProviderResult> provider_results {
        rule_engine::optimizer::CandidateProviderResult {
            .request_id = "process.inventory.by_image_name|string:powershell.exe",
            .subject_ids = {"pid:match", "pid:miss"},
            .available = true,
            .diagnostic = {},
        },
    };

    rule_engine::FactCache facts;
    facts.store(rule_engine::Fact {
        .subject_id = "pid:match",
        .key = "process.name",
        .value = rule_engine::Value::string("powershell.exe"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {0},
    });
    facts.store(rule_engine::Fact {
        .subject_id = "pid:match",
        .key = "pe.imports",
        .value = rule_engine::Value::array(std::vector<rule_engine::Value> {
            rule_engine::Value::object(std::vector<rule_engine::ObjectEntry> {
                rule_engine::ObjectEntry {.key = "dll", .value = rule_engine::Value::string("KERNEL32.dll")},
            }),
        }),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {30},
    });
    facts.store(rule_engine::Fact {
        .subject_id = "pid:miss",
        .key = "process.name",
        .value = rule_engine::Value::string("cmd.exe"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {0},
    });

    const auto plan = rule_engine::optimizer::build_optimizer_plan(*verified);
    const auto sweep =
        rule_engine::optimizer::evaluate_with_optimizer_plan(*verified, plan, subjects, facts, provider_results);

    CHECK(sweep.incomplete_subjects.empty());
    CHECK(sweep.candidate_provider_requests == 1u);
    CHECK(sweep.candidate_provider_subjects_returned == 2u);
    CHECK(sweep.candidate_provider_broad_results == 1u);
    CHECK(sweep.candidate_provider_fallback_predicate_evaluations == 0u);
    CHECK(sweep.optimized_exact_vm_rule_executions == 2u);
    CHECK(sweep.exact_vm_rule_executions_avoided == 0u);
    REQUIRE(sweep.subjects.size() == 2u);
    CHECK(sweep.subjects[0].exact_vm_rule_identifiers == std::vector<std::string> {"expensive_after_name"});
    CHECK(sweep.subjects[1].exact_vm_rule_identifiers == std::vector<std::string> {"expensive_after_name"});
    CHECK(sweep.subjects[1].pruned_rule_identifiers.empty());
    REQUIRE(sweep.subjects[1].rule_results.size() == 1u);
    CHECK_FALSE(sweep.subjects[1].rule_results[0].matched);
}

TEST_CASE("optimizer plan consumes protocol candidate provider subject-set responses") {
    constexpr std::string_view source = R"(
import "process"
import "pe"

rule expensive_after_name {
    condition:
        process.name == "powershell.exe" and
        for any imported in pe.imports : (imported["dll"] contains "KERNEL32.dll")
}
)";

    auto parsed = rule_engine::parse_source("optimizer-plan-protocol-candidate-provider.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());

    const std::vector<rule_engine::Subject> subjects {
        rule_engine::Subject {.kind = "process", .id = "pid:match"},
        rule_engine::Subject {.kind = "process", .id = "pid:miss"},
    };

    rule_engine::protocol::CandidateProviderResponseMessage response;
    response.route = "endpoint.process.inventory";
    response.results.push_back(rule_engine::protocol::CandidateProviderSubjectSet {
        .request_id = "process.inventory.by_image_name|string:powershell.exe",
        .filter_key = "process.inventory.by_image_name",
        .status = rule_engine::FactStatus::available,
        .subject_ids = {"pid:match"},
        .diagnostic = {},
        .ttl = std::chrono::seconds {30},
    });

    const auto provider_results = rule_engine::optimizer::candidate_provider_results_from_protocol(response.results);
    REQUIRE(provider_results.size() == 1u);
    CHECK(provider_results[0].request_id == "process.inventory.by_image_name|string:powershell.exe");
    CHECK(provider_results[0].status == rule_engine::FactStatus::available);
    CHECK(provider_results[0].available);
    CHECK(provider_results[0].ttl == std::chrono::seconds {30});

    rule_engine::FactCache facts;
    facts.store(rule_engine::Fact {
        .subject_id = "pid:match",
        .key = "process.name",
        .value = rule_engine::Value::string("powershell.exe"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {0},
    });
    facts.store(rule_engine::Fact {
        .subject_id = "pid:match",
        .key = "pe.imports",
        .value = rule_engine::Value::array(std::vector<rule_engine::Value> {
            rule_engine::Value::object(std::vector<rule_engine::ObjectEntry> {
                rule_engine::ObjectEntry {.key = "dll", .value = rule_engine::Value::string("KERNEL32.dll")},
            }),
        }),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {30},
    });

    const auto plan = rule_engine::optimizer::build_optimizer_plan(*verified);
    const auto sweep =
        rule_engine::optimizer::evaluate_with_optimizer_plan(*verified, plan, subjects, facts, provider_results);

    CHECK(sweep.candidate_provider_requests == 1u);
    CHECK(sweep.candidate_provider_subjects_returned == 1u);
    CHECK(sweep.candidate_provider_fallback_predicate_evaluations == 0u);
    CHECK(sweep.optimized_exact_vm_rule_executions == 1u);
    CHECK(sweep.exact_vm_rule_executions_avoided == 1u);
    CHECK(sweep.incomplete_subjects.empty());
}

TEST_CASE("optimizer plan falls back when candidate provider results are unavailable") {
    constexpr std::string_view source = R"(
import "process"
import "pe"

rule expensive_after_name {
    condition:
        process.name == "powershell.exe" and
        for any imported in pe.imports : (imported["dll"] contains "KERNEL32.dll")
}
)";

    auto parsed = rule_engine::parse_source("optimizer-plan-candidate-provider-fallback.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());

    const std::vector<rule_engine::Subject> subjects {
        rule_engine::Subject {.kind = "process", .id = "pid:match"},
        rule_engine::Subject {.kind = "process", .id = "pid:miss"},
    };
    const std::vector<rule_engine::optimizer::CandidateProviderResult> provider_results {
        rule_engine::optimizer::CandidateProviderResult {
            .request_id = "process.inventory.by_image_name|string:powershell.exe",
            .subject_ids = {},
            .available = false,
            .diagnostic = "candidate provider unavailable",
        },
    };

    rule_engine::FactCache facts;
    facts.store(rule_engine::Fact {
        .subject_id = "pid:match",
        .key = "process.name",
        .value = rule_engine::Value::string("powershell.exe"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {0},
    });
    facts.store(rule_engine::Fact {
        .subject_id = "pid:match",
        .key = "pe.imports",
        .value = rule_engine::Value::array(std::vector<rule_engine::Value> {
            rule_engine::Value::object(std::vector<rule_engine::ObjectEntry> {
                rule_engine::ObjectEntry {.key = "dll", .value = rule_engine::Value::string("KERNEL32.dll")},
            }),
        }),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {30},
    });
    facts.store(rule_engine::Fact {
        .subject_id = "pid:miss",
        .key = "process.name",
        .value = rule_engine::Value::string("cmd.exe"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {0},
    });

    const auto plan = rule_engine::optimizer::build_optimizer_plan(*verified);
    const auto sweep =
        rule_engine::optimizer::evaluate_with_optimizer_plan(*verified, plan, subjects, facts, provider_results);

    CHECK(sweep.incomplete_subjects.empty());
    CHECK(sweep.candidate_provider_requests == 1u);
    CHECK(sweep.candidate_provider_subjects_returned == 0u);
    CHECK(sweep.candidate_provider_fallback_predicate_evaluations == 2u);
    CHECK(sweep.optimized_exact_vm_rule_executions == 1u);
    CHECK(sweep.exact_vm_rule_executions_avoided == 1u);
    REQUIRE(sweep.shared_dag.trace_events.size() >= 2u);
    CHECK(sweep.shared_dag.trace_events[1].event == "candidate_provider_fallback");
    CHECK(sweep.shared_dag.trace_events[1].predicate_id ==
          "endpoint.process.snapshot|process.name|equal|string:powershell.exe");
    CHECK(sweep.shared_dag.trace_events[1].reason ==
          "candidate provider process.inventory.by_image_name unavailable: candidate provider unavailable; falling "
          "back to server-side predicate evaluation");
    CHECK(sweep.shared_dag.trace_events[1].candidate_subject_count == 2u);
    REQUIRE(sweep.subjects.size() == 2u);
    CHECK(sweep.subjects[0].exact_vm_rule_identifiers == std::vector<std::string> {"expensive_after_name"});
    CHECK(sweep.subjects[1].exact_vm_rule_identifiers.empty());
    CHECK(sweep.subjects[1].pruned_rule_identifiers == std::vector<std::string> {"expensive_after_name"});
}

TEST_CASE("shared predicate DAG simulator reports static cost order and observed selectivity") {
    constexpr std::string_view source = R"(
import "process"

rule handle_first {
    condition:
        process.handles.count > 10 and
        process.name == "powershell.exe"
}
)";

    auto parsed = rule_engine::parse_source("optimizer-cost.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());

    const auto canonical = rule_engine::optimizer::extract_canonical_predicates(*verified);
    REQUIRE(canonical.predicates.size() == 2u);
    CHECK(canonical.predicates[0].id == "endpoint.process.handles|process.handles.count|greater|integer:10");
    CHECK(canonical.predicates[0].cost_class == rule_engine::FactCostClass::handle_signer);
    CHECK(canonical.predicates[1].id == "endpoint.process.snapshot|process.name|equal|string:powershell.exe");
    CHECK(canonical.predicates[1].cost_class == rule_engine::FactCostClass::inventory);

    const std::vector<rule_engine::Subject> subjects {
        rule_engine::Subject {.kind = "process", .id = "pid:match"},
        rule_engine::Subject {.kind = "process", .id = "pid:wrong-name"},
        rule_engine::Subject {.kind = "process", .id = "pid:signed"},
    };

    rule_engine::FactCache facts;
    facts.store(rule_engine::Fact {
        .subject_id = "pid:match",
        .key = "process.name",
        .value = rule_engine::Value::string("powershell.exe"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {0},
    });
    facts.store(rule_engine::Fact {
        .subject_id = "pid:match",
        .key = "process.handles.count",
        .value = rule_engine::Value::integer(20),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {0},
    });
    facts.store(rule_engine::Fact {
        .subject_id = "pid:wrong-name",
        .key = "process.name",
        .value = rule_engine::Value::string("cmd.exe"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {0},
    });
    facts.store(rule_engine::Fact {
        .subject_id = "pid:wrong-name",
        .key = "process.handles.count",
        .value = rule_engine::Value::integer(20),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {0},
    });
    facts.store(rule_engine::Fact {
        .subject_id = "pid:signed",
        .key = "process.name",
        .value = rule_engine::Value::string("cmd.exe"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {0},
    });
    facts.store(rule_engine::Fact {
        .subject_id = "pid:signed",
        .key = "process.handles.count",
        .value = rule_engine::Value::integer(5),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {0},
    });

    const auto simulation =
        rule_engine::optimizer::simulate_shared_predicate_dag(*verified, canonical, subjects, facts);

    const std::vector<std::string> expected_order {
        "endpoint.process.snapshot|process.name|equal|string:powershell.exe",
        "endpoint.process.handles|process.handles.count|greater|integer:10",
    };
    CHECK(simulation.predicate_order == expected_order);
    REQUIRE(simulation.predicate_nodes.size() == 2u);
    CHECK(simulation.predicate_nodes[0].predicate_id == expected_order[0]);
    CHECK(simulation.predicate_nodes[0].cost_class == rule_engine::FactCostClass::inventory);
    CHECK(simulation.predicate_nodes[0].observed_selectivity_ppm == 333333u);
    CHECK(simulation.predicate_nodes[1].predicate_id == expected_order[1]);
    CHECK(simulation.predicate_nodes[1].cost_class == rule_engine::FactCostClass::handle_signer);
    CHECK(simulation.predicate_nodes[1].observed_selectivity_ppm == 666666u);

    const auto json = rule_engine::optimizer::shared_predicate_dag_simulation_json(simulation);
    CHECK(contains(
        json,
        R"("predicateOrder":["endpoint.process.snapshot|process.name|equal|string:powershell.exe","endpoint.process.handles|process.handles.count|greater|integer:10"])"));
    CHECK(contains(json, R"("costClass":"inventory")"));
    CHECK(contains(json, R"("costClass":"handle_signer")"));
    CHECK(contains(json, R"("observedSelectivityPpm":333333)"));
}

TEST_CASE("shared predicate DAG simulator uses observed selectivity feedback within cost class") {
    constexpr std::string_view source = R"(
import "process"

rule same_cost_feedback {
    condition:
        process.architecture == "x64" and
        process.name == "target.exe" and
        process.handles.count > 10
}
)";

    auto parsed = rule_engine::parse_source("optimizer-selectivity-feedback.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());

    const std::vector<rule_engine::Subject> subjects {
        rule_engine::Subject {.kind = "process", .id = "pid:target"},
        rule_engine::Subject {.kind = "process", .id = "pid:helper"},
        rule_engine::Subject {.kind = "process", .id = "pid:benign"},
        rule_engine::Subject {.kind = "process", .id = "pid:other"},
    };

    rule_engine::FactCache facts;
    for (const auto &subject : subjects) {
        facts.store(rule_engine::Fact {
            .subject_id = subject.id,
            .key = "process.architecture",
            .value = rule_engine::Value::string("x64"),
            .status = rule_engine::FactStatus::available,
            .diagnostic = {},
            .ttl = std::chrono::seconds {0},
        });
        facts.store(rule_engine::Fact {
            .subject_id = subject.id,
            .key = "process.handles.count",
            .value = rule_engine::Value::integer(5),
            .status = rule_engine::FactStatus::available,
            .diagnostic = {},
            .ttl = std::chrono::seconds {0},
        });
    }
    facts.store(rule_engine::Fact {
        .subject_id = "pid:target",
        .key = "process.name",
        .value = rule_engine::Value::string("target.exe"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {0},
    });
    for (const auto &subject_id : {"pid:helper", "pid:benign", "pid:other"}) {
        facts.store(rule_engine::Fact {
            .subject_id = subject_id,
            .key = "process.name",
            .value = rule_engine::Value::string("helper.exe"),
            .status = rule_engine::FactStatus::available,
            .diagnostic = {},
            .ttl = std::chrono::seconds {0},
        });
    }

    const auto canonical = rule_engine::optimizer::extract_canonical_predicates(*verified);
    const auto initial = rule_engine::optimizer::simulate_shared_predicate_dag(*verified, canonical, subjects, facts);
    CHECK(initial.predicate_order == std::vector<std::string> {
                                         "endpoint.process.snapshot|process.architecture|equal|string:x64",
                                         "endpoint.process.snapshot|process.name|equal|string:target.exe",
                                         "endpoint.process.handles|process.handles.count|greater|integer:10",
                                     });

    const auto profile = rule_engine::optimizer::build_selectivity_profile(initial);
    REQUIRE(profile.predicates.size() == 3u);
    const auto feedback =
        rule_engine::optimizer::simulate_shared_predicate_dag(*verified, canonical, subjects, facts, profile);

    CHECK(feedback.predicate_order == std::vector<std::string> {
                                          "endpoint.process.snapshot|process.name|equal|string:target.exe",
                                          "endpoint.process.snapshot|process.architecture|equal|string:x64",
                                          "endpoint.process.handles|process.handles.count|greater|integer:10",
                                      });
    CHECK(feedback.trace_events[0].event == "predicate_ordered");
    CHECK(feedback.trace_events[0].predicate_id == "endpoint.process.snapshot|process.name|equal|string:target.exe");
    CHECK(feedback.trace_events[0].reason == "observed selectivity feedback within descriptor cost order");
    REQUIRE(feedback.predicate_nodes.size() == 3u);
    CHECK(feedback.predicate_nodes[0].observed_selectivity_ppm == 250000u);
    CHECK(feedback.predicate_nodes[1].observed_selectivity_ppm == 1000000u);
    CHECK(feedback.predicate_nodes[2].observed_selectivity_ppm == 0u);
}

TEST_CASE("shared predicate DAG simulator reports safe rule candidates and prune reasons") {
    constexpr std::string_view source = R"(
import "process"

rule first {
    condition:
        process.name == "powershell.exe"
}

rule second {
    condition:
        "powershell.exe" == process.name
}

rule broad_or {
    condition:
        process.name == "powershell.exe" or true
}
)";

    auto parsed = rule_engine::parse_source("optimizer-dag.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());

    const auto canonical = rule_engine::optimizer::extract_canonical_predicates(*verified);
    REQUIRE(canonical.predicates.size() == 1u);
    REQUIRE(canonical.predicates[0].owners.size() == 3u);
    CHECK(canonical.predicates[0].owners[0].prune_safe);
    CHECK(canonical.predicates[0].owners[1].prune_safe);
    CHECK_FALSE(canonical.predicates[0].owners[2].prune_safe);

    const std::vector<rule_engine::Subject> subjects {
        rule_engine::Subject {.kind = "process", .id = "pid:match"},
        rule_engine::Subject {.kind = "process", .id = "pid:miss"},
        rule_engine::Subject {.kind = "process", .id = "pid:unknown"},
    };

    rule_engine::FactCache facts;
    facts.store(rule_engine::Fact {
        .subject_id = "pid:match",
        .key = "process.name",
        .value = rule_engine::Value::string("powershell.exe"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {0},
    });
    facts.store(rule_engine::Fact {
        .subject_id = "pid:miss",
        .key = "process.name",
        .value = rule_engine::Value::string("cmd.exe"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {0},
    });

    const auto simulation =
        rule_engine::optimizer::simulate_shared_predicate_dag(*verified, canonical, subjects, facts);

    REQUIRE(simulation.predicate_nodes.size() == 1u);
    CHECK(simulation.predicate_nodes[0].predicate_id ==
          "endpoint.process.snapshot|process.name|equal|string:powershell.exe");
    CHECK(simulation.predicate_nodes[0].matched_subject_ids == std::vector<std::string> {"pid:match"});
    REQUIRE(simulation.predicate_nodes[0].pruned_subjects.size() == 1u);
    CHECK(simulation.predicate_nodes[0].pruned_subjects[0].subject_id == "pid:miss");
    CHECK(simulation.predicate_nodes[0].pruned_subjects[0].reason ==
          "process.name equal string:powershell.exe evaluated false");
    REQUIRE(simulation.predicate_nodes[0].unknown_subjects.size() == 1u);
    CHECK(simulation.predicate_nodes[0].unknown_subjects[0].subject_id == "pid:unknown");
    CHECK(simulation.predicate_nodes[0].unknown_subjects[0].reason == "missing fact process.name");

    REQUIRE(simulation.rule_candidates.size() == 3u);
    CHECK(simulation.rule_candidates[0].rule_identifier == "first");
    CHECK(simulation.rule_candidates[0].candidate_subject_ids ==
          std::vector<std::string>({"pid:match", "pid:unknown"}));
    REQUIRE(simulation.rule_candidates[0].pruned_subjects.size() == 1u);
    CHECK(simulation.rule_candidates[0].pruned_subjects[0].subject_id == "pid:miss");
    CHECK(simulation.rule_candidates[0].pruned_subjects[0].predicate_id ==
          "endpoint.process.snapshot|process.name|equal|string:powershell.exe");

    CHECK(simulation.rule_candidates[1].rule_identifier == "second");
    CHECK(simulation.rule_candidates[1].candidate_subject_ids ==
          std::vector<std::string>({"pid:match", "pid:unknown"}));
    REQUIRE(simulation.rule_candidates[1].pruned_subjects.size() == 1u);
    CHECK(simulation.rule_candidates[1].pruned_subjects[0].subject_id == "pid:miss");

    CHECK(simulation.rule_candidates[2].rule_identifier == "broad_or");
    CHECK(simulation.rule_candidates[2].candidate_subject_ids ==
          std::vector<std::string>({"pid:match", "pid:miss", "pid:unknown"}));
    CHECK(simulation.rule_candidates[2].pruned_subjects.empty());

    CHECK(simulation.predicate_evaluations == 3u);
    CHECK(simulation.pruned_rule_subjects == 2u);
    CHECK(simulation.peak_candidate_set_subjects == 3u);

    const auto json = rule_engine::optimizer::shared_predicate_dag_simulation_json(simulation);
    CHECK(contains(json, R"("schema":"rule-engine-shared-predicate-dag-simulation.v1")"));
    CHECK(contains(json, R"("predicateEvaluations":3)"));
    CHECK(contains(json, R"("prunedRuleSubjects":2)"));
    CHECK(contains(json, R"("rule":"broad_or")"));
    CHECK(contains(json, R"("candidateSubjects":["pid:match","pid:miss","pid:unknown"])"));
}

TEST_CASE("shared predicate DAG simulator emits optimizer trace events") {
    constexpr std::string_view source = R"(
import "process"

rule selective {
    condition:
        process.name == "powershell.exe"
}
)";

    auto parsed = rule_engine::parse_source("optimizer-trace.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());

    const auto canonical = rule_engine::optimizer::extract_canonical_predicates(*verified);
    REQUIRE(canonical.predicates.size() == 1u);

    const std::vector<rule_engine::Subject> subjects {
        rule_engine::Subject {.kind = "process", .id = "pid:match"},
        rule_engine::Subject {.kind = "process", .id = "pid:miss"},
    };

    rule_engine::FactCache facts;
    facts.store(rule_engine::Fact {
        .subject_id = "pid:match",
        .key = "process.name",
        .value = rule_engine::Value::string("powershell.exe"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {0},
    });
    facts.store(rule_engine::Fact {
        .subject_id = "pid:miss",
        .key = "process.name",
        .value = rule_engine::Value::string("cmd.exe"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {0},
    });

    const auto simulation =
        rule_engine::optimizer::simulate_shared_predicate_dag(*verified, canonical, subjects, facts);

    REQUIRE(simulation.trace_events.size() == 2u);
    CHECK(simulation.trace_events[0].event == "predicate_ordered");
    CHECK(simulation.trace_events[0].predicate_id ==
          "endpoint.process.snapshot|process.name|equal|string:powershell.exe");
    CHECK(simulation.trace_events[0].cost_class == rule_engine::FactCostClass::inventory);
    CHECK(simulation.trace_events[0].span.source == "optimizer-trace.yar");
    CHECK(simulation.trace_events[0].span.source_id == 1u);
    CHECK(simulation.trace_events[0].span.start < simulation.trace_events[0].span.end);

    CHECK(simulation.trace_events[1].event == "rule_subject_pruned");
    CHECK(simulation.trace_events[1].predicate_id ==
          "endpoint.process.snapshot|process.name|equal|string:powershell.exe");
    CHECK(simulation.trace_events[1].rule_identifier == "selective");
    CHECK(simulation.trace_events[1].subject_id == "pid:miss");
    CHECK(simulation.trace_events[1].reason == "process.name equal string:powershell.exe evaluated false");
    CHECK(simulation.trace_events[1].candidate_subject_count == 1u);
    CHECK(simulation.trace_events[1].candidate_set_bytes == 1u);
    CHECK(simulation.trace_events[1].span.source == "optimizer-trace.yar");

    const auto json = rule_engine::optimizer::shared_predicate_dag_simulation_json(simulation);
    CHECK(contains(json, R"("traceEvents":[)"));
    CHECK(contains(json, R"("event":"predicate_ordered")"));
    CHECK(contains(json, R"("reason":"static descriptor cost order")"));
    CHECK(contains(json, R"("source":"optimizer-trace.yar")"));
    CHECK(contains(json, R"("event":"rule_subject_pruned")"));
    CHECK(contains(json, R"("rule":"selective")"));
    CHECK(contains(json, R"("subject":"pid:miss")"));
    CHECK(contains(json, R"("candidateSubjectCount":1)"));
    CHECK(contains(json, R"("candidateSetBytes":1)"));
}

TEST_CASE("shared predicate DAG simulator reports adaptive candidate set state") {
    constexpr std::string_view source = R"(
import "process"

rule selective {
    condition:
        process.name == "powershell.exe"
}

rule broad_or {
    condition:
        process.name == "powershell.exe" or true
}
)";

    auto parsed = rule_engine::parse_source("optimizer-adaptive-candidates.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());

    const auto canonical = rule_engine::optimizer::extract_canonical_predicates(*verified);
    REQUIRE(canonical.predicates.size() == 1u);

    std::vector<rule_engine::Subject> subjects;
    subjects.reserve(16u);
    rule_engine::FactCache facts;
    for (std::size_t index = 0; index < 16u; ++index) {
        const auto subject_id = "pid:" + std::to_string(index);
        subjects.push_back(rule_engine::Subject {.kind = "process", .id = subject_id});
        facts.store(rule_engine::Fact {
            .subject_id = subject_id,
            .key = "process.name",
            .value = rule_engine::Value::string(index == 0u ? "powershell.exe" : "cmd.exe"),
            .status = rule_engine::FactStatus::available,
            .diagnostic = {},
            .ttl = std::chrono::seconds {0},
        });
    }

    const auto simulation =
        rule_engine::optimizer::simulate_shared_predicate_dag(*verified, canonical, subjects, facts);

    REQUIRE(simulation.rule_candidates.size() == 2u);
    CHECK(simulation.rule_candidates[0].rule_identifier == "selective");
    CHECK(simulation.rule_candidates[0].candidate_subject_ids == std::vector<std::string> {"pid:0"});
    CHECK(simulation.rule_candidates[0].representation ==
          rule_engine::optimizer::CandidateSetRepresentation::sparse_ids);
    CHECK(simulation.rule_candidates[0].candidate_set_bytes == 1u);

    CHECK(simulation.rule_candidates[1].rule_identifier == "broad_or");
    CHECK(simulation.rule_candidates[1].candidate_subject_ids.size() == 16u);
    CHECK(simulation.rule_candidates[1].representation ==
          rule_engine::optimizer::CandidateSetRepresentation::dense_bitset);
    CHECK(simulation.rule_candidates[1].candidate_set_bytes == 2u);
    CHECK(simulation.peak_candidate_set_bytes == 2u);

    const auto json = rule_engine::optimizer::shared_predicate_dag_simulation_json(simulation);
    CHECK(contains(json, R"("peakCandidateSetBytes":2)"));
    CHECK(contains(json, R"("candidateSetRepresentation":"sparse_ids")"));
    CHECK(contains(json, R"("candidateSetRepresentation":"dense_bitset")"));
    CHECK(contains(json, R"("candidateSetBytes":1)"));
    CHECK(contains(json, R"("candidateSetBytes":2)"));
}

TEST_CASE("shared predicate DAG simulator does not retain nonselective matched subject sets") {
    constexpr std::string_view source = R"(
import "process"

rule broad {
    condition:
        process.name == "target.exe"
}
)";

    auto parsed = rule_engine::parse_source("optimizer-nonselective.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());

    const auto canonical = rule_engine::optimizer::extract_canonical_predicates(*verified);
    REQUIRE(canonical.predicates.size() == 1u);

    const std::vector<rule_engine::Subject> subjects {
        rule_engine::Subject {.kind = "process", .id = "pid:0"},
        rule_engine::Subject {.kind = "process", .id = "pid:1"},
        rule_engine::Subject {.kind = "process", .id = "pid:2"},
    };

    rule_engine::FactCache facts;
    for (const auto &subject : subjects) {
        facts.store(rule_engine::Fact {
            .subject_id = subject.id,
            .key = "process.name",
            .value = rule_engine::Value::string("target.exe"),
            .status = rule_engine::FactStatus::available,
            .diagnostic = {},
            .ttl = std::chrono::seconds {0},
        });
    }

    const auto simulation =
        rule_engine::optimizer::simulate_shared_predicate_dag(*verified, canonical, subjects, facts);

    REQUIRE(simulation.predicate_nodes.size() == 1u);
    CHECK(simulation.predicate_nodes[0].matched_subject_count == 3u);
    CHECK(simulation.predicate_nodes[0].observed_selectivity_ppm == 1'000'000u);
    CHECK(simulation.predicate_nodes[0].nonselective);
    CHECK_FALSE(simulation.predicate_nodes[0].retained_matched_subjects);
    CHECK(simulation.predicate_nodes[0].matched_subject_ids.empty());

    REQUIRE(simulation.rule_candidates.size() == 1u);
    CHECK(simulation.rule_candidates[0].candidate_subject_ids == std::vector<std::string>({"pid:0", "pid:1", "pid:2"}));
    CHECK(simulation.pruned_rule_subjects == 0u);

    const auto json = rule_engine::optimizer::shared_predicate_dag_simulation_json(simulation);
    CHECK(contains(json, R"("matchedSubjectCount":3)"));
    CHECK(contains(json, R"("observedSelectivityPpm":1000000)"));
    CHECK(contains(json, R"("nonselective":true)"));
    CHECK(contains(json, R"("retainedMatchedSubjects":false)"));
    CHECK(contains(json, R"("matchedSubjects":[])"));
    CHECK(contains(json, R"("event":"predicate_nonselective")"));
    CHECK(contains(json, R"("reason":"predicate matched every subject; matched subjects elided")"));
}

TEST_CASE("shared predicate DAG simulator unions simple OR candidate sets before exact VM") {
    constexpr std::string_view source = R"(
import "process"

rule name_or {
    condition:
        process.name == "powershell.exe" or process.name == "cmd.exe"
}

rule broad_or {
    condition:
        process.name == "powershell.exe" or true
}
)";

    auto parsed = rule_engine::parse_source("optimizer-or-union.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());

    const auto canonical = rule_engine::optimizer::extract_canonical_predicates(*verified);
    REQUIRE(canonical.predicates.size() == 2u);
    for (const auto &predicate : canonical.predicates) {
        for (const auto &owner : predicate.owners) { CHECK_FALSE(owner.prune_safe); }
    }

    const std::vector<rule_engine::Subject> subjects {
        rule_engine::Subject {.kind = "process", .id = "pid:powershell"},
        rule_engine::Subject {.kind = "process", .id = "pid:cmd"},
        rule_engine::Subject {.kind = "process", .id = "pid:notepad"},
        rule_engine::Subject {.kind = "process", .id = "pid:diagnostic"},
    };

    rule_engine::FactCache facts;
    facts.store(rule_engine::Fact {
        .subject_id = "pid:powershell",
        .key = "process.name",
        .value = rule_engine::Value::string("powershell.exe"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {0},
    });
    facts.store(rule_engine::Fact {
        .subject_id = "pid:cmd",
        .key = "process.name",
        .value = rule_engine::Value::string("cmd.exe"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {0},
    });
    facts.store(rule_engine::Fact {
        .subject_id = "pid:notepad",
        .key = "process.name",
        .value = rule_engine::Value::string("notepad.exe"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {0},
    });
    facts.store(rule_engine::Fact {
        .subject_id = "pid:diagnostic",
        .key = "process.name",
        .value = rule_engine::Value::undefined(),
        .status = rule_engine::FactStatus::unavailable,
        .diagnostic = "snapshot unavailable",
        .ttl = std::chrono::seconds {0},
    });

    const auto simulation =
        rule_engine::optimizer::simulate_shared_predicate_dag(*verified, canonical, subjects, facts);

    REQUIRE(simulation.rule_candidates.size() == 2u);
    CHECK(simulation.rule_candidates[0].rule_identifier == "name_or");
    CHECK(simulation.rule_candidates[0].candidate_subject_ids ==
          std::vector<std::string>({"pid:powershell", "pid:cmd", "pid:diagnostic"}));
    REQUIRE(simulation.rule_candidates[0].pruned_subjects.size() == 1u);
    CHECK(simulation.rule_candidates[0].pruned_subjects[0].subject_id == "pid:notepad");
    CHECK(simulation.rule_candidates[0].pruned_subjects[0].predicate_id == "or_union:name_or");
    CHECK(simulation.rule_candidates[0].pruned_subjects[0].reason == "all lifted OR alternatives evaluated false");

    CHECK(simulation.rule_candidates[1].rule_identifier == "broad_or");
    CHECK(simulation.rule_candidates[1].candidate_subject_ids ==
          std::vector<std::string>({"pid:powershell", "pid:cmd", "pid:notepad", "pid:diagnostic"}));
    CHECK(simulation.pruned_rule_subjects == 1u);

    const auto json = rule_engine::optimizer::shared_predicate_dag_simulation_json(simulation);
    CHECK(contains(json, R"("predicateId":"or_union:name_or")"));
    CHECK(contains(json, R"("reason":"all lifted OR alternatives evaluated false")"));

    const auto comparison =
        rule_engine::optimizer::compare_prefiltered_evaluation(*verified, canonical, subjects, facts);
    CHECK(comparison.result_mismatches == 0u);
    CHECK(comparison.incomplete_subjects.empty());
    CHECK(comparison.baseline_exact_vm_rule_executions == 8u);
    CHECK(comparison.prefiltered_exact_vm_rule_executions == 7u);
    CHECK(comparison.exact_vm_rule_executions_avoided == 1u);
    REQUIRE(comparison.subjects.size() == 4u);
    CHECK(comparison.subjects[2].subject_id == "pid:notepad");
    CHECK(comparison.subjects[2].pruned_rule_identifiers == std::vector<std::string> {"name_or"});
}

TEST_CASE("lazy provider expansion plans expensive facts only for surviving candidates") {
    constexpr std::string_view source = R"(
import "process"
import "pe"

rule expensive_after_name {
    condition:
        process.name == "powershell.exe" and
        for any imported in pe.imports : (imported["dll"] contains "KERNEL32.dll")
}
)";

    auto parsed = rule_engine::parse_source("optimizer-lazy.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());

    const std::vector<rule_engine::Subject> subjects {
        rule_engine::Subject {.kind = "process", .id = "pid:match"},
        rule_engine::Subject {.kind = "process", .id = "pid:miss"},
        rule_engine::Subject {.kind = "process", .id = "pid:unknown"},
    };

    rule_engine::FactCache facts;
    facts.store(rule_engine::Fact {
        .subject_id = "pid:match",
        .key = "process.name",
        .value = rule_engine::Value::string("powershell.exe"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {0},
    });
    facts.store(rule_engine::Fact {
        .subject_id = "pid:miss",
        .key = "process.name",
        .value = rule_engine::Value::string("cmd.exe"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {0},
    });
    facts.store(rule_engine::Fact {
        .subject_id = "pid:miss",
        .key = "pe.is_valid",
        .value = rule_engine::Value::boolean(true),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {0},
    });

    const auto canonical = rule_engine::optimizer::extract_canonical_predicates(*verified);
    const auto simulation =
        rule_engine::optimizer::simulate_shared_predicate_dag(*verified, canonical, subjects, facts);

    const auto plan = rule_engine::optimizer::plan_lazy_provider_expansion(*verified, simulation);

    REQUIRE(plan.requests.size() == 1u);
    CHECK(plan.requests[0].route == "endpoint.process.image.pe");
    CHECK(plan.requests[0].key == "pe.imports");
    CHECK_FALSE(plan.requests[0].cheap_prefetch);
    CHECK(plan.requests[0].subject_ids == std::vector<std::string>({"pid:match", "pid:unknown"}));
    CHECK(plan.requests[0].rule_identifiers == std::vector<std::string> {"expensive_after_name"});
    CHECK(plan.requests[0].avoided_subject_ids == std::vector<std::string> {"pid:miss"});
    CHECK(plan.provider_batches == 1u);
    CHECK(plan.facts_requested == 2u);
    CHECK(plan.expensive_facts_requested == 2u);
    CHECK(plan.facts_avoided == 1u);
    CHECK(plan.expensive_facts_avoided == 1u);

    const auto json = rule_engine::optimizer::lazy_provider_expansion_plan_json(plan);
    CHECK(contains(json, R"("schema":"rule-engine-lazy-provider-expansion-plan.v1")"));
    CHECK(contains(json, R"("providerBatches":1)"));
    CHECK(contains(json, R"("factsRequested":2)"));
    CHECK(contains(json, R"("expensiveFactsAvoided":1)"));
    CHECK(contains(json, R"("route":"endpoint.process.image.pe")"));
    CHECK(contains(json, R"("subjects":["pid:match","pid:unknown"])"));
    CHECK(contains(json, R"("avoidedSubjects":["pid:miss"])"));
}

TEST_CASE("lazy provider expansion drops empty candidate branches before materializing expensive facts") {
    constexpr std::string_view source = R"(
import "process"
import "pe"

rule impossible_expensive {
    condition:
        process.name == "powershell.exe" and
        for any imported in pe.imports : (imported["dll"] contains "KERNEL32.dll")
}
)";

    auto parsed = rule_engine::parse_source("optimizer-empty-branch.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());

    const std::vector<rule_engine::Subject> subjects {
        rule_engine::Subject {.kind = "process", .id = "pid:cmd"},
        rule_engine::Subject {.kind = "process", .id = "pid:notepad"},
    };

    rule_engine::FactCache facts;
    facts.store(rule_engine::Fact {
        .subject_id = "pid:cmd",
        .key = "process.name",
        .value = rule_engine::Value::string("cmd.exe"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {0},
    });
    facts.store(rule_engine::Fact {
        .subject_id = "pid:notepad",
        .key = "process.name",
        .value = rule_engine::Value::string("notepad.exe"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {0},
    });

    const auto canonical = rule_engine::optimizer::extract_canonical_predicates(*verified);
    const auto simulation =
        rule_engine::optimizer::simulate_shared_predicate_dag(*verified, canonical, subjects, facts);

    REQUIRE(simulation.rule_candidates.size() == 1u);
    CHECK(simulation.rule_candidates[0].rule_identifier == "impossible_expensive");
    CHECK(simulation.rule_candidates[0].candidate_subject_ids.empty());
    CHECK(simulation.rule_candidates[0].dropped);
    CHECK(simulation.dropped_rule_branches == 1u);
    CHECK(simulation.pruned_rule_subjects == 2u);

    const auto simulation_json = rule_engine::optimizer::shared_predicate_dag_simulation_json(simulation);
    CHECK(contains(simulation_json, R"("droppedRuleBranches":1)"));
    CHECK(contains(simulation_json, R"("dropped":true)"));

    const auto plan = rule_engine::optimizer::plan_lazy_provider_expansion(*verified, simulation);
    CHECK(plan.requests.empty());
    CHECK(plan.provider_batches == 0u);
    CHECK(plan.facts_requested == 0u);
    CHECK(plan.expensive_facts_requested == 0u);

    const auto plan_json = rule_engine::optimizer::lazy_provider_expansion_plan_json(plan);
    CHECK(contains(plan_json, R"("providerBatches":0)"));
    CHECK(contains(plan_json, R"("factsRequested":0)"));
    CHECK(contains(plan_json, R"("expensiveFactsRequested":0)"));
    CHECK(contains(plan_json, R"("requests":[])"));
}

TEST_CASE("generic candidate provider filters shared predicates without rule decisions") {
    constexpr std::string_view source = R"(
import "process"
import "pe"

rule expensive_after_name {
    condition:
        process.name == "powershell.exe" and
        for any imported in pe.imports : (imported["dll"] contains "KERNEL32.dll")
}

rule broad_or {
    condition:
        process.name == "powershell.exe" or true
}
)";

    auto parsed = rule_engine::parse_source("optimizer-candidate-provider.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());

    const auto canonical = rule_engine::optimizer::extract_canonical_predicates(*verified);
    const auto request_plan = rule_engine::optimizer::plan_candidate_provider_requests(canonical);

    REQUIRE(request_plan.requests.size() == 1u);
    CHECK(request_plan.requests[0].id == "process.inventory.by_image_name|string:powershell.exe");
    CHECK(request_plan.requests[0].route == "endpoint.process.inventory");
    CHECK(request_plan.requests[0].filter_key == "process.inventory.by_image_name");
    CHECK(request_plan.requests[0].argument_kind == "string");
    CHECK(request_plan.requests[0].argument_value == "powershell.exe");
    CHECK(request_plan.requests[0].rule_identifiers.empty());

    const std::vector<rule_engine::Subject> subjects {
        rule_engine::Subject {.kind = "process", .id = "pid:match"},
        rule_engine::Subject {.kind = "process", .id = "pid:miss"},
    };
    const std::vector<rule_engine::optimizer::CandidateProviderResult> provider_results {
        rule_engine::optimizer::CandidateProviderResult {
            .request_id = "process.inventory.by_image_name|string:powershell.exe",
            .subject_ids = {"pid:match"},
            .available = true,
            .diagnostic = {},
        },
    };

    const auto simulation = rule_engine::optimizer::simulate_candidate_provider_filter(
        *verified, canonical, subjects, request_plan, provider_results, rule_engine::FactCache {});

    CHECK(simulation.provider_requests == 1u);
    CHECK(simulation.candidate_subjects_returned == 1u);
    CHECK(simulation.server_fallback_predicate_evaluations == 0u);
    REQUIRE(simulation.shared_dag.rule_candidates.size() == 2u);
    CHECK(simulation.shared_dag.rule_candidates[0].rule_identifier == "expensive_after_name");
    CHECK(simulation.shared_dag.rule_candidates[0].candidate_subject_ids == std::vector<std::string> {"pid:match"});
    REQUIRE(simulation.shared_dag.rule_candidates[0].pruned_subjects.size() == 1u);
    CHECK(simulation.shared_dag.rule_candidates[0].pruned_subjects[0].subject_id == "pid:miss");
    CHECK(simulation.shared_dag.rule_candidates[1].rule_identifier == "broad_or");
    CHECK(simulation.shared_dag.rule_candidates[1].candidate_subject_ids ==
          std::vector<std::string>({"pid:match", "pid:miss"}));

    const auto lazy_plan = rule_engine::optimizer::plan_lazy_provider_expansion(*verified, simulation.shared_dag);
    REQUIRE(lazy_plan.requests.size() == 1u);
    CHECK(lazy_plan.requests[0].subject_ids == std::vector<std::string> {"pid:match"});
    CHECK(lazy_plan.requests[0].avoided_subject_ids == std::vector<std::string> {"pid:miss"});

    const auto json = rule_engine::optimizer::candidate_provider_simulation_json(simulation);
    CHECK(contains(json, R"("schema":"rule-engine-candidate-provider-simulation.v1")"));
    CHECK(contains(json, R"("providerRequests":1)"));
    CHECK(contains(json, R"("candidateSubjectsReturned":1)"));
    CHECK(contains(json, R"("filterKey":"process.inventory.by_image_name")"));
    CHECK_FALSE(contains(json, R"("rule":"expensive_after_name")"));

    rule_engine::FactCache fallback_facts;
    fallback_facts.store(rule_engine::Fact {
        .subject_id = "pid:match",
        .key = "process.name",
        .value = rule_engine::Value::string("powershell.exe"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {0},
    });
    fallback_facts.store(rule_engine::Fact {
        .subject_id = "pid:miss",
        .key = "process.name",
        .value = rule_engine::Value::string("cmd.exe"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {0},
    });
    const std::vector<rule_engine::optimizer::CandidateProviderResult> unavailable_results {
        rule_engine::optimizer::CandidateProviderResult {
            .request_id = "process.inventory.by_image_name|string:powershell.exe",
            .subject_ids = {},
            .available = false,
            .diagnostic = "candidate provider unavailable",
        },
    };

    const auto fallback = rule_engine::optimizer::simulate_candidate_provider_filter(
        *verified, canonical, subjects, request_plan, unavailable_results, fallback_facts);
    CHECK(fallback.provider_requests == 1u);
    CHECK(fallback.server_fallback_predicate_evaluations == 2u);
    REQUIRE(fallback.shared_dag.rule_candidates.size() == 2u);
    CHECK(fallback.shared_dag.rule_candidates[0].candidate_subject_ids == std::vector<std::string> {"pid:match"});
}

TEST_CASE("discovery gate simulation skips empty rule packs without rule decisions") {
    constexpr std::string_view source = R"(
import "process"
import "pe"

rule alpha {
    condition:
        process.name == "target.exe" and pe.is_valid
}

rule beta {
    condition:
        process.name == "target.exe" and
        for any imported in pe.imports : (imported["dll"] contains "KERNEL32.dll")
}
)";

    auto parsed = rule_engine::parse_source("optimizer-discovery-gate-empty.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());

    const auto canonical = rule_engine::optimizer::extract_canonical_predicates(*verified);
    const auto plan = rule_engine::optimizer::plan_discovery_gates(*verified, canonical);

    REQUIRE(plan.gates.size() == 1u);
    CHECK(plan.gates[0].predicate_id == "endpoint.process.snapshot|process.name|equal|string:target.exe");
    CHECK(plan.gates[0].cost_class == rule_engine::FactCostClass::inventory);
    CHECK(plan.gates[0].rule_identifiers == std::vector<std::string>({"alpha", "beta"}));
    CHECK(plan.gates[0].span.source == "optimizer-discovery-gate-empty.yar");

    const std::vector<rule_engine::Subject> subjects {
        rule_engine::Subject {.kind = "process", .id = "pid:0"},
        rule_engine::Subject {.kind = "process", .id = "pid:1"},
    };

    rule_engine::FactCache facts;
    for (const auto &subject : subjects) {
        facts.store(rule_engine::Fact {
            .subject_id = subject.id,
            .key = "process.name",
            .value = rule_engine::Value::string("benign.exe"),
            .status = rule_engine::FactStatus::available,
            .diagnostic = {},
            .ttl = std::chrono::seconds {0},
        });
    }

    const auto simulation = rule_engine::optimizer::simulate_discovery_gates(*verified, plan, subjects, facts);

    CHECK(simulation.gate_evaluations == 2u);
    CHECK(simulation.pack_skipped);
    CHECK(simulation.skip_reason ==
          "discovery gate endpoint.process.snapshot|process.name|equal|string:target.exe rejected every subject");
    REQUIRE(simulation.gate_results.size() == 1u);
    CHECK(simulation.gate_results[0].matched_subject_ids.empty());
    REQUIRE(simulation.gate_results[0].rejected_subjects.size() == 2u);
    CHECK(simulation.gate_results[0].rejected_subjects[0].subject_id == "pid:0");
    CHECK(simulation.gate_results[0].unknown_subjects.empty());
    REQUIRE(simulation.trace_events.size() == 2u);
    CHECK(simulation.trace_events[0].event == "discovery_gate_ordered");
    CHECK(simulation.trace_events[1].event == "discovery_gate_pack_skipped");
    CHECK(simulation.trace_events[1].candidate_subject_count == 0u);

    const auto json = rule_engine::optimizer::discovery_gate_simulation_json(simulation);
    CHECK(contains(json, R"("schema":"rule-engine-discovery-gate-simulation.v1")"));
    CHECK(contains(json, R"("gateCount":1)"));
    CHECK(contains(json, R"("gateEvaluations":2)"));
    CHECK(contains(json, R"("packSkipped":true)"));
    CHECK(contains(json, R"("event":"discovery_gate_pack_skipped")"));
    CHECK(contains(json, R"("rules":["alpha","beta"])"));
    CHECK(contains(json, R"("rejectedSubjects":[{"subject":"pid:0")"));
}

TEST_CASE("discovery gate simulation keeps unknown subjects from skipping a pack") {
    constexpr std::string_view source = R"(
import "process"

rule alpha {
    condition:
        process.name == "target.exe"
}

rule beta {
    condition:
        process.name == "target.exe"
}
)";

    auto parsed = rule_engine::parse_source("optimizer-discovery-gate-unknown.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());

    const auto canonical = rule_engine::optimizer::extract_canonical_predicates(*verified);
    const auto plan = rule_engine::optimizer::plan_discovery_gates(*verified, canonical);
    REQUIRE(plan.gates.size() == 1u);

    const std::vector<rule_engine::Subject> subjects {
        rule_engine::Subject {.kind = "process", .id = "pid:miss"},
        rule_engine::Subject {.kind = "process", .id = "pid:unknown"},
    };

    rule_engine::FactCache facts;
    facts.store(rule_engine::Fact {
        .subject_id = "pid:miss",
        .key = "process.name",
        .value = rule_engine::Value::string("benign.exe"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {0},
    });

    const auto simulation = rule_engine::optimizer::simulate_discovery_gates(*verified, plan, subjects, facts);

    CHECK(simulation.gate_evaluations == 2u);
    CHECK_FALSE(simulation.pack_skipped);
    REQUIRE(simulation.gate_results.size() == 1u);
    CHECK(simulation.gate_results[0].matched_subject_ids.empty());
    REQUIRE(simulation.gate_results[0].rejected_subjects.size() == 1u);
    CHECK(simulation.gate_results[0].rejected_subjects[0].subject_id == "pid:miss");
    REQUIRE(simulation.gate_results[0].unknown_subjects.size() == 1u);
    CHECK(simulation.gate_results[0].unknown_subjects[0].subject_id == "pid:unknown");
    CHECK(simulation.gate_results[0].unknown_subjects[0].reason == "missing fact process.name");

    const auto json = rule_engine::optimizer::discovery_gate_simulation_json(simulation);
    CHECK(contains(json, R"("packSkipped":false)"));
    CHECK(contains(json, R"("unknownSubjects":[{"subject":"pid:unknown","reason":"missing fact process.name"}])"));
    CHECK_FALSE(contains(json, R"("discovery_gate_pack_skipped")"));
}

TEST_CASE("prefiltered evaluation preserves baseline results while skipping pruned exact VM rules") {
    constexpr std::string_view source = R"(
import "process"
import "pe"

rule cheap_name {
    condition:
        process.name == "powershell.exe"
}

rule expensive_after_name {
    condition:
        process.name == "powershell.exe" and pe.is_valid
}

rule broad_or {
    condition:
        process.name == "powershell.exe" or true
}
)";

    auto parsed = rule_engine::parse_source("optimizer-prefilter.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());

    const std::vector<rule_engine::Subject> subjects {
        rule_engine::Subject {.kind = "process", .id = "pid:match"},
        rule_engine::Subject {.kind = "process", .id = "pid:miss"},
    };

    rule_engine::FactCache facts;
    facts.store(rule_engine::Fact {
        .subject_id = "pid:match",
        .key = "process.name",
        .value = rule_engine::Value::string("powershell.exe"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {0},
    });
    facts.store(rule_engine::Fact {
        .subject_id = "pid:match",
        .key = "pe.is_valid",
        .value = rule_engine::Value::boolean(true),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {0},
    });
    facts.store(rule_engine::Fact {
        .subject_id = "pid:miss",
        .key = "process.name",
        .value = rule_engine::Value::string("cmd.exe"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {0},
    });
    facts.store(rule_engine::Fact {
        .subject_id = "pid:miss",
        .key = "pe.is_valid",
        .value = rule_engine::Value::boolean(true),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {0},
    });

    const auto canonical = rule_engine::optimizer::extract_canonical_predicates(*verified);
    const auto report = rule_engine::optimizer::compare_prefiltered_evaluation(*verified, canonical, subjects, facts);

    CHECK(report.result_mismatches == 0u);
    CHECK(report.incomplete_subjects.empty());
    CHECK(report.baseline_exact_vm_rule_executions == 6u);
    CHECK(report.prefiltered_exact_vm_rule_executions == 4u);
    CHECK(report.exact_vm_rule_executions_avoided == 2u);
    REQUIRE(report.subjects.size() == 2u);

    CHECK(report.subjects[0].subject_id == "pid:match");
    REQUIRE(report.subjects[0].optimized_results.size() == 3u);
    CHECK(report.subjects[0].optimized_results[0].identifier == "cheap_name");
    CHECK(report.subjects[0].optimized_results[0].matched);
    CHECK(report.subjects[0].optimized_results[1].identifier == "expensive_after_name");
    CHECK(report.subjects[0].optimized_results[1].matched);
    CHECK(report.subjects[0].optimized_results[2].identifier == "broad_or");
    CHECK(report.subjects[0].optimized_results[2].matched);

    CHECK(report.subjects[1].subject_id == "pid:miss");
    REQUIRE(report.subjects[1].optimized_results.size() == 3u);
    CHECK(report.subjects[1].optimized_results[0].identifier == "cheap_name");
    CHECK_FALSE(report.subjects[1].optimized_results[0].matched);
    CHECK(report.subjects[1].optimized_results[1].identifier == "expensive_after_name");
    CHECK_FALSE(report.subjects[1].optimized_results[1].matched);
    CHECK(report.subjects[1].optimized_results[2].identifier == "broad_or");
    CHECK(report.subjects[1].optimized_results[2].matched);
    CHECK(report.subjects[1].pruned_rule_identifiers ==
          std::vector<std::string>({"cheap_name", "expensive_after_name"}));

    REQUIRE(report.trace_events.size() == 2u);
    CHECK(report.trace_events[0].event == "exact_vm_rule_skipped");
    CHECK(report.trace_events[0].rule_identifier == "cheap_name");
    CHECK(report.trace_events[0].subject_id == "pid:miss");
    CHECK(report.trace_events[0].predicate_id == "endpoint.process.snapshot|process.name|equal|string:powershell.exe");
    CHECK(report.trace_events[0].reason ==
          "exact VM skipped because process.name equal string:powershell.exe evaluated false");
    CHECK(report.trace_events[0].candidate_subject_count == 1u);
    CHECK(report.trace_events[0].candidate_set_bytes == 1u);

    CHECK(report.trace_events[1].event == "exact_vm_rule_skipped");
    CHECK(report.trace_events[1].rule_identifier == "expensive_after_name");
    CHECK(report.trace_events[1].subject_id == "pid:miss");
    CHECK(report.trace_events[1].reason ==
          "exact VM skipped because process.name equal string:powershell.exe evaluated false");
}

TEST_CASE("prefiltered evaluation keeps diagnostic predicates on the exact VM path") {
    constexpr std::string_view source = R"(
import "process"

rule name_filter {
    condition:
        process.name == "powershell.exe"
}
)";

    auto parsed = rule_engine::parse_source("optimizer-prefilter-diagnostic.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());

    const std::vector<rule_engine::Subject> subjects {
        rule_engine::Subject {.kind = "process", .id = "pid:diagnostic"},
    };

    rule_engine::FactCache facts;
    facts.store(rule_engine::Fact {
        .subject_id = "pid:diagnostic",
        .key = "process.name",
        .value = rule_engine::Value::undefined(),
        .status = rule_engine::FactStatus::unavailable,
        .diagnostic = "snapshot unavailable",
        .ttl = std::chrono::seconds {0},
    });

    const auto canonical = rule_engine::optimizer::extract_canonical_predicates(*verified);
    const auto report = rule_engine::optimizer::compare_prefiltered_evaluation(*verified, canonical, subjects, facts);

    CHECK(report.result_mismatches == 0u);
    CHECK(report.baseline_exact_vm_rule_executions == 1u);
    CHECK(report.prefiltered_exact_vm_rule_executions == 1u);
    CHECK(report.exact_vm_rule_executions_avoided == 0u);
    REQUIRE(report.subjects.size() == 1u);
    CHECK(report.subjects[0].pruned_rule_identifiers.empty());
    REQUIRE(report.subjects[0].optimized_results.size() == 1u);
    CHECK_FALSE(report.subjects[0].optimized_results[0].matched);
    REQUIRE(report.subjects[0].optimized_results[0].diagnostics.size() == 1u);
    CHECK(report.subjects[0].optimized_results[0].diagnostics[0].message == "snapshot unavailable");
}

TEST_CASE("prefiltered evaluation preserves expensive-first diagnostics before pruning later predicates") {
    constexpr std::string_view source = R"(
import "process"
import "pe"

rule expensive_first {
    condition:
        for any imported in pe.imports : (imported["dll"] contains "KERNEL32.dll") and
        process.name == "target.exe"
}

rule cheap_first {
    condition:
        process.name == "target.exe" and
        for any imported in pe.imports : (imported["dll"] contains "KERNEL32.dll")
}
)";

    auto parsed = rule_engine::parse_source("optimizer-prefilter-expensive-first.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());

    const std::vector<rule_engine::Subject> subjects {
        rule_engine::Subject {.kind = "process", .id = "pid:miss"},
    };

    rule_engine::FactCache facts;
    facts.store(rule_engine::Fact {
        .subject_id = "pid:miss",
        .key = "process.name",
        .value = rule_engine::Value::string("benign.exe"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {0},
    });
    facts.store(rule_engine::Fact {
        .subject_id = "pid:miss",
        .key = "pe.imports",
        .value = rule_engine::Value::undefined(),
        .status = rule_engine::FactStatus::unavailable,
        .diagnostic = "imports unavailable",
        .ttl = std::chrono::seconds {0},
    });

    const auto canonical = rule_engine::optimizer::extract_canonical_predicates(*verified);
    REQUIRE(canonical.predicates.size() == 1u);
    REQUIRE(canonical.predicates[0].owners.size() == 2u);
    CHECK_FALSE(canonical.predicates[0].owners[0].prune_safe);
    CHECK(canonical.predicates[0].owners[1].prune_safe);

    const auto report = rule_engine::optimizer::compare_prefiltered_evaluation(*verified, canonical, subjects, facts);

    CHECK(report.result_mismatches == 0u);
    CHECK(report.incomplete_subjects.empty());
    CHECK(report.baseline_exact_vm_rule_executions == 2u);
    CHECK(report.prefiltered_exact_vm_rule_executions == 1u);
    CHECK(report.exact_vm_rule_executions_avoided == 1u);
    REQUIRE(report.subjects.size() == 1u);
    CHECK(report.subjects[0].exact_vm_rule_identifiers == std::vector<std::string> {"expensive_first"});
    CHECK(report.subjects[0].pruned_rule_identifiers == std::vector<std::string> {"cheap_first"});
    REQUIRE(report.subjects[0].optimized_results.size() == 2u);
    CHECK(report.subjects[0].optimized_results[0].identifier == "expensive_first");
    REQUIRE(report.subjects[0].optimized_results[0].diagnostics.size() == 1u);
    CHECK(report.subjects[0].optimized_results[0].diagnostics[0].message == "imports unavailable");
    CHECK(report.subjects[0].optimized_results[1].identifier == "cheap_first");
    CHECK(report.subjects[0].optimized_results[1].diagnostics.empty());
}

TEST_CASE("watchdog simulation classifies nonselective predicates and oversized route batches") {
    rule_engine::optimizer::SharedPredicateDagSimulation dag;
    dag.predicate_nodes.push_back(rule_engine::optimizer::PredicateNodeSimulation {
        .predicate_id = "endpoint.process.snapshot|process.name|equal|string:target.exe",
        .cost_class = rule_engine::FactCostClass::inventory,
        .observed_selectivity_ppm = 100000u,
        .matched_subject_count = 2u,
        .nonselective = false,
        .retained_matched_subjects = true,
        .matched_subject_ids = {},
        .pruned_subjects = {},
        .unknown_subjects = {},
    });
    dag.predicate_nodes.push_back(rule_engine::optimizer::PredicateNodeSimulation {
        .predicate_id = "endpoint.process.snapshot|process.name|not_equal|string:never.exe",
        .cost_class = rule_engine::FactCostClass::inventory,
        .observed_selectivity_ppm = 1000000u,
        .matched_subject_count = 20u,
        .nonselective = true,
        .retained_matched_subjects = false,
        .matched_subject_ids = {},
        .pruned_subjects = {},
        .unknown_subjects = {},
    });

    rule_engine::optimizer::LazyProviderExpansionPlan lazy;
    lazy.requests.push_back(rule_engine::optimizer::LazyProviderExpansionRequest {
        .route = "endpoint.process.image.pe",
        .key = "pe.imports",
        .type = rule_engine::ValueType::array,
        .cheap_prefetch = false,
        .subject_ids = {},
        .avoided_subject_ids = {},
        .rule_identifiers = {"expensive_rule"},
    });
    for (std::size_t index = 0; index < 20u; ++index) {
        lazy.requests[0].subject_ids.push_back("pid:" + std::to_string(index));
    }

    const auto simulation = rule_engine::optimizer::simulate_watchdog_budgets(dag, lazy);

    CHECK(simulation.evaluations == 3u);
    CHECK(simulation.budget_events == 2u);
    CHECK(simulation.predicate_budget_events == 1u);
    CHECK(simulation.route_budget_events == 1u);
    REQUIRE(simulation.trace_events.size() == 2u);
    CHECK(simulation.trace_events[0].event == "predicate_budget_classified");
    CHECK(simulation.trace_events[0].predicate_id ==
          "endpoint.process.snapshot|process.name|not_equal|string:never.exe");
    CHECK(simulation.trace_events[0].reason ==
          "predicate selectivity 1000000 ppm exceeded low-selectivity budget 900000 ppm");
    CHECK(simulation.trace_events[0].candidate_subject_count == 20u);
    CHECK(simulation.trace_events[1].event == "route_budget_classified");
    CHECK(simulation.trace_events[1].predicate_id == "endpoint.process.image.pe|pe.imports");
    CHECK(simulation.trace_events[1].reason ==
          "route endpoint.process.image.pe key pe.imports requested 20 facts exceeded request budget 16");
}

TEST_CASE("watchdog enforcement emits explicit budget diagnostics") {
    rule_engine::optimizer::SharedPredicateDagSimulation dag;
    dag.predicate_nodes.push_back(rule_engine::optimizer::PredicateNodeSimulation {
        .predicate_id = "endpoint.process.snapshot|process.name|not_equal|string:never.exe",
        .cost_class = rule_engine::FactCostClass::inventory,
        .observed_selectivity_ppm = 1000000u,
        .matched_subject_count = 20u,
        .nonselective = true,
        .retained_matched_subjects = false,
        .matched_subject_ids = {},
        .pruned_subjects = {},
        .unknown_subjects = {},
    });

    rule_engine::optimizer::LazyProviderExpansionPlan lazy;
    lazy.requests.push_back(rule_engine::optimizer::LazyProviderExpansionRequest {
        .route = "endpoint.process.image.pe",
        .key = "pe.imports",
        .type = rule_engine::ValueType::array,
        .cheap_prefetch = false,
        .subject_ids = {},
        .avoided_subject_ids = {},
        .rule_identifiers = {"expensive_rule"},
    });
    for (std::size_t index = 0; index < 20u; ++index) {
        lazy.requests[0].subject_ids.push_back("pid:" + std::to_string(index));
    }

    const auto simulation = rule_engine::optimizer::simulate_watchdog_budgets(
        dag, lazy,
        rule_engine::optimizer::WatchdogBudgetPolicy {
            .low_selectivity_budget_ppm = 900000u,
            .route_request_budget = 16u,
            .predicate_budget_action = rule_engine::optimizer::WatchdogBudgetAction::defer_branch,
            .route_budget_action = rule_engine::optimizer::WatchdogBudgetAction::timeout_branch,
        });

    CHECK(simulation.budget_events == 2u);
    CHECK(simulation.explicit_budget_diagnostics == 2u);
    CHECK(simulation.deferred_branch_diagnostics == 1u);
    CHECK(simulation.timeout_diagnostics == 1u);
    CHECK(simulation.unavailable_diagnostics == 0u);
    REQUIRE(simulation.budget_diagnostics.size() == 2u);

    CHECK(simulation.budget_diagnostics[0].action == rule_engine::optimizer::WatchdogBudgetAction::defer_branch);
    CHECK(simulation.budget_diagnostics[0].predicate_id ==
          "endpoint.process.snapshot|process.name|not_equal|string:never.exe");
    CHECK(simulation.budget_diagnostics[0].affected_subject_count == 20u);
    CHECK(simulation.budget_diagnostics[0].diagnostic.source == "optimizer.watchdog");
    CHECK(simulation.budget_diagnostics[0].diagnostic.message ==
          "optimizer watchdog deferred branch because predicate selectivity 1000000 ppm exceeded low-selectivity "
          "budget 900000 ppm");

    CHECK(simulation.budget_diagnostics[1].action == rule_engine::optimizer::WatchdogBudgetAction::timeout_branch);
    CHECK(simulation.budget_diagnostics[1].predicate_id == "endpoint.process.image.pe|pe.imports");
    CHECK(simulation.budget_diagnostics[1].affected_subject_count == 20u);
    CHECK(simulation.budget_diagnostics[1].diagnostic.source == "optimizer.watchdog");
    CHECK(simulation.budget_diagnostics[1].diagnostic.message ==
          "optimizer watchdog timed out route endpoint.process.image.pe key pe.imports because 20 requested facts "
          "exceeded request budget 16");
}

TEST_CASE("static fact cache simulation reuses unchanged image facts and rejects changed identities") {
    std::vector<rule_engine::optimizer::StaticFactCacheCandidate> candidates {
        rule_engine::optimizer::StaticFactCacheCandidate {
            .subject_id = "pid:one",
            .route = "endpoint.process.image.pe",
            .key = "pe.imports",
            .cost_class = rule_engine::FactCostClass::broad_image_array,
            .identity =
                rule_engine::optimizer::StaticFactCacheIdentity {
                    .path = "C:/Windows/System32/app.exe",
                    .file_id = "volume:42:file:7",
                    .file_size = 4096u,
                    .last_write_time = 1000u,
                    .content_hash = "sha256:aaa",
                    .signature_identity = "catalog:stable",
                    .scan_space_name = "process.image.bytes",
                    .scan_space_version = "v1",
                },
            .content_addressable = true,
        },
        rule_engine::optimizer::StaticFactCacheCandidate {
            .subject_id = "pid:two",
            .route = "endpoint.process.image.pe",
            .key = "pe.imports",
            .cost_class = rule_engine::FactCostClass::broad_image_array,
            .identity =
                rule_engine::optimizer::StaticFactCacheIdentity {
                    .path = "C:/Windows/System32/app.exe",
                    .file_id = "volume:42:file:7",
                    .file_size = 4096u,
                    .last_write_time = 1000u,
                    .content_hash = "sha256:aaa",
                    .signature_identity = "catalog:stable",
                    .scan_space_name = "process.image.bytes",
                    .scan_space_version = "v1",
                },
            .content_addressable = true,
        },
        rule_engine::optimizer::StaticFactCacheCandidate {
            .subject_id = "pid:changed",
            .route = "endpoint.process.image.pe",
            .key = "pe.imports",
            .cost_class = rule_engine::FactCostClass::broad_image_array,
            .identity =
                rule_engine::optimizer::StaticFactCacheIdentity {
                    .path = "C:/Windows/System32/app.exe",
                    .file_id = "volume:42:file:7",
                    .file_size = 8192u,
                    .last_write_time = 2000u,
                    .content_hash = "sha256:bbb",
                    .signature_identity = "catalog:changed",
                    .scan_space_name = "process.image.bytes",
                    .scan_space_version = "v1",
                },
            .content_addressable = true,
        },
        rule_engine::optimizer::StaticFactCacheCandidate {
            .subject_id = "pid:volatile",
            .route = "endpoint.process.snapshot",
            .key = "process.name",
            .cost_class = rule_engine::FactCostClass::inventory,
            .identity = {},
            .content_addressable = false,
        },
    };

    const auto simulation = rule_engine::optimizer::simulate_static_fact_cache(candidates);

    CHECK(simulation.lookups == 3u);
    CHECK(simulation.cache_hits == 1u);
    CHECK(simulation.cache_misses == 2u);
    CHECK(simulation.accepted_reuses == 1u);
    CHECK(simulation.rejected_reuses == 1u);
    CHECK(simulation.invalidations == 1u);
    CHECK(simulation.subject_scoped_facts == 1u);
    REQUIRE(simulation.trace_events.size() == 2u);
    CHECK(simulation.trace_events[0].event == "static_fact_cache_reused");
    CHECK(simulation.trace_events[0].subject_id == "pid:two");
    CHECK(simulation.trace_events[0].predicate_id == "endpoint.process.image.pe|pe.imports");
    CHECK(simulation.trace_events[0].reason == "static fact cache reused pe.imports for C:/Windows/System32/app.exe");
    CHECK(simulation.trace_events[1].event == "static_fact_cache_rejected");
    CHECK(simulation.trace_events[1].subject_id == "pid:changed");
    CHECK(simulation.trace_events[1].reason ==
          "static fact cache rejected pe.imports for C:/Windows/System32/app.exe because file identity changed");
}

TEST_CASE("PE static fact identity key defaults use production PE provider facts") {
    const auto keys = rule_engine::optimizer::pe_static_fact_identity_fact_keys();

    CHECK(keys.path == "pe.identity.path");
    CHECK(keys.file_id == "pe.identity.file_id");
    CHECK(keys.file_size == "pe.identity.file_size");
    CHECK(keys.last_write_time == "pe.identity.last_write_time");
    CHECK(keys.content_hash.empty());
    CHECK(keys.signature_identity.empty());
    CHECK(keys.scan_space_name == "pe.identity.scan_space_name");
    CHECK(keys.scan_space_version == "pe.identity.scan_space_version");
}

TEST_CASE("static fact cache primitive reuses static facts and invalidates changed identities") {
    const rule_engine::optimizer::StaticFactCacheIdentity unchanged_identity {
        .path = "C:/Windows/System32/app.exe",
        .file_id = "volume:42:file:7",
        .file_size = 4096u,
        .last_write_time = 1000u,
        .content_hash = "sha256:aaa",
        .signature_identity = "catalog:stable",
        .scan_space_name = "process.image.bytes",
        .scan_space_version = "v1",
    };
    const rule_engine::optimizer::StaticFactCacheIdentity changed_identity {
        .path = "C:/Windows/System32/app.exe",
        .file_id = "volume:42:file:7",
        .file_size = 8192u,
        .last_write_time = 2000u,
        .content_hash = "sha256:bbb",
        .signature_identity = "catalog:changed",
        .scan_space_name = "process.image.bytes",
        .scan_space_version = "v1",
    };

    rule_engine::optimizer::StaticFactCache cache;

    const rule_engine::optimizer::StaticFactCacheCandidate first_static {
        .subject_id = "pid:one",
        .route = "endpoint.process.image.pe",
        .key = "pe.imports",
        .cost_class = rule_engine::FactCostClass::broad_image_array,
        .identity = unchanged_identity,
        .content_addressable = true,
    };
    const auto first_lookup = cache.lookup(first_static);
    CHECK(first_lookup.status == rule_engine::optimizer::StaticFactCacheLookupStatus::miss);
    CHECK_FALSE(first_lookup.fact.has_value());

    CHECK(cache
              .store(first_static,
                     rule_engine::Fact {
                         .subject_id = "pid:one",
                         .key = "pe.imports",
                         .value = rule_engine::Value::integer(3),
                         .status = rule_engine::FactStatus::available,
                         .diagnostic = {},
                         .ttl = std::chrono::seconds {30},
                     })
              .stored);

    const rule_engine::optimizer::StaticFactCacheCandidate second_static {
        .subject_id = "pid:two",
        .route = "endpoint.process.image.pe",
        .key = "pe.imports",
        .cost_class = rule_engine::FactCostClass::broad_image_array,
        .identity = unchanged_identity,
        .content_addressable = true,
    };
    const auto reused = cache.lookup(second_static);
    REQUIRE(reused.status == rule_engine::optimizer::StaticFactCacheLookupStatus::hit);
    REQUIRE(reused.fact.has_value());
    CHECK(reused.fact->subject_id == "pid:two");
    CHECK(reused.fact->key == "pe.imports");
    CHECK(reused.fact->value.as_i64() == 3);
    REQUIRE(reused.trace_event.has_value());
    CHECK(reused.trace_event->event == "static_fact_cache_reused");
    CHECK(reused.trace_event->subject_id == "pid:two");

    const rule_engine::optimizer::StaticFactCacheCandidate changed_static {
        .subject_id = "pid:changed",
        .route = "endpoint.process.image.pe",
        .key = "pe.imports",
        .cost_class = rule_engine::FactCostClass::broad_image_array,
        .identity = changed_identity,
        .content_addressable = true,
    };
    const auto invalidated = cache.lookup(changed_static);
    REQUIRE(invalidated.status == rule_engine::optimizer::StaticFactCacheLookupStatus::invalidated);
    CHECK_FALSE(invalidated.fact.has_value());
    REQUIRE(invalidated.trace_event.has_value());
    CHECK(invalidated.trace_event->event == "static_fact_cache_rejected");
    CHECK(invalidated.trace_event->reason ==
          "static fact cache rejected pe.imports for C:/Windows/System32/app.exe because file identity changed");

    const rule_engine::optimizer::StaticFactCacheCandidate volatile_fact {
        .subject_id = "pid:volatile",
        .route = "endpoint.process.snapshot",
        .key = "process.name",
        .cost_class = rule_engine::FactCostClass::inventory,
        .identity = {},
        .content_addressable = false,
    };
    const auto volatile_store = cache.store(volatile_fact, rule_engine::Fact {
                                                               .subject_id = "pid:volatile",
                                                               .key = "process.name",
                                                               .value = rule_engine::Value::string("app.exe"),
                                                               .status = rule_engine::FactStatus::available,
                                                               .diagnostic = {},
                                                               .ttl = std::chrono::seconds {0},
                                                           });
    CHECK_FALSE(volatile_store.stored);
    CHECK(volatile_store.subject_scoped);
    CHECK(cache.lookup(volatile_fact).status == rule_engine::optimizer::StaticFactCacheLookupStatus::unsupported);

    const auto stats = cache.stats();
    CHECK(stats.lookups == 3u);
    CHECK(stats.cache_hits == 1u);
    CHECK(stats.cache_misses == 2u);
    CHECK(stats.accepted_reuses == 1u);
    CHECK(stats.rejected_reuses == 1u);
    CHECK(stats.invalidations == 1u);
    CHECK(stats.subject_scoped_facts == 1u);
}

TEST_CASE("static fact cache candidates derive from verified identity facts") {
    const std::vector<rule_engine::Subject> subjects {
        rule_engine::Subject {.kind = "process", .id = "pid:one"},
        rule_engine::Subject {.kind = "process", .id = "pid:two"},
        rule_engine::Subject {.kind = "process", .id = "pid:incomplete"},
        rule_engine::Subject {.kind = "process", .id = "pid:diagnostic"},
    };
    const std::vector<rule_engine::optimizer::OptimizerPlanProviderRequirement> requirements {
        rule_engine::optimizer::OptimizerPlanProviderRequirement {
            .route = "endpoint.process.image.pe",
            .key = "pe.imports",
            .type = rule_engine::ValueType::array,
            .cost_class = rule_engine::FactCostClass::broad_image_array,
            .cheap_prefetch = false,
            .rule_identifiers = {"imports_rule"},
        },
        rule_engine::optimizer::OptimizerPlanProviderRequirement {
            .route = "endpoint.process.image.pe",
            .key = "pe.is_valid",
            .type = rule_engine::ValueType::boolean,
            .cost_class = rule_engine::FactCostClass::static_image_header,
            .cheap_prefetch = true,
            .rule_identifiers = {"header_rule"},
        },
        rule_engine::optimizer::OptimizerPlanProviderRequirement {
            .route = "endpoint.process.snapshot",
            .key = "process.name",
            .type = rule_engine::ValueType::string,
            .cost_class = rule_engine::FactCostClass::inventory,
            .cheap_prefetch = true,
            .rule_identifiers = {"process_rule"},
        },
    };

    rule_engine::FactCache identity_facts;
    const auto store_string = [&](std::string subject_id, std::string key, std::string value,
                                  const rule_engine::FactStatus status = rule_engine::FactStatus::available) {
        identity_facts.store(rule_engine::Fact {
            .subject_id = std::move(subject_id),
            .key = std::move(key),
            .value = status == rule_engine::FactStatus::available ? rule_engine::Value::string(std::move(value)) :
                                                                    rule_engine::Value::undefined(),
            .status = status,
            .diagnostic = status == rule_engine::FactStatus::available ? "" : "identity unavailable",
            .ttl = std::chrono::seconds {30},
        });
    };
    const auto store_integer = [&](std::string subject_id, std::string key, const std::int64_t value) {
        identity_facts.store(rule_engine::Fact {
            .subject_id = std::move(subject_id),
            .key = std::move(key),
            .value = rule_engine::Value::integer(value),
            .status = rule_engine::FactStatus::available,
            .diagnostic = {},
            .ttl = std::chrono::seconds {30},
        });
    };
    const auto store_identity = [&](const std::string &subject_id, const std::uint64_t file_size,
                                    const std::uint64_t last_write_time, const std::string &hash,
                                    const std::string &scan_version) {
        store_string(subject_id, "static.identity.path", "C:/Windows/System32/app.exe");
        store_string(subject_id, "static.identity.file_id", "volume:42:file:7");
        store_integer(subject_id, "static.identity.file_size", static_cast<std::int64_t>(file_size));
        store_integer(subject_id, "static.identity.last_write_time", static_cast<std::int64_t>(last_write_time));
        store_string(subject_id, "static.identity.content_hash", hash);
        store_string(subject_id, "static.identity.signature_identity", "catalog:stable");
        store_string(subject_id, "static.identity.scan_space_name", "process.image.bytes");
        store_string(subject_id, "static.identity.scan_space_version", scan_version);
    };
    store_identity("pid:one", 4096u, 1000u, "sha256:aaa", "v1");
    store_identity("pid:two", 4096u, 1000u, "sha256:aaa", "v1");
    store_string("pid:incomplete", "static.identity.path", "C:/Windows/System32/app.exe");
    store_string("pid:diagnostic", "static.identity.path", "", rule_engine::FactStatus::unavailable);
    store_string("pid:diagnostic", "static.identity.file_id", "volume:42:file:7");
    store_integer("pid:diagnostic", "static.identity.file_size", 4096);
    store_integer("pid:diagnostic", "static.identity.last_write_time", 1000);

    const auto candidates = rule_engine::optimizer::derive_static_fact_cache_candidates(
        requirements, subjects, identity_facts,
        rule_engine::optimizer::StaticFactIdentityFactKeys {
            .path = "static.identity.path",
            .file_id = "static.identity.file_id",
            .file_size = "static.identity.file_size",
            .last_write_time = "static.identity.last_write_time",
            .content_hash = "static.identity.content_hash",
            .signature_identity = "static.identity.signature_identity",
            .scan_space_name = "static.identity.scan_space_name",
            .scan_space_version = "static.identity.scan_space_version",
        });

    REQUIRE(candidates.size() == 4u);
    const auto *one_imports = find_static_candidate(candidates, "pid:one", "pe.imports");
    REQUIRE(one_imports != nullptr);
    CHECK(one_imports->route == "endpoint.process.image.pe");
    CHECK(one_imports->cost_class == rule_engine::FactCostClass::broad_image_array);
    CHECK(one_imports->content_addressable);
    CHECK(one_imports->identity.path == "C:/Windows/System32/app.exe");
    CHECK(one_imports->identity.file_id == "volume:42:file:7");
    CHECK(one_imports->identity.file_size == 4096u);
    CHECK(one_imports->identity.last_write_time == 1000u);
    CHECK(one_imports->identity.content_hash == "sha256:aaa");
    CHECK(one_imports->identity.signature_identity == "catalog:stable");
    CHECK(one_imports->identity.scan_space_name == "process.image.bytes");
    CHECK(one_imports->identity.scan_space_version == "v1");

    CHECK(find_static_candidate(candidates, "pid:one", "pe.is_valid") != nullptr);
    CHECK(find_static_candidate(candidates, "pid:two", "pe.imports") != nullptr);
    CHECK(find_static_candidate(candidates, "pid:two", "pe.is_valid") != nullptr);
    CHECK(find_static_candidate(candidates, "pid:one", "process.name") == nullptr);
    CHECK(find_static_candidate(candidates, "pid:incomplete", "pe.imports") == nullptr);
    CHECK(find_static_candidate(candidates, "pid:diagnostic", "pe.imports") == nullptr);
}
