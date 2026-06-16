#include <rule_engine/compiler.hpp>
#include <rule_engine/evaluator.hpp>
#include <rule_engine/modules.hpp>

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace {
    [[nodiscard]] bool artifact_contains(const std::vector<std::byte> &artifact, const std::string_view needle) {
        const auto *data = reinterpret_cast<const char *>(artifact.data());
        const std::string_view haystack {data, artifact.size()};
        return haystack.find(needle) != std::string_view::npos;
    }

    [[nodiscard]] std::uint32_t little_u32_at(const std::vector<std::byte> &artifact, const std::size_t offset) {
        return static_cast<std::uint32_t>(artifact[offset]) |
               (static_cast<std::uint32_t>(artifact[offset + 1u]) << 8u) |
               (static_cast<std::uint32_t>(artifact[offset + 2u]) << 16u) |
               (static_cast<std::uint32_t>(artifact[offset + 3u]) << 24u);
    }
} // namespace

TEST_CASE("scheduler batches missing facts by provider route") {
    constexpr auto source = R"(
import "process"
import "pe"

rule process_and_image {
    condition:
        process.name == "demo.exe" and
        process.parent.pid > 0 and
        pe.number_of_sections > 2
}
)";

    auto parsed = rule_engine::parse_source("schedule.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());

    rule_engine::FactCache facts;
    rule_engine::Evaluator evaluator {*verified, facts};
    const auto step = evaluator.step(rule_engine::Subject {.kind = "process", .id = "pid:100"});

    REQUIRE(step.state == rule_engine::EvaluationState::waiting_for_facts);
    REQUIRE(step.requests.size() == 2u);
    CHECK(step.requests[0].route == "endpoint.process.snapshot");
    CHECK(step.requests[0].keys.size() == 2u);
    CHECK(step.requests[1].route == "endpoint.process.image.pe");
    CHECK(step.requests[1].keys.size() == 1u);
}

TEST_CASE("verified programs expose versioned binary IR and schedule artifacts") {
    constexpr auto source = R"(
import "process"
import "pe"

rule process_and_image {
    condition:
        process.name == "demo.exe" and
        pe.number_of_sections > 2
}
)";

    auto parsed = rule_engine::parse_source("artifact.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());
    CHECK(verified->sources == std::vector<std::string> {"artifact.yar"});
    REQUIRE(verified->rules.size() == 1u);
    CHECK(verified->rules[0].span.source_id == 1u);

    const auto ir_dump = verified->ir_dump();
    CHECK(ir_dump.find("source_id=1") != std::string::npos);

    const auto ir = verified->ir_artifact();
    REQUIRE(ir.size() > 8u);
    CHECK(std::string_view {reinterpret_cast<const char *>(ir.data()), 4u} == "REIR");
    CHECK(little_u32_at(ir, 4u) == 2u);
    CHECK(artifact_contains(ir, "artifact.yar"));
    CHECK(artifact_contains(ir, "process_and_image"));
    CHECK(artifact_contains(ir, "process.name"));
    CHECK(artifact_contains(ir, "pe.number_of_sections"));

    const auto schedule = verified->schedule_plan_artifact();
    REQUIRE(schedule.size() > 8u);
    CHECK(std::string_view {reinterpret_cast<const char *>(schedule.data()), 4u} == "RESC");
    CHECK(little_u32_at(schedule, 4u) == 2u);
    CHECK(artifact_contains(schedule, "endpoint.process.snapshot"));
    CHECK(artifact_contains(schedule, "endpoint.process.image.pe"));
}

TEST_CASE("session cache keeps static facts and expires volatile facts by descriptor TTL") {
    rule_engine::FactCache cache;
    cache.store(rule_engine::Fact {
        .subject_id = "pid:1",
        .key = "process.name",
        .value = rule_engine::Value::string("cmd.exe"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {0},
    });
    cache.store(rule_engine::Fact {
        .subject_id = "pid:1",
        .key = "pe.number_of_sections",
        .value = rule_engine::Value::integer(5),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {30},
    });

    cache.expire_volatile();

    CHECK_FALSE(cache.lookup("pid:1", "process.name").has_value());
    REQUIRE(cache.lookup("pid:1", "pe.number_of_sections").has_value());
    CHECK(cache.lookup("pid:1", "pe.number_of_sections")->value.as_i64() == 5);
}

TEST_CASE("cache policy separates volatile process facts from richer static image facts") {
    constexpr auto source = R"(
import "process"
import "pe"

rule cache_policy {
    condition:
        process.memory.regions.count > 0 and
        for any section in pe.sections : (section["executable"]) and
        for any imported in pe.imports : (imported["dll"] contains "KERNEL32.dll")
}
)";

    auto parsed = rule_engine::parse_source("cache_policy.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());
    REQUIRE(verified->rules.size() == 1u);

    const auto find_required = [&](const std::string_view key) -> const rule_engine::RequiredFact * {
        for (const auto &fact : verified->rules[0].facts) {
            if (fact.key == key) {
                return &fact;
            }
        }
        return nullptr;
    };

    const auto *process_regions = find_required("process.memory.regions.count");
    REQUIRE(process_regions != nullptr);
    CHECK(process_regions->route == "endpoint.process.snapshot");
    CHECK(process_regions->ttl == std::chrono::seconds {0});

    const auto *pe_sections = find_required("pe.sections");
    REQUIRE(pe_sections != nullptr);
    CHECK(pe_sections->route == "endpoint.process.image.pe");
    CHECK(pe_sections->ttl == std::chrono::seconds {30});

    const auto *pe_imports = find_required("pe.imports");
    REQUIRE(pe_imports != nullptr);
    CHECK(pe_imports->route == "endpoint.process.image.pe");
    CHECK(pe_imports->ttl == std::chrono::seconds {30});

    rule_engine::FactCache cache;
    cache.store(rule_engine::Fact {
        .subject_id = "pid:2",
        .key = "process.memory.regions.count",
        .value = rule_engine::Value::integer(42),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {0},
    });
    cache.store(rule_engine::Fact {
        .subject_id = "pid:2",
        .key = "pe.sections",
        .value = rule_engine::Value::array(std::vector<rule_engine::Value> {
            rule_engine::Value::object(std::vector<rule_engine::ObjectEntry> {
                rule_engine::ObjectEntry {.key = "executable", .value = rule_engine::Value::boolean(true)},
            }),
        }),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {30},
    });
    cache.store(rule_engine::Fact {
        .subject_id = "pid:2",
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

    cache.expire_volatile();

    CHECK_FALSE(cache.lookup("pid:2", "process.memory.regions.count").has_value());
    REQUIRE(cache.lookup("pid:2", "pe.sections").has_value());
    REQUIRE(cache.lookup("pid:2", "pe.imports").has_value());
    CHECK(cache.lookup("pid:2", "pe.sections")->value.as_array()->values.size() == 1u);
    CHECK(cache.lookup("pid:2", "pe.imports")->value.as_array()->values.size() == 1u);
}
