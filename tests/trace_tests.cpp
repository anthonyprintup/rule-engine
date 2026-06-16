#include <rule_engine/compiler.hpp>
#include <rule_engine/evaluator.hpp>
#include <rule_engine/modules.hpp>
#include <rule_engine/trace.hpp>

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string_view>
#include <vector>

namespace {
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
        for (const auto ch : value) {
            out.push_back(static_cast<std::byte>(static_cast<unsigned char>(ch)));
        }
    }

    void append_bytes(std::vector<std::byte> &out, const std::vector<std::byte> &value) {
        append_u32(out, static_cast<std::uint32_t>(value.size()));
        out.insert(out.end(), value.begin(), value.end());
    }

    [[nodiscard]] std::vector<std::byte> empty_trace_fact_payload() {
        std::vector<std::byte> out;
        out.push_back(static_cast<std::byte>('R'));
        out.push_back(static_cast<std::byte>('E'));
        out.push_back(static_cast<std::byte>('P'));
        out.push_back(static_cast<std::byte>('V'));
        append_u8(out, 4u);
        append_u32(out, 1u);
        append_string(out, "trace.facts");
        append_u32(out, 0u);
        return out;
    }
} // namespace

TEST_CASE("evaluation traces serialize and replay decisions without provider access") {
    constexpr std::string_view source = R"(
import "process"

rule traced_rule {
    strings:
        $enc = "-enc" ascii
    condition:
        process.name == "powershell.exe" and $enc
}
)";

    auto parsed = rule_engine::parse_source("trace.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());

    const rule_engine::Subject subject {.kind = "process", .id = "pid:42"};
    rule_engine::FactCache facts;
    facts.store(rule_engine::Fact {
        .subject_id = subject.id,
        .key = "process.name",
        .value = rule_engine::Value::string("powershell.exe"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
    });
    facts.store(rule_engine::Fact {
        .subject_id = subject.id,
        .key = "$enc.matches",
        .value = rule_engine::Value::boolean(true),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
    });

    const auto trace = rule_engine::capture_evaluation_trace(*verified, subject, facts);
    REQUIRE(trace.final_step.state == rule_engine::EvaluationState::complete);
    REQUIRE(trace.final_step.rule_results.size() == 1u);
    CHECK(trace.final_step.rule_results[0].matched);
    CHECK(trace.facts.size() == 2u);
    REQUIRE_FALSE(trace.final_step.expression_traces.empty());
    CHECK(trace.final_step.expression_traces[0].rule_identifier == "traced_rule");
    CHECK(trace.final_step.expression_traces[0].status == rule_engine::ExpressionTraceStatus::value);
    CHECK(trace.final_step.expression_traces[0].value_summary == "bool:true");

    rule_engine::Evaluator evaluator {*verified, facts};
    const auto untraced_step = evaluator.step(subject);
    CHECK(untraced_step.expression_traces.empty());

    const auto encoded = rule_engine::encode_evaluation_trace(trace);
    REQUIRE(encoded.has_value());
    REQUIRE(encoded->size() > 8u);
    CHECK(std::string_view {reinterpret_cast<const char *>(encoded->data()), 4u} == "RETR");

    const auto decoded = rule_engine::decode_evaluation_trace(*encoded);
    REQUIRE(decoded.has_value());
    CHECK(decoded->subject.id == subject.id);
    CHECK(decoded->facts.size() == 2u);
    REQUIRE(decoded->final_step.expression_traces.size() == trace.final_step.expression_traces.size());
    CHECK(decoded->final_step.expression_traces[0].rule_identifier == "traced_rule");
    CHECK(decoded->final_step.expression_traces[0].value_summary == "bool:true");

    const auto replayed = rule_engine::replay_evaluation_trace(*verified, *decoded);
    REQUIRE(replayed.has_value());
    CHECK(replayed->state == rule_engine::EvaluationState::complete);
    REQUIRE(replayed->rule_results.size() == trace.final_step.rule_results.size());
    CHECK(replayed->rule_results[0].identifier == trace.final_step.rule_results[0].identifier);
    CHECK(replayed->rule_results[0].matched == trace.final_step.rule_results[0].matched);
}

TEST_CASE("trace decoder rejects oversized counts before reading entries") {
    std::vector<std::byte> artifact;
    artifact.push_back(static_cast<std::byte>('R'));
    artifact.push_back(static_cast<std::byte>('E'));
    artifact.push_back(static_cast<std::byte>('T'));
    artifact.push_back(static_cast<std::byte>('R'));
    append_u32(artifact, 2u);
    append_string(artifact, "process");
    append_string(artifact, "pid:1");
    append_bytes(artifact, empty_trace_fact_payload());
    append_u8(artifact, 1u);
    append_u32(artifact, 100000u);

    const auto decoded = rule_engine::decode_evaluation_trace(artifact);
    REQUIRE_FALSE(decoded.has_value());
    REQUIRE_FALSE(decoded.error().diagnostics.empty());
    CHECK(decoded.error().diagnostics[0].message.find("count exceeds") != std::string::npos);
}
