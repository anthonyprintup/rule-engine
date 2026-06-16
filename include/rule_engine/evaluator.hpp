#pragma once

#include <rule_engine/compiler.hpp>
#include <rule_engine/value.hpp>

#include <chrono>
#include <optional>
#include <string>
#include <vector>

namespace rule_engine {
    struct Subject {
        std::string kind;
        std::string id;
    };

    enum struct FactStatus {
        missing,
        available,
        unavailable,
        access_denied,
        timed_out,
    };

    struct Fact {
        std::string subject_id;
        std::string key;
        Value value;
        FactStatus status {FactStatus::missing};
        std::string diagnostic;
        std::chrono::seconds ttl {};
    };

    struct FactRequestBatch {
        std::string route;
        std::vector<std::string> keys;
        std::vector<ValueType> types;
        std::chrono::seconds timeout {5};
    };

    struct RuleResult {
        std::string identifier;
        bool matched {};
        std::vector<Diagnostic> diagnostics;
    };

    enum struct ExpressionTraceStatus {
        value,
        missing,
        diagnostic,
    };

    struct ExpressionTraceEvent {
        std::string rule_identifier;
        ExpressionKind expression_kind {ExpressionKind::unsupported};
        SourceSpan span {};
        std::string text;
        ExpressionTraceStatus status {ExpressionTraceStatus::value};
        std::string value_summary;
        std::string detail;
    };

    enum struct EvaluationState {
        waiting_for_facts,
        complete,
    };

    struct EvaluationStep {
        EvaluationState state {EvaluationState::complete};
        std::vector<FactRequestBatch> requests;
        std::vector<RuleResult> rule_results;
        std::vector<ExpressionTraceEvent> expression_traces;
    };

    struct EvaluationOptions {
        bool trace_expressions {};
    };

    struct FactCache {
        void store(Fact fact);
        [[nodiscard]] std::optional<Fact> lookup(std::string_view subject_id, std::string_view key) const;
        [[nodiscard]] std::vector<Fact> snapshot_for_subject(std::string_view subject_id) const;
        void expire_volatile();

    private:
        std::vector<Fact> facts_;
    };

    struct Evaluator {
        Evaluator(const VerifiedProgram &program,
                  const FactCache &facts,
                  EvaluationOptions options = {}) noexcept:
            program_ {program},
            facts_ {facts},
            options_ {options} {}

        [[nodiscard]] EvaluationStep step(const Subject &subject) const;

    private:
        const VerifiedProgram &program_;
        const FactCache &facts_;
        EvaluationOptions options_;
    };
} // namespace rule_engine
