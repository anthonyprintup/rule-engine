#pragma once

#include <rule_engine/evaluator.hpp>

#include <cstddef>
#include <expected>
#include <span>
#include <vector>

namespace rule_engine {
    struct EvaluationTrace {
        Subject subject;
        std::vector<Fact> facts;
        EvaluationStep final_step;
    };

    [[nodiscard]] EvaluationTrace capture_evaluation_trace(const VerifiedProgram &program,
                                                           const Subject &subject,
                                                           const FactCache &facts);
    [[nodiscard]] std::expected<std::vector<std::byte>, ErrorSet>
    encode_evaluation_trace(const EvaluationTrace &trace);
    [[nodiscard]] std::expected<EvaluationTrace, ErrorSet> decode_evaluation_trace(std::span<const std::byte> artifact);
    [[nodiscard]] std::expected<EvaluationStep, ErrorSet> replay_evaluation_trace(const VerifiedProgram &program,
                                                                                  const EvaluationTrace &trace);
} // namespace rule_engine
