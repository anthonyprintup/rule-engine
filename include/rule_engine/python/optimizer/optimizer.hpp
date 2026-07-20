#pragma once

#include "rule_engine/python/contract/compiler.hpp"
#include "rule_engine/python/contract/runtime.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace rule_engine::python::optimizer {

    enum struct OptimizerErrorCode : std::uint8_t {
        invalid_request,
        duplicate_certificate,
        certificate_executable_mismatch,
        certificate_semantic_hash_mismatch,
        contradictory_certificate,
    };

    struct OptimizerError {
        OptimizerErrorCode code {OptimizerErrorCode::invalid_request};
        ExecutableId executable;
        std::string message;
    };

    enum struct ExactFallbackReason : std::uint8_t {
        none,
        certificate_missing,
        duplicate_certificate,
        certificate_semantic_hash_mismatch,
        contradictory_certificate,
        certificate_not_transitively_pure,
        certificate_may_fault,
        certificate_recorder_observable,
        recorder_policy_requires_exact,
        certificate_reads_state,
        certificate_reads_history,
        certificate_calls_services,
        certificate_emits_effects,
        certificate_has_logical_reads,
        no_transform_requested,
        no_applicable_transform,
    };

    struct OptimizationRequest {
        ExecutableId executable;
        std::string expected_executable_semantic_hash;
        bool request_specialization {true};
        bool request_pruning {true};
        bool full_flight_recorder_armed {};
    };

    struct OptimizationSelection {
        ExecutableId executable;
        bool use_exact_bytecode {true};
        bool certificate_known {};
        bool certificate_validated {};
        bool specialization_enabled {};
        bool pruning_enabled {};
        ExactFallbackReason fallback_reason {ExactFallbackReason::certificate_missing};
        std::vector<std::uint32_t> prunable_false_prefix_exits;
    };

    // A certificate is bound to both an executable and its platform-independent
    // semantic hash. A mismatch is an activation error, not an optimization miss.
    [[nodiscard]] std::expected<void, OptimizerError>
    validate_optimization_certificate(const OptimizationCertificate &certificate,
                                      const ExecutableId &expected_executable,
                                      std::string_view expected_executable_semantic_hash);

    // Missing, inconsistent, or conservatively unsafe evidence selects exact
    // bytecode. Only a malformed caller request fails selection.
    [[nodiscard]] std::expected<OptimizationSelection, OptimizerError>
    select_optimization(std::span<const OptimizationCertificate> certificates, const OptimizationRequest &request);

    struct LogicalReadObservation {
        std::uint64_t sequence {};
        std::string subject_key_digest;
        FactRoute route;
        SchemaId schema;
        FactTerminalStatus status {FactTerminalStatus::failed};
        SourceSpan span;
        DataLabel label;
        std::string value_digest;
    };

    struct ShadowExecutionSnapshot {
        EvaluationOutcome outcome {EvaluationOutcome::faulted};
        std::optional<bool> verdict;
        std::vector<LogicalReadObservation> logical_reads;
        std::vector<EffectIntent> ordered_effects;
        std::vector<StateMutation> ordered_state;
        std::vector<RecorderEvent> recorder;
        std::optional<FaultChain> fault;
    };

    enum struct ShadowParityDimension : std::uint8_t {
        outcome,
        verdict,
        logical_reads,
        ordered_effects,
        state,
        recorder,
        fault,
    };

    // This deliberately contains no compared values. Counts and an optional
    // sequence index are sufficient to locate captured evidence without leaking
    // fact values, effect/state payloads, recorder summaries, or fault messages.
    struct RedactedShadowMismatch {
        ShadowParityDimension dimension {ShadowParityDimension::outcome};
        std::size_t exact_count {};
        std::size_t optimized_count {};
        std::optional<std::size_t> first_difference_index;
    };

    inline constexpr std::size_t maximum_shadow_mismatch_records = 7;

    struct ShadowParityLimits {
        std::size_t maximum_mismatch_records {maximum_shadow_mismatch_records};
    };

    struct ShadowParityReport {
        bool equivalent {true};
        bool exact_result_is_only_committable {true};
        bool disable_optimized_executable {};
        std::size_t mismatch_dimension_count {};
        bool mismatch_data_truncated {};
        std::vector<RedactedShadowMismatch> mismatches;
    };

    [[nodiscard]] ShadowParityReport compare_shadow_execution(const ShadowExecutionSnapshot &exact,
                                                              const ShadowExecutionSnapshot &optimized,
                                                              ShadowParityLimits limits = {});

} // namespace rule_engine::python::optimizer
