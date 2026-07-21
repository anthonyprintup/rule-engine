#pragma once

#include "rule_engine/python/contract/compiler.hpp"
#include "rule_engine/python/contract/runtime.hpp"

#include <compare>
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
        noncanonical_certificate,
        certificate_prefix_out_of_bounds,
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
        certificate_noncanonical,
        certificate_prefix_out_of_bounds,
        certificate_not_transitively_pure,
        certificate_may_fault,
        certificate_recorder_observable,
        recorder_policy_requires_exact,
        certificate_reads_state,
        certificate_reads_history,
        certificate_calls_services,
        certificate_emits_effects,
        certificate_has_logical_reads,
        certificate_has_no_pure_prefix,
        no_transform_requested,
        no_applicable_transform,
    };

    struct OptimizationRequest {
        ExecutableId executable;
        std::string expected_executable_semantic_hash;
        bool request_specialization {true};
        bool request_pruning {true};
        bool full_flight_recorder_armed {};
        // Binds certified prefix exits to the exact verified bytecode body.
        std::uint32_t exact_instruction_count {};
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
    [[nodiscard]] std::expected<void, OptimizerError> validate_optimization_certificate(
        const OptimizationCertificate &certificate, const ExecutableId &expected_executable,
        std::string_view expected_executable_semantic_hash, std::uint32_t exact_instruction_count);

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

    // Reached provider results are distinct from tentative physical prefetch.
    // Only results made visible at a VM logical-read boundary belong here.
    struct FactReadObservation {
        std::uint64_t sequence {};
        std::string subject_key_digest;
        FactRoute route;
        SchemaId schema;
        FactTerminalStatus status {FactTerminalStatus::failed};
        DataLabel label;
        std::string value_digest;
    };

    struct SemanticResourceCounters {
        std::uint64_t instructions {};
        std::uint64_t peak_frames {};
        std::uint64_t peak_heap_bytes {};
        std::uint64_t loop_iterations_and_yields {};
        std::uint64_t allocation_work {};
        std::uint64_t logical_facts {};
        std::uint64_t provider_rounds {};
        std::uint64_t fact_bytes {};
        std::uint64_t service_calls {};
        std::uint64_t peak_active_service_calls {};
        std::uint64_t service_response_bytes {};
        std::uint64_t history_queries {};
        std::uint64_t history_rows {};
        std::uint64_t history_bytes {};
        std::uint64_t state_keys {};
        std::uint64_t state_bytes {};
        std::uint64_t effect_intents {};
        std::uint64_t effect_bytes {};
        std::uint64_t recorder_events {};
        std::uint64_t recorder_bytes {};

        auto operator<=>(const SemanticResourceCounters &) const = default;
    };

    struct ShadowExecutionSnapshot {
        EvaluationResult evaluation;
        std::vector<FactReadObservation> fact_reads;
        std::vector<LogicalReadObservation> logical_reads;
        std::vector<RecorderEvent> recorder;
        SemanticResourceCounters resources;
        DiagnosticSet diagnostics;
    };

    enum struct ShadowParityDimension : std::uint8_t {
        outcome,
        verdict,
        fact_reads,
        logical_reads,
        ordered_effects,
        state,
        recorder,
        fault,
        budgets,
        diagnostics,
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

    inline constexpr std::size_t maximum_shadow_mismatch_records = 12;

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
