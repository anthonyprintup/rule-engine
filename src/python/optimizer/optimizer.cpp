#include "rule_engine/python/optimizer/optimizer.hpp"

#include <algorithm>
#include <cstddef>
#include <span>
#include <string_view>
#include <utility>

namespace rule_engine::python::optimizer {
    namespace {

        [[nodiscard]] OptimizerError make_error(const OptimizerErrorCode code, const ExecutableId &executable,
                                                std::string_view message) {
            return OptimizerError {
                .code = code,
                .executable = executable,
                .message = std::string {message},
            };
        }

        [[nodiscard]] OptimizationSelection exact_selection(const OptimizationRequest &request,
                                                            const ExactFallbackReason reason,
                                                            const bool certificate_known = false,
                                                            const bool certificate_validated = false) {
            return OptimizationSelection {
                .executable = request.executable,
                .use_exact_bytecode = true,
                .certificate_known = certificate_known,
                .certificate_validated = certificate_validated,
                .specialization_enabled = false,
                .pruning_enabled = false,
                .fallback_reason = reason,
                .prunable_false_prefix_exits = {},
            };
        }

        [[nodiscard]] std::optional<ExactFallbackReason>
        unsafe_certificate_reason(const OptimizationCertificate &certificate,
                                  const OptimizationRequest &request) noexcept {
            if (request.full_flight_recorder_armed) {
                return ExactFallbackReason::recorder_policy_requires_exact;
            }
            if (certificate.recorder_observable) {
                return ExactFallbackReason::certificate_recorder_observable;
            }
            if (certificate.reads_state) {
                return ExactFallbackReason::certificate_reads_state;
            }
            if (certificate.reads_history) {
                return ExactFallbackReason::certificate_reads_history;
            }
            if (certificate.calls_services) {
                return ExactFallbackReason::certificate_calls_services;
            }
            if (certificate.emits_effects) {
                return ExactFallbackReason::certificate_emits_effects;
            }
            if (certificate.may_fault) {
                return ExactFallbackReason::certificate_may_fault;
            }
            if (!certificate.logical_facts.empty()) {
                return ExactFallbackReason::certificate_has_logical_reads;
            }
            if (!certificate.transitively_pure) {
                return ExactFallbackReason::certificate_not_transitively_pure;
            }
            return std::nullopt;
        }

        [[nodiscard]] bool same_frozen_value(const FrozenValue &left, const FrozenValue &right) noexcept {
            return left.canonical_digest == right.canonical_digest && left.label == right.label;
        }

        [[nodiscard]] bool same_logical_read(const LogicalReadObservation &left,
                                             const LogicalReadObservation &right) noexcept {
            return left.sequence == right.sequence && left.subject_key_digest == right.subject_key_digest &&
                   left.route.provider == right.route.provider && left.route.fact == right.route.fact &&
                   left.schema == right.schema && left.status == right.status && left.span == right.span &&
                   left.label == right.label && left.value_digest == right.value_digest;
        }

        [[nodiscard]] bool same_fact_read(const FactReadObservation &left, const FactReadObservation &right) noexcept {
            return left.sequence == right.sequence && left.subject_key_digest == right.subject_key_digest &&
                   left.route.provider == right.route.provider && left.route.fact == right.route.fact &&
                   left.schema == right.schema && left.status == right.status && left.label == right.label &&
                   left.value_digest == right.value_digest;
        }

        [[nodiscard]] bool same_policy(const EffectPolicySnapshot &left, const EffectPolicySnapshot &right) noexcept {
            return left.policy_id == right.policy_id && left.policy_digest == right.policy_digest &&
                   left.sink_ceiling == right.sink_ceiling && left.dry_run == right.dry_run;
        }

        [[nodiscard]] bool same_effect(const EffectIntent &left, const EffectIntent &right) noexcept {
            return left.id == right.id && left.invocation == right.invocation && left.owner == right.owner &&
                   left.binding == right.binding && left.sequence == right.sequence && left.kind == right.kind &&
                   same_frozen_value(left.payload, right.payload) && left.span == right.span &&
                   same_policy(left.policy, right.policy) && left.disposition == right.disposition &&
                   left.idempotency_key == right.idempotency_key;
        }

        [[nodiscard]] bool same_optional_frozen_value(const std::optional<FrozenValue> &left,
                                                      const std::optional<FrozenValue> &right) noexcept {
            if (left.has_value() != right.has_value()) {
                return false;
            }
            return !left.has_value() || same_frozen_value(*left, *right);
        }

        [[nodiscard]] bool same_state(const StateMutation &left, const StateMutation &right) noexcept {
            return left.owner == right.owner && left.namespace_name == right.namespace_name && left.key == right.key &&
                   left.expected_version == right.expected_version &&
                   same_optional_frozen_value(left.value, right.value);
        }

        [[nodiscard]] bool same_recorder_event(const RecorderEvent &left, const RecorderEvent &right) noexcept {
            // The summary participates in parity but is never copied into the report.
            return left.sequence == right.sequence && left.kind == right.kind && left.span == right.span &&
                   left.label == right.label && left.summary == right.summary;
        }

        [[nodiscard]] bool same_fault_frame(const FaultFrame &left, const FaultFrame &right) noexcept {
            // The message participates in parity but is never copied into the report.
            return left.code == right.code && left.message == right.message && left.executable == right.executable &&
                   left.span == right.span;
        }

        [[nodiscard]] bool same_fault(const std::optional<FaultChain> &left,
                                      const std::optional<FaultChain> &right) noexcept {
            if (left.has_value() != right.has_value()) {
                return false;
            }
            if (!left.has_value()) {
                return true;
            }
            return left->double_fault == right->double_fault && left->triple_fault == right->triple_fault &&
                   left->frames.size() == right->frames.size() &&
                   std::ranges::equal(left->frames, right->frames, same_fault_frame);
        }

        [[nodiscard]] bool same_related_diagnostic(const RelatedDiagnostic &left,
                                                   const RelatedDiagnostic &right) noexcept {
            return left.span == right.span && left.message == right.message;
        }

        [[nodiscard]] bool same_diagnostic(const Diagnostic &left, const Diagnostic &right) noexcept {
            return left.code == right.code && left.severity == right.severity && left.message == right.message &&
                   left.span == right.span && left.related.size() == right.related.size() &&
                   std::ranges::equal(left.related, right.related, same_related_diagnostic);
        }

        template<typename Left, typename Right, typename Predicate>
        [[nodiscard]] std::optional<std::size_t> first_difference(const std::span<const Left> exact,
                                                                  const std::span<const Right> optimized,
                                                                  Predicate predicate) {
            const auto common_size = std::min(exact.size(), optimized.size());
            for (std::size_t index = 0; index < common_size; ++index) {
                if (!predicate(exact[index], optimized[index])) {
                    return index;
                }
            }
            if (exact.size() != optimized.size()) {
                return common_size;
            }
            return std::nullopt;
        }

        void add_mismatch(ShadowParityReport &report, const ShadowParityLimits limits,
                          RedactedShadowMismatch mismatch) {
            ++report.mismatch_dimension_count;
            report.equivalent = false;
            report.disable_optimized_executable = true;

            const auto record_limit = std::min(limits.maximum_mismatch_records, maximum_shadow_mismatch_records);
            if (report.mismatches.size() >= record_limit) {
                report.mismatch_data_truncated = true;
                return;
            }
            report.mismatches.push_back(std::move(mismatch));
        }

    } // namespace

    std::expected<void, OptimizerError> validate_optimization_certificate(
        const OptimizationCertificate &certificate, const ExecutableId &expected_executable,
        const std::string_view expected_executable_semantic_hash, const std::uint32_t exact_instruction_count) {
        if (expected_executable.empty() || expected_executable_semantic_hash.empty() || exact_instruction_count == 0) {
            return std::unexpected(make_error(OptimizerErrorCode::invalid_request, expected_executable,
                                              "optimizer certificate validation requires executable identity, semantic "
                                              "hash, and exact instruction count"));
        }
        if (certificate.executable != expected_executable) {
            return std::unexpected(make_error(OptimizerErrorCode::certificate_executable_mismatch, expected_executable,
                                              "optimizer certificate is bound to a different executable"));
        }
        if (certificate.semantic_hash != expected_executable_semantic_hash) {
            return std::unexpected(make_error(OptimizerErrorCode::certificate_semantic_hash_mismatch,
                                              expected_executable,
                                              "optimizer certificate semantic hash does not match executable"));
        }
        if (!std::ranges::is_sorted(certificate.logical_facts) ||
            std::ranges::adjacent_find(certificate.logical_facts) != certificate.logical_facts.end() ||
            std::ranges::any_of(certificate.logical_facts, &std::string::empty)) {
            return std::unexpected(make_error(OptimizerErrorCode::noncanonical_certificate, expected_executable,
                                              "optimizer certificate logical fact routes are not canonical"));
        }
        if (!std::ranges::is_sorted(certificate.pure_false_prefix_exits) ||
            std::ranges::adjacent_find(certificate.pure_false_prefix_exits) !=
                certificate.pure_false_prefix_exits.end() ||
            std::ranges::any_of(certificate.pure_false_prefix_exits,
                                [](const std::uint32_t exit) { return exit == 0; })) {
            return std::unexpected(make_error(OptimizerErrorCode::noncanonical_certificate, expected_executable,
                                              "optimizer certificate pure-prefix exits are not canonical"));
        }
        if (std::ranges::any_of(
                certificate.pure_false_prefix_exits,
                [exact_instruction_count](const std::uint32_t exit) { return exit >= exact_instruction_count; })) {
            return std::unexpected(make_error(OptimizerErrorCode::certificate_prefix_out_of_bounds, expected_executable,
                                              "optimizer certificate pure-prefix exit is outside exact bytecode"));
        }
        return {};
    }

    std::expected<OptimizationSelection, OptimizerError>
    select_optimization(const std::span<const OptimizationCertificate> certificates,
                        const OptimizationRequest &request) {
        if (request.executable.empty() || request.expected_executable_semantic_hash.empty() ||
            request.exact_instruction_count == 0) {
            return std::unexpected(make_error(
                OptimizerErrorCode::invalid_request, request.executable,
                "optimizer selection requires executable identity, semantic hash, and exact instruction count"));
        }

        const OptimizationCertificate *certificate = nullptr;
        for (const auto &candidate : certificates) {
            if (candidate.executable != request.executable) {
                continue;
            }
            if (certificate != nullptr) {
                return exact_selection(request, ExactFallbackReason::duplicate_certificate, true, false);
            }
            certificate = &candidate;
        }

        if (certificate == nullptr) {
            return exact_selection(request, ExactFallbackReason::certificate_missing);
        }

        const auto validation = validate_optimization_certificate(*certificate, request.executable,
                                                                  request.expected_executable_semantic_hash,
                                                                  request.exact_instruction_count);
        if (!validation.has_value()) {
            if (validation.error().code == OptimizerErrorCode::certificate_semantic_hash_mismatch) {
                return exact_selection(request, ExactFallbackReason::certificate_semantic_hash_mismatch, true, false);
            }
            if (validation.error().code == OptimizerErrorCode::contradictory_certificate) {
                return exact_selection(request, ExactFallbackReason::contradictory_certificate, true, false);
            }
            if (validation.error().code == OptimizerErrorCode::noncanonical_certificate) {
                return exact_selection(request, ExactFallbackReason::certificate_noncanonical, true, false);
            }
            if (validation.error().code == OptimizerErrorCode::certificate_prefix_out_of_bounds) {
                return exact_selection(request, ExactFallbackReason::certificate_prefix_out_of_bounds, true, false);
            }
            return exact_selection(request, ExactFallbackReason::certificate_missing, true, false);
        }

        if (!request.request_specialization && !request.request_pruning) {
            return exact_selection(request, ExactFallbackReason::no_transform_requested, true, true);
        }
        if (const auto unsafe = unsafe_certificate_reason(*certificate, request); unsafe.has_value()) {
            return exact_selection(request, *unsafe, true, true);
        }
        if (certificate->pure_false_prefix_exits.empty()) {
            return exact_selection(request, ExactFallbackReason::certificate_has_no_pure_prefix, true, true);
        }

        const auto pruning_enabled = request.request_pruning;
        const auto specialization_enabled = request.request_specialization;
        if (!pruning_enabled && !specialization_enabled) {
            return exact_selection(request, ExactFallbackReason::no_applicable_transform, true, true);
        }

        return OptimizationSelection {
            .executable = request.executable,
            .use_exact_bytecode = false,
            .certificate_known = true,
            .certificate_validated = true,
            .specialization_enabled = specialization_enabled,
            .pruning_enabled = pruning_enabled,
            .fallback_reason = ExactFallbackReason::none,
            .prunable_false_prefix_exits =
                pruning_enabled ? certificate->pure_false_prefix_exits : std::vector<std::uint32_t> {},
        };
    }

    ShadowParityReport compare_shadow_execution(const ShadowExecutionSnapshot &exact,
                                                const ShadowExecutionSnapshot &optimized,
                                                const ShadowParityLimits limits) {
        ShadowParityReport report;

        if (exact.evaluation.outcome != optimized.evaluation.outcome) {
            add_mismatch(report, limits,
                         RedactedShadowMismatch {
                             .dimension = ShadowParityDimension::outcome,
                             .exact_count = 1,
                             .optimized_count = 1,
                             .first_difference_index = 0,
                         });
        }
        if (exact.evaluation.verdict != optimized.evaluation.verdict) {
            add_mismatch(report, limits,
                         RedactedShadowMismatch {
                             .dimension = ShadowParityDimension::verdict,
                             .exact_count = exact.evaluation.verdict.has_value() ? 1u : 0u,
                             .optimized_count = optimized.evaluation.verdict.has_value() ? 1u : 0u,
                             .first_difference_index = 0,
                         });
        }

        if (const auto difference =
                first_difference(std::span {exact.fact_reads}, std::span {optimized.fact_reads}, same_fact_read);
            difference.has_value()) {
            add_mismatch(report, limits,
                         RedactedShadowMismatch {
                             .dimension = ShadowParityDimension::fact_reads,
                             .exact_count = exact.fact_reads.size(),
                             .optimized_count = optimized.fact_reads.size(),
                             .first_difference_index = difference,
                         });
        }
        if (const auto difference = first_difference(std::span {exact.logical_reads},
                                                     std::span {optimized.logical_reads}, same_logical_read);
            difference.has_value()) {
            add_mismatch(report, limits,
                         RedactedShadowMismatch {
                             .dimension = ShadowParityDimension::logical_reads,
                             .exact_count = exact.logical_reads.size(),
                             .optimized_count = optimized.logical_reads.size(),
                             .first_difference_index = difference,
                         });
        }
        if (const auto difference = first_difference(std::span {exact.evaluation.committed_effects},
                                                     std::span {optimized.evaluation.committed_effects}, same_effect);
            difference.has_value()) {
            add_mismatch(report, limits,
                         RedactedShadowMismatch {
                             .dimension = ShadowParityDimension::ordered_effects,
                             .exact_count = exact.evaluation.committed_effects.size(),
                             .optimized_count = optimized.evaluation.committed_effects.size(),
                             .first_difference_index = difference,
                         });
        }
        if (const auto difference = first_difference(std::span {exact.evaluation.state_mutations},
                                                     std::span {optimized.evaluation.state_mutations}, same_state);
            difference.has_value()) {
            add_mismatch(report, limits,
                         RedactedShadowMismatch {
                             .dimension = ShadowParityDimension::state,
                             .exact_count = exact.evaluation.state_mutations.size(),
                             .optimized_count = optimized.evaluation.state_mutations.size(),
                             .first_difference_index = difference,
                         });
        }
        if (const auto difference =
                first_difference(std::span {exact.recorder}, std::span {optimized.recorder}, same_recorder_event);
            difference.has_value()) {
            add_mismatch(report, limits,
                         RedactedShadowMismatch {
                             .dimension = ShadowParityDimension::recorder,
                             .exact_count = exact.recorder.size(),
                             .optimized_count = optimized.recorder.size(),
                             .first_difference_index = difference,
                         });
        }
        if (!same_fault(exact.evaluation.fault, optimized.evaluation.fault)) {
            add_mismatch(
                report, limits,
                RedactedShadowMismatch {
                    .dimension = ShadowParityDimension::fault,
                    .exact_count = exact.evaluation.fault.has_value() ? exact.evaluation.fault->frames.size() : 0u,
                    .optimized_count =
                        optimized.evaluation.fault.has_value() ? optimized.evaluation.fault->frames.size() : 0u,
                    .first_difference_index = 0,
                });
        }
        if (exact.resources != optimized.resources) {
            add_mismatch(report, limits,
                         RedactedShadowMismatch {
                             .dimension = ShadowParityDimension::budgets,
                             .exact_count = 1,
                             .optimized_count = 1,
                             .first_difference_index = 0,
                         });
        }
        if (const auto difference =
                first_difference(std::span {exact.diagnostics}, std::span {optimized.diagnostics}, same_diagnostic);
            difference.has_value()) {
            add_mismatch(report, limits,
                         RedactedShadowMismatch {
                             .dimension = ShadowParityDimension::diagnostics,
                             .exact_count = exact.diagnostics.size(),
                             .optimized_count = optimized.diagnostics.size(),
                             .first_difference_index = difference,
                         });
        }

        return report;
    }

} // namespace rule_engine::python::optimizer
