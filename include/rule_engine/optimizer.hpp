#pragma once

#include <rule_engine/compiler.hpp>
#include <rule_engine/evaluator.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace rule_engine::protocol {
    struct CandidateProviderSubjectSet;
}

namespace rule_engine::optimizer {
    struct CanonicalPredicateOwner {
        std::string rule_identifier;
        SourceSpan span {};
        bool prune_safe {};
    };

    struct CanonicalPredicate {
        std::string id;
        std::string fact_key;
        std::string route;
        FactCostClass cost_class {FactCostClass::custom};
        std::string operation;
        std::string literal_kind;
        std::string literal_value;
        std::vector<CanonicalPredicateOwner> owners;
    };

    struct ExactVmOnlyExpression {
        std::string rule_identifier;
        std::string reason;
        ExpressionKind expression_kind {ExpressionKind::unsupported};
        SourceSpan span {};
    };

    struct CanonicalPredicateReport {
        std::vector<CanonicalPredicate> predicates;
        std::vector<ExactVmOnlyExpression> exact_vm_only;
    };

    struct PredicateSubjectReason {
        std::string subject_id;
        std::string reason;
    };

    struct PredicateNodeSimulation {
        std::string predicate_id;
        FactCostClass cost_class {FactCostClass::custom};
        std::uint64_t observed_selectivity_ppm {};
        std::uint64_t matched_subject_count {};
        bool nonselective {};
        bool retained_matched_subjects {true};
        std::vector<std::string> matched_subject_ids;
        std::vector<PredicateSubjectReason> pruned_subjects;
        std::vector<PredicateSubjectReason> unknown_subjects;
    };

    struct PredicateSelectivityObservation {
        std::string predicate_id;
        std::uint64_t observed_selectivity_ppm {};
        std::uint64_t matched_subject_count {};
    };

    struct PredicateSelectivityProfile {
        std::vector<PredicateSelectivityObservation> predicates;
    };

    struct RulePrunedSubject {
        std::string subject_id;
        std::string predicate_id;
        std::string reason;
    };

    enum struct CandidateSetRepresentation {
        dense_bitset,
        sparse_ids,
    };

    struct RuleCandidateSet {
        std::string rule_identifier;
        std::vector<std::string> candidate_subject_ids;
        std::vector<RulePrunedSubject> pruned_subjects;
        CandidateSetRepresentation representation {CandidateSetRepresentation::dense_bitset};
        std::uint64_t candidate_set_bytes {};
        bool dropped {};
    };

    struct OptimizerTraceEvent {
        std::string event;
        std::string predicate_id;
        std::string rule_identifier;
        std::string subject_id;
        std::string reason;
        FactCostClass cost_class {FactCostClass::custom};
        SourceSpan span {};
        std::uint64_t matched_subject_count {};
        std::uint64_t candidate_subject_count {};
        std::uint64_t candidate_set_bytes {};
    };

    struct SharedPredicateDagSimulation {
        std::vector<std::string> predicate_order;
        std::vector<PredicateNodeSimulation> predicate_nodes;
        std::vector<RuleCandidateSet> rule_candidates;
        std::vector<OptimizerTraceEvent> trace_events;
        std::uint64_t predicate_evaluations {};
        std::uint64_t pruned_rule_subjects {};
        std::uint64_t dropped_rule_branches {};
        std::size_t peak_candidate_set_subjects {};
        std::uint64_t peak_candidate_set_bytes {};
    };

    struct DiscoveryGate {
        std::string predicate_id;
        std::string fact_key;
        std::string route;
        FactCostClass cost_class {FactCostClass::custom};
        std::string operation;
        std::string literal_kind;
        std::string literal_value;
        SourceSpan span {};
        std::vector<std::string> rule_identifiers;
    };

    struct DiscoveryGatePlan {
        std::vector<DiscoveryGate> gates;
    };

    struct DiscoveryGateResult {
        DiscoveryGate gate;
        std::vector<std::string> matched_subject_ids;
        std::vector<PredicateSubjectReason> rejected_subjects;
        std::vector<PredicateSubjectReason> unknown_subjects;
        bool pack_skipped {};
        std::string reason;
    };

    struct DiscoveryGateSimulation {
        DiscoveryGatePlan plan;
        std::vector<DiscoveryGateResult> gate_results;
        std::vector<OptimizerTraceEvent> trace_events;
        std::uint64_t gate_evaluations {};
        bool pack_skipped {};
        std::string skip_reason;
    };

    struct LazyProviderExpansionRequest {
        std::string route;
        std::string key;
        ValueType type {ValueType::undefined};
        bool cheap_prefetch {};
        std::vector<std::string> subject_ids;
        std::vector<std::string> avoided_subject_ids;
        std::vector<std::string> rule_identifiers;
    };

    struct LazyProviderExpansionPlan {
        std::vector<LazyProviderExpansionRequest> requests;
        std::uint64_t provider_batches {};
        std::uint64_t facts_requested {};
        std::uint64_t facts_avoided {};
        std::uint64_t expensive_facts_requested {};
        std::uint64_t expensive_facts_avoided {};
    };

    enum struct WatchdogBudgetAction {
        trace_only,
        defer_branch,
        substitute_gate,
        timeout_branch,
        unavailable_branch,
    };

    struct WatchdogBudgetPolicy {
        std::uint64_t low_selectivity_budget_ppm {900000};
        std::uint64_t route_request_budget {16};
        WatchdogBudgetAction predicate_budget_action {WatchdogBudgetAction::trace_only};
        WatchdogBudgetAction route_budget_action {WatchdogBudgetAction::trace_only};
    };

    struct WatchdogBudgetDiagnostic {
        WatchdogBudgetAction action {WatchdogBudgetAction::trace_only};
        std::string predicate_id;
        std::string route;
        std::string key;
        Diagnostic diagnostic;
        std::uint64_t affected_subject_count {};
    };

    struct WatchdogBudgetSimulation {
        std::vector<OptimizerTraceEvent> trace_events;
        std::vector<WatchdogBudgetDiagnostic> budget_diagnostics;
        std::uint64_t evaluations {};
        std::uint64_t budget_events {};
        std::uint64_t predicate_budget_events {};
        std::uint64_t route_budget_events {};
        std::uint64_t explicit_budget_diagnostics {};
        std::uint64_t deferred_branch_diagnostics {};
        std::uint64_t substituted_gate_diagnostics {};
        std::uint64_t timeout_diagnostics {};
        std::uint64_t unavailable_diagnostics {};
    };

    struct StaticFactCacheIdentity {
        std::string path;
        std::string file_id;
        std::uint64_t file_size {};
        std::uint64_t last_write_time {};
        std::string content_hash;
        std::string signature_identity;
        std::string scan_space_name;
        std::string scan_space_version;
    };

    struct StaticFactCacheCandidate {
        std::string subject_id;
        std::string route;
        std::string key;
        FactCostClass cost_class {FactCostClass::custom};
        StaticFactCacheIdentity identity;
        bool content_addressable {};
    };

    struct StaticFactIdentityFactKeys {
        std::string path;
        std::string file_id;
        std::string file_size;
        std::string last_write_time;
        std::string content_hash;
        std::string signature_identity;
        std::string scan_space_name;
        std::string scan_space_version;
    };

    [[nodiscard]] StaticFactIdentityFactKeys pe_static_fact_identity_fact_keys();

    struct StaticFactCacheSimulation {
        std::vector<OptimizerTraceEvent> trace_events;
        std::uint64_t lookups {};
        std::uint64_t cache_hits {};
        std::uint64_t cache_misses {};
        std::uint64_t accepted_reuses {};
        std::uint64_t rejected_reuses {};
        std::uint64_t invalidations {};
        std::uint64_t subject_scoped_facts {};
    };

    enum struct StaticFactCacheLookupStatus {
        unsupported,
        miss,
        hit,
        invalidated,
    };

    struct StaticFactCacheLookup {
        StaticFactCacheLookupStatus status {StaticFactCacheLookupStatus::unsupported};
        std::optional<Fact> fact;
        std::optional<OptimizerTraceEvent> trace_event;
    };

    struct StaticFactCacheStoreResult {
        bool stored {};
        bool subject_scoped {};
    };

    using StaticFactCacheStats = StaticFactCacheSimulation;

    struct StaticFactCache {
        [[nodiscard]] StaticFactCacheLookup lookup(const StaticFactCacheCandidate &candidate);
        [[nodiscard]] StaticFactCacheStoreResult store(const StaticFactCacheCandidate &candidate, Fact fact);
        [[nodiscard]] StaticFactCacheStats stats() const noexcept;

    private:
        struct Entry {
            std::string locator;
            std::string fingerprint;
            Fact fact;
        };

        std::vector<Entry> entries_;
        StaticFactCacheStats stats_;
    };

    struct CandidateProviderRequest {
        std::string id;
        std::string route;
        std::string filter_key;
        std::string argument_kind;
        std::string argument_value;
        std::vector<std::string> predicate_ids;
        std::vector<std::string> rule_identifiers;
    };

    struct CandidateProviderRequestPlan {
        std::vector<CandidateProviderRequest> requests;
    };

    struct CandidateProviderResult {
        std::string request_id;
        std::vector<std::string> subject_ids;
        bool available {};
        FactStatus status {FactStatus::missing};
        std::string diagnostic;
        std::chrono::seconds ttl {0};
    };

    struct CandidateProviderSimulation {
        CandidateProviderRequestPlan request_plan;
        SharedPredicateDagSimulation shared_dag;
        std::uint64_t provider_requests {};
        std::uint64_t candidate_subjects_returned {};
        std::uint64_t broad_results {};
        std::uint64_t server_fallback_predicate_evaluations {};
    };

    struct PrefilteredSubjectComparison {
        std::string subject_id;
        std::vector<RuleResult> baseline_results;
        std::vector<RuleResult> optimized_results;
        std::vector<std::string> exact_vm_rule_identifiers;
        std::vector<std::string> pruned_rule_identifiers;
    };

    struct PrefilteredEvaluationComparison {
        SharedPredicateDagSimulation shared_dag;
        std::vector<PrefilteredSubjectComparison> subjects;
        std::vector<OptimizerTraceEvent> trace_events;
        std::vector<std::string> incomplete_subjects;
        std::uint64_t baseline_exact_vm_rule_executions {};
        std::uint64_t prefiltered_exact_vm_rule_executions {};
        std::uint64_t exact_vm_rule_executions_avoided {};
        std::uint64_t result_mismatches {};
    };

    struct OptimizerPlanProviderRequirement {
        std::string route;
        std::string key;
        ValueType type {ValueType::undefined};
        FactCostClass cost_class {FactCostClass::custom};
        bool cheap_prefetch {};
        std::vector<std::string> rule_identifiers;
    };

    struct OptimizerPlan {
        std::vector<CanonicalPredicate> predicate_nodes;
        std::vector<std::string> predicate_order;
        std::vector<ExactVmOnlyExpression> exact_vm_fallbacks;
        std::vector<OptimizerPlanProviderRequirement> provider_requirements;
        std::vector<CandidateProviderRequest> candidate_provider_requests;
    };

    struct OptimizedEvaluationSubject {
        std::string subject_id;
        std::vector<RuleResult> rule_results;
        std::vector<std::string> exact_vm_rule_identifiers;
        std::vector<std::string> pruned_rule_identifiers;
    };

    struct OptimizedEvaluationSweep {
        SharedPredicateDagSimulation shared_dag;
        std::vector<OptimizedEvaluationSubject> subjects;
        std::vector<OptimizerTraceEvent> trace_events;
        std::vector<std::string> incomplete_subjects;
        std::uint64_t baseline_exact_vm_rule_executions {};
        std::uint64_t optimized_exact_vm_rule_executions {};
        std::uint64_t exact_vm_rule_executions_avoided {};
        std::uint64_t candidate_provider_requests {};
        std::uint64_t candidate_provider_subjects_returned {};
        std::uint64_t candidate_provider_broad_results {};
        std::uint64_t candidate_provider_fallback_predicate_evaluations {};
    };

    [[nodiscard]] CanonicalPredicateReport extract_canonical_predicates(const VerifiedProgram &program);
    [[nodiscard]] std::string canonical_predicate_report_json(const CanonicalPredicateReport &report);
    [[nodiscard]] OptimizerPlan build_optimizer_plan(const VerifiedProgram &program);
    [[nodiscard]] std::string optimizer_plan_json(const OptimizerPlan &plan);
    [[nodiscard]] OptimizedEvaluationSweep evaluate_with_optimizer_plan(const VerifiedProgram &program,
                                                                        const OptimizerPlan &plan,
                                                                        std::span<const Subject> subjects,
                                                                        const FactCache &facts);
    [[nodiscard]] OptimizedEvaluationSweep
    evaluate_with_optimizer_plan(const VerifiedProgram &program, const OptimizerPlan &plan,
                                 std::span<const Subject> subjects, const FactCache &facts,
                                 std::span<const CandidateProviderResult> candidate_provider_results);
    [[nodiscard]] std::string_view
    candidate_set_representation_name(CandidateSetRepresentation representation) noexcept;
    [[nodiscard]] DiscoveryGatePlan plan_discovery_gates(const VerifiedProgram &program,
                                                         const CanonicalPredicateReport &report);
    [[nodiscard]] DiscoveryGateSimulation simulate_discovery_gates(const VerifiedProgram &program,
                                                                   const DiscoveryGatePlan &plan,
                                                                   std::span<const Subject> subjects,
                                                                   const FactCache &facts);
    [[nodiscard]] std::string discovery_gate_simulation_json(const DiscoveryGateSimulation &simulation);
    [[nodiscard]] SharedPredicateDagSimulation simulate_shared_predicate_dag(const VerifiedProgram &program,
                                                                             const CanonicalPredicateReport &report,
                                                                             std::span<const Subject> subjects,
                                                                             const FactCache &facts);
    [[nodiscard]] SharedPredicateDagSimulation
    simulate_shared_predicate_dag(const VerifiedProgram &program, const CanonicalPredicateReport &report,
                                  std::span<const Subject> subjects, const FactCache &facts,
                                  const PredicateSelectivityProfile &profile);
    [[nodiscard]] PredicateSelectivityProfile build_selectivity_profile(const SharedPredicateDagSimulation &simulation);
    [[nodiscard]] std::string shared_predicate_dag_simulation_json(const SharedPredicateDagSimulation &simulation);
    [[nodiscard]] LazyProviderExpansionPlan
    plan_lazy_provider_expansion(const VerifiedProgram &program, const SharedPredicateDagSimulation &simulation);
    [[nodiscard]] std::string lazy_provider_expansion_plan_json(const LazyProviderExpansionPlan &plan);
    [[nodiscard]] WatchdogBudgetSimulation
    simulate_watchdog_budgets(const SharedPredicateDagSimulation &simulation,
                              const LazyProviderExpansionPlan &lazy_plan,
                              const WatchdogBudgetPolicy &policy = WatchdogBudgetPolicy {});
    [[nodiscard]] std::vector<StaticFactCacheCandidate>
    derive_static_fact_cache_candidates(std::span<const OptimizerPlanProviderRequirement> requirements,
                                        std::span<const Subject> subjects, const FactCache &identity_facts,
                                        const StaticFactIdentityFactKeys &identity_fact_keys);
    [[nodiscard]] StaticFactCacheSimulation
    simulate_static_fact_cache(std::span<const StaticFactCacheCandidate> candidates);
    [[nodiscard]] CandidateProviderRequestPlan plan_candidate_provider_requests(const CanonicalPredicateReport &report);
    [[nodiscard]] CandidateProviderSimulation simulate_candidate_provider_filter(
        const VerifiedProgram &program, const CanonicalPredicateReport &report, std::span<const Subject> subjects,
        const CandidateProviderRequestPlan &request_plan, std::span<const CandidateProviderResult> provider_results,
        const FactCache &fallback_facts);
    [[nodiscard]] std::vector<CandidateProviderResult> candidate_provider_results_from_protocol(
        std::span<const rule_engine::protocol::CandidateProviderSubjectSet> results);
    [[nodiscard]] std::string candidate_provider_simulation_json(const CandidateProviderSimulation &simulation);
    [[nodiscard]] PrefilteredEvaluationComparison compare_prefiltered_evaluation(const VerifiedProgram &program,
                                                                                 const CanonicalPredicateReport &report,
                                                                                 std::span<const Subject> subjects,
                                                                                 const FactCache &facts);
} // namespace rule_engine::optimizer
