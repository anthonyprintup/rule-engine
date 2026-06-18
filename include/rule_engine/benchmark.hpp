#pragma once

#include <rule_engine/diagnostic.hpp>

#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>
#include <vector>

namespace rule_engine::benchmark {
    struct BenchmarkOptions {
        std::string scenario {"shared_process_name"};
        std::uint64_t seed {1};
        std::size_t subject_count {100};
        std::size_t rule_count {1000};
        std::size_t match_every {10};
        bool simulate_discovery_gates {};
        bool simulate_shared_predicate_dag {};
        bool simulate_lazy_provider_expansion {};
        bool simulate_candidate_provider {};
        bool simulate_prefiltered_evaluation {};
        bool simulate_optimizer_plan_prefilter {};
        bool simulate_selectivity_feedback {};
        bool simulate_watchdogs {};
        bool simulate_watchdog_enforcement {};
        bool simulate_static_fact_cache {};
        bool simulate_scheduler_controls {};
        bool simulate_optimization_comparison {};
    };

    struct BenchmarkMetadata {
        std::string schema {"rule-engine-benchmark.v1"};
        std::string mode {"baseline"};
        std::string scenario;
        std::uint64_t seed {};
        std::size_t subject_count {};
        std::size_t rule_count {};
        std::string workload_class;
        std::string selectivity;
        std::string benchmark_tier {"unit"};
        std::size_t acceptance_target_min_clients {1};
        std::size_t acceptance_target_max_clients {16};
        std::size_t acceptance_target_subjects_per_client {1000};
        std::size_t acceptance_target_rules_per_pack {10000};
        std::string build_type;
        std::string provider_latency_model {"zero"};
        std::vector<std::string> optimizer_flags;
    };

    struct BenchmarkMetrics {
        std::uint64_t sweep_wall_time_us {};
        std::uint64_t subjects_evaluated {};
        std::uint64_t provider_rounds {};
        std::uint64_t provider_elapsed_us {};
        std::uint64_t facts_requested {};
        std::uint64_t facts_returned {};
        std::uint64_t returned_payload_bytes {};
        std::uint64_t expression_evaluations {};
        std::uint64_t exact_vm_rule_executions {};
        std::uint64_t rule_matches {};
        std::uint64_t rules_pruned_before_exact_vm {};
        std::uint64_t dropped_rule_branches {};
        std::uint64_t expensive_provider_reaches {};
        std::uint64_t canonical_predicates {};
        std::uint64_t exact_vm_only_expressions {};
        std::uint64_t nonselective_predicates {};
        std::uint64_t optimizer_trace_events {};
        std::uint64_t discovery_gate_count {};
        std::uint64_t discovery_gate_evaluations {};
        std::uint64_t discovery_gate_pack_skips {};
        std::uint64_t fact_cache_lookups {};
        std::uint64_t fact_cache_hits {};
        std::uint64_t fact_cache_misses {};
        std::uint64_t fact_cache_lookup_probes {};
        std::uint64_t peak_candidate_set_subjects {};
        std::uint64_t peak_candidate_set_bytes {};
        std::uint64_t lazy_provider_batches {};
        std::uint64_t lazy_provider_facts_requested {};
        std::uint64_t lazy_provider_facts_avoided {};
        std::uint64_t lazy_provider_expensive_facts_requested {};
        std::uint64_t lazy_provider_expensive_facts_avoided {};
        std::uint64_t candidate_provider_requests {};
        std::uint64_t candidate_provider_subjects_returned {};
        std::uint64_t candidate_provider_broad_results {};
        std::uint64_t candidate_provider_fallback_predicate_evaluations {};
        std::uint64_t prefiltered_exact_vm_rule_executions {};
        std::uint64_t prefiltered_exact_vm_rule_executions_avoided {};
        std::uint64_t prefiltered_exact_vm_rule_skip_trace_events {};
        std::uint64_t prefiltered_result_mismatches {};
        std::uint64_t prefiltered_incomplete_subjects {};
        std::uint64_t optimizer_plan_prefilter_exact_vm_rule_executions {};
        std::uint64_t optimizer_plan_prefilter_exact_vm_rule_executions_avoided {};
        std::uint64_t optimizer_plan_prefilter_exact_vm_rule_skip_trace_events {};
        std::uint64_t optimizer_plan_prefilter_result_mismatches {};
        std::uint64_t optimizer_plan_prefilter_incomplete_subjects {};
        std::uint64_t optimizer_plan_prefilter_replay_subject_mismatches {};
        std::uint64_t optimizer_plan_prefilter_replay_rule_result_mismatches {};
        std::uint64_t optimizer_plan_prefilter_replay_trace_event_mismatches {};
        std::uint64_t optimizer_plan_prefilter_replay_metric_mismatches {};
        std::uint64_t selectivity_feedback_profile_predicates {};
        std::uint64_t selectivity_feedback_reordered_predicates {};
        std::uint64_t watchdog_budget_evaluations {};
        std::uint64_t watchdog_budget_events {};
        std::uint64_t predicate_watchdog_budget_events {};
        std::uint64_t route_watchdog_budget_events {};
        std::uint64_t watchdog_explicit_budget_diagnostics {};
        std::uint64_t watchdog_deferred_branch_diagnostics {};
        std::uint64_t watchdog_substituted_gate_diagnostics {};
        std::uint64_t watchdog_timeout_diagnostics {};
        std::uint64_t watchdog_unavailable_diagnostics {};
        std::uint64_t static_fact_cache_lookups {};
        std::uint64_t static_fact_cache_hits {};
        std::uint64_t static_fact_cache_misses {};
        std::uint64_t static_fact_cache_reuses {};
        std::uint64_t static_fact_cache_invalidations {};
        std::uint64_t static_fact_cache_subject_scoped {};
        std::uint64_t scheduler_simulated_clients {};
        std::uint64_t scheduler_timer_jitter_window_ms {};
        std::uint64_t scheduler_peak_wake_batch {};
        std::uint64_t scheduler_peak_vm_queue_depth {};
        std::uint64_t scheduler_peak_provider_queue_depth {};
        std::uint64_t scheduler_backpressure_events {};
        std::uint64_t scheduler_deadline_misses {};
        std::uint64_t scheduler_idle_state_bytes {};
        std::uint64_t comparison_exact_vm_rule_executions_avoided {};
        std::uint64_t comparison_expensive_provider_facts_avoided {};
        std::uint64_t comparison_optimized_expression_evaluations {};
        std::uint64_t comparison_expression_evaluations_avoided {};
        std::uint64_t comparison_result_mismatches {};
        std::uint64_t comparison_incomplete_subjects {};
        std::uint64_t comparison_broad_nonselective_predicates {};
        std::uint64_t comparison_broad_peak_candidate_set_subjects {};
        std::uint64_t comparison_broad_peak_candidate_set_bytes {};
        std::uint64_t comparison_broad_workload_bounded {};
    };

    struct BenchmarkPredicateObservation {
        std::string predicate_id;
        std::string cost_class;
        std::uint64_t observed_selectivity_ppm {};
    };

    struct BenchmarkOptimizerTraceRecord {
        std::string event;
        std::string predicate_id;
        std::string rule_identifier;
        std::string subject_id;
        std::string reason;
        std::string cost_class;
        std::string source;
        std::uint64_t source_id {};
        std::size_t span_start {};
        std::size_t span_end {};
        std::uint64_t matched_subject_count {};
        std::uint64_t candidate_subject_count {};
        std::uint64_t candidate_set_bytes {};
    };

    struct BenchmarkReport {
        BenchmarkMetadata metadata;
        BenchmarkMetrics metrics;
        std::vector<std::string> optimizer_predicate_order;
        std::vector<BenchmarkPredicateObservation> optimizer_predicate_observations;
        std::vector<BenchmarkOptimizerTraceRecord> optimizer_trace_records;
    };

    [[nodiscard]] std::expected<BenchmarkReport, ErrorSet> run_baseline_benchmark(const BenchmarkOptions &options);
    [[nodiscard]] std::string benchmark_report_json(const BenchmarkReport &report);
    [[nodiscard]] std::string benchmark_report_markdown(const BenchmarkReport &report);
} // namespace rule_engine::benchmark
