#include <rule_engine/benchmark.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <string_view>
#include <vector>

namespace {
    [[nodiscard]] bool contains(const std::string_view text, const std::string_view needle) {
        return text.find(needle) != std::string_view::npos;
    }
} // namespace

TEST_CASE("baseline benchmark produces reproducible reports for shared process-name predicates") {
    const auto report = rule_engine::benchmark::run_baseline_benchmark(rule_engine::benchmark::BenchmarkOptions {
        .scenario = "shared_process_name",
        .seed = 7u,
        .subject_count = 4u,
        .rule_count = 3u,
        .match_every = 2u,
    });

    REQUIRE(report.has_value());
    CHECK(report->metadata.mode == "baseline");
    CHECK(report->metadata.scenario == "shared_process_name");
    CHECK(report->metadata.seed == 7u);
    CHECK(report->metadata.subject_count == 4u);
    CHECK(report->metadata.rule_count == 3u);
    CHECK(report->metadata.selectivity == "every 2 subjects");
    CHECK_FALSE(report->metadata.build_type.empty());
    CHECK(report->metadata.optimizer_flags.empty());
    CHECK(report->metrics.subjects_evaluated == 4u);
    CHECK(report->metrics.provider_rounds == 4u);
    CHECK(report->metrics.facts_requested == 4u);
    CHECK(report->metrics.facts_returned == 4u);
    CHECK(report->metrics.expression_evaluations == 36u);
    CHECK(report->metrics.exact_vm_rule_executions == 12u);
    CHECK(report->metrics.rule_matches == 6u);
    CHECK(report->metrics.rules_pruned_before_exact_vm == 0u);
    CHECK(report->metrics.fact_cache_lookups == 36u);
    CHECK(report->metrics.fact_cache_hits == 24u);
    CHECK(report->metrics.fact_cache_misses == 12u);
    CHECK(report->metrics.fact_cache_lookup_probes == 36u);

    const auto json = rule_engine::benchmark::benchmark_report_json(*report);
    CHECK(contains(json, R"("schema":"rule-engine-benchmark.v1")"));
    CHECK(contains(json, R"("mode":"baseline")"));
    CHECK(contains(json, R"("scenario":"shared_process_name")"));
    CHECK(contains(json, R"("buildType":")"));
    CHECK(contains(json, R"("optimizerFlags":[])"));
    CHECK(contains(json, R"("providerRounds":4)"));
    CHECK(contains(json, R"("providerElapsedUs":)"));
    CHECK(contains(json, R"("expressionEvaluations":36)"));
    CHECK(contains(json, R"("exactVmRuleExecutions":12)"));
    CHECK(contains(json, R"("ruleMatches":6)"));
    CHECK(contains(json, R"("factCacheHits":24)"));
    CHECK(contains(json, R"("factCacheLookupProbes":36)"));

    const auto markdown = rule_engine::benchmark::benchmark_report_markdown(*report);
    CHECK(contains(markdown, "# Rule Engine Benchmark Report"));
    CHECK(contains(markdown, "- Build type: `"));
    CHECK(contains(markdown, "- Optimizer flags: `none`"));
    CHECK(contains(markdown, "| Provider rounds | 4 |"));
    CHECK(contains(markdown, "| Provider elapsed us |"));
    CHECK(contains(markdown, "| Expression evaluations | 36 |"));
    CHECK(contains(markdown, "| Exact VM rule executions | 12 |"));
    CHECK(contains(markdown, "| Rule matches | 6 |"));
    CHECK(contains(markdown, "| Fact cache hits | 24 |"));
    CHECK(contains(markdown, "| Fact cache lookup probes | 36 |"));
}

TEST_CASE("benchmark can include shared predicate DAG simulator metrics") {
    const auto report = rule_engine::benchmark::run_baseline_benchmark(rule_engine::benchmark::BenchmarkOptions {
        .scenario = "shared_process_name",
        .seed = 7u,
        .subject_count = 4u,
        .rule_count = 3u,
        .match_every = 2u,
        .simulate_shared_predicate_dag = true,
    });

    REQUIRE(report.has_value());
    CHECK(report->metadata.mode == "baseline_with_shared_predicate_dag_simulation");
    CHECK(report->metadata.optimizer_flags == std::vector<std::string> {"shared_predicate_dag"});
    CHECK(report->metrics.exact_vm_rule_executions == 12u);
    CHECK(report->metrics.rules_pruned_before_exact_vm == 6u);
    CHECK(report->metrics.optimizer_trace_events == 7u);
    CHECK(report->metrics.peak_candidate_set_subjects == 4u);
    CHECK(report->optimizer_predicate_order ==
          std::vector<std::string> {"endpoint.process.snapshot|process.name|equal|string:target.exe"});
    REQUIRE(report->optimizer_trace_records.size() == 7u);
    CHECK(report->optimizer_trace_records[0].event == "predicate_ordered");
    CHECK(report->optimizer_trace_records[0].predicate_id ==
          "endpoint.process.snapshot|process.name|equal|string:target.exe");
    CHECK(report->optimizer_trace_records[0].cost_class == "inventory");
    CHECK(report->optimizer_trace_records[0].reason == "static descriptor cost order");
    CHECK(report->optimizer_trace_records[0].source == "synthetic-benchmark.yar");
    CHECK(report->optimizer_trace_records[0].source_id == 1u);
    CHECK(report->optimizer_trace_records[0].span_start < report->optimizer_trace_records[0].span_end);
    CHECK(report->optimizer_trace_records[1].event == "rule_subject_pruned");
    CHECK(report->optimizer_trace_records[1].rule_identifier == "bench_rule_0");
    CHECK(report->optimizer_trace_records[1].subject_id == "pid:1");
    CHECK(report->optimizer_trace_records[1].reason == "process.name equal string:target.exe evaluated false");
    CHECK(report->optimizer_trace_records[1].candidate_subject_count == 3u);
    CHECK(report->optimizer_trace_records[1].candidate_set_bytes == 1u);
    REQUIRE(report->optimizer_predicate_observations.size() == 1u);
    CHECK(report->optimizer_predicate_observations[0].predicate_id ==
          "endpoint.process.snapshot|process.name|equal|string:target.exe");
    CHECK(report->optimizer_predicate_observations[0].cost_class == "inventory");
    CHECK(report->optimizer_predicate_observations[0].observed_selectivity_ppm == 500000u);

    const auto json = rule_engine::benchmark::benchmark_report_json(*report);
    CHECK(contains(json, R"("mode":"baseline_with_shared_predicate_dag_simulation")"));
    CHECK(contains(json, R"("optimizerFlags":["shared_predicate_dag"])"));
    CHECK(contains(json, R"("rulesPrunedBeforeExactVm":6)"));
    CHECK(contains(json, R"("optimizerTraceEvents":7)"));
    CHECK(contains(json, R"("peakCandidateSetSubjects":4)"));
    CHECK(contains(json,
                   R"("optimizerPredicateOrder":["endpoint.process.snapshot|process.name|equal|string:target.exe"])"));
    CHECK(contains(json, R"("costClass":"inventory")"));
    CHECK(contains(json, R"("observedSelectivityPpm":500000)"));
    CHECK(contains(json, R"("optimizerTraceRecords":[)"));
    CHECK(contains(json, R"("event":"predicate_ordered")"));
    CHECK(contains(json, R"("event":"rule_subject_pruned")"));
    CHECK(contains(json, R"("rule":"bench_rule_0")"));
    CHECK(contains(json, R"("subject":"pid:1")"));
    CHECK(contains(json, R"("sourceSpan":{"source":"synthetic-benchmark.yar")"));
    CHECK(contains(json, R"("candidateSetBytes":1)"));

    const auto markdown = rule_engine::benchmark::benchmark_report_markdown(*report);
    CHECK(contains(markdown, "- Mode: `baseline_with_shared_predicate_dag_simulation`"));
    CHECK(contains(markdown, "- Optimizer flags: `shared_predicate_dag`"));
    CHECK(contains(markdown, "| Rules pruned before exact VM | 6 |"));
    CHECK(contains(markdown, "| Optimizer trace events | 7 |"));
    CHECK(contains(markdown, "| Peak candidate set subjects | 4 |"));
    CHECK(contains(markdown,
                   R"(| endpoint.process.snapshot\|process.name\|equal\|string:target.exe | inventory | 500000 |)"));
    CHECK(contains(markdown, "## Optimizer Trace Records"));
    CHECK(contains(
        markdown,
        R"(| predicate_ordered | endpoint.process.snapshot\|process.name\|equal\|string:target.exe |  |  | static descriptor cost order |)"));
    CHECK(contains(
        markdown,
        R"(| rule_subject_pruned | endpoint.process.snapshot\|process.name\|equal\|string:target.exe | bench_rule_0 | pid:1 | process.name equal string:target.exe evaluated false |)"));
}

TEST_CASE("benchmark can include selectivity feedback ordering metrics") {
    const auto report = rule_engine::benchmark::run_baseline_benchmark(rule_engine::benchmark::BenchmarkOptions {
        .scenario = "selectivity_feedback_inventory",
        .seed = 7u,
        .subject_count = 4u,
        .rule_count = 3u,
        .match_every = 2u,
        .simulate_selectivity_feedback = true,
    });

    REQUIRE(report.has_value());
    CHECK(report->metadata.mode == "baseline_with_selectivity_feedback_simulation");
    CHECK(report->metadata.optimizer_flags ==
          std::vector<std::string> {"shared_predicate_dag", "selectivity_feedback"});
    CHECK(report->metrics.rule_matches == 6u);
    CHECK(report->metrics.selectivity_feedback_profile_predicates == 2u);
    CHECK(report->metrics.selectivity_feedback_reordered_predicates == 2u);
    CHECK(report->optimizer_predicate_order == std::vector<std::string> {
                                                   "endpoint.process.snapshot|process.name|equal|string:target.exe",
                                                   "endpoint.process.snapshot|process.architecture|equal|string:x64",
                                               });
    REQUIRE(report->optimizer_trace_records.size() >= 2u);
    CHECK(report->optimizer_trace_records[0].event == "predicate_ordered");
    CHECK(report->optimizer_trace_records[0].predicate_id ==
          "endpoint.process.snapshot|process.name|equal|string:target.exe");
    CHECK(report->optimizer_trace_records[0].reason == "observed selectivity feedback within descriptor cost order");

    const auto json = rule_engine::benchmark::benchmark_report_json(*report);
    CHECK(contains(json, R"("mode":"baseline_with_selectivity_feedback_simulation")"));
    CHECK(contains(json, R"("optimizerFlags":["shared_predicate_dag","selectivity_feedback"])"));
    CHECK(contains(json, R"("selectivityFeedbackProfilePredicates":2)"));
    CHECK(contains(json, R"("selectivityFeedbackReorderedPredicates":2)"));
    CHECK(contains(
        json,
        R"("optimizerPredicateOrder":["endpoint.process.snapshot|process.name|equal|string:target.exe","endpoint.process.snapshot|process.architecture|equal|string:x64"])"));
    CHECK(contains(json, R"("reason":"observed selectivity feedback within descriptor cost order")"));

    const auto markdown = rule_engine::benchmark::benchmark_report_markdown(*report);
    CHECK(contains(markdown, "- Mode: `baseline_with_selectivity_feedback_simulation`"));
    CHECK(contains(markdown, "- Optimizer flags: `shared_predicate_dag, selectivity_feedback`"));
    CHECK(contains(markdown, "| Selectivity feedback profile predicates | 2 |"));
    CHECK(contains(markdown, "| Selectivity feedback reordered predicates | 2 |"));
    CHECK(contains(
        markdown,
        R"(| predicate_ordered | endpoint.process.snapshot\|process.name\|equal\|string:target.exe |  |  | observed selectivity feedback within descriptor cost order |)"));
}

TEST_CASE("benchmark reports adaptive candidate set byte metrics") {
    const auto report = rule_engine::benchmark::run_baseline_benchmark(rule_engine::benchmark::BenchmarkOptions {
        .scenario = "shared_process_name",
        .seed = 7u,
        .subject_count = 16u,
        .rule_count = 3u,
        .match_every = 16u,
        .simulate_shared_predicate_dag = true,
    });

    REQUIRE(report.has_value());
    CHECK(report->metrics.rules_pruned_before_exact_vm == 45u);
    CHECK(report->metrics.peak_candidate_set_subjects == 16u);
    CHECK(report->metrics.peak_candidate_set_bytes == 2u);

    const auto json = rule_engine::benchmark::benchmark_report_json(*report);
    CHECK(contains(json, R"("peakCandidateSetSubjects":16)"));
    CHECK(contains(json, R"("peakCandidateSetBytes":2)"));

    const auto markdown = rule_engine::benchmark::benchmark_report_markdown(*report);
    CHECK(contains(markdown, "| Peak candidate set subjects | 16 |"));
    CHECK(contains(markdown, "| Peak candidate set bytes | 2 |"));
}

TEST_CASE("benchmark can include prefiltered evaluation parity metrics") {
    const auto report = rule_engine::benchmark::run_baseline_benchmark(rule_engine::benchmark::BenchmarkOptions {
        .scenario = "shared_process_name",
        .seed = 7u,
        .subject_count = 4u,
        .rule_count = 3u,
        .match_every = 2u,
        .simulate_prefiltered_evaluation = true,
    });

    REQUIRE(report.has_value());
    CHECK(report->metadata.mode == "baseline_with_prefiltered_evaluation_simulation");
    CHECK(report->metadata.optimizer_flags ==
          std::vector<std::string> {"shared_predicate_dag", "prefiltered_evaluation"});
    CHECK(report->metrics.exact_vm_rule_executions == 12u);
    CHECK(report->metrics.prefiltered_exact_vm_rule_executions == 6u);
    CHECK(report->metrics.prefiltered_exact_vm_rule_executions_avoided == 6u);
    CHECK(report->metrics.prefiltered_exact_vm_rule_skip_trace_events == 6u);
    CHECK(report->metrics.prefiltered_result_mismatches == 0u);
    CHECK(report->metrics.prefiltered_incomplete_subjects == 0u);

    const auto json = rule_engine::benchmark::benchmark_report_json(*report);
    CHECK(contains(json, R"("optimizerFlags":["shared_predicate_dag","prefiltered_evaluation"])"));
    CHECK(contains(json, R"("prefilteredExactVmRuleExecutions":6)"));
    CHECK(contains(json, R"("prefilteredExactVmRuleExecutionsAvoided":6)"));
    CHECK(contains(json, R"("prefilteredExactVmRuleSkipTraceEvents":6)"));
    CHECK(contains(json, R"("prefilteredResultMismatches":0)"));
    CHECK(contains(json, R"("prefilteredIncompleteSubjects":0)"));

    const auto markdown = rule_engine::benchmark::benchmark_report_markdown(*report);
    CHECK(contains(markdown, "- Optimizer flags: `shared_predicate_dag, prefiltered_evaluation`"));
    CHECK(contains(markdown, "| Prefiltered exact VM rule executions | 6 |"));
    CHECK(contains(markdown, "| Prefiltered exact VM rule executions avoided | 6 |"));
    CHECK(contains(markdown, "| Prefiltered exact VM rule skip trace events | 6 |"));
    CHECK(contains(markdown, "| Prefiltered result mismatches | 0 |"));
}

TEST_CASE("benchmark can include optimizer plan prefilter metrics") {
    const auto report = rule_engine::benchmark::run_baseline_benchmark(rule_engine::benchmark::BenchmarkOptions {
        .scenario = "shared_process_name",
        .seed = 7u,
        .subject_count = 4u,
        .rule_count = 3u,
        .match_every = 2u,
        .simulate_optimizer_plan_prefilter = true,
    });

    REQUIRE(report.has_value());
    CHECK(report->metadata.mode == "baseline_with_optimizer_plan_prefilter_simulation");
    CHECK(report->metadata.optimizer_flags ==
          std::vector<std::string> {"shared_predicate_dag", "optimizer_plan_prefilter"});
    CHECK(report->metrics.exact_vm_rule_executions == 12u);
    CHECK(report->metrics.optimizer_plan_prefilter_exact_vm_rule_executions == 6u);
    CHECK(report->metrics.optimizer_plan_prefilter_exact_vm_rule_executions_avoided == 6u);
    CHECK(report->metrics.optimizer_plan_prefilter_exact_vm_rule_skip_trace_events == 6u);
    CHECK(report->metrics.optimizer_plan_prefilter_result_mismatches == 0u);
    CHECK(report->metrics.optimizer_plan_prefilter_incomplete_subjects == 0u);
    CHECK(report->metrics.optimizer_plan_prefilter_replay_subject_mismatches == 0u);
    CHECK(report->metrics.optimizer_plan_prefilter_replay_rule_result_mismatches == 0u);
    CHECK(report->metrics.optimizer_plan_prefilter_replay_trace_event_mismatches == 0u);
    CHECK(report->metrics.optimizer_plan_prefilter_replay_metric_mismatches == 0u);

    const auto json = rule_engine::benchmark::benchmark_report_json(*report);
    CHECK(contains(json, R"("optimizerFlags":["shared_predicate_dag","optimizer_plan_prefilter"])"));
    CHECK(contains(json, R"("optimizerPlanPrefilterExactVmRuleExecutions":6)"));
    CHECK(contains(json, R"("optimizerPlanPrefilterExactVmRuleExecutionsAvoided":6)"));
    CHECK(contains(json, R"("optimizerPlanPrefilterExactVmRuleSkipTraceEvents":6)"));
    CHECK(contains(json, R"("optimizerPlanPrefilterResultMismatches":0)"));
    CHECK(contains(json, R"("optimizerPlanPrefilterIncompleteSubjects":0)"));
    CHECK(contains(json, R"("optimizerPlanPrefilterReplaySubjectMismatches":0)"));
    CHECK(contains(json, R"("optimizerPlanPrefilterReplayRuleResultMismatches":0)"));
    CHECK(contains(json, R"("optimizerPlanPrefilterReplayTraceEventMismatches":0)"));
    CHECK(contains(json, R"("optimizerPlanPrefilterReplayMetricMismatches":0)"));

    const auto markdown = rule_engine::benchmark::benchmark_report_markdown(*report);
    CHECK(contains(markdown, "- Optimizer flags: `shared_predicate_dag, optimizer_plan_prefilter`"));
    CHECK(contains(markdown, "| Optimizer plan prefilter exact VM rule executions | 6 |"));
    CHECK(contains(markdown, "| Optimizer plan prefilter exact VM rule executions avoided | 6 |"));
    CHECK(contains(markdown, "| Optimizer plan prefilter exact VM rule skip trace events | 6 |"));
    CHECK(contains(markdown, "| Optimizer plan prefilter result mismatches | 0 |"));
    CHECK(contains(markdown, "| Optimizer plan prefilter replay subject mismatches | 0 |"));
    CHECK(contains(markdown, "| Optimizer plan prefilter replay rule result mismatches | 0 |"));
    CHECK(contains(markdown, "| Optimizer plan prefilter replay trace event mismatches | 0 |"));
    CHECK(contains(markdown, "| Optimizer plan prefilter replay metric mismatches | 0 |"));
}

TEST_CASE("benchmark optimizer plan prefilter preserves global gates in reportable counters") {
    const auto report = rule_engine::benchmark::run_baseline_benchmark(rule_engine::benchmark::BenchmarkOptions {
        .scenario = "global_gate_prefilter",
        .seed = 7u,
        .subject_count = 4u,
        .rule_count = 2u,
        .match_every = 2u,
        .simulate_optimizer_plan_prefilter = true,
    });

    REQUIRE(report.has_value());
    CHECK(report->metadata.mode == "baseline_with_optimizer_plan_prefilter_simulation");
    CHECK(report->metadata.workload_class == "global_gate");
    CHECK(report->metrics.exact_vm_rule_executions == 8u);
    CHECK(report->metrics.rule_matches == 4u);
    CHECK(report->metrics.optimizer_plan_prefilter_exact_vm_rule_executions == 6u);
    CHECK(report->metrics.optimizer_plan_prefilter_exact_vm_rule_executions_avoided == 2u);
    CHECK(report->metrics.optimizer_plan_prefilter_result_mismatches == 0u);
    CHECK(report->metrics.optimizer_plan_prefilter_incomplete_subjects == 0u);

    const auto json = rule_engine::benchmark::benchmark_report_json(*report);
    CHECK(contains(json, R"("scenario":"global_gate_prefilter")"));
    CHECK(contains(json, R"("workloadClass":"global_gate")"));
    CHECK(contains(json, R"("exactVmRuleExecutions":8)"));
    CHECK(contains(json, R"("optimizerPlanPrefilterExactVmRuleExecutions":6)"));
    CHECK(contains(json, R"("optimizerPlanPrefilterExactVmRuleExecutionsAvoided":2)"));
    CHECK(contains(json, R"("optimizerPlanPrefilterResultMismatches":0)"));

    const auto markdown = rule_engine::benchmark::benchmark_report_markdown(*report);
    CHECK(contains(markdown, "- Scenario: `global_gate_prefilter`"));
    CHECK(contains(markdown, "- Workload class: `global_gate`"));
    CHECK(contains(markdown, "| Exact VM rule executions | 8 |"));
    CHECK(contains(markdown, "| Rule matches | 4 |"));
    CHECK(contains(markdown, "| Optimizer plan prefilter exact VM rule executions | 6 |"));
    CHECK(contains(markdown, "| Optimizer plan prefilter exact VM rule executions avoided | 2 |"));
    CHECK(contains(markdown, "| Optimizer plan prefilter result mismatches | 0 |"));
}

TEST_CASE("benchmark can include OR candidate set operation metrics") {
    const auto report = rule_engine::benchmark::run_baseline_benchmark(rule_engine::benchmark::BenchmarkOptions {
        .scenario = "or_process_name",
        .seed = 7u,
        .subject_count = 4u,
        .rule_count = 3u,
        .match_every = 4u,
        .simulate_prefiltered_evaluation = true,
    });

    REQUIRE(report.has_value());
    CHECK(report->metadata.scenario == "or_process_name");
    CHECK(report->metadata.workload_class == "selective_or");
    CHECK(report->metadata.selectivity == "two of every 4 subjects");
    CHECK(report->metrics.exact_vm_rule_executions == 12u);
    CHECK(report->metrics.rule_matches == 6u);
    CHECK(report->metrics.canonical_predicates == 2u);
    CHECK(report->metrics.rules_pruned_before_exact_vm == 6u);
    CHECK(report->metrics.prefiltered_exact_vm_rule_executions == 6u);
    CHECK(report->metrics.prefiltered_exact_vm_rule_executions_avoided == 6u);
    CHECK(report->metrics.prefiltered_result_mismatches == 0u);
    CHECK(report->metrics.prefiltered_incomplete_subjects == 0u);

    const auto json = rule_engine::benchmark::benchmark_report_json(*report);
    CHECK(contains(json, R"("scenario":"or_process_name")"));
    CHECK(contains(json, R"("workloadClass":"selective_or")"));
    CHECK(contains(json, R"("canonicalPredicates":2)"));
    CHECK(contains(json, R"("rulesPrunedBeforeExactVm":6)"));
    CHECK(contains(json, R"("prefilteredExactVmRuleExecutionsAvoided":6)"));

    const auto markdown = rule_engine::benchmark::benchmark_report_markdown(*report);
    CHECK(contains(markdown, "- Scenario: `or_process_name`"));
    CHECK(contains(markdown, "- Workload class: `selective_or`"));
    CHECK(contains(markdown, "| Rules pruned before exact VM | 6 |"));
    CHECK(contains(markdown, "| Prefiltered exact VM rule executions avoided | 6 |"));
}

TEST_CASE("benchmark includes broad nonselective workload coverage") {
    const auto report = rule_engine::benchmark::run_baseline_benchmark(rule_engine::benchmark::BenchmarkOptions {
        .scenario = "broad_process_name",
        .seed = 7u,
        .subject_count = 4u,
        .rule_count = 3u,
        .match_every = 2u,
        .simulate_shared_predicate_dag = true,
    });

    REQUIRE(report.has_value());
    CHECK(report->metadata.scenario == "broad_process_name");
    CHECK(report->metadata.workload_class == "broad");
    CHECK(report->metadata.selectivity == "all subjects");
    CHECK(report->metrics.subjects_evaluated == 4u);
    CHECK(report->metrics.exact_vm_rule_executions == 12u);
    CHECK(report->metrics.rule_matches == 12u);
    CHECK(report->metrics.rules_pruned_before_exact_vm == 0u);
    CHECK(report->metrics.nonselective_predicates == 1u);
    CHECK(report->metrics.peak_candidate_set_subjects == 4u);

    const auto json = rule_engine::benchmark::benchmark_report_json(*report);
    CHECK(contains(json, R"("scenario":"broad_process_name")"));
    CHECK(contains(json, R"("workloadClass":"broad")"));
    CHECK(contains(json, R"("selectivity":"all subjects")"));
    CHECK(contains(json, R"("rulesPrunedBeforeExactVm":0)"));
    CHECK(contains(json, R"("nonselectivePredicates":1)"));

    const auto markdown = rule_engine::benchmark::benchmark_report_markdown(*report);
    CHECK(contains(markdown, "- Workload class: `broad`"));
    CHECK(contains(markdown, "- Selectivity: `all subjects`"));
    CHECK(contains(markdown, "| Rules pruned before exact VM | 0 |"));
    CHECK(contains(markdown, "| Nonselective predicates | 1 |"));
}

TEST_CASE("benchmark can include lazy provider expansion simulation metrics") {
    const auto report = rule_engine::benchmark::run_baseline_benchmark(rule_engine::benchmark::BenchmarkOptions {
        .scenario = "shared_process_name_expensive_pe",
        .seed = 7u,
        .subject_count = 4u,
        .rule_count = 3u,
        .match_every = 2u,
        .simulate_shared_predicate_dag = true,
        .simulate_lazy_provider_expansion = true,
    });

    REQUIRE(report.has_value());
    CHECK(report->metadata.mode == "baseline_with_shared_predicate_dag_and_lazy_provider_simulation");
    CHECK(report->metadata.optimizer_flags ==
          std::vector<std::string> {"shared_predicate_dag", "lazy_provider_expansion"});
    CHECK(report->metrics.subjects_evaluated == 4u);
    CHECK(report->metrics.exact_vm_rule_executions == 12u);
    CHECK(report->metrics.rule_matches == 0u);
    CHECK(report->metrics.facts_requested == 6u);
    CHECK(report->metrics.expensive_provider_reaches == 2u);
    CHECK(report->metrics.rules_pruned_before_exact_vm == 6u);
    CHECK(report->metrics.lazy_provider_batches == 1u);
    CHECK(report->metrics.lazy_provider_facts_requested == 2u);
    CHECK(report->metrics.lazy_provider_expensive_facts_requested == 2u);
    CHECK(report->metrics.lazy_provider_facts_avoided == 2u);
    CHECK(report->metrics.lazy_provider_expensive_facts_avoided == 2u);

    const auto json = rule_engine::benchmark::benchmark_report_json(*report);
    CHECK(contains(json, R"("mode":"baseline_with_shared_predicate_dag_and_lazy_provider_simulation")"));
    CHECK(contains(json, R"("optimizerFlags":["shared_predicate_dag","lazy_provider_expansion"])"));
    CHECK(contains(json, R"("lazyProviderBatches":1)"));
    CHECK(contains(json, R"("lazyProviderFactsRequested":2)"));
    CHECK(contains(json, R"("lazyProviderExpensiveFactsAvoided":2)"));

    const auto markdown = rule_engine::benchmark::benchmark_report_markdown(*report);
    CHECK(contains(markdown, "- Mode: `baseline_with_shared_predicate_dag_and_lazy_provider_simulation`"));
    CHECK(contains(markdown, "- Optimizer flags: `shared_predicate_dag, lazy_provider_expansion`"));
    CHECK(contains(markdown, "| Lazy provider batches | 1 |"));
    CHECK(contains(markdown, "| Lazy provider facts requested | 2 |"));
    CHECK(contains(markdown, "| Lazy provider expensive facts avoided | 2 |"));
}

TEST_CASE("benchmark reports dropped empty branches before lazy provider expansion") {
    const auto report = rule_engine::benchmark::run_baseline_benchmark(rule_engine::benchmark::BenchmarkOptions {
        .scenario = "empty_process_name_expensive_pe",
        .seed = 7u,
        .subject_count = 4u,
        .rule_count = 3u,
        .match_every = 2u,
        .simulate_shared_predicate_dag = true,
        .simulate_lazy_provider_expansion = true,
    });

    REQUIRE(report.has_value());
    CHECK(report->metadata.scenario == "empty_process_name_expensive_pe");
    CHECK(report->metadata.workload_class == "empty");
    CHECK(report->metadata.selectivity == "no subjects");
    CHECK(report->metrics.exact_vm_rule_executions == 12u);
    CHECK(report->metrics.rule_matches == 0u);
    CHECK(report->metrics.rules_pruned_before_exact_vm == 12u);
    CHECK(report->metrics.dropped_rule_branches == 3u);
    CHECK(report->metrics.lazy_provider_batches == 0u);
    CHECK(report->metrics.lazy_provider_facts_requested == 0u);
    CHECK(report->metrics.lazy_provider_expensive_facts_requested == 0u);

    const auto json = rule_engine::benchmark::benchmark_report_json(*report);
    CHECK(contains(json, R"("scenario":"empty_process_name_expensive_pe")"));
    CHECK(contains(json, R"("workloadClass":"empty")"));
    CHECK(contains(json, R"("rulesPrunedBeforeExactVm":12)"));
    CHECK(contains(json, R"("droppedRuleBranches":3)"));
    CHECK(contains(json, R"("lazyProviderBatches":0)"));
    CHECK(contains(json, R"("lazyProviderExpensiveFactsRequested":0)"));

    const auto markdown = rule_engine::benchmark::benchmark_report_markdown(*report);
    CHECK(contains(markdown, "- Workload class: `empty`"));
    CHECK(contains(markdown, "| Rules pruned before exact VM | 12 |"));
    CHECK(contains(markdown, "| Dropped rule branches | 3 |"));
    CHECK(contains(markdown, "| Lazy provider batches | 0 |"));
}

TEST_CASE("benchmark includes mixed expensive and exact-VM-only workload coverage") {
    const auto report = rule_engine::benchmark::run_baseline_benchmark(rule_engine::benchmark::BenchmarkOptions {
        .scenario = "mixed_process_name_expensive_pe",
        .seed = 7u,
        .subject_count = 4u,
        .rule_count = 6u,
        .match_every = 2u,
        .simulate_shared_predicate_dag = true,
        .simulate_lazy_provider_expansion = true,
    });

    REQUIRE(report.has_value());
    CHECK(report->metadata.scenario == "mixed_process_name_expensive_pe");
    CHECK(report->metadata.workload_class == "mixed");
    CHECK(report->metrics.exact_vm_rule_executions == 24u);
    CHECK(report->metrics.canonical_predicates == 1u);
    CHECK(report->metrics.exact_vm_only_expressions == 8u);
    CHECK(report->metrics.rules_pruned_before_exact_vm == 8u);
    CHECK(report->metrics.lazy_provider_batches == 1u);
    CHECK(report->metrics.lazy_provider_facts_requested == 4u);
    CHECK(report->metrics.lazy_provider_facts_avoided == 0u);
    CHECK(report->metrics.lazy_provider_expensive_facts_requested == 4u);
    CHECK(report->metrics.lazy_provider_expensive_facts_avoided == 0u);

    const auto json = rule_engine::benchmark::benchmark_report_json(*report);
    CHECK(contains(json, R"("scenario":"mixed_process_name_expensive_pe")"));
    CHECK(contains(json, R"("workloadClass":"mixed")"));
    CHECK(contains(json, R"("canonicalPredicates":1)"));
    CHECK(contains(json, R"("exactVmOnlyExpressions":8)"));
    CHECK(contains(json, R"("rulesPrunedBeforeExactVm":8)"));

    const auto markdown = rule_engine::benchmark::benchmark_report_markdown(*report);
    CHECK(contains(markdown, "- Workload class: `mixed`"));
    CHECK(contains(markdown, "| Canonical predicates | 1 |"));
    CHECK(contains(markdown, "| Exact VM only expressions | 8 |"));
}

TEST_CASE("benchmark includes production-scale validation workload shape and target metadata") {
    const auto report = rule_engine::benchmark::run_baseline_benchmark(rule_engine::benchmark::BenchmarkOptions {
        .scenario = "production_scale_validation",
        .seed = 7u,
        .subject_count = 20u,
        .rule_count = 8u,
        .match_every = 10u,
        .simulate_shared_predicate_dag = true,
        .simulate_lazy_provider_expansion = true,
        .simulate_prefiltered_evaluation = true,
    });

    REQUIRE(report.has_value());
    CHECK(report->metadata.scenario == "production_scale_validation");
    CHECK(report->metadata.workload_class == "production_scale_validation");
    CHECK(report->metadata.selectivity == "10% selective plus broad/adversarial branches");
    CHECK(report->metadata.benchmark_tier == "unit");
    CHECK(report->metadata.acceptance_target_min_clients == 1u);
    CHECK(report->metadata.acceptance_target_max_clients == 16u);
    CHECK(report->metadata.acceptance_target_subjects_per_client == 1000u);
    CHECK(report->metadata.acceptance_target_rules_per_pack == 10000u);
    CHECK(report->metrics.exact_vm_rule_executions == 160u);
    CHECK(report->metrics.rules_pruned_before_exact_vm > 0u);
    CHECK(report->metrics.exact_vm_only_expressions > 0u);
    CHECK(report->metrics.nonselective_predicates > 0u);
    CHECK(report->metrics.lazy_provider_expensive_facts_requested > 0u);
    CHECK(report->metrics.lazy_provider_expensive_facts_requested <= report->metrics.expensive_provider_reaches);
    CHECK(report->metrics.prefiltered_exact_vm_rule_executions_avoided > 0u);
    CHECK(report->metrics.prefiltered_result_mismatches == 0u);
    CHECK(report->metrics.prefiltered_incomplete_subjects == 0u);
    CHECK(report->metrics.peak_candidate_set_subjects <= report->metadata.subject_count);

    const auto json = rule_engine::benchmark::benchmark_report_json(*report);
    CHECK(contains(json, R"("scenario":"production_scale_validation")"));
    CHECK(contains(json, R"("benchmarkTier":"unit")"));
    CHECK(contains(json, R"("acceptanceTargetMinClients":1)"));
    CHECK(contains(json, R"("acceptanceTargetMaxClients":16)"));
    CHECK(contains(json, R"("acceptanceTargetSubjectsPerClient":1000)"));
    CHECK(contains(json, R"("acceptanceTargetRulesPerPack":10000)"));
    CHECK(contains(json, R"("workloadClass":"production_scale_validation")"));

    const auto markdown = rule_engine::benchmark::benchmark_report_markdown(*report);
    CHECK(contains(markdown, "- Benchmark tier: `unit`"));
    CHECK(contains(markdown, "- Acceptance target: `1-16 clients, 1000 subjects/client, 10000 rules/pack`"));
    CHECK(contains(markdown, "- Workload class: `production_scale_validation`"));
    CHECK(contains(markdown, "| Nonselective predicates |"));
    CHECK(contains(markdown, "| Prefiltered result mismatches | 0 |"));
}

TEST_CASE("benchmark can include optimized versus baseline comparison metrics") {
    const auto report = rule_engine::benchmark::run_baseline_benchmark(rule_engine::benchmark::BenchmarkOptions {
        .scenario = "production_scale_validation",
        .seed = 7u,
        .subject_count = 20u,
        .rule_count = 8u,
        .match_every = 10u,
        .simulate_optimization_comparison = true,
    });

    REQUIRE(report.has_value());
    CHECK(report->metadata.mode == "baseline_with_optimization_comparison_simulation");
    CHECK(report->metadata.optimizer_flags ==
          std::vector<std::string> {"shared_predicate_dag", "prefiltered_evaluation", "optimizer_plan_prefilter",
                                    "lazy_provider_expansion", "optimization_comparison"});
    CHECK(report->metrics.exact_vm_rule_executions == 160u);
    CHECK(report->metrics.optimizer_plan_prefilter_exact_vm_rule_executions > 0u);
    CHECK(report->metrics.optimizer_plan_prefilter_exact_vm_rule_executions_avoided > 0u);
    CHECK(report->metrics.optimizer_plan_prefilter_result_mismatches == 0u);
    CHECK(report->metrics.optimizer_plan_prefilter_incomplete_subjects == 0u);
    CHECK(report->metrics.optimizer_plan_prefilter_replay_subject_mismatches == 0u);
    CHECK(report->metrics.optimizer_plan_prefilter_replay_rule_result_mismatches == 0u);
    CHECK(report->metrics.optimizer_plan_prefilter_replay_trace_event_mismatches == 0u);
    CHECK(report->metrics.optimizer_plan_prefilter_replay_metric_mismatches == 0u);
    CHECK(report->metrics.comparison_exact_vm_rule_executions_avoided > 0u);
    CHECK(report->metrics.comparison_expensive_provider_facts_avoided > 0u);
    CHECK(report->metrics.comparison_optimized_expression_evaluations > 0u);
    CHECK(report->metrics.comparison_optimized_expression_evaluations < report->metrics.expression_evaluations);
    CHECK(report->metrics.comparison_expression_evaluations_avoided > 0u);
    CHECK(report->metrics.comparison_result_mismatches == 0u);
    CHECK(report->metrics.comparison_incomplete_subjects == 0u);
    CHECK(report->metrics.comparison_broad_nonselective_predicates > 0u);
    CHECK(report->metrics.comparison_broad_peak_candidate_set_subjects <= report->metadata.subject_count);
    CHECK(report->metrics.comparison_broad_peak_candidate_set_bytes > 0u);
    CHECK(report->metrics.comparison_broad_workload_bounded == 1u);

    const auto json = rule_engine::benchmark::benchmark_report_json(*report);
    CHECK(contains(
        json,
        R"("optimizerFlags":["shared_predicate_dag","prefiltered_evaluation","optimizer_plan_prefilter","lazy_provider_expansion","optimization_comparison"])"));
    CHECK(contains(json, R"("optimizerPlanPrefilterExactVmRuleExecutions":)"));
    CHECK(contains(json, R"("optimizerPlanPrefilterExactVmRuleExecutionsAvoided":)"));
    CHECK(contains(json, R"("optimizerPlanPrefilterResultMismatches":0)"));
    CHECK(contains(json, R"("optimizerPlanPrefilterIncompleteSubjects":0)"));
    CHECK(contains(json, R"("optimizerPlanPrefilterReplaySubjectMismatches":0)"));
    CHECK(contains(json, R"("optimizerPlanPrefilterReplayRuleResultMismatches":0)"));
    CHECK(contains(json, R"("optimizerPlanPrefilterReplayTraceEventMismatches":0)"));
    CHECK(contains(json, R"("optimizerPlanPrefilterReplayMetricMismatches":0)"));
    CHECK(contains(json, R"("comparisonExactVmRuleExecutionsAvoided":)"));
    CHECK(contains(json, R"("comparisonExpensiveProviderFactsAvoided":)"));
    CHECK(contains(json, R"("comparisonOptimizedExpressionEvaluations":)"));
    CHECK(contains(json, R"("comparisonExpressionEvaluationsAvoided":)"));
    CHECK(contains(json, R"("comparisonResultMismatches":0)"));
    CHECK(contains(json, R"("comparisonIncompleteSubjects":0)"));
    CHECK(contains(json, R"("comparisonBroadWorkloadBounded":1)"));

    const auto markdown = rule_engine::benchmark::benchmark_report_markdown(*report);
    CHECK(contains(markdown, "- Mode: `baseline_with_optimization_comparison_simulation`"));
    CHECK(contains(markdown, "- Optimizer flags: `shared_predicate_dag, prefiltered_evaluation, "
                             "optimizer_plan_prefilter, lazy_provider_expansion, optimization_comparison`"));
    CHECK(contains(markdown, "| Optimizer plan prefilter exact VM rule executions |"));
    CHECK(contains(markdown, "| Optimizer plan prefilter exact VM rule executions avoided |"));
    CHECK(contains(markdown, "| Optimizer plan prefilter result mismatches | 0 |"));
    CHECK(contains(markdown, "| Optimizer plan prefilter replay trace event mismatches | 0 |"));
    CHECK(contains(markdown, "| Comparison exact VM rule executions avoided |"));
    CHECK(contains(markdown, "| Comparison expensive provider facts avoided |"));
    CHECK(contains(markdown, "| Comparison optimized expression evaluations |"));
    CHECK(contains(markdown, "| Comparison expression evaluations avoided |"));
    CHECK(contains(markdown, "| Comparison result mismatches | 0 |"));
    CHECK(contains(markdown, "| Comparison incomplete subjects | 0 |"));
    CHECK(contains(markdown, "| Comparison broad workload bounded | 1 |"));
}

TEST_CASE("benchmark can include trace-only watchdog metrics") {
    const auto predicate_report =
        rule_engine::benchmark::run_baseline_benchmark(rule_engine::benchmark::BenchmarkOptions {
            .scenario = "production_scale_validation",
            .seed = 7u,
            .subject_count = 20u,
            .rule_count = 8u,
            .match_every = 10u,
            .simulate_lazy_provider_expansion = true,
            .simulate_watchdogs = true,
        });

    REQUIRE(predicate_report.has_value());
    CHECK(predicate_report->metadata.optimizer_flags ==
          std::vector<std::string> {"shared_predicate_dag", "lazy_provider_expansion", "watchdogs"});
    CHECK(predicate_report->metrics.watchdog_budget_evaluations == 3u);
    CHECK(predicate_report->metrics.watchdog_budget_events == 1u);
    CHECK(predicate_report->metrics.predicate_watchdog_budget_events == 1u);
    CHECK(predicate_report->metrics.route_watchdog_budget_events == 0u);

    const auto json = rule_engine::benchmark::benchmark_report_json(*predicate_report);
    CHECK(contains(json, R"("watchdogBudgetEvaluations":3)"));
    CHECK(contains(json, R"("watchdogBudgetEvents":1)"));
    CHECK(contains(json, R"("predicateWatchdogBudgetEvents":1)"));
    CHECK(contains(json, R"("routeWatchdogBudgetEvents":0)"));

    const auto markdown = rule_engine::benchmark::benchmark_report_markdown(*predicate_report);
    CHECK(contains(markdown, "- Optimizer flags: `shared_predicate_dag, lazy_provider_expansion, watchdogs`"));
    CHECK(contains(markdown, "| Watchdog budget evaluations | 3 |"));
    CHECK(contains(markdown, "| Watchdog budget events | 1 |"));
    CHECK(contains(markdown, "| Predicate watchdog budget events | 1 |"));
    CHECK(contains(markdown, "| Route watchdog budget events | 0 |"));

    const auto route_report = rule_engine::benchmark::run_baseline_benchmark(rule_engine::benchmark::BenchmarkOptions {
        .scenario = "mixed_process_name_expensive_pe",
        .seed = 7u,
        .subject_count = 20u,
        .rule_count = 8u,
        .match_every = 10u,
        .simulate_lazy_provider_expansion = true,
        .simulate_watchdogs = true,
    });

    REQUIRE(route_report.has_value());
    CHECK(route_report->metrics.watchdog_budget_events == 1u);
    CHECK(route_report->metrics.predicate_watchdog_budget_events == 0u);
    CHECK(route_report->metrics.route_watchdog_budget_events == 1u);

    const auto route_json = rule_engine::benchmark::benchmark_report_json(*route_report);
    CHECK(contains(route_json, R"("scenario":"mixed_process_name_expensive_pe")"));
    CHECK(contains(route_json, R"("routeWatchdogBudgetEvents":1)"));

    const auto route_markdown = rule_engine::benchmark::benchmark_report_markdown(*route_report);
    CHECK(contains(route_markdown, "- Scenario: `mixed_process_name_expensive_pe`"));
    CHECK(contains(route_markdown, "| Route watchdog budget events | 1 |"));
}

TEST_CASE("benchmark can include watchdog enforcement diagnostics") {
    const auto predicate_report =
        rule_engine::benchmark::run_baseline_benchmark(rule_engine::benchmark::BenchmarkOptions {
            .scenario = "production_scale_validation",
            .seed = 7u,
            .subject_count = 20u,
            .rule_count = 8u,
            .match_every = 10u,
            .simulate_lazy_provider_expansion = true,
            .simulate_watchdog_enforcement = true,
        });

    REQUIRE(predicate_report.has_value());
    CHECK(predicate_report->metadata.mode == "baseline_with_watchdog_enforcement_and_lazy_provider_simulation");
    CHECK(predicate_report->metadata.optimizer_flags == std::vector<std::string> {"shared_predicate_dag",
                                                                                  "lazy_provider_expansion",
                                                                                  "watchdogs", "watchdog_enforcement"});
    CHECK(predicate_report->metrics.watchdog_budget_events == 1u);
    CHECK(predicate_report->metrics.watchdog_explicit_budget_diagnostics == 1u);
    CHECK(predicate_report->metrics.watchdog_deferred_branch_diagnostics == 1u);
    CHECK(predicate_report->metrics.watchdog_timeout_diagnostics == 0u);

    const auto json = rule_engine::benchmark::benchmark_report_json(*predicate_report);
    CHECK(contains(json, R"("watchdogExplicitBudgetDiagnostics":1)"));
    CHECK(contains(json, R"("watchdogDeferredBranchDiagnostics":1)"));
    CHECK(contains(json, R"("watchdogTimeoutDiagnostics":0)"));

    const auto markdown = rule_engine::benchmark::benchmark_report_markdown(*predicate_report);
    CHECK(contains(markdown, "- Mode: `baseline_with_watchdog_enforcement_and_lazy_provider_simulation`"));
    CHECK(contains(
        markdown,
        "- Optimizer flags: `shared_predicate_dag, lazy_provider_expansion, watchdogs, watchdog_enforcement`"));
    CHECK(contains(markdown, "| Watchdog explicit budget diagnostics | 1 |"));
    CHECK(contains(markdown, "| Watchdog deferred branch diagnostics | 1 |"));
    CHECK(contains(markdown, "| Watchdog timeout diagnostics | 0 |"));

    const auto route_report = rule_engine::benchmark::run_baseline_benchmark(rule_engine::benchmark::BenchmarkOptions {
        .scenario = "mixed_process_name_expensive_pe",
        .seed = 7u,
        .subject_count = 20u,
        .rule_count = 8u,
        .match_every = 10u,
        .simulate_lazy_provider_expansion = true,
        .simulate_watchdog_enforcement = true,
    });

    REQUIRE(route_report.has_value());
    CHECK(route_report->metrics.watchdog_budget_events == 1u);
    CHECK(route_report->metrics.watchdog_explicit_budget_diagnostics == 1u);
    CHECK(route_report->metrics.watchdog_deferred_branch_diagnostics == 0u);
    CHECK(route_report->metrics.watchdog_timeout_diagnostics == 1u);

    const auto route_json = rule_engine::benchmark::benchmark_report_json(*route_report);
    CHECK(contains(route_json, R"("scenario":"mixed_process_name_expensive_pe")"));
    CHECK(contains(route_json, R"("watchdogExplicitBudgetDiagnostics":1)"));
    CHECK(contains(route_json, R"("watchdogTimeoutDiagnostics":1)"));

    const auto route_markdown = rule_engine::benchmark::benchmark_report_markdown(*route_report);
    CHECK(contains(route_markdown, "- Scenario: `mixed_process_name_expensive_pe`"));
    CHECK(contains(route_markdown, "| Watchdog explicit budget diagnostics | 1 |"));
    CHECK(contains(route_markdown, "| Watchdog timeout diagnostics | 1 |"));
}

TEST_CASE("benchmark can include content-addressed static fact cache metrics") {
    const auto report = rule_engine::benchmark::run_baseline_benchmark(rule_engine::benchmark::BenchmarkOptions {
        .scenario = "production_scale_validation",
        .seed = 7u,
        .subject_count = 20u,
        .rule_count = 8u,
        .match_every = 10u,
        .simulate_static_fact_cache = true,
    });

    REQUIRE(report.has_value());
    CHECK(report->metadata.optimizer_flags == std::vector<std::string> {"static_fact_cache"});
    CHECK(report->metrics.static_fact_cache_lookups == 20u);
    CHECK(report->metrics.static_fact_cache_hits == 18u);
    CHECK(report->metrics.static_fact_cache_misses == 2u);
    CHECK(report->metrics.static_fact_cache_reuses == 18u);
    CHECK(report->metrics.static_fact_cache_invalidations == 1u);
    CHECK(report->metrics.static_fact_cache_subject_scoped == 20u);
    CHECK(report->metrics.optimizer_trace_events == 19u);

    const auto json = rule_engine::benchmark::benchmark_report_json(*report);
    CHECK(contains(json, R"("optimizerFlags":["static_fact_cache"])"));
    CHECK(contains(json, R"("staticFactCacheLookups":20)"));
    CHECK(contains(json, R"("staticFactCacheHits":18)"));
    CHECK(contains(json, R"("staticFactCacheMisses":2)"));
    CHECK(contains(json, R"("staticFactCacheReuses":18)"));
    CHECK(contains(json, R"("staticFactCacheInvalidations":1)"));
    CHECK(contains(json, R"("staticFactCacheSubjectScoped":20)"));

    const auto markdown = rule_engine::benchmark::benchmark_report_markdown(*report);
    CHECK(contains(markdown, "- Optimizer flags: `static_fact_cache`"));
    CHECK(contains(markdown, "| Static fact cache lookups | 20 |"));
    CHECK(contains(markdown, "| Static fact cache hits | 18 |"));
    CHECK(contains(markdown, "| Static fact cache misses | 2 |"));
    CHECK(contains(markdown, "| Static fact cache reuses | 18 |"));
    CHECK(contains(markdown, "| Static fact cache invalidations | 1 |"));
    CHECK(contains(markdown, "| Static fact cache subject-scoped facts | 20 |"));
}

TEST_CASE("benchmark can include scheduler jitter and backpressure metrics") {
    const auto report = rule_engine::benchmark::run_baseline_benchmark(rule_engine::benchmark::BenchmarkOptions {
        .scenario = "production_scale_validation",
        .seed = 7u,
        .subject_count = 20u,
        .rule_count = 8u,
        .match_every = 10u,
        .simulate_scheduler_controls = true,
    });

    REQUIRE(report.has_value());
    CHECK(report->metadata.mode == "baseline_with_scheduler_control_simulation");
    CHECK(report->metadata.benchmark_tier == "stress");
    CHECK(report->metadata.optimizer_flags == std::vector<std::string> {"scheduler_controls"});
    CHECK(report->metrics.scheduler_simulated_clients == 10000u);
    CHECK(report->metrics.scheduler_timer_jitter_window_ms == 300000u);
    CHECK(report->metrics.scheduler_peak_wake_batch == 48u);
    CHECK(report->metrics.scheduler_peak_vm_queue_depth == 403u);
    CHECK(report->metrics.scheduler_peak_provider_queue_depth == 2493u);
    CHECK(report->metrics.scheduler_backpressure_events == 727u);
    CHECK(report->metrics.scheduler_deadline_misses == 0u);
    CHECK(report->metrics.scheduler_idle_state_bytes == 320000u);

    const auto json = rule_engine::benchmark::benchmark_report_json(*report);
    CHECK(contains(json, R"("optimizerFlags":["scheduler_controls"])"));
    CHECK(contains(json, R"("schedulerSimulatedClients":10000)"));
    CHECK(contains(json, R"("schedulerTimerJitterWindowMs":300000)"));
    CHECK(contains(json, R"("schedulerPeakWakeBatch":48)"));
    CHECK(contains(json, R"("schedulerPeakVmQueueDepth":403)"));
    CHECK(contains(json, R"("schedulerPeakProviderQueueDepth":2493)"));
    CHECK(contains(json, R"("schedulerBackpressureEvents":727)"));
    CHECK(contains(json, R"("schedulerDeadlineMisses":0)"));
    CHECK(contains(json, R"("schedulerIdleStateBytes":320000)"));

    const auto markdown = rule_engine::benchmark::benchmark_report_markdown(*report);
    CHECK(contains(markdown, "- Optimizer flags: `scheduler_controls`"));
    CHECK(contains(markdown, "| Scheduler simulated clients | 10000 |"));
    CHECK(contains(markdown, "| Scheduler timer jitter window ms | 300000 |"));
    CHECK(contains(markdown, "| Scheduler peak wake batch | 48 |"));
    CHECK(contains(markdown, "| Scheduler peak VM queue depth | 403 |"));
    CHECK(contains(markdown, "| Scheduler peak provider queue depth | 2493 |"));
    CHECK(contains(markdown, "| Scheduler backpressure events | 727 |"));
    CHECK(contains(markdown, "| Scheduler deadline misses | 0 |"));
    CHECK(contains(markdown, "| Scheduler idle state bytes | 320000 |"));
}

TEST_CASE("benchmark can include generic candidate provider simulation metrics") {
    const auto report = rule_engine::benchmark::run_baseline_benchmark(rule_engine::benchmark::BenchmarkOptions {
        .scenario = "shared_process_name_expensive_pe",
        .seed = 7u,
        .subject_count = 4u,
        .rule_count = 3u,
        .match_every = 2u,
        .simulate_shared_predicate_dag = true,
        .simulate_lazy_provider_expansion = true,
        .simulate_candidate_provider = true,
    });

    REQUIRE(report.has_value());
    CHECK(report->metadata.mode == "baseline_with_candidate_provider_and_lazy_provider_simulation");
    CHECK(report->metadata.optimizer_flags ==
          std::vector<std::string> {"shared_predicate_dag", "candidate_provider", "lazy_provider_expansion"});
    CHECK(report->metrics.subjects_evaluated == 4u);
    CHECK(report->metrics.exact_vm_rule_executions == 12u);
    CHECK(report->metrics.rules_pruned_before_exact_vm == 6u);
    CHECK(report->metrics.lazy_provider_facts_requested == 2u);
    CHECK(report->metrics.lazy_provider_expensive_facts_avoided == 2u);
    CHECK(report->metrics.candidate_provider_requests == 1u);
    CHECK(report->metrics.candidate_provider_subjects_returned == 2u);
    CHECK(report->metrics.candidate_provider_fallback_predicate_evaluations == 0u);

    const auto json = rule_engine::benchmark::benchmark_report_json(*report);
    CHECK(contains(json, R"("mode":"baseline_with_candidate_provider_and_lazy_provider_simulation")"));
    CHECK(
        contains(json, R"("optimizerFlags":["shared_predicate_dag","candidate_provider","lazy_provider_expansion"])"));
    CHECK(contains(json, R"("candidateProviderRequests":1)"));
    CHECK(contains(json, R"("candidateProviderSubjectsReturned":2)"));
    CHECK(contains(json, R"("candidateProviderFallbackPredicateEvaluations":0)"));

    const auto markdown = rule_engine::benchmark::benchmark_report_markdown(*report);
    CHECK(contains(markdown, "- Mode: `baseline_with_candidate_provider_and_lazy_provider_simulation`"));
    CHECK(contains(markdown, "- Optimizer flags: `shared_predicate_dag, candidate_provider, lazy_provider_expansion`"));
    CHECK(contains(markdown, "| Candidate provider requests | 1 |"));
    CHECK(contains(markdown, "| Candidate provider subjects returned | 2 |"));
    CHECK(contains(markdown, "| Candidate provider fallback predicate evaluations | 0 |"));
}

TEST_CASE("benchmark can include optimizer plan prefilter candidate provider metrics") {
    const auto report = rule_engine::benchmark::run_baseline_benchmark(rule_engine::benchmark::BenchmarkOptions {
        .scenario = "shared_process_name_expensive_pe",
        .seed = 7u,
        .subject_count = 4u,
        .rule_count = 3u,
        .match_every = 2u,
        .simulate_lazy_provider_expansion = true,
        .simulate_candidate_provider = true,
        .simulate_optimizer_plan_prefilter = true,
    });

    REQUIRE(report.has_value());
    CHECK(report->metadata.mode ==
          "baseline_with_optimizer_plan_prefilter_candidate_provider_and_lazy_provider_simulation");
    CHECK(report->metadata.optimizer_flags == std::vector<std::string> {"shared_predicate_dag", "candidate_provider",
                                                                        "optimizer_plan_prefilter",
                                                                        "lazy_provider_expansion"});
    CHECK(report->metrics.exact_vm_rule_executions == 12u);
    CHECK(report->metrics.candidate_provider_requests == 1u);
    CHECK(report->metrics.candidate_provider_subjects_returned == 2u);
    CHECK(report->metrics.candidate_provider_fallback_predicate_evaluations == 0u);
    CHECK(report->metrics.optimizer_plan_prefilter_exact_vm_rule_executions == 6u);
    CHECK(report->metrics.optimizer_plan_prefilter_exact_vm_rule_executions_avoided == 6u);
    CHECK(report->metrics.optimizer_plan_prefilter_exact_vm_rule_skip_trace_events == 6u);
    CHECK(report->metrics.optimizer_plan_prefilter_result_mismatches == 0u);
    CHECK(report->metrics.optimizer_plan_prefilter_incomplete_subjects == 0u);
    CHECK(report->metrics.optimizer_plan_prefilter_replay_subject_mismatches == 0u);
    CHECK(report->metrics.optimizer_plan_prefilter_replay_rule_result_mismatches == 0u);
    CHECK(report->metrics.optimizer_plan_prefilter_replay_trace_event_mismatches == 0u);
    CHECK(report->metrics.optimizer_plan_prefilter_replay_metric_mismatches == 0u);
    CHECK(report->metrics.lazy_provider_facts_requested == 2u);
    CHECK(report->metrics.lazy_provider_expensive_facts_requested == 2u);
    CHECK(report->metrics.lazy_provider_expensive_facts_avoided == 2u);

    const auto json = rule_engine::benchmark::benchmark_report_json(*report);
    CHECK(contains(
        json, R"("mode":"baseline_with_optimizer_plan_prefilter_candidate_provider_and_lazy_provider_simulation")"));
    CHECK(contains(
        json,
        R"("optimizerFlags":["shared_predicate_dag","candidate_provider","optimizer_plan_prefilter","lazy_provider_expansion"])"));
    CHECK(contains(json, R"("optimizerPlanPrefilterExactVmRuleExecutions":6)"));
    CHECK(contains(json, R"("optimizerPlanPrefilterExactVmRuleExecutionsAvoided":6)"));
    CHECK(contains(json, R"("optimizerPlanPrefilterResultMismatches":0)"));
    CHECK(contains(json, R"("optimizerPlanPrefilterReplayTraceEventMismatches":0)"));
    CHECK(contains(json, R"("lazyProviderExpensiveFactsAvoided":2)"));

    const auto markdown = rule_engine::benchmark::benchmark_report_markdown(*report);
    CHECK(contains(markdown,
                   "- Mode: `baseline_with_optimizer_plan_prefilter_candidate_provider_and_lazy_provider_simulation`"));
    CHECK(contains(markdown, "- Optimizer flags: `shared_predicate_dag, candidate_provider, optimizer_plan_prefilter, "
                             "lazy_provider_expansion`"));
    CHECK(contains(markdown, "| Optimizer plan prefilter exact VM rule executions avoided | 6 |"));
    CHECK(contains(markdown, "| Optimizer plan prefilter result mismatches | 0 |"));
    CHECK(contains(markdown, "| Optimizer plan prefilter replay trace event mismatches | 0 |"));
    CHECK(contains(markdown, "| Lazy provider expensive facts avoided | 2 |"));
}

TEST_CASE("benchmark reports broad candidate provider results") {
    const auto report = rule_engine::benchmark::run_baseline_benchmark(rule_engine::benchmark::BenchmarkOptions {
        .scenario = "broad_process_name",
        .seed = 7u,
        .subject_count = 4u,
        .rule_count = 3u,
        .match_every = 2u,
        .simulate_candidate_provider = true,
        .simulate_optimizer_plan_prefilter = true,
    });

    REQUIRE(report.has_value());
    CHECK(report->metrics.candidate_provider_requests == 1u);
    CHECK(report->metrics.candidate_provider_subjects_returned == 4u);
    CHECK(report->metrics.candidate_provider_broad_results == 1u);
    CHECK(report->metrics.candidate_provider_fallback_predicate_evaluations == 0u);
    CHECK(report->metrics.optimizer_plan_prefilter_exact_vm_rule_executions == 12u);
    CHECK(report->metrics.optimizer_plan_prefilter_exact_vm_rule_executions_avoided == 0u);
    CHECK(report->metrics.optimizer_plan_prefilter_result_mismatches == 0u);

    const auto json = rule_engine::benchmark::benchmark_report_json(*report);
    CHECK(contains(json, R"("candidateProviderBroadResults":1)"));

    const auto markdown = rule_engine::benchmark::benchmark_report_markdown(*report);
    CHECK(contains(markdown, "| Candidate provider broad results | 1 |"));
}

TEST_CASE("benchmark reports candidate provider fallback simulation metrics") {
    const auto report = rule_engine::benchmark::run_baseline_benchmark(rule_engine::benchmark::BenchmarkOptions {
        .scenario = "candidate_provider_unavailable",
        .seed = 7u,
        .subject_count = 4u,
        .rule_count = 3u,
        .match_every = 2u,
        .simulate_shared_predicate_dag = true,
        .simulate_lazy_provider_expansion = true,
        .simulate_candidate_provider = true,
    });

    REQUIRE(report.has_value());
    CHECK(report->metadata.scenario == "candidate_provider_unavailable");
    CHECK(report->metadata.mode == "baseline_with_candidate_provider_and_lazy_provider_simulation");
    CHECK(report->metrics.rules_pruned_before_exact_vm == 6u);
    CHECK(report->metrics.lazy_provider_facts_requested == 2u);
    CHECK(report->metrics.lazy_provider_expensive_facts_avoided == 2u);
    CHECK(report->metrics.candidate_provider_requests == 1u);
    CHECK(report->metrics.candidate_provider_subjects_returned == 0u);
    CHECK(report->metrics.candidate_provider_fallback_predicate_evaluations == 4u);
    CHECK(report->metrics.optimizer_trace_events == 8u);
    REQUIRE(report->optimizer_trace_records.size() >= 2u);
    CHECK(report->optimizer_trace_records[1].event == "candidate_provider_fallback");
    CHECK(report->optimizer_trace_records[1].reason ==
          "candidate provider process.inventory.by_image_name unavailable: synthetic benchmark candidate provider "
          "unavailable; falling back to server-side predicate evaluation");

    const auto json = rule_engine::benchmark::benchmark_report_json(*report);
    CHECK(contains(json, R"("scenario":"candidate_provider_unavailable")"));
    CHECK(contains(json, R"("candidateProviderRequests":1)"));
    CHECK(contains(json, R"("candidateProviderSubjectsReturned":0)"));
    CHECK(contains(json, R"("candidateProviderFallbackPredicateEvaluations":4)"));
    CHECK(contains(json, R"("event":"candidate_provider_fallback")"));
    CHECK(contains(json, "synthetic benchmark candidate provider unavailable"));

    const auto markdown = rule_engine::benchmark::benchmark_report_markdown(*report);
    CHECK(contains(markdown, "- Scenario: `candidate_provider_unavailable`"));
    CHECK(contains(markdown, "| Candidate provider requests | 1 |"));
    CHECK(contains(markdown, "| Candidate provider subjects returned | 0 |"));
    CHECK(contains(markdown, "| Candidate provider fallback predicate evaluations | 4 |"));
    CHECK(contains(markdown, "| Optimizer trace events | 8 |"));
    CHECK(contains(markdown, "| candidate_provider_fallback |"));
    CHECK(contains(markdown, "synthetic benchmark candidate provider unavailable"));
}

TEST_CASE("benchmark reports discovery gate empty pack metrics") {
    const auto report = rule_engine::benchmark::run_baseline_benchmark(rule_engine::benchmark::BenchmarkOptions {
        .scenario = "discovery_gate_empty_pack",
        .seed = 7u,
        .subject_count = 4u,
        .rule_count = 3u,
        .match_every = 2u,
        .simulate_discovery_gates = true,
    });

    REQUIRE(report.has_value());
    CHECK(report->metadata.mode == "baseline_with_discovery_gate_simulation");
    CHECK(report->metadata.workload_class == "discovery_gate_empty");
    CHECK(report->metadata.optimizer_flags == std::vector<std::string> {"discovery_gates"});
    CHECK(report->metrics.exact_vm_rule_executions == 12u);
    CHECK(report->metrics.rule_matches == 0u);
    CHECK(report->metrics.discovery_gate_count == 1u);
    CHECK(report->metrics.discovery_gate_evaluations == 4u);
    CHECK(report->metrics.discovery_gate_pack_skips == 1u);
    CHECK(report->metrics.optimizer_trace_events == 2u);

    const auto json = rule_engine::benchmark::benchmark_report_json(*report);
    CHECK(contains(json, R"("scenario":"discovery_gate_empty_pack")"));
    CHECK(contains(json, R"("mode":"baseline_with_discovery_gate_simulation")"));
    CHECK(contains(json, R"("optimizerFlags":["discovery_gates"])"));
    CHECK(contains(json, R"("discoveryGateCount":1)"));
    CHECK(contains(json, R"("discoveryGateEvaluations":4)"));
    CHECK(contains(json, R"("discoveryGatePackSkips":1)"));
    CHECK(contains(json, R"("optimizerTraceEvents":2)"));

    const auto markdown = rule_engine::benchmark::benchmark_report_markdown(*report);
    CHECK(contains(markdown, "- Mode: `baseline_with_discovery_gate_simulation`"));
    CHECK(contains(markdown, "- Workload class: `discovery_gate_empty`"));
    CHECK(contains(markdown, "| Discovery gate count | 1 |"));
    CHECK(contains(markdown, "| Discovery gate evaluations | 4 |"));
    CHECK(contains(markdown, "| Discovery gate pack skips | 1 |"));
    CHECK(contains(markdown, "| Optimizer trace events | 2 |"));
}
