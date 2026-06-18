#include <rule_engine/benchmark.hpp>

#include <rule_engine/compiler.hpp>
#include <rule_engine/evaluation_scheduler.hpp>
#include <rule_engine/evaluator.hpp>
#include <rule_engine/modules.hpp>
#include <rule_engine/optimizer.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {
    constexpr std::string_view process_name_key {"process.name"};
    constexpr std::string_view process_snapshot_route {"endpoint.process.snapshot"};
    constexpr std::string_view target_process_name {"target.exe"};
    constexpr std::string_view alternate_process_name {"helper.exe"};
    constexpr std::string_view benign_process_name {"benign.exe"};
    constexpr std::string_view expensive_pe_scenario {"shared_process_name_expensive_pe"};
    constexpr std::string_view broad_process_name_scenario {"broad_process_name"};
    constexpr std::string_view mixed_process_name_expensive_pe_scenario {"mixed_process_name_expensive_pe"};
    constexpr std::string_view or_process_name_scenario {"or_process_name"};
    constexpr std::string_view empty_process_name_expensive_pe_scenario {"empty_process_name_expensive_pe"};
    constexpr std::string_view candidate_provider_unavailable_scenario {"candidate_provider_unavailable"};
    constexpr std::string_view discovery_gate_empty_pack_scenario {"discovery_gate_empty_pack"};
    constexpr std::string_view production_scale_validation_scenario {"production_scale_validation"};
    constexpr std::string_view selectivity_feedback_inventory_scenario {"selectivity_feedback_inventory"};
    constexpr std::string_view global_gate_prefilter_scenario {"global_gate_prefilter"};
    constexpr std::string_view impossible_process_name {"never.exe"};
    constexpr std::size_t max_benchmark_optimizer_trace_records {64u};

    struct SchedulerControlSimulation {
        std::uint64_t simulated_clients {};
        std::uint64_t timer_jitter_window_ms {};
        std::uint64_t peak_wake_batch {};
        std::uint64_t peak_vm_queue_depth {};
        std::uint64_t peak_provider_queue_depth {};
        std::uint64_t backpressure_events {};
        std::uint64_t deadline_misses {};
        std::uint64_t idle_state_bytes {};
    };

    struct OptimizerPlanReplayParity {
        std::uint64_t subject_mismatches {};
        std::uint64_t rule_result_mismatches {};
        std::uint64_t trace_event_mismatches {};
        std::uint64_t metric_mismatches {};
    };

    [[nodiscard]] bool source_spans_equal(const rule_engine::SourceSpan &lhs,
                                          const rule_engine::SourceSpan &rhs) noexcept {
        return lhs.source_id == rhs.source_id && lhs.start == rhs.start && lhs.end == rhs.end &&
               lhs.source == rhs.source;
    }

    [[nodiscard]] bool diagnostics_equal(const std::vector<rule_engine::Diagnostic> &lhs,
                                         const std::vector<rule_engine::Diagnostic> &rhs) noexcept {
        if (lhs.size() != rhs.size()) {
            return false;
        }
        for (std::size_t index = 0; index < lhs.size(); ++index) {
            if (lhs[index].source != rhs[index].source || lhs[index].message != rhs[index].message ||
                !source_spans_equal(lhs[index].span, rhs[index].span)) {
                return false;
            }
        }
        return true;
    }

    [[nodiscard]] bool rule_results_equal(const rule_engine::RuleResult &lhs,
                                          const rule_engine::RuleResult &rhs) noexcept {
        return lhs.identifier == rhs.identifier && lhs.matched == rhs.matched &&
               diagnostics_equal(lhs.diagnostics, rhs.diagnostics);
    }

    [[nodiscard]] bool trace_events_equal(const rule_engine::optimizer::OptimizerTraceEvent &lhs,
                                          const rule_engine::optimizer::OptimizerTraceEvent &rhs) noexcept {
        return lhs.event == rhs.event && lhs.predicate_id == rhs.predicate_id &&
               lhs.rule_identifier == rhs.rule_identifier && lhs.subject_id == rhs.subject_id &&
               lhs.reason == rhs.reason && lhs.cost_class == rhs.cost_class && source_spans_equal(lhs.span, rhs.span) &&
               lhs.matched_subject_count == rhs.matched_subject_count &&
               lhs.candidate_subject_count == rhs.candidate_subject_count &&
               lhs.candidate_set_bytes == rhs.candidate_set_bytes;
    }

    template<typename Value, typename Equals> [[nodiscard]] std::uint64_t
    count_vector_mismatches(const std::vector<Value> &lhs, const std::vector<Value> &rhs, Equals equals) {
        const auto shared_size = std::min(lhs.size(), rhs.size());
        auto out = static_cast<std::uint64_t>(std::max(lhs.size(), rhs.size()) - shared_size);
        for (std::size_t index = 0; index < shared_size; ++index) {
            if (!equals(lhs[index], rhs[index])) {
                ++out;
            }
        }
        return out;
    }

    [[nodiscard]] std::uint64_t count_rule_result_mismatches(const std::vector<rule_engine::RuleResult> &baseline,
                                                             const std::vector<rule_engine::RuleResult> &optimized) {
        return count_vector_mismatches(baseline, optimized, rule_results_equal);
    }

    [[nodiscard]] std::uint64_t
    count_trace_event_mismatches(const std::vector<rule_engine::optimizer::OptimizerTraceEvent> &lhs,
                                 const std::vector<rule_engine::optimizer::OptimizerTraceEvent> &rhs) {
        return count_vector_mismatches(lhs, rhs, trace_events_equal);
    }

    [[nodiscard]] std::uint64_t
    count_optimized_subject_mismatches(const std::vector<rule_engine::optimizer::OptimizedEvaluationSubject> &lhs,
                                       const std::vector<rule_engine::optimizer::OptimizedEvaluationSubject> &rhs) {
        return count_vector_mismatches(lhs, rhs, [](const auto &captured, const auto &replayed) {
            return captured.subject_id == replayed.subject_id &&
                   captured.exact_vm_rule_identifiers == replayed.exact_vm_rule_identifiers &&
                   captured.pruned_rule_identifiers == replayed.pruned_rule_identifiers;
        });
    }

    [[nodiscard]] std::uint64_t count_optimized_subject_rule_result_mismatches(
        const std::vector<rule_engine::optimizer::OptimizedEvaluationSubject> &lhs,
        const std::vector<rule_engine::optimizer::OptimizedEvaluationSubject> &rhs) {
        const auto shared_size = std::min(lhs.size(), rhs.size());
        std::uint64_t out {};
        for (std::size_t index = 0; index < shared_size; ++index) {
            out += count_rule_result_mismatches(lhs[index].rule_results, rhs[index].rule_results);
        }
        return out + static_cast<std::uint64_t>(std::max(lhs.size(), rhs.size()) - shared_size);
    }

    [[nodiscard]] std::uint64_t
    count_optimizer_plan_metric_mismatches(const rule_engine::optimizer::OptimizedEvaluationSweep &lhs,
                                           const rule_engine::optimizer::OptimizedEvaluationSweep &rhs) {
        std::uint64_t out {};
        const auto count_if_different = [&out](const auto &left, const auto &right) {
            if (left != right) {
                ++out;
            }
        };

        count_if_different(lhs.incomplete_subjects, rhs.incomplete_subjects);
        count_if_different(lhs.baseline_exact_vm_rule_executions, rhs.baseline_exact_vm_rule_executions);
        count_if_different(lhs.optimized_exact_vm_rule_executions, rhs.optimized_exact_vm_rule_executions);
        count_if_different(lhs.exact_vm_rule_executions_avoided, rhs.exact_vm_rule_executions_avoided);
        count_if_different(lhs.candidate_provider_requests, rhs.candidate_provider_requests);
        count_if_different(lhs.candidate_provider_subjects_returned, rhs.candidate_provider_subjects_returned);
        count_if_different(lhs.candidate_provider_broad_results, rhs.candidate_provider_broad_results);
        count_if_different(lhs.candidate_provider_fallback_predicate_evaluations,
                           rhs.candidate_provider_fallback_predicate_evaluations);
        count_if_different(lhs.shared_dag.predicate_order, rhs.shared_dag.predicate_order);
        count_if_different(lhs.shared_dag.predicate_evaluations, rhs.shared_dag.predicate_evaluations);
        count_if_different(lhs.shared_dag.pruned_rule_subjects, rhs.shared_dag.pruned_rule_subjects);
        count_if_different(lhs.shared_dag.dropped_rule_branches, rhs.shared_dag.dropped_rule_branches);
        count_if_different(lhs.shared_dag.peak_candidate_set_subjects, rhs.shared_dag.peak_candidate_set_subjects);
        count_if_different(lhs.shared_dag.peak_candidate_set_bytes, rhs.shared_dag.peak_candidate_set_bytes);
        return out;
    }

    [[nodiscard]] OptimizerPlanReplayParity
    compare_optimizer_plan_replay(const rule_engine::optimizer::OptimizedEvaluationSweep &captured,
                                  const rule_engine::optimizer::OptimizedEvaluationSweep &replayed) {
        return OptimizerPlanReplayParity {
            .subject_mismatches = count_optimized_subject_mismatches(captured.subjects, replayed.subjects),
            .rule_result_mismatches =
                count_optimized_subject_rule_result_mismatches(captured.subjects, replayed.subjects),
            .trace_event_mismatches =
                count_trace_event_mismatches(captured.trace_events, replayed.trace_events) +
                count_trace_event_mismatches(captured.shared_dag.trace_events, replayed.shared_dag.trace_events),
            .metric_mismatches = count_optimizer_plan_metric_mismatches(captured, replayed),
        };
    }

    [[nodiscard]] const rule_engine::optimizer::OptimizedEvaluationSubject *
    find_optimized_subject(const rule_engine::optimizer::OptimizedEvaluationSweep &sweep,
                           const std::string_view subject_id) {
        const auto found = std::find_if(sweep.subjects.begin(), sweep.subjects.end(),
                                        [&](const auto &subject) { return subject.subject_id == subject_id; });
        return found == sweep.subjects.end() ? nullptr : &*found;
    }

    [[nodiscard]] bool reportable_rule_identifier(const rule_engine::VerifiedProgram &program,
                                                  const std::string_view identifier) {
        return std::ranges::any_of(program.rules, [&](const auto &rule) {
            const auto rule_id = rule.qualified_identifier.empty() ? rule.identifier : rule.qualified_identifier;
            return !rule.is_global && !rule.is_private && rule_id == identifier;
        });
    }

    [[nodiscard]] std::vector<rule_engine::RuleResult>
    reportable_rule_results(const rule_engine::VerifiedProgram &program,
                            const std::vector<rule_engine::RuleResult> &results) {
        std::vector<rule_engine::RuleResult> out;
        for (const auto &result : results) {
            if (reportable_rule_identifier(program, result.identifier)) {
                out.push_back(result);
            }
        }
        return out;
    }

    [[nodiscard]] std::uint64_t reportable_rule_result_count(const rule_engine::VerifiedProgram &program,
                                                             const std::vector<rule_engine::RuleResult> &results) {
        return static_cast<std::uint64_t>(reportable_rule_results(program, results).size());
    }

    [[nodiscard]] std::uint64_t count_optimizer_plan_result_mismatches(
        const rule_engine::VerifiedProgram &program, const std::vector<rule_engine::Subject> &subjects,
        const rule_engine::FactCache &facts, const rule_engine::optimizer::OptimizedEvaluationSweep &sweep) {
        std::uint64_t out {};
        for (const auto &subject : subjects) {
            const auto *optimized_subject = find_optimized_subject(sweep, subject.id);
            if (optimized_subject == nullptr) {
                ++out;
                continue;
            }

            const rule_engine::Evaluator baseline_evaluator {program, facts};
            const auto baseline_step = baseline_evaluator.step(subject);
            if (baseline_step.state != rule_engine::EvaluationState::complete) {
                ++out;
                continue;
            }

            out += count_rule_result_mismatches(reportable_rule_results(program, baseline_step.rule_results),
                                                optimized_subject->rule_results);
        }
        return out;
    }

    [[nodiscard]] std::size_t normalized_match_every(const std::size_t value) noexcept {
        return value == 0u ? 1u : value;
    }

    [[nodiscard]] bool uses_expensive_pe_branch(const std::string_view scenario) noexcept {
        return scenario == expensive_pe_scenario || scenario == mixed_process_name_expensive_pe_scenario ||
               scenario == empty_process_name_expensive_pe_scenario ||
               scenario == candidate_provider_unavailable_scenario || scenario == discovery_gate_empty_pack_scenario ||
               scenario == production_scale_validation_scenario;
    }

    [[nodiscard]] bool uses_broad_process_names(const std::string_view scenario) noexcept {
        return scenario == broad_process_name_scenario;
    }

    [[nodiscard]] bool uses_or_process_names(const std::string_view scenario) noexcept {
        return scenario == or_process_name_scenario;
    }

    [[nodiscard]] bool uses_empty_process_names(const std::string_view scenario) noexcept {
        return scenario == empty_process_name_expensive_pe_scenario;
    }

    [[nodiscard]] bool uses_mixed_rule_shapes(const std::string_view scenario) noexcept {
        return scenario == mixed_process_name_expensive_pe_scenario;
    }

    [[nodiscard]] bool uses_unavailable_candidate_provider(const std::string_view scenario) noexcept {
        return scenario == candidate_provider_unavailable_scenario;
    }

    [[nodiscard]] bool uses_discovery_gate_empty_pack(const std::string_view scenario) noexcept {
        return scenario == discovery_gate_empty_pack_scenario;
    }

    [[nodiscard]] bool uses_production_scale_validation(const std::string_view scenario) noexcept {
        return scenario == production_scale_validation_scenario;
    }

    [[nodiscard]] bool uses_selectivity_feedback_inventory(const std::string_view scenario) noexcept {
        return scenario == selectivity_feedback_inventory_scenario;
    }

    [[nodiscard]] bool uses_global_gate_prefilter(const std::string_view scenario) noexcept {
        return scenario == global_gate_prefilter_scenario;
    }

    [[nodiscard]] std::string workload_class_for(const std::string_view scenario) {
        if (uses_production_scale_validation(scenario)) {
            return "production_scale_validation";
        }
        if (uses_global_gate_prefilter(scenario)) {
            return "global_gate";
        }
        if (uses_selectivity_feedback_inventory(scenario)) {
            return "selectivity_feedback";
        }
        if (uses_empty_process_names(scenario)) {
            return "empty";
        }
        if (uses_discovery_gate_empty_pack(scenario)) {
            return "discovery_gate_empty";
        }
        if (uses_mixed_rule_shapes(scenario)) {
            return "mixed";
        }
        if (uses_or_process_names(scenario)) {
            return "selective_or";
        }
        if (uses_unavailable_candidate_provider(scenario)) {
            return "candidate_provider_fallback";
        }
        return uses_broad_process_names(scenario) ? "broad" : "selective";
    }

    [[nodiscard]] std::string selectivity_for(const std::string_view scenario, const std::size_t match_every) {
        if (uses_broad_process_names(scenario)) {
            return "all subjects";
        }
        if (uses_empty_process_names(scenario)) {
            return "no subjects";
        }
        if (uses_discovery_gate_empty_pack(scenario)) {
            return "no subjects after discovery gate";
        }
        if (uses_or_process_names(scenario)) {
            return "two of every " + std::to_string(match_every) + " subjects";
        }
        if (uses_production_scale_validation(scenario)) {
            const auto percent = match_every == 0u ? 100u : 100u / match_every;
            return std::to_string(percent) + "% selective plus broad/adversarial branches";
        }
        if (uses_selectivity_feedback_inventory(scenario)) {
            return "broad same-cost inventory gate plus every " + std::to_string(match_every) + " subject name filter";
        }
        if (uses_global_gate_prefilter(scenario)) {
            return "global gate allows every " + std::to_string(match_every) + " subjects";
        }
        return "every " + std::to_string(match_every) + " subjects";
    }

    [[nodiscard]] std::vector<std::string>
    optimizer_flags_for(const rule_engine::benchmark::BenchmarkOptions &options) {
        std::vector<std::string> out;
        if (options.simulate_discovery_gates) {
            out.emplace_back("discovery_gates");
        }
        if (options.simulate_shared_predicate_dag || options.simulate_lazy_provider_expansion ||
            options.simulate_candidate_provider || options.simulate_prefiltered_evaluation ||
            options.simulate_optimizer_plan_prefilter || options.simulate_watchdogs ||
            options.simulate_watchdog_enforcement || options.simulate_selectivity_feedback ||
            options.simulate_optimization_comparison) {
            out.emplace_back("shared_predicate_dag");
        }
        if (options.simulate_candidate_provider) {
            out.emplace_back("candidate_provider");
        }
        if (options.simulate_prefiltered_evaluation || options.simulate_optimization_comparison) {
            out.emplace_back("prefiltered_evaluation");
        }
        if (options.simulate_optimizer_plan_prefilter || options.simulate_optimization_comparison) {
            out.emplace_back("optimizer_plan_prefilter");
        }
        if (options.simulate_selectivity_feedback) {
            out.emplace_back("selectivity_feedback");
        }
        if (options.simulate_lazy_provider_expansion || options.simulate_optimization_comparison) {
            out.emplace_back("lazy_provider_expansion");
        }
        if (options.simulate_optimization_comparison) {
            out.emplace_back("optimization_comparison");
        }
        if (options.simulate_watchdogs || options.simulate_watchdog_enforcement) {
            out.emplace_back("watchdogs");
        }
        if (options.simulate_watchdog_enforcement) {
            out.emplace_back("watchdog_enforcement");
        }
        if (options.simulate_static_fact_cache) {
            out.emplace_back("static_fact_cache");
        }
        if (options.simulate_scheduler_controls) {
            out.emplace_back("scheduler_controls");
        }
        return out;
    }

    [[nodiscard]] std::uint64_t count_changed_order_positions(const std::vector<std::string> &lhs,
                                                              const std::vector<std::string> &rhs) noexcept {
        const auto count = std::max(lhs.size(), rhs.size());
        std::uint64_t changed {};
        for (std::size_t index = 0; index < count; ++index) {
            const auto *left = index < lhs.size() ? &lhs[index] : nullptr;
            const auto *right = index < rhs.size() ? &rhs[index] : nullptr;
            if (left == nullptr || right == nullptr || *left != *right) {
                ++changed;
            }
        }
        return changed;
    }

    [[nodiscard]] std::string build_type_name() {
#ifdef NDEBUG
        return "release";
#else
        return "debug";
#endif
    }

    [[nodiscard]] std::string synthetic_rule_source(const std::size_t rule_count, const std::string_view scenario) {
        if (uses_global_gate_prefilter(scenario)) {
            return R"(import "process"

global rule powershell_only {
    condition:
        process.name == "target.exe"
}

rule cheap_name {
    condition:
        process.name == "target.exe"
}

rule broad_rule {
    condition:
        true
}
)";
        }

        const auto with_expensive_pe = uses_expensive_pe_branch(scenario);
        std::string out;
        out.reserve(96u + (rule_count * 192u));
        out += "import \"process\"\n\n";
        if (with_expensive_pe) {
            out += "import \"pe\"\n\n";
        }
        for (std::size_t index = 0; index < rule_count; ++index) {
            out += "rule bench_rule_";
            out += std::to_string(index);
            out += " {\n";
            out += "    condition:\n";
            if (uses_production_scale_validation(scenario)) {
                const auto shape = index % 4u;
                if (shape == 1u) {
                    out += "        process.name == \"";
                    out += target_process_name;
                    out += "\" and\n";
                    out += "        for any imported in pe.imports : (imported[\"dll\"] contains \"KERNEL32.dll\")";
                } else if (shape == 2u) {
                    out += "        process.name != \"";
                    out += impossible_process_name;
                    out += "\" and\n";
                    out += "        with pname = process.name : (pname != \"";
                    out += impossible_process_name;
                    out += "\")";
                } else {
                    out += "        process.name == \"";
                    out += target_process_name;
                    out += "\"";
                    if (shape == 3u) {
                        out += " and\n";
                        out += "        with pname = process.name : (pname == \"";
                        out += target_process_name;
                        out += "\")";
                    } else {
                        out += " and\n";
                        out += "        for any imported in pe.imports : (imported[\"dll\"] contains \"KERNEL32.dll\")";
                    }
                }
            } else if (uses_mixed_rule_shapes(scenario) && (index % 3u) == 1u) {
                out += "        for any imported in pe.imports : (imported[\"dll\"] contains \"KERNEL32.dll\") and\n";
                out += "        process.name == \"";
                out += target_process_name;
                out += "\"";
            } else if (uses_or_process_names(scenario)) {
                out += "        process.name == \"";
                out += target_process_name;
                out += "\" or process.name == \"";
                out += alternate_process_name;
                out += "\"";
            } else if (uses_selectivity_feedback_inventory(scenario)) {
                out += "        process.architecture == \"x64\" and\n";
                out += "        process.name == \"";
                out += target_process_name;
                out += "\"";
            } else {
                out += "        process.name == \"";
                out += target_process_name;
                out += "\"";
            }
            if (!uses_production_scale_validation(scenario) && uses_mixed_rule_shapes(scenario) && (index % 3u) == 2u) {
                out += " and\n";
                out += "        with pname = process.name : (pname == \"";
                out += target_process_name;
                out += "\")";
            }
            if (!uses_production_scale_validation(scenario) && with_expensive_pe &&
                !(uses_mixed_rule_shapes(scenario) && (index % 3u) == 1u)) {
                out += " and\n";
                out += "        for any imported in pe.imports : (imported[\"dll\"] contains \"KERNEL32.dll\")";
            }
            out += "\n";
            out += "}\n\n";
        }
        return out;
    }

    [[nodiscard]] std::vector<rule_engine::Subject> synthetic_subjects(const std::size_t subject_count) {
        std::vector<rule_engine::Subject> out;
        out.reserve(subject_count);
        for (std::size_t index = 0; index < subject_count; ++index) {
            out.push_back(rule_engine::Subject {
                .kind = "process",
                .id = "pid:" + std::to_string(index),
            });
        }
        return out;
    }

    [[nodiscard]] std::string process_name_for_subject(const std::size_t subject_index, const std::size_t match_every,
                                                       const std::string_view scenario) {
        if (uses_broad_process_names(scenario)) {
            return std::string {target_process_name};
        }
        if (uses_empty_process_names(scenario)) {
            return std::string {benign_process_name};
        }
        if (uses_discovery_gate_empty_pack(scenario)) {
            return std::string {benign_process_name};
        }
        if (uses_production_scale_validation(scenario)) {
            return (subject_index % match_every) == 0u ? std::string {target_process_name} :
                                                         std::string {benign_process_name};
        }
        if (uses_or_process_names(scenario)) {
            const auto position = subject_index % match_every;
            if (position == 0u) {
                return std::string {target_process_name};
            }
            if (match_every > 1u && position == 1u) {
                return std::string {alternate_process_name};
            }
            return std::string {benign_process_name};
        }
        return (subject_index % match_every) == 0u ? std::string {target_process_name} :
                                                     std::string {benign_process_name};
    }

    [[nodiscard]] rule_engine::Fact process_name_fact(const rule_engine::Subject &subject, std::string name) {
        return rule_engine::Fact {
            .subject_id = subject.id,
            .key = std::string {process_name_key},
            .value = rule_engine::Value::string(std::move(name)),
            .status = rule_engine::FactStatus::available,
            .diagnostic = {},
            .ttl = std::chrono::seconds {0},
        };
    }

    [[nodiscard]] rule_engine::Fact process_architecture_fact(const rule_engine::Subject &subject) {
        return rule_engine::Fact {
            .subject_id = subject.id,
            .key = "process.architecture",
            .value = rule_engine::Value::string("x64"),
            .status = rule_engine::FactStatus::available,
            .diagnostic = {},
            .ttl = std::chrono::seconds {0},
        };
    }

    [[nodiscard]] rule_engine::Fact unavailable_fact(const rule_engine::Subject &subject, std::string key) {
        return rule_engine::Fact {
            .subject_id = subject.id,
            .key = std::move(key),
            .value = rule_engine::Value::undefined(),
            .status = rule_engine::FactStatus::unavailable,
            .diagnostic = "synthetic benchmark provider does not implement this fact",
            .ttl = std::chrono::seconds {0},
        };
    }

    [[nodiscard]] rule_engine::FactCache simulation_fact_cache(const std::vector<rule_engine::Subject> &subjects,
                                                               const std::size_t match_every,
                                                               const std::string_view scenario) {
        rule_engine::FactCache facts;
        for (std::size_t subject_index = 0; subject_index < subjects.size(); ++subject_index) {
            facts.store(process_name_fact(subjects[subject_index],
                                          process_name_for_subject(subject_index, match_every, scenario)));
            if (uses_selectivity_feedback_inventory(scenario)) {
                facts.store(process_architecture_fact(subjects[subject_index]));
            }
            if (uses_expensive_pe_branch(scenario)) {
                facts.store(unavailable_fact(subjects[subject_index], "pe.imports"));
            }
        }
        return facts;
    }

    [[nodiscard]] std::vector<rule_engine::optimizer::CandidateProviderResult>
    synthetic_candidate_provider_results(const rule_engine::optimizer::CandidateProviderRequestPlan &plan,
                                         const std::vector<rule_engine::Subject> &subjects,
                                         const std::size_t match_every, const std::string_view scenario) {
        std::vector<rule_engine::optimizer::CandidateProviderResult> out;
        out.reserve(plan.requests.size());
        for (const auto &request : plan.requests) {
            rule_engine::optimizer::CandidateProviderResult result {
                .request_id = request.id,
                .subject_ids = {},
                .available = true,
                .diagnostic = {},
            };
            if (uses_unavailable_candidate_provider(scenario)) {
                result.available = false;
                result.diagnostic = "synthetic benchmark candidate provider unavailable";
                out.push_back(std::move(result));
                continue;
            }
            if (request.filter_key == "process.inventory.by_image_name" && request.argument_kind == "string") {
                for (std::size_t subject_index = 0; subject_index < subjects.size(); ++subject_index) {
                    if (process_name_for_subject(subject_index, match_every, scenario) == request.argument_value) {
                        result.subject_ids.push_back(subjects[subject_index].id);
                    }
                }
            } else {
                result.available = false;
                result.diagnostic = "synthetic benchmark candidate provider does not implement this filter";
            }
            out.push_back(std::move(result));
        }
        return out;
    }

    [[nodiscard]] std::vector<rule_engine::optimizer::StaticFactCacheCandidate>
    synthetic_static_fact_cache_candidates(const std::vector<rule_engine::Subject> &subjects) {
        std::vector<rule_engine::optimizer::StaticFactCacheCandidate> out;
        out.reserve(subjects.size() * 2u);
        const auto split = subjects.empty() ? 0u : subjects.size() / 2u;
        for (std::size_t index = 0; index < subjects.size(); ++index) {
            const auto changed_identity = index >= split;
            out.push_back(rule_engine::optimizer::StaticFactCacheCandidate {
                .subject_id = subjects[index].id,
                .route = "endpoint.process.image.pe",
                .key = "pe.imports",
                .cost_class = rule_engine::FactCostClass::broad_image_array,
                .identity =
                    rule_engine::optimizer::StaticFactCacheIdentity {
                        .path = "C:/Windows/System32/shared-image.exe",
                        .file_id = "volume:42:file:7",
                        .file_size = changed_identity ? 8192u : 4096u,
                        .last_write_time = changed_identity ? 2000u : 1000u,
                        .content_hash = changed_identity ? "sha256:bbb" : "sha256:aaa",
                        .signature_identity = changed_identity ? "catalog:changed" : "catalog:stable",
                        .scan_space_name = "process.image.bytes",
                        .scan_space_version = "v1",
                    },
                .content_addressable = true,
            });
            out.push_back(rule_engine::optimizer::StaticFactCacheCandidate {
                .subject_id = subjects[index].id,
                .route = std::string {process_snapshot_route},
                .key = std::string {process_name_key},
                .cost_class = rule_engine::FactCostClass::inventory,
                .identity = {},
                .content_addressable = false,
            });
        }
        return out;
    }

    [[nodiscard]] SchedulerControlSimulation simulate_scheduler_controls() {
        constexpr std::uint64_t simulated_clients {10000u};
        constexpr std::uint64_t timer_jitter_window_ms {300000u};
        constexpr std::uint64_t bucket_ms {1000u};
        constexpr std::uint64_t buckets {timer_jitter_window_ms / bucket_ms};
        constexpr std::uint64_t vm_worker_slots_per_bucket {32u};
        constexpr std::uint64_t provider_worker_slots_per_bucket {24u};
        const rule_engine::scheduler::EvaluationTimerPolicy policy {
            .cadence = std::chrono::milliseconds {0},
            .jitter_window = std::chrono::milliseconds {static_cast<std::chrono::milliseconds::rep>(
                timer_jitter_window_ms)},
            .sweep_deadline = std::chrono::seconds {30},
        };

        std::vector<rule_engine::scheduler::ClientEvaluationIdleState> clients;
        clients.reserve(simulated_clients);
        for (std::uint64_t index = 0; index < simulated_clients; ++index) {
            clients.push_back(rule_engine::scheduler::schedule_next_client_evaluation(
                "client:" + std::to_string(index), std::chrono::milliseconds {0}, policy,
                static_cast<std::uint32_t>(index)));
        }

        SchedulerControlSimulation out {
            .simulated_clients = simulated_clients,
            .timer_jitter_window_ms = timer_jitter_window_ms,
            .idle_state_bytes = static_cast<std::uint64_t>(clients.size() *
                                                           sizeof(rule_engine::scheduler::ClientEvaluationIdleState)),
        };

        std::vector<std::uint64_t> wakeups_by_bucket;
        wakeups_by_bucket.resize(buckets);
        for (const auto &client : clients) {
            const auto bucket =
                std::min<std::uint64_t>(static_cast<std::uint64_t>(client.next_due_at.count()) / bucket_ms,
                                        buckets - 1u);
            ++wakeups_by_bucket[bucket];
        }

        std::uint64_t vm_queue {};
        std::uint64_t provider_queue {};
        for (std::uint64_t bucket = 0; bucket < buckets; ++bucket) {
            const auto wakeups = wakeups_by_bucket[bucket];
            out.peak_wake_batch = std::max(out.peak_wake_batch, wakeups);

            vm_queue += wakeups;
            if (vm_queue > vm_worker_slots_per_bucket) {
                ++out.backpressure_events;
            }
            const auto vm_completed = std::min(vm_queue, vm_worker_slots_per_bucket);
            vm_queue -= vm_completed;
            out.peak_vm_queue_depth = std::max(out.peak_vm_queue_depth, vm_queue);

            provider_queue += vm_completed;
            if (provider_queue > provider_worker_slots_per_bucket) {
                ++out.backpressure_events;
            }
            const auto provider_completed = std::min(provider_queue, provider_worker_slots_per_bucket);
            provider_queue -= provider_completed;
            out.peak_provider_queue_depth = std::max(out.peak_provider_queue_depth, provider_queue);
        }

        while (vm_queue != 0u || provider_queue != 0u) {
            if (vm_queue != 0u) {
                if (vm_queue > vm_worker_slots_per_bucket) {
                    ++out.backpressure_events;
                }
                const auto vm_completed = std::min(vm_queue, vm_worker_slots_per_bucket);
                vm_queue -= vm_completed;
                provider_queue += vm_completed;
                out.peak_vm_queue_depth = std::max(out.peak_vm_queue_depth, vm_queue);
            }

            if (provider_queue > provider_worker_slots_per_bucket) {
                ++out.backpressure_events;
            }
            const auto provider_completed = std::min(provider_queue, provider_worker_slots_per_bucket);
            provider_queue -= provider_completed;
            out.peak_provider_queue_depth = std::max(out.peak_provider_queue_depth, provider_queue);
        }

        return out;
    }

    void append_optimizer_trace_records(rule_engine::benchmark::BenchmarkReport &report,
                                        const std::vector<rule_engine::optimizer::OptimizerTraceEvent> &events) {
        for (const auto &event : events) {
            if (report.optimizer_trace_records.size() >= max_benchmark_optimizer_trace_records) {
                return;
            }
            report.optimizer_trace_records.push_back(rule_engine::benchmark::BenchmarkOptimizerTraceRecord {
                .event = event.event,
                .predicate_id = event.predicate_id,
                .rule_identifier = event.rule_identifier,
                .subject_id = event.subject_id,
                .reason = event.reason,
                .cost_class = std::string {rule_engine::fact_cost_class_name(event.cost_class)},
                .source = event.span.source,
                .source_id = event.span.source_id,
                .span_start = event.span.start,
                .span_end = event.span.end,
                .matched_subject_count = event.matched_subject_count,
                .candidate_subject_count = event.candidate_subject_count,
                .candidate_set_bytes = event.candidate_set_bytes,
            });
        }
    }

    void append_json_string(std::string &out, const std::string_view value) {
        out.push_back('"');
        for (const auto raw : value) {
            const auto ch = static_cast<unsigned char>(raw);
            switch (ch) {
                case '"': out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\b': out += "\\b"; break;
                case '\f': out += "\\f"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default:
                    if (ch < 0x20u) {
                        constexpr char digits[] = "0123456789abcdef";
                        out += "\\u00";
                        out.push_back(digits[(ch >> 4u) & 0x0fu]);
                        out.push_back(digits[ch & 0x0fu]);
                        break;
                    }
                    out.push_back(static_cast<char>(ch));
                    break;
            }
        }
        out.push_back('"');
    }

    void append_key(std::string &out, const std::string_view key) {
        append_json_string(out, key);
        out.push_back(':');
    }

    void append_key_string(std::string &out, const std::string_view key, const std::string_view value) {
        append_key(out, key);
        append_json_string(out, value);
    }

    void append_key_u64(std::string &out, const std::string_view key, const std::uint64_t value) {
        append_key(out, key);
        out += std::to_string(value);
    }

    void append_key_size(std::string &out, const std::string_view key, const std::size_t value) {
        append_key(out, key);
        out += std::to_string(value);
    }

    void append_key_string_array(std::string &out, const std::string_view key, const std::vector<std::string> &values) {
        append_key(out, key);
        out.push_back('[');
        for (std::size_t index = 0; index < values.size(); ++index) {
            if (index != 0u) {
                out.push_back(',');
            }
            append_json_string(out, values[index]);
        }
        out.push_back(']');
    }

    [[nodiscard]] std::string markdown_optimizer_flags(const std::vector<std::string> &flags) {
        if (flags.empty()) {
            return "none";
        }

        std::string out;
        for (std::size_t index = 0; index < flags.size(); ++index) {
            if (index != 0u) {
                out += ", ";
            }
            out += flags[index];
        }
        return out;
    }

    void append_metric_json(std::string &out, const rule_engine::benchmark::BenchmarkMetrics &metrics) {
        out.push_back('{');
        append_key_u64(out, "sweepWallTimeUs", metrics.sweep_wall_time_us);
        out.push_back(',');
        append_key_u64(out, "subjectsEvaluated", metrics.subjects_evaluated);
        out.push_back(',');
        append_key_u64(out, "providerRounds", metrics.provider_rounds);
        out.push_back(',');
        append_key_u64(out, "providerElapsedUs", metrics.provider_elapsed_us);
        out.push_back(',');
        append_key_u64(out, "factsRequested", metrics.facts_requested);
        out.push_back(',');
        append_key_u64(out, "factsReturned", metrics.facts_returned);
        out.push_back(',');
        append_key_u64(out, "returnedPayloadBytes", metrics.returned_payload_bytes);
        out.push_back(',');
        append_key_u64(out, "expressionEvaluations", metrics.expression_evaluations);
        out.push_back(',');
        append_key_u64(out, "exactVmRuleExecutions", metrics.exact_vm_rule_executions);
        out.push_back(',');
        append_key_u64(out, "ruleMatches", metrics.rule_matches);
        out.push_back(',');
        append_key_u64(out, "rulesPrunedBeforeExactVm", metrics.rules_pruned_before_exact_vm);
        out.push_back(',');
        append_key_u64(out, "droppedRuleBranches", metrics.dropped_rule_branches);
        out.push_back(',');
        append_key_u64(out, "expensiveProviderReaches", metrics.expensive_provider_reaches);
        out.push_back(',');
        append_key_u64(out, "canonicalPredicates", metrics.canonical_predicates);
        out.push_back(',');
        append_key_u64(out, "exactVmOnlyExpressions", metrics.exact_vm_only_expressions);
        out.push_back(',');
        append_key_u64(out, "nonselectivePredicates", metrics.nonselective_predicates);
        out.push_back(',');
        append_key_u64(out, "optimizerTraceEvents", metrics.optimizer_trace_events);
        out.push_back(',');
        append_key_u64(out, "discoveryGateCount", metrics.discovery_gate_count);
        out.push_back(',');
        append_key_u64(out, "discoveryGateEvaluations", metrics.discovery_gate_evaluations);
        out.push_back(',');
        append_key_u64(out, "discoveryGatePackSkips", metrics.discovery_gate_pack_skips);
        out.push_back(',');
        append_key_u64(out, "factCacheLookups", metrics.fact_cache_lookups);
        out.push_back(',');
        append_key_u64(out, "factCacheHits", metrics.fact_cache_hits);
        out.push_back(',');
        append_key_u64(out, "factCacheMisses", metrics.fact_cache_misses);
        out.push_back(',');
        append_key_u64(out, "factCacheLookupProbes", metrics.fact_cache_lookup_probes);
        out.push_back(',');
        append_key_u64(out, "peakCandidateSetSubjects", metrics.peak_candidate_set_subjects);
        out.push_back(',');
        append_key_u64(out, "peakCandidateSetBytes", metrics.peak_candidate_set_bytes);
        out.push_back(',');
        append_key_u64(out, "lazyProviderBatches", metrics.lazy_provider_batches);
        out.push_back(',');
        append_key_u64(out, "lazyProviderFactsRequested", metrics.lazy_provider_facts_requested);
        out.push_back(',');
        append_key_u64(out, "lazyProviderFactsAvoided", metrics.lazy_provider_facts_avoided);
        out.push_back(',');
        append_key_u64(out, "lazyProviderExpensiveFactsRequested", metrics.lazy_provider_expensive_facts_requested);
        out.push_back(',');
        append_key_u64(out, "lazyProviderExpensiveFactsAvoided", metrics.lazy_provider_expensive_facts_avoided);
        out.push_back(',');
        append_key_u64(out, "candidateProviderRequests", metrics.candidate_provider_requests);
        out.push_back(',');
        append_key_u64(out, "candidateProviderSubjectsReturned", metrics.candidate_provider_subjects_returned);
        out.push_back(',');
        append_key_u64(out, "candidateProviderBroadResults", metrics.candidate_provider_broad_results);
        out.push_back(',');
        append_key_u64(out, "candidateProviderFallbackPredicateEvaluations",
                       metrics.candidate_provider_fallback_predicate_evaluations);
        out.push_back(',');
        append_key_u64(out, "prefilteredExactVmRuleExecutions", metrics.prefiltered_exact_vm_rule_executions);
        out.push_back(',');
        append_key_u64(out, "prefilteredExactVmRuleExecutionsAvoided",
                       metrics.prefiltered_exact_vm_rule_executions_avoided);
        out.push_back(',');
        append_key_u64(out, "prefilteredExactVmRuleSkipTraceEvents",
                       metrics.prefiltered_exact_vm_rule_skip_trace_events);
        out.push_back(',');
        append_key_u64(out, "prefilteredResultMismatches", metrics.prefiltered_result_mismatches);
        out.push_back(',');
        append_key_u64(out, "prefilteredIncompleteSubjects", metrics.prefiltered_incomplete_subjects);
        out.push_back(',');
        append_key_u64(out, "optimizerPlanPrefilterExactVmRuleExecutions",
                       metrics.optimizer_plan_prefilter_exact_vm_rule_executions);
        out.push_back(',');
        append_key_u64(out, "optimizerPlanPrefilterExactVmRuleExecutionsAvoided",
                       metrics.optimizer_plan_prefilter_exact_vm_rule_executions_avoided);
        out.push_back(',');
        append_key_u64(out, "optimizerPlanPrefilterExactVmRuleSkipTraceEvents",
                       metrics.optimizer_plan_prefilter_exact_vm_rule_skip_trace_events);
        out.push_back(',');
        append_key_u64(out, "optimizerPlanPrefilterResultMismatches",
                       metrics.optimizer_plan_prefilter_result_mismatches);
        out.push_back(',');
        append_key_u64(out, "optimizerPlanPrefilterIncompleteSubjects",
                       metrics.optimizer_plan_prefilter_incomplete_subjects);
        out.push_back(',');
        append_key_u64(out, "optimizerPlanPrefilterReplaySubjectMismatches",
                       metrics.optimizer_plan_prefilter_replay_subject_mismatches);
        out.push_back(',');
        append_key_u64(out, "optimizerPlanPrefilterReplayRuleResultMismatches",
                       metrics.optimizer_plan_prefilter_replay_rule_result_mismatches);
        out.push_back(',');
        append_key_u64(out, "optimizerPlanPrefilterReplayTraceEventMismatches",
                       metrics.optimizer_plan_prefilter_replay_trace_event_mismatches);
        out.push_back(',');
        append_key_u64(out, "optimizerPlanPrefilterReplayMetricMismatches",
                       metrics.optimizer_plan_prefilter_replay_metric_mismatches);
        out.push_back(',');
        append_key_u64(out, "selectivityFeedbackProfilePredicates", metrics.selectivity_feedback_profile_predicates);
        out.push_back(',');
        append_key_u64(out, "selectivityFeedbackReorderedPredicates",
                       metrics.selectivity_feedback_reordered_predicates);
        out.push_back(',');
        append_key_u64(out, "watchdogBudgetEvaluations", metrics.watchdog_budget_evaluations);
        out.push_back(',');
        append_key_u64(out, "watchdogBudgetEvents", metrics.watchdog_budget_events);
        out.push_back(',');
        append_key_u64(out, "predicateWatchdogBudgetEvents", metrics.predicate_watchdog_budget_events);
        out.push_back(',');
        append_key_u64(out, "routeWatchdogBudgetEvents", metrics.route_watchdog_budget_events);
        out.push_back(',');
        append_key_u64(out, "watchdogExplicitBudgetDiagnostics", metrics.watchdog_explicit_budget_diagnostics);
        out.push_back(',');
        append_key_u64(out, "watchdogDeferredBranchDiagnostics", metrics.watchdog_deferred_branch_diagnostics);
        out.push_back(',');
        append_key_u64(out, "watchdogSubstitutedGateDiagnostics", metrics.watchdog_substituted_gate_diagnostics);
        out.push_back(',');
        append_key_u64(out, "watchdogTimeoutDiagnostics", metrics.watchdog_timeout_diagnostics);
        out.push_back(',');
        append_key_u64(out, "watchdogUnavailableDiagnostics", metrics.watchdog_unavailable_diagnostics);
        out.push_back(',');
        append_key_u64(out, "staticFactCacheLookups", metrics.static_fact_cache_lookups);
        out.push_back(',');
        append_key_u64(out, "staticFactCacheHits", metrics.static_fact_cache_hits);
        out.push_back(',');
        append_key_u64(out, "staticFactCacheMisses", metrics.static_fact_cache_misses);
        out.push_back(',');
        append_key_u64(out, "staticFactCacheReuses", metrics.static_fact_cache_reuses);
        out.push_back(',');
        append_key_u64(out, "staticFactCacheInvalidations", metrics.static_fact_cache_invalidations);
        out.push_back(',');
        append_key_u64(out, "staticFactCacheSubjectScoped", metrics.static_fact_cache_subject_scoped);
        out.push_back(',');
        append_key_u64(out, "schedulerSimulatedClients", metrics.scheduler_simulated_clients);
        out.push_back(',');
        append_key_u64(out, "schedulerTimerJitterWindowMs", metrics.scheduler_timer_jitter_window_ms);
        out.push_back(',');
        append_key_u64(out, "schedulerPeakWakeBatch", metrics.scheduler_peak_wake_batch);
        out.push_back(',');
        append_key_u64(out, "schedulerPeakVmQueueDepth", metrics.scheduler_peak_vm_queue_depth);
        out.push_back(',');
        append_key_u64(out, "schedulerPeakProviderQueueDepth", metrics.scheduler_peak_provider_queue_depth);
        out.push_back(',');
        append_key_u64(out, "schedulerBackpressureEvents", metrics.scheduler_backpressure_events);
        out.push_back(',');
        append_key_u64(out, "schedulerDeadlineMisses", metrics.scheduler_deadline_misses);
        out.push_back(',');
        append_key_u64(out, "schedulerIdleStateBytes", metrics.scheduler_idle_state_bytes);
        out.push_back(',');
        append_key_u64(out, "comparisonExactVmRuleExecutionsAvoided",
                       metrics.comparison_exact_vm_rule_executions_avoided);
        out.push_back(',');
        append_key_u64(out, "comparisonExpensiveProviderFactsAvoided",
                       metrics.comparison_expensive_provider_facts_avoided);
        out.push_back(',');
        append_key_u64(out, "comparisonOptimizedExpressionEvaluations",
                       metrics.comparison_optimized_expression_evaluations);
        out.push_back(',');
        append_key_u64(out, "comparisonExpressionEvaluationsAvoided",
                       metrics.comparison_expression_evaluations_avoided);
        out.push_back(',');
        append_key_u64(out, "comparisonResultMismatches", metrics.comparison_result_mismatches);
        out.push_back(',');
        append_key_u64(out, "comparisonIncompleteSubjects", metrics.comparison_incomplete_subjects);
        out.push_back(',');
        append_key_u64(out, "comparisonBroadNonselectivePredicates", metrics.comparison_broad_nonselective_predicates);
        out.push_back(',');
        append_key_u64(out, "comparisonBroadPeakCandidateSetSubjects",
                       metrics.comparison_broad_peak_candidate_set_subjects);
        out.push_back(',');
        append_key_u64(out, "comparisonBroadPeakCandidateSetBytes", metrics.comparison_broad_peak_candidate_set_bytes);
        out.push_back(',');
        append_key_u64(out, "comparisonBroadWorkloadBounded", metrics.comparison_broad_workload_bounded);
        out.push_back('}');
    }

    void append_markdown_metric(std::string &out, const std::string_view name, const std::uint64_t value) {
        out += "| ";
        out += name;
        out += " | ";
        out += std::to_string(value);
        out += " |\n";
    }

    void append_predicate_observations_json(
        std::string &out, const std::vector<rule_engine::benchmark::BenchmarkPredicateObservation> &observations) {
        out.push_back('[');
        for (std::size_t index = 0; index < observations.size(); ++index) {
            if (index != 0u) {
                out.push_back(',');
            }
            const auto &observation = observations[index];
            out.push_back('{');
            append_key_string(out, "id", observation.predicate_id);
            out.push_back(',');
            append_key_string(out, "costClass", observation.cost_class);
            out.push_back(',');
            append_key_u64(out, "observedSelectivityPpm", observation.observed_selectivity_ppm);
            out.push_back('}');
        }
        out.push_back(']');
    }

    void append_optimizer_trace_records_json(
        std::string &out, const std::vector<rule_engine::benchmark::BenchmarkOptimizerTraceRecord> &records) {
        out.push_back('[');
        for (std::size_t index = 0; index < records.size(); ++index) {
            if (index != 0u) {
                out.push_back(',');
            }
            const auto &record = records[index];
            out.push_back('{');
            append_key_string(out, "event", record.event);
            out.push_back(',');
            append_key_string(out, "predicateId", record.predicate_id);
            out.push_back(',');
            append_key_string(out, "rule", record.rule_identifier);
            out.push_back(',');
            append_key_string(out, "subject", record.subject_id);
            out.push_back(',');
            append_key_string(out, "reason", record.reason);
            out.push_back(',');
            append_key_string(out, "costClass", record.cost_class);
            out.push_back(',');
            append_key(out, "sourceSpan");
            out.push_back('{');
            append_key_string(out, "source", record.source);
            out.push_back(',');
            append_key_u64(out, "sourceId", record.source_id);
            out.push_back(',');
            append_key_size(out, "start", record.span_start);
            out.push_back(',');
            append_key_size(out, "end", record.span_end);
            out.push_back('}');
            out.push_back(',');
            append_key_u64(out, "matchedSubjectCount", record.matched_subject_count);
            out.push_back(',');
            append_key_u64(out, "candidateSubjectCount", record.candidate_subject_count);
            out.push_back(',');
            append_key_u64(out, "candidateSetBytes", record.candidate_set_bytes);
            out.push_back('}');
        }
        out.push_back(']');
    }

    [[nodiscard]] std::string markdown_table_cell(const std::string_view value) {
        std::string out;
        out.reserve(value.size());
        for (const auto ch : value) {
            if (ch == '|') {
                out += "\\|";
                continue;
            }
            if (ch == '\r' || ch == '\n') {
                out.push_back(' ');
                continue;
            }
            out.push_back(ch);
        }
        return out;
    }
} // namespace

namespace rule_engine::benchmark {
    std::expected<BenchmarkReport, ErrorSet> run_baseline_benchmark(const BenchmarkOptions &options) {
        if (options.subject_count == 0u) {
            return std::unexpected(single_error("benchmark", "subject_count must be greater than zero"));
        }
        if (options.rule_count == 0u) {
            return std::unexpected(single_error("benchmark", "rule_count must be greater than zero"));
        }

        const auto source = synthetic_rule_source(options.rule_count, options.scenario);
        auto parsed = parse_source("synthetic-benchmark.yar", source);
        if (!parsed) {
            return std::unexpected(std::move(parsed.error()));
        }

        auto verified = verify(*parsed, default_module_registry());
        if (!verified) {
            return std::unexpected(std::move(verified.error()));
        }

        BenchmarkReport report;
        report.metadata.scenario = options.scenario;
        report.metadata.seed = options.seed;
        report.metadata.subject_count = options.subject_count;
        report.metadata.rule_count = options.rule_count;
        const auto match_every = normalized_match_every(options.match_every);
        report.metadata.workload_class = workload_class_for(options.scenario);
        report.metadata.selectivity = selectivity_for(options.scenario, match_every);
        report.metadata.build_type = build_type_name();
        report.metadata.optimizer_flags = optimizer_flags_for(options);
        if (options.simulate_optimization_comparison) {
            report.metadata.mode = "baseline_with_optimization_comparison_simulation";
        } else if (options.simulate_scheduler_controls) {
            report.metadata.mode = "baseline_with_scheduler_control_simulation";
            report.metadata.benchmark_tier = "stress";
        } else if (options.simulate_candidate_provider && options.simulate_optimizer_plan_prefilter &&
                   options.simulate_lazy_provider_expansion) {
            report.metadata.mode =
                "baseline_with_optimizer_plan_prefilter_candidate_provider_and_lazy_provider_simulation";
        } else if (options.simulate_candidate_provider && options.simulate_optimizer_plan_prefilter) {
            report.metadata.mode = "baseline_with_optimizer_plan_prefilter_candidate_provider_simulation";
        } else if (options.simulate_candidate_provider && options.simulate_lazy_provider_expansion) {
            report.metadata.mode = "baseline_with_candidate_provider_and_lazy_provider_simulation";
        } else if (options.simulate_optimizer_plan_prefilter && options.simulate_lazy_provider_expansion) {
            report.metadata.mode = "baseline_with_optimizer_plan_prefilter_and_lazy_provider_simulation";
        } else if (options.simulate_selectivity_feedback) {
            report.metadata.mode = "baseline_with_selectivity_feedback_simulation";
        } else if (options.simulate_watchdog_enforcement && options.simulate_prefiltered_evaluation &&
                   options.simulate_lazy_provider_expansion) {
            report.metadata.mode =
                "baseline_with_prefiltered_evaluation_lazy_provider_and_watchdog_enforcement_simulation";
        } else if (options.simulate_watchdog_enforcement && options.simulate_lazy_provider_expansion) {
            report.metadata.mode = "baseline_with_watchdog_enforcement_and_lazy_provider_simulation";
        } else if (options.simulate_watchdogs && options.simulate_prefiltered_evaluation &&
                   options.simulate_lazy_provider_expansion) {
            report.metadata.mode = "baseline_with_prefiltered_evaluation_lazy_provider_and_watchdog_simulation";
        } else if (options.simulate_watchdogs && options.simulate_lazy_provider_expansion) {
            report.metadata.mode = "baseline_with_watchdog_and_lazy_provider_simulation";
        } else if (options.simulate_watchdog_enforcement) {
            report.metadata.mode = "baseline_with_watchdog_enforcement_simulation";
        } else if (options.simulate_watchdogs) {
            report.metadata.mode = "baseline_with_watchdog_simulation";
        } else if (options.simulate_static_fact_cache) {
            report.metadata.mode = "baseline_with_static_fact_cache_simulation";
        } else if (options.simulate_discovery_gates && !options.simulate_shared_predicate_dag &&
                   !options.simulate_lazy_provider_expansion && !options.simulate_candidate_provider &&
                   !options.simulate_prefiltered_evaluation) {
            report.metadata.mode = "baseline_with_discovery_gate_simulation";
        } else if (options.simulate_candidate_provider) {
            report.metadata.mode = "baseline_with_candidate_provider_simulation";
        } else if (options.simulate_prefiltered_evaluation && options.simulate_lazy_provider_expansion) {
            report.metadata.mode = "baseline_with_prefiltered_evaluation_and_lazy_provider_simulation";
        } else if (options.simulate_prefiltered_evaluation) {
            report.metadata.mode = "baseline_with_prefiltered_evaluation_simulation";
        } else if (options.simulate_optimizer_plan_prefilter) {
            report.metadata.mode = "baseline_with_optimizer_plan_prefilter_simulation";
        } else if (options.simulate_shared_predicate_dag && options.simulate_lazy_provider_expansion) {
            report.metadata.mode = "baseline_with_shared_predicate_dag_and_lazy_provider_simulation";
        } else if (options.simulate_shared_predicate_dag) {
            report.metadata.mode = "baseline_with_shared_predicate_dag_simulation";
        } else if (options.simulate_lazy_provider_expansion) {
            report.metadata.mode = "baseline_with_lazy_provider_simulation";
        }

        const auto started = std::chrono::steady_clock::now();
        const auto subjects = synthetic_subjects(options.subject_count);
        constexpr std::size_t max_rounds {16};
        EvaluationInstrumentation instrumentation;

        for (std::size_t subject_index = 0; subject_index < subjects.size(); ++subject_index) {
            FactCache facts;
            bool complete {};
            for (std::size_t round = 0; round < max_rounds; ++round) {
                const Evaluator evaluator {*verified, facts, EvaluationOptions {.instrumentation = &instrumentation}};
                auto step = evaluator.step(subjects[subject_index]);
                if (step.state == EvaluationState::complete) {
                    complete = true;
                    ++report.metrics.subjects_evaluated;
                    report.metrics.exact_vm_rule_executions +=
                        reportable_rule_result_count(*verified, step.rule_results);
                    for (const auto &result : step.rule_results) {
                        if (result.matched && reportable_rule_identifier(*verified, result.identifier)) {
                            ++report.metrics.rule_matches;
                        }
                    }
                    break;
                }

                ++report.metrics.provider_rounds;
                const auto provider_started = std::chrono::steady_clock::now();
                for (const auto &batch : step.requests) {
                    if (batch.route != process_snapshot_route) {
                        report.metrics.expensive_provider_reaches += batch.keys.size();
                    }
                    for (const auto &key : batch.keys) {
                        ++report.metrics.facts_requested;
                        Fact fact = unavailable_fact(subjects[subject_index], key);
                        if (key == process_name_key) {
                            fact = process_name_fact(
                                subjects[subject_index],
                                process_name_for_subject(subject_index, match_every, options.scenario));
                        } else if (uses_selectivity_feedback_inventory(options.scenario) &&
                                   key == "process.architecture") {
                            fact = process_architecture_fact(subjects[subject_index]);
                        }
                        if (const auto *value = fact.value.as_string(); value != nullptr) {
                            report.metrics.returned_payload_bytes += value->size();
                        } else {
                            report.metrics.returned_payload_bytes += fact.diagnostic.size();
                        }
                        ++report.metrics.facts_returned;
                        facts.store(std::move(fact));
                    }
                }
                const auto provider_elapsed = std::chrono::steady_clock::now() - provider_started;
                report.metrics.provider_elapsed_us += static_cast<std::uint64_t>(
                    std::chrono::duration_cast<std::chrono::microseconds>(provider_elapsed).count());
            }

            if (!complete) {
                return std::unexpected(single_error("benchmark", "baseline benchmark did not converge"));
            }

            const auto cache_stats = facts.stats();
            report.metrics.fact_cache_lookups += cache_stats.lookups;
            report.metrics.fact_cache_hits += cache_stats.hits;
            report.metrics.fact_cache_misses += cache_stats.misses;
            report.metrics.fact_cache_lookup_probes += cache_stats.lookup_probes;
        }

        report.metrics.expression_evaluations = instrumentation.expression_evaluations;
        if (options.simulate_static_fact_cache) {
            const auto static_cache =
                optimizer::simulate_static_fact_cache(synthetic_static_fact_cache_candidates(subjects));
            report.metrics.static_fact_cache_lookups = static_cache.lookups;
            report.metrics.static_fact_cache_hits = static_cache.cache_hits;
            report.metrics.static_fact_cache_misses = static_cache.cache_misses;
            report.metrics.static_fact_cache_reuses = static_cache.accepted_reuses;
            report.metrics.static_fact_cache_invalidations = static_cache.invalidations;
            report.metrics.static_fact_cache_subject_scoped = static_cache.subject_scoped_facts;
            report.metrics.optimizer_trace_events += static_cast<std::uint64_t>(static_cache.trace_events.size());
            append_optimizer_trace_records(report, static_cache.trace_events);
        }
        if (options.simulate_scheduler_controls) {
            const auto scheduler = simulate_scheduler_controls();
            report.metrics.scheduler_simulated_clients = scheduler.simulated_clients;
            report.metrics.scheduler_timer_jitter_window_ms = scheduler.timer_jitter_window_ms;
            report.metrics.scheduler_peak_wake_batch = scheduler.peak_wake_batch;
            report.metrics.scheduler_peak_vm_queue_depth = scheduler.peak_vm_queue_depth;
            report.metrics.scheduler_peak_provider_queue_depth = scheduler.peak_provider_queue_depth;
            report.metrics.scheduler_backpressure_events = scheduler.backpressure_events;
            report.metrics.scheduler_deadline_misses = scheduler.deadline_misses;
            report.metrics.scheduler_idle_state_bytes = scheduler.idle_state_bytes;
        }

        if (options.simulate_static_fact_cache && !options.simulate_discovery_gates &&
            !options.simulate_shared_predicate_dag && !options.simulate_lazy_provider_expansion &&
            !options.simulate_candidate_provider && !options.simulate_prefiltered_evaluation &&
            !options.simulate_optimizer_plan_prefilter && !options.simulate_watchdogs &&
            !options.simulate_watchdog_enforcement && !options.simulate_selectivity_feedback &&
            !options.simulate_scheduler_controls && !options.simulate_optimization_comparison) {
            const auto elapsed = std::chrono::steady_clock::now() - started;
            report.metrics.sweep_wall_time_us =
                static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count());
            return report;
        }

        if (options.simulate_discovery_gates || options.simulate_shared_predicate_dag ||
            options.simulate_lazy_provider_expansion || options.simulate_candidate_provider ||
            options.simulate_prefiltered_evaluation || options.simulate_optimizer_plan_prefilter ||
            options.simulate_watchdogs || options.simulate_watchdog_enforcement ||
            options.simulate_selectivity_feedback || options.simulate_optimization_comparison) {
            const auto canonical = optimizer::extract_canonical_predicates(*verified);
            report.metrics.canonical_predicates = static_cast<std::uint64_t>(canonical.predicates.size());
            report.metrics.exact_vm_only_expressions = static_cast<std::uint64_t>(canonical.exact_vm_only.size());
            auto simulation_facts = simulation_fact_cache(subjects, match_every, options.scenario);
            if (options.simulate_discovery_gates) {
                const auto discovery_plan = optimizer::plan_discovery_gates(*verified, canonical);
                const auto discovery_simulation =
                    optimizer::simulate_discovery_gates(*verified, discovery_plan, subjects, simulation_facts);
                report.metrics.discovery_gate_count =
                    static_cast<std::uint64_t>(discovery_simulation.plan.gates.size());
                report.metrics.discovery_gate_evaluations = discovery_simulation.gate_evaluations;
                report.metrics.discovery_gate_pack_skips = discovery_simulation.pack_skipped ? 1u : 0u;
                report.metrics.optimizer_trace_events +=
                    static_cast<std::uint64_t>(discovery_simulation.trace_events.size());
                append_optimizer_trace_records(report, discovery_simulation.trace_events);
            }
            if (!options.simulate_shared_predicate_dag && !options.simulate_lazy_provider_expansion &&
                !options.simulate_candidate_provider && !options.simulate_prefiltered_evaluation &&
                !options.simulate_optimizer_plan_prefilter && !options.simulate_watchdogs &&
                !options.simulate_watchdog_enforcement && !options.simulate_selectivity_feedback &&
                !options.simulate_optimization_comparison) {
                const auto elapsed = std::chrono::steady_clock::now() - started;
                report.metrics.sweep_wall_time_us =
                    static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count());
                return report;
            }
            auto simulation = optimizer::SharedPredicateDagSimulation {};
            auto optimizer_plan_prefilter = optimizer::OptimizedEvaluationSweep {};
            auto optimizer_plan_for_replay = optimizer::OptimizerPlan {};
            std::vector<optimizer::CandidateProviderResult> optimizer_plan_candidate_results_for_replay;
            bool has_optimizer_plan_prefilter {};
            bool has_optimizer_plan_for_replay {};
            bool replay_optimizer_plan_with_candidate_results {};
            if (options.simulate_selectivity_feedback) {
                const auto static_simulation =
                    optimizer::simulate_shared_predicate_dag(*verified, canonical, subjects, simulation_facts);
                const auto profile = optimizer::build_selectivity_profile(static_simulation);
                report.metrics.selectivity_feedback_profile_predicates =
                    static_cast<std::uint64_t>(profile.predicates.size());
                simulation =
                    optimizer::simulate_shared_predicate_dag(*verified, canonical, subjects, simulation_facts, profile);
                report.metrics.selectivity_feedback_reordered_predicates =
                    count_changed_order_positions(static_simulation.predicate_order, simulation.predicate_order);
            } else if (options.simulate_candidate_provider) {
                if (options.simulate_optimizer_plan_prefilter) {
                    optimizer_plan_for_replay = optimizer::build_optimizer_plan(*verified);
                    has_optimizer_plan_for_replay = true;
                }
                const auto candidate_request_plan =
                    options.simulate_optimizer_plan_prefilter ?
                        optimizer::CandidateProviderRequestPlan {
                            .requests = optimizer_plan_for_replay.candidate_provider_requests,
                        } :
                        optimizer::plan_candidate_provider_requests(canonical);
                const auto candidate_results = synthetic_candidate_provider_results(candidate_request_plan, subjects,
                                                                                    match_every, options.scenario);
                if (options.simulate_optimizer_plan_prefilter) {
                    optimizer_plan_candidate_results_for_replay = candidate_results;
                    replay_optimizer_plan_with_candidate_results = true;
                    optimizer_plan_prefilter = optimizer::evaluate_with_optimizer_plan(
                        *verified, optimizer_plan_for_replay, subjects, simulation_facts,
                        optimizer_plan_candidate_results_for_replay);
                    simulation = optimizer_plan_prefilter.shared_dag;
                    has_optimizer_plan_prefilter = true;
                    report.metrics.candidate_provider_requests = optimizer_plan_prefilter.candidate_provider_requests;
                    report.metrics.candidate_provider_subjects_returned =
                        optimizer_plan_prefilter.candidate_provider_subjects_returned;
                    report.metrics.candidate_provider_broad_results =
                        optimizer_plan_prefilter.candidate_provider_broad_results;
                    report.metrics.candidate_provider_fallback_predicate_evaluations =
                        optimizer_plan_prefilter.candidate_provider_fallback_predicate_evaluations;
                } else {
                    const auto candidate_simulation = optimizer::simulate_candidate_provider_filter(
                        *verified, canonical, subjects, candidate_request_plan, candidate_results, simulation_facts);
                    simulation = candidate_simulation.shared_dag;
                    report.metrics.candidate_provider_requests = candidate_simulation.provider_requests;
                    report.metrics.candidate_provider_subjects_returned =
                        candidate_simulation.candidate_subjects_returned;
                    report.metrics.candidate_provider_broad_results = candidate_simulation.broad_results;
                    report.metrics.candidate_provider_fallback_predicate_evaluations =
                        candidate_simulation.server_fallback_predicate_evaluations;
                }
            } else if (options.simulate_optimizer_plan_prefilter) {
                optimizer_plan_for_replay = optimizer::build_optimizer_plan(*verified);
                has_optimizer_plan_for_replay = true;
                optimizer_plan_prefilter = optimizer::evaluate_with_optimizer_plan(*verified, optimizer_plan_for_replay,
                                                                                   subjects, simulation_facts);
                simulation = optimizer_plan_prefilter.shared_dag;
                has_optimizer_plan_prefilter = true;
            } else {
                simulation = optimizer::simulate_shared_predicate_dag(*verified, canonical, subjects, simulation_facts);
            }
            report.metrics.rules_pruned_before_exact_vm = simulation.pruned_rule_subjects;
            report.metrics.dropped_rule_branches = simulation.dropped_rule_branches;
            report.metrics.peak_candidate_set_subjects = simulation.peak_candidate_set_subjects;
            report.metrics.peak_candidate_set_bytes = simulation.peak_candidate_set_bytes;
            report.metrics.optimizer_trace_events += static_cast<std::uint64_t>(simulation.trace_events.size());
            append_optimizer_trace_records(report, simulation.trace_events);
            report.optimizer_predicate_order = simulation.predicate_order;
            report.optimizer_predicate_observations.clear();
            report.optimizer_predicate_observations.reserve(simulation.predicate_nodes.size());
            for (const auto &node : simulation.predicate_nodes) {
                if (node.nonselective) {
                    ++report.metrics.nonselective_predicates;
                }
                report.optimizer_predicate_observations.push_back(BenchmarkPredicateObservation {
                    .predicate_id = node.predicate_id,
                    .cost_class = std::string {fact_cost_class_name(node.cost_class)},
                    .observed_selectivity_ppm = node.observed_selectivity_ppm,
                });
            }
            const auto should_compare_optimizer_plan =
                options.simulate_optimizer_plan_prefilter || options.simulate_optimization_comparison;
            if (should_compare_optimizer_plan) {
                if (!has_optimizer_plan_prefilter) {
                    optimizer_plan_for_replay = optimizer::build_optimizer_plan(*verified);
                    has_optimizer_plan_for_replay = true;
                    optimizer_plan_prefilter = optimizer::evaluate_with_optimizer_plan(
                        *verified, optimizer_plan_for_replay, subjects, simulation_facts);
                }
                if (!has_optimizer_plan_for_replay) {
                    optimizer_plan_for_replay = optimizer::build_optimizer_plan(*verified);
                }
                report.metrics.optimizer_plan_prefilter_exact_vm_rule_executions =
                    optimizer_plan_prefilter.optimized_exact_vm_rule_executions;
                report.metrics.optimizer_plan_prefilter_exact_vm_rule_executions_avoided =
                    optimizer_plan_prefilter.exact_vm_rule_executions_avoided;
                report.metrics.optimizer_plan_prefilter_exact_vm_rule_skip_trace_events =
                    static_cast<std::uint64_t>(optimizer_plan_prefilter.trace_events.size());
                report.metrics.optimizer_plan_prefilter_result_mismatches = count_optimizer_plan_result_mismatches(
                    *verified, subjects, simulation_facts, optimizer_plan_prefilter);
                report.metrics.optimizer_plan_prefilter_incomplete_subjects =
                    static_cast<std::uint64_t>(optimizer_plan_prefilter.incomplete_subjects.size());
                const auto replayed_optimizer_plan_prefilter =
                    replay_optimizer_plan_with_candidate_results ?
                        optimizer::evaluate_with_optimizer_plan(*verified, optimizer_plan_for_replay, subjects,
                                                                simulation_facts,
                                                                optimizer_plan_candidate_results_for_replay) :
                        optimizer::evaluate_with_optimizer_plan(*verified, optimizer_plan_for_replay, subjects,
                                                                simulation_facts);
                const auto replay_parity =
                    compare_optimizer_plan_replay(optimizer_plan_prefilter, replayed_optimizer_plan_prefilter);
                report.metrics.optimizer_plan_prefilter_replay_subject_mismatches = replay_parity.subject_mismatches;
                report.metrics.optimizer_plan_prefilter_replay_rule_result_mismatches =
                    replay_parity.rule_result_mismatches;
                report.metrics.optimizer_plan_prefilter_replay_trace_event_mismatches =
                    replay_parity.trace_event_mismatches;
                report.metrics.optimizer_plan_prefilter_replay_metric_mismatches = replay_parity.metric_mismatches;
                report.metrics.optimizer_trace_events +=
                    static_cast<std::uint64_t>(optimizer_plan_prefilter.trace_events.size());
                append_optimizer_trace_records(report, optimizer_plan_prefilter.trace_events);
            }
            auto prefiltered = optimizer::PrefilteredEvaluationComparison {};
            const auto should_compare_prefiltered =
                options.simulate_prefiltered_evaluation || options.simulate_optimization_comparison;
            if (should_compare_prefiltered) {
                prefiltered =
                    optimizer::compare_prefiltered_evaluation(*verified, canonical, subjects, simulation_facts);
                report.metrics.prefiltered_exact_vm_rule_executions = prefiltered.prefiltered_exact_vm_rule_executions;
                report.metrics.prefiltered_exact_vm_rule_executions_avoided =
                    prefiltered.exact_vm_rule_executions_avoided;
                report.metrics.prefiltered_exact_vm_rule_skip_trace_events =
                    static_cast<std::uint64_t>(prefiltered.trace_events.size());
                report.metrics.optimizer_trace_events += static_cast<std::uint64_t>(prefiltered.trace_events.size());
                append_optimizer_trace_records(report, prefiltered.trace_events);
                report.metrics.prefiltered_result_mismatches = prefiltered.result_mismatches;
                report.metrics.prefiltered_incomplete_subjects =
                    static_cast<std::uint64_t>(prefiltered.incomplete_subjects.size());
            }
            auto lazy_plan = optimizer::LazyProviderExpansionPlan {};
            const auto should_plan_lazy_provider =
                options.simulate_lazy_provider_expansion || options.simulate_watchdogs ||
                options.simulate_watchdog_enforcement || options.simulate_optimization_comparison;
            if (should_plan_lazy_provider) {
                lazy_plan = optimizer::plan_lazy_provider_expansion(*verified, simulation);
                if (options.simulate_watchdogs || options.simulate_watchdog_enforcement) {
                    auto policy = optimizer::WatchdogBudgetPolicy {};
                    if (options.simulate_watchdog_enforcement) {
                        policy.predicate_budget_action = optimizer::WatchdogBudgetAction::defer_branch;
                        policy.route_budget_action = optimizer::WatchdogBudgetAction::timeout_branch;
                    }
                    const auto watchdog = optimizer::simulate_watchdog_budgets(simulation, lazy_plan, policy);
                    report.metrics.watchdog_budget_evaluations = watchdog.evaluations;
                    report.metrics.watchdog_budget_events = watchdog.budget_events;
                    report.metrics.predicate_watchdog_budget_events = watchdog.predicate_budget_events;
                    report.metrics.route_watchdog_budget_events = watchdog.route_budget_events;
                    report.metrics.watchdog_explicit_budget_diagnostics = watchdog.explicit_budget_diagnostics;
                    report.metrics.watchdog_deferred_branch_diagnostics = watchdog.deferred_branch_diagnostics;
                    report.metrics.watchdog_substituted_gate_diagnostics = watchdog.substituted_gate_diagnostics;
                    report.metrics.watchdog_timeout_diagnostics = watchdog.timeout_diagnostics;
                    report.metrics.watchdog_unavailable_diagnostics = watchdog.unavailable_diagnostics;
                    report.metrics.optimizer_trace_events += static_cast<std::uint64_t>(watchdog.trace_events.size());
                    append_optimizer_trace_records(report, watchdog.trace_events);
                }
                if (!options.simulate_lazy_provider_expansion && !options.simulate_optimization_comparison) {
                    const auto elapsed = std::chrono::steady_clock::now() - started;
                    report.metrics.sweep_wall_time_us = static_cast<std::uint64_t>(
                        std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count());
                    return report;
                }
                report.metrics.lazy_provider_batches = lazy_plan.provider_batches;
                report.metrics.lazy_provider_facts_requested = lazy_plan.facts_requested;
                report.metrics.lazy_provider_facts_avoided = lazy_plan.facts_avoided;
                report.metrics.lazy_provider_expensive_facts_requested = lazy_plan.expensive_facts_requested;
                report.metrics.lazy_provider_expensive_facts_avoided = lazy_plan.expensive_facts_avoided;
            }
            if (options.simulate_optimization_comparison) {
                report.metrics.comparison_exact_vm_rule_executions_avoided =
                    prefiltered.exact_vm_rule_executions_avoided;
                report.metrics.comparison_expensive_provider_facts_avoided = lazy_plan.expensive_facts_avoided;
                // The comparison POC models optimized expression work as predicate-DAG checks plus
                // baseline exact-VM expression work for rule/subject pairs that still require final evaluation.
                const auto retained_exact_vm_expressions =
                    report.metrics.exact_vm_rule_executions == 0u ?
                        0u :
                        (report.metrics.expression_evaluations * prefiltered.prefiltered_exact_vm_rule_executions) /
                            report.metrics.exact_vm_rule_executions;
                report.metrics.comparison_optimized_expression_evaluations =
                    simulation.predicate_evaluations + retained_exact_vm_expressions;
                if (report.metrics.expression_evaluations >
                    report.metrics.comparison_optimized_expression_evaluations) {
                    report.metrics.comparison_expression_evaluations_avoided =
                        report.metrics.expression_evaluations -
                        report.metrics.comparison_optimized_expression_evaluations;
                }
                report.metrics.comparison_result_mismatches = prefiltered.result_mismatches;
                report.metrics.comparison_incomplete_subjects =
                    static_cast<std::uint64_t>(prefiltered.incomplete_subjects.size());
                report.metrics.comparison_broad_nonselective_predicates = report.metrics.nonselective_predicates;
                report.metrics.comparison_broad_peak_candidate_set_subjects =
                    static_cast<std::uint64_t>(simulation.peak_candidate_set_subjects);
                report.metrics.comparison_broad_peak_candidate_set_bytes = simulation.peak_candidate_set_bytes;
                report.metrics.comparison_broad_workload_bounded =
                    report.metrics.nonselective_predicates > 0u &&
                            simulation.peak_candidate_set_subjects <= report.metadata.subject_count &&
                            simulation.peak_candidate_set_bytes > 0u ?
                        1u :
                        0u;
            }
        }
        const auto elapsed = std::chrono::steady_clock::now() - started;
        report.metrics.sweep_wall_time_us =
            static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count());
        return report;
    }

    std::string benchmark_report_json(const BenchmarkReport &report) {
        std::string out;
        out.push_back('{');
        append_key_string(out, "schema", report.metadata.schema);
        out.push_back(',');
        append_key(out, "metadata");
        out.push_back('{');
        append_key_string(out, "mode", report.metadata.mode);
        out.push_back(',');
        append_key_string(out, "scenario", report.metadata.scenario);
        out.push_back(',');
        append_key_string(out, "workloadClass", report.metadata.workload_class);
        out.push_back(',');
        append_key_u64(out, "seed", report.metadata.seed);
        out.push_back(',');
        append_key_size(out, "subjectCount", report.metadata.subject_count);
        out.push_back(',');
        append_key_size(out, "ruleCount", report.metadata.rule_count);
        out.push_back(',');
        append_key_string(out, "selectivity", report.metadata.selectivity);
        out.push_back(',');
        append_key_string(out, "benchmarkTier", report.metadata.benchmark_tier);
        out.push_back(',');
        append_key_size(out, "acceptanceTargetMinClients", report.metadata.acceptance_target_min_clients);
        out.push_back(',');
        append_key_size(out, "acceptanceTargetMaxClients", report.metadata.acceptance_target_max_clients);
        out.push_back(',');
        append_key_size(out, "acceptanceTargetSubjectsPerClient",
                        report.metadata.acceptance_target_subjects_per_client);
        out.push_back(',');
        append_key_size(out, "acceptanceTargetRulesPerPack", report.metadata.acceptance_target_rules_per_pack);
        out.push_back(',');
        append_key_string(out, "buildType", report.metadata.build_type);
        out.push_back(',');
        append_key_string(out, "providerLatencyModel", report.metadata.provider_latency_model);
        out.push_back(',');
        append_key_string_array(out, "optimizerFlags", report.metadata.optimizer_flags);
        out.push_back('}');
        out.push_back(',');
        append_key(out, "metrics");
        append_metric_json(out, report.metrics);
        out.push_back(',');
        append_key_string_array(out, "optimizerPredicateOrder", report.optimizer_predicate_order);
        out.push_back(',');
        append_key(out, "optimizerPredicateObservations");
        append_predicate_observations_json(out, report.optimizer_predicate_observations);
        out.push_back(',');
        append_key(out, "optimizerTraceRecords");
        append_optimizer_trace_records_json(out, report.optimizer_trace_records);
        out.push_back('}');
        return out;
    }

    std::string benchmark_report_markdown(const BenchmarkReport &report) {
        std::string out;
        out += "# Rule Engine Benchmark Report\n\n";
        out += "- Schema: `";
        out += report.metadata.schema;
        out += "`\n";
        out += "- Mode: `";
        out += report.metadata.mode;
        out += "`\n";
        out += "- Scenario: `";
        out += report.metadata.scenario;
        out += "`\n";
        out += "- Workload class: `";
        out += report.metadata.workload_class;
        out += "`\n";
        out += "- Seed: `";
        out += std::to_string(report.metadata.seed);
        out += "`\n";
        out += "- Subjects: `";
        out += std::to_string(report.metadata.subject_count);
        out += "`\n";
        out += "- Rules: `";
        out += std::to_string(report.metadata.rule_count);
        out += "`\n";
        out += "- Selectivity: `";
        out += report.metadata.selectivity;
        out += "`\n";
        out += "- Benchmark tier: `";
        out += report.metadata.benchmark_tier;
        out += "`\n";
        out += "- Acceptance target: `";
        out += std::to_string(report.metadata.acceptance_target_min_clients);
        out += "-";
        out += std::to_string(report.metadata.acceptance_target_max_clients);
        out += " clients, ";
        out += std::to_string(report.metadata.acceptance_target_subjects_per_client);
        out += " subjects/client, ";
        out += std::to_string(report.metadata.acceptance_target_rules_per_pack);
        out += " rules/pack`\n\n";
        out += "- Build type: `";
        out += report.metadata.build_type;
        out += "`\n";
        out += "- Optimizer flags: `";
        out += markdown_optimizer_flags(report.metadata.optimizer_flags);
        out += "`\n\n";
        out += "| Metric | Value |\n";
        out += "| --- | ---: |\n";
        append_markdown_metric(out, "Sweep wall time us", report.metrics.sweep_wall_time_us);
        append_markdown_metric(out, "Subjects evaluated", report.metrics.subjects_evaluated);
        append_markdown_metric(out, "Provider rounds", report.metrics.provider_rounds);
        append_markdown_metric(out, "Provider elapsed us", report.metrics.provider_elapsed_us);
        append_markdown_metric(out, "Facts requested", report.metrics.facts_requested);
        append_markdown_metric(out, "Facts returned", report.metrics.facts_returned);
        append_markdown_metric(out, "Returned payload bytes", report.metrics.returned_payload_bytes);
        append_markdown_metric(out, "Expression evaluations", report.metrics.expression_evaluations);
        append_markdown_metric(out, "Exact VM rule executions", report.metrics.exact_vm_rule_executions);
        append_markdown_metric(out, "Rule matches", report.metrics.rule_matches);
        append_markdown_metric(out, "Rules pruned before exact VM", report.metrics.rules_pruned_before_exact_vm);
        append_markdown_metric(out, "Dropped rule branches", report.metrics.dropped_rule_branches);
        append_markdown_metric(out, "Expensive provider reaches", report.metrics.expensive_provider_reaches);
        append_markdown_metric(out, "Canonical predicates", report.metrics.canonical_predicates);
        append_markdown_metric(out, "Exact VM only expressions", report.metrics.exact_vm_only_expressions);
        append_markdown_metric(out, "Nonselective predicates", report.metrics.nonselective_predicates);
        append_markdown_metric(out, "Optimizer trace events", report.metrics.optimizer_trace_events);
        append_markdown_metric(out, "Discovery gate count", report.metrics.discovery_gate_count);
        append_markdown_metric(out, "Discovery gate evaluations", report.metrics.discovery_gate_evaluations);
        append_markdown_metric(out, "Discovery gate pack skips", report.metrics.discovery_gate_pack_skips);
        append_markdown_metric(out, "Fact cache lookups", report.metrics.fact_cache_lookups);
        append_markdown_metric(out, "Fact cache hits", report.metrics.fact_cache_hits);
        append_markdown_metric(out, "Fact cache misses", report.metrics.fact_cache_misses);
        append_markdown_metric(out, "Fact cache lookup probes", report.metrics.fact_cache_lookup_probes);
        append_markdown_metric(out, "Peak candidate set subjects", report.metrics.peak_candidate_set_subjects);
        append_markdown_metric(out, "Peak candidate set bytes", report.metrics.peak_candidate_set_bytes);
        append_markdown_metric(out, "Lazy provider batches", report.metrics.lazy_provider_batches);
        append_markdown_metric(out, "Lazy provider facts requested", report.metrics.lazy_provider_facts_requested);
        append_markdown_metric(out, "Lazy provider facts avoided", report.metrics.lazy_provider_facts_avoided);
        append_markdown_metric(out, "Lazy provider expensive facts requested",
                               report.metrics.lazy_provider_expensive_facts_requested);
        append_markdown_metric(out, "Lazy provider expensive facts avoided",
                               report.metrics.lazy_provider_expensive_facts_avoided);
        append_markdown_metric(out, "Candidate provider requests", report.metrics.candidate_provider_requests);
        append_markdown_metric(out, "Candidate provider subjects returned",
                               report.metrics.candidate_provider_subjects_returned);
        append_markdown_metric(out, "Candidate provider broad results",
                               report.metrics.candidate_provider_broad_results);
        append_markdown_metric(out, "Candidate provider fallback predicate evaluations",
                               report.metrics.candidate_provider_fallback_predicate_evaluations);
        append_markdown_metric(out, "Prefiltered exact VM rule executions",
                               report.metrics.prefiltered_exact_vm_rule_executions);
        append_markdown_metric(out, "Prefiltered exact VM rule executions avoided",
                               report.metrics.prefiltered_exact_vm_rule_executions_avoided);
        append_markdown_metric(out, "Prefiltered exact VM rule skip trace events",
                               report.metrics.prefiltered_exact_vm_rule_skip_trace_events);
        append_markdown_metric(out, "Prefiltered result mismatches", report.metrics.prefiltered_result_mismatches);
        append_markdown_metric(out, "Prefiltered incomplete subjects", report.metrics.prefiltered_incomplete_subjects);
        append_markdown_metric(out, "Optimizer plan prefilter exact VM rule executions",
                               report.metrics.optimizer_plan_prefilter_exact_vm_rule_executions);
        append_markdown_metric(out, "Optimizer plan prefilter exact VM rule executions avoided",
                               report.metrics.optimizer_plan_prefilter_exact_vm_rule_executions_avoided);
        append_markdown_metric(out, "Optimizer plan prefilter exact VM rule skip trace events",
                               report.metrics.optimizer_plan_prefilter_exact_vm_rule_skip_trace_events);
        append_markdown_metric(out, "Optimizer plan prefilter result mismatches",
                               report.metrics.optimizer_plan_prefilter_result_mismatches);
        append_markdown_metric(out, "Optimizer plan prefilter incomplete subjects",
                               report.metrics.optimizer_plan_prefilter_incomplete_subjects);
        append_markdown_metric(out, "Optimizer plan prefilter replay subject mismatches",
                               report.metrics.optimizer_plan_prefilter_replay_subject_mismatches);
        append_markdown_metric(out, "Optimizer plan prefilter replay rule result mismatches",
                               report.metrics.optimizer_plan_prefilter_replay_rule_result_mismatches);
        append_markdown_metric(out, "Optimizer plan prefilter replay trace event mismatches",
                               report.metrics.optimizer_plan_prefilter_replay_trace_event_mismatches);
        append_markdown_metric(out, "Optimizer plan prefilter replay metric mismatches",
                               report.metrics.optimizer_plan_prefilter_replay_metric_mismatches);
        append_markdown_metric(out, "Selectivity feedback profile predicates",
                               report.metrics.selectivity_feedback_profile_predicates);
        append_markdown_metric(out, "Selectivity feedback reordered predicates",
                               report.metrics.selectivity_feedback_reordered_predicates);
        append_markdown_metric(out, "Watchdog budget evaluations", report.metrics.watchdog_budget_evaluations);
        append_markdown_metric(out, "Watchdog budget events", report.metrics.watchdog_budget_events);
        append_markdown_metric(out, "Predicate watchdog budget events",
                               report.metrics.predicate_watchdog_budget_events);
        append_markdown_metric(out, "Route watchdog budget events", report.metrics.route_watchdog_budget_events);
        append_markdown_metric(out, "Watchdog explicit budget diagnostics",
                               report.metrics.watchdog_explicit_budget_diagnostics);
        append_markdown_metric(out, "Watchdog deferred branch diagnostics",
                               report.metrics.watchdog_deferred_branch_diagnostics);
        append_markdown_metric(out, "Watchdog substituted gate diagnostics",
                               report.metrics.watchdog_substituted_gate_diagnostics);
        append_markdown_metric(out, "Watchdog timeout diagnostics", report.metrics.watchdog_timeout_diagnostics);
        append_markdown_metric(out, "Watchdog unavailable diagnostics",
                               report.metrics.watchdog_unavailable_diagnostics);
        append_markdown_metric(out, "Static fact cache lookups", report.metrics.static_fact_cache_lookups);
        append_markdown_metric(out, "Static fact cache hits", report.metrics.static_fact_cache_hits);
        append_markdown_metric(out, "Static fact cache misses", report.metrics.static_fact_cache_misses);
        append_markdown_metric(out, "Static fact cache reuses", report.metrics.static_fact_cache_reuses);
        append_markdown_metric(out, "Static fact cache invalidations", report.metrics.static_fact_cache_invalidations);
        append_markdown_metric(out, "Static fact cache subject-scoped facts",
                               report.metrics.static_fact_cache_subject_scoped);
        append_markdown_metric(out, "Scheduler simulated clients", report.metrics.scheduler_simulated_clients);
        append_markdown_metric(out, "Scheduler timer jitter window ms",
                               report.metrics.scheduler_timer_jitter_window_ms);
        append_markdown_metric(out, "Scheduler peak wake batch", report.metrics.scheduler_peak_wake_batch);
        append_markdown_metric(out, "Scheduler peak VM queue depth", report.metrics.scheduler_peak_vm_queue_depth);
        append_markdown_metric(out, "Scheduler peak provider queue depth",
                               report.metrics.scheduler_peak_provider_queue_depth);
        append_markdown_metric(out, "Scheduler backpressure events", report.metrics.scheduler_backpressure_events);
        append_markdown_metric(out, "Scheduler deadline misses", report.metrics.scheduler_deadline_misses);
        append_markdown_metric(out, "Scheduler idle state bytes", report.metrics.scheduler_idle_state_bytes);
        append_markdown_metric(out, "Comparison exact VM rule executions avoided",
                               report.metrics.comparison_exact_vm_rule_executions_avoided);
        append_markdown_metric(out, "Comparison expensive provider facts avoided",
                               report.metrics.comparison_expensive_provider_facts_avoided);
        append_markdown_metric(out, "Comparison optimized expression evaluations",
                               report.metrics.comparison_optimized_expression_evaluations);
        append_markdown_metric(out, "Comparison expression evaluations avoided",
                               report.metrics.comparison_expression_evaluations_avoided);
        append_markdown_metric(out, "Comparison result mismatches", report.metrics.comparison_result_mismatches);
        append_markdown_metric(out, "Comparison incomplete subjects", report.metrics.comparison_incomplete_subjects);
        append_markdown_metric(out, "Comparison broad nonselective predicates",
                               report.metrics.comparison_broad_nonselective_predicates);
        append_markdown_metric(out, "Comparison broad peak candidate set subjects",
                               report.metrics.comparison_broad_peak_candidate_set_subjects);
        append_markdown_metric(out, "Comparison broad peak candidate set bytes",
                               report.metrics.comparison_broad_peak_candidate_set_bytes);
        append_markdown_metric(out, "Comparison broad workload bounded",
                               report.metrics.comparison_broad_workload_bounded);
        if (!report.optimizer_predicate_observations.empty()) {
            out += "\n## Optimizer Predicate Observations\n\n";
            out += "| Predicate | Cost class | Observed selectivity ppm |\n";
            out += "| --- | --- | ---: |\n";
            for (const auto &observation : report.optimizer_predicate_observations) {
                out += "| ";
                out += markdown_table_cell(observation.predicate_id);
                out += " | ";
                out += markdown_table_cell(observation.cost_class);
                out += " | ";
                out += std::to_string(observation.observed_selectivity_ppm);
                out += " |\n";
            }
        }
        if (!report.optimizer_trace_records.empty()) {
            out += "\n## Optimizer Trace Records\n\n";
            out += "| Event | Predicate | Rule | Subject | Reason |\n";
            out += "| --- | --- | --- | --- | --- |\n";
            for (const auto &record : report.optimizer_trace_records) {
                out += "| ";
                out += markdown_table_cell(record.event);
                out += " | ";
                out += markdown_table_cell(record.predicate_id);
                out += " | ";
                out += markdown_table_cell(record.rule_identifier);
                out += " | ";
                out += markdown_table_cell(record.subject_id);
                out += " | ";
                out += markdown_table_cell(record.reason);
                out += " |\n";
            }
        }
        return out;
    }
} // namespace rule_engine::benchmark
