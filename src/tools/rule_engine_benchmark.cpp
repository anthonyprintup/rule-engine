#include <rule_engine/benchmark.hpp>

#include <fmt/format.h>

#include <charconv>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace {
    enum struct OutputFormat {
        json,
        markdown,
    };

    struct Options {
        rule_engine::benchmark::BenchmarkOptions benchmark;
        OutputFormat format {OutputFormat::json};
    };

    [[nodiscard]] bool wants_help(const std::string_view arg) noexcept { return arg == "--help" || arg == "-h"; }

    void print_usage() {
        fmt::print(stderr, "usage: rule_engine_benchmark [--format json|markdown] [--scenario <name>] "
                           "[--seed <n>] [--subjects <n>] [--rules <n>] [--match-every <n>] "
                           "[--simulate-discovery-gates] [--simulate-shared-predicate-dag] "
                           "[--simulate-lazy-provider-expansion] "
                           "[--simulate-candidate-provider] [--simulate-prefiltered-evaluation] "
                           "[--simulate-optimizer-plan-prefilter] "
                           "[--simulate-selectivity-feedback] "
                           "[--simulate-watchdogs] [--simulate-watchdog-enforcement] "
                           "[--simulate-static-fact-cache] "
                           "[--simulate-scheduler-controls] [--simulate-optimization-comparison]\n");
    }

    [[nodiscard]] bool parse_u64(const std::string_view text, std::uint64_t &out) noexcept {
        std::uint64_t value {};
        const auto *first = text.data();
        const auto *last = text.data() + text.size();
        const auto [ptr, ec] = std::from_chars(first, last, value);
        if (ec != std::errc {} || ptr != last) {
            return false;
        }
        out = value;
        return true;
    }

    [[nodiscard]] bool parse_size(const std::string_view text, std::size_t &out) noexcept {
        std::uint64_t value {};
        if (!parse_u64(text, value)) {
            return false;
        }
        out = static_cast<std::size_t>(value);
        return static_cast<std::uint64_t>(out) == value;
    }

    [[nodiscard]] bool parse_format(const std::string_view text, OutputFormat &out) noexcept {
        if (text == "json") {
            out = OutputFormat::json;
            return true;
        }
        if (text == "markdown") {
            out = OutputFormat::markdown;
            return true;
        }
        return false;
    }

    [[nodiscard]] bool read_value(int &index, const int argc, char **argv, std::string_view &out) noexcept {
        if (index + 1 >= argc) {
            return false;
        }
        ++index;
        out = std::string_view {argv[index]};
        return true;
    }

    [[nodiscard]] bool parse_options(const int argc, char **argv, Options &out) {
        for (int index = 1; index < argc; ++index) {
            const std::string_view arg {argv[index]};
            if (wants_help(arg)) {
                print_usage();
                return false;
            }
            if (arg == "--simulate-shared-predicate-dag") {
                out.benchmark.simulate_shared_predicate_dag = true;
                continue;
            }
            if (arg == "--simulate-discovery-gates") {
                out.benchmark.simulate_discovery_gates = true;
                continue;
            }
            if (arg == "--simulate-lazy-provider-expansion") {
                out.benchmark.simulate_lazy_provider_expansion = true;
                continue;
            }
            if (arg == "--simulate-candidate-provider") {
                out.benchmark.simulate_candidate_provider = true;
                continue;
            }
            if (arg == "--simulate-prefiltered-evaluation") {
                out.benchmark.simulate_prefiltered_evaluation = true;
                continue;
            }
            if (arg == "--simulate-optimizer-plan-prefilter") {
                out.benchmark.simulate_optimizer_plan_prefilter = true;
                continue;
            }
            if (arg == "--simulate-selectivity-feedback") {
                out.benchmark.simulate_selectivity_feedback = true;
                continue;
            }
            if (arg == "--simulate-watchdogs") {
                out.benchmark.simulate_watchdogs = true;
                continue;
            }
            if (arg == "--simulate-watchdog-enforcement") {
                out.benchmark.simulate_watchdog_enforcement = true;
                continue;
            }
            if (arg == "--simulate-static-fact-cache") {
                out.benchmark.simulate_static_fact_cache = true;
                continue;
            }
            if (arg == "--simulate-scheduler-controls") {
                out.benchmark.simulate_scheduler_controls = true;
                continue;
            }
            if (arg == "--simulate-optimization-comparison") {
                out.benchmark.simulate_optimization_comparison = true;
                continue;
            }

            std::string_view value;
            if (arg == "--format") {
                if (!read_value(index, argc, argv, value) || !parse_format(value, out.format)) {
                    fmt::print(stderr, "invalid --format value\n");
                    return false;
                }
                continue;
            }
            if (arg == "--scenario") {
                if (!read_value(index, argc, argv, value)) {
                    fmt::print(stderr, "missing --scenario value\n");
                    return false;
                }
                out.benchmark.scenario = std::string {value};
                continue;
            }
            if (arg == "--seed") {
                if (!read_value(index, argc, argv, value) || !parse_u64(value, out.benchmark.seed)) {
                    fmt::print(stderr, "invalid --seed value\n");
                    return false;
                }
                continue;
            }
            if (arg == "--subjects") {
                if (!read_value(index, argc, argv, value) || !parse_size(value, out.benchmark.subject_count)) {
                    fmt::print(stderr, "invalid --subjects value\n");
                    return false;
                }
                continue;
            }
            if (arg == "--rules") {
                if (!read_value(index, argc, argv, value) || !parse_size(value, out.benchmark.rule_count)) {
                    fmt::print(stderr, "invalid --rules value\n");
                    return false;
                }
                continue;
            }
            if (arg == "--match-every") {
                if (!read_value(index, argc, argv, value) || !parse_size(value, out.benchmark.match_every)) {
                    fmt::print(stderr, "invalid --match-every value\n");
                    return false;
                }
                continue;
            }

            fmt::print(stderr, "invalid argument: {}\n", arg);
            print_usage();
            return false;
        }
        return true;
    }

    void print_errors(const rule_engine::ErrorSet &errors) {
        for (const auto &diagnostic : errors.diagnostics) {
            fmt::print(stderr, "{}:{}: {}\n", diagnostic.source, diagnostic.span.start, diagnostic.message);
        }
    }
} // namespace

int main(int argc, char **argv) {
    Options options;
    if (!parse_options(argc, argv, options)) {
        return wants_help(argc > 1 ? std::string_view {argv[1]} : std::string_view {}) ? 0 : 2;
    }

    auto report = rule_engine::benchmark::run_baseline_benchmark(options.benchmark);
    if (!report) {
        print_errors(report.error());
        return 1;
    }

    switch (options.format) {
        case OutputFormat::json: fmt::print("{}\n", rule_engine::benchmark::benchmark_report_json(*report)); break;
        case OutputFormat::markdown:
            fmt::print("{}\n", rule_engine::benchmark::benchmark_report_markdown(*report));
            break;
        default: return 2;
    }
    return 0;
}
