#pragma once

#include "rule_engine/python/tools/common.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>

namespace rule_engine::python::tools {

    struct PythonBenchmarkOptions {
        std::size_t peers {10'000U};
        OutputFormat format {OutputFormat::text};
    };

    struct PythonBenchmarkReport {
        std::size_t peers {};
        std::string semantic_hash;
        std::string executable;
        std::string optimized_strategy;
        bool optimizer_certificate_validated {};
        bool parity_equivalent {};
        std::size_t parity_mismatches {};
        std::uint64_t exact_vm_sessions {};
        std::uint64_t optimized_vm_sessions {};
        std::uint64_t exact_instructions_charged {};
        std::uint64_t optimized_instructions_charged {};
        std::uint64_t exact_wall_nanoseconds {};
        std::uint64_t optimized_wall_nanoseconds {};
        std::string resident_simulation_model;
        bool resident_network_simulated {};
        bool resident_postgresql_simulated {};
        std::uint64_t resident_work_enqueued {};
        std::uint64_t resident_work_committed {};
        std::uint64_t resident_retry_attempts {};
        std::uint64_t resident_stale_fence_rejections {};
        std::uint64_t resident_ordering_violations {};
        std::uint64_t resident_claim_batch_limit {};
        std::uint64_t resident_peak_claim_batch {};
        std::uint64_t resident_peak_active_leases {};
        std::uint64_t resident_final_ready_work {};
        std::uint64_t resident_final_active_leases {};
        std::uint64_t resident_backpressure_transitions {};
        std::uint64_t resident_backpressure_clears {};
        std::uint64_t resident_peak_agent_sessions {};
        std::uint64_t resident_peak_pending_records {};
        std::uint64_t resident_peak_pending_bytes {};
        std::uint64_t resident_simulation_wall_nanoseconds {};
    };

    struct PythonBenchmarkError {
        ExitCode exit_code {ExitCode::internal_invariant_failed};
        std::string code;
        std::string message;
    };

    [[nodiscard]] std::expected<PythonBenchmarkReport, PythonBenchmarkError>
    run_python_benchmark(const PythonBenchmarkOptions &options);
    [[nodiscard]] std::string render_python_benchmark_json(const PythonBenchmarkReport &report);
    [[nodiscard]] std::string render_python_benchmark_text(const PythonBenchmarkReport &report);
    [[nodiscard]] std::string_view benchmark_help() noexcept;
    [[nodiscard]] CommandOutput run_rule_engine_benchmark(std::span<const std::string_view> arguments);

} // namespace rule_engine::python::tools
