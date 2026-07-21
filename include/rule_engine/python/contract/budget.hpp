#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace rule_engine::python {

    struct ExecutorBudget {
        std::chrono::milliseconds elapsed {};
        std::chrono::milliseconds active_cpu {};
        std::uint64_t instructions {};
        std::uint32_t frames {};
        std::size_t heap_bytes {};
        std::uint64_t loop_iterations_and_yields {};
        std::uint32_t logical_facts {};
        std::uint32_t provider_rounds {};
        std::size_t fact_bytes {};
        std::uint32_t service_calls {};
        std::uint32_t active_service_calls {};
        std::size_t service_response_bytes {};
        std::chrono::milliseconds maximum_service_deadline {};
        std::uint32_t history_queries {};
        std::uint32_t history_rows {};
        std::size_t history_bytes {};
        std::uint32_t state_keys {};
        std::size_t state_bytes {};
        std::uint32_t effect_intents {};
        std::size_t effect_bytes {};
        std::uint32_t event_intents {};
        std::size_t event_bytes {};
        std::uint32_t event_maximum_depth {};
        std::uint32_t recorder_events {};
        std::size_t recorder_bytes {};
    };

    struct RecoveryBudget {
        std::chrono::milliseconds elapsed {};
        std::chrono::milliseconds active_cpu {};
        std::uint64_t instructions {};
        std::size_t heap_bytes {};
        std::uint32_t service_calls {};
        std::uint32_t effect_intents {};
    };

    struct CompileBudget {
        std::size_t source_closure_bytes {};
        std::uint64_t ast_nodes {};
        std::uint32_t generated_bindings {};
        std::size_t generator_input_bytes {};
        std::size_t worker_memory_bytes {};
        std::chrono::milliseconds worker_elapsed {};
        std::uint32_t snapshot_items {};
        std::size_t snapshot_bytes {};
    };

    struct BudgetProfile {
        std::string_view name;
        ExecutorBudget normal;
        RecoveryBudget finalizer_or_fault;
        RecoveryBudget double_fault;
        RecoveryBudget forced_cleanup;
        CompileBudget compile;
    };

    inline constexpr std::size_t kibibyte = 1024U;
    inline constexpr std::size_t mebibyte = 1024U * kibibyte;

    inline constexpr BudgetProfile balanced_v1 {
        .name = "balanced.v1",
        .normal = {.elapsed = std::chrono::seconds {10},
                   .active_cpu = std::chrono::milliseconds {100},
                   .instructions = 1'000'000,
                   .frames = 128,
                   .heap_bytes = 16 * mebibyte,
                   .loop_iterations_and_yields = 250'000,
                   .logical_facts = 512,
                   .provider_rounds = 16,
                   .fact_bytes = 16 * mebibyte,
                   .service_calls = 128,
                   .active_service_calls = 16,
                   .service_response_bytes = 16 * mebibyte,
                   .maximum_service_deadline = std::chrono::seconds {5},
                   .history_queries = 16,
                   .history_rows = 10'000,
                   .history_bytes = 16 * mebibyte,
                   .state_keys = 256,
                   .state_bytes = 1 * mebibyte,
                   .effect_intents = 256,
                   .effect_bytes = 2 * mebibyte,
                   .event_intents = 256,
                   .event_bytes = 2 * mebibyte,
                   .event_maximum_depth = 64,
                   .recorder_events = 25'000,
                   .recorder_bytes = 4 * mebibyte},
        .finalizer_or_fault = {.elapsed = std::chrono::seconds {2},
                               .active_cpu = std::chrono::milliseconds {50},
                               .instructions = 100'000,
                               .heap_bytes = 2 * mebibyte,
                               .service_calls = 8,
                               .effect_intents = 64},
        .double_fault = {.elapsed = std::chrono::seconds {1},
                         .active_cpu = {},
                         .instructions = 25'000,
                         .heap_bytes = 512 * kibibyte,
                         .service_calls = 0,
                         .effect_intents = 0},
        .forced_cleanup = {.elapsed = std::chrono::milliseconds {500},
                           .active_cpu = {},
                           .instructions = 25'000,
                           .heap_bytes = 0,
                           .service_calls = 0,
                           .effect_intents = 0},
        .compile = {.source_closure_bytes = 16 * mebibyte,
                    .ast_nodes = 1'000'000,
                    .generated_bindings = 100'000,
                    .generator_input_bytes = 64 * mebibyte,
                    .worker_memory_bytes = 512 * mebibyte,
                    .worker_elapsed = std::chrono::seconds {15},
                    .snapshot_items = 100'000,
                    .snapshot_bytes = 16 * mebibyte},
    };

    struct BreakerProfile {
        std::uint32_t peer_threshold {};
        std::chrono::minutes peer_window {};
        std::chrono::minutes peer_quarantine {};
        std::uint32_t global_threshold {};
        std::uint32_t global_distinct_peers {};
        std::chrono::minutes global_window {};
    };

    inline constexpr BreakerProfile breaker_v1 {
        .peer_threshold = 3,
        .peer_window = std::chrono::minutes {10},
        .peer_quarantine = std::chrono::minutes {30},
        .global_threshold = 5,
        .global_distinct_peers = 3,
        .global_window = std::chrono::minutes {15},
    };

} // namespace rule_engine::python
