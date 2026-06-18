#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace rule_engine::scheduler {
    struct EvaluationTimerPolicy {
        std::chrono::milliseconds cadence {std::chrono::minutes {5}};
        std::chrono::milliseconds jitter_window {std::chrono::minutes {5}};
        std::chrono::milliseconds sweep_deadline {std::chrono::seconds {30}};
    };

    struct ClientEvaluationIdleState {
        std::uint64_t client_hash {};
        std::chrono::milliseconds next_due_at {};
        std::chrono::milliseconds deadline_at {};
        std::uint32_t sequence {};
    };

    struct EvaluationAdmissionReport {
        std::uint64_t tracked_clients {};
        std::uint64_t due_clients {};
        std::uint64_t admitted_clients {};
        std::uint64_t deferred_clients {};
        std::uint64_t active_client_sweeps {};
        std::uint64_t deadline_misses {};
        std::uint64_t idle_state_bytes {};
    };

    [[nodiscard]] std::uint64_t stable_client_hash(std::string_view client_id) noexcept;
    [[nodiscard]] std::chrono::milliseconds jitter_for_client(std::string_view client_id,
                                                              const EvaluationTimerPolicy &policy) noexcept;
    [[nodiscard]] ClientEvaluationIdleState
    schedule_next_client_evaluation(std::string_view client_id, std::chrono::milliseconds completed_at,
                                    const EvaluationTimerPolicy &policy, std::uint32_t sequence = 0u) noexcept;
    [[nodiscard]] EvaluationAdmissionReport
    admit_due_client_evaluations(std::span<const ClientEvaluationIdleState> clients, std::chrono::milliseconds now,
                                 std::size_t max_active_client_sweeps,
                                 std::size_t active_client_sweeps = 0u) noexcept;
} // namespace rule_engine::scheduler
