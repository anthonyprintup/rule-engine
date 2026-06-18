#include <rule_engine/evaluation_scheduler.hpp>

#include <algorithm>

namespace {
    [[nodiscard]] std::chrono::milliseconds nonnegative(const std::chrono::milliseconds value) noexcept {
        if (value.count() <= 0) {
            return std::chrono::milliseconds {0};
        }
        return value;
    }
} // namespace

namespace rule_engine::scheduler {
    std::uint64_t stable_client_hash(const std::string_view client_id) noexcept {
        std::uint64_t hash {14695981039346656037ull};
        for (const auto ch : client_id) {
            hash ^= static_cast<std::uint8_t>(ch);
            hash *= 1099511628211ull;
        }
        return hash;
    }

    std::chrono::milliseconds jitter_for_client(const std::string_view client_id,
                                                const EvaluationTimerPolicy &policy) noexcept {
        const auto window = nonnegative(policy.jitter_window);
        if (window.count() == 0) {
            return std::chrono::milliseconds {0};
        }
        const auto hash = stable_client_hash(client_id);
        return std::chrono::milliseconds {
            static_cast<std::chrono::milliseconds::rep>(hash % static_cast<std::uint64_t>(window.count()))};
    }

    ClientEvaluationIdleState schedule_next_client_evaluation(const std::string_view client_id,
                                                              const std::chrono::milliseconds completed_at,
                                                              const EvaluationTimerPolicy &policy,
                                                              const std::uint32_t sequence) noexcept {
        const auto cadence = nonnegative(policy.cadence);
        const auto next_due_at = completed_at + cadence + jitter_for_client(client_id, policy);
        return ClientEvaluationIdleState {
            .client_hash = stable_client_hash(client_id),
            .next_due_at = next_due_at,
            .deadline_at = next_due_at + nonnegative(policy.sweep_deadline),
            .sequence = sequence,
        };
    }

    EvaluationAdmissionReport admit_due_client_evaluations(const std::span<const ClientEvaluationIdleState> clients,
                                                           const std::chrono::milliseconds now,
                                                           const std::size_t max_active_client_sweeps,
                                                           const std::size_t active_client_sweeps) noexcept {
        EvaluationAdmissionReport out {
            .tracked_clients = static_cast<std::uint64_t>(clients.size()),
            .idle_state_bytes = static_cast<std::uint64_t>(clients.size() * sizeof(ClientEvaluationIdleState)),
        };
        for (const auto &client : clients) {
            if (client.next_due_at > now) {
                continue;
            }
            ++out.due_clients;
            if (client.deadline_at < now) {
                ++out.deadline_misses;
            }
        }

        const auto available_sweeps =
            active_client_sweeps >= max_active_client_sweeps ? 0u : max_active_client_sweeps - active_client_sweeps;
        out.admitted_clients = std::min<std::uint64_t>(out.due_clients, static_cast<std::uint64_t>(available_sweeps));
        out.deferred_clients = out.due_clients - out.admitted_clients;
        out.active_client_sweeps = static_cast<std::uint64_t>(active_client_sweeps) + out.admitted_clients;
        return out;
    }
} // namespace rule_engine::scheduler
