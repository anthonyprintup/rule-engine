#pragma once

#include "rule_engine/python/cluster/coordinator.hpp"
#include "rule_engine/python/protocol/snapshot.hpp"
#include "rule_engine/python/tools/active_pack.hpp"
#include "rule_engine/python/tools/resident_service.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <stop_token>
#include <string>
#include <vector>

namespace rule_engine::python::tools {

    // Projects committed authoritative snapshots into deterministic VM
    // evaluations. Provider turns are leased to the authenticated agent; VM
    // completion is committed through the fenced cluster coordinator.
    struct ResidentEvaluationScheduler {
        [[nodiscard]] static std::expected<std::unique_ptr<ResidentEvaluationScheduler>, protocol_v2::ProtocolError>
        create(cluster::IClusterRuntimeStore &store, cluster::AuditTrail &audit, std::string node_id,
               std::chrono::milliseconds work_lease_duration, std::vector<ResidentActivePack> active_packs,
               protocol_v2::ProtocolLimits limits = {});
        ~ResidentEvaluationScheduler();

        ResidentEvaluationScheduler(const ResidentEvaluationScheduler &) = delete;
        ResidentEvaluationScheduler &operator=(const ResidentEvaluationScheduler &) = delete;

        [[nodiscard]] std::expected<void, protocol_v2::ProtocolError>
        bind_session(const ResidentAgentSession &session) noexcept;
        // Pure, state-aware validation used before the durable receipt is
        // advanced. Callers must still invoke ingest after persistence.
        [[nodiscard]] std::expected<void, protocol_v2::ProtocolError>
        validate_ingest(const ResidentAgentSession &session, std::uint64_t sequence,
                        const protocol_v2::DurableAgentBody &body, std::stop_token cancellation) noexcept;
        [[nodiscard]] std::expected<void, protocol_v2::ProtocolError> ingest(const ResidentAgentSession &session,
                                                                             std::uint64_t sequence,
                                                                             const protocol_v2::DurableAgentBody &body,
                                                                             std::stop_token cancellation) noexcept;
        [[nodiscard]] std::expected<std::vector<protocol_v2::WorkLeaseMessage>, protocol_v2::ProtocolError>
        take_work(const ResidentAgentSession &session, std::size_t limit, std::stop_token cancellation) noexcept;
        void close(const ResidentAgentSession &session) noexcept;

    private:
        struct Impl;
        explicit ResidentEvaluationScheduler(std::unique_ptr<Impl> impl) noexcept;
        std::unique_ptr<Impl> impl_;
    };

} // namespace rule_engine::python::tools
