#pragma once

#include "rule_engine/python/cluster/coordinator.hpp"
#include "rule_engine/python/protocol/session.hpp"
#include "rule_engine/python/runtime/orchestrator.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace rule_engine::python::runtime {

    struct SequencedDurableAgentMessage {
        std::uint64_t sequence {};
        protocol_v2::DurableAgentBody body;
    };

    // Reorders the durable protocol-v2 stream without conflating in-memory
    // delivery with durable acknowledgement. The caller must route and persist
    // next_contiguous() before mark_durable(); only then may its transport emit
    // an acknowledgement. This gate accepts every durable agent-body kind so a
    // snapshot record cannot permanently hide a later work result behind a gap.
    // It is session-strand state, not an internally synchronized queue. Its
    // memory ceiling is the negotiated frame-size/sequence-gap window; operators
    // must tune those protocol limits to their per-session memory budget.
    struct ProtocolV2DurableSequenceGate {
        [[nodiscard]] static std::expected<ProtocolV2DurableSequenceGate, protocol_v2::ProtocolError>
        create(PeerId peer, SessionId session, std::uint64_t session_fence, std::string agent_epoch,
               std::uint64_t acknowledged_through = 0U,
               std::uint16_t selected_minor = protocol_v2::initial_minor_version,
               protocol_v2::ProtocolLimits limits = {});

        [[nodiscard]] std::expected<protocol_v2::SequenceDisposition, protocol_v2::ProtocolError>
        admit(protocol_v2::PeerEnvelope envelope);
        [[nodiscard]] std::optional<SequencedDurableAgentMessage> next_contiguous() const;
        [[nodiscard]] std::expected<std::uint64_t, protocol_v2::ProtocolError> mark_durable(std::uint64_t sequence);
        [[nodiscard]] std::uint64_t acknowledged_through() const noexcept { return receive_.acknowledged_through; }

    private:
        ProtocolV2DurableSequenceGate(protocol_v2::ServerReceiveState receive, std::uint16_t selected_minor,
                                      protocol_v2::ProtocolLimits limits) noexcept;

        protocol_v2::ServerReceiveState receive_;
        std::uint16_t selected_minor_ {protocol_v2::initial_minor_version};
        protocol_v2::ProtocolLimits limits_;
        std::map<std::uint64_t, protocol_v2::DurableAgentBody> staged_;
        std::map<std::uint64_t, std::vector<std::byte>> fingerprints_;
    };

    struct IProtocolV2CancelSink {
        virtual ~IProtocolV2CancelSink() = default;
        // Server-sequence allocation and transport are session concerns, so the
        // response port forwards the authenticated lease identity instead of
        // inventing a CancelWorkMessage sequence locally.
        virtual void cancel(const protocol_v2::WorkLeaseMessage &work,
                            std::span<const RequestId> requests) noexcept = 0;
    };

    // Admits one complete terminal WorkResult for one exact lease and exposes
    // its typed responses through the resident orchestrator's provider port.
    // Structural/value bounds and the exact request/returned schema identity
    // are checked here. The C++ VM remains responsible for validating the
    // value against the authoritative descriptor before it is exposed.
    struct ProtocolV2ProviderResponsePort final: IProviderResponsePort {
        [[nodiscard]] static std::expected<ProtocolV2ProviderResponsePort, protocol_v2::ProtocolError>
        create(protocol_v2::WorkLeaseMessage work, IProtocolV2CancelSink &cancel_sink,
               protocol_v2::ProtocolLimits limits = {});

        [[nodiscard]] std::expected<void, protocol_v2::ProtocolError>
        admit(const protocol_v2::WorkResultMessage &result);

        [[nodiscard]] std::expected<std::vector<FactResponse>, PortError>
        resolve_facts(std::span<const FactRequest> requests) noexcept override;
        [[nodiscard]] std::expected<std::vector<ScanResponse>, PortError>
        resolve_scans(std::span<const ScanRequest> requests) noexcept override;
        void cancel(std::span<const RequestId> requests) noexcept override;

    private:
        ProtocolV2ProviderResponsePort(protocol_v2::WorkLeaseMessage work, IProtocolV2CancelSink &cancel_sink,
                                       protocol_v2::ProtocolLimits limits) noexcept;

        protocol_v2::WorkLeaseMessage work_;
        IProtocolV2CancelSink &cancel_sink_;
        protocol_v2::ProtocolLimits limits_;
        std::map<std::string, FactRequest, std::less<>> expected_facts_;
        std::map<std::string, ScanRequest, std::less<>> expected_scans_;
        std::map<std::string, FactResponse, std::less<>> facts_;
        std::map<std::string, ScanResponse, std::less<>> scans_;
        std::set<std::string, std::less<>> canceled_;
        bool admitted_ {};
    };

    struct IRuntimeClock {
        virtual ~IRuntimeClock() = default;
        [[nodiscard]] virtual std::uint64_t now_unix_ms() const noexcept = 0;
    };

    // Binds the generic resident transaction port to an exact cluster lease.
    // The coordinator remains the authority that checks the current attempt,
    // lease fence, event, and store transaction atomically with work completion.
    // The current cluster store has no independent active-generation lookup;
    // generation freshness therefore relies on cutover fencing old leases, and
    // this port rejects any resident identity that differs from its claimed
    // lease instead of inventing activation state.
    struct ClusterWorkTransactionPort final: ITransactionPort {
        ClusterWorkTransactionPort(cluster::DeterministicWorkCoordinator &coordinator, cluster::WorkLease lease,
                                   const IRuntimeClock &clock) noexcept:
            coordinator_ {coordinator}, lease_ {std::move(lease)}, clock_ {clock} {}

        [[nodiscard]] std::expected<TransactionReceipt, StoreError>
        commit(const ResidentWorkIdentity &work, const RuntimeTransaction &transaction) noexcept override;

    private:
        cluster::DeterministicWorkCoordinator &coordinator_;
        cluster::WorkLease lease_;
        const IRuntimeClock &clock_;
    };

} // namespace rule_engine::python::runtime
