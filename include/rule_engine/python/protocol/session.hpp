#pragma once

#include "rule_engine/python/protocol/types.hpp"

#include <deque>
#include <expected>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <vector>

namespace rule_engine::python::protocol_v2 {

    struct TlsPeerIdentity {
        std::uint16_t tls_major {};
        std::uint16_t tls_minor {};
        bool mutual_authentication {};
        bool certificate_chain_verified {};
        bool client_auth_eku {};
        bool revoked {};
        std::string canonical_uri_san;
        std::string certificate_sha256;
    };

    struct AuthenticatedPeer {
        TenantId tenant;
        PeerId peer;
    };

    struct ITrustPolicy {
        virtual ~ITrustPolicy() = default;
        [[nodiscard]] virtual std::expected<AuthenticatedPeer, ProtocolError>
        authenticate(const TlsPeerIdentity &identity) const noexcept = 0;
        [[nodiscard]] virtual std::expected<void, ProtocolError>
        authorize_capabilities(const AuthenticatedPeer &peer,
                               std::span<const CapabilityAdvertisement> capabilities) const noexcept;
    };

    struct CapabilityPermission {
        CapabilityId capability;
        std::uint32_t maximum_version {};
        SchemaId request_schema;
        SchemaId response_schema;
    };

    struct PeerEnrollment {
        std::string canonical_uri_san;
        std::string certificate_sha256;
        AuthenticatedPeer identity;
        bool disabled {};
        std::vector<CapabilityPermission> capabilities;
    };

    struct OperatorTrustPolicy final: ITrustPolicy {
        [[nodiscard]] std::expected<void, ProtocolError> enroll(PeerEnrollment enrollment);
        [[nodiscard]] std::expected<AuthenticatedPeer, ProtocolError>
        authenticate(const TlsPeerIdentity &identity) const noexcept override;
        [[nodiscard]] std::expected<void, ProtocolError>
        authorize_capabilities(const AuthenticatedPeer &peer,
                               std::span<const CapabilityAdvertisement> capabilities) const noexcept override;

    private:
        std::vector<PeerEnrollment> enrollments_;
    };

    // Validates transport facts supplied by the TLS implementation, then delegates
    // enrollment/SAN mapping to the operator trust policy. The codec itself never
    // claims to establish TLS or peer identity.
    [[nodiscard]] std::expected<AuthenticatedPeer, ProtocolError>
    authenticate_transport(const TlsPeerIdentity &identity, const ITrustPolicy &policy) noexcept;

    [[nodiscard]] std::expected<AuthenticatedPeer, ProtocolError>
    authenticate_and_authorize(const TlsPeerIdentity &identity, const ITrustPolicy &policy,
                               std::span<const CapabilityAdvertisement> capabilities) noexcept;

    enum struct SequenceDisposition : std::uint8_t { accepted, accepted_out_of_order, duplicate };

    struct ServerReceiveState {
        PeerId peer;
        SessionId session;
        std::uint64_t session_fence {};
        std::string agent_epoch;
        std::uint64_t acknowledged_through {};
        std::size_t maximum_gap {4'096};

        [[nodiscard]] std::expected<SequenceDisposition, ProtocolError> observe(const PeerEnvelope &envelope);
        [[nodiscard]] std::expected<std::uint64_t, ProtocolError> mark_durable(std::uint64_t sequence);

    private:
        std::set<std::uint64_t> observed_;
        std::set<std::uint64_t> durable_;
    };

    struct AgentSpoolLimits {
        std::size_t maximum_records {8'192};
        std::size_t maximum_bytes {64 * mebibyte};
        std::size_t high_water_bytes {48 * mebibyte};
        std::size_t low_water_bytes {32 * mebibyte};
    };

    struct OutboundRecord {
        std::uint64_t sequence {};
        DurableAgentBody body;
        std::size_t encoded_bytes {};
        bool in_flight {};
        std::uint32_t transmit_attempts {};
    };

    struct QuarantinedRecord {
        OutboundRecord record;
        ProtocolErrorCode reason {ProtocolErrorCode::malformed};
        std::string diagnostic;
    };

    struct WorkAcceptance {
        enum struct Disposition : std::uint8_t { accepted, duplicate, superseded };
        Disposition disposition {Disposition::accepted};
        std::vector<RequestId> requests;
    };

    struct AgentSessionState {
        explicit AgentSessionState(PeerId peer, std::string agent_epoch, AgentSpoolLimits limits = {});

        [[nodiscard]] std::expected<void, ProtocolError> establish(const ServerHelloMessage &hello);
        void disconnect() noexcept;
        [[nodiscard]] std::expected<WorkAcceptance, ProtocolError> accept_work(const WorkLeaseMessage &work);
        [[nodiscard]] std::expected<std::vector<RequestId>, ProtocolError>
        accept_cancel(const CancelWorkMessage &cancel);

        [[nodiscard]] std::expected<std::uint64_t, ProtocolError> enqueue(DurableAgentBody body,
                                                                          std::size_t encoded_bytes);
        [[nodiscard]] std::vector<OutboundRecord> take_transmit_batch();
        [[nodiscard]] std::expected<void, ProtocolError> acknowledge(const AckMessage &ack);
        [[nodiscard]] std::expected<void, ProtocolError> reject(const NackMessage &nack);
        void update_credit(CreditWindow credit) noexcept;

        [[nodiscard]] bool established() const noexcept { return session_.has_value(); }
        [[nodiscard]] bool backpressured() const noexcept { return backpressured_; }
        [[nodiscard]] bool work_canceled(std::string_view work_id) const;
        [[nodiscard]] std::uint64_t acknowledged_through() const noexcept { return acknowledged_through_; }
        [[nodiscard]] std::size_t pending_records() const noexcept { return pending_.size(); }
        [[nodiscard]] std::size_t pending_bytes() const noexcept { return pending_bytes_; }
        [[nodiscard]] const std::vector<QuarantinedRecord> &quarantined() const noexcept { return quarantined_; }

    private:
        struct AcceptedWork {
            std::string work_id;
            std::string attempt_id;
            std::uint64_t work_fence {};
            bool canceled {};
        };

        void release_in_flight(const OutboundRecord &record) noexcept;
        void refresh_backpressure() noexcept;
        [[nodiscard]] std::expected<void, ProtocolError> validate_server_message(const SessionId &session,
                                                                                 const PeerId &peer,
                                                                                 std::uint64_t fence,
                                                                                 std::uint64_t sequence);

        PeerId peer_;
        std::string agent_epoch_;
        AgentSpoolLimits limits_;
        std::optional<SessionId> session_;
        std::uint64_t session_fence_ {};
        std::uint64_t last_server_sequence_ {};
        std::uint64_t next_sequence_ {1};
        std::uint64_t acknowledged_through_ {};
        CreditWindow credit_ {};
        std::uint64_t in_flight_bytes_ {};
        std::uint32_t in_flight_messages_ {};
        std::uint32_t in_flight_snapshot_chunks_ {};
        std::size_t pending_bytes_ {};
        bool backpressured_ {};
        std::deque<OutboundRecord> pending_;
        std::vector<QuarantinedRecord> quarantined_;
        std::vector<AcceptedWork> accepted_work_;
    };

} // namespace rule_engine::python::protocol_v2
