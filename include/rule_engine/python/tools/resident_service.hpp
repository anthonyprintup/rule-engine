#pragma once

#include "rule_engine/python/cluster/admin_authorization.hpp"
#include "rule_engine/python/protocol/network.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <vector>

namespace rule_engine::python::tools {

    enum struct ResidentSessionRole : std::uint8_t { agent, administrator };

    struct ResidentServiceLimits {
        std::size_t worker_threads {4U};
        std::size_t maximum_queued_sessions {128U};
        std::size_t maximum_memory_bytes {128U * mebibyte};
        std::size_t maximum_frame_bytes {4U * mebibyte};
        std::size_t maximum_messages_per_session {4'096U};
        std::size_t maximum_inflight_work_per_session {64U};
        std::chrono::milliseconds maximum_session_duration {30'000};
        protocol_v2::CreditWindow inbound_credit {
            .bytes = 16U * mebibyte,
            .messages = 256U,
            .work_attempts = 64U,
            .snapshot_chunks = 64U,
        };
    };

    [[nodiscard]] std::expected<void, protocol_v2::ProtocolError>
    validate_resident_service_limits(const ResidentServiceLimits &limits) noexcept;

    // A single authenticated application channel. Production wraps one owned
    // TLS connection; tests may supply a byte-faithful fake. Every operation is
    // deadline and stop-token bounded.
    struct IResidentSecureChannel {
        virtual ~IResidentSecureChannel() = default;
        [[nodiscard]] virtual std::expected<protocol_v2::PeerEnvelope, protocol_v2::ProtocolError>
        receive_protocol(std::chrono::steady_clock::time_point deadline, std::stop_token cancellation) noexcept = 0;
        [[nodiscard]] virtual std::expected<void, protocol_v2::ProtocolError>
        send_protocol(const protocol_v2::PeerEnvelope &envelope, std::chrono::steady_clock::time_point deadline,
                      std::stop_token cancellation) noexcept = 0;
        [[nodiscard]] virtual std::expected<std::vector<std::byte>, protocol_v2::ProtocolError>
        receive_application_frame(std::chrono::steady_clock::time_point deadline,
                                  std::stop_token cancellation) noexcept = 0;
        [[nodiscard]] virtual std::expected<void, protocol_v2::ProtocolError>
        send_application_frame(std::span<const std::byte> payload,
                               std::chrono::steady_clock::time_point deadline,
                               std::stop_token cancellation) noexcept = 0;
        virtual void shutdown() noexcept = 0;
    };

    [[nodiscard]] std::unique_ptr<IResidentSecureChannel>
    make_resident_tls_channel(protocol_v2::TlsPeerConnection connection);

    struct ResidentAgentSession {
        protocol_v2::AuthenticatedPeer authenticated_peer;
        SessionId session;
        std::uint64_t session_fence {};
        std::string agent_epoch;
        std::uint64_t acknowledged_through {};
        protocol_v2::CreditWindow credit;
    };

    struct DurableAgentReceipt {
        std::uint64_t acknowledged_through {};
        protocol_v2::CreditWindow credit;
    };

    // Implementations own the durable session/result transaction. persist()
    // may report success only after the body and the cumulative receipt are
    // durable. This is the point at which the service is allowed to emit ACK.
    struct IResidentAgentBackend {
        virtual ~IResidentAgentBackend() = default;
        [[nodiscard]] virtual std::expected<ResidentAgentSession, protocol_v2::ProtocolError>
        establish(const protocol_v2::AuthenticatedPeer &peer, const protocol_v2::AgentHelloMessage &hello,
                  std::stop_token cancellation) noexcept = 0;
        [[nodiscard]] virtual std::expected<std::vector<protocol_v2::WorkLeaseMessage>, protocol_v2::ProtocolError>
        take_work(const ResidentAgentSession &session, std::size_t limit, std::stop_token cancellation) noexcept = 0;
        [[nodiscard]] virtual std::expected<DurableAgentReceipt, protocol_v2::ProtocolError>
        persist(const ResidentAgentSession &session, std::uint64_t sequence,
                const protocol_v2::DurableAgentBody &body, std::stop_token cancellation) noexcept = 0;
        virtual void close(const ResidentAgentSession &session) noexcept = 0;
    };

    enum struct ResidentAdminRequestKind : std::uint8_t { pack_snapshot = 1, operation_snapshot = 2, activation_flip = 3 };

    struct ResidentAdminRequest {
        ResidentAdminRequestKind kind {ResidentAdminRequestKind::pack_snapshot};
        std::string request_id;
        TenantId tenant;
        PackId pack;
        std::string operation_id;
        std::string idempotency_key;
        std::uint64_t expected_pack_version {};
        std::uint64_t at_unix_ms {};
    };

    enum struct ResidentAdminResponseStatus : std::uint8_t { ok = 0, rejected = 1, unavailable = 2 };

    struct ResidentAdminResponse {
        ResidentAdminResponseStatus status {ResidentAdminResponseStatus::rejected};
        std::string request_id;
        std::string code;
        std::string diagnostic;
        std::uint64_t storage_revision {};
        std::uint64_t resource_version {};
        std::optional<std::uint64_t> active_generation;
        std::optional<std::uint64_t> previous_active_generation;
    };

    [[nodiscard]] std::expected<std::vector<std::byte>, protocol_v2::ProtocolError>
    encode_resident_admin_request(const ResidentAdminRequest &request, std::size_t maximum_frame_bytes);
    [[nodiscard]] std::expected<ResidentAdminRequest, protocol_v2::ProtocolError>
    decode_resident_admin_request(std::span<const std::byte> payload, std::size_t maximum_frame_bytes);
    [[nodiscard]] std::expected<std::vector<std::byte>, protocol_v2::ProtocolError>
    encode_resident_admin_response(const ResidentAdminResponse &response, std::size_t maximum_frame_bytes);
    [[nodiscard]] std::expected<ResidentAdminResponse, protocol_v2::ProtocolError>
    decode_resident_admin_response(std::span<const std::byte> payload, std::size_t maximum_frame_bytes);

    struct IResidentAdminBackend {
        virtual ~IResidentAdminBackend() = default;
        [[nodiscard]] virtual ResidentAdminResponse execute(const protocol_v2::AuthenticatedPeer &peer,
                                                            const ResidentAdminRequest &request) noexcept = 0;
    };

    struct IResidentAdminAccessPolicy: cluster::IAdminAuthorizer {
        [[nodiscard]] virtual std::expected<cluster::AuthenticatedAdminPrincipal, cluster::AuthorizedAdminError>
        principal_for(const protocol_v2::AuthenticatedPeer &peer) const noexcept = 0;
    };

    struct AuthorizedResidentAdminBackend final: IResidentAdminBackend {
        AuthorizedResidentAdminBackend(cluster::IActivationControlStore &store, const IResidentAdminAccessPolicy &policy,
                                       cluster::IAdminSecurityAuditSink *security_audit = nullptr) noexcept;

        [[nodiscard]] ResidentAdminResponse execute(const protocol_v2::AuthenticatedPeer &peer,
                                                    const ResidentAdminRequest &request) noexcept override;

    private:
        cluster::DurableActivationAdmin durable_;
        const IResidentAdminAccessPolicy &policy_;
        cluster::IAdminSecurityAuditSink *security_audit_ {};
    };

    struct ResidentSessionJob {
        ResidentSessionRole role {ResidentSessionRole::agent};
        protocol_v2::AuthenticatedPeer peer;
        std::unique_ptr<IResidentSecureChannel> channel;
    };

    struct IResidentSessionHandler {
        virtual ~IResidentSessionHandler() = default;
        virtual void run(ResidentSessionJob job, std::stop_token cancellation) noexcept = 0;
    };

    enum struct ResidentAdmission : std::uint8_t { accepted, overloaded, stopped };

    struct ResidentSchedulerSnapshot {
        std::size_t queued_sessions {};
        std::size_t active_sessions {};
        std::size_t accepted_sessions {};
        std::size_t rejected_sessions {};
        bool stopping {};
    };

    struct ResidentServiceScheduler {
        [[nodiscard]] static std::expected<std::unique_ptr<ResidentServiceScheduler>, protocol_v2::ProtocolError>
        create(ResidentServiceLimits limits, IResidentSessionHandler &handler);
        ~ResidentServiceScheduler();

        ResidentServiceScheduler(const ResidentServiceScheduler &) = delete;
        ResidentServiceScheduler &operator=(const ResidentServiceScheduler &) = delete;

        [[nodiscard]] ResidentAdmission submit(ResidentSessionJob job) noexcept;
        void request_stop() noexcept;
        void join() noexcept;
        [[nodiscard]] ResidentSchedulerSnapshot snapshot() const noexcept;

    private:
        struct Impl;
        explicit ResidentServiceScheduler(std::unique_ptr<Impl> impl) noexcept;
        std::unique_ptr<Impl> impl_;
    };

    struct ResidentApplicationService final: IResidentSessionHandler {
        ResidentApplicationService(ResidentServiceLimits limits, const protocol_v2::ITrustPolicy &peer_trust,
                                   IResidentAgentBackend &agents, IResidentAdminBackend &admin) noexcept;

        void run(ResidentSessionJob job, std::stop_token cancellation) noexcept override;

    private:
        void run_agent(ResidentSessionJob &job, std::stop_token cancellation) noexcept;
        void run_admin(ResidentSessionJob &job, std::stop_token cancellation) noexcept;

        ResidentServiceLimits limits_;
        const protocol_v2::ITrustPolicy &peer_trust_;
        IResidentAgentBackend &agents_;
        IResidentAdminBackend &admin_;
    };

} // namespace rule_engine::python::tools
