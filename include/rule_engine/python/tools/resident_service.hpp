#pragma once

#include "rule_engine/python/cluster/admin_authorization.hpp"
#include "rule_engine/python/protocol/network.hpp"
#include "rule_engine/python/tools/active_pack.hpp"

#include <atomic>
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
        std::chrono::milliseconds work_poll_interval {250};
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
        // False means the deadline elapsed. Implementations must not consume a
        // partial frame while checking readiness.
        [[nodiscard]] virtual std::expected<bool, protocol_v2::ProtocolError>
        wait_protocol_input(std::chrono::steady_clock::time_point deadline, std::stop_token cancellation) noexcept = 0;
        [[nodiscard]] virtual std::expected<void, protocol_v2::ProtocolError>
        send_protocol(const protocol_v2::PeerEnvelope &envelope, std::chrono::steady_clock::time_point deadline,
                      std::stop_token cancellation) noexcept = 0;
        [[nodiscard]] virtual std::expected<std::vector<std::byte>, protocol_v2::ProtocolError>
        receive_application_frame(std::chrono::steady_clock::time_point deadline,
                                  std::stop_token cancellation) noexcept = 0;
        [[nodiscard]] virtual std::expected<void, protocol_v2::ProtocolError>
        send_application_frame(std::span<const std::byte> payload, std::chrono::steady_clock::time_point deadline,
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
        std::vector<protocol_v2::SchemaAdvertisement> schemas;
        std::vector<protocol_v2::CapabilityAdvertisement> capabilities;
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
        [[nodiscard]] virtual std::expected<void, protocol_v2::ProtocolError>
        activate(std::span<const ResidentActivePack> packs) noexcept {
            if (packs.empty()) {
                return {};
            }
            return std::unexpected(protocol_v2::ProtocolError {
                .code = protocol_v2::ProtocolErrorCode::dependency_unavailable,
                .message = "agent backend does not implement active-pack evaluation",
            });
        }
        [[nodiscard]] virtual std::expected<ResidentAgentSession, protocol_v2::ProtocolError>
        establish(const protocol_v2::AuthenticatedPeer &peer, const protocol_v2::AgentHelloMessage &hello,
                  std::stop_token cancellation) noexcept = 0;
        [[nodiscard]] virtual std::expected<std::vector<protocol_v2::WorkLeaseMessage>, protocol_v2::ProtocolError>
        take_work(const ResidentAgentSession &session, std::size_t limit, std::stop_token cancellation) noexcept = 0;
        [[nodiscard]] virtual std::expected<DurableAgentReceipt, protocol_v2::ProtocolError>
        persist(const ResidentAgentSession &session, std::uint64_t sequence, const protocol_v2::DurableAgentBody &body,
                std::stop_token cancellation) noexcept = 0;
        virtual void close(const ResidentAgentSession &session) noexcept = 0;
        virtual void fence_activation() noexcept {}
    };

    enum struct ResidentAdminRequestKind : std::uint8_t {
        pack_snapshot = 1,
        operation_snapshot = 2,
        activation_flip = 3,
        activation_preview = 4,
        activation_drain = 5,
        activation_fence = 6,
        upload_begin = 7,
        upload_chunk = 8,
        upload_finalize = 9,
        stage_preview = 10,
        stage_apply = 11,
        rollback_preview = 12,
        rollback_apply = 13,
    };

    struct ResidentAdminRequest {
        ResidentAdminRequestKind kind {ResidentAdminRequestKind::pack_snapshot};
        std::string request_id;
        TenantId tenant;
        PackId pack;
        std::string operation_id;
        std::string idempotency_key;
        std::uint64_t expected_pack_version {};
        std::uint64_t at_unix_ms {};
        std::string reason;
        std::uint64_t target_generation {};
        std::uint64_t rollback_source_generation {};
        std::uint64_t drain_boundary {};
        std::vector<std::string> work_ids;
        std::uint64_t upload_offset {};
        std::uint64_t upload_total_bytes {};
        std::vector<std::byte> payload;
        SourceDigest source_digest;
        std::string state_schema_hash;
        std::string state_namespace;
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
        std::string operation_phase;
        std::uint64_t target_generation {};
        std::uint64_t drain_boundary {};
        std::uint64_t assignment_fence {};
        std::vector<std::string> work_ids;
        std::uint64_t upload_received_bytes {};
        std::uint64_t upload_total_bytes {};
        std::optional<SourceDigest> source_digest;
        std::uint64_t registry_maintenance_runs {};
        std::uint64_t registry_last_maintenance_unix_ms {};
        std::uint64_t registry_expired_partial_sessions {};
        std::uint64_t registry_removed_completion_records {};
        std::uint64_t registry_removed_objects {};
        std::uint64_t registry_reclaimed_bytes {};
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

    struct ResidentPackUploadReceipt {
        std::uint64_t received_bytes {};
        std::uint64_t total_bytes {};
        std::optional<SourceDigest> source_digest;
    };

    struct ResidentPackRegistryMaintenanceReceipt {
        std::uint64_t expired_partial_sessions {};
        std::uint64_t removed_completion_records {};
        std::uint64_t removed_objects {};
        std::uint64_t reclaimed_bytes {};
    };

    struct ResidentPackRegistryObservation {
        std::uint64_t successful_maintenance_runs {};
        std::uint64_t last_maintenance_unix_ms {};
        std::uint64_t expired_partial_sessions {};
        std::uint64_t removed_completion_records {};
        std::uint64_t removed_objects {};
        std::uint64_t reclaimed_bytes {};

        auto operator<=>(const ResidentPackRegistryObservation &) const = default;
    };

    struct IResidentPackUploadBackend {
        virtual ~IResidentPackUploadBackend() = default;
        [[nodiscard]] virtual std::expected<ResidentPackUploadReceipt, protocol_v2::ProtocolError>
        begin(const TenantId &tenant, const PackId &pack, std::string_view upload_id,
              std::uint64_t total_bytes) noexcept = 0;
        [[nodiscard]] virtual std::expected<ResidentPackUploadReceipt, protocol_v2::ProtocolError>
        append(const TenantId &tenant, const PackId &pack, std::string_view upload_id, std::uint64_t offset,
               std::span<const std::byte> payload) noexcept = 0;
        [[nodiscard]] virtual std::expected<ResidentPackUploadReceipt, protocol_v2::ProtocolError>
        finalize(const TenantId &tenant, const PackId &pack, std::string_view upload_id) noexcept = 0;
        [[nodiscard]] virtual std::expected<ResidentPackRegistryMaintenanceReceipt, protocol_v2::ProtocolError>
        maintain(std::span<const SourceDigest> reachable_source_digests, std::uint64_t now_unix_ms) noexcept = 0;
        [[nodiscard]] virtual std::expected<ResidentPackRegistryObservation, protocol_v2::ProtocolError>
        observe_maintenance() noexcept = 0;
    };

    struct IResidentStageSourceBackend {
        virtual ~IResidentStageSourceBackend() = default;
        [[nodiscard]] virtual std::expected<cluster::GenerationRequest, protocol_v2::ProtocolError>
        resolve(const PackId &pack, const SourceDigest &source_digest, std::uint64_t generation,
                std::string_view state_schema_hash, std::string_view state_namespace) noexcept = 0;
    };

    struct AuthorizedResidentAdminBackend final: IResidentAdminBackend {
        AuthorizedResidentAdminBackend(cluster::IActivationControlStore &store,
                                       const IResidentAdminAccessPolicy &policy,
                                       cluster::IAdminSecurityAuditSink *security_audit = nullptr,
                                       IResidentPackUploadBackend *uploads = nullptr,
                                       IResidentStageSourceBackend *stages = nullptr,
                                       IResidentAgentBackend *activation_target = nullptr) noexcept;

        [[nodiscard]] ResidentAdminResponse execute(const protocol_v2::AuthenticatedPeer &peer,
                                                    const ResidentAdminRequest &request) noexcept override;

    private:
        cluster::DurableActivationAdmin durable_;
        const IResidentAdminAccessPolicy &policy_;
        cluster::IAdminSecurityAuditSink *security_audit_ {};
        IResidentPackUploadBackend *uploads_ {};
        IResidentStageSourceBackend *stages_ {};
        IResidentAgentBackend *activation_target_ {};
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

    // Process-local, payload-free polling evidence. Totals saturate instead of
    // wrapping so a long-running resident never reports deceptively small
    // values. Delay is measured from the first observed empty poll in an idle
    // period (or the start of an immediately nonempty poll) through the last
    // successfully sent lease in that poll.
    struct ResidentWorkPollSnapshot {
        std::uint64_t empty_polls {};
        std::uint64_t nonempty_polls {};
        std::uint64_t delivered_work {};
        std::uint64_t delivery_delay_samples {};
        std::uint64_t delivery_delay_total_microseconds {};
        std::uint64_t delivery_delay_max_microseconds {};

        void merge(const ResidentWorkPollSnapshot &other) noexcept;
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
        [[nodiscard]] ResidentWorkPollSnapshot work_poll_snapshot() const noexcept;

    private:
        void run_agent(ResidentSessionJob &job, std::stop_token cancellation) noexcept;
        void run_admin(ResidentSessionJob &job, std::stop_token cancellation) noexcept;

        ResidentServiceLimits limits_;
        const protocol_v2::ITrustPolicy &peer_trust_;
        IResidentAgentBackend &agents_;
        IResidentAdminBackend &admin_;
        std::atomic<std::uint64_t> empty_work_polls_ {};
        std::atomic<std::uint64_t> nonempty_work_polls_ {};
        std::atomic<std::uint64_t> delivered_work_ {};
        std::atomic<std::uint64_t> delivery_delay_samples_ {};
        std::atomic<std::uint64_t> delivery_delay_total_microseconds_ {};
        std::atomic<std::uint64_t> delivery_delay_max_microseconds_ {};
    };

} // namespace rule_engine::python::tools
