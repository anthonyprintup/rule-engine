#pragma once

#include "rule_engine/python/contract.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace rule_engine::python::protocol_v2 {

    inline constexpr std::uint16_t major_version = 2;
    inline constexpr std::uint16_t initial_minor_version = 0;

    struct ProtocolLimits {
        std::size_t maximum_frame_bytes {protocol_v2_pre_negotiation_frame_limit};
        std::size_t maximum_string_bytes {1 * mebibyte};
        std::size_t maximum_blob_bytes {16 * mebibyte};
        std::size_t maximum_collection_items {100'000};
        std::size_t maximum_total_value_nodes {250'000};
        std::size_t maximum_subject_depth {32};
        std::size_t maximum_value_depth {32};
        std::size_t maximum_identity_fields {64};
        std::size_t maximum_fact_requests {512};
        std::size_t maximum_scan_requests {128};
        std::size_t maximum_scan_patterns {4'096};
        std::size_t maximum_scan_matches {100'000};
        std::size_t maximum_label_categories {64};
        std::size_t maximum_snapshot_items {100'000};
        std::size_t maximum_snapshot_bytes {16 * mebibyte};
        std::size_t maximum_sequence_gap {4'096};
    };

    enum struct ProtocolErrorCode : std::uint8_t {
        truncated,
        malformed,
        unsupported_version,
        unexpected_message,
        duplicate_field,
        invalid_utf8,
        invalid_identity,
        invalid_value,
        limit_exceeded,
        sequence_gap,
        stale_session,
        stale_fence,
        stale_generation,
        schema_mismatch,
        capability_mismatch,
        digest_mismatch,
        duplicate_item,
        backpressured,
        unknown_route,
        provider_violation,
        canceled,
        unauthenticated,
        dependency_unavailable,
        transport_error,
        persistence_error,
    };

    struct ProtocolError {
        ProtocolErrorCode code {ProtocolErrorCode::malformed};
        std::string message;
        std::size_t byte_offset {};
    };

    struct SchemaAdvertisement {
        SchemaId schema;
        std::uint32_t major {};
        std::string canonical_hash;
    };

    struct CapabilityAdvertisement {
        CapabilityId capability;
        std::uint32_t version {};
        SchemaId request_schema;
        SchemaId response_schema;
    };

    struct CreditWindow {
        std::uint64_t bytes {};
        std::uint32_t messages {};
        std::uint32_t work_attempts {};
        std::uint32_t snapshot_chunks {};
    };

    struct AgentHelloMessage {
        std::uint16_t minimum_minor {initial_minor_version};
        std::uint16_t maximum_minor {initial_minor_version};
        std::string agent_version;
        std::string agent_epoch;
        std::uint64_t next_sequence {1};
        std::vector<SchemaAdvertisement> schemas;
        std::vector<CapabilityAdvertisement> capabilities;
        CreditWindow receive_limit;
    };

    struct ServerHelloMessage {
        std::uint16_t selected_minor {initial_minor_version};
        SessionId session;
        PeerId peer;
        std::uint64_t session_fence {};
        std::uint64_t acknowledged_sequence {};
        std::vector<SchemaAdvertisement> schemas;
        std::vector<CapabilityAdvertisement> capabilities;
        CreditWindow credit;
        std::uint64_t heartbeat_interval_ms {};
    };

    struct WorkLeaseMessage {
        SessionId session;
        PeerId peer;
        std::uint64_t session_fence {};
        std::string work_id;
        std::string attempt_id;
        std::uint64_t work_fence {};
        std::uint64_t generation {};
        std::uint64_t server_sequence {};
        std::string route;
        std::vector<FactRequest> facts;
        std::vector<ScanRequest> scans;
    };

    struct WorkResultMessage {
        SessionId originating_session;
        PeerId peer;
        std::uint64_t originating_session_fence {};
        std::string work_id;
        std::string attempt_id;
        std::uint64_t work_fence {};
        std::uint64_t generation {};
        std::vector<FactResponse> facts;
        std::vector<ScanResponse> scans;
    };

    struct CancelWorkMessage {
        SessionId session;
        PeerId peer;
        std::uint64_t session_fence {};
        std::string work_id;
        std::string attempt_id;
        std::uint64_t work_fence {};
        std::uint64_t server_sequence {};
        std::string route;
        std::vector<RequestId> requests;
    };

    struct AuthoritativeSnapshotBegin {
        SessionId session;
        PeerId peer;
        std::uint64_t session_fence {};
        std::string snapshot_id;
        std::optional<SubjectKey> parent;
        SchemaId subject_schema;
        std::uint64_t generation {};
        std::uint64_t expected_count {};
        std::string expected_digest;
    };

    struct AuthoritativeSnapshotChunk {
        SessionId session;
        PeerId peer;
        std::uint64_t session_fence {};
        std::string snapshot_id;
        std::uint64_t generation {};
        std::uint32_t chunk_index {};
        std::vector<SubjectKey> subjects;
    };

    struct AuthoritativeSnapshotCommit {
        SessionId session;
        PeerId peer;
        std::uint64_t session_fence {};
        std::string snapshot_id;
        std::uint64_t generation {};
        std::uint64_t item_count {};
        std::string canonical_digest;
    };

    struct AckMessage {
        std::string agent_epoch;
        std::uint64_t acknowledged_through {};
        CreditWindow credit;
    };

    struct NackMessage {
        std::string agent_epoch;
        std::uint64_t sequence {};
        ProtocolErrorCode reason {ProtocolErrorCode::malformed};
        bool permanent {};
        std::string diagnostic;
    };

    struct CreditUpdateMessage {
        CreditWindow credit;
    };

    using MessageBody = std::variant<AgentHelloMessage, ServerHelloMessage, WorkLeaseMessage, WorkResultMessage,
                                     CancelWorkMessage, AuthoritativeSnapshotBegin, AuthoritativeSnapshotChunk,
                                     AuthoritativeSnapshotCommit, AckMessage, NackMessage, CreditUpdateMessage>;

    using DurableAgentBody = std::variant<WorkResultMessage, AuthoritativeSnapshotBegin, AuthoritativeSnapshotChunk,
                                          AuthoritativeSnapshotCommit>;

    enum struct MessageKind : std::uint8_t {
        agent_hello = 1,
        server_hello = 2,
        work_lease = 3,
        work_result = 4,
        cancel_work = 5,
        snapshot_begin = 6,
        snapshot_chunk = 7,
        snapshot_commit = 8,
        ack = 9,
        nack = 10,
        credit_update = 11,
    };

    struct PeerEnvelope {
        std::uint16_t protocol_major {major_version};
        std::uint16_t protocol_minor {initial_minor_version};
        std::string message_id;
        std::optional<SessionId> session;
        std::string agent_epoch;
        std::uint64_t agent_sequence {};
        std::uint64_t acknowledged_agent_sequence {};
        MessageBody body;
    };

    [[nodiscard]] MessageKind message_kind(const MessageBody &body) noexcept;

} // namespace rule_engine::python::protocol_v2
