#pragma once

#include "rule_engine/python/contract/runtime.hpp"

#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <vector>

namespace rule_engine::python {

    struct EventEnvelope {
        EventId id;
        SchemaId schema;
        TenantId tenant;
        PeerId peer;
        std::optional<SubjectKey> subject;
        std::uint64_t producer_unix_ms {};
        std::uint64_t ingest_unix_ms {};
        DataLabel label;
        std::optional<EventId> causation;
        FrozenValue payload;
    };

    struct CursorAdvance {
        std::string consumer;
        std::uint64_t expected_position {};
        std::uint64_t new_position {};
    };

    struct OutboxRecord {
        IntentId intent;
        std::string destination;
        FrozenValue payload;
        std::string idempotency_key;
        std::uint64_t not_before_unix_ms {};
    };

    struct RuntimeTransaction {
        EventEnvelope input;
        CursorAdvance cursor;
        EvaluationResult evaluation;
        std::vector<StateMutation> state;
        std::vector<EventEnvelope> emitted_events;
        std::vector<EffectIntent> journal;
        std::vector<OutboxRecord> outbox;
        std::uint64_t fence_token {};
    };

    struct TransactionReceipt {
        EventId input;
        std::uint64_t committed_cursor {};
        std::vector<EventId> emitted_events;
        std::vector<IntentId> outbox_intents;
    };

    enum struct StoreErrorCode : std::uint8_t {
        unavailable,
        conflict,
        stale_fence,
        constraint_violation,
        incompatible_schema,
        canceled,
    };

    struct StoreError {
        StoreErrorCode code {};
        std::string message;
        bool retryable {};
    };

    struct IRuntimeStore {
        virtual ~IRuntimeStore() = default;
        [[nodiscard]] virtual std::expected<TransactionReceipt, StoreError>
        transact_event(const RuntimeTransaction &transaction) = 0;
    };

    inline constexpr std::uint16_t protocol_v2_major = 2;
    inline constexpr std::size_t protocol_v2_pre_negotiation_frame_limit = 16 * mebibyte;

    struct AgentHello {
        std::uint16_t protocol_major {protocol_v2_major};
        std::string agent_version;
        std::vector<SchemaId> schemas;
        std::vector<CapabilityId> capabilities;
        std::uint64_t last_acknowledged_sequence {};
    };

    struct ServerHello {
        std::uint16_t protocol_major {protocol_v2_major};
        SessionId session;
        PeerId peer;
        std::vector<SchemaId> accepted_schemas;
        std::vector<CapabilityId> accepted_capabilities;
        std::uint64_t fence_token {};
        std::size_t frame_limit {};
    };

    enum struct WorkKind : std::uint8_t { fact_batch, scan_batch, snapshot, cancel };

    struct WorkEnvelope {
        SessionId session;
        PeerId peer;
        std::uint64_t fence_token {};
        std::uint64_t sequence {};
        WorkKind kind {};
        std::vector<FactRequest> facts;
        std::vector<ScanRequest> scans;
        std::vector<RequestId> cancellations;
    };

    struct ResultEnvelope {
        SessionId session;
        PeerId peer;
        std::uint64_t fence_token {};
        std::uint64_t sequence {};
        std::vector<FactResponse> facts;
        std::vector<ScanResponse> scans;
    };

    enum struct ActivationPhase : std::uint8_t { staged, compiling, ready, draining, active, failed, rolled_back };

    struct NodeCompilation {
        std::string node_id;
        std::string semantic_hash;
        std::string binding_hash;
        bool healthy {};
        std::vector<Diagnostic> diagnostics;
    };

    struct PackActivation {
        PackId pack;
        PackVersion version;
        SourceDigest source_digest;
        std::uint64_t generation {};
        ActivationPhase phase {ActivationPhase::staged};
        std::vector<NodeCompilation> nodes;
    };

} // namespace rule_engine::python
