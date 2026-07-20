#pragma once

#include "rule_engine/python/contract.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace rule_engine::python::events {

    enum struct ErrorCode : std::uint8_t {
        invalid_identity,
        invalid_schema,
        schema_mismatch,
        invalid_label,
        invalid_bounds,
        unauthorized,
        duplicate_conflict,
        invalid_cursor,
        state_conflict,
        replay_exhausted,
        replay_diverged,
        budget_exhausted,
        group_busy,
        stale_group_lease,
        causation_cycle,
        causation_depth_exceeded,
        quota_exceeded,
        not_found,
        store_failure,
        invalid_transition,
        group_quarantined,
    };

    struct Error {
        ErrorCode code {};
        std::string message;
    };

    enum struct EventFamily : std::uint8_t {
        observation,
        removal,
        match,
        fault,
        action_delivery,
        capture_result,
        custom_observation,
    };

    enum struct PayloadShape : std::uint8_t {
        null_value,
        boolean,
        integer,
        floating_point,
        unicode,
        bytes,
        enumeration,
        list,
        map,
        record,
    };

    struct EventSchema {
        SchemaId id;
        EventFamily family {EventFamily::observation};
        PayloadShape payload_shape {PayloadShape::record};
        std::optional<SchemaId> payload_record_schema;
        DataLabel label_ceiling;
        bool subject_required {};
    };

    struct EventRuntimeLimits {
        std::uint32_t maximum_history_rows {10'000};
        std::uint32_t maximum_history_page_rows {1'000};
        std::uint64_t maximum_history_span_ms {31ULL * 24ULL * 60ULL * 60ULL * 1'000ULL};
        std::size_t maximum_group_key_bytes {4 * kibibyte};
        std::uint32_t maximum_group_key_depth {16};
        std::uint32_t maximum_causation_depth {32};
        std::uint32_t maximum_retention_intents {256};
        std::uint32_t maximum_capture_intents {64};
    };

    struct EventAdmission {
        std::uint64_t ingest_position {};
        bool duplicate {};
        std::uint32_t causation_depth {};
    };

    enum struct HistoryTimeBasis : std::uint8_t { ingest, producer };

    struct HistoryCursor {
        std::string plan_fingerprint;
        std::uint64_t snapshot_ingest_position {};
        std::uint64_t selected_timestamp {};
        EventId event;
        std::uint32_t returned_rows {};
    };

    struct HistoryPlan {
        TenantId tenant;
        std::optional<PeerId> peer;
        bool fleet_history {};
        std::vector<SchemaId> schemas;
        HistoryTimeBasis time_basis {HistoryTimeBasis::ingest};
        std::uint64_t begin_unix_ms {};
        std::uint64_t end_unix_ms {};
        std::uint32_t limit {};
        std::uint32_t page_rows {};
        DataLabel result_ceiling;
        std::optional<HistoryCursor> after;
    };

    struct HistoryPage {
        std::vector<EventEnvelope> events;
        std::optional<HistoryCursor> next;
    };

    struct StateNamespace {
        TenantId tenant;
        ExecutableId owner;
        std::string namespace_id;
        SchemaId schema;
        DataLabel label_ceiling;
        std::vector<ExecutableId> shared_readers;
        std::vector<ExecutableId> shared_writers;
    };

    struct StateAddress {
        TenantId tenant;
        ExecutableId owner;
        std::string namespace_id;
        SchemaId schema;
        std::optional<PeerId> peer;
        std::string scope;
        std::string key;
    };

    struct StateAccess {
        TenantId tenant;
        ExecutableId actor;
        std::uint64_t evaluation_ingest_unix_ms {};
    };

    struct StateRead {
        std::optional<FrozenValue> value;
        std::uint64_t version {};
    };

    struct StateCommitReceipt {
        bool committed {};
        std::uint32_t writes {};
        std::uint64_t highest_version {};
    };

    struct StateSnapshotCell {
        StateAddress address;
        std::optional<FrozenValue> value;
        std::uint64_t version {};
        std::uint64_t modified_ingest_unix_ms {};
    };

    struct StateStagedMutation {
        StateAddress address;
        std::uint64_t expected_version {};
        std::optional<FrozenValue> value;
    };

    struct StateOverlay {
    public:
        [[nodiscard]] std::expected<StateRead, Error> read(const StateAddress &address);
        [[nodiscard]] std::expected<void, Error> write(const StateAddress &address, FrozenValue value);
        [[nodiscard]] std::expected<void, Error> erase(const StateAddress &address);
        [[nodiscard]] const std::vector<StateStagedMutation> &staged() const noexcept { return staged_; }

    private:
        friend struct InMemoryReferenceRuntime;

        StateAccess access_;
        std::map<std::string, StateNamespace, std::less<>> namespaces_;
        std::map<std::string, StateSnapshotCell, std::less<>> snapshot_;
        std::map<std::string, std::uint64_t, std::less<>> read_versions_;
        std::vector<StateStagedMutation> staged_;
        std::uint64_t purge_epoch_ {};
    };

    struct CapturedInputs {
        [[nodiscard]] std::expected<void, Error> capture(std::string key, FrozenValue value);
        void seal() noexcept { sealed_ = true; }
        [[nodiscard]] bool sealed() const noexcept { return sealed_; }
        [[nodiscard]] std::expected<const FrozenValue *, Error> resolve(std::string_view key) const;
        [[nodiscard]] std::size_t size() const noexcept { return values_.size(); }

    private:
        bool sealed_ {};
        std::map<std::string, FrozenValue, std::less<>> values_;
    };

    struct SharedRetryBudget {
        std::uint64_t limit {};
        std::uint64_t consumed {};

        [[nodiscard]] std::expected<void, Error> charge(std::uint64_t units);
        [[nodiscard]] std::uint64_t remaining() const noexcept { return limit >= consumed ? limit - consumed : 0; }
    };

    enum struct ConflictDisposition : std::uint8_t { retry, exhausted };

    struct MvccRetryController {
        static constexpr std::uint32_t maximum_attempts = 3;

        explicit MvccRetryController(std::uint64_t shared_budget_limit):
            budget {.limit = shared_budget_limit, .consumed = 0} {}

        [[nodiscard]] std::expected<std::uint32_t, Error> begin_attempt();
        [[nodiscard]] ConflictDisposition state_conflict();
        void complete() noexcept;

        CapturedInputs inputs;
        SharedRetryBudget budget;

    private:
        std::uint32_t attempts_started_ {};
        bool attempt_active_ {};
        bool finished_ {};
    };

    struct CorrelationKey;
    using CorrelationTuple = std::vector<CorrelationKey>;

    struct CorrelationKey {
        std::variant<std::monostate, bool, IntegerValue, UnicodeValue, BytesValue, EnumValue, CorrelationTuple> value;
    };

    [[nodiscard]] std::expected<std::string, Error> canonical_group_key(const CorrelationKey &key,
                                                                        const EventRuntimeLimits &limits = {});

    struct CorrelationEdge {
        BindingId source;
        BindingId target;
    };

    [[nodiscard]] std::expected<void, Error> validate_correlation_dag(const std::vector<CorrelationEdge> &edges);

    struct CorrelationGroupId {
        TenantId tenant;
        ExecutableId executable;
        BindingId binding;
        std::string canonical_key;
    };

    struct CorrelationLease {
        CorrelationGroupId group;
        std::uint64_t expected_cursor {};
        std::uint64_t token {};
    };

    enum struct CorrelationCompletion : std::uint8_t {
        committed,
        defined_fault,
        quarantined,
        retryable_fault,
        rolled_back,
    };

    struct CorrelationTimePolicy {
        HistoryTimeBasis time_basis {HistoryTimeBasis::ingest};
        std::uint64_t allowed_lateness_ms {};
        std::uint64_t accepted_clock_skew_ms {};
    };

    struct WindowAdmission {
        std::uint64_t selected_timestamp {};
        std::uint64_t watermark {};
        bool late_beyond_watermark {};
    };

    struct RetentionProfile {
        std::string id;
        DataLabel label_ceiling;
        std::uint64_t maximum_ttl_ms {};
        std::uint32_t maximum_intents {};
    };

    struct RetentionIntent {
        IntentId id;
        TenantId tenant;
        EventId event;
        std::string profile;
        DataLabel label;
        std::uint64_t expires_unix_ms {};
        bool logical_read {};
    };

    struct CaptureProfile {
        std::string id;
        DataLabel label_ceiling;
        std::uint64_t maximum_ttl_ms {};
        std::uint32_t maximum_pending {};
    };

    struct CaptureIntent {
        IntentId id;
        TenantId tenant;
        PeerId peer;
        std::optional<SubjectKey> subject;
        std::string profile;
        FrozenValue parameters;
        EventId anchor;
        std::string reason;
        std::string dedupe_key;
        std::uint64_t expires_unix_ms {};
        bool dry_run {};
    };

    struct CaptureReceipt {
        IntentId id;
        bool duplicate {};
        bool dry_run {};
    };

    struct PurgeRequest {
        TenantId tenant;
        std::optional<PeerId> peer;
        std::uint64_t begin_ingest_unix_ms {};
        std::uint64_t end_ingest_unix_ms {};
        std::string reason;
    };

    struct PurgePreview {
        std::uint64_t events {};
        std::uint64_t state_cells {};
        std::uint64_t retention_intents {};
        std::uint64_t capture_intents {};
    };

    struct PurgeAudit {
        std::uint64_t purge_epoch {};
        PurgeRequest request;
        PurgePreview removed;
        std::vector<EventId> tombstones;
    };

    struct InMemoryReferenceRuntime {
        explicit InMemoryReferenceRuntime(EventRuntimeLimits limits = {}): limits_(limits) {}

        [[nodiscard]] std::expected<void, Error> register_event_schema(EventSchema schema);
        [[nodiscard]] std::expected<EventAdmission, Error> append_event(EventEnvelope event);
        [[nodiscard]] std::expected<HistoryPage, Error> query_history(const HistoryPlan &plan) const;

        [[nodiscard]] std::expected<void, Error> register_state_namespace(StateNamespace state_namespace);
        [[nodiscard]] std::expected<StateOverlay, Error> begin_state(StateAccess access) const;
        [[nodiscard]] std::expected<StateCommitReceipt, Error> commit_state(StateOverlay &overlay, bool commit);

        [[nodiscard]] std::expected<CorrelationLease, Error> claim_group(const CorrelationGroupId &group);
        [[nodiscard]] std::expected<WindowAdmission, Error> admit_group_event(const CorrelationLease &lease,
                                                                              const EventEnvelope &event,
                                                                              const CorrelationTimePolicy &policy,
                                                                              std::uint64_t server_now_unix_ms);
        [[nodiscard]] std::expected<std::uint64_t, Error> complete_group(const CorrelationLease &lease,
                                                                         CorrelationCompletion completion);
        [[nodiscard]] std::expected<void, Error> clear_group_quarantine(const CorrelationGroupId &group);
        [[nodiscard]] std::uint64_t group_cursor(const CorrelationGroupId &group) const;

        [[nodiscard]] std::expected<void, Error> retain(const RetentionProfile &profile, RetentionIntent intent,
                                                        std::uint64_t now_unix_ms);
        [[nodiscard]] std::expected<CaptureReceipt, Error> capture(const CaptureProfile &profile, CaptureIntent intent,
                                                                   std::uint64_t now_unix_ms);
        [[nodiscard]] std::expected<PurgePreview, Error> preview_purge(const PurgeRequest &request) const;
        [[nodiscard]] std::expected<PurgeAudit, Error> purge(const PurgeRequest &request);

        [[nodiscard]] std::vector<PurgeAudit> purge_audits() const;

    private:
        struct StoredEvent {
            EventEnvelope envelope;
            std::uint64_t ingest_position {};
            std::uint32_t causation_depth {};
        };

        struct GroupState {
            std::uint64_t cursor {};
            std::uint64_t next_token {1};
            std::optional<std::uint64_t> active_token;
            std::uint64_t maximum_producer_timestamp {};
            std::uint64_t watermark {};
            bool quarantined {};
        };

        [[nodiscard]] std::expected<void, Error> validate_event(const EventEnvelope &event) const;
        [[nodiscard]] static std::string state_namespace_key(const StateNamespace &state_namespace);
        [[nodiscard]] static std::string state_address_key(const StateAddress &address);
        [[nodiscard]] static std::string group_key(const CorrelationGroupId &group);
        [[nodiscard]] PurgePreview preview_purge_locked(const PurgeRequest &request) const;

        EventRuntimeLimits limits_;
        mutable std::mutex mutex_;
        std::map<std::string, EventSchema, std::less<>> event_schemas_;
        std::vector<StoredEvent> events_;
        std::map<std::string, std::size_t, std::less<>> event_index_;
        std::set<std::string, std::less<>> event_tombstones_;
        std::map<std::string, StateNamespace, std::less<>> state_namespaces_;
        std::map<std::string, StateSnapshotCell, std::less<>> state_cells_;
        std::map<std::string, GroupState, std::less<>> groups_;
        std::vector<RetentionIntent> retention_intents_;
        std::vector<CaptureIntent> capture_intents_;
        std::map<std::string, IntentId, std::less<>> capture_dedupe_;
        std::vector<PurgeAudit> purge_audits_;
        std::uint64_t next_ingest_position_ {1};
        std::uint64_t purge_epoch_ {};
    };

} // namespace rule_engine::python::events
