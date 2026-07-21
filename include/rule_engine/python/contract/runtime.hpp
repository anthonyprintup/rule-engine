#pragma once

#include "rule_engine/python/contract/compiler.hpp"
#include "rule_engine/python/contract/subject.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace rule_engine::python {

    enum struct EvaluationOutcome : std::uint8_t { match, no_match, faulted, quarantined, canceled };

    enum struct EffectDisposition : std::uint8_t { pending, committed, rolled_back, suppressed, dry_run };

    struct EffectPolicySnapshot {
        std::string policy_id;
        std::string policy_digest;
        DataLabel sink_ceiling;
        bool dry_run {};
    };

    struct EffectIntent {
        IntentId id;
        InvocationId invocation;
        ExecutableId owner;
        BindingId binding;
        std::uint64_t sequence {};
        std::string kind;
        FrozenValue payload;
        SourceSpan span;
        EffectPolicySnapshot policy;
        EffectDisposition disposition {EffectDisposition::pending};
        std::string idempotency_key;
    };

    struct StateReadRequest {
        RequestId request_id;
        ExecutableId owner;
        std::string namespace_name;
        std::string key;
        SchemaId schema;
    };

    struct StateReadResponse {
        RequestId request_id;
        std::optional<FrozenValue> value;
        std::uint64_t version {};
        std::optional<Diagnostic> diagnostic;
    };

    struct StateMutation {
        ExecutableId owner;
        std::string namespace_name;
        std::string key;
        std::uint64_t expected_version {};
        std::optional<FrozenValue> value;
    };

    struct CapabilityRequest {
        RequestId request_id;
        CapabilityId capability;
        SchemaId request_schema;
        FrozenValue arguments;
        std::uint64_t deadline_unix_ms {};
    };

    struct CapabilityResponse {
        RequestId request_id;
        FactTerminalStatus status {FactTerminalStatus::failed};
        std::optional<FrozenValue> value;
        std::optional<Diagnostic> diagnostic;
    };

    struct HistoryRequest {
        RequestId request_id;
        TenantId tenant;
        PeerId peer;
        SchemaId event_schema;
        std::uint64_t begin_ingest_unix_ms {};
        std::uint64_t end_ingest_unix_ms {};
        std::uint32_t limit {};
    };

    struct HistoryResponse {
        RequestId request_id;
        std::vector<FrozenValue> rows;
        std::optional<Diagnostic> diagnostic;
    };

    struct HostResponses {
        std::vector<FactResponse> facts;
        std::vector<ScanResponse> scans;
        std::vector<CapabilityResponse> capabilities;
        std::vector<StateReadResponse> state;
        std::vector<HistoryResponse> history;
        bool cancel {};
    };

    struct FaultFrame {
        std::string code;
        std::string message;
        ExecutableId executable;
        SourceSpan span;
    };

    struct FaultChain {
        std::vector<FaultFrame> frames;
        bool double_fault {};
        bool triple_fault {};
    };

    struct RecorderEvent {
        std::uint64_t sequence {};
        std::string kind;
        SourceSpan span;
        DataLabel label;
        std::string summary;
    };

    struct EvaluationResult {
        EvaluationOutcome outcome {EvaluationOutcome::faulted};
        std::optional<bool> verdict;
        std::vector<EffectIntent> committed_effects;
        std::vector<StateMutation> state_mutations;
        std::optional<FaultChain> fault;
    };

    enum struct VmStepState : std::uint8_t {
        yielded,
        waiting_for_facts,
        waiting_for_capabilities,
        complete,
        faulted,
        quarantined,
        canceled,
    };

    struct VmStep {
        VmStepState state {VmStepState::yielded};
        std::vector<FactRequest> fact_requests;
        std::vector<ScanRequest> scan_requests;
        std::vector<CapabilityRequest> capability_requests;
        std::vector<StateReadRequest> state_requests;
        std::vector<HistoryRequest> history_requests;
        std::vector<EffectIntent> journal_delta;
        std::vector<RecorderEvent> recorder_delta;
        std::optional<PyValue> yielded_value;
        std::optional<EvaluationResult> result;
    };

    // Normal-executor work consumed by one fresh VM session. Cumulative fields
    // are evaluation-owned across transparent retries. Peak fields describe
    // independently bounded, per-attempt resident resources and therefore use
    // max aggregation rather than subtraction from the next attempt.
    struct VmResourceUsage {
        std::chrono::nanoseconds elapsed {};
        std::chrono::nanoseconds active_cpu {};
        std::uint64_t instructions {};
        std::uint32_t peak_frames {};
        std::size_t peak_live_heap_bytes {};
        std::size_t logical_heap_allocation_bytes {};
        std::uint64_t loop_iterations_and_yields {};
        std::uint32_t logical_facts {};
        std::uint32_t provider_rounds {};
        std::size_t fact_bytes {};
        std::uint32_t service_calls {};
        std::uint32_t peak_active_service_calls {};
        std::size_t service_response_bytes {};
        std::uint32_t history_queries {};
        std::uint32_t history_rows {};
        std::size_t history_bytes {};
        std::uint32_t state_keys {};
        std::size_t state_bytes {};
        std::uint32_t effect_intents {};
        std::size_t effect_bytes {};
        std::uint32_t recorder_events {};
        std::size_t recorder_bytes {};
    };

    struct VmSession {
        virtual ~VmSession() = default;
        [[nodiscard]] virtual VmStep step(HostResponses responses) = 0;
        [[nodiscard]] virtual VmResourceUsage resource_usage() const noexcept = 0;
    };

    struct VmInvocation {
        ExecutionId execution;
        InvocationId invocation;
        BindingId binding;
        SubjectKey subject;
        BudgetProfile budget {balanced_v1};
        std::uint64_t deterministic_hash_seed {};
    };

    struct VmFactory {
        virtual ~VmFactory() = default;
        [[nodiscard]] virtual std::expected<std::unique_ptr<VmSession>, DiagnosticSet>
        start(const CompiledPack &pack, const VmInvocation &invocation) = 0;
    };

} // namespace rule_engine::python
