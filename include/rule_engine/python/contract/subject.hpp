#pragma once

#include "rule_engine/python/contract/core.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <variant>
#include <vector>

namespace rule_engine::python {

    using IdentityScalar = std::variant<bool, std::int64_t, std::uint64_t, IntegerValue, UnicodeValue, BytesValue>;

    struct IdentityField {
        std::uint32_t field_id {};
        IdentityScalar value;
    };

    struct SubjectKey {
        PeerId peer;
        SchemaId descriptor;
        std::vector<IdentityField> identity;
        std::shared_ptr<const SubjectKey> parent;

        [[nodiscard]] bool valid() const noexcept;
    };

    [[nodiscard]] std::string canonical_subject_key(const SubjectKey &subject);

    enum struct FactTerminalStatus : std::uint8_t {
        value,
        unavailable,
        unsupported,
        denied,
        timed_out,
        failed,
        canceled,
    };

    struct FactRoute {
        std::string provider;
        std::string fact;
    };

    struct FactRequest {
        RequestId request_id;
        SubjectKey subject;
        FactRoute route;
        SchemaId expected_schema;
        std::uint64_t deadline_unix_ms {};
    };

    struct ScanSpace {
        std::string kind;
        std::uint64_t begin {};
        std::uint64_t size {};
        std::uint32_t permissions {};
        std::string identity;
        DataLabel label;
        std::uint64_t subject_generation {};
    };

    enum struct ScanResultMode : std::uint8_t { exact_complete = 1, existential = 2 };

    struct ScanPlan {
        std::string plan_id;
        std::string encoded_pattern;
        std::uint64_t maximum_bytes {};
        std::uint32_t maximum_matches {};
        std::uint32_t context_bytes_before {};
        std::uint32_t context_bytes_after {};
        ScanResultMode result_mode {ScanResultMode::exact_complete};
    };

    struct ScanRequest {
        RequestId request_id;
        SubjectKey subject;
        ScanSpace space;
        ScanPlan plan;
        std::uint64_t deadline_unix_ms {};
    };

    struct FactResponse {
        RequestId request_id;
        SubjectKey subject;
        FactTerminalStatus status {FactTerminalStatus::failed};
        std::optional<FactValue> value;
        std::optional<Diagnostic> diagnostic;
    };

    struct ScanMatch {
        std::uint64_t offset {};
        std::uint64_t length {};
        std::string pattern_id;
        std::string scan_space_id;
        std::uint64_t absolute_address {};
        std::uint32_t permission_snapshot {};
        std::vector<std::byte> matched_bytes;
        std::vector<std::byte> before_bytes;
        std::vector<std::byte> after_bytes;
        DataLabel label;
        std::uint64_t subject_generation {};
    };

    struct ScanResponse {
        RequestId request_id;
        SubjectKey subject;
        FactTerminalStatus status {FactTerminalStatus::failed};
        std::vector<ScanMatch> matches;
        bool truncated {};
        std::optional<Diagnostic> diagnostic;
        ScanResultMode mode {ScanResultMode::exact_complete};
    };

    struct SnapshotBegin {
        PeerId peer;
        SchemaId subject_schema;
        std::uint64_t generation {};
    };

    struct SnapshotChunk {
        PeerId peer;
        SchemaId subject_schema;
        std::uint64_t generation {};
        std::uint32_t sequence {};
        std::vector<SubjectKey> subjects;
    };

    struct SnapshotCommit {
        PeerId peer;
        SchemaId subject_schema;
        std::uint64_t generation {};
        std::uint64_t item_count {};
        std::string canonical_digest;
    };

    struct IProviderDispatcher {
        virtual ~IProviderDispatcher() = default;
        virtual void request_facts(std::vector<FactRequest> requests) = 0;
        virtual void request_scans(std::vector<ScanRequest> requests) = 0;
        virtual void cancel(std::vector<RequestId> requests) = 0;
    };

} // namespace rule_engine::python
