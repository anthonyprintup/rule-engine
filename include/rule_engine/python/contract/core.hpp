#pragma once

#include <compare>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace rule_engine::python {

    template<typename Tag> struct StrongId {
        std::string value;

        [[nodiscard]] bool empty() const noexcept { return value.empty(); }
        auto operator<=>(const StrongId &) const = default;
    };

    struct PackIdTag;
    struct PackVersionTag;
    struct SourceIdTag;
    struct SourceDigestTag;
    struct ExecutableIdTag;
    struct BindingIdTag;
    struct SchemaIdTag;
    struct PeerIdTag;
    struct SessionIdTag;
    struct ExecutionIdTag;
    struct InvocationIdTag;
    struct EventIdTag;
    struct IntentIdTag;
    struct RequestIdTag;
    struct CapabilityIdTag;
    struct TenantIdTag;

    using PackId = StrongId<PackIdTag>;
    using PackVersion = StrongId<PackVersionTag>;
    using SourceId = StrongId<SourceIdTag>;
    using SourceDigest = StrongId<SourceDigestTag>;
    using ExecutableId = StrongId<ExecutableIdTag>;
    using BindingId = StrongId<BindingIdTag>;
    using SchemaId = StrongId<SchemaIdTag>;
    using PeerId = StrongId<PeerIdTag>;
    using SessionId = StrongId<SessionIdTag>;
    using ExecutionId = StrongId<ExecutionIdTag>;
    using InvocationId = StrongId<InvocationIdTag>;
    using EventId = StrongId<EventIdTag>;
    using IntentId = StrongId<IntentIdTag>;
    using RequestId = StrongId<RequestIdTag>;
    using CapabilityId = StrongId<CapabilityIdTag>;
    using TenantId = StrongId<TenantIdTag>;

    struct SchemaIdentity {
        SchemaId id;
        std::string canonical_hash;

        [[nodiscard]] bool valid() const noexcept { return !id.empty() && !canonical_hash.empty(); }
        auto operator<=>(const SchemaIdentity &) const = default;
    };

    struct SourceSpan {
        SourceId source;
        std::uint32_t begin_byte {};
        std::uint32_t end_byte {};

        [[nodiscard]] bool valid() const noexcept { return !source.empty() && begin_byte <= end_byte; }
        auto operator<=>(const SourceSpan &) const = default;
    };

    enum struct DiagnosticSeverity : std::uint8_t { note, warning, error };

    struct RelatedDiagnostic {
        SourceSpan span;
        std::string message;
    };

    struct Diagnostic {
        std::string code;
        DiagnosticSeverity severity {DiagnosticSeverity::error};
        std::string message;
        std::optional<SourceSpan> span;
        std::vector<RelatedDiagnostic> related;
    };

    using DiagnosticSet = std::vector<Diagnostic>;

    enum struct Classification : std::uint8_t { public_data, internal, sensitive, secret };

    struct DataLabel {
        Classification classification {Classification::public_data};
        std::vector<std::string> categories;

        auto operator<=>(const DataLabel &) const = default;
    };

    [[nodiscard]] DataLabel join_labels(const DataLabel &left, const DataLabel &right);
    [[nodiscard]] bool may_flow_to(const DataLabel &value, const DataLabel &ceiling) noexcept;

    struct IntegerValue {
        // Canonical base-ten spelling, including a leading '-' only for negative values.
        std::string decimal;
        auto operator<=>(const IntegerValue &) const = default;
    };

    struct UnicodeValue {
        std::string utf8;
        auto operator<=>(const UnicodeValue &) const = default;
    };

    struct BytesValue {
        std::vector<std::byte> bytes;
        auto operator<=>(const BytesValue &) const = default;
    };

    struct EnumValue {
        SchemaId schema;
        std::string member;
        auto operator<=>(const EnumValue &) const = default;
    };

    struct FactNode;

    struct FactValue {
        std::shared_ptr<const FactNode> node;

        [[nodiscard]] bool valid() const noexcept { return static_cast<bool>(node); }
        auto operator<=>(const FactValue &) const = default;
    };

    struct FactList {
        std::vector<FactValue> items;
    };

    struct FactMapEntry {
        FactValue key;
        FactValue value;
    };

    struct FactMap {
        std::vector<FactMapEntry> entries;
    };

    struct FactRecordField {
        std::uint32_t field_id {};
        FactValue value;
    };

    struct FactRecord {
        SchemaId schema;
        std::vector<FactRecordField> fields;
    };

    using FactData = std::variant<std::monostate, bool, IntegerValue, double, UnicodeValue, BytesValue, EnumValue,
                                  FactList, FactMap, FactRecord>;

    struct FactNode {
        FactData data;
    };

    [[nodiscard]] FactValue make_fact(FactData data);

    struct FrozenValue {
        FactValue value;
        DataLabel label;
        std::string canonical_digest;
    };

    // A VM-local stable handle. The VM lane owns the heap and generation checks.
    struct PyValue {
        std::uint32_t slot {};
        std::uint32_t generation {};
        auto operator<=>(const PyValue &) const = default;
    };

    enum struct FreezeErrorCode : std::uint8_t {
        invalid_handle,
        cycle,
        unsupported_type,
        schema_mismatch,
        budget_exhausted,
    };

    struct FreezeError {
        FreezeErrorCode code {};
        std::string message;
        std::optional<SourceSpan> span;
    };

} // namespace rule_engine::python
