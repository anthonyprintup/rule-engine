#include "rule_engine/python/protocol/codec.hpp"

#include "protocol_v2.protocyte.hpp"

#include <protocyte/runtime/runtime.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_set>
#include <utility>
#include <vector>

namespace rule_engine::python::protocol_v2 {
    namespace {
        namespace wire = rule_engine::python::protocol_v2::wire;
        using Context = protocyte::DefaultConfig::Context;

        [[nodiscard]] ProtocolError codec_error(const ProtocolErrorCode code, std::string message,
                                                const std::size_t offset = 0) {
            return ProtocolError {.code = code, .message = std::move(message), .byte_offset = offset};
        }

        [[nodiscard]] ProtocolError wire_error(const protocyte::Error error, std::string_view operation) {
            ProtocolErrorCode code = ProtocolErrorCode::malformed;
            switch (error.code) {
                case protocyte::ErrorCode::unexpected_eof: code = ProtocolErrorCode::truncated; break;
                case protocyte::ErrorCode::invalid_utf8: code = ProtocolErrorCode::invalid_utf8; break;
                case protocyte::ErrorCode::no_memory:
                case protocyte::ErrorCode::recursion_limit:
                case protocyte::ErrorCode::size_limit:
                case protocyte::ErrorCode::count_limit: code = ProtocolErrorCode::limit_exceeded; break;
                default: break;
            }
            return codec_error(code, std::string {operation} + " failed in generated Protocyte code", error.offset);
        }

        [[nodiscard]] Context make_context(const ProtocolLimits &limits) {
            protocyte::Limits wire_limits;
            wire_limits.max_total_bytes = limits.maximum_frame_bytes;
            wire_limits.max_recursion_depth =
                std::max(limits.maximum_subject_depth, limits.maximum_value_depth) + 16;
            wire_limits.max_message_bytes = limits.maximum_frame_bytes;
            wire_limits.max_string_bytes = limits.maximum_string_bytes;
            wire_limits.max_repeated_elements = limits.maximum_collection_items;
            wire_limits.max_map_entries = limits.maximum_collection_items;
            wire_limits.max_total_allocation_bytes =
                limits.maximum_frame_bytes > std::numeric_limits<std::size_t>::max() / 4
                    ? std::numeric_limits<std::size_t>::max()
                    : limits.maximum_frame_bytes * 4;
            wire_limits.max_unknown_field_bytes = 0;
            return Context {protocyte::hosted_allocator(), wire_limits};
        }

        [[nodiscard]] std::string text(const protocyte::StringView value) {
            return std::string {value.data(), value.size()};
        }

        [[nodiscard]] std::vector<std::byte> bytes(const protocyte::Span<const protocyte::u8> value) {
            const auto *first = reinterpret_cast<const std::byte *>(value.data());
            return std::vector<std::byte> {first, first + value.size()};
        }

        [[nodiscard]] protocyte::Span<const protocyte::u8> byte_view(const std::span<const std::byte> value) {
            return {reinterpret_cast<const protocyte::u8 *>(value.data()), value.size()};
        }

        template<typename Status>
        [[nodiscard]] std::expected<void, ProtocolError> checked(Status status, std::string_view operation) {
            if (!status) {
                return std::unexpected(wire_error(status.error(), operation));
            }
            return {};
        }

        template<typename Vector, typename Fill>
        [[nodiscard]] std::expected<void, ProtocolError> append_message(Vector &values, Context &ctx, Fill &&fill) {
            auto added = values.emplace_back(ctx);
            if (!added) {
                return std::unexpected(wire_error(added.error(), "Protocyte repeated-message allocation"));
            }
            return std::forward<Fill>(fill)(*added);
        }

        template<typename Vector>
        [[nodiscard]] std::expected<void, ProtocolError> append_text(Vector &values, Context &ctx,
                                                                     const std::string_view value) {
            auto added = values.emplace_back(&ctx);
            if (!added) {
                return std::unexpected(wire_error(added.error(), "Protocyte repeated-string allocation"));
            }
            return checked(added->assign(protocyte::Span<const char> {value.data(), value.size()}),
                           "Protocyte repeated-string assignment");
        }

        [[nodiscard]] bool canonical_integer(const std::string_view value) noexcept {
            if (value.empty()) {
                return false;
            }
            std::size_t offset {};
            if (value.front() == '-') {
                if (value.size() == 1 || value[1] == '0') {
                    return false;
                }
                offset = 1;
            }
            if (value[offset] == '0' && value.size() - offset != 1) {
                return false;
            }
            return std::all_of(value.begin() + static_cast<std::ptrdiff_t>(offset), value.end(),
                               [](const char ch) { return ch >= '0' && ch <= '9'; });
        }

        enum struct PreflightShape : std::uint8_t { peer_envelope, durable_envelope };

        [[nodiscard]] std::expected<std::uint64_t, ProtocolError>
        read_canonical_varint(const std::span<const std::byte> input, std::size_t &offset) {
            std::uint64_t value {};
            std::size_t count {};
            for (; count < 10; ++count) {
                if (offset >= input.size()) {
                    return std::unexpected(codec_error(ProtocolErrorCode::truncated, "protobuf varint is truncated",
                                                       offset));
                }
                const auto byte = std::to_integer<std::uint8_t>(input[offset++]);
                if (count == 9 && byte > 1) {
                    return std::unexpected(
                        codec_error(ProtocolErrorCode::malformed, "protobuf varint overflows uint64", offset - 1));
                }
                value |= static_cast<std::uint64_t>(byte & 0x7fU) << (count * 7U);
                if ((byte & 0x80U) == 0) {
                    if (count != 0 && byte == 0) {
                        return std::unexpected(codec_error(ProtocolErrorCode::malformed,
                                                           "protobuf varint is not canonical", offset - 1));
                    }
                    return value;
                }
            }
            return std::unexpected(
                codec_error(ProtocolErrorCode::malformed, "protobuf varint is too long", offset));
        }

        [[nodiscard]] std::expected<void, ProtocolError>
        preflight_generated_message(const std::span<const std::byte> input, const PreflightShape shape) {
            std::array<bool, 10> seen {};
            const std::uint32_t maximum_field = shape == PreflightShape::peer_envelope ? 9U : 2U;
            std::size_t offset {};
            while (offset < input.size()) {
                const auto tag_offset = offset;
                auto tag = read_canonical_varint(input, offset);
                if (!tag) {
                    return std::unexpected(std::move(tag.error()));
                }
                const auto field = static_cast<std::uint32_t>(*tag >> 3U);
                const auto wire_type = static_cast<std::uint8_t>(*tag & 7U);
                if (field == 0 || wire_type == 3 || wire_type == 4 || wire_type > 5) {
                    return std::unexpected(
                        codec_error(ProtocolErrorCode::malformed, "protobuf tag is invalid", tag_offset));
                }
                if (field <= maximum_field) {
                    if (seen[field]) {
                        return std::unexpected(codec_error(ProtocolErrorCode::duplicate_field,
                                                           "duplicate envelope field", tag_offset));
                    }
                    seen[field] = true;
                }
                if (wire_type == 0) {
                    if (auto value = read_canonical_varint(input, offset); !value) {
                        return std::unexpected(std::move(value.error()));
                    }
                    continue;
                }
                if (wire_type == 1 || wire_type == 5) {
                    const std::size_t width = wire_type == 1 ? 8 : 4;
                    if (input.size() - offset < width) {
                        return std::unexpected(
                            codec_error(ProtocolErrorCode::truncated, "fixed-width protobuf field is truncated", offset));
                    }
                    offset += width;
                    continue;
                }
                auto length = read_canonical_varint(input, offset);
                if (!length) {
                    return std::unexpected(std::move(length.error()));
                }
                if (*length > input.size() - offset) {
                    return std::unexpected(
                        codec_error(ProtocolErrorCode::truncated, "length-delimited protobuf field is truncated", offset));
                }
                offset += static_cast<std::size_t>(*length);
            }
            return {};
        }

        [[nodiscard]] std::expected<void, ProtocolError> validate_label(const DataLabel &label,
                                                                        const ProtocolLimits &limits) {
            if (static_cast<std::uint8_t>(label.classification) >
                    static_cast<std::uint8_t>(Classification::secret) ||
                label.categories.size() > limits.maximum_label_categories) {
                return std::unexpected(codec_error(ProtocolErrorCode::limit_exceeded, "data label exceeds its limits"));
            }
            std::unordered_set<std::string_view> unique;
            for (const auto &category : label.categories) {
                if (category.empty() || category.size() > limits.maximum_string_bytes || !unique.insert(category).second) {
                    return std::unexpected(
                        codec_error(ProtocolErrorCode::malformed, "data label category is empty or duplicated"));
                }
            }
            return {};
        }

        [[nodiscard]] std::expected<void, ProtocolError> validate_subject(const SubjectKey &subject,
                                                                          const ProtocolLimits &limits,
                                                                          const std::size_t depth = 1) {
            if (depth > limits.maximum_subject_depth) {
                return std::unexpected(
                    codec_error(ProtocolErrorCode::limit_exceeded, "subject nesting exceeds the limit"));
            }
            if (!subject.valid() || subject.identity.size() > limits.maximum_identity_fields) {
                return std::unexpected(codec_error(ProtocolErrorCode::invalid_identity, "subject identity is invalid"));
            }
            for (const auto &field : subject.identity) {
                const auto valid = std::visit(
                    [&](const auto &value) {
                        using Value = std::remove_cvref_t<decltype(value)>;
                        if constexpr (std::is_same_v<Value, IntegerValue>) {
                            return canonical_integer(value.decimal);
                        } else if constexpr (std::is_same_v<Value, UnicodeValue>) {
                            return value.utf8.size() <= limits.maximum_string_bytes;
                        } else if constexpr (std::is_same_v<Value, BytesValue>) {
                            return value.bytes.size() <= limits.maximum_blob_bytes;
                        } else {
                            return true;
                        }
                    },
                    field.value);
                if (!valid) {
                    return std::unexpected(
                        codec_error(ProtocolErrorCode::invalid_identity, "subject identity scalar is invalid"));
                }
            }
            if (subject.parent) {
                return validate_subject(*subject.parent, limits, depth + 1);
            }
            return {};
        }

        struct ValueBudget {
            std::size_t nodes {};
        };

        [[nodiscard]] std::expected<void, ProtocolError>
        validate_value(const FactValue &value, const ProtocolLimits &limits, ValueBudget &budget,
                       const std::size_t depth = 1) {
            if (!value.valid()) {
                return std::unexpected(codec_error(ProtocolErrorCode::invalid_value, "fact value is absent"));
            }
            if (depth > limits.maximum_value_depth || ++budget.nodes > limits.maximum_total_value_nodes) {
                return std::unexpected(codec_error(ProtocolErrorCode::limit_exceeded, "fact graph exceeds its budget"));
            }
            return std::visit(
                [&](const auto &item) -> std::expected<void, ProtocolError> {
                    using Item = std::remove_cvref_t<decltype(item)>;
                    if constexpr (std::is_same_v<Item, IntegerValue>) {
                        if (!canonical_integer(item.decimal)) {
                            return std::unexpected(
                                codec_error(ProtocolErrorCode::invalid_value, "integer spelling is not canonical"));
                        }
                    } else if constexpr (std::is_same_v<Item, UnicodeValue>) {
                        if (item.utf8.size() > limits.maximum_string_bytes) {
                            return std::unexpected(
                                codec_error(ProtocolErrorCode::limit_exceeded, "Unicode fact exceeds the limit"));
                        }
                    } else if constexpr (std::is_same_v<Item, BytesValue>) {
                        if (item.bytes.size() > limits.maximum_blob_bytes) {
                            return std::unexpected(
                                codec_error(ProtocolErrorCode::limit_exceeded, "bytes fact exceeds the limit"));
                        }
                    } else if constexpr (std::is_same_v<Item, EnumValue>) {
                        if (item.schema.empty() || item.member.empty()) {
                            return std::unexpected(codec_error(ProtocolErrorCode::invalid_value, "enum fact is empty"));
                        }
                    } else if constexpr (std::is_same_v<Item, FactList>) {
                        if (item.items.size() > limits.maximum_collection_items) {
                            return std::unexpected(
                                codec_error(ProtocolErrorCode::limit_exceeded, "fact list exceeds the limit"));
                        }
                        for (const auto &child : item.items) {
                            if (auto valid = validate_value(child, limits, budget, depth + 1); !valid) {
                                return valid;
                            }
                        }
                    } else if constexpr (std::is_same_v<Item, FactMap>) {
                        if (item.entries.size() > limits.maximum_collection_items) {
                            return std::unexpected(
                                codec_error(ProtocolErrorCode::limit_exceeded, "fact map exceeds the limit"));
                        }
                        for (const auto &entry : item.entries) {
                            if (auto valid = validate_value(entry.key, limits, budget, depth + 1); !valid) {
                                return valid;
                            }
                            if (auto valid = validate_value(entry.value, limits, budget, depth + 1); !valid) {
                                return valid;
                            }
                        }
                    } else if constexpr (std::is_same_v<Item, FactRecord>) {
                        if (item.schema.empty() || item.fields.size() > limits.maximum_collection_items) {
                            return std::unexpected(
                                codec_error(ProtocolErrorCode::invalid_value, "fact record is invalid"));
                        }
                        std::uint32_t previous {};
                        for (const auto &field : item.fields) {
                            if (field.field_id == 0 || field.field_id <= previous) {
                                return std::unexpected(
                                    codec_error(ProtocolErrorCode::invalid_value, "record fields are not canonical"));
                            }
                            previous = field.field_id;
                            if (auto valid = validate_value(field.value, limits, budget, depth + 1); !valid) {
                                return valid;
                            }
                        }
                    }
                    return {};
                },
                value.node->data);
        }

        [[nodiscard]] std::expected<void, ProtocolError> validate_diagnostic(const Diagnostic &diagnostic) {
            if (diagnostic.code.empty() || diagnostic.message.empty() || diagnostic.span || !diagnostic.related.empty()) {
                return std::unexpected(
                    codec_error(ProtocolErrorCode::provider_violation, "provider diagnostic contains source data"));
            }
            return {};
        }

        [[nodiscard]] std::expected<void, ProtocolError> validate_scan_match(const ScanMatch &match,
                                                                             const ProtocolLimits &limits) {
            if (match.pattern_id.empty() || match.scan_space_id.empty() ||
                match.matched_bytes.size() != match.length || match.matched_bytes.size() > limits.maximum_blob_bytes ||
                match.before_bytes.size() > limits.maximum_blob_bytes || match.after_bytes.size() > limits.maximum_blob_bytes ||
                match.subject_generation == 0) {
                return std::unexpected(codec_error(ProtocolErrorCode::malformed, "scan match is inconsistent"));
            }
            return validate_label(match.label, limits);
        }

        [[nodiscard]] std::expected<void, ProtocolError> validate_envelope(const PeerEnvelope &envelope,
                                                                           const ProtocolLimits &limits);

        void to_wire(wire::CreditWindow<> &target, const CreditWindow &source) {
            target.set_bytes(source.bytes);
            target.set_messages(source.messages);
            target.set_work_attempts(source.work_attempts);
            target.set_snapshot_chunks(source.snapshot_chunks);
        }

        [[nodiscard]] CreditWindow from_wire(const wire::CreditWindow<> &source) {
            return {.bytes = source.bytes(),
                    .messages = source.messages(),
                    .work_attempts = source.work_attempts(),
                    .snapshot_chunks = source.snapshot_chunks()};
        }

        [[nodiscard]] std::expected<void, ProtocolError>
        to_wire(wire::SchemaAdvertisement<> &target, const SchemaAdvertisement &source) {
            if (source.schema.empty() || source.major == 0 || source.canonical_hash.empty()) {
                return std::unexpected(codec_error(ProtocolErrorCode::malformed, "schema advertisement is incomplete"));
            }
            if (auto status = checked(target.set_schema(source.schema.value), "set schema ID"); !status) return status;
            target.set_major(source.major);
            return checked(target.set_canonical_hash(source.canonical_hash), "set schema hash");
        }

        [[nodiscard]] SchemaAdvertisement from_wire(const wire::SchemaAdvertisement<> &source) {
            return {.schema = SchemaId {text(source.schema())},
                    .major = source.major(),
                    .canonical_hash = text(source.canonical_hash())};
        }

        [[nodiscard]] std::expected<void, ProtocolError>
        to_wire(wire::SchemaIdentity<> &target, const SchemaIdentity &source) {
            if (!source.valid()) {
                return std::unexpected(codec_error(ProtocolErrorCode::schema_mismatch, "schema identity is incomplete"));
            }
            if (auto status = checked(target.set_id(source.id.value), "set schema identity"); !status) return status;
            return checked(target.set_canonical_hash(source.canonical_hash), "set schema identity hash");
        }

        [[nodiscard]] SchemaIdentity from_wire(const wire::SchemaIdentity<> &source) {
            return {.id = SchemaId {text(source.id())}, .canonical_hash = text(source.canonical_hash())};
        }

        [[nodiscard]] std::expected<void, ProtocolError>
        to_wire(wire::CapabilityAdvertisement<> &target, const CapabilityAdvertisement &source) {
            if (source.capability.empty() || source.version == 0 || source.request_schema.empty() ||
                source.response_schema.empty()) {
                return std::unexpected(
                    codec_error(ProtocolErrorCode::malformed, "capability advertisement is incomplete"));
            }
            if (auto status = checked(target.set_capability(source.capability.value), "set capability"); !status)
                return status;
            target.set_version(source.version);
            if (auto status = checked(target.set_request_schema(source.request_schema.value), "set request schema");
                !status)
                return status;
            return checked(target.set_response_schema(source.response_schema.value), "set response schema");
        }

        [[nodiscard]] CapabilityAdvertisement from_wire(const wire::CapabilityAdvertisement<> &source) {
            return {.capability = CapabilityId {text(source.capability())},
                    .version = source.version(),
                    .request_schema = SchemaId {text(source.request_schema())},
                    .response_schema = SchemaId {text(source.response_schema())}};
        }

        [[nodiscard]] std::expected<void, ProtocolError>
        to_wire(wire::IdentityField<> &target, const IdentityField &source) {
            if (source.field_id == 0) {
                return std::unexpected(codec_error(ProtocolErrorCode::invalid_identity, "identity field ID is zero"));
            }
            target.set_field_id(source.field_id);
            return std::visit(
                [&](const auto &value) -> std::expected<void, ProtocolError> {
                    using Value = std::remove_cvref_t<decltype(value)>;
                    if constexpr (std::is_same_v<Value, bool>) {
                        target.set_kind(1);
                        target.set_bool_value(value);
                    } else if constexpr (std::is_same_v<Value, std::int64_t>) {
                        target.set_kind(2);
                        target.set_int64_value(value);
                    } else if constexpr (std::is_same_v<Value, std::uint64_t>) {
                        target.set_kind(3);
                        target.set_uint64_value(value);
                    } else if constexpr (std::is_same_v<Value, IntegerValue>) {
                        target.set_kind(4);
                        if (auto status = checked(target.set_integer_value(value.decimal), "set identity integer");
                            !status)
                            return status;
                    } else if constexpr (std::is_same_v<Value, UnicodeValue>) {
                        target.set_kind(5);
                        if (auto status = checked(target.set_unicode_value(value.utf8), "set identity text"); !status)
                            return status;
                    } else {
                        target.set_kind(6);
                        if (auto status =
                                checked(target.set_bytes_value(byte_view(value.bytes)), "set identity bytes");
                            !status)
                            return status;
                    }
                    return {};
                },
                source.value);
        }

        [[nodiscard]] std::expected<IdentityField, ProtocolError> from_wire(const wire::IdentityField<> &source) {
            IdentityScalar value;
            switch (source.kind()) {
                case 1: value = source.bool_value(); break;
                case 2: value = source.int64_value(); break;
                case 3: value = source.uint64_value(); break;
                case 4: value = IntegerValue {text(source.integer_value())}; break;
                case 5: value = UnicodeValue {text(source.unicode_value())}; break;
                case 6: value = BytesValue {bytes(source.bytes_value())}; break;
                default:
                    return std::unexpected(
                        codec_error(ProtocolErrorCode::invalid_identity, "identity scalar kind is invalid"));
            }
            return IdentityField {.field_id = source.field_id(), .value = std::move(value)};
        }

        [[nodiscard]] std::expected<void, ProtocolError>
        to_wire(wire::SubjectKey<> &target, const SubjectKey &source, Context &ctx, const ProtocolLimits &limits) {
            if (auto valid = validate_subject(source, limits); !valid) return valid;
            if (auto status = checked(target.set_peer(source.peer.value), "set subject peer"); !status) return status;
            if (auto status = checked(target.set_descriptor(source.descriptor.value), "set subject descriptor"); !status)
                return status;
            for (const auto &field : source.identity) {
                if (auto status = append_message(target.mutable_identity(), ctx,
                                                 [&](auto &item) { return to_wire(item, field); });
                    !status)
                    return status;
            }
            if (source.parent) {
                auto parent = target.ensure_parent();
                if (!parent) return std::unexpected(wire_error(parent.error(), "allocate subject parent"));
                return to_wire(*parent, *source.parent, ctx, limits);
            }
            return {};
        }

        [[nodiscard]] std::expected<SubjectKey, ProtocolError>
        from_wire(const wire::SubjectKey<> &source, const ProtocolLimits &limits, const std::size_t depth = 1) {
            if (depth > limits.maximum_subject_depth) {
                return std::unexpected(
                    codec_error(ProtocolErrorCode::limit_exceeded, "subject nesting exceeds the limit"));
            }
            SubjectKey result {.peer = PeerId {text(source.peer())},
                               .descriptor = SchemaId {text(source.descriptor())},
                               .identity = {},
                               .parent = {}};
            if (source.identity().size() > limits.maximum_identity_fields) {
                return std::unexpected(
                    codec_error(ProtocolErrorCode::limit_exceeded, "subject identity count exceeds the limit"));
            }
            result.identity.reserve(source.identity().size());
            for (const auto &field : source.identity()) {
                auto decoded = from_wire(field);
                if (!decoded) return std::unexpected(std::move(decoded.error()));
                result.identity.push_back(std::move(*decoded));
            }
            if (source.has_parent()) {
                auto parent = from_wire(*source.parent(), limits, depth + 1);
                if (!parent) return std::unexpected(std::move(parent.error()));
                result.parent = std::make_shared<const SubjectKey>(std::move(*parent));
            }
            if (auto valid = validate_subject(result, limits); !valid) return std::unexpected(std::move(valid.error()));
            return result;
        }

        [[nodiscard]] std::expected<void, ProtocolError>
        to_wire(wire::FactValue<> &target, const FactValue &source, Context &ctx, const ProtocolLimits &limits,
                ValueBudget &budget, const std::size_t depth = 1) {
            if (depth == 1) {
                if (auto valid = validate_value(source, limits, budget); !valid) return valid;
            }
            target.set_kind(static_cast<std::uint32_t>(source.node->data.index()));
            return std::visit(
                [&](const auto &item) -> std::expected<void, ProtocolError> {
                    using Item = std::remove_cvref_t<decltype(item)>;
                    if constexpr (std::is_same_v<Item, std::monostate>) {
                        // The discriminator is the complete null representation.
                    } else if constexpr (std::is_same_v<Item, bool>) {
                        target.set_bool_value(item);
                    } else if constexpr (std::is_same_v<Item, IntegerValue>) {
                        if (auto status = checked(target.set_integer_value(item.decimal), "set fact integer"); !status)
                            return status;
                    } else if constexpr (std::is_same_v<Item, double>) {
                        target.set_double_value(item);
                    } else if constexpr (std::is_same_v<Item, UnicodeValue>) {
                        if (auto status = checked(target.set_unicode_value(item.utf8), "set fact text"); !status)
                            return status;
                    } else if constexpr (std::is_same_v<Item, BytesValue>) {
                        if (auto status = checked(target.set_bytes_value(byte_view(item.bytes)), "set fact bytes");
                            !status)
                            return status;
                    } else if constexpr (std::is_same_v<Item, EnumValue>) {
                        auto value = target.ensure_enum_value();
                        if (!value) return std::unexpected(wire_error(value.error(), "allocate enum fact"));
                        if (auto status = checked(value->set_schema(item.schema.value), "set enum schema"); !status)
                            return status;
                        if (auto status = checked(value->set_member(item.member), "set enum member"); !status)
                            return status;
                    } else if constexpr (std::is_same_v<Item, FactList>) {
                        for (const auto &child : item.items) {
                            if (auto status = append_message(target.mutable_list_items(), ctx, [&](auto &wire_child) {
                                    return to_wire(wire_child, child, ctx, limits, budget, depth + 1);
                                });
                                !status)
                                return status;
                        }
                    } else if constexpr (std::is_same_v<Item, FactMap>) {
                        for (const auto &entry : item.entries) {
                            if (auto status = append_message(target.mutable_map_entries(), ctx, [&](auto &wire_entry) {
                                    auto key = wire_entry.ensure_key();
                                    if (!key) return std::expected<void, ProtocolError> {std::unexpected(
                                        wire_error(key.error(), "allocate fact-map key"))};
                                    if (auto child = to_wire(*key, entry.key, ctx, limits, budget, depth + 1); !child)
                                        return child;
                                    auto value = wire_entry.ensure_value();
                                    if (!value) return std::expected<void, ProtocolError> {std::unexpected(
                                        wire_error(value.error(), "allocate fact-map value"))};
                                    return to_wire(*value, entry.value, ctx, limits, budget, depth + 1);
                                });
                                !status)
                                return status;
                        }
                    } else {
                        if (auto status = checked(target.set_record_schema(item.schema.value), "set record schema");
                            !status)
                            return status;
                        for (const auto &field : item.fields) {
                            if (auto status = append_message(target.mutable_record_fields(), ctx, [&](auto &wire_field) {
                                    wire_field.set_field_id(field.field_id);
                                    auto value = wire_field.ensure_value();
                                    if (!value) return std::expected<void, ProtocolError> {std::unexpected(
                                        wire_error(value.error(), "allocate record field"))};
                                    return to_wire(*value, field.value, ctx, limits, budget, depth + 1);
                                });
                                !status)
                                return status;
                        }
                    }
                    return {};
                },
                source.node->data);
        }

        [[nodiscard]] std::expected<FactValue, ProtocolError>
        from_wire(const wire::FactValue<> &source, const ProtocolLimits &limits, ValueBudget &budget,
                  const std::size_t depth = 1) {
            if (depth > limits.maximum_value_depth || ++budget.nodes > limits.maximum_total_value_nodes) {
                return std::unexpected(codec_error(ProtocolErrorCode::limit_exceeded, "fact graph exceeds its budget"));
            }
            FactData result;
            switch (source.kind()) {
                case 0: result = std::monostate {}; break;
                case 1: result = source.bool_value(); break;
                case 2: result = IntegerValue {text(source.integer_value())}; break;
                case 3: result = source.double_value(); break;
                case 4: result = UnicodeValue {text(source.unicode_value())}; break;
                case 5: result = BytesValue {bytes(source.bytes_value())}; break;
                case 6:
                    if (!source.has_enum_value()) {
                        return std::unexpected(codec_error(ProtocolErrorCode::invalid_value, "enum fact is absent"));
                    }
                    result = EnumValue {.schema = SchemaId {text(source.enum_value()->schema())},
                                        .member = text(source.enum_value()->member())};
                    break;
                case 7: {
                    FactList list;
                    list.items.reserve(source.list_items().size());
                    for (const auto &child : source.list_items()) {
                        auto decoded = from_wire(child, limits, budget, depth + 1);
                        if (!decoded) return std::unexpected(std::move(decoded.error()));
                        list.items.push_back(std::move(*decoded));
                    }
                    result = std::move(list);
                    break;
                }
                case 8: {
                    FactMap map;
                    map.entries.reserve(source.map_entries().size());
                    for (const auto &entry : source.map_entries()) {
                        if (!entry.has_key() || !entry.has_value()) {
                            return std::unexpected(
                                codec_error(ProtocolErrorCode::invalid_value, "fact-map entry is incomplete"));
                        }
                        auto key = from_wire(*entry.key(), limits, budget, depth + 1);
                        if (!key) return std::unexpected(std::move(key.error()));
                        auto value = from_wire(*entry.value(), limits, budget, depth + 1);
                        if (!value) return std::unexpected(std::move(value.error()));
                        map.entries.push_back({.key = std::move(*key), .value = std::move(*value)});
                    }
                    result = std::move(map);
                    break;
                }
                case 9: {
                    FactRecord record {.schema = SchemaId {text(source.record_schema())}, .fields = {}};
                    record.fields.reserve(source.record_fields().size());
                    for (const auto &field : source.record_fields()) {
                        if (!field.has_value()) {
                            return std::unexpected(
                                codec_error(ProtocolErrorCode::invalid_value, "record field value is absent"));
                        }
                        auto value = from_wire(*field.value(), limits, budget, depth + 1);
                        if (!value) return std::unexpected(std::move(value.error()));
                        record.fields.push_back({.field_id = field.field_id(), .value = std::move(*value)});
                    }
                    result = std::move(record);
                    break;
                }
                default:
                    return std::unexpected(codec_error(ProtocolErrorCode::invalid_value, "fact kind is invalid"));
            }
            auto value = make_fact(std::move(result));
            if (depth == 1) {
                ValueBudget validation;
                if (auto valid = validate_value(value, limits, validation); !valid)
                    return std::unexpected(std::move(valid.error()));
            }
            return value;
        }

        [[nodiscard]] std::expected<void, ProtocolError>
        to_wire(wire::ProviderDiagnostic<> &target, const Diagnostic &source) {
            if (auto valid = validate_diagnostic(source); !valid) return valid;
            if (auto status = checked(target.set_code(source.code), "set diagnostic code"); !status) return status;
            target.set_severity(static_cast<std::uint32_t>(source.severity));
            return checked(target.set_message(source.message), "set diagnostic message");
        }

        [[nodiscard]] std::expected<Diagnostic, ProtocolError>
        from_wire(const wire::ProviderDiagnostic<> &source) {
            if (source.severity() > static_cast<std::uint32_t>(DiagnosticSeverity::error)) {
                return std::unexpected(codec_error(ProtocolErrorCode::malformed, "diagnostic severity is invalid"));
            }
            Diagnostic result {.code = text(source.code()),
                               .severity = static_cast<DiagnosticSeverity>(source.severity()),
                               .message = text(source.message()),
                               .span = std::nullopt,
                               .related = {}};
            if (auto valid = validate_diagnostic(result); !valid) return std::unexpected(std::move(valid.error()));
            return result;
        }

        [[nodiscard]] std::expected<void, ProtocolError>
        to_wire(wire::DataLabel<> &target, const DataLabel &source, Context &ctx, const ProtocolLimits &limits) {
            if (auto valid = validate_label(source, limits); !valid) return valid;
            target.set_classification(static_cast<std::uint32_t>(source.classification));
            for (const auto &category : source.categories) {
                if (auto status = append_text(target.mutable_categories(), ctx, category); !status) return status;
            }
            return {};
        }

        [[nodiscard]] std::expected<DataLabel, ProtocolError>
        from_wire(const wire::DataLabel<> &source, const ProtocolLimits &limits) {
            DataLabel result {.classification = static_cast<Classification>(source.classification()), .categories = {}};
            result.categories.reserve(source.categories().size());
            for (const auto &category : source.categories()) result.categories.push_back(text(category.view()));
            if (auto valid = validate_label(result, limits); !valid) return std::unexpected(std::move(valid.error()));
            return result;
        }

        [[nodiscard]] std::expected<void, ProtocolError>
        to_wire(wire::FactRequest<> &target, const FactRequest &source, Context &ctx, const ProtocolLimits &limits) {
            if (source.request_id.empty() || source.route.provider.empty() || source.route.fact.empty() ||
                source.expected_schema.empty() || source.expected_schema_hash.empty() || source.deadline_unix_ms == 0) {
                return std::unexpected(codec_error(ProtocolErrorCode::malformed, "fact request is incomplete"));
            }
            if (auto status = checked(target.set_request_id(source.request_id.value), "set fact request ID"); !status)
                return status;
            auto subject = target.ensure_subject();
            if (!subject) return std::unexpected(wire_error(subject.error(), "allocate fact subject"));
            if (auto status = to_wire(*subject, source.subject, ctx, limits); !status) return status;
            if (auto status = checked(target.set_provider(source.route.provider), "set fact provider"); !status)
                return status;
            if (auto status = checked(target.set_fact(source.route.fact), "set fact name"); !status) return status;
            if (auto status = checked(target.set_expected_schema(source.expected_schema.value), "set fact schema");
                !status)
                return status;
            target.set_deadline_unix_ms(source.deadline_unix_ms);
            return checked(target.set_expected_schema_hash(source.expected_schema_hash), "set expected schema hash");
        }

        [[nodiscard]] std::expected<FactRequest, ProtocolError>
        from_wire(const wire::FactRequest<> &source, const ProtocolLimits &limits) {
            if (!source.has_subject()) {
                return std::unexpected(codec_error(ProtocolErrorCode::malformed, "fact subject is absent"));
            }
            auto subject = from_wire(*source.subject(), limits);
            if (!subject) return std::unexpected(std::move(subject.error()));
            FactRequest result {.request_id = RequestId {text(source.request_id())},
                                .subject = std::move(*subject),
                                .route = {.provider = text(source.provider()), .fact = text(source.fact())},
                                .expected_schema = SchemaId {text(source.expected_schema())},
                                .expected_schema_hash = text(source.expected_schema_hash()),
                                .deadline_unix_ms = source.deadline_unix_ms()};
            if (result.request_id.empty() || result.route.provider.empty() || result.route.fact.empty() ||
                result.expected_schema.empty() || result.expected_schema_hash.empty() || result.deadline_unix_ms == 0) {
                return std::unexpected(codec_error(ProtocolErrorCode::malformed, "fact request is incomplete"));
            }
            return result;
        }

        [[nodiscard]] std::expected<void, ProtocolError>
        to_wire(wire::ScanRequest<> &target, const ScanRequest &source, Context &ctx, const ProtocolLimits &limits) {
            if (source.plan.pattern_ids.size() > limits.maximum_scan_patterns) {
                return std::unexpected(
                    codec_error(ProtocolErrorCode::limit_exceeded, "scan pattern count exceeds the limit"));
            }
            if (source.request_id.empty() || source.space.kind.empty() || source.space.identity.empty() ||
                source.space.size == 0 || source.space.subject_generation == 0 || source.plan.plan_id.empty() ||
                source.plan.encoded_pattern.empty() || source.plan.maximum_bytes == 0 ||
                source.plan.maximum_matches == 0 || source.deadline_unix_ms == 0 || source.plan.pattern_ids.empty() ||
                source.plan.pattern_ids.size() > limits.maximum_collection_items) {
                return std::unexpected(codec_error(ProtocolErrorCode::malformed, "scan request is incomplete"));
            }
            std::unordered_set<std::string_view> patterns;
            for (const auto &pattern : source.plan.pattern_ids) {
                if (pattern.empty()) {
                    return std::unexpected(codec_error(ProtocolErrorCode::malformed, "scan pattern ID is empty"));
                }
                if (!patterns.insert(pattern).second) {
                    return std::unexpected(
                        codec_error(ProtocolErrorCode::duplicate_item, "scan pattern ID is duplicated"));
                }
            }
            if (auto status = checked(target.set_request_id(source.request_id.value), "set scan request ID"); !status)
                return status;
            auto subject = target.ensure_subject();
            if (!subject) return std::unexpected(wire_error(subject.error(), "allocate scan subject"));
            if (auto status = to_wire(*subject, source.subject, ctx, limits); !status) return status;
            if (auto status = checked(target.set_space_kind(source.space.kind), "set scan-space kind"); !status)
                return status;
            target.set_begin(source.space.begin);
            target.set_size(source.space.size);
            target.set_permissions(source.space.permissions);
            if (auto status = checked(target.set_plan_id(source.plan.plan_id), "set scan plan ID"); !status)
                return status;
            if (auto status = checked(target.set_encoded_pattern(source.plan.encoded_pattern), "set scan pattern");
                !status)
                return status;
            target.set_maximum_bytes(source.plan.maximum_bytes);
            target.set_maximum_matches(source.plan.maximum_matches);
            target.set_deadline_unix_ms(source.deadline_unix_ms);
            if (auto status = checked(target.set_space_identity(source.space.identity), "set scan-space identity");
                !status)
                return status;
            target.set_subject_generation(source.space.subject_generation);
            auto label = target.ensure_label();
            if (!label) return std::unexpected(wire_error(label.error(), "allocate scan label"));
            if (auto status = to_wire(*label, source.space.label, ctx, limits); !status) return status;
            target.set_context_bytes_before(source.plan.context_bytes_before);
            target.set_context_bytes_after(source.plan.context_bytes_after);
            target.set_result_mode(static_cast<std::uint32_t>(source.plan.result_mode));
            for (const auto &pattern : source.plan.pattern_ids) {
                if (auto status = append_text(target.mutable_pattern_ids(), ctx, pattern); !status) return status;
            }
            return {};
        }

        [[nodiscard]] std::expected<ScanRequest, ProtocolError>
        from_wire(const wire::ScanRequest<> &source, const ProtocolLimits &limits) {
            if (!source.has_subject() || !source.has_label()) {
                return std::unexpected(codec_error(ProtocolErrorCode::malformed, "scan request subject or label absent"));
            }
            auto subject = from_wire(*source.subject(), limits);
            if (!subject) return std::unexpected(std::move(subject.error()));
            auto label = from_wire(*source.label(), limits);
            if (!label) return std::unexpected(std::move(label.error()));
            ScanRequest result {.request_id = RequestId {text(source.request_id())},
                                .subject = std::move(*subject),
                                .space = {.kind = text(source.space_kind()),
                                          .begin = source.begin(),
                                          .size = source.size(),
                                          .permissions = source.permissions(),
                                          .identity = text(source.space_identity()),
                                          .label = std::move(*label),
                                          .subject_generation = source.subject_generation()},
                                .plan = {.plan_id = text(source.plan_id()),
                                         .encoded_pattern = text(source.encoded_pattern()),
                                         .maximum_bytes = source.maximum_bytes(),
                                         .maximum_matches = source.maximum_matches(),
                                         .context_bytes_before = source.context_bytes_before(),
                                         .context_bytes_after = source.context_bytes_after(),
                                         .result_mode = static_cast<ScanResultMode>(source.result_mode()),
                                         .pattern_ids = {}},
                                .deadline_unix_ms = source.deadline_unix_ms()};
            result.plan.pattern_ids.reserve(source.pattern_ids().size());
            for (const auto &pattern : source.pattern_ids()) result.plan.pattern_ids.push_back(text(pattern.view()));
            Context ctx = make_context(limits);
            auto probe = wire::ScanRequest<>::create(ctx);
            if (auto valid = to_wire(probe, result, ctx, limits); !valid)
                return std::unexpected(std::move(valid.error()));
            return result;
        }

        [[nodiscard]] std::expected<void, ProtocolError>
        to_wire(wire::FactResponse<> &target, const FactResponse &source, Context &ctx, const ProtocolLimits &limits) {
            if (source.request_id.empty() || !valid_fact_response_shape(source)) {
                return std::unexpected(codec_error(ProtocolErrorCode::malformed, "fact response shape is invalid"));
            }
            if (auto status = checked(target.set_request_id(source.request_id.value), "set fact response ID"); !status)
                return status;
            auto subject = target.ensure_subject();
            if (!subject) return std::unexpected(wire_error(subject.error(), "allocate fact-response subject"));
            if (auto status = to_wire(*subject, source.subject, ctx, limits); !status) return status;
            target.set_status(static_cast<std::uint32_t>(source.status));
            if (source.value) {
                auto value = target.ensure_value();
                if (!value) return std::unexpected(wire_error(value.error(), "allocate fact response value"));
                ValueBudget budget;
                if (auto status = to_wire(*value, *source.value, ctx, limits, budget); !status) return status;
            }
            if (source.diagnostic) {
                auto diagnostic = target.ensure_diagnostic();
                if (!diagnostic)
                    return std::unexpected(wire_error(diagnostic.error(), "allocate fact diagnostic"));
                if (auto status = to_wire(*diagnostic, *source.diagnostic); !status) return status;
            }
            if (source.returned_schema) {
                auto schema = target.ensure_returned_schema();
                if (!schema) return std::unexpected(wire_error(schema.error(), "allocate returned schema"));
                if (auto status = to_wire(*schema, *source.returned_schema); !status) return status;
            }
            return {};
        }

        [[nodiscard]] std::expected<FactResponse, ProtocolError>
        from_wire(const wire::FactResponse<> &source, const ProtocolLimits &limits) {
            if (!source.has_subject() || source.status() > static_cast<std::uint32_t>(FactTerminalStatus::canceled)) {
                return std::unexpected(codec_error(ProtocolErrorCode::malformed, "fact response is invalid"));
            }
            auto subject = from_wire(*source.subject(), limits);
            if (!subject) return std::unexpected(std::move(subject.error()));
            FactResponse result {.request_id = RequestId {text(source.request_id())},
                                 .subject = std::move(*subject),
                                 .status = static_cast<FactTerminalStatus>(source.status()),
                                 .value = std::nullopt,
                                 .returned_schema = std::nullopt,
                                 .diagnostic = std::nullopt};
            if (source.has_value()) {
                ValueBudget budget;
                auto value = from_wire(*source.value(), limits, budget);
                if (!value) return std::unexpected(std::move(value.error()));
                result.value = std::move(*value);
            }
            if (source.has_diagnostic()) {
                auto diagnostic = from_wire(*source.diagnostic());
                if (!diagnostic) return std::unexpected(std::move(diagnostic.error()));
                result.diagnostic = std::move(*diagnostic);
            }
            if (source.has_returned_schema()) result.returned_schema = from_wire(*source.returned_schema());
            if (result.request_id.empty() || !valid_fact_response_shape(result)) {
                return std::unexpected(codec_error(ProtocolErrorCode::malformed, "fact response shape is invalid"));
            }
            return result;
        }

        [[nodiscard]] std::expected<void, ProtocolError>
        to_wire(wire::ScanMatch<> &target, const ScanMatch &source, Context &ctx, const ProtocolLimits &limits) {
            if (auto valid = validate_scan_match(source, limits); !valid) return valid;
            target.set_offset(source.offset);
            target.set_length(source.length);
            if (auto status = checked(target.set_pattern_id(source.pattern_id), "set match pattern ID"); !status)
                return status;
            if (auto status = checked(target.set_scan_space_id(source.scan_space_id), "set match scan-space ID");
                !status)
                return status;
            target.set_absolute_address(source.absolute_address);
            target.set_permission_snapshot(source.permission_snapshot);
            if (auto status = checked(target.set_matched_bytes(byte_view(source.matched_bytes)), "set matched bytes");
                !status)
                return status;
            if (auto status = checked(target.set_before_bytes(byte_view(source.before_bytes)), "set before bytes");
                !status)
                return status;
            if (auto status = checked(target.set_after_bytes(byte_view(source.after_bytes)), "set after bytes"); !status)
                return status;
            auto label = target.ensure_label();
            if (!label) return std::unexpected(wire_error(label.error(), "allocate match label"));
            if (auto status = to_wire(*label, source.label, ctx, limits); !status) return status;
            target.set_subject_generation(source.subject_generation);
            return {};
        }

        [[nodiscard]] std::expected<ScanMatch, ProtocolError>
        from_wire(const wire::ScanMatch<> &source, const ProtocolLimits &limits) {
            if (!source.has_label()) {
                return std::unexpected(codec_error(ProtocolErrorCode::malformed, "scan match label is absent"));
            }
            auto label = from_wire(*source.label(), limits);
            if (!label) return std::unexpected(std::move(label.error()));
            ScanMatch result {.offset = source.offset(),
                              .length = source.length(),
                              .pattern_id = text(source.pattern_id()),
                              .scan_space_id = text(source.scan_space_id()),
                              .absolute_address = source.absolute_address(),
                              .permission_snapshot = source.permission_snapshot(),
                              .matched_bytes = bytes(source.matched_bytes()),
                              .before_bytes = bytes(source.before_bytes()),
                              .after_bytes = bytes(source.after_bytes()),
                              .label = std::move(*label),
                              .subject_generation = source.subject_generation()};
            if (auto valid = validate_scan_match(result, limits); !valid)
                return std::unexpected(std::move(valid.error()));
            return result;
        }

        [[nodiscard]] std::expected<void, ProtocolError>
        to_wire(wire::ScanResponse<> &target, const ScanResponse &source, Context &ctx, const ProtocolLimits &limits) {
            if (source.request_id.empty() || source.truncated ||
                source.status > FactTerminalStatus::canceled || source.matches.size() > limits.maximum_scan_matches ||
                (source.status == FactTerminalStatus::value && source.diagnostic) ||
                (source.status != FactTerminalStatus::value && !source.matches.empty())) {
                return std::unexpected(codec_error(ProtocolErrorCode::malformed, "scan response shape is invalid"));
            }
            if (auto status = checked(target.set_request_id(source.request_id.value), "set scan response ID"); !status)
                return status;
            auto subject = target.ensure_subject();
            if (!subject) return std::unexpected(wire_error(subject.error(), "allocate scan-response subject"));
            if (auto status = to_wire(*subject, source.subject, ctx, limits); !status) return status;
            target.set_status(static_cast<std::uint32_t>(source.status));
            for (const auto &match : source.matches) {
                if (auto status = append_message(target.mutable_matches(), ctx, [&](auto &item) {
                        return to_wire(item, match, ctx, limits);
                    });
                    !status)
                    return status;
            }
            target.set_truncated(false);
            if (source.diagnostic) {
                auto diagnostic = target.ensure_diagnostic();
                if (!diagnostic)
                    return std::unexpected(wire_error(diagnostic.error(), "allocate scan diagnostic"));
                if (auto status = to_wire(*diagnostic, *source.diagnostic); !status) return status;
            }
            target.set_result_mode(static_cast<std::uint32_t>(source.mode));
            return {};
        }

        [[nodiscard]] std::expected<ScanResponse, ProtocolError>
        from_wire(const wire::ScanResponse<> &source, const ProtocolLimits &limits) {
            if (!source.has_subject() || source.matches().size() > limits.maximum_scan_matches) {
                return std::unexpected(codec_error(ProtocolErrorCode::malformed, "scan response is invalid"));
            }
            auto subject = from_wire(*source.subject(), limits);
            if (!subject) return std::unexpected(std::move(subject.error()));
            ScanResponse result {.request_id = RequestId {text(source.request_id())},
                                 .subject = std::move(*subject),
                                 .status = static_cast<FactTerminalStatus>(source.status()),
                                 .matches = {},
                                 .truncated = source.truncated(),
                                 .diagnostic = std::nullopt,
                                 .mode = static_cast<ScanResultMode>(source.result_mode())};
            result.matches.reserve(source.matches().size());
            for (const auto &match : source.matches()) {
                auto decoded = from_wire(match, limits);
                if (!decoded) return std::unexpected(std::move(decoded.error()));
                result.matches.push_back(std::move(*decoded));
            }
            if (source.has_diagnostic()) {
                auto diagnostic = from_wire(*source.diagnostic());
                if (!diagnostic) return std::unexpected(std::move(diagnostic.error()));
                result.diagnostic = std::move(*diagnostic);
            }
            Context ctx = make_context(limits);
            auto probe = wire::ScanResponse<>::create(ctx);
            if (auto valid = to_wire(probe, result, ctx, limits); !valid)
                return std::unexpected(std::move(valid.error()));
            return result;
        }

        template<typename WireHello>
        [[nodiscard]] std::expected<void, ProtocolError>
        append_advertisements(WireHello &target, const std::span<const SchemaAdvertisement> schemas,
                              const std::span<const CapabilityAdvertisement> capabilities, Context &ctx) {
            std::unordered_set<std::string_view> schema_ids;
            for (const auto &schema : schemas) {
                if (!schema_ids.insert(schema.schema.value).second) {
                    return std::unexpected(codec_error(ProtocolErrorCode::duplicate_item, "schema is duplicated"));
                }
                if (auto status = append_message(target.mutable_schemas(), ctx,
                                                 [&](auto &item) { return to_wire(item, schema); });
                    !status)
                    return status;
            }
            std::unordered_set<std::string_view> capability_ids;
            for (const auto &capability : capabilities) {
                if (!capability_ids.insert(capability.capability.value).second) {
                    return std::unexpected(codec_error(ProtocolErrorCode::duplicate_item, "capability is duplicated"));
                }
                if (auto status = append_message(target.mutable_capabilities(), ctx,
                                                 [&](auto &item) { return to_wire(item, capability); });
                    !status)
                    return status;
            }
            return {};
        }

        template<typename WireHello>
        void read_advertisements(const WireHello &source, std::vector<SchemaAdvertisement> &schemas,
                                 std::vector<CapabilityAdvertisement> &capabilities) {
            schemas.reserve(source.schemas().size());
            for (const auto &schema : source.schemas()) schemas.push_back(from_wire(schema));
            capabilities.reserve(source.capabilities().size());
            for (const auto &capability : source.capabilities()) capabilities.push_back(from_wire(capability));
        }

        [[nodiscard]] std::expected<void, ProtocolError>
        to_wire(wire::AgentHello<> &target, const AgentHelloMessage &source, Context &ctx,
                const ProtocolLimits &) {
            if (source.minimum_minor > source.maximum_minor || source.agent_version.empty() ||
                source.agent_epoch.empty() || source.next_sequence == 0) {
                return std::unexpected(codec_error(ProtocolErrorCode::malformed, "agent hello is incomplete"));
            }
            target.set_minimum_minor(source.minimum_minor);
            target.set_maximum_minor(source.maximum_minor);
            if (auto status = checked(target.set_agent_version(source.agent_version), "set agent version"); !status)
                return status;
            if (auto status = checked(target.set_agent_epoch(source.agent_epoch), "set agent epoch"); !status)
                return status;
            target.set_next_sequence(source.next_sequence);
            if (auto status = append_advertisements(target, source.schemas, source.capabilities, ctx); !status)
                return status;
            auto credit = target.ensure_receive_limit();
            if (!credit) return std::unexpected(wire_error(credit.error(), "allocate hello receive limit"));
            to_wire(*credit, source.receive_limit);
            return {};
        }

        [[nodiscard]] std::expected<AgentHelloMessage, ProtocolError>
        from_wire(const wire::AgentHello<> &source, const ProtocolLimits &limits) {
            if (!source.has_receive_limit()) {
                return std::unexpected(codec_error(ProtocolErrorCode::malformed, "agent hello credit is absent"));
            }
            AgentHelloMessage result {.minimum_minor = static_cast<std::uint16_t>(source.minimum_minor()),
                                      .maximum_minor = static_cast<std::uint16_t>(source.maximum_minor()),
                                      .agent_version = text(source.agent_version()),
                                      .agent_epoch = text(source.agent_epoch()),
                                      .next_sequence = source.next_sequence(),
                                      .schemas = {},
                                      .capabilities = {},
                                      .receive_limit = from_wire(*source.receive_limit())};
            read_advertisements(source, result.schemas, result.capabilities);
            Context ctx = make_context(limits);
            auto probe = wire::AgentHello<>::create(ctx);
            if (auto valid = to_wire(probe, result, ctx, limits); !valid)
                return std::unexpected(std::move(valid.error()));
            return result;
        }

        [[nodiscard]] std::expected<void, ProtocolError>
        to_wire(wire::ServerHello<> &target, const ServerHelloMessage &source, Context &ctx,
                const ProtocolLimits &) {
            if (source.selected_minor != initial_minor_version || source.session.empty() || source.peer.empty() ||
                source.session_fence == 0 || source.heartbeat_interval_ms == 0) {
                return std::unexpected(codec_error(ProtocolErrorCode::malformed, "server hello is incomplete"));
            }
            target.set_selected_minor(source.selected_minor);
            if (auto status = checked(target.set_session(source.session.value), "set server session"); !status)
                return status;
            if (auto status = checked(target.set_peer(source.peer.value), "set server peer"); !status) return status;
            target.set_session_fence(source.session_fence);
            target.set_acknowledged_sequence(source.acknowledged_sequence);
            if (auto status = append_advertisements(target, source.schemas, source.capabilities, ctx); !status)
                return status;
            auto credit = target.ensure_credit();
            if (!credit) return std::unexpected(wire_error(credit.error(), "allocate server credit"));
            to_wire(*credit, source.credit);
            target.set_heartbeat_interval_ms(source.heartbeat_interval_ms);
            return {};
        }

        [[nodiscard]] std::expected<ServerHelloMessage, ProtocolError>
        from_wire(const wire::ServerHello<> &source, const ProtocolLimits &limits) {
            if (!source.has_credit()) {
                return std::unexpected(codec_error(ProtocolErrorCode::malformed, "server hello credit is absent"));
            }
            ServerHelloMessage result {.selected_minor = static_cast<std::uint16_t>(source.selected_minor()),
                                       .session = SessionId {text(source.session())},
                                       .peer = PeerId {text(source.peer())},
                                       .session_fence = source.session_fence(),
                                       .acknowledged_sequence = source.acknowledged_sequence(),
                                       .schemas = {},
                                       .capabilities = {},
                                       .credit = from_wire(*source.credit()),
                                       .heartbeat_interval_ms = source.heartbeat_interval_ms()};
            read_advertisements(source, result.schemas, result.capabilities);
            Context ctx = make_context(limits);
            auto probe = wire::ServerHello<>::create(ctx);
            if (auto valid = to_wire(probe, result, ctx, limits); !valid)
                return std::unexpected(std::move(valid.error()));
            return result;
        }

        [[nodiscard]] bool unique_request_ids(const std::span<const FactRequest> facts,
                                              const std::span<const ScanRequest> scans) {
            std::unordered_set<std::string_view> ids;
            for (const auto &request : facts)
                if (!ids.insert(request.request_id.value).second) return false;
            for (const auto &request : scans)
                if (!ids.insert(request.request_id.value).second) return false;
            return true;
        }

        [[nodiscard]] std::expected<void, ProtocolError>
        to_wire(wire::WorkLease<> &target, const WorkLeaseMessage &source, Context &ctx, const ProtocolLimits &limits) {
            if (source.session.empty() || source.peer.empty() || source.session_fence == 0 || source.work_id.empty() ||
                source.attempt_id.empty() || source.work_fence == 0 || source.generation == 0 ||
                source.server_sequence == 0 || source.route.empty() || (source.facts.empty() && source.scans.empty()) ||
                source.facts.size() > limits.maximum_fact_requests || source.scans.size() > limits.maximum_scan_requests ||
                !unique_request_ids(source.facts, source.scans)) {
                return std::unexpected(codec_error(ProtocolErrorCode::malformed, "work lease is incomplete"));
            }
            if (auto status = checked(target.set_session(source.session.value), "set work session"); !status)
                return status;
            if (auto status = checked(target.set_peer(source.peer.value), "set work peer"); !status) return status;
            target.set_session_fence(source.session_fence);
            if (auto status = checked(target.set_work_id(source.work_id), "set work ID"); !status) return status;
            if (auto status = checked(target.set_attempt_id(source.attempt_id), "set attempt ID"); !status) return status;
            target.set_work_fence(source.work_fence);
            target.set_generation(source.generation);
            target.set_server_sequence(source.server_sequence);
            if (auto status = checked(target.set_route(source.route), "set work route"); !status) return status;
            for (const auto &request : source.facts) {
                if (request.subject.peer != source.peer || request.route.provider != source.route) {
                    return std::unexpected(codec_error(ProtocolErrorCode::malformed, "fact escapes work route"));
                }
                if (auto status = append_message(target.mutable_facts(), ctx, [&](auto &item) {
                        return to_wire(item, request, ctx, limits);
                    });
                    !status)
                    return status;
            }
            for (const auto &request : source.scans) {
                if (request.subject.peer != source.peer) {
                    return std::unexpected(codec_error(ProtocolErrorCode::malformed, "scan escapes work peer"));
                }
                if (auto status = append_message(target.mutable_scans(), ctx, [&](auto &item) {
                        return to_wire(item, request, ctx, limits);
                    });
                    !status)
                    return status;
            }
            return {};
        }

        [[nodiscard]] std::expected<WorkLeaseMessage, ProtocolError>
        from_wire(const wire::WorkLease<> &source, const ProtocolLimits &limits) {
            WorkLeaseMessage result {.session = SessionId {text(source.session())},
                                     .peer = PeerId {text(source.peer())},
                                     .session_fence = source.session_fence(),
                                     .work_id = text(source.work_id()),
                                     .attempt_id = text(source.attempt_id()),
                                     .work_fence = source.work_fence(),
                                     .generation = source.generation(),
                                     .server_sequence = source.server_sequence(),
                                     .route = text(source.route()),
                                     .facts = {},
                                     .scans = {}};
            result.facts.reserve(source.facts().size());
            for (const auto &request : source.facts()) {
                auto decoded = from_wire(request, limits);
                if (!decoded) return std::unexpected(std::move(decoded.error()));
                result.facts.push_back(std::move(*decoded));
            }
            result.scans.reserve(source.scans().size());
            for (const auto &request : source.scans()) {
                auto decoded = from_wire(request, limits);
                if (!decoded) return std::unexpected(std::move(decoded.error()));
                result.scans.push_back(std::move(*decoded));
            }
            Context ctx = make_context(limits);
            auto probe = wire::WorkLease<>::create(ctx);
            if (auto valid = to_wire(probe, result, ctx, limits); !valid)
                return std::unexpected(std::move(valid.error()));
            return result;
        }

        [[nodiscard]] std::expected<void, ProtocolError>
        to_wire(wire::WorkResult<> &target, const WorkResultMessage &source, Context &ctx,
                const ProtocolLimits &limits) {
            if (source.originating_session.empty() || source.peer.empty() || source.originating_session_fence == 0 ||
                source.work_id.empty() || source.attempt_id.empty() || source.work_fence == 0 || source.generation == 0 ||
                (source.facts.empty() && source.scans.empty()) || source.facts.size() > limits.maximum_fact_requests ||
                source.scans.size() > limits.maximum_scan_requests) {
                return std::unexpected(codec_error(ProtocolErrorCode::malformed, "work result is incomplete"));
            }
            if (auto status = checked(target.set_originating_session(source.originating_session.value),
                                      "set result session");
                !status)
                return status;
            if (auto status = checked(target.set_peer(source.peer.value), "set result peer"); !status) return status;
            target.set_originating_session_fence(source.originating_session_fence);
            if (auto status = checked(target.set_work_id(source.work_id), "set result work ID"); !status) return status;
            if (auto status = checked(target.set_attempt_id(source.attempt_id), "set result attempt ID"); !status)
                return status;
            target.set_work_fence(source.work_fence);
            target.set_generation(source.generation);
            for (const auto &response : source.facts) {
                if (response.subject.peer != source.peer) {
                    return std::unexpected(codec_error(ProtocolErrorCode::malformed, "fact result escapes work peer"));
                }
                if (auto status = append_message(target.mutable_facts(), ctx, [&](auto &item) {
                        return to_wire(item, response, ctx, limits);
                    });
                    !status)
                    return status;
            }
            for (const auto &response : source.scans) {
                if (response.subject.peer != source.peer) {
                    return std::unexpected(codec_error(ProtocolErrorCode::malformed, "scan result escapes work peer"));
                }
                if (auto status = append_message(target.mutable_scans(), ctx, [&](auto &item) {
                        return to_wire(item, response, ctx, limits);
                    });
                    !status)
                    return status;
            }
            return {};
        }

        [[nodiscard]] std::expected<WorkResultMessage, ProtocolError>
        from_wire(const wire::WorkResult<> &source, const ProtocolLimits &limits) {
            WorkResultMessage result {.originating_session = SessionId {text(source.originating_session())},
                                      .peer = PeerId {text(source.peer())},
                                      .originating_session_fence = source.originating_session_fence(),
                                      .work_id = text(source.work_id()),
                                      .attempt_id = text(source.attempt_id()),
                                      .work_fence = source.work_fence(),
                                      .generation = source.generation(),
                                      .facts = {},
                                      .scans = {}};
            for (const auto &response : source.facts()) {
                auto decoded = from_wire(response, limits);
                if (!decoded) return std::unexpected(std::move(decoded.error()));
                result.facts.push_back(std::move(*decoded));
            }
            for (const auto &response : source.scans()) {
                auto decoded = from_wire(response, limits);
                if (!decoded) return std::unexpected(std::move(decoded.error()));
                result.scans.push_back(std::move(*decoded));
            }
            Context ctx = make_context(limits);
            auto probe = wire::WorkResult<>::create(ctx);
            if (auto valid = to_wire(probe, result, ctx, limits); !valid)
                return std::unexpected(std::move(valid.error()));
            return result;
        }

        [[nodiscard]] std::expected<void, ProtocolError>
        to_wire(wire::CancelWork<> &target, const CancelWorkMessage &source, Context &ctx,
                const ProtocolLimits &limits) {
            if (source.session.empty() || source.peer.empty() || source.session_fence == 0 || source.work_id.empty() ||
                source.attempt_id.empty() || source.work_fence == 0 || source.server_sequence == 0 ||
                source.route.empty() || source.requests.empty() ||
                source.requests.size() > limits.maximum_fact_requests + limits.maximum_scan_requests) {
                return std::unexpected(codec_error(ProtocolErrorCode::malformed, "cancellation is incomplete"));
            }
            if (auto status = checked(target.set_session(source.session.value), "set cancel session"); !status)
                return status;
            if (auto status = checked(target.set_peer(source.peer.value), "set cancel peer"); !status) return status;
            target.set_session_fence(source.session_fence);
            if (auto status = checked(target.set_work_id(source.work_id), "set cancel work ID"); !status) return status;
            if (auto status = checked(target.set_attempt_id(source.attempt_id), "set cancel attempt ID"); !status)
                return status;
            target.set_work_fence(source.work_fence);
            target.set_server_sequence(source.server_sequence);
            if (auto status = checked(target.set_route(source.route), "set cancel route"); !status) return status;
            std::unordered_set<std::string_view> ids;
            for (const auto &request : source.requests) {
                if (request.empty() || !ids.insert(request.value).second) {
                    return std::unexpected(
                        codec_error(ProtocolErrorCode::duplicate_item, "cancel request is empty or duplicated"));
                }
                if (auto status = append_text(target.mutable_requests(), ctx, request.value); !status) return status;
            }
            return {};
        }

        [[nodiscard]] std::expected<CancelWorkMessage, ProtocolError>
        from_wire(const wire::CancelWork<> &source, const ProtocolLimits &limits) {
            CancelWorkMessage result {.session = SessionId {text(source.session())},
                                      .peer = PeerId {text(source.peer())},
                                      .session_fence = source.session_fence(),
                                      .work_id = text(source.work_id()),
                                      .attempt_id = text(source.attempt_id()),
                                      .work_fence = source.work_fence(),
                                      .server_sequence = source.server_sequence(),
                                      .route = text(source.route()),
                                      .requests = {}};
            for (const auto &request : source.requests()) result.requests.push_back(RequestId {text(request.view())});
            Context ctx = make_context(limits);
            auto probe = wire::CancelWork<>::create(ctx);
            if (auto valid = to_wire(probe, result, ctx, limits); !valid)
                return std::unexpected(std::move(valid.error()));
            return result;
        }

        [[nodiscard]] bool valid_sha256(const std::string_view value) noexcept {
            return value.size() == 71 && value.starts_with("sha256:") &&
                   std::all_of(value.begin() + 7, value.end(), [](const char ch) {
                       return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
                   });
        }

        template<typename Snapshot>
        [[nodiscard]] std::expected<void, ProtocolError> set_snapshot_identity(auto &target, const Snapshot &source) {
            if (source.session.empty() || source.peer.empty() || source.session_fence == 0 || source.snapshot_id.empty() ||
                source.generation == 0) {
                return std::unexpected(codec_error(ProtocolErrorCode::malformed, "snapshot identity is incomplete"));
            }
            if (auto status = checked(target.set_session(source.session.value), "set snapshot session"); !status)
                return status;
            if (auto status = checked(target.set_peer(source.peer.value), "set snapshot peer"); !status) return status;
            target.set_session_fence(source.session_fence);
            if (auto status = checked(target.set_snapshot_id(source.snapshot_id), "set snapshot ID"); !status)
                return status;
            target.set_generation(source.generation);
            return {};
        }

        [[nodiscard]] std::expected<void, ProtocolError>
        to_wire(wire::SnapshotBegin<> &target, const AuthoritativeSnapshotBegin &source, Context &ctx,
                const ProtocolLimits &limits) {
            if (source.subject_schema.empty() || !valid_sha256(source.expected_digest) ||
                source.expected_count > limits.maximum_snapshot_items) {
                return std::unexpected(codec_error(ProtocolErrorCode::malformed, "snapshot begin is invalid"));
            }
            if (auto status = set_snapshot_identity(target, source); !status) return status;
            if (source.parent) {
                auto parent = target.ensure_parent();
                if (!parent) return std::unexpected(wire_error(parent.error(), "allocate snapshot parent"));
                if (auto status = to_wire(*parent, *source.parent, ctx, limits); !status) return status;
            }
            if (auto status = checked(target.set_subject_schema(source.subject_schema.value), "set snapshot schema");
                !status)
                return status;
            target.set_expected_count(source.expected_count);
            return checked(target.set_expected_digest(source.expected_digest), "set snapshot digest");
        }

        [[nodiscard]] std::expected<AuthoritativeSnapshotBegin, ProtocolError>
        from_wire(const wire::SnapshotBegin<> &source, const ProtocolLimits &limits) {
            AuthoritativeSnapshotBegin result {.session = SessionId {text(source.session())},
                                               .peer = PeerId {text(source.peer())},
                                               .session_fence = source.session_fence(),
                                               .snapshot_id = text(source.snapshot_id()),
                                               .parent = std::nullopt,
                                               .subject_schema = SchemaId {text(source.subject_schema())},
                                               .generation = source.generation(),
                                               .expected_count = source.expected_count(),
                                               .expected_digest = text(source.expected_digest())};
            if (source.has_parent()) {
                auto parent = from_wire(*source.parent(), limits);
                if (!parent) return std::unexpected(std::move(parent.error()));
                result.parent = std::move(*parent);
            }
            Context ctx = make_context(limits);
            auto probe = wire::SnapshotBegin<>::create(ctx);
            if (auto valid = to_wire(probe, result, ctx, limits); !valid)
                return std::unexpected(std::move(valid.error()));
            return result;
        }

        [[nodiscard]] std::expected<void, ProtocolError>
        to_wire(wire::SnapshotChunk<> &target, const AuthoritativeSnapshotChunk &source, Context &ctx,
                const ProtocolLimits &limits) {
            if (source.subjects.empty() || source.subjects.size() > limits.maximum_snapshot_items) {
                return std::unexpected(codec_error(ProtocolErrorCode::malformed, "snapshot chunk is empty or oversized"));
            }
            if (auto status = set_snapshot_identity(target, source); !status) return status;
            target.set_chunk_index(source.chunk_index);
            for (const auto &subject : source.subjects) {
                if (subject.peer != source.peer) {
                    return std::unexpected(codec_error(ProtocolErrorCode::malformed, "snapshot subject escapes peer"));
                }
                if (auto status = append_message(target.mutable_subjects(), ctx, [&](auto &item) {
                        return to_wire(item, subject, ctx, limits);
                    });
                    !status)
                    return status;
            }
            return {};
        }

        [[nodiscard]] std::expected<AuthoritativeSnapshotChunk, ProtocolError>
        from_wire(const wire::SnapshotChunk<> &source, const ProtocolLimits &limits) {
            AuthoritativeSnapshotChunk result {.session = SessionId {text(source.session())},
                                               .peer = PeerId {text(source.peer())},
                                               .session_fence = source.session_fence(),
                                               .snapshot_id = text(source.snapshot_id()),
                                               .generation = source.generation(),
                                               .chunk_index = source.chunk_index(),
                                               .subjects = {}};
            for (const auto &subject : source.subjects()) {
                auto decoded = from_wire(subject, limits);
                if (!decoded) return std::unexpected(std::move(decoded.error()));
                result.subjects.push_back(std::move(*decoded));
            }
            Context ctx = make_context(limits);
            auto probe = wire::SnapshotChunk<>::create(ctx);
            if (auto valid = to_wire(probe, result, ctx, limits); !valid)
                return std::unexpected(std::move(valid.error()));
            return result;
        }

        [[nodiscard]] std::expected<void, ProtocolError>
        to_wire(wire::SnapshotCommit<> &target, const AuthoritativeSnapshotCommit &source) {
            if (!valid_sha256(source.canonical_digest)) {
                return std::unexpected(codec_error(ProtocolErrorCode::malformed, "snapshot commit digest is invalid"));
            }
            if (auto status = set_snapshot_identity(target, source); !status) return status;
            target.set_item_count(source.item_count);
            return checked(target.set_canonical_digest(source.canonical_digest), "set snapshot commit digest");
        }

        [[nodiscard]] std::expected<AuthoritativeSnapshotCommit, ProtocolError>
        from_wire(const wire::SnapshotCommit<> &source) {
            AuthoritativeSnapshotCommit result {.session = SessionId {text(source.session())},
                                                .peer = PeerId {text(source.peer())},
                                                .session_fence = source.session_fence(),
                                                .snapshot_id = text(source.snapshot_id()),
                                                .generation = source.generation(),
                                                .item_count = source.item_count(),
                                                .canonical_digest = text(source.canonical_digest())};
            Context ctx = make_context({});
            auto probe = wire::SnapshotCommit<>::create(ctx);
            if (auto valid = to_wire(probe, result); !valid) return std::unexpected(std::move(valid.error()));
            return result;
        }

        [[nodiscard]] std::expected<void, ProtocolError> to_wire(wire::Ack<> &target, const AckMessage &source) {
            if (source.agent_epoch.empty()) {
                return std::unexpected(codec_error(ProtocolErrorCode::malformed, "ACK epoch is absent"));
            }
            if (auto status = checked(target.set_agent_epoch(source.agent_epoch), "set ACK epoch"); !status)
                return status;
            target.set_acknowledged_through(source.acknowledged_through);
            auto credit = target.ensure_credit();
            if (!credit) return std::unexpected(wire_error(credit.error(), "allocate ACK credit"));
            to_wire(*credit, source.credit);
            return {};
        }

        [[nodiscard]] std::expected<AckMessage, ProtocolError> from_wire(const wire::Ack<> &source) {
            if (!source.has_credit()) {
                return std::unexpected(codec_error(ProtocolErrorCode::malformed, "ACK credit is absent"));
            }
            AckMessage result {.agent_epoch = text(source.agent_epoch()),
                               .acknowledged_through = source.acknowledged_through(),
                               .credit = from_wire(*source.credit())};
            if (result.agent_epoch.empty()) {
                return std::unexpected(codec_error(ProtocolErrorCode::malformed, "ACK epoch is absent"));
            }
            return result;
        }

        [[nodiscard]] std::expected<void, ProtocolError> to_wire(wire::Nack<> &target, const NackMessage &source) {
            if (source.agent_epoch.empty() || source.sequence == 0 || source.diagnostic.empty()) {
                return std::unexpected(codec_error(ProtocolErrorCode::malformed, "NACK is incomplete"));
            }
            if (auto status = checked(target.set_agent_epoch(source.agent_epoch), "set NACK epoch"); !status)
                return status;
            target.set_sequence(source.sequence);
            target.set_reason(static_cast<std::uint32_t>(source.reason));
            target.set_permanent(source.permanent);
            return checked(target.set_diagnostic(source.diagnostic), "set NACK diagnostic");
        }

        [[nodiscard]] std::expected<NackMessage, ProtocolError> from_wire(const wire::Nack<> &source) {
            if (source.reason() > static_cast<std::uint32_t>(ProtocolErrorCode::timed_out)) {
                return std::unexpected(codec_error(ProtocolErrorCode::malformed, "NACK reason is invalid"));
            }
            NackMessage result {.agent_epoch = text(source.agent_epoch()),
                                .sequence = source.sequence(),
                                .reason = static_cast<ProtocolErrorCode>(source.reason()),
                                .permanent = source.permanent(),
                                .diagnostic = text(source.diagnostic())};
            Context ctx = make_context({});
            auto probe = wire::Nack<>::create(ctx);
            if (auto valid = to_wire(probe, result); !valid) return std::unexpected(std::move(valid.error()));
            return result;
        }

        void to_wire(wire::CreditUpdate<> &target, const CreditUpdateMessage &source) {
            if (auto credit = target.ensure_credit(); credit) to_wire(*credit, source.credit);
        }

        [[nodiscard]] std::expected<CreditUpdateMessage, ProtocolError>
        from_wire(const wire::CreditUpdate<> &source) {
            if (!source.has_credit()) {
                return std::unexpected(codec_error(ProtocolErrorCode::malformed, "credit update is empty"));
            }
            return CreditUpdateMessage {.credit = from_wire(*source.credit())};
        }

        [[nodiscard]] std::expected<void, ProtocolError>
        to_wire(wire::MessageBody<> &target, const MessageBody &source, Context &ctx, const ProtocolLimits &limits) {
            return std::visit(
                [&](const auto &message) -> std::expected<void, ProtocolError> {
                    using Message = std::remove_cvref_t<decltype(message)>;
                    auto result = [&]() {
                        if constexpr (std::is_same_v<Message, AgentHelloMessage>) return target.ensure_agent_hello();
                        else if constexpr (std::is_same_v<Message, ServerHelloMessage>) return target.ensure_server_hello();
                        else if constexpr (std::is_same_v<Message, WorkLeaseMessage>) return target.ensure_work_lease();
                        else if constexpr (std::is_same_v<Message, WorkResultMessage>) return target.ensure_work_result();
                        else if constexpr (std::is_same_v<Message, CancelWorkMessage>) return target.ensure_cancel_work();
                        else if constexpr (std::is_same_v<Message, AuthoritativeSnapshotBegin>)
                            return target.ensure_snapshot_begin();
                        else if constexpr (std::is_same_v<Message, AuthoritativeSnapshotChunk>)
                            return target.ensure_snapshot_chunk();
                        else if constexpr (std::is_same_v<Message, AuthoritativeSnapshotCommit>)
                            return target.ensure_snapshot_commit();
                        else if constexpr (std::is_same_v<Message, AckMessage>) return target.ensure_ack();
                        else if constexpr (std::is_same_v<Message, NackMessage>) return target.ensure_nack();
                        else return target.ensure_credit_update();
                    }();
                    if (!result) return std::unexpected(wire_error(result.error(), "allocate protocol body"));
                    if constexpr (std::is_same_v<Message, AuthoritativeSnapshotCommit> ||
                                  std::is_same_v<Message, AckMessage> || std::is_same_v<Message, NackMessage>) {
                        return to_wire(*result, message);
                    } else if constexpr (std::is_same_v<Message, CreditUpdateMessage>) {
                        to_wire(*result, message);
                        return {};
                    } else {
                        return to_wire(*result, message, ctx, limits);
                    }
                },
                source);
        }

        [[nodiscard]] std::expected<MessageBody, ProtocolError>
        from_wire(const wire::MessageBody<> &source, const ProtocolLimits &limits) {
            switch (source.value_case()) {
                case wire::MessageBody<>::ValueCase::agent_hello: {
                    auto value = from_wire(*source.agent_hello(), limits);
                    if (!value) return std::unexpected(std::move(value.error()));
                    return MessageBody {std::move(*value)};
                }
                case wire::MessageBody<>::ValueCase::server_hello: {
                    auto value = from_wire(*source.server_hello(), limits);
                    if (!value) return std::unexpected(std::move(value.error()));
                    return MessageBody {std::move(*value)};
                }
                case wire::MessageBody<>::ValueCase::work_lease: {
                    auto value = from_wire(*source.work_lease(), limits);
                    if (!value) return std::unexpected(std::move(value.error()));
                    return MessageBody {std::move(*value)};
                }
                case wire::MessageBody<>::ValueCase::work_result: {
                    auto value = from_wire(*source.work_result(), limits);
                    if (!value) return std::unexpected(std::move(value.error()));
                    return MessageBody {std::move(*value)};
                }
                case wire::MessageBody<>::ValueCase::cancel_work: {
                    auto value = from_wire(*source.cancel_work(), limits);
                    if (!value) return std::unexpected(std::move(value.error()));
                    return MessageBody {std::move(*value)};
                }
                case wire::MessageBody<>::ValueCase::snapshot_begin: {
                    auto value = from_wire(*source.snapshot_begin(), limits);
                    if (!value) return std::unexpected(std::move(value.error()));
                    return MessageBody {std::move(*value)};
                }
                case wire::MessageBody<>::ValueCase::snapshot_chunk: {
                    auto value = from_wire(*source.snapshot_chunk(), limits);
                    if (!value) return std::unexpected(std::move(value.error()));
                    return MessageBody {std::move(*value)};
                }
                case wire::MessageBody<>::ValueCase::snapshot_commit: {
                    auto value = from_wire(*source.snapshot_commit());
                    if (!value) return std::unexpected(std::move(value.error()));
                    return MessageBody {std::move(*value)};
                }
                case wire::MessageBody<>::ValueCase::ack: {
                    auto value = from_wire(*source.ack());
                    if (!value) return std::unexpected(std::move(value.error()));
                    return MessageBody {std::move(*value)};
                }
                case wire::MessageBody<>::ValueCase::nack: {
                    auto value = from_wire(*source.nack());
                    if (!value) return std::unexpected(std::move(value.error()));
                    return MessageBody {std::move(*value)};
                }
                case wire::MessageBody<>::ValueCase::credit_update: {
                    auto value = from_wire(*source.credit_update());
                    if (!value) return std::unexpected(std::move(value.error()));
                    return MessageBody {std::move(*value)};
                }
                case wire::MessageBody<>::ValueCase::none:
                default:
                    return std::unexpected(
                        codec_error(ProtocolErrorCode::unexpected_message, "protocol body is absent"));
            }
        }

        [[nodiscard]] bool durable_agent_message(const MessageKind kind) noexcept {
            return kind == MessageKind::work_result || kind == MessageKind::snapshot_begin ||
                   kind == MessageKind::snapshot_chunk || kind == MessageKind::snapshot_commit;
        }

        [[nodiscard]] std::expected<void, ProtocolError> validate_envelope(const PeerEnvelope &envelope,
                                                                           const ProtocolLimits &limits) {
            if (envelope.protocol_major != major_version || envelope.protocol_minor != initial_minor_version) {
                return std::unexpected(
                    codec_error(ProtocolErrorCode::unsupported_version, "protocol version is not supported"));
            }
            if (envelope.message_id.empty() || envelope.message_id.size() > limits.maximum_string_bytes) {
                return std::unexpected(codec_error(ProtocolErrorCode::malformed, "message ID is invalid"));
            }
            const auto kind = message_kind(envelope.body);
            if (kind == MessageKind::agent_hello) {
                const auto &hello = std::get<AgentHelloMessage>(envelope.body);
                if (envelope.session || envelope.agent_sequence != 0 || envelope.agent_epoch != hello.agent_epoch) {
                    return std::unexpected(codec_error(ProtocolErrorCode::malformed, "agent hello envelope is invalid"));
                }
                return {};
            }
            if (!envelope.session || envelope.session->empty() || envelope.agent_epoch.empty()) {
                return std::unexpected(
                    codec_error(ProtocolErrorCode::stale_session, "post-handshake envelope lacks session state"));
            }
            if (durable_agent_message(kind) != (envelope.agent_sequence != 0)) {
                return std::unexpected(
                    codec_error(ProtocolErrorCode::malformed, "durable sequence does not match message direction"));
            }
            if (kind == MessageKind::server_hello &&
                *envelope.session != std::get<ServerHelloMessage>(envelope.body).session)
                return std::unexpected(codec_error(ProtocolErrorCode::stale_session, "server session mismatch"));
            if (kind == MessageKind::work_lease &&
                *envelope.session != std::get<WorkLeaseMessage>(envelope.body).session)
                return std::unexpected(codec_error(ProtocolErrorCode::stale_session, "work session mismatch"));
            if (kind == MessageKind::cancel_work &&
                *envelope.session != std::get<CancelWorkMessage>(envelope.body).session)
                return std::unexpected(codec_error(ProtocolErrorCode::stale_session, "cancel session mismatch"));
            if (kind == MessageKind::ack && envelope.agent_epoch != std::get<AckMessage>(envelope.body).agent_epoch)
                return std::unexpected(codec_error(ProtocolErrorCode::stale_session, "ACK epoch mismatch"));
            if (kind == MessageKind::nack && envelope.agent_epoch != std::get<NackMessage>(envelope.body).agent_epoch)
                return std::unexpected(codec_error(ProtocolErrorCode::stale_session, "NACK epoch mismatch"));
            return {};
        }

        [[nodiscard]] std::expected<void, ProtocolError>
        to_wire(wire::PeerEnvelope<> &target, const PeerEnvelope &source, Context &ctx, const ProtocolLimits &limits) {
            if (auto valid = validate_envelope(source, limits); !valid) return valid;
            target.set_protocol_major(source.protocol_major);
            target.set_protocol_minor(source.protocol_minor);
            if (auto status = checked(target.set_message_id(source.message_id), "set message ID"); !status)
                return status;
            if (source.session) {
                if (auto status = checked(target.set_session(source.session->value), "set envelope session"); !status)
                    return status;
            }
            if (auto status = checked(target.set_agent_epoch(source.agent_epoch), "set envelope epoch"); !status)
                return status;
            target.set_agent_sequence(source.agent_sequence);
            target.set_acknowledged_agent_sequence(source.acknowledged_agent_sequence);
            target.set_message_kind(static_cast<std::uint32_t>(message_kind(source.body)));
            auto body = target.ensure_body();
            if (!body) return std::unexpected(wire_error(body.error(), "allocate envelope body"));
            return to_wire(*body, source.body, ctx, limits);
        }

        [[nodiscard]] std::expected<PeerEnvelope, ProtocolError>
        from_wire(const wire::PeerEnvelope<> &source, const ProtocolLimits &limits) {
            if (!source.has_body() || source.protocol_major() > std::numeric_limits<std::uint16_t>::max() ||
                source.protocol_minor() > std::numeric_limits<std::uint16_t>::max()) {
                return std::unexpected(codec_error(ProtocolErrorCode::malformed, "protocol envelope is incomplete"));
            }
            auto body = from_wire(*source.body(), limits);
            if (!body) return std::unexpected(std::move(body.error()));
            if (source.message_kind() != static_cast<std::uint32_t>(message_kind(*body))) {
                return std::unexpected(
                    codec_error(ProtocolErrorCode::unexpected_message, "message kind and generated oneof disagree"));
            }
            PeerEnvelope result {.protocol_major = static_cast<std::uint16_t>(source.protocol_major()),
                                 .protocol_minor = static_cast<std::uint16_t>(source.protocol_minor()),
                                 .message_id = text(source.message_id()),
                                 .session = source.has_session()
                                                ? std::optional<SessionId> {SessionId {text(source.session())}}
                                                : std::nullopt,
                                 .agent_epoch = text(source.agent_epoch()),
                                 .agent_sequence = source.agent_sequence(),
                                 .acknowledged_agent_sequence = source.acknowledged_agent_sequence(),
                                 .body = std::move(*body)};
            if (auto valid = validate_envelope(result, limits); !valid) return std::unexpected(std::move(valid.error()));
            return result;
        }

        template<typename WireMessage>
        [[nodiscard]] std::expected<std::vector<std::byte>, ProtocolError>
        serialize_generated(const WireMessage &message, const ProtocolLimits &limits) {
            auto size = message.encoded_size();
            if (!size) return std::unexpected(wire_error(size.error(), "Protocyte encoded_size"));
            if (*size == 0 || *size > limits.maximum_frame_bytes) {
                return std::unexpected(
                    codec_error(ProtocolErrorCode::limit_exceeded, "generated protocol payload exceeds the limit"));
            }
            std::vector<std::byte> output(*size);
            auto written = message.serialize(
                protocyte::Span<protocyte::u8> {reinterpret_cast<protocyte::u8 *>(output.data()), output.size()});
            if (!written) return std::unexpected(wire_error(written.error(), "Protocyte serialize"));
            if (*written != output.size()) {
                return std::unexpected(codec_error(ProtocolErrorCode::malformed, "Protocyte wrote a partial payload"));
            }
            return output;
        }
    } // namespace

    std::expected<std::vector<std::byte>, ProtocolError> encode_payload(const PeerEnvelope &envelope,
                                                                        const ProtocolLimits &limits) {
        Context ctx = make_context(limits);
        auto generated = wire::PeerEnvelope<>::create(ctx);
        if (auto converted = to_wire(generated, envelope, ctx, limits); !converted)
            return std::unexpected(std::move(converted.error()));
        return serialize_generated(generated, limits);
    }

    std::expected<PeerEnvelope, ProtocolError> decode_payload(const std::span<const std::byte> payload,
                                                              const ProtocolLimits &limits) {
        if (payload.empty() || payload.size() > limits.maximum_frame_bytes) {
            return std::unexpected(
                codec_error(payload.empty() ? ProtocolErrorCode::truncated : ProtocolErrorCode::limit_exceeded,
                            "protocol payload is empty or oversized"));
        }
        if (auto valid = preflight_generated_message(payload, PreflightShape::peer_envelope); !valid)
            return std::unexpected(std::move(valid.error()));
        Context ctx = make_context(limits);
        auto generated = wire::PeerEnvelope<>::parse(ctx, byte_view(payload));
        if (!generated) return std::unexpected(wire_error(generated.error(), "Protocyte parse"));
        return from_wire(*generated, limits);
    }

    std::expected<std::vector<std::byte>, ProtocolError> encode_frame(const PeerEnvelope &envelope,
                                                                      const ProtocolLimits &limits) {
        auto payload = encode_payload(envelope, limits);
        if (!payload) return std::unexpected(std::move(payload.error()));
        if (payload->size() > std::numeric_limits<std::uint32_t>::max()) {
            return std::unexpected(codec_error(ProtocolErrorCode::limit_exceeded, "protocol frame exceeds uint32"));
        }
        const auto size = static_cast<std::uint32_t>(payload->size());
        std::vector<std::byte> frame;
        frame.reserve(payload->size() + 4);
        frame.push_back(static_cast<std::byte>((size >> 24U) & 0xffU));
        frame.push_back(static_cast<std::byte>((size >> 16U) & 0xffU));
        frame.push_back(static_cast<std::byte>((size >> 8U) & 0xffU));
        frame.push_back(static_cast<std::byte>(size & 0xffU));
        frame.insert(frame.end(), payload->begin(), payload->end());
        return frame;
    }

    std::expected<DecodedFrame, ProtocolError> decode_frame(const std::span<const std::byte> input,
                                                            const ProtocolLimits &limits) {
        if (input.size() < 4) {
            return std::unexpected(codec_error(ProtocolErrorCode::truncated, "frame header is truncated"));
        }
        const auto size = (std::to_integer<std::uint32_t>(input[0]) << 24U) |
                          (std::to_integer<std::uint32_t>(input[1]) << 16U) |
                          (std::to_integer<std::uint32_t>(input[2]) << 8U) |
                          std::to_integer<std::uint32_t>(input[3]);
        if (size == 0 || size > limits.maximum_frame_bytes) {
            return std::unexpected(
                codec_error(size == 0 ? ProtocolErrorCode::malformed : ProtocolErrorCode::limit_exceeded,
                            "frame length is zero or exceeds the limit"));
        }
        if (size > input.size() - 4) {
            return std::unexpected(codec_error(ProtocolErrorCode::truncated, "frame payload is truncated"));
        }
        auto envelope = decode_payload(input.subspan(4, size), limits);
        if (!envelope) return std::unexpected(std::move(envelope.error()));
        return DecodedFrame {.envelope = std::move(*envelope), .bytes_consumed = static_cast<std::size_t>(size) + 4};
    }

    std::expected<std::vector<std::byte>, ProtocolError> encode_durable_body(const DurableAgentBody &body,
                                                                             const ProtocolLimits &limits) {
        const MessageBody message = std::visit([](const auto &value) -> MessageBody { return value; }, body);
        const auto kind = message_kind(message);
        if (!durable_agent_message(kind)) {
            return std::unexpected(
                codec_error(ProtocolErrorCode::unexpected_message, "spool body is not durable agent data"));
        }
        Context ctx = make_context(limits);
        auto generated = wire::DurableAgentEnvelope<>::create(ctx);
        generated.set_message_kind(static_cast<std::uint32_t>(kind));
        auto generated_body = generated.ensure_body();
        if (!generated_body)
            return std::unexpected(wire_error(generated_body.error(), "allocate durable protocol body"));
        if (auto converted = to_wire(*generated_body, message, ctx, limits); !converted)
            return std::unexpected(std::move(converted.error()));
        return serialize_generated(generated, limits);
    }

    std::expected<DurableAgentBody, ProtocolError> decode_durable_body(const std::span<const std::byte> input,
                                                                       const ProtocolLimits &limits) {
        if (input.empty() || input.size() > limits.maximum_frame_bytes) {
            return std::unexpected(
                codec_error(input.empty() ? ProtocolErrorCode::truncated : ProtocolErrorCode::limit_exceeded,
                            "durable spool body is empty or oversized"));
        }
        if (auto valid = preflight_generated_message(input, PreflightShape::durable_envelope); !valid)
            return std::unexpected(std::move(valid.error()));
        Context ctx = make_context(limits);
        auto generated = wire::DurableAgentEnvelope<>::parse(ctx, byte_view(input));
        if (!generated) return std::unexpected(wire_error(generated.error(), "Protocyte durable parse"));
        if (!generated->has_body()) {
            return std::unexpected(
                codec_error(ProtocolErrorCode::unexpected_message, "durable protocol body is absent"));
        }
        auto message = from_wire(*generated->body(), limits);
        if (!message) return std::unexpected(std::move(message.error()));
        const auto kind = message_kind(*message);
        if (!durable_agent_message(kind) || generated->message_kind() != static_cast<std::uint32_t>(kind)) {
            return std::unexpected(
                codec_error(ProtocolErrorCode::unexpected_message, "durable body kind is invalid"));
        }
        switch (kind) {
            case MessageKind::work_result: return DurableAgentBody {std::get<WorkResultMessage>(std::move(*message))};
            case MessageKind::snapshot_begin:
                return DurableAgentBody {std::get<AuthoritativeSnapshotBegin>(std::move(*message))};
            case MessageKind::snapshot_chunk:
                return DurableAgentBody {std::get<AuthoritativeSnapshotChunk>(std::move(*message))};
            case MessageKind::snapshot_commit:
                return DurableAgentBody {std::get<AuthoritativeSnapshotCommit>(std::move(*message))};
            default:
                return std::unexpected(
                    codec_error(ProtocolErrorCode::unexpected_message, "durable body kind is unsupported"));
        }
    }

} // namespace rule_engine::python::protocol_v2
