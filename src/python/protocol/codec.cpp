#include "rule_engine/python/protocol/codec.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cmath>
#include <cstring>
#include <expected>
#include <limits>
#include <optional>
#include <span>
#include <string_view>
#include <type_traits>
#include <unordered_set>
#include <utility>

namespace rule_engine::python::protocol_v2 {
    namespace {

        enum struct WireType : std::uint8_t { varint = 0, fixed64 = 1, length_delimited = 2, fixed32 = 5 };

        struct Tag {
            std::uint32_t field {};
            WireType wire {};
        };

        [[nodiscard]] ProtocolError codec_error(const ProtocolErrorCode code, std::string message,
                                                const std::size_t offset = 0) {
            return ProtocolError {.code = code, .message = std::move(message), .byte_offset = offset};
        }

        struct Writer {
            std::vector<std::byte> bytes;

            void varint(std::uint64_t value) {
                while (value >= 0x80U) {
                    bytes.push_back(static_cast<std::byte>((value & 0x7fU) | 0x80U));
                    value >>= 7U;
                }
                bytes.push_back(static_cast<std::byte>(value));
            }

            void tag(const std::uint32_t field, const WireType wire) {
                varint((static_cast<std::uint64_t>(field) << 3U) | static_cast<std::uint8_t>(wire));
            }

            void unsigned_field(const std::uint32_t field, const std::uint64_t value) {
                tag(field, WireType::varint);
                varint(value);
            }

            void boolean_field(const std::uint32_t field, const bool value) { unsigned_field(field, value ? 1U : 0U); }

            void fixed64_field(const std::uint32_t field, const std::uint64_t value) {
                tag(field, WireType::fixed64);
                for (std::uint32_t shift = 0; shift < 64; shift += 8) {
                    bytes.push_back(static_cast<std::byte>((value >> shift) & 0xffU));
                }
            }

            void raw_length_field(const std::uint32_t field, const std::span<const std::byte> value) {
                tag(field, WireType::length_delimited);
                varint(value.size());
                bytes.insert(bytes.end(), value.begin(), value.end());
            }

            void string_field(const std::uint32_t field, const std::string_view value) {
                raw_length_field(field, std::as_bytes(std::span {value.data(), value.size()}));
            }

            void message_field(const std::uint32_t field, const Writer &message) {
                raw_length_field(field, message.bytes);
            }
        };

        struct DecodeBudget {
            std::size_t value_nodes {};
            std::size_t collection_items {};
        };

        struct Reader {
            std::span<const std::byte> bytes;
            const ProtocolLimits *limits {};
            DecodeBudget *budget {};
            std::size_t depth {};
            std::size_t offset {};

            [[nodiscard]] bool eof() const noexcept { return offset == bytes.size(); }

            [[nodiscard]] std::expected<std::uint64_t, ProtocolError> varint() {
                const auto start = offset;
                std::uint64_t value {};
                for (std::uint32_t index = 0; index < 10; ++index) {
                    if (offset >= bytes.size()) {
                        return std::unexpected(codec_error(ProtocolErrorCode::truncated, "truncated varint", offset));
                    }
                    const auto octet = std::to_integer<std::uint8_t>(bytes[offset++]);
                    if (index == 9 && (octet & 0xfeU) != 0) {
                        return std::unexpected(
                            codec_error(ProtocolErrorCode::malformed, "varint overflows uint64", start));
                    }
                    value |= static_cast<std::uint64_t>(octet & 0x7fU) << (index * 7U);
                    if ((octet & 0x80U) == 0) {
                        std::size_t minimum_bytes {1};
                        for (auto remaining = value; remaining >= 0x80U; remaining >>= 7U) { ++minimum_bytes; }
                        if (offset - start != minimum_bytes) {
                            return std::unexpected(
                                codec_error(ProtocolErrorCode::malformed, "non-canonical overlong varint", start));
                        }
                        return value;
                    }
                }
                return std::unexpected(codec_error(ProtocolErrorCode::malformed, "unterminated varint", start));
            }

            [[nodiscard]] std::expected<Tag, ProtocolError> next_tag() {
                const auto start = offset;
                auto encoded = varint();
                if (!encoded) {
                    return std::unexpected(std::move(encoded.error()));
                }
                const auto field = static_cast<std::uint32_t>(*encoded >> 3U);
                const auto wire_number = static_cast<std::uint8_t>(*encoded & 0x7U);
                if (field == 0 || field > 0x1fffffffU ||
                    (wire_number != 0 && wire_number != 1 && wire_number != 2 && wire_number != 5)) {
                    return std::unexpected(codec_error(ProtocolErrorCode::malformed, "invalid protobuf tag", start));
                }
                return Tag {.field = field, .wire = static_cast<WireType>(wire_number)};
            }

            [[nodiscard]] std::expected<std::uint64_t, ProtocolError> read_unsigned(const Tag tag) {
                if (tag.wire != WireType::varint) {
                    return std::unexpected(codec_error(ProtocolErrorCode::malformed, "expected varint field", offset));
                }
                return varint();
            }

            [[nodiscard]] std::expected<bool, ProtocolError> read_boolean(const Tag tag) {
                auto value = read_unsigned(tag);
                if (!value) {
                    return std::unexpected(std::move(value.error()));
                }
                if (*value > 1) {
                    return std::unexpected(
                        codec_error(ProtocolErrorCode::malformed, "boolean is not zero or one", offset));
                }
                return *value == 1;
            }

            [[nodiscard]] std::expected<std::uint64_t, ProtocolError> read_fixed64(const Tag tag) {
                if (tag.wire != WireType::fixed64 || bytes.size() - offset < 8) {
                    return std::unexpected(codec_error(tag.wire == WireType::fixed64 ? ProtocolErrorCode::truncated :
                                                                                       ProtocolErrorCode::malformed,
                                                       "invalid fixed64 field", offset));
                }
                std::uint64_t value {};
                for (std::uint32_t shift = 0; shift < 64; shift += 8) {
                    value |= static_cast<std::uint64_t>(std::to_integer<std::uint8_t>(bytes[offset++])) << shift;
                }
                return value;
            }

            [[nodiscard]] std::expected<std::span<const std::byte>, ProtocolError>
            read_bytes(const Tag tag, const std::size_t maximum) {
                if (tag.wire != WireType::length_delimited) {
                    return std::unexpected(
                        codec_error(ProtocolErrorCode::malformed, "expected length-delimited field", offset));
                }
                auto size = varint();
                if (!size) {
                    return std::unexpected(std::move(size.error()));
                }
                if (*size > maximum || *size > bytes.size() - offset) {
                    return std::unexpected(
                        codec_error(*size > maximum ? ProtocolErrorCode::limit_exceeded : ProtocolErrorCode::truncated,
                                    "length-delimited field exceeds its bound", offset));
                }
                const auto result = bytes.subspan(offset, static_cast<std::size_t>(*size));
                offset += static_cast<std::size_t>(*size);
                return result;
            }

            [[nodiscard]] std::expected<void, ProtocolError> skip(const Tag tag) {
                switch (tag.wire) {
                    case WireType::varint: {
                        auto ignored = varint();
                        if (!ignored) {
                            return std::unexpected(std::move(ignored.error()));
                        }
                        return {};
                    }
                    case WireType::fixed64:
                        if (bytes.size() - offset < 8) {
                            return std::unexpected(
                                codec_error(ProtocolErrorCode::truncated, "truncated unknown fixed64 field", offset));
                        }
                        offset += 8;
                        return {};
                    case WireType::fixed32:
                        if (bytes.size() - offset < 4) {
                            return std::unexpected(
                                codec_error(ProtocolErrorCode::truncated, "truncated unknown fixed32 field", offset));
                        }
                        offset += 4;
                        return {};
                    case WireType::length_delimited: {
                        auto ignored = read_bytes(tag, limits->maximum_frame_bytes);
                        if (!ignored) {
                            return std::unexpected(std::move(ignored.error()));
                        }
                        return {};
                    }
                    default: break;
                }
                return std::unexpected(codec_error(ProtocolErrorCode::malformed, "unknown wire type", offset));
            }
        };

        struct SeenFields {
            std::unordered_set<std::uint32_t> fields;

            [[nodiscard]] std::expected<void, ProtocolError> mark(const std::uint32_t field, const std::size_t offset) {
                if (!fields.insert(field).second) {
                    return std::unexpected(
                        codec_error(ProtocolErrorCode::duplicate_field, "duplicate non-repeated field", offset));
                }
                return {};
            }
        };

        [[nodiscard]] bool valid_utf8(const std::string_view text) noexcept {
            const auto *data = reinterpret_cast<const unsigned char *>(text.data());
            std::size_t index {};
            while (index < text.size()) {
                const auto first = data[index++];
                if (first <= 0x7fU) {
                    continue;
                }
                std::uint32_t value {};
                std::size_t continuation {};
                std::uint32_t minimum {};
                if (first >= 0xc2U && first <= 0xdfU) {
                    value = first & 0x1fU;
                    continuation = 1;
                    minimum = 0x80U;
                } else if (first >= 0xe0U && first <= 0xefU) {
                    value = first & 0x0fU;
                    continuation = 2;
                    minimum = 0x800U;
                } else if (first >= 0xf0U && first <= 0xf4U) {
                    value = first & 0x07U;
                    continuation = 3;
                    minimum = 0x10000U;
                } else {
                    return false;
                }
                if (continuation > text.size() - index) {
                    return false;
                }
                for (std::size_t count = 0; count < continuation; ++count) {
                    const auto next = data[index++];
                    if ((next & 0xc0U) != 0x80U) {
                        return false;
                    }
                    value = (value << 6U) | (next & 0x3fU);
                }
                if (value < minimum || value > 0x10ffffU || (value >= 0xd800U && value <= 0xdfffU)) {
                    return false;
                }
            }
            return true;
        }

        [[nodiscard]] std::expected<void, ProtocolError>
        validate_scan_pattern_ids(const std::span<const std::string> pattern_ids, const ProtocolLimits &limits) {
            if (pattern_ids.empty()) {
                return std::unexpected(
                    codec_error(ProtocolErrorCode::malformed, "scan plan must declare at least one pattern ID"));
            }
            if (pattern_ids.size() > limits.maximum_scan_patterns) {
                return std::unexpected(
                    codec_error(ProtocolErrorCode::limit_exceeded, "scan pattern ID count exceeds the limit"));
            }

            std::unordered_set<std::string_view> unique_ids;
            unique_ids.reserve(pattern_ids.size());
            for (const auto &pattern_id : pattern_ids) {
                if (pattern_id.empty()) {
                    return std::unexpected(
                        codec_error(ProtocolErrorCode::malformed, "scan pattern ID must not be empty"));
                }
                if (pattern_id.size() > limits.maximum_string_bytes) {
                    return std::unexpected(
                        codec_error(ProtocolErrorCode::limit_exceeded, "scan pattern ID exceeds the string limit"));
                }
                if (!valid_utf8(pattern_id)) {
                    return std::unexpected(
                        codec_error(ProtocolErrorCode::invalid_utf8, "scan pattern ID is not canonical UTF-8"));
                }
                if (!unique_ids.insert(pattern_id).second) {
                    return std::unexpected(
                        codec_error(ProtocolErrorCode::duplicate_item, "scan pattern IDs must be unique"));
                }
            }
            return {};
        }

        [[nodiscard]] bool canonical_integer(const std::string_view decimal) noexcept {
            if (decimal.empty()) {
                return false;
            }
            std::size_t offset {};
            if (decimal.front() == '-') {
                if (decimal.size() == 1 || decimal[1] == '0') {
                    return false;
                }
                offset = 1;
            }
            if (decimal[offset] == '0' && decimal.size() - offset != 1) {
                return false;
            }
            return std::ranges::all_of(decimal.substr(offset),
                                       [](const char value) { return value >= '0' && value <= '9'; });
        }

        [[nodiscard]] std::expected<std::string, ProtocolError> read_string(Reader &reader, const Tag tag,
                                                                            const bool require_utf8 = true) {
            auto bytes = reader.read_bytes(tag, reader.limits->maximum_string_bytes);
            if (!bytes) {
                return std::unexpected(std::move(bytes.error()));
            }
            std::string result(reinterpret_cast<const char *>(bytes->data()), bytes->size());
            if (require_utf8 && !valid_utf8(result)) {
                return std::unexpected(
                    codec_error(ProtocolErrorCode::invalid_utf8, "string is not canonical UTF-8", reader.offset));
            }
            return result;
        }

        [[nodiscard]] std::expected<Reader, ProtocolError> child_reader(Reader &reader, const Tag tag,
                                                                        const std::size_t maximum_depth) {
            if (reader.depth >= maximum_depth) {
                return std::unexpected(codec_error(ProtocolErrorCode::limit_exceeded,
                                                   "nested message depth exceeds the limit", reader.offset));
            }
            auto body = reader.read_bytes(tag, reader.limits->maximum_frame_bytes);
            if (!body) {
                return std::unexpected(std::move(body.error()));
            }
            return Reader {.bytes = *body,
                           .limits = reader.limits,
                           .budget = reader.budget,
                           .depth = reader.depth + 1,
                           .offset = 0};
        }

        [[nodiscard]] std::expected<void, ProtocolError> count_collection(Reader &reader,
                                                                          const std::size_t amount = 1) {
            if (amount > reader.limits->maximum_collection_items - reader.budget->collection_items) {
                return std::unexpected(codec_error(ProtocolErrorCode::limit_exceeded,
                                                   "decoded collection item count exceeds the limit", reader.offset));
            }
            reader.budget->collection_items += amount;
            return {};
        }

        void encode_credit(Writer &writer, const CreditWindow &credit) {
            writer.unsigned_field(1, credit.bytes);
            writer.unsigned_field(2, credit.messages);
            writer.unsigned_field(3, credit.work_attempts);
            writer.unsigned_field(4, credit.snapshot_chunks);
        }

        [[nodiscard]] std::expected<CreditWindow, ProtocolError> decode_credit(Reader &reader) {
            CreditWindow result;
            SeenFields seen;
            while (!reader.eof()) {
                auto tag = reader.next_tag();
                if (!tag) {
                    return std::unexpected(std::move(tag.error()));
                }
                if (tag->field > 4) {
                    if (auto skipped = reader.skip(*tag); !skipped) {
                        return std::unexpected(std::move(skipped.error()));
                    }
                    continue;
                }
                if (auto marked = seen.mark(tag->field, reader.offset); !marked) {
                    return std::unexpected(std::move(marked.error()));
                }
                auto value = reader.read_unsigned(*tag);
                if (!value) {
                    return std::unexpected(std::move(value.error()));
                }
                switch (tag->field) {
                    case 1: result.bytes = *value; break;
                    case 2:
                        if (*value > std::numeric_limits<std::uint32_t>::max()) {
                            return std::unexpected(codec_error(ProtocolErrorCode::limit_exceeded,
                                                               "message credit exceeds uint32", reader.offset));
                        }
                        result.messages = static_cast<std::uint32_t>(*value);
                        break;
                    case 3:
                        if (*value > std::numeric_limits<std::uint32_t>::max()) {
                            return std::unexpected(codec_error(ProtocolErrorCode::limit_exceeded,
                                                               "work credit exceeds uint32", reader.offset));
                        }
                        result.work_attempts = static_cast<std::uint32_t>(*value);
                        break;
                    case 4:
                        if (*value > std::numeric_limits<std::uint32_t>::max()) {
                            return std::unexpected(codec_error(ProtocolErrorCode::limit_exceeded,
                                                               "snapshot credit exceeds uint32", reader.offset));
                        }
                        result.snapshot_chunks = static_cast<std::uint32_t>(*value);
                        break;
                    default: break;
                }
            }
            return result;
        }

        void encode_schema(Writer &writer, const SchemaAdvertisement &schema) {
            writer.string_field(1, schema.schema.value);
            writer.unsigned_field(2, schema.major);
            writer.string_field(3, schema.canonical_hash);
        }

        [[nodiscard]] std::expected<SchemaAdvertisement, ProtocolError> decode_schema(Reader &reader) {
            SchemaAdvertisement result;
            SeenFields seen;
            while (!reader.eof()) {
                auto tag = reader.next_tag();
                if (!tag) {
                    return std::unexpected(std::move(tag.error()));
                }
                if (tag->field > 3) {
                    if (auto skipped = reader.skip(*tag); !skipped) {
                        return std::unexpected(std::move(skipped.error()));
                    }
                    continue;
                }
                if (auto marked = seen.mark(tag->field, reader.offset); !marked) {
                    return std::unexpected(std::move(marked.error()));
                }
                if (tag->field == 2) {
                    auto value = reader.read_unsigned(*tag);
                    if (!value || *value > std::numeric_limits<std::uint32_t>::max()) {
                        return std::unexpected(value ? codec_error(ProtocolErrorCode::limit_exceeded,
                                                                   "schema major exceeds uint32", reader.offset) :
                                                       std::move(value.error()));
                    }
                    result.major = static_cast<std::uint32_t>(*value);
                    continue;
                }
                auto value = read_string(reader, *tag);
                if (!value) {
                    return std::unexpected(std::move(value.error()));
                }
                if (tag->field == 1) {
                    result.schema = SchemaId {std::move(*value)};
                } else {
                    result.canonical_hash = std::move(*value);
                }
            }
            if (result.schema.empty() || result.major == 0 || result.canonical_hash.empty()) {
                return std::unexpected(codec_error(ProtocolErrorCode::schema_mismatch,
                                                   "schema advertisement is incomplete", reader.offset));
            }
            return result;
        }

        void encode_schema_identity(Writer &writer, const SchemaIdentity &identity) {
            writer.string_field(1, identity.id.value);
            writer.string_field(2, identity.canonical_hash);
        }

        [[nodiscard]] std::expected<SchemaIdentity, ProtocolError> decode_schema_identity(Reader &reader) {
            SchemaIdentity result;
            SeenFields seen;
            while (!reader.eof()) {
                auto tag = reader.next_tag();
                if (!tag) {
                    return std::unexpected(std::move(tag.error()));
                }
                if (tag->field > 2) {
                    if (auto skipped = reader.skip(*tag); !skipped) {
                        return std::unexpected(std::move(skipped.error()));
                    }
                    continue;
                }
                if (auto marked = seen.mark(tag->field, reader.offset); !marked) {
                    return std::unexpected(std::move(marked.error()));
                }
                auto value = read_string(reader, *tag);
                if (!value) {
                    return std::unexpected(std::move(value.error()));
                }
                if (tag->field == 1) {
                    result.id = SchemaId {std::move(*value)};
                } else {
                    result.canonical_hash = std::move(*value);
                }
            }
            if (!result.valid()) {
                return std::unexpected(codec_error(ProtocolErrorCode::schema_mismatch,
                                                   "schema identity is incomplete", reader.offset));
            }
            return result;
        }

        void encode_capability(Writer &writer, const CapabilityAdvertisement &capability) {
            writer.string_field(1, capability.capability.value);
            writer.unsigned_field(2, capability.version);
            writer.string_field(3, capability.request_schema.value);
            writer.string_field(4, capability.response_schema.value);
        }

        [[nodiscard]] std::expected<CapabilityAdvertisement, ProtocolError> decode_capability(Reader &reader) {
            CapabilityAdvertisement result;
            SeenFields seen;
            while (!reader.eof()) {
                auto tag = reader.next_tag();
                if (!tag) {
                    return std::unexpected(std::move(tag.error()));
                }
                if (tag->field > 4) {
                    if (auto skipped = reader.skip(*tag); !skipped) {
                        return std::unexpected(std::move(skipped.error()));
                    }
                    continue;
                }
                if (auto marked = seen.mark(tag->field, reader.offset); !marked) {
                    return std::unexpected(std::move(marked.error()));
                }
                if (tag->field == 2) {
                    auto value = reader.read_unsigned(*tag);
                    if (!value || *value > std::numeric_limits<std::uint32_t>::max()) {
                        return std::unexpected(value ? codec_error(ProtocolErrorCode::limit_exceeded,
                                                                   "capability version exceeds uint32", reader.offset) :
                                                       std::move(value.error()));
                    }
                    result.version = static_cast<std::uint32_t>(*value);
                    continue;
                }
                auto value = read_string(reader, *tag);
                if (!value) {
                    return std::unexpected(std::move(value.error()));
                }
                if (tag->field == 1) {
                    result.capability = CapabilityId {std::move(*value)};
                } else if (tag->field == 3) {
                    result.request_schema = SchemaId {std::move(*value)};
                } else {
                    result.response_schema = SchemaId {std::move(*value)};
                }
            }
            if (result.capability.empty() || result.version == 0 || result.request_schema.empty() ||
                result.response_schema.empty()) {
                return std::unexpected(codec_error(ProtocolErrorCode::capability_mismatch,
                                                   "capability advertisement is incomplete", reader.offset));
            }
            return result;
        }

        void encode_identity(Writer &writer, const IdentityField &identity) {
            writer.unsigned_field(1, identity.field_id);
            std::visit(
                [&writer](const auto &value) {
                    using Value = std::remove_cvref_t<decltype(value)>;
                    if constexpr (std::is_same_v<Value, bool>) {
                        writer.unsigned_field(2, 1);
                        writer.boolean_field(3, value);
                    } else if constexpr (std::is_same_v<Value, std::int64_t>) {
                        writer.unsigned_field(2, 2);
                        writer.fixed64_field(4, std::bit_cast<std::uint64_t>(value));
                    } else if constexpr (std::is_same_v<Value, std::uint64_t>) {
                        writer.unsigned_field(2, 3);
                        writer.unsigned_field(5, value);
                    } else if constexpr (std::is_same_v<Value, IntegerValue>) {
                        writer.unsigned_field(2, 4);
                        writer.string_field(6, value.decimal);
                    } else if constexpr (std::is_same_v<Value, UnicodeValue>) {
                        writer.unsigned_field(2, 5);
                        writer.string_field(7, value.utf8);
                    } else {
                        writer.unsigned_field(2, 6);
                        writer.raw_length_field(8, value.bytes);
                    }
                },
                identity.value);
        }

        [[nodiscard]] std::expected<IdentityField, ProtocolError> decode_identity(Reader &reader) {
            IdentityField result;
            SeenFields seen;
            std::optional<std::uint64_t> kind;
            std::optional<IdentityScalar> value;
            while (!reader.eof()) {
                auto tag = reader.next_tag();
                if (!tag) {
                    return std::unexpected(std::move(tag.error()));
                }
                if (tag->field > 8) {
                    if (auto skipped = reader.skip(*tag); !skipped) {
                        return std::unexpected(std::move(skipped.error()));
                    }
                    continue;
                }
                if (auto marked = seen.mark(tag->field, reader.offset); !marked) {
                    return std::unexpected(std::move(marked.error()));
                }
                if (tag->field == 1 || tag->field == 2 || tag->field == 3 || tag->field == 5) {
                    if (tag->field == 3) {
                        auto boolean = reader.read_boolean(*tag);
                        if (!boolean) {
                            return std::unexpected(std::move(boolean.error()));
                        }
                        value = *boolean;
                        continue;
                    }
                    auto number = reader.read_unsigned(*tag);
                    if (!number) {
                        return std::unexpected(std::move(number.error()));
                    }
                    if (tag->field == 1) {
                        if (*number == 0 || *number > std::numeric_limits<std::uint32_t>::max()) {
                            return std::unexpected(codec_error(ProtocolErrorCode::invalid_identity,
                                                               "identity field number is invalid", reader.offset));
                        }
                        result.field_id = static_cast<std::uint32_t>(*number);
                    } else if (tag->field == 2) {
                        kind = *number;
                    } else {
                        value = *number;
                    }
                    continue;
                }
                if (tag->field == 4) {
                    auto number = reader.read_fixed64(*tag);
                    if (!number) {
                        return std::unexpected(std::move(number.error()));
                    }
                    value = std::bit_cast<std::int64_t>(*number);
                    continue;
                }
                if (tag->field == 8) {
                    auto bytes = reader.read_bytes(*tag, reader.limits->maximum_blob_bytes);
                    if (!bytes) {
                        return std::unexpected(std::move(bytes.error()));
                    }
                    value = BytesValue {std::vector<std::byte>(bytes->begin(), bytes->end())};
                    continue;
                }
                auto text = read_string(reader, *tag);
                if (!text) {
                    return std::unexpected(std::move(text.error()));
                }
                if (tag->field == 6) {
                    value = IntegerValue {std::move(*text)};
                } else {
                    value = UnicodeValue {std::move(*text)};
                }
            }
            if (result.field_id == 0 || !kind.has_value() || !value.has_value() || *kind == 0 || *kind > 6 ||
                value->index() != *kind - 1) {
                return std::unexpected(codec_error(ProtocolErrorCode::invalid_identity,
                                                   "identity kind and value do not agree", reader.offset));
            }
            if (const auto *integer = std::get_if<IntegerValue>(&*value);
                integer != nullptr && !canonical_integer(integer->decimal)) {
                return std::unexpected(codec_error(ProtocolErrorCode::invalid_identity,
                                                   "arbitrary integer spelling is not canonical", reader.offset));
            }
            result.value = std::move(*value);
            return result;
        }

        void encode_subject(Writer &writer, const SubjectKey &subject, const std::size_t depth = 0) {
            writer.string_field(1, subject.peer.value);
            writer.string_field(2, subject.descriptor.value);
            for (const auto &identity : subject.identity) {
                Writer nested;
                encode_identity(nested, identity);
                writer.message_field(3, nested);
            }
            if (subject.parent) {
                Writer nested;
                encode_subject(nested, *subject.parent, depth + 1);
                writer.message_field(4, nested);
            }
        }

        [[nodiscard]] std::expected<SubjectKey, ProtocolError> decode_subject(Reader &reader) {
            SubjectKey result;
            SeenFields seen;
            while (!reader.eof()) {
                auto tag = reader.next_tag();
                if (!tag) {
                    return std::unexpected(std::move(tag.error()));
                }
                if (tag->field == 3) {
                    if (auto counted = count_collection(reader); !counted) {
                        return std::unexpected(std::move(counted.error()));
                    }
                    if (result.identity.size() >= reader.limits->maximum_identity_fields) {
                        return std::unexpected(codec_error(ProtocolErrorCode::limit_exceeded,
                                                           "subject identity field count exceeds the limit",
                                                           reader.offset));
                    }
                    auto nested = child_reader(reader, *tag, reader.limits->maximum_subject_depth);
                    if (!nested) {
                        return std::unexpected(std::move(nested.error()));
                    }
                    auto identity = decode_identity(*nested);
                    if (!identity) {
                        return std::unexpected(std::move(identity.error()));
                    }
                    result.identity.push_back(std::move(*identity));
                    continue;
                }
                if (tag->field == 4) {
                    if (auto marked = seen.mark(tag->field, reader.offset); !marked) {
                        return std::unexpected(std::move(marked.error()));
                    }
                    auto nested = child_reader(reader, *tag, reader.limits->maximum_subject_depth);
                    if (!nested) {
                        return std::unexpected(std::move(nested.error()));
                    }
                    auto parent = decode_subject(*nested);
                    if (!parent) {
                        return std::unexpected(std::move(parent.error()));
                    }
                    result.parent = std::make_shared<const SubjectKey>(std::move(*parent));
                    continue;
                }
                if (tag->field == 1 || tag->field == 2) {
                    if (auto marked = seen.mark(tag->field, reader.offset); !marked) {
                        return std::unexpected(std::move(marked.error()));
                    }
                    auto text = read_string(reader, *tag);
                    if (!text) {
                        return std::unexpected(std::move(text.error()));
                    }
                    if (tag->field == 1) {
                        result.peer = PeerId {std::move(*text)};
                    } else {
                        result.descriptor = SchemaId {std::move(*text)};
                    }
                    continue;
                }
                if (auto skipped = reader.skip(*tag); !skipped) {
                    return std::unexpected(std::move(skipped.error()));
                }
            }
            if (!result.valid()) {
                return std::unexpected(codec_error(ProtocolErrorCode::invalid_identity,
                                                   "decoded subject identity is invalid", reader.offset));
            }
            return result;
        }

        struct EncodeBudget {
            std::size_t value_nodes {};
            std::size_t collection_items {};
            std::vector<const FactNode *> active_nodes;
        };

        [[nodiscard]] std::expected<void, ProtocolError> encode_fact_value(Writer &writer, const FactValue &value,
                                                                           const ProtocolLimits &limits,
                                                                           EncodeBudget &budget,
                                                                           const std::size_t depth = 0) {
            if (!value.valid()) {
                return std::unexpected(codec_error(ProtocolErrorCode::invalid_value, "fact value handle is empty"));
            }
            if (depth > limits.maximum_value_depth || budget.value_nodes >= limits.maximum_total_value_nodes) {
                return std::unexpected(
                    codec_error(ProtocolErrorCode::limit_exceeded, "fact value depth or node count exceeds the limit"));
            }
            if (std::ranges::find(budget.active_nodes, value.node.get()) != budget.active_nodes.end()) {
                return std::unexpected(codec_error(ProtocolErrorCode::invalid_value, "fact value contains a cycle"));
            }
            ++budget.value_nodes;
            budget.active_nodes.push_back(value.node.get());
            const auto pop = [&budget]() { budget.active_nodes.pop_back(); };

            const auto &data = value.node->data;
            writer.unsigned_field(1, data.index());
            auto result = std::visit(
                [&](const auto &item) -> std::expected<void, ProtocolError> {
                    using Item = std::remove_cvref_t<decltype(item)>;
                    if constexpr (std::is_same_v<Item, std::monostate>) {
                        return {};
                    } else if constexpr (std::is_same_v<Item, bool>) {
                        writer.boolean_field(2, item);
                        return {};
                    } else if constexpr (std::is_same_v<Item, IntegerValue>) {
                        if (!canonical_integer(item.decimal) || item.decimal.size() > limits.maximum_string_bytes) {
                            return std::unexpected(codec_error(ProtocolErrorCode::invalid_value,
                                                               "integer spelling is not canonical or is too large"));
                        }
                        writer.string_field(3, item.decimal);
                        return {};
                    } else if constexpr (std::is_same_v<Item, double>) {
                        writer.fixed64_field(4, std::bit_cast<std::uint64_t>(item));
                        return {};
                    } else if constexpr (std::is_same_v<Item, UnicodeValue>) {
                        if (!valid_utf8(item.utf8) || item.utf8.size() > limits.maximum_string_bytes) {
                            return std::unexpected(codec_error(ProtocolErrorCode::invalid_utf8,
                                                               "fact string is invalid UTF-8 or too large"));
                        }
                        writer.string_field(5, item.utf8);
                        return {};
                    } else if constexpr (std::is_same_v<Item, BytesValue>) {
                        if (item.bytes.size() > limits.maximum_blob_bytes) {
                            return std::unexpected(
                                codec_error(ProtocolErrorCode::limit_exceeded, "fact bytes exceed the limit"));
                        }
                        writer.raw_length_field(6, item.bytes);
                        return {};
                    } else if constexpr (std::is_same_v<Item, EnumValue>) {
                        if (item.schema.empty() || item.member.empty() || !valid_utf8(item.member)) {
                            return std::unexpected(
                                codec_error(ProtocolErrorCode::invalid_value, "enum identity is incomplete"));
                        }
                        Writer nested;
                        nested.string_field(1, item.schema.value);
                        nested.string_field(2, item.member);
                        writer.message_field(7, nested);
                        return {};
                    } else if constexpr (std::is_same_v<Item, FactList>) {
                        if (item.items.size() > limits.maximum_collection_items - budget.collection_items) {
                            return std::unexpected(
                                codec_error(ProtocolErrorCode::limit_exceeded, "fact list count exceeds the limit"));
                        }
                        budget.collection_items += item.items.size();
                        for (const auto &child : item.items) {
                            Writer nested;
                            if (auto encoded = encode_fact_value(nested, child, limits, budget, depth + 1); !encoded) {
                                return encoded;
                            }
                            writer.message_field(8, nested);
                        }
                        return {};
                    } else if constexpr (std::is_same_v<Item, FactMap>) {
                        if (item.entries.size() > limits.maximum_collection_items - budget.collection_items) {
                            return std::unexpected(
                                codec_error(ProtocolErrorCode::limit_exceeded, "fact map count exceeds the limit"));
                        }
                        budget.collection_items += item.entries.size();
                        for (const auto &entry : item.entries) {
                            Writer nested;
                            Writer key;
                            if (auto encoded = encode_fact_value(key, entry.key, limits, budget, depth + 1); !encoded) {
                                return encoded;
                            }
                            nested.message_field(1, key);
                            Writer mapped;
                            if (auto encoded = encode_fact_value(mapped, entry.value, limits, budget, depth + 1);
                                !encoded) {
                                return encoded;
                            }
                            nested.message_field(2, mapped);
                            writer.message_field(9, nested);
                        }
                        return {};
                    } else {
                        if (item.schema.empty() ||
                            item.fields.size() > limits.maximum_collection_items - budget.collection_items) {
                            return std::unexpected(codec_error(ProtocolErrorCode::limit_exceeded,
                                                               "fact record schema or field count is invalid"));
                        }
                        budget.collection_items += item.fields.size();
                        writer.string_field(10, item.schema.value);
                        std::uint32_t previous {};
                        for (const auto &field : item.fields) {
                            if (field.field_id == 0 || field.field_id <= previous) {
                                return std::unexpected(codec_error(ProtocolErrorCode::invalid_value,
                                                                   "fact record fields are not canonical"));
                            }
                            previous = field.field_id;
                            Writer nested;
                            nested.unsigned_field(1, field.field_id);
                            Writer field_value;
                            if (auto encoded = encode_fact_value(field_value, field.value, limits, budget, depth + 1);
                                !encoded) {
                                return encoded;
                            }
                            nested.message_field(2, field_value);
                            writer.message_field(11, nested);
                        }
                        return {};
                    }
                },
                data);
            pop();
            return result;
        }

        [[nodiscard]] std::expected<EnumValue, ProtocolError> decode_enum(Reader &reader) {
            EnumValue result;
            SeenFields seen;
            while (!reader.eof()) {
                auto tag = reader.next_tag();
                if (!tag) {
                    return std::unexpected(std::move(tag.error()));
                }
                if (tag->field != 1 && tag->field != 2) {
                    if (auto skipped = reader.skip(*tag); !skipped) {
                        return std::unexpected(std::move(skipped.error()));
                    }
                    continue;
                }
                if (auto marked = seen.mark(tag->field, reader.offset); !marked) {
                    return std::unexpected(std::move(marked.error()));
                }
                auto text = read_string(reader, *tag);
                if (!text) {
                    return std::unexpected(std::move(text.error()));
                }
                if (tag->field == 1) {
                    result.schema = SchemaId {std::move(*text)};
                } else {
                    result.member = std::move(*text);
                }
            }
            if (result.schema.empty() || result.member.empty()) {
                return std::unexpected(codec_error(ProtocolErrorCode::invalid_value, "enum value is incomplete"));
            }
            return result;
        }

        [[nodiscard]] std::expected<FactValue, ProtocolError> decode_fact_value(Reader &reader) {
            if (reader.depth > reader.limits->maximum_value_depth ||
                reader.budget->value_nodes >= reader.limits->maximum_total_value_nodes) {
                return std::unexpected(codec_error(ProtocolErrorCode::limit_exceeded,
                                                   "fact value depth or node count exceeds the limit", reader.offset));
            }
            ++reader.budget->value_nodes;
            SeenFields seen;
            std::optional<std::uint64_t> kind;
            FactData data;
            bool payload_seen {};
            std::vector<FactValue> list_items;
            std::vector<FactMapEntry> map_entries;
            SchemaId record_schema;
            std::vector<FactRecordField> record_fields;

            while (!reader.eof()) {
                auto tag = reader.next_tag();
                if (!tag) {
                    return std::unexpected(std::move(tag.error()));
                }
                if (tag->field == 8 || tag->field == 9 || tag->field == 11) {
                    if (auto counted = count_collection(reader); !counted) {
                        return std::unexpected(std::move(counted.error()));
                    }
                    auto nested = child_reader(reader, *tag, reader.limits->maximum_value_depth);
                    if (!nested) {
                        return std::unexpected(std::move(nested.error()));
                    }
                    if (tag->field == 8) {
                        auto child = decode_fact_value(*nested);
                        if (!child) {
                            return std::unexpected(std::move(child.error()));
                        }
                        list_items.push_back(std::move(*child));
                        continue;
                    }
                    if (tag->field == 9) {
                        SeenFields entry_seen;
                        std::optional<FactValue> key;
                        std::optional<FactValue> value;
                        while (!nested->eof()) {
                            auto entry_tag = nested->next_tag();
                            if (!entry_tag) {
                                return std::unexpected(std::move(entry_tag.error()));
                            }
                            if (entry_tag->field != 1 && entry_tag->field != 2) {
                                if (auto skipped = nested->skip(*entry_tag); !skipped) {
                                    return std::unexpected(std::move(skipped.error()));
                                }
                                continue;
                            }
                            if (auto marked = entry_seen.mark(entry_tag->field, nested->offset); !marked) {
                                return std::unexpected(std::move(marked.error()));
                            }
                            auto value_reader = child_reader(*nested, *entry_tag, reader.limits->maximum_value_depth);
                            if (!value_reader) {
                                return std::unexpected(std::move(value_reader.error()));
                            }
                            auto decoded = decode_fact_value(*value_reader);
                            if (!decoded) {
                                return std::unexpected(std::move(decoded.error()));
                            }
                            if (entry_tag->field == 1) {
                                key = std::move(*decoded);
                            } else {
                                value = std::move(*decoded);
                            }
                        }
                        if (!key.has_value() || !value.has_value()) {
                            return std::unexpected(codec_error(ProtocolErrorCode::invalid_value,
                                                               "fact map entry is incomplete", reader.offset));
                        }
                        map_entries.push_back(FactMapEntry {.key = std::move(*key), .value = std::move(*value)});
                        continue;
                    }

                    SeenFields field_seen;
                    std::uint32_t field_id {};
                    std::optional<FactValue> field_value;
                    while (!nested->eof()) {
                        auto field_tag = nested->next_tag();
                        if (!field_tag) {
                            return std::unexpected(std::move(field_tag.error()));
                        }
                        if (field_tag->field != 1 && field_tag->field != 2) {
                            if (auto skipped = nested->skip(*field_tag); !skipped) {
                                return std::unexpected(std::move(skipped.error()));
                            }
                            continue;
                        }
                        if (auto marked = field_seen.mark(field_tag->field, nested->offset); !marked) {
                            return std::unexpected(std::move(marked.error()));
                        }
                        if (field_tag->field == 1) {
                            auto number = nested->read_unsigned(*field_tag);
                            if (!number || *number == 0 || *number > std::numeric_limits<std::uint32_t>::max()) {
                                return std::unexpected(number ?
                                                           codec_error(ProtocolErrorCode::invalid_value,
                                                                       "record field ID is invalid", nested->offset) :
                                                           std::move(number.error()));
                            }
                            field_id = static_cast<std::uint32_t>(*number);
                            continue;
                        }
                        auto value_reader = child_reader(*nested, *field_tag, reader.limits->maximum_value_depth);
                        if (!value_reader) {
                            return std::unexpected(std::move(value_reader.error()));
                        }
                        auto decoded = decode_fact_value(*value_reader);
                        if (!decoded) {
                            return std::unexpected(std::move(decoded.error()));
                        }
                        field_value = std::move(*decoded);
                    }
                    if (field_id == 0 || !field_value.has_value() ||
                        (!record_fields.empty() && field_id <= record_fields.back().field_id)) {
                        return std::unexpected(codec_error(ProtocolErrorCode::invalid_value,
                                                           "record fields are incomplete or non-canonical",
                                                           reader.offset));
                    }
                    record_fields.push_back(FactRecordField {.field_id = field_id, .value = std::move(*field_value)});
                    continue;
                }

                if (tag->field > 11) {
                    if (auto skipped = reader.skip(*tag); !skipped) {
                        return std::unexpected(std::move(skipped.error()));
                    }
                    continue;
                }
                if (auto marked = seen.mark(tag->field, reader.offset); !marked) {
                    return std::unexpected(std::move(marked.error()));
                }
                switch (tag->field) {
                    case 1: {
                        auto number = reader.read_unsigned(*tag);
                        if (!number || *number > 9) {
                            return std::unexpected(number ? codec_error(ProtocolErrorCode::invalid_value,
                                                                        "fact value kind is invalid", reader.offset) :
                                                            std::move(number.error()));
                        }
                        kind = *number;
                        break;
                    }
                    case 2: {
                        auto boolean = reader.read_boolean(*tag);
                        if (!boolean) {
                            return std::unexpected(std::move(boolean.error()));
                        }
                        data = *boolean;
                        payload_seen = true;
                        break;
                    }
                    case 3: {
                        auto integer = read_string(reader, *tag);
                        if (!integer) {
                            return std::unexpected(std::move(integer.error()));
                        }
                        if (!canonical_integer(*integer)) {
                            return std::unexpected(codec_error(ProtocolErrorCode::invalid_value,
                                                               "integer spelling is not canonical", reader.offset));
                        }
                        data = IntegerValue {std::move(*integer)};
                        payload_seen = true;
                        break;
                    }
                    case 4: {
                        auto bits = reader.read_fixed64(*tag);
                        if (!bits) {
                            return std::unexpected(std::move(bits.error()));
                        }
                        data = std::bit_cast<double>(*bits);
                        payload_seen = true;
                        break;
                    }
                    case 5: {
                        auto text = read_string(reader, *tag);
                        if (!text) {
                            return std::unexpected(std::move(text.error()));
                        }
                        data = UnicodeValue {std::move(*text)};
                        payload_seen = true;
                        break;
                    }
                    case 6: {
                        auto bytes = reader.read_bytes(*tag, reader.limits->maximum_blob_bytes);
                        if (!bytes) {
                            return std::unexpected(std::move(bytes.error()));
                        }
                        data = BytesValue {std::vector<std::byte>(bytes->begin(), bytes->end())};
                        payload_seen = true;
                        break;
                    }
                    case 7: {
                        auto nested = child_reader(reader, *tag, reader.limits->maximum_value_depth);
                        if (!nested) {
                            return std::unexpected(std::move(nested.error()));
                        }
                        auto value = decode_enum(*nested);
                        if (!value) {
                            return std::unexpected(std::move(value.error()));
                        }
                        data = std::move(*value);
                        payload_seen = true;
                        break;
                    }
                    case 10: {
                        auto schema = read_string(reader, *tag);
                        if (!schema) {
                            return std::unexpected(std::move(schema.error()));
                        }
                        record_schema = SchemaId {std::move(*schema)};
                        break;
                    }
                    default:
                        return std::unexpected(codec_error(ProtocolErrorCode::invalid_value,
                                                           "unexpected non-repeated fact value field", reader.offset));
                }
            }

            if (!kind.has_value()) {
                return std::unexpected(codec_error(ProtocolErrorCode::invalid_value, "fact value kind is absent"));
            }
            if (*kind == 0) {
                if (payload_seen || !list_items.empty() || !map_entries.empty() || !record_schema.empty() ||
                    !record_fields.empty()) {
                    return std::unexpected(codec_error(ProtocolErrorCode::invalid_value,
                                                       "null fact value contains a payload", reader.offset));
                }
                return make_fact(std::monostate {});
            }
            if (*kind == 7) {
                if (payload_seen || !map_entries.empty() || !record_schema.empty() || !record_fields.empty()) {
                    return std::unexpected(codec_error(ProtocolErrorCode::invalid_value,
                                                       "fact list has conflicting payload fields", reader.offset));
                }
                return make_fact(FactList {.items = std::move(list_items)});
            }
            if (*kind == 8) {
                if (payload_seen || !list_items.empty() || !record_schema.empty() || !record_fields.empty()) {
                    return std::unexpected(codec_error(ProtocolErrorCode::invalid_value,
                                                       "fact map has conflicting payload fields", reader.offset));
                }
                return make_fact(FactMap {.entries = std::move(map_entries)});
            }
            if (*kind == 9) {
                if (payload_seen || !list_items.empty() || !map_entries.empty() || record_schema.empty()) {
                    return std::unexpected(codec_error(ProtocolErrorCode::invalid_value,
                                                       "fact record has conflicting or missing fields", reader.offset));
                }
                return make_fact(FactRecord {.schema = std::move(record_schema), .fields = std::move(record_fields)});
            }
            if (!payload_seen || data.index() != *kind || !list_items.empty() || !map_entries.empty() ||
                !record_schema.empty() || !record_fields.empty()) {
                return std::unexpected(codec_error(ProtocolErrorCode::invalid_value,
                                                   "fact value kind and payload do not agree", reader.offset));
            }
            return make_fact(std::move(data));
        }

        [[nodiscard]] std::expected<void, ProtocolError> validate_provider_diagnostic(const Diagnostic &diagnostic) {
            if (diagnostic.code.empty() || diagnostic.message.empty() || !valid_utf8(diagnostic.code) ||
                !valid_utf8(diagnostic.message) || diagnostic.span.has_value() || !diagnostic.related.empty()) {
                return std::unexpected(codec_error(ProtocolErrorCode::invalid_value,
                                                   "provider diagnostic must be bounded and source-free"));
            }
            return {};
        }

        void encode_diagnostic(Writer &writer, const Diagnostic &diagnostic) {
            writer.string_field(1, diagnostic.code);
            writer.unsigned_field(2, static_cast<std::uint8_t>(diagnostic.severity));
            writer.string_field(3, diagnostic.message);
        }

        [[nodiscard]] std::expected<Diagnostic, ProtocolError> decode_diagnostic(Reader &reader) {
            Diagnostic result;
            SeenFields seen;
            while (!reader.eof()) {
                auto tag = reader.next_tag();
                if (!tag) {
                    return std::unexpected(std::move(tag.error()));
                }
                if (tag->field > 3) {
                    if (auto skipped = reader.skip(*tag); !skipped) {
                        return std::unexpected(std::move(skipped.error()));
                    }
                    continue;
                }
                if (auto marked = seen.mark(tag->field, reader.offset); !marked) {
                    return std::unexpected(std::move(marked.error()));
                }
                if (tag->field == 2) {
                    auto severity = reader.read_unsigned(*tag);
                    if (!severity || *severity > static_cast<std::uint8_t>(DiagnosticSeverity::error)) {
                        return std::unexpected(severity ? codec_error(ProtocolErrorCode::invalid_value,
                                                                      "provider diagnostic severity is invalid",
                                                                      reader.offset) :
                                                          std::move(severity.error()));
                    }
                    result.severity = static_cast<DiagnosticSeverity>(*severity);
                    continue;
                }
                auto text = read_string(reader, *tag);
                if (!text) {
                    return std::unexpected(std::move(text.error()));
                }
                if (tag->field == 1) {
                    result.code = std::move(*text);
                } else {
                    result.message = std::move(*text);
                }
            }
            if (auto valid = validate_provider_diagnostic(result); !valid) {
                return std::unexpected(std::move(valid.error()));
            }
            return result;
        }

        [[nodiscard]] bool terminal_status_valid(const FactTerminalStatus status) noexcept {
            return status >= FactTerminalStatus::value && status <= FactTerminalStatus::canceled;
        }

        [[nodiscard]] std::expected<void, ProtocolError> validate_label(const DataLabel &label,
                                                                        const ProtocolLimits &limits) {
            if (label.classification > Classification::secret ||
                label.categories.size() > limits.maximum_label_categories ||
                !std::ranges::is_sorted(label.categories)) {
                return std::unexpected(
                    codec_error(ProtocolErrorCode::invalid_value, "scan data label is not canonical"));
            }
            std::string_view previous;
            for (const auto &category : label.categories) {
                if (category.empty() || category.size() > limits.maximum_string_bytes || !valid_utf8(category) ||
                    (!previous.empty() && previous == category)) {
                    return std::unexpected(
                        codec_error(ProtocolErrorCode::invalid_value, "scan data label category is invalid"));
                }
                previous = category;
            }
            return {};
        }

        void encode_label(Writer &writer, const DataLabel &label) {
            writer.unsigned_field(1, static_cast<std::uint8_t>(label.classification));
            for (const auto &category : label.categories) { writer.string_field(2, category); }
        }

        [[nodiscard]] std::expected<DataLabel, ProtocolError> decode_label(Reader &reader) {
            DataLabel result;
            bool classification_seen {};
            while (!reader.eof()) {
                auto tag = reader.next_tag();
                if (!tag) {
                    return std::unexpected(std::move(tag.error()));
                }
                if (tag->field > 2) {
                    if (auto skipped = reader.skip(*tag); !skipped) {
                        return std::unexpected(std::move(skipped.error()));
                    }
                    continue;
                }
                if (tag->field == 1) {
                    if (classification_seen) {
                        return std::unexpected(codec_error(ProtocolErrorCode::duplicate_field,
                                                           "duplicate scan label classification", reader.offset));
                    }
                    auto classification = reader.read_unsigned(*tag);
                    if (!classification || *classification > static_cast<std::uint8_t>(Classification::secret)) {
                        return std::unexpected(classification ?
                                                   codec_error(ProtocolErrorCode::invalid_value,
                                                               "scan label classification is invalid", reader.offset) :
                                                   std::move(classification.error()));
                    }
                    classification_seen = true;
                    result.classification = static_cast<Classification>(*classification);
                    continue;
                }
                if (auto counted = count_collection(reader); !counted) {
                    return std::unexpected(std::move(counted.error()));
                }
                if (result.categories.size() >= reader.limits->maximum_label_categories) {
                    return std::unexpected(codec_error(ProtocolErrorCode::limit_exceeded,
                                                       "scan label category count exceeds the limit", reader.offset));
                }
                auto category = read_string(reader, *tag);
                if (!category) {
                    return std::unexpected(std::move(category.error()));
                }
                result.categories.push_back(std::move(*category));
            }
            if (!classification_seen) {
                return std::unexpected(
                    codec_error(ProtocolErrorCode::invalid_value, "scan label classification is missing"));
            }
            if (auto valid = validate_label(result, *reader.limits); !valid) {
                return std::unexpected(std::move(valid.error()));
            }
            return result;
        }

        [[nodiscard]] std::expected<void, ProtocolError> encode_fact_request(Writer &writer, const FactRequest &request,
                                                                             const ProtocolLimits &limits) {
            if (request.request_id.empty() || !request.subject.valid() || request.route.provider.empty() ||
                request.route.fact.empty() || request.expected_schema.empty() || request.expected_schema_hash.empty() ||
                request.expected_schema_hash.size() > limits.maximum_string_bytes ||
                !valid_utf8(request.expected_schema_hash) || request.deadline_unix_ms == 0) {
                return std::unexpected(
                    codec_error(ProtocolErrorCode::malformed, "fact request identity is incomplete"));
            }
            writer.string_field(1, request.request_id.value);
            Writer subject;
            encode_subject(subject, request.subject);
            writer.message_field(2, subject);
            writer.string_field(3, request.route.provider);
            writer.string_field(4, request.route.fact);
            writer.string_field(5, request.expected_schema.value);
            writer.unsigned_field(6, request.deadline_unix_ms);
            writer.string_field(7, request.expected_schema_hash);
            return {};
        }

        [[nodiscard]] std::expected<FactRequest, ProtocolError> decode_fact_request(Reader &reader) {
            FactRequest result;
            SeenFields seen;
            while (!reader.eof()) {
                auto tag = reader.next_tag();
                if (!tag) {
                    return std::unexpected(std::move(tag.error()));
                }
                if (tag->field > 7) {
                    if (auto skipped = reader.skip(*tag); !skipped) {
                        return std::unexpected(std::move(skipped.error()));
                    }
                    continue;
                }
                if (auto marked = seen.mark(tag->field, reader.offset); !marked) {
                    return std::unexpected(std::move(marked.error()));
                }
                if (tag->field == 2) {
                    auto nested = child_reader(reader, *tag, reader.limits->maximum_subject_depth);
                    if (!nested) {
                        return std::unexpected(std::move(nested.error()));
                    }
                    auto subject = decode_subject(*nested);
                    if (!subject) {
                        return std::unexpected(std::move(subject.error()));
                    }
                    result.subject = std::move(*subject);
                    continue;
                }
                if (tag->field == 6) {
                    auto deadline = reader.read_unsigned(*tag);
                    if (!deadline) {
                        return std::unexpected(std::move(deadline.error()));
                    }
                    result.deadline_unix_ms = *deadline;
                    continue;
                }
                auto text = read_string(reader, *tag);
                if (!text) {
                    return std::unexpected(std::move(text.error()));
                }
                switch (tag->field) {
                    case 1: result.request_id = RequestId {std::move(*text)}; break;
                    case 3: result.route.provider = std::move(*text); break;
                    case 4: result.route.fact = std::move(*text); break;
                    case 5: result.expected_schema = SchemaId {std::move(*text)}; break;
                    case 7: result.expected_schema_hash = std::move(*text); break;
                    default: break;
                }
            }
            if (result.request_id.empty() || !result.subject.valid() || result.route.provider.empty() ||
                result.route.fact.empty() || result.expected_schema.empty() || result.expected_schema_hash.empty() ||
                result.deadline_unix_ms == 0) {
                return std::unexpected(
                    codec_error(ProtocolErrorCode::malformed, "decoded fact request is incomplete", reader.offset));
            }
            return result;
        }

        [[nodiscard]] std::expected<void, ProtocolError> encode_scan_request(Writer &writer, const ScanRequest &request,
                                                                             const ProtocolLimits &limits) {
            if (request.request_id.empty() || !request.subject.valid() || request.space.kind.empty() ||
                request.space.identity.empty() || request.space.subject_generation == 0 ||
                request.space.size > std::numeric_limits<std::uint64_t>::max() - request.space.begin ||
                request.plan.plan_id.empty() || request.plan.encoded_pattern.empty() ||
                request.plan.encoded_pattern.size() > limits.maximum_string_bytes || request.plan.maximum_bytes == 0 ||
                request.plan.maximum_bytes > limits.maximum_blob_bytes || request.plan.maximum_matches == 0 ||
                request.plan.maximum_matches > limits.maximum_scan_matches ||
                request.plan.context_bytes_before > limits.maximum_blob_bytes ||
                request.plan.context_bytes_after > limits.maximum_blob_bytes ||
                (request.plan.result_mode != ScanResultMode::exact_complete &&
                 request.plan.result_mode != ScanResultMode::existential) ||
                request.deadline_unix_ms == 0) {
                return std::unexpected(
                    codec_error(ProtocolErrorCode::malformed, "scan request identity or bounds are invalid"));
            }
            if (auto valid = validate_label(request.space.label, limits); !valid) {
                return valid;
            }
            if (auto valid = validate_scan_pattern_ids(request.plan.pattern_ids, limits); !valid) {
                return valid;
            }
            writer.string_field(1, request.request_id.value);
            Writer subject;
            encode_subject(subject, request.subject);
            writer.message_field(2, subject);
            writer.string_field(3, request.space.kind);
            writer.unsigned_field(4, request.space.begin);
            writer.unsigned_field(5, request.space.size);
            writer.unsigned_field(6, request.space.permissions);
            writer.string_field(7, request.plan.plan_id);
            writer.string_field(8, request.plan.encoded_pattern);
            writer.unsigned_field(9, request.plan.maximum_bytes);
            writer.unsigned_field(10, request.plan.maximum_matches);
            writer.unsigned_field(11, request.deadline_unix_ms);
            writer.string_field(12, request.space.identity);
            writer.unsigned_field(13, request.space.subject_generation);
            Writer label;
            encode_label(label, request.space.label);
            writer.message_field(14, label);
            writer.unsigned_field(15, request.plan.context_bytes_before);
            writer.unsigned_field(16, request.plan.context_bytes_after);
            writer.unsigned_field(17, static_cast<std::uint8_t>(request.plan.result_mode));
            for (const auto &pattern_id : request.plan.pattern_ids) { writer.string_field(18, pattern_id); }
            return {};
        }

        [[nodiscard]] std::expected<ScanRequest, ProtocolError> decode_scan_request(Reader &reader) {
            ScanRequest result;
            SeenFields seen;
            bool label_seen {};
            bool mode_seen {};
            while (!reader.eof()) {
                auto tag = reader.next_tag();
                if (!tag) {
                    return std::unexpected(std::move(tag.error()));
                }
                if (tag->field == 18) {
                    if (auto counted = count_collection(reader); !counted) {
                        return std::unexpected(std::move(counted.error()));
                    }
                    if (result.plan.pattern_ids.size() >= reader.limits->maximum_scan_patterns) {
                        return std::unexpected(codec_error(ProtocolErrorCode::limit_exceeded,
                                                           "scan pattern ID count exceeds the limit", reader.offset));
                    }
                    auto pattern_id = read_string(reader, *tag);
                    if (!pattern_id) {
                        return std::unexpected(std::move(pattern_id.error()));
                    }
                    result.plan.pattern_ids.push_back(std::move(*pattern_id));
                    continue;
                }
                if (tag->field > 18) {
                    if (auto skipped = reader.skip(*tag); !skipped) {
                        return std::unexpected(std::move(skipped.error()));
                    }
                    continue;
                }
                if (auto marked = seen.mark(tag->field, reader.offset); !marked) {
                    return std::unexpected(std::move(marked.error()));
                }
                if (tag->field == 2 || tag->field == 14) {
                    auto nested = child_reader(reader, *tag,
                                               tag->field == 2 ? reader.limits->maximum_subject_depth :
                                                                 reader.limits->maximum_value_depth);
                    if (!nested) {
                        return std::unexpected(std::move(nested.error()));
                    }
                    if (tag->field == 2) {
                        auto subject = decode_subject(*nested);
                        if (!subject) {
                            return std::unexpected(std::move(subject.error()));
                        }
                        result.subject = std::move(*subject);
                    } else {
                        auto label = decode_label(*nested);
                        if (!label) {
                            return std::unexpected(std::move(label.error()));
                        }
                        result.space.label = std::move(*label);
                        label_seen = true;
                    }
                    continue;
                }
                if (tag->field == 1 || tag->field == 3 || tag->field == 7 || tag->field == 8 || tag->field == 12) {
                    auto text = read_string(reader, *tag);
                    if (!text) {
                        return std::unexpected(std::move(text.error()));
                    }
                    if (tag->field == 1) {
                        result.request_id = RequestId {std::move(*text)};
                    } else if (tag->field == 3) {
                        result.space.kind = std::move(*text);
                    } else if (tag->field == 7) {
                        result.plan.plan_id = std::move(*text);
                    } else if (tag->field == 8) {
                        result.plan.encoded_pattern = std::move(*text);
                    } else {
                        result.space.identity = std::move(*text);
                    }
                    continue;
                }
                auto number = reader.read_unsigned(*tag);
                if (!number) {
                    return std::unexpected(std::move(number.error()));
                }
                switch (tag->field) {
                    case 4: result.space.begin = *number; break;
                    case 5: result.space.size = *number; break;
                    case 6:
                        if (*number > std::numeric_limits<std::uint32_t>::max()) {
                            return std::unexpected(codec_error(ProtocolErrorCode::limit_exceeded,
                                                               "scan permissions exceed uint32", reader.offset));
                        }
                        result.space.permissions = static_cast<std::uint32_t>(*number);
                        break;
                    case 9: result.plan.maximum_bytes = *number; break;
                    case 10:
                        if (*number > std::numeric_limits<std::uint32_t>::max()) {
                            return std::unexpected(codec_error(ProtocolErrorCode::limit_exceeded,
                                                               "scan match bound exceeds uint32", reader.offset));
                        }
                        result.plan.maximum_matches = static_cast<std::uint32_t>(*number);
                        break;
                    case 11: result.deadline_unix_ms = *number; break;
                    case 13: result.space.subject_generation = *number; break;
                    case 15:
                    case 16:
                        if (*number > std::numeric_limits<std::uint32_t>::max()) {
                            return std::unexpected(codec_error(ProtocolErrorCode::limit_exceeded,
                                                               "scan context bound exceeds uint32", reader.offset));
                        }
                        if (tag->field == 15) {
                            result.plan.context_bytes_before = static_cast<std::uint32_t>(*number);
                        } else {
                            result.plan.context_bytes_after = static_cast<std::uint32_t>(*number);
                        }
                        break;
                    case 17:
                        if (*number < static_cast<std::uint8_t>(ScanResultMode::exact_complete) ||
                            *number > static_cast<std::uint8_t>(ScanResultMode::existential)) {
                            return std::unexpected(codec_error(ProtocolErrorCode::invalid_value,
                                                               "scan result mode is invalid", reader.offset));
                        }
                        result.plan.result_mode = static_cast<ScanResultMode>(*number);
                        mode_seen = true;
                        break;
                    default: break;
                }
            }
            if (!label_seen || !mode_seen || result.request_id.empty() || !result.subject.valid() ||
                result.space.kind.empty() || result.space.identity.empty() || result.space.subject_generation == 0 ||
                result.space.size > std::numeric_limits<std::uint64_t>::max() - result.space.begin ||
                result.plan.plan_id.empty() || result.plan.encoded_pattern.empty() || result.plan.maximum_bytes == 0 ||
                result.plan.maximum_bytes > reader.limits->maximum_blob_bytes || result.plan.maximum_matches == 0 ||
                result.plan.maximum_matches > reader.limits->maximum_scan_matches ||
                result.plan.context_bytes_before > reader.limits->maximum_blob_bytes ||
                result.plan.context_bytes_after > reader.limits->maximum_blob_bytes || result.deadline_unix_ms == 0) {
                return std::unexpected(
                    codec_error(ProtocolErrorCode::malformed, "decoded scan request is invalid", reader.offset));
            }
            if (auto valid = validate_scan_pattern_ids(result.plan.pattern_ids, *reader.limits); !valid) {
                return std::unexpected(std::move(valid.error()));
            }
            return result;
        }

        [[nodiscard]] std::expected<void, ProtocolError>
        encode_fact_response(Writer &writer, const FactResponse &response, const ProtocolLimits &limits) {
            if (response.request_id.empty() || !response.subject.valid() || !terminal_status_valid(response.status) ||
                !valid_fact_response_shape(response) ||
                (response.returned_schema.has_value() &&
                 (response.returned_schema->id.value.size() > limits.maximum_string_bytes ||
                  response.returned_schema->canonical_hash.size() > limits.maximum_string_bytes ||
                  !valid_utf8(response.returned_schema->id.value) ||
                  !valid_utf8(response.returned_schema->canonical_hash)))) {
                return std::unexpected(
                    codec_error(ProtocolErrorCode::invalid_value, "fact response terminal shape is invalid"));
            }
            writer.string_field(1, response.request_id.value);
            Writer subject;
            encode_subject(subject, response.subject);
            writer.message_field(2, subject);
            writer.unsigned_field(3, static_cast<std::uint8_t>(response.status));
            if (response.value.has_value()) {
                Writer value;
                EncodeBudget budget;
                if (auto encoded = encode_fact_value(value, *response.value, limits, budget); !encoded) {
                    return encoded;
                }
                writer.message_field(4, value);
            }
            if (response.diagnostic.has_value()) {
                if (auto valid = validate_provider_diagnostic(*response.diagnostic); !valid) {
                    return valid;
                }
                Writer diagnostic;
                encode_diagnostic(diagnostic, *response.diagnostic);
                writer.message_field(5, diagnostic);
            }
            if (response.returned_schema.has_value()) {
                Writer schema;
                encode_schema_identity(schema, *response.returned_schema);
                writer.message_field(6, schema);
            }
            return {};
        }

        [[nodiscard]] std::expected<FactResponse, ProtocolError> decode_fact_response(Reader &reader) {
            FactResponse result;
            SeenFields seen;
            bool status_seen {};
            while (!reader.eof()) {
                auto tag = reader.next_tag();
                if (!tag) {
                    return std::unexpected(std::move(tag.error()));
                }
                if (tag->field > 6) {
                    if (auto skipped = reader.skip(*tag); !skipped) {
                        return std::unexpected(std::move(skipped.error()));
                    }
                    continue;
                }
                if (auto marked = seen.mark(tag->field, reader.offset); !marked) {
                    return std::unexpected(std::move(marked.error()));
                }
                if (tag->field == 1) {
                    auto id = read_string(reader, *tag);
                    if (!id) {
                        return std::unexpected(std::move(id.error()));
                    }
                    result.request_id = RequestId {std::move(*id)};
                } else if (tag->field == 2) {
                    auto nested = child_reader(reader, *tag, reader.limits->maximum_subject_depth);
                    if (!nested) {
                        return std::unexpected(std::move(nested.error()));
                    }
                    auto subject = decode_subject(*nested);
                    if (!subject) {
                        return std::unexpected(std::move(subject.error()));
                    }
                    result.subject = std::move(*subject);
                } else if (tag->field == 3) {
                    auto status = reader.read_unsigned(*tag);
                    if (!status || *status > static_cast<std::uint8_t>(FactTerminalStatus::canceled)) {
                        return std::unexpected(status ? codec_error(ProtocolErrorCode::invalid_value,
                                                                    "fact status is invalid", reader.offset) :
                                                        std::move(status.error()));
                    }
                    result.status = static_cast<FactTerminalStatus>(*status);
                    status_seen = true;
                } else if (tag->field == 4) {
                    auto nested = child_reader(reader, *tag, reader.limits->maximum_value_depth);
                    if (!nested) {
                        return std::unexpected(std::move(nested.error()));
                    }
                    auto value = decode_fact_value(*nested);
                    if (!value) {
                        return std::unexpected(std::move(value.error()));
                    }
                    result.value = std::move(*value);
                } else if (tag->field == 5) {
                    auto nested = child_reader(reader, *tag, reader.limits->maximum_value_depth);
                    if (!nested) {
                        return std::unexpected(std::move(nested.error()));
                    }
                    auto diagnostic = decode_diagnostic(*nested);
                    if (!diagnostic) {
                        return std::unexpected(std::move(diagnostic.error()));
                    }
                    result.diagnostic = std::move(*diagnostic);
                } else {
                    auto nested = child_reader(reader, *tag, reader.limits->maximum_value_depth);
                    if (!nested) {
                        return std::unexpected(std::move(nested.error()));
                    }
                    auto schema = decode_schema_identity(*nested);
                    if (!schema) {
                        return std::unexpected(std::move(schema.error()));
                    }
                    result.returned_schema = std::move(*schema);
                }
            }
            if (!status_seen || result.request_id.empty() || !result.subject.valid() ||
                !valid_fact_response_shape(result)) {
                return std::unexpected(codec_error(ProtocolErrorCode::invalid_value,
                                                   "decoded fact response is incomplete", reader.offset));
            }
            return result;
        }

        [[nodiscard]] std::expected<void, ProtocolError> validate_scan_match(const ScanMatch &match,
                                                                             const ProtocolLimits &limits) {
            if (match.pattern_id.empty() || match.scan_space_id.empty() ||
                match.pattern_id.size() > limits.maximum_string_bytes ||
                match.scan_space_id.size() > limits.maximum_string_bytes || !valid_utf8(match.pattern_id) ||
                !valid_utf8(match.scan_space_id) || match.subject_generation == 0 ||
                match.matched_bytes.size() != match.length || match.matched_bytes.size() > limits.maximum_blob_bytes ||
                match.before_bytes.size() > limits.maximum_blob_bytes - match.matched_bytes.size() ||
                match.after_bytes.size() >
                    limits.maximum_blob_bytes - match.matched_bytes.size() - match.before_bytes.size()) {
                return std::unexpected(
                    codec_error(ProtocolErrorCode::invalid_value, "scan match metadata or context is invalid"));
            }
            return validate_label(match.label, limits);
        }

        [[nodiscard]] std::expected<void, ProtocolError> encode_scan_match(Writer &writer, const ScanMatch &match,
                                                                           const ProtocolLimits &limits) {
            if (auto valid = validate_scan_match(match, limits); !valid) {
                return valid;
            }
            writer.unsigned_field(1, match.offset);
            writer.unsigned_field(2, match.length);
            writer.string_field(3, match.pattern_id);
            writer.string_field(4, match.scan_space_id);
            writer.unsigned_field(5, match.absolute_address);
            writer.unsigned_field(6, match.permission_snapshot);
            writer.raw_length_field(7, match.matched_bytes);
            writer.raw_length_field(8, match.before_bytes);
            writer.raw_length_field(9, match.after_bytes);
            Writer label;
            encode_label(label, match.label);
            writer.message_field(10, label);
            writer.unsigned_field(11, match.subject_generation);
            return {};
        }

        [[nodiscard]] std::expected<ScanMatch, ProtocolError> decode_scan_match(Reader &reader) {
            ScanMatch result;
            SeenFields seen;
            std::array<bool, 11> required {};
            while (!reader.eof()) {
                auto tag = reader.next_tag();
                if (!tag) {
                    return std::unexpected(std::move(tag.error()));
                }
                if (tag->field > 11) {
                    if (auto skipped = reader.skip(*tag); !skipped) {
                        return std::unexpected(std::move(skipped.error()));
                    }
                    continue;
                }
                if (auto marked = seen.mark(tag->field, reader.offset); !marked) {
                    return std::unexpected(std::move(marked.error()));
                }
                required[tag->field - 1] = true;
                if (tag->field == 3 || tag->field == 4) {
                    auto text = read_string(reader, *tag);
                    if (!text) {
                        return std::unexpected(std::move(text.error()));
                    }
                    if (tag->field == 3) {
                        result.pattern_id = std::move(*text);
                    } else {
                        result.scan_space_id = std::move(*text);
                    }
                    continue;
                }
                if (tag->field >= 7 && tag->field <= 9) {
                    auto bytes = reader.read_bytes(*tag, reader.limits->maximum_blob_bytes);
                    if (!bytes) {
                        return std::unexpected(std::move(bytes.error()));
                    }
                    std::vector<std::byte> value(bytes->begin(), bytes->end());
                    if (tag->field == 7) {
                        result.matched_bytes = std::move(value);
                    } else if (tag->field == 8) {
                        result.before_bytes = std::move(value);
                    } else {
                        result.after_bytes = std::move(value);
                    }
                    continue;
                }
                if (tag->field == 10) {
                    auto nested = child_reader(reader, *tag, reader.limits->maximum_value_depth);
                    if (!nested) {
                        return std::unexpected(std::move(nested.error()));
                    }
                    auto label = decode_label(*nested);
                    if (!label) {
                        return std::unexpected(std::move(label.error()));
                    }
                    result.label = std::move(*label);
                    continue;
                }
                auto number = reader.read_unsigned(*tag);
                if (!number) {
                    return std::unexpected(std::move(number.error()));
                }
                switch (tag->field) {
                    case 1: result.offset = *number; break;
                    case 2: result.length = *number; break;
                    case 5: result.absolute_address = *number; break;
                    case 6:
                        if (*number > std::numeric_limits<std::uint32_t>::max()) {
                            return std::unexpected(codec_error(ProtocolErrorCode::limit_exceeded,
                                                               "scan permission snapshot exceeds uint32",
                                                               reader.offset));
                        }
                        result.permission_snapshot = static_cast<std::uint32_t>(*number);
                        break;
                    case 11: result.subject_generation = *number; break;
                    default: break;
                }
            }
            if (!std::ranges::all_of(required, std::identity {})) {
                return std::unexpected(
                    codec_error(ProtocolErrorCode::invalid_value, "scan match metadata is incomplete", reader.offset));
            }
            if (auto valid = validate_scan_match(result, *reader.limits); !valid) {
                return std::unexpected(std::move(valid.error()));
            }
            return result;
        }

        [[nodiscard]] std::expected<void, ProtocolError>
        encode_scan_response(Writer &writer, const ScanResponse &response, const ProtocolLimits &limits) {
            if (response.request_id.empty() || !response.subject.valid() || !terminal_status_valid(response.status) ||
                response.truncated || response.matches.size() > limits.maximum_scan_matches ||
                (response.mode != ScanResultMode::exact_complete && response.mode != ScanResultMode::existential) ||
                (response.mode == ScanResultMode::existential && response.matches.size() > 1) ||
                (response.status != FactTerminalStatus::value && !response.matches.empty())) {
                return std::unexpected(codec_error(ProtocolErrorCode::invalid_value,
                                                   "scan response is truncated, oversized, or status-invalid"));
            }
            writer.string_field(1, response.request_id.value);
            Writer subject;
            encode_subject(subject, response.subject);
            writer.message_field(2, subject);
            writer.unsigned_field(3, static_cast<std::uint8_t>(response.status));
            for (const auto &match : response.matches) {
                Writer nested;
                if (auto encoded = encode_scan_match(nested, match, limits); !encoded) {
                    return encoded;
                }
                writer.message_field(4, nested);
            }
            writer.boolean_field(5, false);
            if (response.diagnostic.has_value()) {
                if (auto valid = validate_provider_diagnostic(*response.diagnostic); !valid) {
                    return valid;
                }
                Writer diagnostic;
                encode_diagnostic(diagnostic, *response.diagnostic);
                writer.message_field(6, diagnostic);
            }
            writer.unsigned_field(7, static_cast<std::uint8_t>(response.mode));
            return {};
        }

        [[nodiscard]] std::expected<ScanResponse, ProtocolError> decode_scan_response(Reader &reader) {
            ScanResponse result;
            SeenFields seen;
            bool status_seen {};
            bool mode_seen {};
            while (!reader.eof()) {
                auto tag = reader.next_tag();
                if (!tag) {
                    return std::unexpected(std::move(tag.error()));
                }
                if (tag->field == 4) {
                    if (auto counted = count_collection(reader); !counted) {
                        return std::unexpected(std::move(counted.error()));
                    }
                    if (result.matches.size() >= reader.limits->maximum_scan_matches) {
                        return std::unexpected(codec_error(ProtocolErrorCode::limit_exceeded,
                                                           "scan match count exceeds the limit", reader.offset));
                    }
                    auto nested = child_reader(reader, *tag, reader.limits->maximum_value_depth);
                    if (!nested) {
                        return std::unexpected(std::move(nested.error()));
                    }
                    auto match = decode_scan_match(*nested);
                    if (!match) {
                        return std::unexpected(std::move(match.error()));
                    }
                    result.matches.push_back(*match);
                    continue;
                }
                if (tag->field > 7) {
                    if (auto skipped = reader.skip(*tag); !skipped) {
                        return std::unexpected(std::move(skipped.error()));
                    }
                    continue;
                }
                if (auto marked = seen.mark(tag->field, reader.offset); !marked) {
                    return std::unexpected(std::move(marked.error()));
                }
                if (tag->field == 1) {
                    auto id = read_string(reader, *tag);
                    if (!id) {
                        return std::unexpected(std::move(id.error()));
                    }
                    result.request_id = RequestId {std::move(*id)};
                } else if (tag->field == 2) {
                    auto nested = child_reader(reader, *tag, reader.limits->maximum_subject_depth);
                    if (!nested) {
                        return std::unexpected(std::move(nested.error()));
                    }
                    auto subject = decode_subject(*nested);
                    if (!subject) {
                        return std::unexpected(std::move(subject.error()));
                    }
                    result.subject = std::move(*subject);
                } else if (tag->field == 3) {
                    auto status = reader.read_unsigned(*tag);
                    if (!status || *status > static_cast<std::uint8_t>(FactTerminalStatus::canceled)) {
                        return std::unexpected(status ? codec_error(ProtocolErrorCode::invalid_value,
                                                                    "scan status is invalid", reader.offset) :
                                                        std::move(status.error()));
                    }
                    result.status = static_cast<FactTerminalStatus>(*status);
                    status_seen = true;
                } else if (tag->field == 5) {
                    auto truncated = reader.read_boolean(*tag);
                    if (!truncated) {
                        return std::unexpected(std::move(truncated.error()));
                    }
                    result.truncated = *truncated;
                } else if (tag->field == 6) {
                    auto nested = child_reader(reader, *tag, reader.limits->maximum_value_depth);
                    if (!nested) {
                        return std::unexpected(std::move(nested.error()));
                    }
                    auto diagnostic = decode_diagnostic(*nested);
                    if (!diagnostic) {
                        return std::unexpected(std::move(diagnostic.error()));
                    }
                    result.diagnostic = std::move(*diagnostic);
                } else {
                    auto mode = reader.read_unsigned(*tag);
                    if (!mode || *mode < static_cast<std::uint8_t>(ScanResultMode::exact_complete) ||
                        *mode > static_cast<std::uint8_t>(ScanResultMode::existential)) {
                        return std::unexpected(mode ? codec_error(ProtocolErrorCode::invalid_value,
                                                                  "scan result mode is invalid", reader.offset) :
                                                      std::move(mode.error()));
                    }
                    result.mode = static_cast<ScanResultMode>(*mode);
                    mode_seen = true;
                }
            }
            if (!status_seen || !mode_seen || result.request_id.empty() || !result.subject.valid() ||
                result.truncated || (result.mode == ScanResultMode::existential && result.matches.size() > 1) ||
                (result.status != FactTerminalStatus::value && !result.matches.empty())) {
                return std::unexpected(
                    codec_error(ProtocolErrorCode::invalid_value, "decoded scan response is invalid", reader.offset));
            }
            return result;
        }

        [[nodiscard]] std::expected<void, ProtocolError>
        validate_advertisements(const std::span<const SchemaAdvertisement> schemas,
                                const std::span<const CapabilityAdvertisement> capabilities,
                                const ProtocolLimits &limits) {
            if (schemas.size() > limits.maximum_collection_items ||
                capabilities.size() > limits.maximum_collection_items - schemas.size()) {
                return std::unexpected(
                    codec_error(ProtocolErrorCode::limit_exceeded, "advertisement count exceeds the limit"));
            }
            std::unordered_set<std::string> schema_ids;
            for (const auto &schema : schemas) {
                if (schema.schema.empty() || schema.major == 0 || schema.canonical_hash.empty() ||
                    !schema_ids.insert(schema.schema.value).second) {
                    return std::unexpected(codec_error(ProtocolErrorCode::schema_mismatch,
                                                       "schema advertisement is invalid or duplicated"));
                }
            }
            std::unordered_set<std::string> capability_ids;
            for (const auto &capability : capabilities) {
                if (capability.capability.empty() || capability.version == 0 || capability.request_schema.empty() ||
                    capability.response_schema.empty() || !capability_ids.insert(capability.capability.value).second) {
                    return std::unexpected(codec_error(ProtocolErrorCode::capability_mismatch,
                                                       "capability advertisement is invalid or duplicated"));
                }
            }
            return {};
        }

        [[nodiscard]] std::expected<void, ProtocolError>
        encode_agent_hello(Writer &writer, const AgentHelloMessage &hello, const ProtocolLimits &limits) {
            if (hello.minimum_minor > hello.maximum_minor || hello.agent_version.empty() || hello.agent_epoch.empty() ||
                hello.next_sequence == 0) {
                return std::unexpected(codec_error(ProtocolErrorCode::malformed, "agent hello is incomplete"));
            }
            if (auto valid = validate_advertisements(hello.schemas, hello.capabilities, limits); !valid) {
                return valid;
            }
            writer.unsigned_field(1, hello.minimum_minor);
            writer.unsigned_field(2, hello.maximum_minor);
            writer.string_field(3, hello.agent_version);
            writer.string_field(4, hello.agent_epoch);
            writer.unsigned_field(5, hello.next_sequence);
            for (const auto &schema : hello.schemas) {
                Writer nested;
                encode_schema(nested, schema);
                writer.message_field(6, nested);
            }
            for (const auto &capability : hello.capabilities) {
                Writer nested;
                encode_capability(nested, capability);
                writer.message_field(7, nested);
            }
            Writer credit;
            encode_credit(credit, hello.receive_limit);
            writer.message_field(8, credit);
            return {};
        }

        [[nodiscard]] std::expected<AgentHelloMessage, ProtocolError> decode_agent_hello(Reader &reader) {
            AgentHelloMessage result;
            SeenFields seen;
            bool minimum_seen {};
            bool maximum_seen {};
            while (!reader.eof()) {
                auto tag = reader.next_tag();
                if (!tag) {
                    return std::unexpected(std::move(tag.error()));
                }
                if (tag->field == 6 || tag->field == 7) {
                    if (auto counted = count_collection(reader); !counted) {
                        return std::unexpected(std::move(counted.error()));
                    }
                    auto nested = child_reader(reader, *tag, reader.limits->maximum_value_depth);
                    if (!nested) {
                        return std::unexpected(std::move(nested.error()));
                    }
                    if (tag->field == 6) {
                        auto schema = decode_schema(*nested);
                        if (!schema) {
                            return std::unexpected(std::move(schema.error()));
                        }
                        result.schemas.push_back(std::move(*schema));
                    } else {
                        auto capability = decode_capability(*nested);
                        if (!capability) {
                            return std::unexpected(std::move(capability.error()));
                        }
                        result.capabilities.push_back(std::move(*capability));
                    }
                    continue;
                }
                if (tag->field > 8) {
                    if (auto skipped = reader.skip(*tag); !skipped) {
                        return std::unexpected(std::move(skipped.error()));
                    }
                    continue;
                }
                if (auto marked = seen.mark(tag->field, reader.offset); !marked) {
                    return std::unexpected(std::move(marked.error()));
                }
                if (tag->field == 1 || tag->field == 2 || tag->field == 5) {
                    auto number = reader.read_unsigned(*tag);
                    if (!number) {
                        return std::unexpected(std::move(number.error()));
                    }
                    if ((tag->field == 1 || tag->field == 2) && *number > std::numeric_limits<std::uint16_t>::max()) {
                        return std::unexpected(codec_error(ProtocolErrorCode::limit_exceeded,
                                                           "protocol minor exceeds uint16", reader.offset));
                    }
                    if (tag->field == 1) {
                        result.minimum_minor = static_cast<std::uint16_t>(*number);
                        minimum_seen = true;
                    } else if (tag->field == 2) {
                        result.maximum_minor = static_cast<std::uint16_t>(*number);
                        maximum_seen = true;
                    } else {
                        result.next_sequence = *number;
                    }
                } else if (tag->field == 3 || tag->field == 4) {
                    auto text = read_string(reader, *tag);
                    if (!text) {
                        return std::unexpected(std::move(text.error()));
                    }
                    if (tag->field == 3) {
                        result.agent_version = std::move(*text);
                    } else {
                        result.agent_epoch = std::move(*text);
                    }
                } else if (tag->field == 8) {
                    auto nested = child_reader(reader, *tag, reader.limits->maximum_value_depth);
                    if (!nested) {
                        return std::unexpected(std::move(nested.error()));
                    }
                    auto credit = decode_credit(*nested);
                    if (!credit) {
                        return std::unexpected(std::move(credit.error()));
                    }
                    result.receive_limit = *credit;
                } else {
                    return std::unexpected(
                        codec_error(ProtocolErrorCode::malformed, "unexpected agent hello field", reader.offset));
                }
            }
            if (!minimum_seen || !maximum_seen || result.minimum_minor > result.maximum_minor ||
                result.agent_version.empty() || result.agent_epoch.empty() || result.next_sequence == 0) {
                return std::unexpected(
                    codec_error(ProtocolErrorCode::malformed, "decoded agent hello is incomplete", reader.offset));
            }
            if (auto valid = validate_advertisements(result.schemas, result.capabilities, *reader.limits); !valid) {
                return std::unexpected(std::move(valid.error()));
            }
            return result;
        }

        [[nodiscard]] std::expected<void, ProtocolError>
        encode_server_hello(Writer &writer, const ServerHelloMessage &hello, const ProtocolLimits &limits) {
            if (hello.selected_minor != initial_minor_version || hello.session.empty() || hello.peer.empty() ||
                hello.session_fence == 0 || hello.heartbeat_interval_ms == 0) {
                return std::unexpected(codec_error(ProtocolErrorCode::malformed, "server hello is incomplete"));
            }
            if (auto valid = validate_advertisements(hello.schemas, hello.capabilities, limits); !valid) {
                return valid;
            }
            writer.unsigned_field(1, hello.selected_minor);
            writer.string_field(2, hello.session.value);
            writer.string_field(3, hello.peer.value);
            writer.unsigned_field(4, hello.session_fence);
            writer.unsigned_field(5, hello.acknowledged_sequence);
            for (const auto &schema : hello.schemas) {
                Writer nested;
                encode_schema(nested, schema);
                writer.message_field(6, nested);
            }
            for (const auto &capability : hello.capabilities) {
                Writer nested;
                encode_capability(nested, capability);
                writer.message_field(7, nested);
            }
            Writer credit;
            encode_credit(credit, hello.credit);
            writer.message_field(8, credit);
            writer.unsigned_field(9, hello.heartbeat_interval_ms);
            return {};
        }

        [[nodiscard]] std::expected<ServerHelloMessage, ProtocolError> decode_server_hello(Reader &reader) {
            ServerHelloMessage result;
            SeenFields seen;
            bool minor_seen {};
            while (!reader.eof()) {
                auto tag = reader.next_tag();
                if (!tag) {
                    return std::unexpected(std::move(tag.error()));
                }
                if (tag->field == 6 || tag->field == 7) {
                    if (auto counted = count_collection(reader); !counted) {
                        return std::unexpected(std::move(counted.error()));
                    }
                    auto nested = child_reader(reader, *tag, reader.limits->maximum_value_depth);
                    if (!nested) {
                        return std::unexpected(std::move(nested.error()));
                    }
                    if (tag->field == 6) {
                        auto schema = decode_schema(*nested);
                        if (!schema) {
                            return std::unexpected(std::move(schema.error()));
                        }
                        result.schemas.push_back(std::move(*schema));
                    } else {
                        auto capability = decode_capability(*nested);
                        if (!capability) {
                            return std::unexpected(std::move(capability.error()));
                        }
                        result.capabilities.push_back(std::move(*capability));
                    }
                    continue;
                }
                if (tag->field > 9) {
                    if (auto skipped = reader.skip(*tag); !skipped) {
                        return std::unexpected(std::move(skipped.error()));
                    }
                    continue;
                }
                if (auto marked = seen.mark(tag->field, reader.offset); !marked) {
                    return std::unexpected(std::move(marked.error()));
                }
                if (tag->field == 2 || tag->field == 3) {
                    auto text = read_string(reader, *tag);
                    if (!text) {
                        return std::unexpected(std::move(text.error()));
                    }
                    if (tag->field == 2) {
                        result.session = SessionId {std::move(*text)};
                    } else {
                        result.peer = PeerId {std::move(*text)};
                    }
                } else if (tag->field == 8) {
                    auto nested = child_reader(reader, *tag, reader.limits->maximum_value_depth);
                    if (!nested) {
                        return std::unexpected(std::move(nested.error()));
                    }
                    auto credit = decode_credit(*nested);
                    if (!credit) {
                        return std::unexpected(std::move(credit.error()));
                    }
                    result.credit = *credit;
                } else {
                    auto number = reader.read_unsigned(*tag);
                    if (!number) {
                        return std::unexpected(std::move(number.error()));
                    }
                    switch (tag->field) {
                        case 1:
                            if (*number > std::numeric_limits<std::uint16_t>::max()) {
                                return std::unexpected(codec_error(ProtocolErrorCode::limit_exceeded,
                                                                   "protocol minor exceeds uint16", reader.offset));
                            }
                            result.selected_minor = static_cast<std::uint16_t>(*number);
                            minor_seen = true;
                            break;
                        case 4: result.session_fence = *number; break;
                        case 5: result.acknowledged_sequence = *number; break;
                        case 9: result.heartbeat_interval_ms = *number; break;
                        default:
                            return std::unexpected(codec_error(ProtocolErrorCode::malformed,
                                                               "unexpected server hello field", reader.offset));
                    }
                }
            }
            if (!minor_seen || result.selected_minor != initial_minor_version || result.session.empty() ||
                result.peer.empty() || result.session_fence == 0 || result.heartbeat_interval_ms == 0) {
                return std::unexpected(
                    codec_error(ProtocolErrorCode::malformed, "decoded server hello is incomplete", reader.offset));
            }
            if (auto valid = validate_advertisements(result.schemas, result.capabilities, *reader.limits); !valid) {
                return std::unexpected(std::move(valid.error()));
            }
            return result;
        }

        [[nodiscard]] bool unique_request_ids(const std::span<const FactRequest> facts,
                                              const std::span<const ScanRequest> scans) {
            std::unordered_set<std::string> ids;
            ids.reserve(facts.size() + scans.size());
            for (const auto &request : facts) {
                if (!ids.insert(request.request_id.value).second) {
                    return false;
                }
            }
            for (const auto &request : scans) {
                if (!ids.insert(request.request_id.value).second) {
                    return false;
                }
            }
            return true;
        }

        [[nodiscard]] std::expected<void, ProtocolError> validate_work_lease(const WorkLeaseMessage &work,
                                                                             const ProtocolLimits &limits) {
            if (work.session.empty() || work.peer.empty() || work.session_fence == 0 || work.work_id.empty() ||
                work.attempt_id.empty() || work.work_fence == 0 || work.generation == 0 || work.server_sequence == 0 ||
                work.route.empty() || (work.facts.empty() && work.scans.empty()) ||
                work.facts.size() > limits.maximum_fact_requests || work.scans.size() > limits.maximum_scan_requests ||
                !unique_request_ids(work.facts, work.scans)) {
                return std::unexpected(
                    codec_error(ProtocolErrorCode::malformed, "work lease identity, count, or sequence is invalid"));
            }
            for (const auto &request : work.facts) {
                if (request.subject.peer != work.peer || request.route.provider != work.route) {
                    return std::unexpected(
                        codec_error(ProtocolErrorCode::malformed, "fact request escapes the work peer or route"));
                }
            }
            for (const auto &request : work.scans) {
                if (request.subject.peer != work.peer) {
                    return std::unexpected(
                        codec_error(ProtocolErrorCode::malformed, "scan request escapes the work peer"));
                }
            }
            return {};
        }

        [[nodiscard]] std::expected<void, ProtocolError> encode_work_lease(Writer &writer, const WorkLeaseMessage &work,
                                                                           const ProtocolLimits &limits) {
            if (auto valid = validate_work_lease(work, limits); !valid) {
                return valid;
            }
            writer.string_field(1, work.session.value);
            writer.string_field(2, work.peer.value);
            writer.unsigned_field(3, work.session_fence);
            writer.string_field(4, work.work_id);
            writer.string_field(5, work.attempt_id);
            writer.unsigned_field(6, work.work_fence);
            writer.unsigned_field(7, work.generation);
            writer.unsigned_field(8, work.server_sequence);
            writer.string_field(9, work.route);
            for (const auto &request : work.facts) {
                Writer nested;
                if (auto encoded = encode_fact_request(nested, request, limits); !encoded) {
                    return encoded;
                }
                writer.message_field(10, nested);
            }
            for (const auto &request : work.scans) {
                Writer nested;
                if (auto encoded = encode_scan_request(nested, request, limits); !encoded) {
                    return encoded;
                }
                writer.message_field(11, nested);
            }
            return {};
        }

        [[nodiscard]] std::expected<WorkLeaseMessage, ProtocolError> decode_work_lease(Reader &reader) {
            WorkLeaseMessage result;
            SeenFields seen;
            while (!reader.eof()) {
                auto tag = reader.next_tag();
                if (!tag) {
                    return std::unexpected(std::move(tag.error()));
                }
                if (tag->field == 10 || tag->field == 11) {
                    if (auto counted = count_collection(reader); !counted) {
                        return std::unexpected(std::move(counted.error()));
                    }
                    if ((tag->field == 10 && result.facts.size() >= reader.limits->maximum_fact_requests) ||
                        (tag->field == 11 && result.scans.size() >= reader.limits->maximum_scan_requests)) {
                        return std::unexpected(codec_error(ProtocolErrorCode::limit_exceeded,
                                                           "work request count exceeds the limit", reader.offset));
                    }
                    auto nested = child_reader(reader, *tag, reader.limits->maximum_value_depth);
                    if (!nested) {
                        return std::unexpected(std::move(nested.error()));
                    }
                    if (tag->field == 10) {
                        auto request = decode_fact_request(*nested);
                        if (!request) {
                            return std::unexpected(std::move(request.error()));
                        }
                        result.facts.push_back(std::move(*request));
                    } else {
                        auto request = decode_scan_request(*nested);
                        if (!request) {
                            return std::unexpected(std::move(request.error()));
                        }
                        result.scans.push_back(std::move(*request));
                    }
                    continue;
                }
                if (tag->field > 11) {
                    if (auto skipped = reader.skip(*tag); !skipped) {
                        return std::unexpected(std::move(skipped.error()));
                    }
                    continue;
                }
                if (auto marked = seen.mark(tag->field, reader.offset); !marked) {
                    return std::unexpected(std::move(marked.error()));
                }
                if (tag->field == 1 || tag->field == 2 || tag->field == 4 || tag->field == 5 || tag->field == 9) {
                    auto text = read_string(reader, *tag);
                    if (!text) {
                        return std::unexpected(std::move(text.error()));
                    }
                    switch (tag->field) {
                        case 1: result.session = SessionId {std::move(*text)}; break;
                        case 2: result.peer = PeerId {std::move(*text)}; break;
                        case 4: result.work_id = std::move(*text); break;
                        case 5: result.attempt_id = std::move(*text); break;
                        case 9: result.route = std::move(*text); break;
                        default: break;
                    }
                } else {
                    auto number = reader.read_unsigned(*tag);
                    if (!number) {
                        return std::unexpected(std::move(number.error()));
                    }
                    switch (tag->field) {
                        case 3: result.session_fence = *number; break;
                        case 6: result.work_fence = *number; break;
                        case 7: result.generation = *number; break;
                        case 8: result.server_sequence = *number; break;
                        default:
                            return std::unexpected(codec_error(ProtocolErrorCode::malformed,
                                                               "unexpected work lease field", reader.offset));
                    }
                }
            }
            if (auto valid = validate_work_lease(result, *reader.limits); !valid) {
                return std::unexpected(std::move(valid.error()));
            }
            return result;
        }

        [[nodiscard]] std::expected<void, ProtocolError> validate_work_result(const WorkResultMessage &result,
                                                                              const ProtocolLimits &limits) {
            if (result.originating_session.empty() || result.peer.empty() || result.originating_session_fence == 0 ||
                result.work_id.empty() || result.attempt_id.empty() || result.work_fence == 0 ||
                result.generation == 0 || result.facts.size() > limits.maximum_fact_requests ||
                result.scans.size() > limits.maximum_scan_requests || (result.facts.empty() && result.scans.empty())) {
                return std::unexpected(codec_error(ProtocolErrorCode::malformed, "work result is incomplete"));
            }
            std::unordered_set<std::string> ids;
            for (const auto &response : result.facts) {
                if (response.request_id.empty() || response.subject.peer != result.peer ||
                    !ids.insert(response.request_id.value).second) {
                    return std::unexpected(codec_error(ProtocolErrorCode::provider_violation,
                                                       "fact result request identity is invalid or duplicated"));
                }
            }
            for (const auto &response : result.scans) {
                if (response.request_id.empty() || response.subject.peer != result.peer ||
                    !ids.insert(response.request_id.value).second) {
                    return std::unexpected(codec_error(ProtocolErrorCode::provider_violation,
                                                       "scan result request identity is invalid or duplicated"));
                }
            }
            return {};
        }

        [[nodiscard]] std::expected<void, ProtocolError>
        encode_work_result(Writer &writer, const WorkResultMessage &result, const ProtocolLimits &limits) {
            if (auto valid = validate_work_result(result, limits); !valid) {
                return valid;
            }
            writer.string_field(1, result.originating_session.value);
            writer.string_field(2, result.peer.value);
            writer.unsigned_field(3, result.originating_session_fence);
            writer.string_field(4, result.work_id);
            writer.string_field(5, result.attempt_id);
            writer.unsigned_field(6, result.work_fence);
            writer.unsigned_field(7, result.generation);
            for (const auto &response : result.facts) {
                Writer nested;
                if (auto encoded = encode_fact_response(nested, response, limits); !encoded) {
                    return encoded;
                }
                writer.message_field(8, nested);
            }
            for (const auto &response : result.scans) {
                Writer nested;
                if (auto encoded = encode_scan_response(nested, response, limits); !encoded) {
                    return encoded;
                }
                writer.message_field(9, nested);
            }
            return {};
        }

        [[nodiscard]] std::expected<WorkResultMessage, ProtocolError> decode_work_result(Reader &reader) {
            WorkResultMessage result;
            SeenFields seen;
            while (!reader.eof()) {
                auto tag = reader.next_tag();
                if (!tag) {
                    return std::unexpected(std::move(tag.error()));
                }
                if (tag->field == 8 || tag->field == 9) {
                    if (auto counted = count_collection(reader); !counted) {
                        return std::unexpected(std::move(counted.error()));
                    }
                    if ((tag->field == 8 && result.facts.size() >= reader.limits->maximum_fact_requests) ||
                        (tag->field == 9 && result.scans.size() >= reader.limits->maximum_scan_requests)) {
                        return std::unexpected(codec_error(ProtocolErrorCode::limit_exceeded,
                                                           "work result count exceeds the limit", reader.offset));
                    }
                    auto nested = child_reader(reader, *tag, reader.limits->maximum_value_depth);
                    if (!nested) {
                        return std::unexpected(std::move(nested.error()));
                    }
                    if (tag->field == 8) {
                        auto response = decode_fact_response(*nested);
                        if (!response) {
                            return std::unexpected(std::move(response.error()));
                        }
                        result.facts.push_back(std::move(*response));
                    } else {
                        auto response = decode_scan_response(*nested);
                        if (!response) {
                            return std::unexpected(std::move(response.error()));
                        }
                        result.scans.push_back(std::move(*response));
                    }
                    continue;
                }
                if (tag->field > 9) {
                    if (auto skipped = reader.skip(*tag); !skipped) {
                        return std::unexpected(std::move(skipped.error()));
                    }
                    continue;
                }
                if (auto marked = seen.mark(tag->field, reader.offset); !marked) {
                    return std::unexpected(std::move(marked.error()));
                }
                if (tag->field == 1 || tag->field == 2 || tag->field == 4 || tag->field == 5) {
                    auto text = read_string(reader, *tag);
                    if (!text) {
                        return std::unexpected(std::move(text.error()));
                    }
                    switch (tag->field) {
                        case 1: result.originating_session = SessionId {std::move(*text)}; break;
                        case 2: result.peer = PeerId {std::move(*text)}; break;
                        case 4: result.work_id = std::move(*text); break;
                        case 5: result.attempt_id = std::move(*text); break;
                        default: break;
                    }
                } else {
                    auto number = reader.read_unsigned(*tag);
                    if (!number) {
                        return std::unexpected(std::move(number.error()));
                    }
                    switch (tag->field) {
                        case 3: result.originating_session_fence = *number; break;
                        case 6: result.work_fence = *number; break;
                        case 7: result.generation = *number; break;
                        default:
                            return std::unexpected(codec_error(ProtocolErrorCode::malformed,
                                                               "unexpected work result field", reader.offset));
                    }
                }
            }
            if (auto valid = validate_work_result(result, *reader.limits); !valid) {
                return std::unexpected(std::move(valid.error()));
            }
            return result;
        }

        [[nodiscard]] std::expected<void, ProtocolError> encode_cancel(Writer &writer, const CancelWorkMessage &cancel,
                                                                       const ProtocolLimits &limits) {
            if (cancel.session.empty() || cancel.peer.empty() || cancel.session_fence == 0 || cancel.work_id.empty() ||
                cancel.attempt_id.empty() || cancel.work_fence == 0 || cancel.server_sequence == 0 ||
                cancel.route.empty() || cancel.requests.size() > limits.maximum_collection_items) {
                return std::unexpected(codec_error(ProtocolErrorCode::malformed, "cancel message is incomplete"));
            }
            std::unordered_set<std::string> ids;
            for (const auto &request : cancel.requests) {
                if (request.empty() || !ids.insert(request.value).second) {
                    return std::unexpected(codec_error(ProtocolErrorCode::duplicate_item,
                                                       "cancel request identity is empty or duplicated"));
                }
            }
            writer.string_field(1, cancel.session.value);
            writer.string_field(2, cancel.peer.value);
            writer.unsigned_field(3, cancel.session_fence);
            writer.string_field(4, cancel.work_id);
            writer.string_field(5, cancel.attempt_id);
            writer.unsigned_field(6, cancel.work_fence);
            writer.unsigned_field(7, cancel.server_sequence);
            writer.string_field(8, cancel.route);
            for (const auto &request : cancel.requests) { writer.string_field(9, request.value); }
            return {};
        }

        [[nodiscard]] std::expected<CancelWorkMessage, ProtocolError> decode_cancel(Reader &reader) {
            CancelWorkMessage result;
            SeenFields seen;
            std::unordered_set<std::string> ids;
            while (!reader.eof()) {
                auto tag = reader.next_tag();
                if (!tag) {
                    return std::unexpected(std::move(tag.error()));
                }
                if (tag->field == 9) {
                    if (auto counted = count_collection(reader); !counted) {
                        return std::unexpected(std::move(counted.error()));
                    }
                    auto id = read_string(reader, *tag);
                    if (!id) {
                        return std::unexpected(std::move(id.error()));
                    }
                    if (id->empty() || !ids.insert(*id).second) {
                        return std::unexpected(codec_error(ProtocolErrorCode::duplicate_item,
                                                           "cancel request is empty or duplicated", reader.offset));
                    }
                    result.requests.push_back(RequestId {std::move(*id)});
                    continue;
                }
                if (tag->field > 9) {
                    if (auto skipped = reader.skip(*tag); !skipped) {
                        return std::unexpected(std::move(skipped.error()));
                    }
                    continue;
                }
                if (auto marked = seen.mark(tag->field, reader.offset); !marked) {
                    return std::unexpected(std::move(marked.error()));
                }
                if (tag->field == 1 || tag->field == 2 || tag->field == 4 || tag->field == 5 || tag->field == 8) {
                    auto text = read_string(reader, *tag);
                    if (!text) {
                        return std::unexpected(std::move(text.error()));
                    }
                    switch (tag->field) {
                        case 1: result.session = SessionId {std::move(*text)}; break;
                        case 2: result.peer = PeerId {std::move(*text)}; break;
                        case 4: result.work_id = std::move(*text); break;
                        case 5: result.attempt_id = std::move(*text); break;
                        case 8: result.route = std::move(*text); break;
                        default: break;
                    }
                } else {
                    auto number = reader.read_unsigned(*tag);
                    if (!number) {
                        return std::unexpected(std::move(number.error()));
                    }
                    if (tag->field == 3) {
                        result.session_fence = *number;
                    } else if (tag->field == 6) {
                        result.work_fence = *number;
                    } else if (tag->field == 7) {
                        result.server_sequence = *number;
                    } else {
                        return std::unexpected(
                            codec_error(ProtocolErrorCode::malformed, "unexpected cancel field", reader.offset));
                    }
                }
            }
            if (result.session.empty() || result.peer.empty() || result.session_fence == 0 || result.work_id.empty() ||
                result.attempt_id.empty() || result.work_fence == 0 || result.server_sequence == 0 ||
                result.route.empty()) {
                return std::unexpected(
                    codec_error(ProtocolErrorCode::malformed, "decoded cancel message is incomplete", reader.offset));
            }
            return result;
        }

        [[nodiscard]] bool valid_sha256(const std::string_view digest) noexcept {
            return digest.size() == 71 && digest.starts_with("sha256:") &&
                   std::ranges::all_of(digest.substr(7), [](const char value) {
                       return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f');
                   });
        }

        [[nodiscard]] std::expected<void, ProtocolError>
        validate_snapshot_begin(const AuthoritativeSnapshotBegin &message, const ProtocolLimits &limits) {
            if (message.session.empty() || message.peer.empty() || message.session_fence == 0 ||
                message.snapshot_id.empty() || message.subject_schema.empty() || message.generation == 0 ||
                message.expected_count > limits.maximum_snapshot_items || !valid_sha256(message.expected_digest) ||
                (message.parent.has_value() && (!message.parent->valid() || message.parent->peer != message.peer))) {
                return std::unexpected(
                    codec_error(ProtocolErrorCode::malformed, "snapshot begin identity, count, or digest is invalid"));
            }
            return {};
        }

        [[nodiscard]] std::expected<void, ProtocolError>
        encode_snapshot_begin(Writer &writer, const AuthoritativeSnapshotBegin &message, const ProtocolLimits &limits) {
            if (auto valid = validate_snapshot_begin(message, limits); !valid) {
                return valid;
            }
            writer.string_field(1, message.session.value);
            writer.string_field(2, message.peer.value);
            writer.unsigned_field(3, message.session_fence);
            writer.string_field(4, message.snapshot_id);
            if (message.parent.has_value()) {
                Writer parent;
                encode_subject(parent, *message.parent);
                writer.message_field(5, parent);
            }
            writer.string_field(6, message.subject_schema.value);
            writer.unsigned_field(7, message.generation);
            writer.unsigned_field(8, message.expected_count);
            writer.string_field(9, message.expected_digest);
            return {};
        }

        [[nodiscard]] std::expected<AuthoritativeSnapshotBegin, ProtocolError> decode_snapshot_begin(Reader &reader) {
            AuthoritativeSnapshotBegin result;
            SeenFields seen;
            while (!reader.eof()) {
                auto tag = reader.next_tag();
                if (!tag) {
                    return std::unexpected(std::move(tag.error()));
                }
                if (tag->field > 9) {
                    if (auto skipped = reader.skip(*tag); !skipped) {
                        return std::unexpected(std::move(skipped.error()));
                    }
                    continue;
                }
                if (auto marked = seen.mark(tag->field, reader.offset); !marked) {
                    return std::unexpected(std::move(marked.error()));
                }
                if (tag->field == 5) {
                    auto nested = child_reader(reader, *tag, reader.limits->maximum_subject_depth);
                    if (!nested) {
                        return std::unexpected(std::move(nested.error()));
                    }
                    auto parent = decode_subject(*nested);
                    if (!parent) {
                        return std::unexpected(std::move(parent.error()));
                    }
                    result.parent = std::move(*parent);
                } else if (tag->field == 1 || tag->field == 2 || tag->field == 4 || tag->field == 6 ||
                           tag->field == 9) {
                    auto text = read_string(reader, *tag);
                    if (!text) {
                        return std::unexpected(std::move(text.error()));
                    }
                    switch (tag->field) {
                        case 1: result.session = SessionId {std::move(*text)}; break;
                        case 2: result.peer = PeerId {std::move(*text)}; break;
                        case 4: result.snapshot_id = std::move(*text); break;
                        case 6: result.subject_schema = SchemaId {std::move(*text)}; break;
                        case 9: result.expected_digest = std::move(*text); break;
                        default: break;
                    }
                } else {
                    auto number = reader.read_unsigned(*tag);
                    if (!number) {
                        return std::unexpected(std::move(number.error()));
                    }
                    if (tag->field == 3) {
                        result.session_fence = *number;
                    } else if (tag->field == 7) {
                        result.generation = *number;
                    } else if (tag->field == 8) {
                        result.expected_count = *number;
                    } else {
                        return std::unexpected(codec_error(ProtocolErrorCode::malformed,
                                                           "unexpected snapshot begin field", reader.offset));
                    }
                }
            }
            if (auto valid = validate_snapshot_begin(result, *reader.limits); !valid) {
                return std::unexpected(std::move(valid.error()));
            }
            return result;
        }

        [[nodiscard]] std::expected<void, ProtocolError>
        validate_snapshot_chunk(const AuthoritativeSnapshotChunk &message, const ProtocolLimits &limits) {
            if (message.session.empty() || message.peer.empty() || message.session_fence == 0 ||
                message.snapshot_id.empty() || message.generation == 0 ||
                message.subjects.size() > limits.maximum_snapshot_items) {
                return std::unexpected(
                    codec_error(ProtocolErrorCode::malformed, "snapshot chunk identity or count is invalid"));
            }
            std::unordered_set<std::string> keys;
            std::size_t bytes {};
            for (const auto &subject : message.subjects) {
                const auto key = canonical_subject_key(subject);
                if (key.empty() || subject.peer != message.peer || !keys.insert(key).second ||
                    key.size() > limits.maximum_snapshot_bytes - bytes) {
                    return std::unexpected(codec_error(ProtocolErrorCode::invalid_identity,
                                                       "snapshot chunk subject is invalid, duplicate, or oversized"));
                }
                bytes += key.size();
            }
            return {};
        }

        [[nodiscard]] std::expected<void, ProtocolError>
        encode_snapshot_chunk(Writer &writer, const AuthoritativeSnapshotChunk &message, const ProtocolLimits &limits) {
            if (auto valid = validate_snapshot_chunk(message, limits); !valid) {
                return valid;
            }
            writer.string_field(1, message.session.value);
            writer.string_field(2, message.peer.value);
            writer.unsigned_field(3, message.session_fence);
            writer.string_field(4, message.snapshot_id);
            writer.unsigned_field(5, message.generation);
            writer.unsigned_field(6, message.chunk_index);
            for (const auto &subject : message.subjects) {
                Writer nested;
                encode_subject(nested, subject);
                writer.message_field(7, nested);
            }
            return {};
        }

        [[nodiscard]] std::expected<AuthoritativeSnapshotChunk, ProtocolError> decode_snapshot_chunk(Reader &reader) {
            AuthoritativeSnapshotChunk result;
            SeenFields seen;
            bool chunk_seen {};
            while (!reader.eof()) {
                auto tag = reader.next_tag();
                if (!tag) {
                    return std::unexpected(std::move(tag.error()));
                }
                if (tag->field == 7) {
                    if (auto counted = count_collection(reader); !counted) {
                        return std::unexpected(std::move(counted.error()));
                    }
                    if (result.subjects.size() >= reader.limits->maximum_snapshot_items) {
                        return std::unexpected(codec_error(ProtocolErrorCode::limit_exceeded,
                                                           "snapshot chunk exceeds the item limit", reader.offset));
                    }
                    auto nested = child_reader(reader, *tag, reader.limits->maximum_subject_depth);
                    if (!nested) {
                        return std::unexpected(std::move(nested.error()));
                    }
                    auto subject = decode_subject(*nested);
                    if (!subject) {
                        return std::unexpected(std::move(subject.error()));
                    }
                    result.subjects.push_back(std::move(*subject));
                    continue;
                }
                if (tag->field > 7) {
                    if (auto skipped = reader.skip(*tag); !skipped) {
                        return std::unexpected(std::move(skipped.error()));
                    }
                    continue;
                }
                if (auto marked = seen.mark(tag->field, reader.offset); !marked) {
                    return std::unexpected(std::move(marked.error()));
                }
                if (tag->field == 1 || tag->field == 2 || tag->field == 4) {
                    auto text = read_string(reader, *tag);
                    if (!text) {
                        return std::unexpected(std::move(text.error()));
                    }
                    if (tag->field == 1) {
                        result.session = SessionId {std::move(*text)};
                    } else if (tag->field == 2) {
                        result.peer = PeerId {std::move(*text)};
                    } else {
                        result.snapshot_id = std::move(*text);
                    }
                } else {
                    auto number = reader.read_unsigned(*tag);
                    if (!number) {
                        return std::unexpected(std::move(number.error()));
                    }
                    if (tag->field == 3) {
                        result.session_fence = *number;
                    } else if (tag->field == 5) {
                        result.generation = *number;
                    } else if (tag->field == 6) {
                        if (*number > std::numeric_limits<std::uint32_t>::max()) {
                            return std::unexpected(codec_error(ProtocolErrorCode::limit_exceeded,
                                                               "snapshot chunk index exceeds uint32", reader.offset));
                        }
                        result.chunk_index = static_cast<std::uint32_t>(*number);
                        chunk_seen = true;
                    } else {
                        return std::unexpected(codec_error(ProtocolErrorCode::malformed,
                                                           "unexpected snapshot chunk field", reader.offset));
                    }
                }
            }
            if (!chunk_seen) {
                return std::unexpected(
                    codec_error(ProtocolErrorCode::malformed, "snapshot chunk index is absent", reader.offset));
            }
            if (auto valid = validate_snapshot_chunk(result, *reader.limits); !valid) {
                return std::unexpected(std::move(valid.error()));
            }
            return result;
        }

        [[nodiscard]] std::expected<void, ProtocolError>
        encode_snapshot_commit(Writer &writer, const AuthoritativeSnapshotCommit &message) {
            if (message.session.empty() || message.peer.empty() || message.session_fence == 0 ||
                message.snapshot_id.empty() || message.generation == 0 || !valid_sha256(message.canonical_digest)) {
                return std::unexpected(codec_error(ProtocolErrorCode::malformed, "snapshot commit is invalid"));
            }
            writer.string_field(1, message.session.value);
            writer.string_field(2, message.peer.value);
            writer.unsigned_field(3, message.session_fence);
            writer.string_field(4, message.snapshot_id);
            writer.unsigned_field(5, message.generation);
            writer.unsigned_field(6, message.item_count);
            writer.string_field(7, message.canonical_digest);
            return {};
        }

        [[nodiscard]] std::expected<AuthoritativeSnapshotCommit, ProtocolError> decode_snapshot_commit(Reader &reader) {
            AuthoritativeSnapshotCommit result;
            SeenFields seen;
            while (!reader.eof()) {
                auto tag = reader.next_tag();
                if (!tag) {
                    return std::unexpected(std::move(tag.error()));
                }
                if (tag->field > 7) {
                    if (auto skipped = reader.skip(*tag); !skipped) {
                        return std::unexpected(std::move(skipped.error()));
                    }
                    continue;
                }
                if (auto marked = seen.mark(tag->field, reader.offset); !marked) {
                    return std::unexpected(std::move(marked.error()));
                }
                if (tag->field == 1 || tag->field == 2 || tag->field == 4 || tag->field == 7) {
                    auto text = read_string(reader, *tag);
                    if (!text) {
                        return std::unexpected(std::move(text.error()));
                    }
                    if (tag->field == 1) {
                        result.session = SessionId {std::move(*text)};
                    } else if (tag->field == 2) {
                        result.peer = PeerId {std::move(*text)};
                    } else if (tag->field == 4) {
                        result.snapshot_id = std::move(*text);
                    } else {
                        result.canonical_digest = std::move(*text);
                    }
                } else {
                    auto number = reader.read_unsigned(*tag);
                    if (!number) {
                        return std::unexpected(std::move(number.error()));
                    }
                    if (tag->field == 3) {
                        result.session_fence = *number;
                    } else if (tag->field == 5) {
                        result.generation = *number;
                    } else if (tag->field == 6) {
                        result.item_count = *number;
                    } else {
                        return std::unexpected(codec_error(ProtocolErrorCode::malformed,
                                                           "unexpected snapshot commit field", reader.offset));
                    }
                }
            }
            if (result.session.empty() || result.peer.empty() || result.session_fence == 0 ||
                result.snapshot_id.empty() || result.generation == 0 ||
                result.item_count > reader.limits->maximum_snapshot_items || !valid_sha256(result.canonical_digest)) {
                return std::unexpected(
                    codec_error(ProtocolErrorCode::malformed, "decoded snapshot commit is invalid", reader.offset));
            }
            return result;
        }

        void encode_ack(Writer &writer, const AckMessage &message) {
            writer.string_field(1, message.agent_epoch);
            writer.unsigned_field(2, message.acknowledged_through);
            Writer credit;
            encode_credit(credit, message.credit);
            writer.message_field(3, credit);
        }

        [[nodiscard]] std::expected<AckMessage, ProtocolError> decode_ack(Reader &reader) {
            AckMessage result;
            SeenFields seen;
            while (!reader.eof()) {
                auto tag = reader.next_tag();
                if (!tag) {
                    return std::unexpected(std::move(tag.error()));
                }
                if (tag->field > 3) {
                    if (auto skipped = reader.skip(*tag); !skipped) {
                        return std::unexpected(std::move(skipped.error()));
                    }
                    continue;
                }
                if (auto marked = seen.mark(tag->field, reader.offset); !marked) {
                    return std::unexpected(std::move(marked.error()));
                }
                if (tag->field == 1) {
                    auto epoch = read_string(reader, *tag);
                    if (!epoch) {
                        return std::unexpected(std::move(epoch.error()));
                    }
                    result.agent_epoch = std::move(*epoch);
                } else if (tag->field == 2) {
                    auto sequence = reader.read_unsigned(*tag);
                    if (!sequence) {
                        return std::unexpected(std::move(sequence.error()));
                    }
                    result.acknowledged_through = *sequence;
                } else {
                    auto nested = child_reader(reader, *tag, reader.limits->maximum_value_depth);
                    if (!nested) {
                        return std::unexpected(std::move(nested.error()));
                    }
                    auto credit = decode_credit(*nested);
                    if (!credit) {
                        return std::unexpected(std::move(credit.error()));
                    }
                    result.credit = *credit;
                }
            }
            if (result.agent_epoch.empty()) {
                return std::unexpected(
                    codec_error(ProtocolErrorCode::malformed, "acknowledgement epoch is absent", reader.offset));
            }
            return result;
        }

        [[nodiscard]] std::expected<void, ProtocolError> encode_nack(Writer &writer, const NackMessage &message) {
            if (message.agent_epoch.empty() || message.sequence == 0 || message.diagnostic.empty() ||
                !valid_utf8(message.diagnostic)) {
                return std::unexpected(codec_error(ProtocolErrorCode::malformed, "NACK is incomplete"));
            }
            writer.string_field(1, message.agent_epoch);
            writer.unsigned_field(2, message.sequence);
            writer.unsigned_field(3, static_cast<std::uint8_t>(message.reason));
            writer.boolean_field(4, message.permanent);
            writer.string_field(5, message.diagnostic);
            return {};
        }

        [[nodiscard]] std::expected<NackMessage, ProtocolError> decode_nack(Reader &reader) {
            NackMessage result;
            SeenFields seen;
            bool reason_seen {};
            while (!reader.eof()) {
                auto tag = reader.next_tag();
                if (!tag) {
                    return std::unexpected(std::move(tag.error()));
                }
                if (tag->field > 5) {
                    if (auto skipped = reader.skip(*tag); !skipped) {
                        return std::unexpected(std::move(skipped.error()));
                    }
                    continue;
                }
                if (auto marked = seen.mark(tag->field, reader.offset); !marked) {
                    return std::unexpected(std::move(marked.error()));
                }
                if (tag->field == 1 || tag->field == 5) {
                    auto text = read_string(reader, *tag);
                    if (!text) {
                        return std::unexpected(std::move(text.error()));
                    }
                    if (tag->field == 1) {
                        result.agent_epoch = std::move(*text);
                    } else {
                        result.diagnostic = std::move(*text);
                    }
                } else if (tag->field == 4) {
                    auto permanent = reader.read_boolean(*tag);
                    if (!permanent) {
                        return std::unexpected(std::move(permanent.error()));
                    }
                    result.permanent = *permanent;
                } else {
                    auto number = reader.read_unsigned(*tag);
                    if (!number) {
                        return std::unexpected(std::move(number.error()));
                    }
                    if (tag->field == 2) {
                        result.sequence = *number;
                    } else if (tag->field == 3) {
                        if (*number > static_cast<std::uint8_t>(ProtocolErrorCode::timed_out)) {
                            return std::unexpected(
                                codec_error(ProtocolErrorCode::malformed, "NACK reason is invalid", reader.offset));
                        }
                        result.reason = static_cast<ProtocolErrorCode>(*number);
                        reason_seen = true;
                    } else {
                        return std::unexpected(
                            codec_error(ProtocolErrorCode::malformed, "unexpected NACK field", reader.offset));
                    }
                }
            }
            if (!reason_seen || result.agent_epoch.empty() || result.sequence == 0 || result.diagnostic.empty()) {
                return std::unexpected(
                    codec_error(ProtocolErrorCode::malformed, "decoded NACK is incomplete", reader.offset));
            }
            return result;
        }

        void encode_credit_update(Writer &writer, const CreditUpdateMessage &message) {
            Writer credit;
            encode_credit(credit, message.credit);
            writer.message_field(1, credit);
        }

        [[nodiscard]] std::expected<CreditUpdateMessage, ProtocolError> decode_credit_update(Reader &reader) {
            CreditUpdateMessage result;
            SeenFields seen;
            bool credit_seen {};
            while (!reader.eof()) {
                auto tag = reader.next_tag();
                if (!tag) {
                    return std::unexpected(std::move(tag.error()));
                }
                if (tag->field != 1) {
                    if (auto skipped = reader.skip(*tag); !skipped) {
                        return std::unexpected(std::move(skipped.error()));
                    }
                    continue;
                }
                if (auto marked = seen.mark(tag->field, reader.offset); !marked) {
                    return std::unexpected(std::move(marked.error()));
                }
                auto nested = child_reader(reader, *tag, reader.limits->maximum_value_depth);
                if (!nested) {
                    return std::unexpected(std::move(nested.error()));
                }
                auto credit = decode_credit(*nested);
                if (!credit) {
                    return std::unexpected(std::move(credit.error()));
                }
                result.credit = *credit;
                credit_seen = true;
            }
            if (!credit_seen) {
                return std::unexpected(
                    codec_error(ProtocolErrorCode::malformed, "credit update is empty", reader.offset));
            }
            return result;
        }

        [[nodiscard]] std::expected<void, ProtocolError> encode_body(Writer &writer, const MessageBody &body,
                                                                     const ProtocolLimits &limits) {
            return std::visit(
                [&](const auto &message) -> std::expected<void, ProtocolError> {
                    using Message = std::remove_cvref_t<decltype(message)>;
                    if constexpr (std::is_same_v<Message, AgentHelloMessage>) {
                        return encode_agent_hello(writer, message, limits);
                    } else if constexpr (std::is_same_v<Message, ServerHelloMessage>) {
                        return encode_server_hello(writer, message, limits);
                    } else if constexpr (std::is_same_v<Message, WorkLeaseMessage>) {
                        return encode_work_lease(writer, message, limits);
                    } else if constexpr (std::is_same_v<Message, WorkResultMessage>) {
                        return encode_work_result(writer, message, limits);
                    } else if constexpr (std::is_same_v<Message, CancelWorkMessage>) {
                        return encode_cancel(writer, message, limits);
                    } else if constexpr (std::is_same_v<Message, AuthoritativeSnapshotBegin>) {
                        return encode_snapshot_begin(writer, message, limits);
                    } else if constexpr (std::is_same_v<Message, AuthoritativeSnapshotChunk>) {
                        return encode_snapshot_chunk(writer, message, limits);
                    } else if constexpr (std::is_same_v<Message, AuthoritativeSnapshotCommit>) {
                        return encode_snapshot_commit(writer, message);
                    } else if constexpr (std::is_same_v<Message, AckMessage>) {
                        if (message.agent_epoch.empty()) {
                            return std::unexpected(
                                codec_error(ProtocolErrorCode::malformed, "acknowledgement epoch is absent"));
                        }
                        encode_ack(writer, message);
                        return {};
                    } else if constexpr (std::is_same_v<Message, NackMessage>) {
                        return encode_nack(writer, message);
                    } else {
                        encode_credit_update(writer, message);
                        return {};
                    }
                },
                body);
        }

        [[nodiscard]] std::expected<MessageBody, ProtocolError> decode_body(const MessageKind kind, Reader &reader) {
            switch (kind) {
                case MessageKind::agent_hello: {
                    auto message = decode_agent_hello(reader);
                    if (!message)
                        return std::unexpected(std::move(message.error()));
                    return MessageBody {std::move(*message)};
                }
                case MessageKind::server_hello: {
                    auto message = decode_server_hello(reader);
                    if (!message)
                        return std::unexpected(std::move(message.error()));
                    return MessageBody {std::move(*message)};
                }
                case MessageKind::work_lease: {
                    auto message = decode_work_lease(reader);
                    if (!message)
                        return std::unexpected(std::move(message.error()));
                    return MessageBody {std::move(*message)};
                }
                case MessageKind::work_result: {
                    auto message = decode_work_result(reader);
                    if (!message)
                        return std::unexpected(std::move(message.error()));
                    return MessageBody {std::move(*message)};
                }
                case MessageKind::cancel_work: {
                    auto message = decode_cancel(reader);
                    if (!message)
                        return std::unexpected(std::move(message.error()));
                    return MessageBody {std::move(*message)};
                }
                case MessageKind::snapshot_begin: {
                    auto message = decode_snapshot_begin(reader);
                    if (!message)
                        return std::unexpected(std::move(message.error()));
                    return MessageBody {std::move(*message)};
                }
                case MessageKind::snapshot_chunk: {
                    auto message = decode_snapshot_chunk(reader);
                    if (!message)
                        return std::unexpected(std::move(message.error()));
                    return MessageBody {std::move(*message)};
                }
                case MessageKind::snapshot_commit: {
                    auto message = decode_snapshot_commit(reader);
                    if (!message)
                        return std::unexpected(std::move(message.error()));
                    return MessageBody {std::move(*message)};
                }
                case MessageKind::ack: {
                    auto message = decode_ack(reader);
                    if (!message)
                        return std::unexpected(std::move(message.error()));
                    return MessageBody {std::move(*message)};
                }
                case MessageKind::nack: {
                    auto message = decode_nack(reader);
                    if (!message)
                        return std::unexpected(std::move(message.error()));
                    return MessageBody {std::move(*message)};
                }
                case MessageKind::credit_update: {
                    auto message = decode_credit_update(reader);
                    if (!message)
                        return std::unexpected(std::move(message.error()));
                    return MessageBody {std::move(*message)};
                }
                default: break;
            }
            return std::unexpected(codec_error(ProtocolErrorCode::unexpected_message, "unknown protocol message kind"));
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
            if (envelope.message_id.empty() || envelope.message_id.size() > limits.maximum_string_bytes ||
                !valid_utf8(envelope.message_id)) {
                return std::unexpected(codec_error(ProtocolErrorCode::malformed, "message ID is invalid"));
            }
            const auto kind = message_kind(envelope.body);
            if (kind == MessageKind::agent_hello) {
                const auto &hello = std::get<AgentHelloMessage>(envelope.body);
                if (envelope.session.has_value() || envelope.agent_sequence != 0 ||
                    envelope.agent_epoch != hello.agent_epoch) {
                    return std::unexpected(codec_error(ProtocolErrorCode::malformed,
                                                       "agent hello envelope has session or sequence state"));
                }
                return {};
            }
            if (!envelope.session.has_value() || envelope.session->empty() || envelope.agent_epoch.empty() ||
                envelope.agent_epoch.size() > limits.maximum_string_bytes || !valid_utf8(envelope.agent_epoch)) {
                return std::unexpected(codec_error(ProtocolErrorCode::stale_session,
                                                   "post-handshake envelope lacks session or agent epoch"));
            }
            if (durable_agent_message(kind) != (envelope.agent_sequence != 0)) {
                return std::unexpected(
                    codec_error(ProtocolErrorCode::malformed, "durable sequence does not match message direction"));
            }
            if (kind == MessageKind::server_hello &&
                *envelope.session != std::get<ServerHelloMessage>(envelope.body).session) {
                return std::unexpected(
                    codec_error(ProtocolErrorCode::stale_session, "server hello envelope session does not match"));
            }
            if (kind == MessageKind::work_lease &&
                *envelope.session != std::get<WorkLeaseMessage>(envelope.body).session) {
                return std::unexpected(
                    codec_error(ProtocolErrorCode::stale_session, "work envelope session does not match"));
            }
            if (kind == MessageKind::cancel_work &&
                *envelope.session != std::get<CancelWorkMessage>(envelope.body).session) {
                return std::unexpected(
                    codec_error(ProtocolErrorCode::stale_session, "cancel envelope session does not match"));
            }
            if (kind == MessageKind::ack && envelope.agent_epoch != std::get<AckMessage>(envelope.body).agent_epoch) {
                return std::unexpected(
                    codec_error(ProtocolErrorCode::stale_session, "ACK envelope epoch does not match"));
            }
            if (kind == MessageKind::nack && envelope.agent_epoch != std::get<NackMessage>(envelope.body).agent_epoch) {
                return std::unexpected(
                    codec_error(ProtocolErrorCode::stale_session, "NACK envelope epoch does not match"));
            }
            return {};
        }

    } // namespace

    std::expected<std::vector<std::byte>, ProtocolError> encode_payload(const PeerEnvelope &envelope,
                                                                        const ProtocolLimits &limits) {
        if (auto valid = validate_envelope(envelope, limits); !valid) {
            return std::unexpected(std::move(valid.error()));
        }
        Writer writer;
        writer.unsigned_field(1, envelope.protocol_major);
        writer.unsigned_field(2, envelope.protocol_minor);
        writer.string_field(3, envelope.message_id);
        if (envelope.session.has_value()) {
            writer.string_field(4, envelope.session->value);
        }
        if (!envelope.agent_epoch.empty()) {
            writer.string_field(5, envelope.agent_epoch);
        }
        if (envelope.agent_sequence != 0) {
            writer.unsigned_field(6, envelope.agent_sequence);
        }
        if (envelope.acknowledged_agent_sequence != 0) {
            writer.unsigned_field(7, envelope.acknowledged_agent_sequence);
        }
        writer.unsigned_field(8, static_cast<std::uint8_t>(message_kind(envelope.body)));
        Writer body;
        if (auto encoded = encode_body(body, envelope.body, limits); !encoded) {
            return std::unexpected(std::move(encoded.error()));
        }
        writer.message_field(9, body);
        if (writer.bytes.size() > limits.maximum_frame_bytes) {
            return std::unexpected(
                codec_error(ProtocolErrorCode::limit_exceeded, "protocol payload exceeds the frame limit"));
        }
        // Decode our own canonical output once so encoder-side callers receive the
        // same per-field/depth/count validation as untrusted inputs.
        auto validated = decode_payload(writer.bytes, limits);
        if (!validated) {
            return std::unexpected(std::move(validated.error()));
        }
        return writer.bytes;
    }

    std::expected<PeerEnvelope, ProtocolError> decode_payload(const std::span<const std::byte> payload,
                                                              const ProtocolLimits &limits) {
        if (payload.empty() || payload.size() > limits.maximum_frame_bytes) {
            return std::unexpected(
                codec_error(payload.empty() ? ProtocolErrorCode::truncated : ProtocolErrorCode::limit_exceeded,
                            "protocol payload is empty or oversized"));
        }
        DecodeBudget budget;
        Reader reader {.bytes = payload, .limits = &limits, .budget = &budget, .depth = 0, .offset = 0};
        PeerEnvelope result;
        SeenFields seen;
        std::optional<MessageKind> kind;
        std::optional<std::span<const std::byte>> body_bytes;
        bool major_seen {};
        bool minor_seen {};
        while (!reader.eof()) {
            auto tag = reader.next_tag();
            if (!tag) {
                return std::unexpected(std::move(tag.error()));
            }
            if (tag->field > 9) {
                if (auto skipped = reader.skip(*tag); !skipped) {
                    return std::unexpected(std::move(skipped.error()));
                }
                continue;
            }
            if (auto marked = seen.mark(tag->field, reader.offset); !marked) {
                return std::unexpected(std::move(marked.error()));
            }
            if (tag->field == 3 || tag->field == 4 || tag->field == 5) {
                auto text = read_string(reader, *tag);
                if (!text) {
                    return std::unexpected(std::move(text.error()));
                }
                if (tag->field == 3) {
                    result.message_id = std::move(*text);
                } else if (tag->field == 4) {
                    result.session = SessionId {std::move(*text)};
                } else {
                    result.agent_epoch = std::move(*text);
                }
            } else if (tag->field == 9) {
                auto bytes = reader.read_bytes(*tag, limits.maximum_frame_bytes);
                if (!bytes) {
                    return std::unexpected(std::move(bytes.error()));
                }
                body_bytes = *bytes;
            } else {
                auto number = reader.read_unsigned(*tag);
                if (!number) {
                    return std::unexpected(std::move(number.error()));
                }
                switch (tag->field) {
                    case 1:
                        if (*number > std::numeric_limits<std::uint16_t>::max()) {
                            return std::unexpected(codec_error(ProtocolErrorCode::limit_exceeded,
                                                               "protocol major exceeds uint16", reader.offset));
                        }
                        result.protocol_major = static_cast<std::uint16_t>(*number);
                        major_seen = true;
                        break;
                    case 2:
                        if (*number > std::numeric_limits<std::uint16_t>::max()) {
                            return std::unexpected(codec_error(ProtocolErrorCode::limit_exceeded,
                                                               "protocol minor exceeds uint16", reader.offset));
                        }
                        result.protocol_minor = static_cast<std::uint16_t>(*number);
                        minor_seen = true;
                        break;
                    case 6: result.agent_sequence = *number; break;
                    case 7: result.acknowledged_agent_sequence = *number; break;
                    case 8:
                        if (*number < static_cast<std::uint8_t>(MessageKind::agent_hello) ||
                            *number > static_cast<std::uint8_t>(MessageKind::credit_update)) {
                            return std::unexpected(codec_error(ProtocolErrorCode::unexpected_message,
                                                               "protocol message kind is unknown", reader.offset));
                        }
                        kind = static_cast<MessageKind>(*number);
                        break;
                    default:
                        return std::unexpected(
                            codec_error(ProtocolErrorCode::malformed, "unexpected envelope field", reader.offset));
                }
            }
        }
        if (!major_seen || !minor_seen || !kind.has_value() || !body_bytes.has_value()) {
            return std::unexpected(
                codec_error(ProtocolErrorCode::malformed, "protocol envelope is incomplete", reader.offset));
        }
        Reader body_reader {.bytes = *body_bytes, .limits = &limits, .budget = &budget, .depth = 1, .offset = 0};
        auto body = decode_body(*kind, body_reader);
        if (!body) {
            return std::unexpected(std::move(body.error()));
        }
        result.body = std::move(*body);
        if (auto valid = validate_envelope(result, limits); !valid) {
            return std::unexpected(std::move(valid.error()));
        }
        return result;
    }

    std::expected<std::vector<std::byte>, ProtocolError> encode_frame(const PeerEnvelope &envelope,
                                                                      const ProtocolLimits &limits) {
        auto payload = encode_payload(envelope, limits);
        if (!payload) {
            return std::unexpected(std::move(payload.error()));
        }
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

    std::expected<std::vector<std::byte>, ProtocolError> encode_durable_body(const DurableAgentBody &body,
                                                                             const ProtocolLimits &limits) {
        const auto message = std::visit([](const auto &value) -> MessageBody { return value; }, body);
        const auto kind = message_kind(message);
        if (!durable_agent_message(kind)) {
            return std::unexpected(
                codec_error(ProtocolErrorCode::unexpected_message, "spool body is not durable agent data"));
        }

        Writer body_writer;
        if (auto encoded = encode_body(body_writer, message, limits); !encoded) {
            return std::unexpected(std::move(encoded.error()));
        }
        Writer writer;
        writer.unsigned_field(1, static_cast<std::uint8_t>(kind));
        writer.message_field(2, body_writer);
        if (writer.bytes.empty() || writer.bytes.size() > limits.maximum_frame_bytes) {
            return std::unexpected(
                codec_error(ProtocolErrorCode::limit_exceeded, "durable spool body exceeds the frame limit"));
        }
        auto validated = decode_durable_body(writer.bytes, limits);
        if (!validated) {
            return std::unexpected(std::move(validated.error()));
        }
        return writer.bytes;
    }

    std::expected<DurableAgentBody, ProtocolError> decode_durable_body(const std::span<const std::byte> bytes,
                                                                       const ProtocolLimits &limits) {
        if (bytes.empty() || bytes.size() > limits.maximum_frame_bytes) {
            return std::unexpected(
                codec_error(bytes.empty() ? ProtocolErrorCode::truncated : ProtocolErrorCode::limit_exceeded,
                            "durable spool body is empty or oversized"));
        }
        DecodeBudget budget;
        Reader reader {.bytes = bytes, .limits = &limits, .budget = &budget, .depth = 0, .offset = 0};
        SeenFields seen;
        std::optional<MessageKind> kind;
        std::optional<std::span<const std::byte>> body_bytes;
        while (!reader.eof()) {
            auto tag = reader.next_tag();
            if (!tag) {
                return std::unexpected(std::move(tag.error()));
            }
            if (tag->field > 2) {
                if (auto skipped = reader.skip(*tag); !skipped) {
                    return std::unexpected(std::move(skipped.error()));
                }
                continue;
            }
            if (auto marked = seen.mark(tag->field, reader.offset); !marked) {
                return std::unexpected(std::move(marked.error()));
            }
            if (tag->field == 1) {
                auto number = reader.read_unsigned(*tag);
                if (!number || *number > static_cast<std::uint8_t>(MessageKind::credit_update)) {
                    return std::unexpected(number ? codec_error(ProtocolErrorCode::unexpected_message,
                                                                "durable spool message kind is unknown") :
                                                    std::move(number.error()));
                }
                kind = static_cast<MessageKind>(*number);
                continue;
            }
            auto encoded = reader.read_bytes(*tag, limits.maximum_frame_bytes);
            if (!encoded) {
                return std::unexpected(std::move(encoded.error()));
            }
            body_bytes = *encoded;
        }
        if (!kind.has_value() || !body_bytes.has_value() || !durable_agent_message(*kind)) {
            return std::unexpected(
                codec_error(ProtocolErrorCode::unexpected_message, "durable spool body kind is missing or invalid"));
        }
        Reader body_reader {.bytes = *body_bytes, .limits = &limits, .budget = &budget, .depth = 1, .offset = 0};
        auto decoded = decode_body(*kind, body_reader);
        if (!decoded) {
            return std::unexpected(std::move(decoded.error()));
        }
        switch (*kind) {
            case MessageKind::work_result: return DurableAgentBody {std::get<WorkResultMessage>(std::move(*decoded))};
            case MessageKind::snapshot_begin:
                return DurableAgentBody {std::get<AuthoritativeSnapshotBegin>(std::move(*decoded))};
            case MessageKind::snapshot_chunk:
                return DurableAgentBody {std::get<AuthoritativeSnapshotChunk>(std::move(*decoded))};
            case MessageKind::snapshot_commit:
                return DurableAgentBody {std::get<AuthoritativeSnapshotCommit>(std::move(*decoded))};
            case MessageKind::agent_hello:
            case MessageKind::server_hello:
            case MessageKind::work_lease:
            case MessageKind::cancel_work:
            case MessageKind::ack:
            case MessageKind::nack:
            case MessageKind::credit_update: break;
            default: break;
        }
        return std::unexpected(
            codec_error(ProtocolErrorCode::unexpected_message, "durable spool body kind is not supported"));
    }

    std::expected<DecodedFrame, ProtocolError> decode_frame(const std::span<const std::byte> bytes,
                                                            const ProtocolLimits &limits) {
        if (bytes.size() < 4) {
            return std::unexpected(codec_error(ProtocolErrorCode::truncated, "frame header is truncated"));
        }
        const auto size = (std::to_integer<std::uint32_t>(bytes[0]) << 24U) |
                          (std::to_integer<std::uint32_t>(bytes[1]) << 16U) |
                          (std::to_integer<std::uint32_t>(bytes[2]) << 8U) | std::to_integer<std::uint32_t>(bytes[3]);
        if (size == 0 || size > limits.maximum_frame_bytes) {
            return std::unexpected(
                codec_error(size == 0 ? ProtocolErrorCode::malformed : ProtocolErrorCode::limit_exceeded,
                            "frame length is zero or exceeds the limit"));
        }
        if (size > bytes.size() - 4) {
            return std::unexpected(codec_error(ProtocolErrorCode::truncated, "frame payload is truncated"));
        }
        auto envelope = decode_payload(bytes.subspan(4, size), limits);
        if (!envelope) {
            return std::unexpected(std::move(envelope.error()));
        }
        return DecodedFrame {.envelope = std::move(*envelope), .bytes_consumed = static_cast<std::size_t>(size) + 4};
    }

} // namespace rule_engine::python::protocol_v2
