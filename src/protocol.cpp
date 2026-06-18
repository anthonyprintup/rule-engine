#include <rule_engine/protocol.hpp>

#include <array>
#include <bit>
#include <limits>
#include <optional>
#include <string_view>
#include <utility>

namespace rule_engine::protocol {
    namespace {
        enum struct MessageKind : std::uint8_t {
            handshake = 1,
            subject_list = 2,
            fact_batch_request = 3,
            fact_batch_response = 4,
            candidate_provider_request = 5,
            candidate_provider_response = 6,
        };

        enum struct ValueKind : std::uint8_t {
            undefined = 0,
            boolean = 1,
            integer = 2,
            floating = 3,
            string = 4,
            pattern = 5,
            bytes = 6,
            array = 7,
            object = 8,
        };

        constexpr std::uint32_t protocol_version {1};
        constexpr std::uint32_t max_collection_count {65536};
        constexpr std::uint32_t max_value_nesting_depth {32};

        void append_u8(std::vector<std::byte> &out, const std::uint8_t value) {
            out.push_back(static_cast<std::byte>(value));
        }

        void append_u32(std::vector<std::byte> &out, const std::uint32_t value) {
            out.push_back(static_cast<std::byte>(value & 0xffu));
            out.push_back(static_cast<std::byte>((value >> 8u) & 0xffu));
            out.push_back(static_cast<std::byte>((value >> 16u) & 0xffu));
            out.push_back(static_cast<std::byte>((value >> 24u) & 0xffu));
        }

        void append_u64(std::vector<std::byte> &out, const std::uint64_t value) {
            for (std::uint32_t shift = 0; shift < 64u; shift += 8u) {
                out.push_back(static_cast<std::byte>((value >> shift) & 0xffu));
            }
        }

        void append_i64(std::vector<std::byte> &out, const std::int64_t value) {
            append_u64(out, static_cast<std::uint64_t>(value));
        }

        [[nodiscard]] std::expected<void, ErrorSet> append_string(std::vector<std::byte> &out,
                                                                  const std::string_view value) {
            if (value.size() > std::numeric_limits<std::uint32_t>::max()) {
                return std::unexpected(single_error("protocol", "string exceeds v1 message size"));
            }
            append_u32(out, static_cast<std::uint32_t>(value.size()));
            for (const auto ch : value) {
                out.push_back(static_cast<std::byte>(static_cast<unsigned char>(ch)));
            }
            return {};
        }

        [[nodiscard]] std::expected<void, ErrorSet> append_bytes(std::vector<std::byte> &out,
                                                                 const std::span<const std::byte> value) {
            if (value.size() > std::numeric_limits<std::uint32_t>::max()) {
                return std::unexpected(single_error("protocol", "byte vector exceeds v1 message size"));
            }
            append_u32(out, static_cast<std::uint32_t>(value.size()));
            out.insert(out.end(), value.begin(), value.end());
            return {};
        }

        [[nodiscard]] std::expected<void, ErrorSet> validate_count(const std::uint32_t count,
                                                                   const std::string_view what) {
            if (count > max_collection_count) {
                return std::unexpected(single_error("protocol",
                                                    std::string {what} + " count exceeds v1 limit"));
            }
            return {};
        }

        void append_header(std::vector<std::byte> &out, const MessageKind kind) {
            out.push_back(static_cast<std::byte>('R'));
            out.push_back(static_cast<std::byte>('E'));
            out.push_back(static_cast<std::byte>('P'));
            out.push_back(static_cast<std::byte>('V'));
            append_u8(out, static_cast<std::uint8_t>(kind));
            append_u32(out, protocol_version);
        }

        [[nodiscard]] std::uint8_t status_to_wire(const FactStatus status) noexcept {
            switch (status) {
                case FactStatus::missing: return 0u;
                case FactStatus::available: return 1u;
                case FactStatus::unavailable: return 2u;
                case FactStatus::access_denied: return 3u;
                case FactStatus::timed_out: return 4u;
                default: return 0u;
            }
        }

        [[nodiscard]] std::optional<FactStatus> status_from_wire(const std::uint8_t value) noexcept {
            switch (value) {
                case 0u: return FactStatus::missing;
                case 1u: return FactStatus::available;
                case 2u: return FactStatus::unavailable;
                case 3u: return FactStatus::access_denied;
                case 4u: return FactStatus::timed_out;
                default: return std::nullopt;
            }
        }

        [[nodiscard]] std::uint8_t value_type_to_wire(const ValueType type) noexcept {
            switch (type) {
                case ValueType::boolean: return 1u;
                case ValueType::integer: return 2u;
                case ValueType::floating: return 3u;
                case ValueType::string: return 4u;
                case ValueType::bytes: return 5u;
                case ValueType::array: return 6u;
                case ValueType::pattern: return 7u;
                case ValueType::object: return 8u;
                case ValueType::undefined:
                default: return 0u;
            }
        }

        [[nodiscard]] std::optional<ValueType> value_type_from_wire(const std::uint8_t value) noexcept {
            switch (value) {
                case 0u: return ValueType::undefined;
                case 1u: return ValueType::boolean;
                case 2u: return ValueType::integer;
                case 3u: return ValueType::floating;
                case 4u: return ValueType::string;
                case 5u: return ValueType::bytes;
                case 6u: return ValueType::array;
                case 7u: return ValueType::pattern;
                case 8u: return ValueType::object;
                default: return std::nullopt;
            }
        }

        struct Reader {
            std::span<const std::byte> bytes;
            std::size_t offset {};

            [[nodiscard]] bool read_u8(std::uint8_t &out) noexcept {
                if (offset + 1u > bytes.size()) {
                    return false;
                }
                out = static_cast<std::uint8_t>(bytes[offset]);
                ++offset;
                return true;
            }

            [[nodiscard]] bool read_u32(std::uint32_t &out) noexcept {
                if (offset + 4u > bytes.size()) {
                    return false;
                }
                out = static_cast<std::uint32_t>(bytes[offset]) |
                      (static_cast<std::uint32_t>(bytes[offset + 1u]) << 8u) |
                      (static_cast<std::uint32_t>(bytes[offset + 2u]) << 16u) |
                      (static_cast<std::uint32_t>(bytes[offset + 3u]) << 24u);
                offset += 4u;
                return true;
            }

            [[nodiscard]] bool read_u64(std::uint64_t &out) noexcept {
                if (offset + 8u > bytes.size()) {
                    return false;
                }
                out = {};
                for (std::uint32_t shift = 0; shift < 64u; shift += 8u) {
                    out |= static_cast<std::uint64_t>(bytes[offset]) << shift;
                    ++offset;
                }
                return true;
            }

            [[nodiscard]] bool read_i64(std::int64_t &out) noexcept {
                std::uint64_t bits {};
                if (!read_u64(bits)) {
                    return false;
                }
                out = static_cast<std::int64_t>(bits);
                return true;
            }

            [[nodiscard]] bool read_string(std::string &out) {
                std::uint32_t size {};
                if (!read_u32(size) || offset + size > bytes.size()) {
                    return false;
                }
                const auto first = reinterpret_cast<const char *>(bytes.data() + offset);
                out.assign(first, first + size);
                offset += size;
                return true;
            }

            [[nodiscard]] bool read_bytes(std::vector<std::byte> &out) {
                std::uint32_t size {};
                if (!read_u32(size) || offset + size > bytes.size()) {
                    return false;
                }
                out.assign(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                           bytes.begin() + static_cast<std::ptrdiff_t>(offset + size));
                offset += size;
                return true;
            }
        };

        [[nodiscard]] std::expected<Reader, ErrorSet> reader_for(std::span<const std::byte> payload,
                                                                 const MessageKind expected_kind) {
            Reader reader {.bytes = payload};
            if (payload.size() < 9u || payload[0] != static_cast<std::byte>('R') ||
                payload[1] != static_cast<std::byte>('E') || payload[2] != static_cast<std::byte>('P') ||
                payload[3] != static_cast<std::byte>('V')) {
                return std::unexpected(single_error("protocol", "invalid protocol message header"));
            }
            reader.offset = 4u;
            std::uint8_t kind {};
            std::uint32_t version {};
            if (!reader.read_u8(kind) || !reader.read_u32(version)) {
                return std::unexpected(single_error("protocol", "truncated protocol message header"));
            }
            if (kind != static_cast<std::uint8_t>(expected_kind)) {
                return std::unexpected(single_error("protocol", "unexpected protocol message type"));
            }
            if (version != protocol_version) {
                return std::unexpected(single_error("protocol", "unsupported protocol message version"));
            }
            return reader;
        }

        [[nodiscard]] std::expected<void, ErrorSet> append_value(std::vector<std::byte> &out,
                                                                 const Value &value,
                                                                 const std::uint32_t depth = 0u) {
            if (depth > max_value_nesting_depth) {
                return std::unexpected(single_error("protocol", "fact value nesting exceeds v1 limit"));
            }
            if (value.is_undefined()) {
                append_u8(out, static_cast<std::uint8_t>(ValueKind::undefined));
                return {};
            }
            if (const auto boolean = value.as_bool(); boolean.has_value()) {
                append_u8(out, static_cast<std::uint8_t>(ValueKind::boolean));
                append_u8(out, *boolean ? 1u : 0u);
                return {};
            }
            if (const auto integer = value.as_i64(); integer.has_value()) {
                append_u8(out, static_cast<std::uint8_t>(ValueKind::integer));
                append_i64(out, *integer);
                return {};
            }
            if (const auto floating = value.as_f64(); floating.has_value()) {
                append_u8(out, static_cast<std::uint8_t>(ValueKind::floating));
                append_u64(out, std::bit_cast<std::uint64_t>(*floating));
                return {};
            }
            if (const auto *string = value.as_string(); string != nullptr) {
                append_u8(out, static_cast<std::uint8_t>(ValueKind::string));
                return append_string(out, *string);
            }
            if (const auto *bytes = value.as_bytes(); bytes != nullptr) {
                append_u8(out, static_cast<std::uint8_t>(ValueKind::bytes));
                return append_bytes(out, *bytes);
            }
            if (const auto *pattern = value.as_pattern(); pattern != nullptr) {
                if (pattern->matches.size() > std::numeric_limits<std::uint32_t>::max()) {
                    return std::unexpected(single_error("protocol", "pattern match count exceeds v1 message size"));
                }
                append_u8(out, static_cast<std::uint8_t>(ValueKind::pattern));
                append_u8(out, pattern->matched ? 1u : 0u);
                append_u32(out, static_cast<std::uint32_t>(pattern->matches.size()));
                for (const auto &match : pattern->matches) {
                    append_u64(out, match.offset);
                    append_u64(out, match.length);
                    if (auto result = append_bytes(out, match.bytes); !result) {
                        return result;
                    }
                    if (auto result = append_bytes(out, match.before); !result) {
                        return result;
                    }
                    if (auto result = append_bytes(out, match.after); !result) {
                        return result;
                    }
                    if (auto result = append_string(out, match.scan_space); !result) {
                        return result;
                    }
                    if (auto result = append_string(out, match.region_permissions); !result) {
                        return result;
                    }
                }
                return {};
            }
            if (const auto *array = value.as_array(); array != nullptr) {
                if (array->values.size() > max_collection_count) {
                    return std::unexpected(single_error("protocol", "array value count exceeds v1 limit"));
                }
                append_u8(out, static_cast<std::uint8_t>(ValueKind::array));
                append_u32(out, static_cast<std::uint32_t>(array->values.size()));
                for (const auto &entry : array->values) {
                    if (auto result = append_value(out, entry, depth + 1u); !result) {
                        return result;
                    }
                }
                return {};
            }
            if (const auto *object = value.as_object(); object != nullptr) {
                if (object->entries.size() > max_collection_count) {
                    return std::unexpected(single_error("protocol", "object value count exceeds v1 limit"));
                }
                append_u8(out, static_cast<std::uint8_t>(ValueKind::object));
                append_u32(out, static_cast<std::uint32_t>(object->entries.size()));
                for (const auto &entry : object->entries) {
                    if (auto result = append_string(out, entry.key); !result) {
                        return result;
                    }
                    if (auto result = append_value(out, entry.value, depth + 1u); !result) {
                        return result;
                    }
                }
                return {};
            }
            return std::unexpected(single_error("protocol", "unsupported v1 fact value type"));
        }

        [[nodiscard]] std::expected<Value, ErrorSet> read_value(Reader &reader, const std::uint32_t depth = 0u) {
            if (depth > max_value_nesting_depth) {
                return std::unexpected(single_error("protocol", "fact value nesting exceeds v1 limit"));
            }
            std::uint8_t kind {};
            if (!reader.read_u8(kind)) {
                return std::unexpected(single_error("protocol", "truncated fact value type"));
            }

            if (kind == static_cast<std::uint8_t>(ValueKind::undefined)) {
                return Value::undefined();
            }
            if (kind == static_cast<std::uint8_t>(ValueKind::boolean)) {
                std::uint8_t value {};
                if (!reader.read_u8(value)) {
                    return std::unexpected(single_error("protocol", "truncated boolean fact value"));
                }
                return Value::boolean(value != 0u);
            }
            if (kind == static_cast<std::uint8_t>(ValueKind::integer)) {
                std::int64_t value {};
                if (!reader.read_i64(value)) {
                    return std::unexpected(single_error("protocol", "truncated integer fact value"));
                }
                return Value::integer(value);
            }
            if (kind == static_cast<std::uint8_t>(ValueKind::floating)) {
                std::uint64_t bits {};
                if (!reader.read_u64(bits)) {
                    return std::unexpected(single_error("protocol", "truncated floating fact value"));
                }
                return Value::number(std::bit_cast<double>(bits));
            }
            if (kind == static_cast<std::uint8_t>(ValueKind::string)) {
                std::string value;
                if (!reader.read_string(value)) {
                    return std::unexpected(single_error("protocol", "truncated string fact value"));
                }
                return Value::string(std::move(value));
            }
            if (kind == static_cast<std::uint8_t>(ValueKind::bytes)) {
                std::vector<std::byte> value;
                if (!reader.read_bytes(value)) {
                    return std::unexpected(single_error("protocol", "truncated byte fact value"));
                }
                return Value::bytes(std::move(value));
            }
            if (kind == static_cast<std::uint8_t>(ValueKind::pattern)) {
                std::uint8_t matched {};
                std::uint32_t count {};
                if (!reader.read_u8(matched) || !reader.read_u32(count)) {
                    return std::unexpected(single_error("protocol", "truncated pattern fact value"));
                }
                PatternValue pattern;
                pattern.matched = matched != 0u;
                if (auto count_ok = validate_count(count, "pattern match"); !count_ok) {
                    return std::unexpected(std::move(count_ok.error()));
                }
                pattern.matches.reserve(count);
                for (std::uint32_t index = 0; index < count; ++index) {
                    PatternMatchContext match;
                    if (!reader.read_u64(match.offset) || !reader.read_u64(match.length) ||
                        !reader.read_bytes(match.bytes) || !reader.read_bytes(match.before) ||
                        !reader.read_bytes(match.after) || !reader.read_string(match.scan_space) ||
                        !reader.read_string(match.region_permissions)) {
                        return std::unexpected(single_error("protocol", "truncated pattern match context"));
                    }
                    pattern.matches.push_back(std::move(match));
                }
                return Value::pattern(std::move(pattern));
            }
            if (kind == static_cast<std::uint8_t>(ValueKind::array)) {
                std::uint32_t count {};
                if (!reader.read_u32(count)) {
                    return std::unexpected(single_error("protocol", "truncated array fact value"));
                }
                if (auto count_ok = validate_count(count, "array value"); !count_ok) {
                    return std::unexpected(std::move(count_ok.error()));
                }
                std::vector<Value> values;
                values.reserve(count);
                for (std::uint32_t index = 0; index < count; ++index) {
                    auto value = read_value(reader, depth + 1u);
                    if (!value) {
                        return std::unexpected(std::move(value.error()));
                    }
                    values.push_back(std::move(*value));
                }
                return Value::array(std::move(values));
            }
            if (kind == static_cast<std::uint8_t>(ValueKind::object)) {
                std::uint32_t count {};
                if (!reader.read_u32(count)) {
                    return std::unexpected(single_error("protocol", "truncated object fact value"));
                }
                if (auto count_ok = validate_count(count, "object value"); !count_ok) {
                    return std::unexpected(std::move(count_ok.error()));
                }
                std::vector<ObjectEntry> entries;
                entries.reserve(count);
                for (std::uint32_t index = 0; index < count; ++index) {
                    ObjectEntry entry;
                    if (!reader.read_string(entry.key)) {
                        return std::unexpected(single_error("protocol", "truncated object fact entry"));
                    }
                    auto value = read_value(reader, depth + 1u);
                    if (!value) {
                        return std::unexpected(std::move(value.error()));
                    }
                    entry.value = std::move(*value);
                    entries.push_back(std::move(entry));
                }
                return Value::object(std::move(entries));
            }
            return std::unexpected(single_error("protocol", "unknown fact value type"));
        }

        [[nodiscard]] std::expected<void, ErrorSet> append_fact(std::vector<std::byte> &out, const Fact &fact) {
            if (auto result = append_string(out, fact.subject_id); !result) {
                return result;
            }
            if (auto result = append_string(out, fact.key); !result) {
                return result;
            }
            append_u8(out, status_to_wire(fact.status));
            if (auto result = append_value(out, fact.value); !result) {
                return result;
            }
            if (auto result = append_string(out, fact.diagnostic); !result) {
                return result;
            }
            append_u32(out, static_cast<std::uint32_t>(fact.ttl.count()));
            return {};
        }

        [[nodiscard]] std::expected<Fact, ErrorSet> read_fact(Reader &reader) {
            Fact fact;
            if (!reader.read_string(fact.subject_id) || !reader.read_string(fact.key)) {
                return std::unexpected(single_error("protocol", "truncated fact identity"));
            }
            std::uint8_t status {};
            if (!reader.read_u8(status)) {
                return std::unexpected(single_error("protocol", "truncated fact status"));
            }
            const auto parsed_status = status_from_wire(status);
            if (!parsed_status.has_value()) {
                return std::unexpected(single_error("protocol", "unknown fact status"));
            }
            fact.status = *parsed_status;
            auto value = read_value(reader);
            if (!value) {
                return std::unexpected(std::move(value.error()));
            }
            fact.value = std::move(*value);
            if (!reader.read_string(fact.diagnostic)) {
                return std::unexpected(single_error("protocol", "truncated fact diagnostic"));
            }
            std::uint32_t ttl {};
            if (!reader.read_u32(ttl)) {
                return std::unexpected(single_error("protocol", "truncated fact ttl"));
            }
            fact.ttl = std::chrono::seconds {ttl};
            return fact;
        }
    } // namespace

    std::expected<std::vector<std::byte>, ErrorSet> encode_handshake(const HandshakeMessage &message) {
        std::vector<std::byte> out;
        append_header(out, MessageKind::handshake);
        if (auto result = append_string(out, message.protocol); !result) {
            return std::unexpected(std::move(result.error()));
        }
        append_u32(out, message.version);
        append_u32(out, static_cast<std::uint32_t>(message.capabilities.size()));
        for (const auto &capability : message.capabilities) {
            if (auto result = append_string(out, capability.route); !result) {
                return std::unexpected(std::move(result.error()));
            }
            if (auto result = append_string(out, capability.filter_key); !result) {
                return std::unexpected(std::move(result.error()));
            }
            append_u32(out, static_cast<std::uint32_t>(capability.argument_types.size()));
            for (const auto type : capability.argument_types) {
                append_u8(out, value_type_to_wire(type));
            }
            if (auto result = append_string(out, capability.result_kind); !result) {
                return std::unexpected(std::move(result.error()));
            }
        }
        return out;
    }

    std::expected<HandshakeMessage, ErrorSet> decode_handshake(const std::span<const std::byte> payload) {
        auto reader = reader_for(payload, MessageKind::handshake);
        if (!reader) {
            return std::unexpected(std::move(reader.error()));
        }
        HandshakeMessage out;
        std::uint32_t capability_count {};
        if (!reader->read_string(out.protocol) || !reader->read_u32(out.version) ||
            !reader->read_u32(capability_count)) {
            return std::unexpected(single_error("protocol", "truncated handshake message"));
        }
        if (auto count_ok = validate_count(capability_count, "handshake capability"); !count_ok) {
            return std::unexpected(std::move(count_ok.error()));
        }
        out.capabilities.reserve(capability_count);
        for (std::uint32_t index = 0; index < capability_count; ++index) {
            Capability capability;
            std::uint32_t argument_type_count {};
            if (!reader->read_string(capability.route) || !reader->read_string(capability.filter_key) ||
                !reader->read_u32(argument_type_count)) {
                return std::unexpected(single_error("protocol", "truncated handshake capability"));
            }
            if (auto count_ok = validate_count(argument_type_count, "handshake capability argument type"); !count_ok) {
                return std::unexpected(std::move(count_ok.error()));
            }
            capability.argument_types.reserve(argument_type_count);
            for (std::uint32_t type_index = 0; type_index < argument_type_count; ++type_index) {
                std::uint8_t type {};
                if (!reader->read_u8(type)) {
                    return std::unexpected(single_error("protocol", "truncated handshake capability argument type"));
                }
                const auto parsed_type = value_type_from_wire(type);
                if (!parsed_type.has_value()) {
                    return std::unexpected(single_error("protocol", "unknown handshake capability argument type"));
                }
                capability.argument_types.push_back(*parsed_type);
            }
            if (!reader->read_string(capability.result_kind)) {
                return std::unexpected(single_error("protocol", "truncated handshake capability result kind"));
            }
            out.capabilities.push_back(std::move(capability));
        }
        return out;
    }

    std::expected<std::vector<std::byte>, ErrorSet> encode_subject_list(const SubjectListMessage &message) {
        std::vector<std::byte> out;
        append_header(out, MessageKind::subject_list);
        append_u32(out, static_cast<std::uint32_t>(message.subjects.size()));
        for (const auto &subject : message.subjects) {
            if (auto result = append_string(out, subject.kind); !result) {
                return std::unexpected(std::move(result.error()));
            }
            if (auto result = append_string(out, subject.id); !result) {
                return std::unexpected(std::move(result.error()));
            }
        }
        return out;
    }

    std::expected<SubjectListMessage, ErrorSet> decode_subject_list(const std::span<const std::byte> payload) {
        auto reader = reader_for(payload, MessageKind::subject_list);
        if (!reader) {
            return std::unexpected(std::move(reader.error()));
        }
        std::uint32_t subject_count {};
        if (!reader->read_u32(subject_count)) {
            return std::unexpected(single_error("protocol", "truncated subject list message"));
        }
        SubjectListMessage out;
        if (auto count_ok = validate_count(subject_count, "subject"); !count_ok) {
            return std::unexpected(std::move(count_ok.error()));
        }
        out.subjects.reserve(subject_count);
        for (std::uint32_t index = 0; index < subject_count; ++index) {
            Subject subject;
            if (!reader->read_string(subject.kind) || !reader->read_string(subject.id)) {
                return std::unexpected(single_error("protocol", "truncated subject entry"));
            }
            out.subjects.push_back(std::move(subject));
        }
        return out;
    }

    std::expected<std::vector<std::byte>, ErrorSet>
    encode_fact_batch_request(const FactBatchRequestMessage &message) {
        std::vector<std::byte> out;
        append_header(out, MessageKind::fact_batch_request);
        if (auto result = append_string(out, message.route); !result) {
            return std::unexpected(std::move(result.error()));
        }
        append_u32(out, static_cast<std::uint32_t>(message.timeout.count()));
        append_u32(out, static_cast<std::uint32_t>(message.keys.size()));
        for (const auto &key : message.keys) {
            if (auto result = append_string(out, key.subject_id); !result) {
                return std::unexpected(std::move(result.error()));
            }
            if (auto result = append_string(out, key.key); !result) {
                return std::unexpected(std::move(result.error()));
            }
        }
        append_u32(out, static_cast<std::uint32_t>(message.expected_types.size()));
        for (const auto type : message.expected_types) {
            append_u8(out, value_type_to_wire(type));
        }
        append_u32(out, static_cast<std::uint32_t>(message.scan_plans.size()));
        for (const auto &scan_plan : message.scan_plans) {
            if (auto result = append_string(out, scan_plan.pattern_key); !result) {
                return std::unexpected(std::move(result.error()));
            }
            if (auto result = append_bytes(out, scan_plan.literal); !result) {
                return std::unexpected(std::move(result.error()));
            }
        }
        return out;
    }

    std::expected<FactBatchRequestMessage, ErrorSet>
    decode_fact_batch_request(const std::span<const std::byte> payload) {
        auto reader = reader_for(payload, MessageKind::fact_batch_request);
        if (!reader) {
            return std::unexpected(std::move(reader.error()));
        }
        std::uint32_t timeout {};
        std::uint32_t key_count {};
        FactBatchRequestMessage out;
        if (!reader->read_string(out.route) || !reader->read_u32(timeout) || !reader->read_u32(key_count)) {
            return std::unexpected(single_error("protocol", "truncated fact request message"));
        }
        out.timeout = std::chrono::milliseconds {timeout};
        if (auto count_ok = validate_count(key_count, "fact request key"); !count_ok) {
            return std::unexpected(std::move(count_ok.error()));
        }
        out.keys.reserve(key_count);
        for (std::uint32_t index = 0; index < key_count; ++index) {
            FactKey key;
            if (!reader->read_string(key.subject_id) || !reader->read_string(key.key)) {
                return std::unexpected(single_error("protocol", "truncated fact request key"));
            }
            out.keys.push_back(std::move(key));
        }
        std::uint32_t expected_type_count {};
        if (!reader->read_u32(expected_type_count)) {
            return std::unexpected(single_error("protocol", "truncated fact request expected type count"));
        }
        if (auto count_ok = validate_count(expected_type_count, "fact request expected type"); !count_ok) {
            return std::unexpected(std::move(count_ok.error()));
        }
        out.expected_types.reserve(expected_type_count);
        for (std::uint32_t index = 0; index < expected_type_count; ++index) {
            std::uint8_t type {};
            if (!reader->read_u8(type)) {
                return std::unexpected(single_error("protocol", "truncated fact request expected type"));
            }
            const auto parsed_type = value_type_from_wire(type);
            if (!parsed_type.has_value()) {
                return std::unexpected(single_error("protocol", "unknown fact request expected type"));
            }
            out.expected_types.push_back(*parsed_type);
        }
        std::uint32_t scan_plan_count {};
        if (!reader->read_u32(scan_plan_count)) {
            return std::unexpected(single_error("protocol", "truncated fact request scan plan count"));
        }
        if (auto count_ok = validate_count(scan_plan_count, "fact request scan plan"); !count_ok) {
            return std::unexpected(std::move(count_ok.error()));
        }
        out.scan_plans.reserve(scan_plan_count);
        for (std::uint32_t index = 0; index < scan_plan_count; ++index) {
            PatternScanPlan scan_plan;
            if (!reader->read_string(scan_plan.pattern_key) || !reader->read_bytes(scan_plan.literal)) {
                return std::unexpected(single_error("protocol", "truncated fact request scan plan"));
            }
            out.scan_plans.push_back(std::move(scan_plan));
        }
        return out;
    }

    std::expected<std::vector<std::byte>, ErrorSet>
    encode_fact_batch_response(const FactBatchResponseMessage &message) {
        std::vector<std::byte> out;
        append_header(out, MessageKind::fact_batch_response);
        if (auto result = append_string(out, message.route); !result) {
            return std::unexpected(std::move(result.error()));
        }
        append_u32(out, static_cast<std::uint32_t>(message.values.size()));
        for (const auto &fact : message.values) {
            if (auto result = append_fact(out, fact); !result) {
                return std::unexpected(std::move(result.error()));
            }
        }
        return out;
    }

    std::expected<FactBatchResponseMessage, ErrorSet>
    decode_fact_batch_response(const std::span<const std::byte> payload) {
        auto reader = reader_for(payload, MessageKind::fact_batch_response);
        if (!reader) {
            return std::unexpected(std::move(reader.error()));
        }
        std::uint32_t value_count {};
        FactBatchResponseMessage out;
        if (!reader->read_string(out.route) || !reader->read_u32(value_count)) {
            return std::unexpected(single_error("protocol", "truncated fact response message"));
        }
        if (auto count_ok = validate_count(value_count, "fact response value"); !count_ok) {
            return std::unexpected(std::move(count_ok.error()));
        }
        out.values.reserve(value_count);
        for (std::uint32_t index = 0; index < value_count; ++index) {
            auto fact = read_fact(*reader);
            if (!fact) {
                return std::unexpected(std::move(fact.error()));
            }
            out.values.push_back(std::move(*fact));
        }
        return out;
    }

    std::expected<std::vector<std::byte>, ErrorSet>
    encode_candidate_provider_request(const CandidateProviderRequestMessage &message) {
        std::vector<std::byte> out;
        append_header(out, MessageKind::candidate_provider_request);
        if (auto result = append_string(out, message.route); !result) {
            return std::unexpected(std::move(result.error()));
        }
        append_u32(out, static_cast<std::uint32_t>(message.timeout.count()));
        append_u32(out, static_cast<std::uint32_t>(message.filters.size()));
        for (const auto &filter : message.filters) {
            if (auto result = append_string(out, filter.request_id); !result) {
                return std::unexpected(std::move(result.error()));
            }
            if (auto result = append_string(out, filter.filter_key); !result) {
                return std::unexpected(std::move(result.error()));
            }
            if (auto result = append_string(out, filter.argument_kind); !result) {
                return std::unexpected(std::move(result.error()));
            }
            if (auto result = append_string(out, filter.argument_value); !result) {
                return std::unexpected(std::move(result.error()));
            }
        }
        return out;
    }

    std::expected<CandidateProviderRequestMessage, ErrorSet>
    decode_candidate_provider_request(const std::span<const std::byte> payload) {
        auto reader = reader_for(payload, MessageKind::candidate_provider_request);
        if (!reader) {
            return std::unexpected(std::move(reader.error()));
        }
        std::uint32_t timeout {};
        std::uint32_t filter_count {};
        CandidateProviderRequestMessage out;
        if (!reader->read_string(out.route) || !reader->read_u32(timeout) || !reader->read_u32(filter_count)) {
            return std::unexpected(single_error("protocol", "truncated candidate provider request message"));
        }
        out.timeout = std::chrono::milliseconds {timeout};
        if (auto count_ok = validate_count(filter_count, "candidate provider request filter"); !count_ok) {
            return std::unexpected(std::move(count_ok.error()));
        }
        out.filters.reserve(filter_count);
        for (std::uint32_t index = 0; index < filter_count; ++index) {
            CandidateProviderFilterRequest filter;
            if (!reader->read_string(filter.request_id) || !reader->read_string(filter.filter_key) ||
                !reader->read_string(filter.argument_kind) || !reader->read_string(filter.argument_value)) {
                return std::unexpected(single_error("protocol", "truncated candidate provider request filter"));
            }
            out.filters.push_back(std::move(filter));
        }
        return out;
    }

    std::expected<std::vector<std::byte>, ErrorSet>
    encode_candidate_provider_response(const CandidateProviderResponseMessage &message) {
        std::vector<std::byte> out;
        append_header(out, MessageKind::candidate_provider_response);
        if (auto result = append_string(out, message.route); !result) {
            return std::unexpected(std::move(result.error()));
        }
        append_u32(out, static_cast<std::uint32_t>(message.results.size()));
        for (const auto &result : message.results) {
            if (auto append_result = append_string(out, result.request_id); !append_result) {
                return std::unexpected(std::move(append_result.error()));
            }
            if (auto append_result = append_string(out, result.filter_key); !append_result) {
                return std::unexpected(std::move(append_result.error()));
            }
            append_u8(out, status_to_wire(result.status));
            append_u32(out, static_cast<std::uint32_t>(result.subject_ids.size()));
            for (const auto &subject_id : result.subject_ids) {
                if (auto append_result = append_string(out, subject_id); !append_result) {
                    return std::unexpected(std::move(append_result.error()));
                }
            }
            if (auto append_result = append_string(out, result.diagnostic); !append_result) {
                return std::unexpected(std::move(append_result.error()));
            }
            append_u32(out, static_cast<std::uint32_t>(result.ttl.count()));
        }
        return out;
    }

    std::expected<CandidateProviderResponseMessage, ErrorSet>
    decode_candidate_provider_response(const std::span<const std::byte> payload) {
        auto reader = reader_for(payload, MessageKind::candidate_provider_response);
        if (!reader) {
            return std::unexpected(std::move(reader.error()));
        }
        std::uint32_t result_count {};
        CandidateProviderResponseMessage out;
        if (!reader->read_string(out.route) || !reader->read_u32(result_count)) {
            return std::unexpected(single_error("protocol", "truncated candidate provider response message"));
        }
        if (auto count_ok = validate_count(result_count, "candidate provider response result"); !count_ok) {
            return std::unexpected(std::move(count_ok.error()));
        }
        out.results.reserve(result_count);
        for (std::uint32_t index = 0; index < result_count; ++index) {
            CandidateProviderSubjectSet result;
            std::uint8_t status {};
            std::uint32_t subject_count {};
            if (!reader->read_string(result.request_id) || !reader->read_string(result.filter_key) ||
                !reader->read_u8(status) || !reader->read_u32(subject_count)) {
                return std::unexpected(single_error("protocol", "truncated candidate provider response result"));
            }
            const auto parsed_status = status_from_wire(status);
            if (!parsed_status.has_value()) {
                return std::unexpected(single_error("protocol", "unknown candidate provider response status"));
            }
            result.status = *parsed_status;
            if (auto count_ok = validate_count(subject_count, "candidate provider response subject"); !count_ok) {
                return std::unexpected(std::move(count_ok.error()));
            }
            result.subject_ids.reserve(subject_count);
            for (std::uint32_t subject_index = 0; subject_index < subject_count; ++subject_index) {
                std::string subject_id;
                if (!reader->read_string(subject_id)) {
                    return std::unexpected(single_error("protocol", "truncated candidate provider response subject"));
                }
                result.subject_ids.push_back(std::move(subject_id));
            }
            std::uint32_t ttl {};
            if (!reader->read_string(result.diagnostic) || !reader->read_u32(ttl)) {
                return std::unexpected(single_error("protocol", "truncated candidate provider response metadata"));
            }
            result.ttl = std::chrono::seconds {ttl};
            out.results.push_back(std::move(result));
        }
        return out;
    }

    std::expected<std::vector<std::byte>, ErrorSet> encode_frame(const std::span<const std::byte> payload) {
        if (payload.size() > 0xffff'ffffu) {
            return std::unexpected(single_error("protocol", "payload exceeds v1 frame size"));
        }
        const auto size = static_cast<std::uint32_t>(payload.size());
        std::vector<std::byte> out;
        out.reserve(payload.size() + 4u);
        out.push_back(static_cast<std::byte>((size >> 24u) & 0xffu));
        out.push_back(static_cast<std::byte>((size >> 16u) & 0xffu));
        out.push_back(static_cast<std::byte>((size >> 8u) & 0xffu));
        out.push_back(static_cast<std::byte>(size & 0xffu));
        out.insert(out.end(), payload.begin(), payload.end());
        return out;
    }

    std::expected<DecodedFrame, ErrorSet> try_decode_frame(const std::span<const std::byte> bytes) {
        if (bytes.size() < 4u) {
            return std::unexpected(single_error("protocol", "incomplete frame header"));
        }
        const auto size = (static_cast<std::uint32_t>(bytes[0]) << 24u) |
                          (static_cast<std::uint32_t>(bytes[1]) << 16u) |
                          (static_cast<std::uint32_t>(bytes[2]) << 8u) | static_cast<std::uint32_t>(bytes[3]);
        if (bytes.size() < static_cast<std::size_t>(size) + 4u) {
            return std::unexpected(single_error("protocol", "incomplete frame payload"));
        }
        std::vector<std::byte> payload;
        payload.insert(payload.end(), bytes.begin() + 4, bytes.begin() + 4 + size);
        return DecodedFrame {.payload = std::move(payload), .bytes_consumed = static_cast<std::size_t>(size) + 4u};
    }
} // namespace rule_engine::protocol
