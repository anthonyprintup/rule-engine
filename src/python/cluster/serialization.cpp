#include "serialization.hpp"

#include <algorithm>
#include <bit>
#include <cstdint>
#include <limits>
#include <set>
#include <string_view>
#include <type_traits>
#include <utility>

namespace rule_engine::python::cluster::serialization {
    namespace {

        constexpr std::uint32_t magic = 0x31534552U;
        constexpr std::uint8_t evaluation_wire_version = 0xe2U;
        constexpr std::size_t maximum_bytes = 64U * 1024U * 1024U;
        constexpr std::uint32_t maximum_collection = 100'000U;
        constexpr std::uint32_t maximum_depth = 64U;

        enum struct PayloadKind : std::uint8_t {
            frozen = 1,
            event = 2,
            evaluation = 3,
            effect = 4,
            outbox = 5,
            receipt = 6,
            transaction = 7,
        };

        struct Writer {
            std::vector<std::byte> bytes;
            std::string error;

            void u8(const std::uint8_t value) { bytes.push_back(static_cast<std::byte>(value)); }

            template<typename Value> void number(const Value value) {
                using Unsigned = std::make_unsigned_t<Value>;
                const auto converted = static_cast<Unsigned>(value);
                for (std::size_t index = 0; index < sizeof(Value); ++index) {
                    u8(static_cast<std::uint8_t>((converted >> (index * 8U)) & static_cast<Unsigned>(0xffU)));
                }
            }

            void boolean(const bool value) { u8(value ? 1U : 0U); }

            void raw(const std::span<const std::byte> value) {
                if (value.size() > maximum_bytes || bytes.size() > maximum_bytes - value.size()) {
                    error = "serialized payload exceeds the store codec limit";
                    return;
                }
                bytes.insert(bytes.end(), value.begin(), value.end());
            }

            void string(const std::string_view value) {
                if (value.size() > std::numeric_limits<std::uint32_t>::max()) {
                    error = "serialized string exceeds the store codec limit";
                    return;
                }
                number(static_cast<std::uint32_t>(value.size()));
                raw(std::as_bytes(std::span {value.data(), value.size()}));
            }

            void header(const PayloadKind kind) {
                number(magic);
                u8(static_cast<std::uint8_t>(kind));
            }

            [[nodiscard]] bool valid() const { return error.empty() && bytes.size() <= maximum_bytes; }
        };

        struct Reader {
            std::span<const std::byte> bytes;
            std::size_t offset {};
            std::string error;

            template<typename Value> Value number() {
                using Unsigned = std::make_unsigned_t<Value>;
                if (!require(sizeof(Value))) {
                    return {};
                }
                Unsigned result {};
                for (std::size_t index = 0; index < sizeof(Value); ++index) {
                    result |= static_cast<Unsigned>(std::to_integer<std::uint8_t>(bytes[offset + index]))
                              << (index * 8U);
                }
                offset += sizeof(Value);
                return static_cast<Value>(result);
            }

            std::uint8_t u8() { return number<std::uint8_t>(); }

            bool boolean() {
                const auto value = u8();
                if (value > 1U && error.empty()) {
                    error = "invalid serialized boolean";
                }
                return value == 1U;
            }

            std::string string() {
                const auto size = number<std::uint32_t>();
                if (!require(size)) {
                    return {};
                }
                const auto *begin = reinterpret_cast<const char *>(bytes.data() + offset);
                std::string result {begin, size};
                offset += size;
                return result;
            }

            std::vector<std::byte> blob() {
                const auto size = number<std::uint32_t>();
                if (!require(size)) {
                    return {};
                }
                std::vector<std::byte> result(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                                              bytes.begin() + static_cast<std::ptrdiff_t>(offset + size));
                offset += size;
                return result;
            }

            std::uint32_t count() {
                const auto value = number<std::uint32_t>();
                if (value > maximum_collection && error.empty()) {
                    error = "serialized collection exceeds the store codec limit";
                    return 0;
                }
                return value;
            }

            bool header(const PayloadKind expected) {
                if (bytes.size() > maximum_bytes) {
                    error = "serialized payload exceeds the store codec limit";
                    return false;
                }
                if (number<std::uint32_t>() != magic || u8() != static_cast<std::uint8_t>(expected)) {
                    if (error.empty()) {
                        error = "serialized payload header is invalid";
                    }
                    return false;
                }
                return true;
            }

            bool finish() {
                if (error.empty() && offset != bytes.size()) {
                    error = "serialized payload has trailing bytes";
                }
                return error.empty();
            }

        private:
            bool require(const std::size_t size) {
                if (!error.empty()) {
                    return false;
                }
                if (size > bytes.size() - std::min(offset, bytes.size())) {
                    error = "serialized payload is truncated";
                    return false;
                }
                return true;
            }
        };

        template<typename Id> void write_id(Writer &writer, const Id &id) { writer.string(id.value); }
        template<typename Id> Id read_id(Reader &reader) { return Id {reader.string()}; }

        void write_label(Writer &writer, const DataLabel &label) {
            writer.u8(static_cast<std::uint8_t>(label.classification));
            writer.number(static_cast<std::uint32_t>(label.categories.size()));
            for (const auto &category : label.categories) { writer.string(category); }
        }

        DataLabel read_label(Reader &reader) {
            DataLabel result;
            const auto classification = reader.u8();
            if (classification > static_cast<std::uint8_t>(Classification::secret) && reader.error.empty()) {
                reader.error = "serialized data classification is invalid";
            }
            result.classification = static_cast<Classification>(classification);
            const auto count = reader.count();
            result.categories.reserve(count);
            for (std::uint32_t index = 0; index < count; ++index) { result.categories.push_back(reader.string()); }
            return result;
        }

        void write_span(Writer &writer, const SourceSpan &span) {
            write_id(writer, span.source);
            writer.number(span.begin_byte);
            writer.number(span.end_byte);
        }

        SourceSpan read_span(Reader &reader) {
            return SourceSpan {.source = read_id<SourceId>(reader),
                               .begin_byte = reader.number<std::uint32_t>(),
                               .end_byte = reader.number<std::uint32_t>()};
        }

        bool write_fact(Writer &writer, const FactValue &value, std::set<const FactNode *> &path,
                        const std::uint32_t depth) {
            if (!value.valid() || depth > maximum_depth || !path.insert(value.node.get()).second) {
                writer.error = "fact value is invalid, cyclic, or too deeply nested";
                return false;
            }
            const auto &data = value.node->data;
            writer.u8(static_cast<std::uint8_t>(data.index()));
            std::visit(
                [&writer, &path, depth](const auto &selected) {
                    using Value = std::remove_cvref_t<decltype(selected)>;
                    if constexpr (std::is_same_v<Value, std::monostate>) {
                        return;
                    } else if constexpr (std::is_same_v<Value, bool>) {
                        writer.boolean(selected);
                    } else if constexpr (std::is_same_v<Value, IntegerValue>) {
                        writer.string(selected.decimal);
                    } else if constexpr (std::is_same_v<Value, double>) {
                        writer.number(std::bit_cast<std::uint64_t>(selected));
                    } else if constexpr (std::is_same_v<Value, UnicodeValue>) {
                        writer.string(selected.utf8);
                    } else if constexpr (std::is_same_v<Value, BytesValue>) {
                        writer.number(static_cast<std::uint32_t>(selected.bytes.size()));
                        writer.raw(selected.bytes);
                    } else if constexpr (std::is_same_v<Value, EnumValue>) {
                        write_id(writer, selected.schema);
                        writer.string(selected.member);
                    } else if constexpr (std::is_same_v<Value, FactList>) {
                        writer.number(static_cast<std::uint32_t>(selected.items.size()));
                        for (const auto &item : selected.items) { write_fact(writer, item, path, depth + 1U); }
                    } else if constexpr (std::is_same_v<Value, FactMap>) {
                        writer.number(static_cast<std::uint32_t>(selected.entries.size()));
                        for (const auto &entry : selected.entries) {
                            write_fact(writer, entry.key, path, depth + 1U);
                            write_fact(writer, entry.value, path, depth + 1U);
                        }
                    } else if constexpr (std::is_same_v<Value, FactRecord>) {
                        write_id(writer, selected.schema);
                        writer.number(static_cast<std::uint32_t>(selected.fields.size()));
                        for (const auto &field : selected.fields) {
                            writer.number(field.field_id);
                            write_fact(writer, field.value, path, depth + 1U);
                        }
                    }
                },
                data);
            path.erase(value.node.get());
            return writer.valid();
        }

        FactValue read_fact(Reader &reader, const std::uint32_t depth) {
            if (depth > maximum_depth) {
                reader.error = "serialized fact exceeds the nesting limit";
                return {};
            }
            const auto kind = reader.u8();
            switch (kind) {
                case 0: return make_fact(std::monostate {});
                case 1: return make_fact(reader.boolean());
                case 2: return make_fact(IntegerValue {.decimal = reader.string()});
                case 3: return make_fact(std::bit_cast<double>(reader.number<std::uint64_t>()));
                case 4: return make_fact(UnicodeValue {.utf8 = reader.string()});
                case 5: {
                    const auto size = reader.number<std::uint32_t>();
                    if (size > maximum_bytes || reader.offset + size > reader.bytes.size()) {
                        reader.error = "serialized byte value is truncated or excessive";
                        return {};
                    }
                    BytesValue value;
                    value.bytes.assign(reader.bytes.begin() + static_cast<std::ptrdiff_t>(reader.offset),
                                       reader.bytes.begin() + static_cast<std::ptrdiff_t>(reader.offset + size));
                    reader.offset += size;
                    return make_fact(std::move(value));
                }
                case 6: return make_fact(EnumValue {.schema = read_id<SchemaId>(reader), .member = reader.string()});
                case 7: {
                    FactList value;
                    const auto count = reader.count();
                    value.items.reserve(count);
                    for (std::uint32_t index = 0; index < count; ++index) {
                        value.items.push_back(read_fact(reader, depth + 1U));
                    }
                    return make_fact(std::move(value));
                }
                case 8: {
                    FactMap value;
                    const auto count = reader.count();
                    value.entries.reserve(count);
                    for (std::uint32_t index = 0; index < count; ++index) {
                        value.entries.push_back(FactMapEntry {.key = read_fact(reader, depth + 1U),
                                                              .value = read_fact(reader, depth + 1U)});
                    }
                    return make_fact(std::move(value));
                }
                case 9: {
                    FactRecord value {.schema = read_id<SchemaId>(reader), .fields = {}};
                    const auto count = reader.count();
                    value.fields.reserve(count);
                    for (std::uint32_t index = 0; index < count; ++index) {
                        value.fields.push_back(FactRecordField {.field_id = reader.number<std::uint32_t>(),
                                                                .value = read_fact(reader, depth + 1U)});
                    }
                    return make_fact(std::move(value));
                }
                default: reader.error = "serialized fact kind is invalid"; return {};
            }
        }

        void write_frozen(Writer &writer, const FrozenValue &value) {
            std::set<const FactNode *> path;
            write_fact(writer, value.value, path, 0);
            write_label(writer, value.label);
            writer.string(value.canonical_digest);
        }

        FrozenValue read_frozen(Reader &reader) {
            return FrozenValue {
                .value = read_fact(reader, 0), .label = read_label(reader), .canonical_digest = reader.string()};
        }

        void write_identity(Writer &writer, const IdentityField &field) {
            writer.number(field.field_id);
            writer.u8(static_cast<std::uint8_t>(field.value.index()));
            std::visit(
                [&writer](const auto &selected) {
                    using Value = std::remove_cvref_t<decltype(selected)>;
                    if constexpr (std::is_same_v<Value, bool>) {
                        writer.boolean(selected);
                    } else if constexpr (std::is_same_v<Value, std::int64_t>) {
                        writer.number(selected);
                    } else if constexpr (std::is_same_v<Value, std::uint64_t>) {
                        writer.number(selected);
                    } else if constexpr (std::is_same_v<Value, IntegerValue>) {
                        writer.string(selected.decimal);
                    } else if constexpr (std::is_same_v<Value, UnicodeValue>) {
                        writer.string(selected.utf8);
                    } else if constexpr (std::is_same_v<Value, BytesValue>) {
                        writer.number(static_cast<std::uint32_t>(selected.bytes.size()));
                        writer.raw(selected.bytes);
                    }
                },
                field.value);
        }

        IdentityField read_identity(Reader &reader) {
            IdentityField result {.field_id = reader.number<std::uint32_t>(), .value = false};
            switch (reader.u8()) {
                case 0: result.value = reader.boolean(); break;
                case 1: result.value = reader.number<std::int64_t>(); break;
                case 2: result.value = reader.number<std::uint64_t>(); break;
                case 3: result.value = IntegerValue {.decimal = reader.string()}; break;
                case 4: result.value = UnicodeValue {.utf8 = reader.string()}; break;
                case 5: result.value = BytesValue {.bytes = reader.blob()}; break;
                default: reader.error = "serialized identity kind is invalid"; break;
            }
            return result;
        }

        void write_subject(Writer &writer, const SubjectKey &subject, const std::uint32_t depth) {
            if (depth > maximum_depth) {
                writer.error = "subject identity exceeds the nesting limit";
                return;
            }
            write_id(writer, subject.peer);
            write_id(writer, subject.descriptor);
            writer.number(static_cast<std::uint32_t>(subject.identity.size()));
            for (const auto &field : subject.identity) { write_identity(writer, field); }
            writer.boolean(static_cast<bool>(subject.parent));
            if (subject.parent) {
                write_subject(writer, *subject.parent, depth + 1U);
            }
        }

        SubjectKey read_subject(Reader &reader, const std::uint32_t depth) {
            if (depth > maximum_depth) {
                reader.error = "serialized subject exceeds the nesting limit";
                return {};
            }
            SubjectKey result {.peer = read_id<PeerId>(reader),
                               .descriptor = read_id<SchemaId>(reader),
                               .identity = {},
                               .parent = nullptr};
            const auto count = reader.count();
            result.identity.reserve(count);
            for (std::uint32_t index = 0; index < count; ++index) { result.identity.push_back(read_identity(reader)); }
            if (reader.boolean()) {
                result.parent = std::make_shared<const SubjectKey>(read_subject(reader, depth + 1U));
            }
            return result;
        }

        void write_event(Writer &writer, const EventEnvelope &event) {
            write_id(writer, event.id);
            write_id(writer, event.schema);
            write_id(writer, event.tenant);
            write_id(writer, event.peer);
            writer.boolean(event.subject.has_value());
            if (event.subject) {
                write_subject(writer, *event.subject, 0);
            }
            writer.number(event.producer_unix_ms);
            writer.number(event.ingest_unix_ms);
            write_label(writer, event.label);
            writer.boolean(event.causation.has_value());
            if (event.causation) {
                write_id(writer, *event.causation);
            }
            write_frozen(writer, event.payload);
        }

        EventEnvelope read_event(Reader &reader) {
            EventEnvelope result {.id = read_id<EventId>(reader),
                                  .schema = read_id<SchemaId>(reader),
                                  .tenant = read_id<TenantId>(reader),
                                  .peer = read_id<PeerId>(reader),
                                  .subject = std::nullopt,
                                  .producer_unix_ms = 0,
                                  .ingest_unix_ms = 0,
                                  .label = {},
                                  .causation = std::nullopt,
                                  .payload = {}};
            if (reader.boolean()) {
                result.subject = read_subject(reader, 0);
            }
            result.producer_unix_ms = reader.number<std::uint64_t>();
            result.ingest_unix_ms = reader.number<std::uint64_t>();
            result.label = read_label(reader);
            if (reader.boolean()) {
                result.causation = read_id<EventId>(reader);
            }
            result.payload = read_frozen(reader);
            return result;
        }

        void write_state(Writer &writer, const StateMutation &state) {
            write_id(writer, state.owner);
            writer.string(state.namespace_name);
            writer.string(state.key);
            writer.number(state.expected_version);
            writer.boolean(state.value.has_value());
            if (state.value) {
                write_frozen(writer, *state.value);
            }
        }

        StateMutation read_state(Reader &reader) {
            StateMutation result {.owner = read_id<ExecutableId>(reader),
                                  .namespace_name = reader.string(),
                                  .key = reader.string(),
                                  .expected_version = reader.number<std::uint64_t>(),
                                  .value = std::nullopt};
            if (reader.boolean()) {
                result.value = read_frozen(reader);
            }
            return result;
        }

        void write_effect(Writer &writer, const EffectIntent &effect) {
            write_id(writer, effect.id);
            write_id(writer, effect.invocation);
            write_id(writer, effect.owner);
            write_id(writer, effect.binding);
            writer.number(effect.sequence);
            writer.string(effect.kind);
            write_frozen(writer, effect.payload);
            write_span(writer, effect.span);
            writer.string(effect.policy.policy_id);
            writer.string(effect.policy.policy_digest);
            write_label(writer, effect.policy.sink_ceiling);
            writer.boolean(effect.policy.dry_run);
            writer.u8(static_cast<std::uint8_t>(effect.disposition));
            writer.string(effect.idempotency_key);
        }

        EffectIntent read_effect(Reader &reader) {
            return EffectIntent {
                .id = read_id<IntentId>(reader),
                .invocation = read_id<InvocationId>(reader),
                .owner = read_id<ExecutableId>(reader),
                .binding = read_id<BindingId>(reader),
                .sequence = reader.number<std::uint64_t>(),
                .kind = reader.string(),
                .payload = read_frozen(reader),
                .span = read_span(reader),
                .policy = EffectPolicySnapshot {.policy_id = reader.string(),
                                                .policy_digest = reader.string(),
                                                .sink_ceiling = read_label(reader),
                                                .dry_run = reader.boolean()},
                .disposition = static_cast<EffectDisposition>(reader.u8()),
                .idempotency_key = reader.string(),
            };
        }

        void write_event_intent(Writer &writer, const EventIntent &event) {
            write_id(writer, event.id);
            write_id(writer, event.root_event);
            write_id(writer, event.invocation);
            write_id(writer, event.owner);
            write_id(writer, event.binding);
            writer.number(event.sequence);
            write_id(writer, event.schema);
            writer.string(event.schema_hash);
            write_frozen(writer, event.payload);
            write_span(writer, event.span);
            writer.u8(static_cast<std::uint8_t>(event.disposition));
        }

        EventIntent read_event_intent(Reader &reader) {
            return EventIntent {
                .id = read_id<IntentId>(reader),
                .root_event = read_id<EventId>(reader),
                .invocation = read_id<InvocationId>(reader),
                .owner = read_id<ExecutableId>(reader),
                .binding = read_id<BindingId>(reader),
                .sequence = reader.number<std::uint64_t>(),
                .schema = read_id<SchemaId>(reader),
                .schema_hash = reader.string(),
                .payload = read_frozen(reader),
                .span = read_span(reader),
                .disposition = static_cast<EventDisposition>(reader.u8()),
            };
        }

        void write_fault(Writer &writer, const FaultChain &fault) {
            writer.number(static_cast<std::uint32_t>(fault.frames.size()));
            for (const auto &frame : fault.frames) {
                writer.string(frame.code);
                writer.string(frame.message);
                write_id(writer, frame.executable);
                write_span(writer, frame.span);
            }
            writer.boolean(fault.double_fault);
            writer.boolean(fault.triple_fault);
        }

        FaultChain read_fault(Reader &reader) {
            FaultChain result;
            const auto count = reader.count();
            result.frames.reserve(count);
            for (std::uint32_t index = 0; index < count; ++index) {
                result.frames.push_back(FaultFrame {.code = reader.string(),
                                                    .message = reader.string(),
                                                    .executable = read_id<ExecutableId>(reader),
                                                    .span = read_span(reader)});
            }
            result.double_fault = reader.boolean();
            result.triple_fault = reader.boolean();
            return result;
        }

        void write_evaluation(Writer &writer, const EvaluationResult &evaluation) {
            writer.u8(evaluation_wire_version);
            writer.u8(static_cast<std::uint8_t>(evaluation.outcome));
            writer.boolean(evaluation.verdict.has_value());
            if (evaluation.verdict) {
                writer.boolean(*evaluation.verdict);
            }
            writer.number(static_cast<std::uint32_t>(evaluation.committed_effects.size()));
            for (const auto &effect : evaluation.committed_effects) { write_effect(writer, effect); }
            writer.number(static_cast<std::uint32_t>(evaluation.committed_events.size()));
            for (const auto &event : evaluation.committed_events) { write_event_intent(writer, event); }
            writer.number(static_cast<std::uint32_t>(evaluation.state_mutations.size()));
            for (const auto &state : evaluation.state_mutations) { write_state(writer, state); }
            writer.boolean(evaluation.fault.has_value());
            if (evaluation.fault) {
                write_fault(writer, *evaluation.fault);
            }
        }

        EvaluationResult read_evaluation(Reader &reader) {
            if (reader.u8() != evaluation_wire_version && reader.error.empty()) {
                reader.error = "serialized evaluation version is unsupported";
            }
            EvaluationResult result {.outcome = static_cast<EvaluationOutcome>(reader.u8()),
                                     .verdict = std::nullopt,
                                     .committed_effects = {},
                                     .committed_events = {},
                                     .state_mutations = {},
                                     .fault = std::nullopt};
            if (reader.boolean()) {
                result.verdict = reader.boolean();
            }
            auto count = reader.count();
            result.committed_effects.reserve(count);
            for (std::uint32_t index = 0; index < count; ++index) {
                result.committed_effects.push_back(read_effect(reader));
            }
            count = reader.count();
            result.committed_events.reserve(count);
            for (std::uint32_t index = 0; index < count; ++index) {
                result.committed_events.push_back(read_event_intent(reader));
            }
            count = reader.count();
            result.state_mutations.reserve(count);
            for (std::uint32_t index = 0; index < count; ++index) {
                result.state_mutations.push_back(read_state(reader));
            }
            if (reader.boolean()) {
                result.fault = read_fault(reader);
            }
            return result;
        }

        void write_outbox(Writer &writer, const OutboxRecord &record) {
            write_id(writer, record.intent);
            writer.string(record.destination);
            write_frozen(writer, record.payload);
            writer.string(record.idempotency_key);
            writer.number(record.not_before_unix_ms);
        }

        OutboxRecord read_outbox(Reader &reader) {
            return OutboxRecord {.intent = read_id<IntentId>(reader),
                                 .destination = reader.string(),
                                 .payload = read_frozen(reader),
                                 .idempotency_key = reader.string(),
                                 .not_before_unix_ms = reader.number<std::uint64_t>()};
        }

        void write_receipt(Writer &writer, const TransactionReceipt &receipt) {
            write_id(writer, receipt.input);
            writer.number(receipt.committed_cursor);
            writer.number(static_cast<std::uint32_t>(receipt.emitted_events.size()));
            for (const auto &event : receipt.emitted_events) { write_id(writer, event); }
            writer.number(static_cast<std::uint32_t>(receipt.outbox_intents.size()));
            for (const auto &intent : receipt.outbox_intents) { write_id(writer, intent); }
        }

        TransactionReceipt read_receipt(Reader &reader) {
            TransactionReceipt result {.input = read_id<EventId>(reader),
                                       .committed_cursor = reader.number<std::uint64_t>(),
                                       .emitted_events = {},
                                       .outbox_intents = {}};
            auto count = reader.count();
            result.emitted_events.reserve(count);
            for (std::uint32_t index = 0; index < count; ++index) {
                result.emitted_events.push_back(read_id<EventId>(reader));
            }
            count = reader.count();
            result.outbox_intents.reserve(count);
            for (std::uint32_t index = 0; index < count; ++index) {
                result.outbox_intents.push_back(read_id<IntentId>(reader));
            }
            return result;
        }

        template<typename Value, typename Encode> std::expected<std::vector<std::byte>, CodecError>
        encode_value(const PayloadKind kind, const Value &value, Encode encode) {
            Writer writer;
            writer.header(kind);
            encode(writer, value);
            if (!writer.valid()) {
                return std::unexpected(CodecError {.message = std::move(writer.error)});
            }
            return std::move(writer.bytes);
        }

        template<typename Value, typename Decode> std::expected<Value, CodecError>
        decode_value(const std::span<const std::byte> bytes, const PayloadKind kind, Decode decode) {
            Reader reader {.bytes = bytes, .offset = 0, .error = {}};
            if (!reader.header(kind)) {
                return std::unexpected(CodecError {.message = std::move(reader.error)});
            }
            auto value = decode(reader);
            if (!reader.finish()) {
                return std::unexpected(CodecError {.message = std::move(reader.error)});
            }
            return value;
        }

    } // namespace

    std::expected<std::vector<std::byte>, CodecError> encode(const FrozenValue &value) {
        return encode_value(PayloadKind::frozen, value, write_frozen);
    }

    std::expected<FrozenValue, CodecError> decode_frozen(const std::span<const std::byte> bytes) {
        return decode_value<FrozenValue>(bytes, PayloadKind::frozen, read_frozen);
    }

    std::expected<std::vector<std::byte>, CodecError> encode(const EventEnvelope &value) {
        return encode_value(PayloadKind::event, value, write_event);
    }

    std::expected<EventEnvelope, CodecError> decode_event(const std::span<const std::byte> bytes) {
        return decode_value<EventEnvelope>(bytes, PayloadKind::event, read_event);
    }

    std::expected<std::vector<std::byte>, CodecError> encode(const EvaluationResult &value) {
        return encode_value(PayloadKind::evaluation, value, write_evaluation);
    }

    std::expected<EvaluationResult, CodecError> decode_evaluation(const std::span<const std::byte> bytes) {
        return decode_value<EvaluationResult>(bytes, PayloadKind::evaluation, read_evaluation);
    }

    std::expected<std::vector<std::byte>, CodecError> encode(const EffectIntent &value) {
        return encode_value(PayloadKind::effect, value, write_effect);
    }

    std::expected<EffectIntent, CodecError> decode_effect(const std::span<const std::byte> bytes) {
        return decode_value<EffectIntent>(bytes, PayloadKind::effect, read_effect);
    }

    std::expected<std::vector<std::byte>, CodecError> encode(const OutboxRecord &value) {
        return encode_value(PayloadKind::outbox, value, write_outbox);
    }

    std::expected<OutboxRecord, CodecError> decode_outbox(const std::span<const std::byte> bytes) {
        return decode_value<OutboxRecord>(bytes, PayloadKind::outbox, read_outbox);
    }

    std::expected<std::vector<std::byte>, CodecError> encode(const TransactionReceipt &value) {
        return encode_value(PayloadKind::receipt, value, write_receipt);
    }

    std::expected<TransactionReceipt, CodecError> decode_receipt(const std::span<const std::byte> bytes) {
        return decode_value<TransactionReceipt>(bytes, PayloadKind::receipt, read_receipt);
    }

    std::expected<std::vector<std::byte>, CodecError> encode(const RuntimeTransaction &value) {
        return encode_value(PayloadKind::transaction, value, [](Writer &writer, const RuntimeTransaction &transaction) {
            write_event(writer, transaction.input);
            writer.string(transaction.cursor.consumer);
            writer.number(transaction.cursor.expected_position);
            writer.number(transaction.cursor.new_position);
            write_evaluation(writer, transaction.evaluation);
            writer.number(static_cast<std::uint32_t>(transaction.state.size()));
            for (const auto &state : transaction.state) { write_state(writer, state); }
            writer.number(static_cast<std::uint32_t>(transaction.emitted_events.size()));
            for (const auto &event : transaction.emitted_events) { write_event(writer, event); }
            writer.number(static_cast<std::uint32_t>(transaction.journal.size()));
            for (const auto &effect : transaction.journal) { write_effect(writer, effect); }
            writer.number(static_cast<std::uint32_t>(transaction.outbox.size()));
            for (const auto &record : transaction.outbox) { write_outbox(writer, record); }
            writer.number(transaction.fence_token);
        });
    }

    std::expected<void, CodecError> validate(const RuntimeTransaction &value) {
        if (value.input.id.empty() || value.input.schema.empty() || value.input.tenant.empty() ||
            value.input.peer.empty() || !value.input.payload.value.valid() ||
            value.input.payload.canonical_digest.empty()) {
            return std::unexpected(CodecError {.message = "input event identity or payload is invalid"});
        }
        if (value.cursor.consumer.empty() ||
            value.cursor.expected_position == std::numeric_limits<std::uint64_t>::max() ||
            value.cursor.new_position != value.cursor.expected_position + 1U || value.fence_token == 0) {
            return std::unexpected(CodecError {.message = "cursor or fence is invalid"});
        }
        if (value.evaluation.state_mutations.size() != value.state.size()) {
            return std::unexpected(CodecError {.message = "evaluation and transaction state sizes disagree"});
        }
        for (std::size_t index = 0; index < value.state.size(); ++index) {
            Writer left;
            Writer right;
            write_state(left, value.evaluation.state_mutations[index]);
            write_state(right, value.state[index]);
            if (!left.valid() || !right.valid() || left.bytes != right.bytes) {
                return std::unexpected(CodecError {.message = "evaluation and transaction state disagree"});
            }
        }
        if (value.evaluation.committed_effects.size() != value.journal.size()) {
            return std::unexpected(CodecError {.message = "evaluation and transaction effect sizes disagree"});
        }
        for (std::size_t index = 0; index < value.journal.size(); ++index) {
            Writer left;
            Writer right;
            write_effect(left, value.evaluation.committed_effects[index]);
            write_effect(right, value.journal[index]);
            if (!left.valid() || !right.valid() || left.bytes != right.bytes) {
                return std::unexpected(CodecError {.message = "evaluation and transaction effects disagree"});
            }
        }
        if (value.evaluation.committed_events.size() != value.emitted_events.size()) {
            return std::unexpected(CodecError {.message = "evaluation and transaction event sizes disagree"});
        }
        std::uint64_t previous_event_sequence {};
        for (std::size_t index = 0; index < value.emitted_events.size(); ++index) {
            const auto &intent = value.evaluation.committed_events[index];
            const auto &event = value.emitted_events[index];
            Writer intent_payload;
            Writer event_payload;
            Writer root_subject;
            Writer event_subject;
            write_frozen(intent_payload, intent.payload);
            write_frozen(event_payload, event.payload);
            root_subject.boolean(value.input.subject.has_value());
            event_subject.boolean(event.subject.has_value());
            if (value.input.subject) {
                write_subject(root_subject, *value.input.subject, 0U);
            }
            if (event.subject) {
                write_subject(event_subject, *event.subject, 0U);
            }
            if (intent.disposition != EventDisposition::committed || intent.root_event != value.input.id ||
                intent.invocation.empty() || intent.owner.empty() || intent.binding.empty() || intent.sequence == 0U ||
                intent.sequence <= previous_event_sequence || intent.schema.empty() || intent.schema_hash.empty() ||
                intent.id != deterministic_event_intent_id(value.input.id, intent.invocation, intent.sequence) ||
                event.id != EventId {intent.id.value} || event.schema != intent.schema ||
                event.tenant != value.input.tenant || event.peer != value.input.peer || !root_subject.valid() ||
                !event_subject.valid() || root_subject.bytes != event_subject.bytes ||
                event.producer_unix_ms != value.input.ingest_unix_ms ||
                event.ingest_unix_ms != value.input.ingest_unix_ms || event.label != intent.payload.label ||
                event.causation != value.input.id || !intent_payload.valid() || !event_payload.valid() ||
                intent_payload.bytes != event_payload.bytes) {
                return std::unexpected(CodecError {.message = "evaluation and transaction events disagree"});
            }
            previous_event_sequence = intent.sequence;
        }
        if (value.evaluation.outcome == EvaluationOutcome::canceled &&
            (!value.evaluation.committed_events.empty() || !value.state.empty() || !value.emitted_events.empty() ||
             !value.journal.empty() || !value.outbox.empty())) {
            return std::unexpected(CodecError {.message = "canceled evaluation contains committed effects"});
        }
        return {};
    }

} // namespace rule_engine::python::cluster::serialization
