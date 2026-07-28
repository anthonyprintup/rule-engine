#include "control_serialization.hpp"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <string_view>
#include <type_traits>
#include <utility>

namespace rule_engine::python::cluster::control_serialization {
    namespace {

        constexpr std::uint32_t magic = 0x31435052U;
        constexpr std::size_t maximum_bytes = 16U * 1024U * 1024U;
        constexpr std::uint32_t maximum_items = 10'000U;

        enum struct PayloadKind : std::uint8_t {
            generation = 1,
            pack = 2,
            operation = 3,
            activation_fingerprint = 4,
            rollback_fingerprint = 5,
            node = 6,
            generation_v2 = 7,
            stage_fingerprint = 8,
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
                    error = "control-plane payload exceeds the codec limit";
                    return;
                }
                bytes.insert(bytes.end(), value.begin(), value.end());
            }

            void string(const std::string_view value) {
                if (value.size() > std::numeric_limits<std::uint32_t>::max()) {
                    error = "control-plane string exceeds the codec limit";
                    return;
                }
                number(static_cast<std::uint32_t>(value.size()));
                raw(std::as_bytes(std::span {value.data(), value.size()}));
            }

            void blob(const std::span<const std::byte> value) {
                if (value.size() > std::numeric_limits<std::uint32_t>::max()) {
                    error = "control-plane blob exceeds the codec limit";
                    return;
                }
                number(static_cast<std::uint32_t>(value.size()));
                raw(value);
            }

            std::uint32_t count(const std::size_t value) {
                if (value > maximum_items) {
                    error = "control-plane collection exceeds the codec limit";
                    return 0;
                }
                return static_cast<std::uint32_t>(value);
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
                    error = "invalid control-plane boolean";
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
                if (value > maximum_items && error.empty()) {
                    error = "control-plane collection exceeds the codec limit";
                    return 0;
                }
                return value;
            }

            bool header(const PayloadKind expected) {
                if (bytes.size() > maximum_bytes) {
                    error = "control-plane payload exceeds the codec limit";
                    return false;
                }
                if (number<std::uint32_t>() != magic || u8() != static_cast<std::uint8_t>(expected)) {
                    if (error.empty()) {
                        error = "control-plane payload header is invalid";
                    }
                    return false;
                }
                return true;
            }

            bool finish() {
                if (error.empty() && offset != bytes.size()) {
                    error = "control-plane payload has trailing bytes";
                }
                return error.empty();
            }

        private:
            bool require(const std::size_t size) {
                if (!error.empty()) {
                    return false;
                }
                if (offset > bytes.size() || size > bytes.size() - offset) {
                    error = "control-plane payload is truncated";
                    return false;
                }
                return true;
            }
        };

        template<typename Id> void write_id(Writer &writer, const Id &value) { writer.string(value.value); }
        template<typename Id> Id read_id(Reader &reader) { return Id {reader.string()}; }

        void write_optional_u64(Writer &writer, const std::optional<std::uint64_t> value) {
            writer.boolean(value.has_value());
            if (value) {
                writer.number(*value);
            }
        }

        std::optional<std::uint64_t> read_optional_u64(Reader &reader) {
            if (!reader.boolean()) {
                return std::nullopt;
            }
            return reader.number<std::uint64_t>();
        }

        void write_strings(Writer &writer, const std::vector<std::string> &values) {
            writer.number(writer.count(values.size()));
            for (const auto &value : values) { writer.string(value); }
        }

        std::vector<std::string> read_strings(Reader &reader) {
            std::vector<std::string> result;
            const auto count = reader.count();
            result.reserve(count);
            for (std::uint32_t index = 0; index < count; ++index) { result.push_back(reader.string()); }
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

        void write_diagnostic(Writer &writer, const Diagnostic &diagnostic) {
            writer.string(diagnostic.code);
            writer.u8(static_cast<std::uint8_t>(diagnostic.severity));
            writer.string(diagnostic.message);
            writer.boolean(diagnostic.span.has_value());
            if (diagnostic.span) {
                write_span(writer, *diagnostic.span);
            }
            writer.number(writer.count(diagnostic.related.size()));
            for (const auto &related : diagnostic.related) {
                write_span(writer, related.span);
                writer.string(related.message);
            }
        }

        Diagnostic read_diagnostic(Reader &reader) {
            Diagnostic result {.code = reader.string(),
                               .severity = DiagnosticSeverity::error,
                               .message = {},
                               .span = std::nullopt,
                               .related = {}};
            const auto severity = reader.u8();
            if (severity > static_cast<std::uint8_t>(DiagnosticSeverity::error) && reader.error.empty()) {
                reader.error = "control-plane diagnostic severity is invalid";
            }
            result.severity = static_cast<DiagnosticSeverity>(severity);
            result.message = reader.string();
            if (reader.boolean()) {
                result.span = read_span(reader);
            }
            const auto count = reader.count();
            result.related.reserve(count);
            for (std::uint32_t index = 0; index < count; ++index) {
                result.related.push_back(RelatedDiagnostic {.span = read_span(reader), .message = reader.string()});
            }
            return result;
        }

        void write_transition(Writer &writer, const StateTransitionPlan &transition) {
            writer.u8(static_cast<std::uint8_t>(transition.mode));
            writer.string(transition.source_namespace);
            writer.string(transition.target_namespace);
            writer.string(transition.migration_id);
            writer.boolean(transition.reset_authorized);
            writer.boolean(transition.accept_state_gap);
        }

        StateTransitionPlan read_transition(Reader &reader) {
            StateTransitionPlan result;
            const auto mode = reader.u8();
            if (mode > static_cast<std::uint8_t>(StateTransitionMode::retained_gap) && reader.error.empty()) {
                reader.error = "control-plane state transition is invalid";
            }
            result.mode = static_cast<StateTransitionMode>(mode);
            result.source_namespace = reader.string();
            result.target_namespace = reader.string();
            result.migration_id = reader.string();
            result.reset_authorized = reader.boolean();
            result.accept_state_gap = reader.boolean();
            return result;
        }

        void write_request(Writer &writer, const GenerationRequest &request) {
            write_id(writer, request.pack);
            write_id(writer, request.version);
            write_id(writer, request.source_digest);
            writer.number(request.generation);
            writer.string(request.state_schema_hash);
            writer.string(request.state_namespace);
            write_strings(writer, request.required_capability_hashes);
            write_transition(writer, request.state_transition);
            write_optional_u64(writer, request.rollback_from);
            writer.boolean(request.signature_verified);
        }

        GenerationRequest read_request(Reader &reader) {
            return GenerationRequest {.pack = read_id<PackId>(reader),
                                      .version = read_id<PackVersion>(reader),
                                      .source_digest = read_id<SourceDigest>(reader),
                                      .generation = reader.number<std::uint64_t>(),
                                      .state_schema_hash = reader.string(),
                                      .state_namespace = reader.string(),
                                      .required_capability_hashes = read_strings(reader),
                                      .state_transition = read_transition(reader),
                                      .rollback_from = read_optional_u64(reader),
                                      .signature_verified = reader.boolean()};
        }

        void write_report(Writer &writer, const CompilationReport &report) {
            writer.string(report.node_id);
            writer.number(report.node_lease_fence);
            writer.boolean(report.success);
            writer.string(report.semantic_hash);
            writer.string(report.binding_hash);
            writer.string(report.executable_hash);
            write_strings(writer, report.capability_hashes);
            writer.number(writer.count(report.diagnostics.size()));
            for (const auto &diagnostic : report.diagnostics) { write_diagnostic(writer, diagnostic); }
        }

        CompilationReport read_report(Reader &reader) {
            CompilationReport result {.node_id = reader.string(),
                                      .node_lease_fence = reader.number<std::uint64_t>(),
                                      .success = reader.boolean(),
                                      .semantic_hash = reader.string(),
                                      .binding_hash = reader.string(),
                                      .executable_hash = reader.string(),
                                      .capability_hashes = read_strings(reader),
                                      .diagnostics = {}};
            const auto count = reader.count();
            result.diagnostics.reserve(count);
            for (std::uint32_t index = 0; index < count; ++index) {
                result.diagnostics.push_back(read_diagnostic(reader));
            }
            return result;
        }

        void write_target(Writer &writer, const StageTargetNode &target) {
            writer.string(target.node_id);
            writer.string(target.platform_abi);
            writer.number(target.lease_fence);
            writer.number(target.lease_until_unix_ms);
            write_strings(writer, target.capability_hashes);
        }

        StageTargetNode read_target(Reader &reader) {
            return StageTargetNode {.node_id = reader.string(),
                                    .platform_abi = reader.string(),
                                    .lease_fence = reader.number<std::uint64_t>(),
                                    .lease_until_unix_ms = reader.number<std::uint64_t>(),
                                    .capability_hashes = read_strings(reader)};
        }

        void write_generation_v2(Writer &writer, const GenerationSnapshot &generation) {
            write_request(writer, generation.request);
            writer.u8(static_cast<std::uint8_t>(generation.phase));
            write_strings(writer, generation.target_nodes);
            writer.number(writer.count(generation.targets.size()));
            for (const auto &target : generation.targets) { write_target(writer, target); }
            writer.number(writer.count(generation.reports.size()));
            for (const auto &report : generation.reports) { write_report(writer, report); }
            writer.string(generation.semantic_hash);
            writer.string(generation.binding_hash);
            write_strings(writer, generation.requeued_work);
            writer.string(generation.failure);
        }

        GenerationSnapshot read_generation_v1(Reader &reader) {
            GenerationSnapshot result {.request = read_request(reader),
                                       .phase = GenerationPhase::compiling,
                                       .target_nodes = {},
                                       .targets = {},
                                       .reports = {},
                                       .semantic_hash = {},
                                       .binding_hash = {},
                                       .requeued_work = {},
                                       .failure = {}};
            const auto phase = reader.u8();
            if (phase > static_cast<std::uint8_t>(GenerationPhase::failed) && reader.error.empty()) {
                reader.error = "control-plane generation phase is invalid";
            }
            result.phase = static_cast<GenerationPhase>(phase);
            result.target_nodes = read_strings(reader);
            const auto count = reader.count();
            result.reports.reserve(count);
            for (std::uint32_t index = 0; index < count; ++index) { result.reports.push_back(read_report(reader)); }
            result.semantic_hash = reader.string();
            result.binding_hash = reader.string();
            result.requeued_work = read_strings(reader);
            result.failure = reader.string();
            return result;
        }

        GenerationSnapshot read_generation_v2(Reader &reader) {
            GenerationSnapshot result {.request = read_request(reader),
                                       .phase = GenerationPhase::compiling,
                                       .target_nodes = {},
                                       .targets = {},
                                       .reports = {},
                                       .semantic_hash = {},
                                       .binding_hash = {},
                                       .requeued_work = {},
                                       .failure = {}};
            const auto phase = reader.u8();
            if (phase > static_cast<std::uint8_t>(GenerationPhase::failed) && reader.error.empty()) {
                reader.error = "control-plane generation phase is invalid";
            }
            result.phase = static_cast<GenerationPhase>(phase);
            result.target_nodes = read_strings(reader);
            const auto target_count = reader.count();
            result.targets.reserve(target_count);
            for (std::uint32_t index = 0; index < target_count; ++index) {
                result.targets.push_back(read_target(reader));
            }
            const auto report_count = reader.count();
            result.reports.reserve(report_count);
            for (std::uint32_t index = 0; index < report_count; ++index) {
                result.reports.push_back(read_report(reader));
            }
            result.semantic_hash = reader.string();
            result.binding_hash = reader.string();
            result.requeued_work = read_strings(reader);
            result.failure = reader.string();
            return result;
        }

        void write_pack(Writer &writer, const DurablePackControlSnapshot &pack) {
            write_id(writer, pack.pack);
            writer.number(pack.resource_version);
            write_optional_u64(writer, pack.active_generation);
            writer.number(pack.assignment_fence);
            writer.boolean(pack.accepting_assignments);
            write_optional_u64(writer, pack.drain_boundary);
            write_optional_u64(writer, pack.drain_target);
            write_strings(writer, pack.pending_requeues);
        }

        DurablePackControlSnapshot read_pack(Reader &reader) {
            return DurablePackControlSnapshot {.pack = read_id<PackId>(reader),
                                               .resource_version = reader.number<std::uint64_t>(),
                                               .active_generation = read_optional_u64(reader),
                                               .assignment_fence = reader.number<std::uint64_t>(),
                                               .accepting_assignments = reader.boolean(),
                                               .drain_boundary = read_optional_u64(reader),
                                               .drain_target = read_optional_u64(reader),
                                               .pending_requeues = read_strings(reader)};
        }

        void write_node(Writer &writer, const DurableResidentNode &node) {
            writer.string(node.node_id);
            writer.string(node.platform_abi);
            writer.number(node.lease_fence);
            writer.number(node.lease_until_unix_ms);
            writer.number(node.updated_at_unix_ms);
            writer.boolean(node.serving);
            write_strings(writer, node.capability_hashes);
        }

        DurableResidentNode read_node(Reader &reader) {
            return DurableResidentNode {.node_id = reader.string(),
                                        .platform_abi = reader.string(),
                                        .lease_fence = reader.number<std::uint64_t>(),
                                        .lease_until_unix_ms = reader.number<std::uint64_t>(),
                                        .updated_at_unix_ms = reader.number<std::uint64_t>(),
                                        .serving = reader.boolean(),
                                        .capability_hashes = read_strings(reader)};
        }

        void write_receipt(Writer &writer, const ActivationReceipt &receipt) {
            write_id(writer, receipt.pack);
            write_optional_u64(writer, receipt.retired_generation);
            writer.number(receipt.active_generation);
            writer.number(receipt.activation_cursor);
            writer.number(receipt.assignment_fence);
            write_strings(writer, receipt.requeued_work);
        }

        ActivationReceipt read_receipt(Reader &reader) {
            return ActivationReceipt {.pack = read_id<PackId>(reader),
                                      .retired_generation = read_optional_u64(reader),
                                      .active_generation = reader.number<std::uint64_t>(),
                                      .activation_cursor = reader.number<std::uint64_t>(),
                                      .assignment_fence = reader.number<std::uint64_t>(),
                                      .requeued_work = read_strings(reader)};
        }

        void write_operation(Writer &writer, const AdminOperationRecord &operation) {
            writer.string(operation.operation_id);
            write_id(writer, operation.request_id);
            writer.string(operation.idempotency_key);
            writer.blob(operation.request_fingerprint);
            writer.string(operation.actor);
            writer.string(operation.reason);
            writer.u8(static_cast<std::uint8_t>(operation.kind));
            writer.u8(static_cast<std::uint8_t>(operation.phase));
            write_id(writer, operation.pack);
            writer.number(operation.target_generation);
            write_optional_u64(writer, operation.rollback_source_generation);
            write_optional_u64(writer, operation.previous_active_generation);
            write_transition(writer, operation.state_transition);
            writer.number(operation.expected_pack_version);
            writer.number(operation.created_at_unix_ms);
            writer.number(operation.updated_at_unix_ms);
            write_optional_u64(writer, operation.drain_boundary);
            write_strings(writer, operation.requeued_work);
            writer.boolean(operation.result.has_value());
            if (operation.result) {
                write_receipt(writer, *operation.result);
            }
            writer.string(operation.failure);
        }

        AdminOperationRecord read_operation(Reader &reader) {
            AdminOperationRecord result {.operation_id = reader.string(),
                                         .request_id = read_id<RequestId>(reader),
                                         .idempotency_key = reader.string(),
                                         .request_fingerprint = reader.blob(),
                                         .actor = reader.string(),
                                         .reason = reader.string(),
                                         .kind = AdminOperationKind::stage,
                                         .phase = AdminOperationPhase::previewed,
                                         .pack = {},
                                         .target_generation = 0,
                                         .rollback_source_generation = std::nullopt,
                                         .previous_active_generation = std::nullopt,
                                         .state_transition = {},
                                         .expected_pack_version = 0,
                                         .created_at_unix_ms = 0,
                                         .updated_at_unix_ms = 0,
                                         .drain_boundary = std::nullopt,
                                         .requeued_work = {},
                                         .result = std::nullopt,
                                         .failure = {}};
            const auto kind = reader.u8();
            const auto phase = reader.u8();
            if (kind > static_cast<std::uint8_t>(AdminOperationKind::rollback) && reader.error.empty()) {
                reader.error = "control-plane operation kind is invalid";
            }
            if (phase > static_cast<std::uint8_t>(AdminOperationPhase::failed) && reader.error.empty()) {
                reader.error = "control-plane operation phase is invalid";
            }
            result.kind = static_cast<AdminOperationKind>(kind);
            result.phase = static_cast<AdminOperationPhase>(phase);
            result.pack = read_id<PackId>(reader);
            result.target_generation = reader.number<std::uint64_t>();
            result.rollback_source_generation = read_optional_u64(reader);
            result.previous_active_generation = read_optional_u64(reader);
            result.state_transition = read_transition(reader);
            result.expected_pack_version = reader.number<std::uint64_t>();
            result.created_at_unix_ms = reader.number<std::uint64_t>();
            result.updated_at_unix_ms = reader.number<std::uint64_t>();
            result.drain_boundary = read_optional_u64(reader);
            result.requeued_work = read_strings(reader);
            if (reader.boolean()) {
                result.result = read_receipt(reader);
            }
            result.failure = reader.string();
            return result;
        }

        template<typename Value, typename Encode> std::expected<std::vector<std::byte>, CodecError>
        encode_value(const PayloadKind kind, const Value &value, Encode encode_value_body) {
            Writer writer;
            writer.header(kind);
            encode_value_body(writer, value);
            if (!writer.valid()) {
                return std::unexpected(CodecError {.message = std::move(writer.error)});
            }
            return std::move(writer.bytes);
        }

        template<typename Value, typename Decode> std::expected<Value, CodecError>
        decode_value(const std::span<const std::byte> bytes, const PayloadKind kind, Decode decode_value_body) {
            Reader reader {.bytes = bytes, .offset = 0, .error = {}};
            if (!reader.header(kind)) {
                return std::unexpected(CodecError {.message = std::move(reader.error)});
            }
            auto value = decode_value_body(reader);
            if (!reader.finish()) {
                return std::unexpected(CodecError {.message = std::move(reader.error)});
            }
            return value;
        }

    } // namespace

    std::expected<std::vector<std::byte>, CodecError> encode(const GenerationSnapshot &value) {
        return encode_value(PayloadKind::generation_v2, value, write_generation_v2);
    }

    std::expected<GenerationSnapshot, CodecError> decode_generation(const std::span<const std::byte> bytes) {
        if (bytes.size() < sizeof(std::uint32_t) + sizeof(std::uint8_t)) {
            return std::unexpected(CodecError {.message = "control-plane payload is truncated"});
        }
        const auto kind = static_cast<PayloadKind>(std::to_integer<std::uint8_t>(bytes[sizeof(std::uint32_t)]));
        if (kind == PayloadKind::generation) {
            return decode_value<GenerationSnapshot>(bytes, PayloadKind::generation, read_generation_v1);
        }
        return decode_value<GenerationSnapshot>(bytes, PayloadKind::generation_v2, read_generation_v2);
    }

    std::expected<std::vector<std::byte>, CodecError> encode(const DurablePackControlSnapshot &value) {
        return encode_value(PayloadKind::pack, value, write_pack);
    }

    std::expected<DurablePackControlSnapshot, CodecError> decode_pack(const std::span<const std::byte> bytes) {
        return decode_value<DurablePackControlSnapshot>(bytes, PayloadKind::pack, read_pack);
    }

    std::expected<std::vector<std::byte>, CodecError> encode(const DurableResidentNode &value) {
        return encode_value(PayloadKind::node, value, write_node);
    }

    std::expected<DurableResidentNode, CodecError> decode_node(const std::span<const std::byte> bytes) {
        return decode_value<DurableResidentNode>(bytes, PayloadKind::node, read_node);
    }

    std::expected<std::vector<std::byte>, CodecError> encode(const AdminOperationRecord &value) {
        return encode_value(PayloadKind::operation, value, write_operation);
    }

    std::expected<AdminOperationRecord, CodecError> decode_operation(const std::span<const std::byte> bytes) {
        return decode_value<AdminOperationRecord>(bytes, PayloadKind::operation, read_operation);
    }

    std::expected<std::vector<std::byte>, CodecError> activation_fingerprint(const PackId &pack,
                                                                             const std::uint64_t target_generation) {
        return encode_value(PayloadKind::activation_fingerprint, target_generation,
                            [&pack](Writer &writer, const std::uint64_t generation) {
                                write_id(writer, pack);
                                writer.number(generation);
                            });
    }

    std::expected<std::vector<std::byte>, CodecError> stage_fingerprint(const GenerationRequest &request) {
        return encode_value(PayloadKind::stage_fingerprint, request,
                            [](Writer &writer, const GenerationRequest &value) { write_request(writer, value); });
    }

    std::expected<std::vector<std::byte>, CodecError>
    rollback_fingerprint(const PackId &pack, const std::uint64_t source_generation, const std::uint64_t new_generation,
                         const StateTransitionPlan &state_transition) {
        return encode_value(PayloadKind::rollback_fingerprint, source_generation,
                            [&pack, new_generation, &state_transition](Writer &writer, const std::uint64_t source) {
                                write_id(writer, pack);
                                writer.number(source);
                                writer.number(new_generation);
                                write_transition(writer, state_transition);
                            });
    }

} // namespace rule_engine::python::cluster::control_serialization
