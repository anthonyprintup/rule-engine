#include "rule_engine/python/contract.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <deque>
#include <limits>
#include <ranges>
#include <set>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>

namespace rule_engine::python {
    namespace {

        void append_token(std::string &output, const std::string_view token) {
            std::array<char, 32> length {};
            const auto [end, error] = std::to_chars(length.data(), length.data() + length.size(), token.size());
            if (error == std::errc {}) {
                output.append(length.data(), end);
            }
            output.push_back(':');
            output.append(token);
            output.push_back(';');
        }

        std::string bytes_as_hex(const std::vector<std::byte> &bytes) {
            constexpr std::string_view digits = "0123456789abcdef";
            std::string result;
            result.reserve(bytes.size() * 2U);
            for (const auto value : bytes) {
                const auto number = std::to_integer<unsigned int>(value);
                result.push_back(digits[(number >> 4U) & 0xFU]);
                result.push_back(digits[number & 0xFU]);
            }
            return result;
        }

        void append_identity(std::string &output, const IdentityScalar &scalar) {
            std::visit(
                [&output](const auto &value) {
                    using ValueType = std::remove_cvref_t<decltype(value)>;
                    if constexpr (std::is_same_v<ValueType, bool>) {
                        append_token(output, value ? "b1" : "b0");
                    } else if constexpr (std::is_same_v<ValueType, std::int64_t>) {
                        append_token(output, "i" + std::to_string(value));
                    } else if constexpr (std::is_same_v<ValueType, std::uint64_t>) {
                        append_token(output, "u" + std::to_string(value));
                    } else if constexpr (std::is_same_v<ValueType, IntegerValue>) {
                        append_token(output, "n" + value.decimal);
                    } else if constexpr (std::is_same_v<ValueType, UnicodeValue>) {
                        append_token(output, "s" + value.utf8);
                    } else if constexpr (std::is_same_v<ValueType, BytesValue>) {
                        append_token(output, "x" + bytes_as_hex(value.bytes));
                    }
                },
                scalar);
        }

        Diagnostic bytecode_error(std::string code, std::string message,
                                  std::optional<SourceSpan> span = std::nullopt) {
            return Diagnostic {.code = std::move(code),
                               .severity = DiagnosticSeverity::error,
                               .message = std::move(message),
                               .span = std::move(span),
                               .related = {}};
        }

        [[nodiscard]] std::string hexadecimal(std::uint64_t value) {
            constexpr std::string_view digits = "0123456789abcdef";
            std::array<char, 16> result {};
            for (auto index = result.size(); index > 0; --index) {
                result[index - 1] = digits[value & 0xfU];
                value >>= 4U;
            }
            return std::string {result.data(), result.size()};
        }

        [[nodiscard]] std::string stable_compiler_digest(const std::string_view canonical) {
            std::uint64_t value = 1469598103934665603ULL;
            for (const auto character : canonical) {
                value ^= static_cast<unsigned char>(character);
                value *= 1099511628211ULL;
            }
            return "fnv1a64:" + hexadecimal(value);
        }

        [[nodiscard]] std::optional<std::string_view> builtin_schema_name(const std::string_view schema) noexcept {
            if (schema == "none" || schema == "null") {
                return "none";
            }
            if (schema == "bool" || schema == "boolean") {
                return "bool";
            }
            if (schema == "int" || schema == "integer") {
                return "int";
            }
            if (schema == "float") {
                return "float";
            }
            if (schema == "str" || schema == "string" || schema == "text" || schema == "unicode") {
                return "text";
            }
            if (schema == "bytes") {
                return "bytes";
            }
            if (schema == "list") {
                return "list";
            }
            if (schema == "tuple") {
                return "tuple";
            }
            if (schema == "dict") {
                return "dict";
            }
            if (schema == "any") {
                return "any";
            }
            return std::nullopt;
        }

        struct EventOperand {
            SchemaId schema;
            std::string schema_hash;
        };

        [[nodiscard]] std::optional<std::string> fact_text(const FactValue &value) {
            if (!value.valid()) {
                return std::nullopt;
            }
            const auto *text = std::get_if<UnicodeValue>(&value.node->data);
            return text == nullptr ? std::nullopt : std::optional<std::string> {text->utf8};
        }

        [[nodiscard]] std::optional<EventOperand> decode_event_operand(const FactValue &value) {
            if (!value.valid()) {
                return std::nullopt;
            }
            const auto *record = std::get_if<FactRecord>(&value.node->data);
            if (record == nullptr || record->schema.value != python_event_operand_schema_v1 ||
                record->fields.size() != 2U || record->fields[0].field_id != 1U || record->fields[1].field_id != 2U) {
                return std::nullopt;
            }
            auto schema = fact_text(record->fields[0].value);
            auto schema_hash = fact_text(record->fields[1].value);
            if (!schema || schema->empty() || !schema_hash || schema_hash->empty()) {
                return std::nullopt;
            }
            return EventOperand {.schema = SchemaId {std::move(*schema)}, .schema_hash = std::move(*schema_hash)};
        }

        [[nodiscard]] bool canonical_label(const DataLabel &label) {
            return std::ranges::is_sorted(label.categories) &&
                   std::ranges::adjacent_find(label.categories) == label.categories.end() &&
                   std::ranges::none_of(label.categories, [](const std::string &category) { return category.empty(); });
        }

        [[nodiscard]] EventProjectionError projection_error(const EventProjectionErrorCode code, std::string message,
                                                            std::optional<SourceSpan> span = std::nullopt) {
            return EventProjectionError {.code = code, .message = std::move(message), .span = std::move(span)};
        }

        struct EventPayloadValidation {
            std::size_t bytes {};
            std::set<const FactNode *> path;
        };

        [[nodiscard]] std::expected<void, EventProjectionError>
        charge_event_bytes(EventPayloadValidation &state, const std::size_t amount, const std::size_t maximum,
                           const std::optional<SourceSpan> &span) {
            if (amount > maximum || state.bytes > maximum - amount) {
                return std::unexpected(projection_error(EventProjectionErrorCode::budget_exhausted,
                                                        "event payload byte budget is exhausted", span));
            }
            state.bytes += amount;
            return {};
        }

        [[nodiscard]] std::expected<void, EventProjectionError>
        validate_event_value(const FactValue &value, EventPayloadValidation &state, const std::size_t maximum_bytes,
                             const std::uint32_t maximum_depth, const std::uint32_t depth,
                             const std::optional<SourceSpan> &span) {
            if (!value.valid()) {
                return std::unexpected(projection_error(EventProjectionErrorCode::invalid_payload,
                                                        "event payload contains an empty value", span));
            }
            if (depth > maximum_depth) {
                return std::unexpected(projection_error(EventProjectionErrorCode::budget_exhausted,
                                                        "event payload depth budget is exhausted", span));
            }
            if (!state.path.insert(value.node.get()).second) {
                return std::unexpected(projection_error(EventProjectionErrorCode::invalid_payload,
                                                        "event payload contains a cycle", span));
            }
            const auto erase_path = [&state, &value] { state.path.erase(value.node.get()); };
            auto charged = charge_event_bytes(state, 1U, maximum_bytes, span);
            if (!charged) {
                erase_path();
                return charged;
            }

            const auto &data = value.node->data;
            std::size_t scalar_bytes {};
            if (const auto *integer = std::get_if<IntegerValue>(&data); integer != nullptr) {
                scalar_bytes = integer->decimal.size();
            } else if (std::holds_alternative<double>(data)) {
                scalar_bytes = sizeof(double);
            } else if (const auto *text = std::get_if<UnicodeValue>(&data); text != nullptr) {
                scalar_bytes = text->utf8.size();
            } else if (const auto *bytes = std::get_if<BytesValue>(&data); bytes != nullptr) {
                scalar_bytes = bytes->bytes.size();
            } else if (const auto *enumeration = std::get_if<EnumValue>(&data); enumeration != nullptr) {
                scalar_bytes = enumeration->schema.value.size() + enumeration->member.size();
            }
            if (scalar_bytes != 0U) {
                charged = charge_event_bytes(state, scalar_bytes, maximum_bytes, span);
                erase_path();
                return charged;
            }

            const auto validate_child = [&](const FactValue &child) {
                return validate_event_value(child, state, maximum_bytes, maximum_depth, depth + 1U, span);
            };
            if (const auto *list = std::get_if<FactList>(&data); list != nullptr) {
                for (const auto &item : list->items) {
                    if (auto valid = validate_child(item); !valid) {
                        erase_path();
                        return valid;
                    }
                }
            } else if (const auto *map = std::get_if<FactMap>(&data); map != nullptr) {
                for (const auto &entry : map->entries) {
                    if (auto valid = validate_child(entry.key); !valid) {
                        erase_path();
                        return valid;
                    }
                    if (auto valid = validate_child(entry.value); !valid) {
                        erase_path();
                        return valid;
                    }
                }
            } else if (const auto *record = std::get_if<FactRecord>(&data); record != nullptr) {
                if (record->schema.empty()) {
                    erase_path();
                    return std::unexpected(projection_error(EventProjectionErrorCode::invalid_payload,
                                                            "event payload record schema is empty", span));
                }
                if (auto schema_bytes = charge_event_bytes(state, record->schema.value.size(), maximum_bytes, span);
                    !schema_bytes) {
                    erase_path();
                    return schema_bytes;
                }
                std::uint32_t previous {};
                for (const auto &field : record->fields) {
                    if (field.field_id == 0U || field.field_id <= previous) {
                        erase_path();
                        return std::unexpected(projection_error(EventProjectionErrorCode::invalid_payload,
                                                                "event record fields are not canonical", span));
                    }
                    previous = field.field_id;
                    if (auto field_bytes = charge_event_bytes(state, sizeof(field.field_id), maximum_bytes, span);
                        !field_bytes) {
                        erase_path();
                        return field_bytes;
                    }
                    if (auto valid = validate_child(field.value); !valid) {
                        erase_path();
                        return valid;
                    }
                }
            }
            erase_path();
            return {};
        }

        [[nodiscard]] bool primitive_schema_matches(const FactValue &value, const SchemaId &schema) {
            const auto &data = value.node->data;
            const auto &id = schema.value;
            if (id == "any") {
                return true;
            }
            if (id == "none" || id == "null") {
                return std::holds_alternative<std::monostate>(data);
            }
            if (id == "bool" || id == "boolean") {
                return std::holds_alternative<bool>(data);
            }
            if (id == "int" || id == "integer") {
                return std::holds_alternative<IntegerValue>(data);
            }
            if (id == "float") {
                return std::holds_alternative<double>(data);
            }
            if (id == "str" || id == "string" || id == "text" || id == "unicode") {
                return std::holds_alternative<UnicodeValue>(data);
            }
            if (id == "bytes") {
                return std::holds_alternative<BytesValue>(data);
            }
            if (id == "list") {
                return std::holds_alternative<FactList>(data);
            }
            if (id == "map") {
                return std::holds_alternative<FactMap>(data);
            }
            return false;
        }

        [[nodiscard]] std::expected<void, EventProjectionError>
        validate_event_schema(const FactValue &value, const SchemaId &expected, const SchemaCatalog &schemas,
                              const std::optional<SourceSpan> &span) {
            if (!value.valid() || expected.empty()) {
                return std::unexpected(projection_error(EventProjectionErrorCode::invalid_schema,
                                                        "event boundary schema or value is empty", span));
            }
            if (primitive_schema_matches(value, expected)) {
                return {};
            }
            if (const auto *enumeration = std::get_if<EnumValue>(&value.node->data); enumeration != nullptr) {
                if (enumeration->schema == expected) {
                    return {};
                }
                return std::unexpected(projection_error(EventProjectionErrorCode::invalid_schema,
                                                        "event enum schema does not match its descriptor", span));
            }
            const auto *record = std::get_if<FactRecord>(&value.node->data);
            if (record == nullptr || record->schema != expected) {
                return std::unexpected(projection_error(EventProjectionErrorCode::invalid_schema,
                                                        "event record schema does not match its descriptor", span));
            }
            const auto descriptor = std::ranges::find(schemas.descriptors, expected, &SchemaDescriptor::id);
            if (descriptor == schemas.descriptors.end()) {
                return std::unexpected(projection_error(EventProjectionErrorCode::invalid_schema,
                                                        "event payload references an absent schema", span));
            }
            for (const auto &schema_field : descriptor->fields) {
                const auto field = std::ranges::find(record->fields, schema_field.field_id, &FactRecordField::field_id);
                if (field == record->fields.end()) {
                    if (!schema_field.optional) {
                        return std::unexpected(projection_error(
                            EventProjectionErrorCode::invalid_schema,
                            "event payload is missing required field " + std::to_string(schema_field.field_id), span));
                    }
                    continue;
                }
                if (auto valid = validate_event_schema(field->value, schema_field.type, schemas, span); !valid) {
                    return valid;
                }
            }
            for (const auto &field : record->fields) {
                if (std::ranges::find(descriptor->fields, field.field_id, &SchemaField::field_id) ==
                    descriptor->fields.end()) {
                    return std::unexpected(projection_error(
                        EventProjectionErrorCode::invalid_schema,
                        "event payload contains unknown field " + std::to_string(field.field_id), span));
                }
            }
            return {};
        }

        [[nodiscard]] DataLabel event_payload_label(const FactRecord &record, const SchemaDescriptor &descriptor) {
            DataLabel result;
            for (const auto &field : record.fields) {
                const auto schema_field = std::ranges::find(descriptor.fields, field.field_id, &SchemaField::field_id);
                if (schema_field != descriptor.fields.end()) {
                    result = join_labels(result, schema_field->label);
                }
            }
            return result;
        }

    } // namespace

    std::string canonical_operator_bindings_hash(const std::span<const OperatorBinding> bindings) {
        auto normalized = OperatorBindings {bindings.begin(), bindings.end()};
        for (auto &binding : normalized) {
            std::ranges::sort(binding.capabilities, {}, &CapabilityId::value);
            binding.capabilities.erase(std::ranges::unique(binding.capabilities).begin(), binding.capabilities.end());
        }
        std::ranges::sort(normalized, [](const OperatorBinding &left, const OperatorBinding &right) {
            return std::tie(left.id.value, left.executable.value) < std::tie(right.id.value, right.executable.value);
        });

        std::string canonical {"python-static-bindings-v1;"};
        for (const auto &binding : normalized) {
            append_token(canonical, binding.id.value);
            append_token(canonical, binding.executable.value);
            append_token(canonical, binding.budget.name);
            append_token(canonical, std::to_string(binding.capabilities.size()));
            for (const auto &capability : binding.capabilities) { append_token(canonical, capability.value); }
        }
        return stable_compiler_digest(canonical);
    }

    std::string compiled_pack_executable_hash(const CompiledPack &pack, const std::string_view platform_abi) {
        std::string canonical {"python-static-executable-v1;"};
        append_token(canonical, platform_abi);
        append_token(canonical, pack.compiler_abi);
        append_token(canonical, pack.pack.value);
        append_token(canonical, pack.version.value);
        append_token(canonical, pack.source_digest.value);
        append_token(canonical, pack.semantic_hash);
        append_token(canonical, pack.state_schema_hash);
        append_token(canonical, canonical_operator_bindings_hash(pack.bindings));
        append_token(canonical, pack.schemas.canonical_hash);
        return stable_compiler_digest(canonical);
    }

    std::string canonical_schema_hash(const std::string_view canonical_descriptor) {
        std::uint64_t value = 1469598103934665603ULL;
        for (const auto character : canonical_descriptor) {
            value ^= static_cast<unsigned char>(character);
            value *= 1099511628211ULL;
        }
        return "fnv1a64:" + hexadecimal(value);
    }

    std::optional<SchemaIdentity> resolve_schema_identity(const SchemaCatalog &catalog, const SchemaId &schema) {
        if (schema.empty()) {
            return std::nullopt;
        }
        const auto descriptor = std::ranges::find(catalog.descriptors, schema, &SchemaDescriptor::id);
        if (descriptor != catalog.descriptors.end()) {
            if (descriptor->canonical_hash.empty()) {
                return std::nullopt;
            }
            return SchemaIdentity {.id = descriptor->id, .canonical_hash = descriptor->canonical_hash};
        }
        const auto builtin = builtin_schema_name(schema.value);
        if (!builtin.has_value()) {
            return std::nullopt;
        }
        return SchemaIdentity {
            .id = schema,
            .canonical_hash = canonical_schema_hash("rule-engine.builtin-schema.v1|" + std::string {*builtin}),
        };
    }

    bool valid_fact_response_shape(const FactResponse &response) noexcept {
        if (response.status == FactTerminalStatus::value) {
            return response.value.has_value() && response.value->valid() && response.returned_schema.has_value() &&
                   response.returned_schema->valid() && !response.diagnostic.has_value();
        }
        const auto known_terminal = [&] {
            switch (response.status) {
                case FactTerminalStatus::unavailable:
                case FactTerminalStatus::unsupported:
                case FactTerminalStatus::denied:
                case FactTerminalStatus::timed_out:
                case FactTerminalStatus::failed:
                case FactTerminalStatus::canceled: return true;
                case FactTerminalStatus::value: return false;
                default: return false;
            }
        }();
        return known_terminal && !response.value.has_value() && !response.returned_schema.has_value();
    }

    bool fact_response_schema_matches(const FactRequest &request, const FactResponse &response) noexcept {
        if (!valid_fact_response_shape(response) || request.expected_schema.empty() ||
            request.expected_schema_hash.empty()) {
            return false;
        }
        if (response.status != FactTerminalStatus::value) {
            return true;
        }
        return response.returned_schema ==
               std::optional<SchemaIdentity> {
                   SchemaIdentity {.id = request.expected_schema, .canonical_hash = request.expected_schema_hash}};
    }

    DataLabel join_labels(const DataLabel &left, const DataLabel &right) {
        DataLabel result {
            .classification = std::max(left.classification, right.classification),
            .categories = left.categories,
        };
        result.categories.insert(result.categories.end(), right.categories.begin(), right.categories.end());
        std::ranges::sort(result.categories);
        const auto unique_end = std::ranges::unique(result.categories).begin();
        result.categories.erase(unique_end, result.categories.end());
        return result;
    }

    bool may_flow_to(const DataLabel &value, const DataLabel &ceiling) noexcept {
        if (value.classification > ceiling.classification) {
            return false;
        }
        return std::ranges::all_of(value.categories, [&ceiling](const std::string &category) {
            return std::ranges::find(ceiling.categories, category) != ceiling.categories.end();
        });
    }

    FactValue make_fact(FactData data) {
        return FactValue {.node = std::make_shared<const FactNode>(FactNode {.data = std::move(data)})};
    }

    IntentId deterministic_event_intent_id(const EventId &root_event, const InvocationId &invocation,
                                           const std::uint64_t sequence) {
        std::string identity;
        append_token(identity, "event-intent-v1");
        append_token(identity, root_event.value);
        append_token(identity, invocation.value);
        append_token(identity, std::to_string(sequence));
        return IntentId {std::move(identity)};
    }

    bool SubjectKey::valid() const noexcept {
        if (peer.empty() || descriptor.empty() || identity.empty()) {
            return false;
        }
        std::uint32_t previous {};
        for (const auto &field : identity) {
            if (field.field_id == 0 || field.field_id <= previous) {
                return false;
            }
            previous = field.field_id;
        }

        std::set<const SubjectKey *> seen;
        auto current = this;
        while (current != nullptr) {
            if (!seen.insert(current).second || current->peer != peer) {
                return false;
            }
            current = current->parent.get();
        }
        return true;
    }

    std::string canonical_subject_key(const SubjectKey &subject) {
        if (!subject.valid()) {
            return {};
        }

        std::vector<const SubjectKey *> lineage;
        for (auto current = &subject; current != nullptr; current = current->parent.get()) {
            lineage.push_back(current);
        }
        std::ranges::reverse(lineage);

        std::string output;
        append_token(output, "subject-key-v1");
        append_token(output, subject.peer.value);
        for (const auto *part : lineage) {
            append_token(output, part->descriptor.value);
            for (const auto &field : part->identity) {
                append_token(output, std::to_string(field.field_id));
                append_identity(output, field.value);
            }
            append_token(output, "/");
        }
        return output;
    }

    std::expected<void, DiagnosticSet> verify_bytecode(const CompiledPack &pack) {
        DiagnosticSet diagnostics;
        if (pack.pack.empty() || pack.version.empty() || pack.source_digest.empty()) {
            diagnostics.push_back(bytecode_error("PYC0001", "compiled pack identity is incomplete"));
        }
        if (pack.compiler_abi.empty() || pack.semantic_hash.empty()) {
            diagnostics.push_back(bytecode_error("PYC0002", "compiled pack semantic identity is incomplete"));
        }

        std::set<std::string> function_ids;
        for (const auto &function : pack.functions) {
            if (function.id.empty() || !function_ids.insert(function.id.value).second) {
                diagnostics.push_back(bytecode_error("PYC0100", "bytecode function IDs must be non-empty and unique"));
            }
            if (function.register_count < function.parameter_count) {
                diagnostics.push_back(bytecode_error("PYC0101", "parameter count exceeds register count"));
            }
            for (std::size_t index = 0; index < function.instructions.size(); ++index) {
                const auto &instruction = function.instructions[index];
                if (std::to_underlying(instruction.opcode) > std::to_underlying(Opcode::emit_event)) {
                    diagnostics.push_back(bytecode_error("PYC0109", "instruction opcode is unknown", instruction.span));
                    continue;
                }
                if (!instruction.span.valid()) {
                    diagnostics.push_back(bytecode_error("PYC0102", "instruction has an invalid UTF-8 byte span"));
                }
                const auto has_no_destination =
                    instruction.opcode == Opcode::jump || instruction.opcode == Opcode::enter_try ||
                    instruction.opcode == Opcode::leave_try || instruction.opcode == Opcode::begin_transaction ||
                    instruction.opcode == Opcode::commit_transaction ||
                    instruction.opcode == Opcode::rollback_transaction || instruction.opcode == Opcode::delete_state ||
                    instruction.opcode == Opcode::reraise || instruction.opcode == Opcode::unwind_jump ||
                    instruction.opcode == Opcode::leave_except || instruction.opcode == Opcode::emit_event;
                if (instruction.destination >= function.register_count && !has_no_destination) {
                    diagnostics.push_back(bytecode_error("PYC0103", "instruction destination register is out of range",
                                                         instruction.span));
                }
                if ((instruction.opcode == Opcode::jump || instruction.opcode == Opcode::jump_if_false ||
                     instruction.opcode == Opcode::iter_next || instruction.opcode == Opcode::unwind_jump) &&
                    instruction.immediate >= function.instructions.size()) {
                    diagnostics.push_back(bytecode_error("PYC0104", "jump target is out of range", instruction.span));
                }
                const auto register_valid = [&](const std::uint32_t reg) { return reg < function.register_count; };
                const auto register_window_valid = [&](const std::uint32_t first, const std::uint32_t count) {
                    return first <= function.register_count && count <= function.register_count - first;
                };
                const auto malformed_register = [&] {
                    diagnostics.push_back(
                        bytecode_error("PYC0106", "instruction register operand is out of range", instruction.span));
                };
                const auto malformed_reserved = [&] {
                    diagnostics.push_back(
                        bytecode_error("PYC0107", "instruction reserved operand must be zero", instruction.span));
                };
                switch (instruction.opcode) {
                    case Opcode::build_list:
                    case Opcode::build_tuple:
                        if (!register_window_valid(instruction.operand_a, instruction.operand_b)) {
                            malformed_register();
                        }
                        if (instruction.immediate != 0U) {
                            malformed_reserved();
                        }
                        break;
                    case Opcode::build_dict:
                        if (instruction.operand_a > function.register_count ||
                            instruction.operand_b > (function.register_count - instruction.operand_a) / 2U) {
                            malformed_register();
                        }
                        if (instruction.immediate != 0U) {
                            malformed_reserved();
                        }
                        break;
                    case Opcode::get_iter:
                        if (!register_valid(instruction.operand_a)) {
                            malformed_register();
                        }
                        if (instruction.operand_b != 0U || instruction.immediate != 0U) {
                            malformed_reserved();
                        }
                        break;
                    case Opcode::iter_next:
                        if (!register_valid(instruction.operand_a)) {
                            malformed_register();
                        }
                        if (instruction.operand_b != 0U) {
                            malformed_reserved();
                        }
                        break;
                    case Opcode::load_subscript:
                    case Opcode::store_subscript:
                        if (!register_valid(instruction.operand_a) || !register_valid(instruction.operand_b)) {
                            malformed_register();
                        }
                        if (instruction.immediate != 0U) {
                            malformed_reserved();
                        }
                        break;
                    case Opcode::delete_state:
                        if (instruction.immediate >= pack.constants.size()) {
                            diagnostics.push_back(bytecode_error(
                                "PYC0108", "delete_state constant index is out of range", instruction.span));
                        }
                        if (instruction.destination != 0U || instruction.operand_a != 0U ||
                            instruction.operand_b != 0U) {
                            malformed_reserved();
                        }
                        break;
                    case Opcode::build_record: {
                        if (!register_window_valid(instruction.operand_a, instruction.operand_b)) {
                            malformed_register();
                        }
                        if (instruction.immediate >= pack.constants.size()) {
                            diagnostics.push_back(bytecode_error(
                                "PYC0116", "build_record constant index is out of range", instruction.span));
                            break;
                        }
                        const auto operand = decode_event_operand(pack.constants[instruction.immediate]);
                        if (!operand) {
                            diagnostics.push_back(bytecode_error(
                                "PYC0116", "build_record requires a canonical event schema operand", instruction.span));
                            break;
                        }
                        const auto descriptor =
                            std::ranges::find(pack.schemas.descriptors, operand->schema, &SchemaDescriptor::id);
                        if (descriptor == pack.schemas.descriptors.end() || descriptor->kind != SchemaKind::event ||
                            descriptor->canonical_hash.empty() || descriptor->canonical_hash != operand->schema_hash ||
                            descriptor->fields.size() != instruction.operand_b) {
                            diagnostics.push_back(bytecode_error(
                                "PYC0116", "build_record operand does not pin the exact active event schema fields",
                                instruction.span));
                        }
                        break;
                    }
                    case Opcode::emit_event: {
                        if (!register_valid(instruction.operand_a)) {
                            malformed_register();
                        }
                        if (instruction.destination != 0U || instruction.operand_b != 0U) {
                            malformed_reserved();
                        }
                        if (instruction.immediate >= pack.constants.size()) {
                            diagnostics.push_back(bytecode_error("PYC0115", "emit_event constant index is out of range",
                                                                 instruction.span));
                            break;
                        }
                        const auto operand = decode_event_operand(pack.constants[instruction.immediate]);
                        if (!operand) {
                            diagnostics.push_back(bytecode_error(
                                "PYC0115", "emit_event requires a canonical event schema operand", instruction.span));
                            break;
                        }
                        const auto descriptor =
                            std::ranges::find(pack.schemas.descriptors, operand->schema, &SchemaDescriptor::id);
                        if (descriptor == pack.schemas.descriptors.end() || descriptor->kind != SchemaKind::event ||
                            descriptor->canonical_hash.empty() || descriptor->canonical_hash != operand->schema_hash) {
                            diagnostics.push_back(bytecode_error(
                                "PYC0115", "emit_event operand does not pin an active event schema", instruction.span));
                        }
                        break;
                    }
                    case Opcode::load_current_exception:
                        if (instruction.operand_a != 0U || instruction.operand_b != 0U || instruction.immediate != 0U) {
                            malformed_reserved();
                        }
                        break;
                    case Opcode::match_exception:
                        if (instruction.operand_a >= function.instructions.size() ||
                            instruction.operand_b >= function.instructions.size()) {
                            diagnostics.push_back(
                                bytecode_error("PYC0104", "exception filter target is out of range", instruction.span));
                        }
                        if (instruction.immediate > std::to_underlying(PythonFaultKind::exception)) {
                            diagnostics.push_back(
                                bytecode_error("PYC0112", "exception filter kind is outside the closed fault table",
                                               instruction.span));
                        }
                        break;
                    case Opcode::reraise:
                    case Opcode::leave_except:
                        if (instruction.destination != 0U || instruction.operand_a != 0U ||
                            instruction.operand_b != 0U || instruction.immediate != 0U) {
                            malformed_reserved();
                        }
                        break;
                    case Opcode::unwind_jump:
                        if (instruction.destination != 0U || instruction.operand_a != 0U ||
                            instruction.operand_b != 0U) {
                            malformed_reserved();
                        }
                        break;
                    case Opcode::raise_fault:
                        if (instruction.immediate > std::to_underlying(PythonFaultKind::arithmetic_error)) {
                            diagnostics.push_back(bytecode_error(
                                "PYC0112", "raise kind is not a concrete engine-owned fault kind", instruction.span));
                        }
                        break;
                    case Opcode::load_const:
                    case Opcode::move:
                    case Opcode::unary_op:
                    case Opcode::binary_op:
                    case Opcode::compare:
                    case Opcode::jump:
                    case Opcode::jump_if_false:
                    case Opcode::call:
                    case Opcode::return_value:
                    case Opcode::enter_try:
                    case Opcode::leave_try:
                    case Opcode::yield_value:
                    case Opcode::await_fact:
                    case Opcode::await_capability:
                    case Opcode::read_state:
                    case Opcode::write_state:
                    case Opcode::append_effect:
                    case Opcode::begin_transaction:
                    case Opcode::commit_transaction:
                    case Opcode::rollback_transaction: break;
                    default: std::unreachable();
                }
            }
            const auto instruction_count = function.instructions.size();
            std::set<std::uint32_t> cleanup_entries;
            std::set<std::uint32_t> filter_nodes;
            std::vector<std::pair<std::uint32_t, std::set<std::uint32_t>>> filter_handler_targets;
            for (const auto &region : function.exception_regions) {
                if (region.begin_instruction >= region.end_instruction || region.end_instruction > instruction_count ||
                    region.handler_instruction >= instruction_count ||
                    region.cleanup_instruction >= instruction_count) {
                    diagnostics.push_back(bytecode_error("PYC0105", "exception region is out of range"));
                    continue;
                }
                if ((region.handler_instruction >= region.begin_instruction &&
                     region.handler_instruction < region.end_instruction) ||
                    (region.cleanup_instruction >= region.begin_instruction &&
                     region.cleanup_instruction < region.end_instruction)) {
                    diagnostics.push_back(
                        bytecode_error("PYC0110", "exception region target lies inside its protected interval"));
                }
                if (std::to_underlying(region.kind) > std::to_underlying(ExceptionRegionKind::cleanup)) {
                    diagnostics.push_back(bytecode_error("PYC0110", "exception region kind is unknown"));
                    continue;
                }
                switch (region.kind) {
                    case ExceptionRegionKind::handler:
                        if (region.cleanup_instruction != region.handler_instruction) {
                            diagnostics.push_back(bytecode_error(
                                "PYC0110", "handler region must use its handler as the compatibility cleanup target"));
                        }
                        break;
                    case ExceptionRegionKind::cleanup:
                        if (region.cleanup_instruction == region.handler_instruction ||
                            function.instructions[region.handler_instruction].opcode != Opcode::reraise) {
                            diagnostics.push_back(bytecode_error(
                                "PYC0110", "cleanup region must resume exceptions at a distinct reraise instruction"));
                        }
                        if (!cleanup_entries.insert(region.cleanup_instruction).second) {
                            diagnostics.push_back(
                                bytecode_error("PYC0110", "cleanup regions must have distinct entry instructions"));
                        }
                        break;
                    default: std::unreachable();
                }

                if (function.instructions[region.handler_instruction].opcode != Opcode::match_exception) {
                    continue;
                }
                std::set<std::uint32_t> chain;
                std::set<PythonFaultKind> kinds;
                std::set<std::uint32_t> handler_targets;
                auto cursor = region.handler_instruction;
                while (cursor < instruction_count && function.instructions[cursor].opcode == Opcode::match_exception) {
                    if (!chain.insert(cursor).second) {
                        diagnostics.push_back(bytecode_error("PYC0112", "exception filter chain contains a cycle",
                                                             function.instructions[cursor].span));
                        break;
                    }
                    filter_nodes.insert(cursor);
                    const auto &filter = function.instructions[cursor];
                    const auto kind = static_cast<PythonFaultKind>(filter.immediate);
                    if (filter.immediate <= std::to_underlying(PythonFaultKind::exception) &&
                        !kinds.insert(kind).second) {
                        diagnostics.push_back(
                            bytecode_error("PYC0112", "exception filter kind is duplicated", filter.span));
                    }
                    handler_targets.insert(filter.operand_a);
                    if (filter.operand_a >= region.begin_instruction && filter.operand_a < region.end_instruction) {
                        diagnostics.push_back(bytecode_error(
                            "PYC0112", "exception handler target lies inside its protected interval", filter.span));
                    }
                    if (filter.immediate == std::to_underlying(PythonFaultKind::exception) &&
                        (filter.operand_b >= instruction_count ||
                         function.instructions[filter.operand_b].opcode != Opcode::reraise)) {
                        diagnostics.push_back(bytecode_error(
                            "PYC0112", "catch-all exception filter must terminate the ordered filter chain",
                            filter.span));
                    }
                    cursor = filter.operand_b;
                }
                if (cursor >= instruction_count || function.instructions[cursor].opcode != Opcode::reraise) {
                    diagnostics.push_back(
                        bytecode_error("PYC0112", "exception filter chain must terminate at a reraise instruction"));
                }
                filter_handler_targets.emplace_back(region.handler_instruction, std::move(handler_targets));
                for (const auto target : filter_handler_targets.back().second) {
                    if (chain.contains(target)) {
                        diagnostics.push_back(
                            bytecode_error("PYC0112", "exception filter matching edge targets another filter node"));
                    }
                }
            }

            for (std::size_t left = 0U; left < function.exception_regions.size(); ++left) {
                const auto &a = function.exception_regions[left];
                if (a.begin_instruction >= a.end_instruction || a.end_instruction > instruction_count) {
                    continue;
                }
                for (std::size_t right = left + 1U; right < function.exception_regions.size(); ++right) {
                    const auto &b = function.exception_regions[right];
                    if (b.begin_instruction >= b.end_instruction || b.end_instruction > instruction_count) {
                        continue;
                    }
                    const auto overlap = std::max(a.begin_instruction, b.begin_instruction) <
                                         std::min(a.end_instruction, b.end_instruction);
                    const auto a_contains_b =
                        a.begin_instruction <= b.begin_instruction && a.end_instruction >= b.end_instruction;
                    const auto b_contains_a =
                        b.begin_instruction <= a.begin_instruction && b.end_instruction >= a.end_instruction;
                    const auto identical =
                        a.begin_instruction == b.begin_instruction && a.end_instruction == b.end_instruction;
                    if (overlap && (identical || (!a_contains_b && !b_contains_a))) {
                        diagnostics.push_back(
                            bytecode_error("PYC0111", "exception regions overlap without strict lexical nesting"));
                    }
                }
            }

            for (std::uint32_t pc = 0U; pc < instruction_count; ++pc) {
                if (function.instructions[pc].opcode == Opcode::match_exception && !filter_nodes.contains(pc)) {
                    diagnostics.push_back(
                        bytecode_error("PYC0112", "exception filter instruction is not owned by a handler region",
                                       function.instructions[pc].span));
                }
            }

            const auto add_normal_successors = [&](const std::uint32_t pc, auto &&add) {
                const auto &instruction = function.instructions[pc];
                switch (instruction.opcode) {
                    case Opcode::jump:
                    case Opcode::unwind_jump: add(instruction.immediate); break;
                    case Opcode::jump_if_false:
                    case Opcode::iter_next:
                        add(instruction.immediate);
                        add(pc + 1U);
                        break;
                    case Opcode::match_exception:
                        add(instruction.operand_a);
                        add(instruction.operand_b);
                        break;
                    case Opcode::return_value:
                    case Opcode::raise_fault:
                    case Opcode::reraise: break;
                    case Opcode::load_const:
                    case Opcode::move:
                    case Opcode::unary_op:
                    case Opcode::binary_op:
                    case Opcode::compare:
                    case Opcode::call:
                    case Opcode::enter_try:
                    case Opcode::leave_try:
                    case Opcode::yield_value:
                    case Opcode::await_fact:
                    case Opcode::await_capability:
                    case Opcode::read_state:
                    case Opcode::write_state:
                    case Opcode::append_effect:
                    case Opcode::begin_transaction:
                    case Opcode::commit_transaction:
                    case Opcode::rollback_transaction:
                    case Opcode::build_list:
                    case Opcode::build_tuple:
                    case Opcode::build_dict:
                    case Opcode::get_iter:
                    case Opcode::load_subscript:
                    case Opcode::store_subscript:
                    case Opcode::delete_state:
                    case Opcode::load_current_exception:
                    case Opcode::build_record:
                    case Opcode::emit_event: add(pc + 1U); break;
                    case Opcode::leave_except: add(pc + 1U); break;
                    default: break;
                }
            };
            for (std::uint32_t pc = 0U; pc < instruction_count; ++pc) {
                add_normal_successors(pc, [&](const std::uint32_t successor) {
                    for (const auto &region : function.exception_regions) {
                        const auto source_inside = pc >= region.begin_instruction && pc < region.end_instruction;
                        const auto successor_inside =
                            successor >= region.begin_instruction && successor < region.end_instruction;
                        if (successor >= instruction_count || source_inside || !successor_inside ||
                            successor == region.begin_instruction) {
                            continue;
                        }
                        diagnostics.push_back(
                            bytecode_error("PYC0110", "ordinary control flow enters the middle of an exception region",
                                           function.instructions[pc].span));
                    }
                });
            }
            for (const auto &region : function.exception_regions) {
                if (region.kind != ExceptionRegionKind::cleanup || region.cleanup_instruction >= instruction_count) {
                    continue;
                }
                std::vector<bool> visited(instruction_count, false);
                std::deque<std::uint32_t> work {region.cleanup_instruction};
                visited[region.cleanup_instruction] = true;
                while (!work.empty()) {
                    const auto pc = work.front();
                    work.pop_front();
                    const auto opcode = function.instructions[pc].opcode;
                    if (opcode == Opcode::leave_try || opcode == Opcode::return_value ||
                        opcode == Opcode::raise_fault || opcode == Opcode::reraise || opcode == Opcode::unwind_jump) {
                        continue;
                    }
                    add_normal_successors(pc, [&](const std::uint32_t successor) {
                        if (successor >= instruction_count) {
                            diagnostics.push_back(bytecode_error("PYC0110",
                                                                 "cleanup path reaches the end without a continuation",
                                                                 function.instructions[pc].span));
                            return;
                        }
                        if (successor >= region.begin_instruction && successor < region.end_instruction) {
                            diagnostics.push_back(bytecode_error("PYC0114",
                                                                 "cleanup path re-enters its protected interval",
                                                                 function.instructions[pc].span));
                            return;
                        }
                        if (!visited[successor]) {
                            visited[successor] = true;
                            work.push_back(successor);
                        }
                    });
                }
            }
            for (const auto &[root, targets] : filter_handler_targets) {
                for (const auto target : targets) {
                    std::vector<bool> visited(instruction_count, false);
                    std::deque<std::uint32_t> work;
                    if (target < instruction_count) {
                        visited[target] = true;
                        work.push_back(target);
                    }
                    while (!work.empty()) {
                        const auto pc = work.front();
                        work.pop_front();
                        if (filter_nodes.contains(pc)) {
                            diagnostics.push_back(
                                bytecode_error("PYC0112", "exception handler control flow re-enters a filter chain",
                                               function.instructions[root].span));
                            break;
                        }
                        add_normal_successors(pc, [&](const std::uint32_t successor) {
                            if (successor < instruction_count && !visited[successor]) {
                                visited[successor] = true;
                                work.push_back(successor);
                            }
                        });
                    }
                }
            }
            std::vector<bool> normal_reachable(instruction_count, false);
            std::deque<std::uint32_t> normal_work;
            if (instruction_count != 0U) {
                normal_reachable.front() = true;
                normal_work.push_back(0U);
            }
            while (!normal_work.empty()) {
                const auto pc = normal_work.front();
                normal_work.pop_front();
                add_normal_successors(pc, [&](const std::uint32_t successor) {
                    if (successor < instruction_count && !normal_reachable[successor]) {
                        normal_reachable[successor] = true;
                        normal_work.push_back(successor);
                    }
                });
            }
            for (std::uint32_t pc = 0U; pc < instruction_count; ++pc) {
                if (!normal_reachable[pc]) {
                    continue;
                }
                const auto opcode = function.instructions[pc].opcode;
                if (opcode == Opcode::load_current_exception || opcode == Opcode::match_exception ||
                    opcode == Opcode::reraise || opcode == Opcode::leave_except) {
                    diagnostics.push_back(bytecode_error(
                        "PYC0113", "current-exception instruction is reachable without an exception edge",
                        function.instructions[pc].span));
                }
            }
            for (const auto &region : function.exception_regions) {
                if (region.handler_instruction < instruction_count && normal_reachable[region.handler_instruction]) {
                    diagnostics.push_back(
                        bytecode_error("PYC0113", "exception handler is reachable by ordinary control flow"));
                }
                if (region.kind == ExceptionRegionKind::cleanup && region.cleanup_instruction < instruction_count &&
                    normal_reachable[region.cleanup_instruction]) {
                    diagnostics.push_back(
                        bytecode_error("PYC0113", "cleanup entry is reachable by ordinary control flow"));
                }
                if (region.kind != ExceptionRegionKind::cleanup || region.begin_instruction >= region.end_instruction ||
                    region.end_instruction > instruction_count) {
                    continue;
                }
                for (auto pc = region.begin_instruction; pc < region.end_instruction; ++pc) {
                    const auto &instruction = function.instructions[pc];
                    if (instruction.opcode == Opcode::return_value || instruction.opcode == Opcode::raise_fault ||
                        instruction.opcode == Opcode::reraise || instruction.opcode == Opcode::unwind_jump) {
                        continue;
                    }
                    add_normal_successors(pc, [&](const std::uint32_t successor) {
                        if (successor < region.begin_instruction || successor >= region.end_instruction) {
                            diagnostics.push_back(
                                bytecode_error("PYC0114", "ordinary control-flow edge bypasses a cleanup continuation",
                                               instruction.span));
                        }
                    });
                }
            }
        }

        for (const auto &certificate : pack.optimization_certificates) {
            if (!function_ids.contains(certificate.executable.value)) {
                diagnostics.push_back(
                    bytecode_error("PYC0200", "optimizer certificate references an unknown executable"));
            }
            if (certificate.transitively_pure &&
                (certificate.emits_effects || certificate.emits_events || certificate.reads_state ||
                 certificate.reads_history || certificate.calls_services || certificate.may_fault ||
                 certificate.recorder_observable)) {
                diagnostics.push_back(
                    bytecode_error("PYC0201", "pure optimizer certificate contradicts its effect summary"));
            }
            const auto function = std::ranges::find(pack.functions, certificate.executable, &BytecodeFunction::id);
            if (function != pack.functions.end() &&
                std::ranges::any_of(
                    function->instructions,
                    [](const Instruction &instruction) { return instruction.opcode == Opcode::emit_event; }) &&
                !certificate.emits_events) {
                diagnostics.push_back(bytecode_error("PYC0202", "optimizer certificate omits a direct event emission"));
            }
        }

        if (!diagnostics.empty()) {
            return std::unexpected(std::move(diagnostics));
        }
        return {};
    }

    std::expected<std::vector<EventEnvelope>, EventProjectionError>
    project_committed_events(const EventEnvelope &root, const VmInvocation &invocation, const SchemaCatalog &schemas,
                             const std::span<const EventIntent> intents, const EventProjectionLimits &limits) {
        if (root.id.empty() || root.tenant.empty() || root.peer.empty() || invocation.invocation.empty() ||
            invocation.binding.empty() || invocation.root_event != root.id || limits.maximum_intents == 0U ||
            limits.maximum_bytes == 0U || limits.maximum_depth == 0U) {
            return std::unexpected(projection_error(EventProjectionErrorCode::invalid_context,
                                                    "event projection context or limits are invalid"));
        }
        if (intents.size() > limits.maximum_intents) {
            return std::unexpected(
                projection_error(EventProjectionErrorCode::budget_exhausted, "event intent count budget is exhausted"));
        }

        EventPayloadValidation payload_state;
        std::vector<EventEnvelope> projected;
        projected.reserve(intents.size());
        std::uint64_t previous_sequence {};
        std::set<std::string, std::less<>> identities;
        for (const auto &intent : intents) {
            if (intent.disposition != EventDisposition::committed) {
                return std::unexpected(projection_error(EventProjectionErrorCode::invalid_identity,
                                                        "only committed event intents may be projected", intent.span));
            }
            if (intent.root_event != root.id || intent.invocation != invocation.invocation ||
                intent.binding != invocation.binding || intent.owner.empty() || intent.sequence == 0U ||
                intent.id != deterministic_event_intent_id(root.id, invocation.invocation, intent.sequence) ||
                !identities.insert(intent.id.value).second) {
                return std::unexpected(projection_error(EventProjectionErrorCode::invalid_identity,
                                                        "event intent identity does not match its invocation",
                                                        intent.span));
            }
            if (intent.sequence <= previous_sequence) {
                return std::unexpected(projection_error(EventProjectionErrorCode::invalid_order,
                                                        "event intent sequence is not strictly increasing",
                                                        intent.span));
            }
            previous_sequence = intent.sequence;

            const auto descriptor = std::ranges::find(schemas.descriptors, intent.schema, &SchemaDescriptor::id);
            if (descriptor == schemas.descriptors.end() || descriptor->kind != SchemaKind::event ||
                descriptor->canonical_hash.empty() || descriptor->canonical_hash != intent.schema_hash) {
                return std::unexpected(projection_error(EventProjectionErrorCode::invalid_schema,
                                                        "event intent does not pin an active event schema",
                                                        intent.span));
            }
            if (intent.payload.canonical_digest.empty() || !canonical_label(intent.payload.label)) {
                return std::unexpected(projection_error(EventProjectionErrorCode::invalid_payload,
                                                        "event payload digest or label is not canonical", intent.span));
            }
            if (auto valid = validate_event_value(intent.payload.value, payload_state, limits.maximum_bytes,
                                                  limits.maximum_depth, 0U, intent.span);
                !valid) {
                return std::unexpected(valid.error());
            }
            if (auto valid = validate_event_schema(intent.payload.value, intent.schema, schemas, intent.span); !valid) {
                return std::unexpected(valid.error());
            }
            const auto *record = std::get_if<FactRecord>(&intent.payload.value.node->data);
            if (record == nullptr || intent.payload.label != event_payload_label(*record, *descriptor)) {
                return std::unexpected(projection_error(EventProjectionErrorCode::invalid_payload,
                                                        "event payload label does not match its schema fields",
                                                        intent.span));
            }

            projected.push_back(EventEnvelope {
                .id = EventId {intent.id.value},
                .schema = intent.schema,
                .tenant = root.tenant,
                .peer = root.peer,
                .subject = root.subject,
                .producer_unix_ms = root.ingest_unix_ms,
                .ingest_unix_ms = root.ingest_unix_ms,
                .label = intent.payload.label,
                .causation = root.id,
                .payload = intent.payload,
            });
        }
        return projected;
    }

} // namespace rule_engine::python
