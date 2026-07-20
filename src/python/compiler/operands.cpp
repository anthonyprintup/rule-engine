#include "rule_engine/python/compiler/operands.hpp"

#include <algorithm>
#include <optional>
#include <string>
#include <utility>

namespace rule_engine::python::compiler {
    namespace {

        [[nodiscard]] FactValue text_fact(std::string value) {
            return make_fact(UnicodeValue {.utf8 = std::move(value)});
        }

        [[nodiscard]] FactValue operand_record(const std::string_view schema, std::vector<FactRecordField> fields) {
            return make_fact(FactRecord {.schema = SchemaId {std::string {schema}}, .fields = std::move(fields)});
        }

        [[nodiscard]] Diagnostic operand_error(std::string message) {
            return Diagnostic {.code = "PYC-OPERAND-CONSTANT",
                               .severity = DiagnosticSeverity::error,
                               .message = std::move(message),
                               .span = std::nullopt,
                               .related = {}};
        }

        [[nodiscard]] std::optional<std::string> text_field(const FactRecord &record, const std::uint32_t id) {
            const auto found = std::ranges::find(record.fields, id, &FactRecordField::field_id);
            if (found == record.fields.end() || !found->value.valid()) {
                return std::nullopt;
            }
            const auto *text = std::get_if<UnicodeValue>(&found->value.node->data);
            return text == nullptr ? std::nullopt : std::optional<std::string> {text->utf8};
        }

        [[nodiscard]] std::expected<const FactRecord *, DiagnosticSet>
        record(const FactValue &value, const std::string_view schema, const std::size_t fields) {
            if (!value.valid()) {
                return std::unexpected(DiagnosticSet {operand_error("VM operand constant is empty")});
            }
            const auto *record_value = std::get_if<FactRecord>(&value.node->data);
            if (record_value == nullptr || record_value->schema.value != schema ||
                record_value->fields.size() != fields) {
                return std::unexpected(
                    DiagnosticSet {operand_error("VM operand constant has the wrong record schema or field count")});
            }
            std::uint32_t previous {};
            for (const auto &field : record_value->fields) {
                if (field.field_id == 0U || field.field_id <= previous) {
                    return std::unexpected(DiagnosticSet {operand_error("VM operand record fields are not canonical")});
                }
                previous = field.field_id;
            }
            return record_value;
        }

    } // namespace

    FactValue make_vm_fact_operand(FactRoute route, SchemaId expected_schema) {
        return operand_record(
            vm_fact_operand_schema,
            {
                FactRecordField {.field_id = 1U, .value = text_fact(std::move(route.provider))},
                FactRecordField {.field_id = 2U, .value = text_fact(std::move(route.fact))},
                FactRecordField {.field_id = 3U, .value = text_fact(std::move(expected_schema.value))},
            });
    }

    FactValue make_vm_capability_operand(CapabilityId capability, SchemaId request_schema) {
        return operand_record(vm_capability_operand_schema,
                              {
                                  FactRecordField {.field_id = 1U, .value = text_fact(std::move(capability.value))},
                                  FactRecordField {.field_id = 2U, .value = text_fact(std::move(request_schema.value))},
                              });
    }

    std::expected<FactOperand, DiagnosticSet> decode_vm_fact_operand(const FactValue &value) {
        const auto decoded = record(value, vm_fact_operand_schema, 3U);
        if (!decoded) {
            return std::unexpected(decoded.error());
        }
        const auto provider = text_field(**decoded, 1U);
        const auto fact = text_field(**decoded, 2U);
        const auto schema = text_field(**decoded, 3U);
        if (!provider || provider->empty() || !fact || fact->empty() || !schema || schema->empty()) {
            return std::unexpected(
                DiagnosticSet {operand_error("fact operand requires nonempty provider, fact, and schema strings")});
        }
        return FactOperand {
            .route = FactRoute {.provider = *provider, .fact = *fact},
            .expected_schema = SchemaId {*schema},
        };
    }

    std::expected<CapabilityOperand, DiagnosticSet> decode_vm_capability_operand(const FactValue &value) {
        const auto decoded = record(value, vm_capability_operand_schema, 2U);
        if (!decoded) {
            return std::unexpected(decoded.error());
        }
        const auto capability = text_field(**decoded, 1U);
        const auto schema = text_field(**decoded, 2U);
        if (!capability || capability->empty() || !schema || schema->empty()) {
            return std::unexpected(
                DiagnosticSet {operand_error("capability operand requires nonempty capability and schema strings")});
        }
        return CapabilityOperand {.capability = CapabilityId {*capability}, .request_schema = SchemaId {*schema}};
    }

} // namespace rule_engine::python::compiler
