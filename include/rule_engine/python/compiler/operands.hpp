#pragma once

#include "rule_engine/python/contract.hpp"

#include <expected>
#include <string_view>

namespace rule_engine::python::compiler {

    inline constexpr std::string_view vm_fact_operand_schema = "rule-engine.vm.fact-operand.v1";
    inline constexpr std::string_view vm_capability_operand_schema = "rule-engine.vm.capability-operand.v1";

    struct FactOperand {
        FactRoute route;
        SchemaId expected_schema;

        [[nodiscard]] bool operator==(const FactOperand &other) const noexcept {
            return route.provider == other.route.provider && route.fact == other.route.fact &&
                   expected_schema == other.expected_schema;
        }
    };

    struct CapabilityOperand {
        CapabilityId capability;
        SchemaId request_schema;
        bool operator==(const CapabilityOperand &) const = default;
    };

    [[nodiscard]] FactValue make_vm_fact_operand(FactRoute route, SchemaId expected_schema);
    [[nodiscard]] FactValue make_vm_capability_operand(CapabilityId capability, SchemaId request_schema);
    [[nodiscard]] FactValue make_vm_event_operand(SchemaId schema, std::string schema_hash);
    [[nodiscard]] std::expected<FactOperand, DiagnosticSet> decode_vm_fact_operand(const FactValue &value);
    [[nodiscard]] std::expected<CapabilityOperand, DiagnosticSet> decode_vm_capability_operand(const FactValue &value);

} // namespace rule_engine::python::compiler
