#pragma once

#include "rule_engine/python/contract/budget.hpp"
#include "rule_engine/python/contract/core.hpp"

#include <cstdint>
#include <expected>
#include <string>
#include <vector>

namespace rule_engine::python {

    enum struct SchemaKind : std::uint8_t {
        model,
        fact,
        scope,
        service,
        action,
        event,
        state,
        capability,
    };

    struct SchemaField {
        std::uint32_t field_id {};
        std::string name;
        SchemaId type;
        bool optional {};
        DataLabel label;
    };

    struct SchemaDescriptor {
        SchemaId id;
        SchemaKind kind {};
        std::string qualified_name;
        std::string canonical_hash;
        std::vector<SchemaField> fields;
    };

    struct SchemaCatalog {
        std::vector<SchemaDescriptor> descriptors;
        std::string canonical_hash;
    };

    struct OperatorBinding {
        BindingId id;
        ExecutableId executable;
        std::vector<CapabilityId> capabilities;
        BudgetProfile budget {balanced_v1};
    };

    using OperatorBindings = std::vector<OperatorBinding>;

    struct PackManifest {
        PackId pack;
        PackVersion version;
        std::string compiler_abi;
        std::string budget_profile;
        std::vector<std::string> entry_modules;
        std::vector<std::string> dependency_digests;
    };

    struct SourceFile {
        SourceId id;
        std::string module;
        std::string utf8;
        SourceDigest digest;
    };

    struct TrustResult {
        std::string signer_key_id;
        std::string signature_algorithm;
        bool production_authorized {};
    };

    struct VerifiedRulePack {
        PackManifest manifest;
        std::vector<SourceFile> sources;
        TrustResult trust;
        SourceDigest closure_digest;
    };

    enum struct Opcode : std::uint16_t {
        load_const,
        move,
        unary_op,
        binary_op,
        compare,
        jump,
        jump_if_false,
        call,
        return_value,
        raise_fault,
        enter_try,
        leave_try,
        yield_value,
        await_fact,
        await_capability,
        read_state,
        write_state,
        append_effect,
        begin_transaction,
        commit_transaction,
        rollback_transaction,
    };

    struct Instruction {
        Opcode opcode {};
        std::uint32_t destination {};
        std::uint32_t operand_a {};
        std::uint32_t operand_b {};
        std::uint32_t immediate {};
        SourceSpan span;
    };

    struct ExceptionRegion {
        std::uint32_t begin_instruction {};
        std::uint32_t end_instruction {};
        std::uint32_t handler_instruction {};
        std::uint32_t cleanup_instruction {};
    };

    struct BytecodeFunction {
        ExecutableId id;
        std::string qualified_name;
        std::uint32_t register_count {};
        std::uint32_t parameter_count {};
        bool generator {};
        bool async {};
        std::vector<Instruction> instructions;
        std::vector<ExceptionRegion> exception_regions;
    };

    struct OptimizationCertificate {
        ExecutableId executable;
        bool transitively_pure {};
        bool recorder_observable {};
        bool may_fault {};
        bool reads_state {};
        bool reads_history {};
        bool calls_services {};
        bool emits_effects {};
        std::vector<std::string> logical_facts;
        std::vector<std::uint32_t> pure_false_prefix_exits;
        std::string semantic_hash;
    };

    struct CompiledPack {
        PackId pack;
        PackVersion version;
        SourceDigest source_digest;
        std::string compiler_abi;
        std::string semantic_hash;
        SchemaCatalog schemas;
        std::vector<FactValue> constants;
        std::vector<BytecodeFunction> functions;
        std::vector<OperatorBinding> bindings;
        std::vector<OptimizationCertificate> optimization_certificates;
    };

    [[nodiscard]] std::expected<void, DiagnosticSet> verify_bytecode(const CompiledPack &pack);

    struct PackCompiler {
        virtual ~PackCompiler() = default;
        [[nodiscard]] virtual std::expected<CompiledPack, DiagnosticSet>
        compile(const VerifiedRulePack &pack, const SchemaCatalog &schemas, const OperatorBindings &bindings) = 0;
    };

} // namespace rule_engine::python
