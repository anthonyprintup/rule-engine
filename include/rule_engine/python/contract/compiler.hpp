#pragma once

#include "rule_engine/python/contract/budget.hpp"
#include "rule_engine/python/contract/core.hpp"

#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <vector>

namespace rule_engine::python {

    inline constexpr std::string_view python_ast_schema_v1 = "rule-engine.ast/1";
    inline constexpr std::string_view python_static_compiler_abi_v1 = "python-3.14.6/static-compiler-v1";
    inline constexpr std::string_view python_event_operand_schema_v1 = "rule-engine.vm.event-operand.v1";

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

    // Uses the compiler's stable schema digest algorithm. Callers must pass a
    // complete canonical descriptor, not a value or route name.
    [[nodiscard]] std::string canonical_schema_hash(std::string_view canonical_descriptor);
    [[nodiscard]] std::optional<SchemaIdentity> resolve_schema_identity(const SchemaCatalog &catalog,
                                                                         const SchemaId &schema);

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
        build_list,
        build_tuple,
        build_dict,
        get_iter,
        iter_next,
        load_subscript,
        store_subscript,
        delete_state,
        load_current_exception,
        match_exception,
        reraise,
        unwind_jump,
        leave_except,
        emit_event,
    };

    // Closed, engine-owned exception classes understood by the bytecode verifier and VM.
    // `exception` is a catch-all filter and is not a concrete raise kind.
    enum struct PythonFaultKind : std::uint8_t {
        value_error,
        type_error,
        arithmetic_error,
        exception,
    };

    enum struct ExceptionRegionKind : std::uint8_t {
        handler,
        cleanup,
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
        ExceptionRegionKind kind {ExceptionRegionKind::handler};
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
        bool emits_events {};
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
