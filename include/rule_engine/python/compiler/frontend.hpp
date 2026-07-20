#pragma once

#include "rule_engine/python/compiler/ast.hpp"
#include "rule_engine/python/compiler/operands.hpp"

#include <expected>
#include <span>
#include <string>
#include <vector>

namespace rule_engine::python::compiler {

    enum struct StaticTypeKind : std::uint8_t {
        none,
        boolean,
        integer,
        floating,
        string,
        bytes,
        list,
        dictionary,
        model,
        callable,
        unknown,
    };

    struct StaticType {
        StaticTypeKind kind {StaticTypeKind::unknown};
        std::string qualified_name;
        auto operator<=>(const StaticType &) const = default;
    };

    enum struct SymbolKind : std::uint8_t {
        module,
        imported,
        parameter,
        function,
        rule,
        rule_template,
        correlation,
        model,
    };

    struct BoundSymbol {
        std::string module;
        std::string name;
        std::string qualified_name;
        SymbolKind kind {SymbolKind::function};
        StaticType type;
        SourceSpan span;
        bool public_api {};
        bool async {};
        bool generator {};
        auto operator<=>(const BoundSymbol &) const = default;
    };

    struct FactRequirement {
        ExecutableId executable;
        std::string parameter;
        std::string attribute_path;
        FactRoute route;
        SchemaId expected_schema;
        std::uint32_t operand_constant {};
        SourceSpan span;
        bool conditional {};

        [[nodiscard]] bool operator==(const FactRequirement &other) const noexcept {
            return executable == other.executable && parameter == other.parameter &&
                   attribute_path == other.attribute_path && route.provider == other.route.provider &&
                   route.fact == other.route.fact && expected_schema == other.expected_schema &&
                   operand_constant == other.operand_constant && span == other.span && conditional == other.conditional;
        }
    };

    struct CompilationArtifact {
        CompiledPack pack;
        std::vector<BoundSymbol> symbols;
        std::vector<FactRequirement> fact_requirements;
        std::string canonical_form;
    };

    struct AstEnvelopeProvider {
        virtual ~AstEnvelopeProvider() = default;
        [[nodiscard]] virtual std::expected<std::vector<std::byte>, DiagnosticSet>
        load(const VerifiedRulePack &pack) = 0;
    };

    struct StaticCompiler {
        [[nodiscard]] std::expected<CompilationArtifact, DiagnosticSet> compile(const VerifiedRulePack &pack,
                                                                                std::span<const std::byte> ast_payload,
                                                                                const SchemaCatalog &schemas,
                                                                                const OperatorBindings &bindings) const;
    };

    struct StaticPackCompiler final: PackCompiler {
        explicit StaticPackCompiler(AstEnvelopeProvider &provider) noexcept: provider_ {provider} {}

        [[nodiscard]] std::expected<CompiledPack, DiagnosticSet>
        compile(const VerifiedRulePack &pack, const SchemaCatalog &schemas, const OperatorBindings &bindings) override;

    private:
        AstEnvelopeProvider &provider_;
        StaticCompiler compiler_;
    };

    [[nodiscard]] std::expected<void, DiagnosticSet> verify_compiler_output(const CompilationArtifact &artifact);

} // namespace rule_engine::python::compiler
