#pragma once

#include "rule_engine/python/compiler/ast.hpp"

namespace rule_engine::python::compiler::detail {

    [[nodiscard]] std::expected<AstEnvelope, DiagnosticSet> finish_ast_envelope(AstEnvelope envelope,
                                                                                const VerifiedRulePack &pack);

} // namespace rule_engine::python::compiler::detail
