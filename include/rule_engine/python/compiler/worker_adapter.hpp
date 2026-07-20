#pragma once

#include "rule_engine/python/compiler/frontend.hpp"
#include "rule_engine/python/packaging/worker.hpp"

#include <cstdint>

namespace rule_engine::python::compiler {

    // Invokes the exact private parser worker once per verified module, validates
    // every returned AST envelope, and merges them without executing source.
    struct WorkerAstEnvelopeProvider final: AstEnvelopeProvider {
        explicit WorkerAstEnvelopeProvider(packaging::WorkerClient &client) noexcept: client_ {client} {}

        [[nodiscard]] std::expected<std::vector<std::byte>, DiagnosticSet> load(const VerifiedRulePack &pack) override;

    private:
        packaging::WorkerClient &client_;
        std::uint64_t request_generation_ {};
    };

} // namespace rule_engine::python::compiler
