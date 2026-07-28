#pragma once

#include "rule_engine/python/compiler/frontend.hpp"

#include <cstdint>
#include <string>

namespace rule_engine::python::tools {

    struct ResidentActivePack {
        std::uint64_t generation {};
        // Durable activation selects the physical state namespace. Bytecode
        // state operands remain logical names and are mapped beneath this
        // namespace by the resident scheduler before store access.
        std::string state_namespace;
        compiler::CompilationArtifact compilation;
    };

} // namespace rule_engine::python::tools
