#pragma once

#include "rule_engine/python/compiler/frontend.hpp"

#include <cstdint>

namespace rule_engine::python::tools {

    struct ResidentActivePack {
        std::uint64_t generation {};
        compiler::CompilationArtifact compilation;
    };

} // namespace rule_engine::python::tools
