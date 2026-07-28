#pragma once

#include "rule_engine/python/compiler/frontend.hpp"
#include "rule_engine/python/packaging/generator.hpp"
#include "rule_engine/python/packaging/source_pack.hpp"
#include "rule_engine/python/packaging/worker.hpp"

#include <cstdint>
#include <expected>
#include <optional>
#include <stop_token>
#include <string>

namespace rule_engine::python::compiler {

    enum struct SourcePackCompileErrorKind : std::uint8_t {
        canceled,
        authorization,
        source,
        worker,
        generator,
        compiler,
        invariant,
    };

    struct SourcePackCompileError {
        SourcePackCompileErrorKind kind {SourcePackCompileErrorKind::compiler};
        std::string code;
        std::string message;
        DiagnosticSet diagnostics;
    };

    struct SourcePackCompilation {
        CompilationArtifact artifact;
        std::optional<packaging::CanonicalGeneratorOutput> generated;
    };

    // Authoritative source-pack compilation shared by operator tooling and
    // resident startup. Python only parses trusted source and expands an
    // explicitly authorized generator; C++ validates and owns every semantic
    // artifact and binding.
    [[nodiscard]] std::expected<SourcePackCompilation, SourcePackCompileError>
    compile_source_pack(const packaging::LoadedSourcePack &pack, const packaging::SourcePackArchive &archive,
                        packaging::WorkerClient &worker, const SchemaCatalog &schemas = {},
                        std::stop_token cancellation = {});

} // namespace rule_engine::python::compiler
