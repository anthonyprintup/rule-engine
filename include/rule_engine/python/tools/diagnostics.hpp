#pragma once

#include "rule_engine/python/tools/common.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace rule_engine::python::tools {

    struct SourceDocument {
        SourceId id;
        std::string path;
        std::string utf8;
    };

    struct ResolvedSourceSpan {
        std::string path;
        std::uint32_t begin_byte {};
        std::uint32_t end_byte {};
        std::uint32_t start_line {1};
        std::uint32_t start_column {1};
        std::uint32_t end_line {1};
        std::uint32_t end_column {1};
    };

    [[nodiscard]] std::optional<ResolvedSourceSpan>
    resolve_source_span(const SourceSpan &span, std::span<const SourceDocument> sources) noexcept;
    [[nodiscard]] std::string diagnostic_severity_name(DiagnosticSeverity severity);
    [[nodiscard]] std::string render_diagnostics_text(const DiagnosticSet &diagnostics,
                                                      std::span<const SourceDocument> sources);
    [[nodiscard]] std::string render_diagnostics_json(const DiagnosticSet &diagnostics,
                                                      std::span<const SourceDocument> sources);
    [[nodiscard]] std::string render_diagnostics_sarif(const DiagnosticSet &diagnostics,
                                                       std::span<const SourceDocument> sources,
                                                       std::string_view tool_name);

} // namespace rule_engine::python::tools
