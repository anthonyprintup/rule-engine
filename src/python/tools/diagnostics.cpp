#include "rule_engine/python/tools/diagnostics.hpp"

#include "rendering.hpp"
#include "rule_engine/python/tools/redaction.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <sstream>
#include <string_view>
#include <vector>

namespace rule_engine::python::tools {
    namespace {

        [[nodiscard]] const SourceDocument *find_source(const SourceId &id,
                                                        const std::span<const SourceDocument> sources) noexcept {
            const auto found =
                std::ranges::find_if(sources, [&id](const SourceDocument &source) { return source.id == id; });
            return found == sources.end() ? nullptr : &*found;
        }

        struct LineColumn {
            std::uint32_t line {1};
            std::uint32_t column {1};
        };

        [[nodiscard]] LineColumn line_column(const std::string_view utf8, const std::size_t offset) noexcept {
            LineColumn result;
            for (std::size_t index = 0; index < offset; ++index) {
                if (utf8[index] == '\n') {
                    ++result.line;
                    result.column = 1;
                    continue;
                }
                ++result.column;
            }
            return result;
        }

        void append_location_json(std::ostringstream &output, const ResolvedSourceSpan &location) {
            output << "{\"path\":" << detail::json_quote(redact_text(location.path))
                   << ",\"beginByte\":" << location.begin_byte << ",\"endByte\":" << location.end_byte
                   << ",\"startLine\":" << location.start_line << ",\"startColumn\":" << location.start_column
                   << ",\"endLine\":" << location.end_line << ",\"endColumn\":" << location.end_column << '}';
        }

        void append_related_json(std::ostringstream &output, const RelatedDiagnostic &related,
                                 const std::span<const SourceDocument> sources) {
            output << "{\"message\":" << detail::json_quote(redact_text(related.message));
            if (const auto location = resolve_source_span(related.span, sources); location.has_value()) {
                output << ",\"location\":";
                append_location_json(output, *location);
            }
            output << '}';
        }

        void append_diagnostic_json(std::ostringstream &output, const Diagnostic &diagnostic,
                                    const std::span<const SourceDocument> sources) {
            output << "{\"code\":" << detail::json_quote(redact_text(diagnostic.code))
                   << ",\"severity\":" << detail::json_quote(diagnostic_severity_name(diagnostic.severity))
                   << ",\"message\":" << detail::json_quote(redact_text(diagnostic.message));
            if (diagnostic.span.has_value()) {
                if (const auto location = resolve_source_span(*diagnostic.span, sources); location.has_value()) {
                    output << ",\"location\":";
                    append_location_json(output, *location);
                }
            }
            output << ",\"related\":[";
            for (std::size_t index = 0; index < diagnostic.related.size(); ++index) {
                if (index != 0) {
                    output << ',';
                }
                append_related_json(output, diagnostic.related[index], sources);
            }
            output << "]}";
        }

        [[nodiscard]] std::string sarif_level(const DiagnosticSeverity severity) {
            switch (severity) {
                case DiagnosticSeverity::note: return "note";
                case DiagnosticSeverity::warning: return "warning";
                case DiagnosticSeverity::error:
                default: break;
            }
            return "error";
        }

        void append_sarif_physical_location(std::ostringstream &output, const ResolvedSourceSpan &location) {
            output << R"({"artifactLocation":{"uri":)" << detail::json_quote(redact_text(location.path))
                   << R"(},"region":{"startLine":)" << location.start_line
                   << ",\"startColumn\":" << location.start_column << ",\"endLine\":" << location.end_line
                   << ",\"endColumn\":" << location.end_column << ",\"byteOffset\":" << location.begin_byte
                   << ",\"byteLength\":" << (location.end_byte - location.begin_byte) << "}}";
        }

    } // namespace

    std::optional<ResolvedSourceSpan> resolve_source_span(const SourceSpan &span,
                                                          const std::span<const SourceDocument> sources) noexcept {
        if (!span.valid()) {
            return std::nullopt;
        }

        const auto *source = find_source(span.source, sources);
        if (source == nullptr) {
            return ResolvedSourceSpan {
                .path = span.source.value,
                .begin_byte = span.begin_byte,
                .end_byte = span.end_byte,
                .start_line = 1,
                .start_column = span.begin_byte + 1U,
                .end_line = 1,
                .end_column = span.end_byte + 1U,
            };
        }
        if (static_cast<std::size_t>(span.end_byte) > source->utf8.size()) {
            return std::nullopt;
        }

        const auto begin = line_column(source->utf8, span.begin_byte);
        const auto end = line_column(source->utf8, span.end_byte);
        return ResolvedSourceSpan {
            .path = source->path,
            .begin_byte = span.begin_byte,
            .end_byte = span.end_byte,
            .start_line = begin.line,
            .start_column = begin.column,
            .end_line = end.line,
            .end_column = end.column,
        };
    }

    std::string diagnostic_severity_name(const DiagnosticSeverity severity) {
        switch (severity) {
            case DiagnosticSeverity::note: return "note";
            case DiagnosticSeverity::warning: return "warning";
            case DiagnosticSeverity::error:
            default: break;
        }
        return "error";
    }

    std::string render_diagnostics_text(const DiagnosticSet &diagnostics,
                                        const std::span<const SourceDocument> sources) {
        std::ostringstream output;
        for (const auto &diagnostic : diagnostics) {
            if (diagnostic.span.has_value()) {
                if (const auto location = resolve_source_span(*diagnostic.span, sources); location.has_value()) {
                    output << redact_text(location->path) << ':' << location->start_line << ':'
                           << location->start_column << ": ";
                }
            }
            output << diagnostic_severity_name(diagnostic.severity) << ' ' << redact_text(diagnostic.code) << ": "
                   << redact_text(diagnostic.message) << '\n';
            for (const auto &related : diagnostic.related) {
                output << "  note";
                if (const auto location = resolve_source_span(related.span, sources); location.has_value()) {
                    output << ' ' << redact_text(location->path) << ':' << location->start_line << ':'
                           << location->start_column;
                }
                output << ": " << redact_text(related.message) << '\n';
            }
        }
        return output.str();
    }

    std::string render_diagnostics_json(const DiagnosticSet &diagnostics,
                                        const std::span<const SourceDocument> sources) {
        std::ostringstream output;
        output << R"({"schema":"rule-engine.diagnostics.v1","diagnostics":[)";
        for (std::size_t index = 0; index < diagnostics.size(); ++index) {
            if (index != 0) {
                output << ',';
            }
            append_diagnostic_json(output, diagnostics[index], sources);
        }
        output << "]}\n";
        return output.str();
    }

    std::string render_diagnostics_sarif(const DiagnosticSet &diagnostics,
                                         const std::span<const SourceDocument> sources,
                                         const std::string_view tool_name) {
        std::vector<std::string> rule_ids;
        rule_ids.reserve(diagnostics.size());
        for (const auto &diagnostic : diagnostics) {
            if (std::ranges::find(rule_ids, diagnostic.code) == rule_ids.end()) {
                rule_ids.push_back(diagnostic.code);
            }
        }

        std::ostringstream output;
        output << "{\"$schema\":\"https://json.schemastore.org/sarif-2.1.0.json\",\"version\":\"2.1.0\","
                  "\"runs\":[{\"tool\":{\"driver\":{\"name\":"
               << detail::json_quote(redact_text(tool_name))
               << ",\"semanticVersion\":" << detail::json_quote(tools_api_version) << ",\"rules\":[";
        for (std::size_t index = 0; index < rule_ids.size(); ++index) {
            if (index != 0) {
                output << ',';
            }
            output << "{\"id\":" << detail::json_quote(redact_text(rule_ids[index])) << '}';
        }
        output << "]}},\"results\":[";

        for (std::size_t index = 0; index < diagnostics.size(); ++index) {
            if (index != 0) {
                output << ',';
            }
            const auto &diagnostic = diagnostics[index];
            output << "{\"ruleId\":" << detail::json_quote(redact_text(diagnostic.code))
                   << ",\"level\":" << detail::json_quote(sarif_level(diagnostic.severity)) << R"(,"message":{"text":)"
                   << detail::json_quote(redact_text(diagnostic.message)) << '}';
            if (diagnostic.span.has_value()) {
                if (const auto location = resolve_source_span(*diagnostic.span, sources); location.has_value()) {
                    output << R"(,"locations":[{"physicalLocation":)";
                    append_sarif_physical_location(output, *location);
                    output << "}]";
                }
            }
            if (!diagnostic.related.empty()) {
                output << ",\"relatedLocations\":[";
                bool first = true;
                std::uint32_t related_id {1};
                for (const auto &related : diagnostic.related) {
                    const auto location = resolve_source_span(related.span, sources);
                    if (!location.has_value()) {
                        continue;
                    }
                    if (!first) {
                        output << ',';
                    }
                    first = false;
                    output << "{\"id\":" << related_id++ << R"(,"message":{"text":)"
                           << detail::json_quote(redact_text(related.message)) << "},\"physicalLocation\":";
                    append_sarif_physical_location(output, *location);
                    output << '}';
                }
                output << ']';
            }
            output << '}';
        }
        output << "]}]}\n";
        return output.str();
    }

} // namespace rule_engine::python::tools
