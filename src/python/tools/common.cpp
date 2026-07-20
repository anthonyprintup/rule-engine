#include "rule_engine/python/tools/common.hpp"

#include <algorithm>

namespace rule_engine::python::tools {

    ExitCode exit_code_for(const ToolFailure &failure) noexcept {
        switch (failure.kind) {
            case ToolFailureKind::operation: return ExitCode::operation_failed;
            case ToolFailureKind::unavailable_dependency:
            case ToolFailureKind::unavailable_transport: return ExitCode::unavailable;
            case ToolFailureKind::authentication:
            case ToolFailureKind::authorization: return ExitCode::authentication_or_authorization_failed;
            case ToolFailureKind::internal_invariant:
            default: break;
        }
        return ExitCode::internal_invariant_failed;
    }

    bool has_errors(const DiagnosticSet &diagnostics) noexcept {
        return std::ranges::any_of(
            diagnostics, [](const Diagnostic &diagnostic) { return diagnostic.severity == DiagnosticSeverity::error; });
    }

    std::expected<OutputFormat, std::string> parse_output_format(const std::string_view value) {
        if (value == "text") {
            return OutputFormat::text;
        }
        if (value == "json") {
            return OutputFormat::json;
        }
        if (value == "sarif") {
            return OutputFormat::sarif;
        }
        return std::unexpected("format must be one of text, json, or sarif");
    }

    std::string_view output_format_name(const OutputFormat format) noexcept {
        switch (format) {
            case OutputFormat::text: return "text";
            case OutputFormat::json: return "json";
            case OutputFormat::sarif: return "sarif";
            default: return "text";
        }
    }

} // namespace rule_engine::python::tools
