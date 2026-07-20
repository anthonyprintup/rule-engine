#pragma once

#include "rule_engine/python/contract/core.hpp"

#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <vector>

namespace rule_engine::python::tools {

    inline constexpr auto tools_api_version = "1.0.0";

    enum struct ExitCode : std::uint8_t {
        success = 0,
        operation_failed = 1,
        command_line_error = 2,
        unavailable = 3,
        authentication_or_authorization_failed = 4,
        internal_invariant_failed = 5,
    };

    enum struct OutputFormat : std::uint8_t { text, json, sarif };

    enum struct ToolFailureKind : std::uint8_t {
        operation,
        unavailable_dependency,
        unavailable_transport,
        authentication,
        authorization,
        internal_invariant,
    };

    struct ToolFailure {
        ToolFailureKind kind {ToolFailureKind::operation};
        std::string code;
        std::string message;
        DiagnosticSet diagnostics;
    };

    struct DisplayField {
        std::string name;
        std::string value;
        DataLabel label;
        bool secret_reference {};
    };

    struct CommandOutput {
        ExitCode exit_code {ExitCode::success};
        std::string standard_output;
        std::string standard_error;
    };

    [[nodiscard]] ExitCode exit_code_for(const ToolFailure &failure) noexcept;
    [[nodiscard]] bool has_errors(const DiagnosticSet &diagnostics) noexcept;
    [[nodiscard]] std::expected<OutputFormat, std::string> parse_output_format(std::string_view value);
    [[nodiscard]] std::string_view output_format_name(OutputFormat format) noexcept;

} // namespace rule_engine::python::tools
