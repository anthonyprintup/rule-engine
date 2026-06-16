#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace rule_engine {
    struct SourceSpan {
        std::uint32_t source_id {};
        std::size_t start {};
        std::size_t end {};
        std::string source;
    };

    struct Diagnostic {
        std::string source;
        SourceSpan span {};
        std::string message;
    };

    struct ErrorSet {
        std::vector<Diagnostic> diagnostics;

        [[nodiscard]] bool empty() const noexcept { return diagnostics.empty(); }
    };

    inline ErrorSet single_error(std::string source, const std::string_view message) {
        ErrorSet out;
        out.diagnostics.push_back(Diagnostic {.source = std::move(source), .message = std::string {message}});
        return out;
    }
} // namespace rule_engine
