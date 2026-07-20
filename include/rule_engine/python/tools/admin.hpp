#pragma once

#include "rule_engine/python/tools/diagnostics.hpp"

#include <cstdint>
#include <expected>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace rule_engine::python::tools {

    enum struct AdminAction : std::uint8_t {
        upload,
        stage,
        activate,
        rollback,
        operation,
        packs,
        nodes,
        policy,
        quarantine,
        trace,
        capture,
        backfill,
        outbox,
        deadletters,
        purge,
        audit,
    };

    struct AdminCommand {
        AdminAction action {AdminAction::packs};
        std::vector<std::string> operands;
        std::map<std::string, std::string, std::less<>> options;
        OutputFormat format {OutputFormat::text};
        std::string request_id;
        std::string reason;
        bool wait {};
        bool preview {};
    };

    struct AdminToolResult {
        bool success {};
        DiagnosticSet diagnostics;
        std::vector<SourceDocument> sources;
        std::vector<DisplayField> fields;
    };

    struct AdminToolBackend {
        virtual ~AdminToolBackend() = default;
        [[nodiscard]] virtual std::expected<AdminToolResult, ToolFailure> execute(const AdminCommand &command) = 0;
    };

    [[nodiscard]] bool admin_action_mutates(AdminAction action) noexcept;
    [[nodiscard]] bool admin_action_defaults_to_preview(AdminAction action) noexcept;
    [[nodiscard]] std::string_view admin_action_name(AdminAction action) noexcept;

} // namespace rule_engine::python::tools
