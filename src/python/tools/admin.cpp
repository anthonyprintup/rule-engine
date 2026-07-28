#include "rule_engine/python/tools/admin.hpp"

namespace rule_engine::python::tools {

    bool admin_action_mutates(const AdminAction action) noexcept {
        switch (action) {
            case AdminAction::operation:
            case AdminAction::packs:
            case AdminAction::audit: return false;
            case AdminAction::upload:
            case AdminAction::stage:
            case AdminAction::activate:
            case AdminAction::rollback:
            case AdminAction::nodes:
            case AdminAction::policy:
            case AdminAction::quarantine:
            case AdminAction::trace:
            case AdminAction::capture:
            case AdminAction::backfill:
            case AdminAction::outbox:
            case AdminAction::deadletters:
            case AdminAction::purge: return true;
            default: return false;
        }
    }

    bool admin_action_defaults_to_preview(const AdminAction action) noexcept {
        switch (action) {
            case AdminAction::stage:
            case AdminAction::activate:
            case AdminAction::rollback:
            case AdminAction::nodes:
            case AdminAction::policy:
            case AdminAction::quarantine:
            case AdminAction::trace:
            case AdminAction::capture:
            case AdminAction::backfill:
            case AdminAction::outbox:
            case AdminAction::deadletters:
            case AdminAction::purge: return true;
            case AdminAction::upload:
            case AdminAction::operation:
            case AdminAction::packs:
            case AdminAction::audit: return false;
            default: return true;
        }
    }

    std::string_view admin_action_name(const AdminAction action) noexcept {
        switch (action) {
            case AdminAction::upload: return "upload";
            case AdminAction::stage: return "stage";
            case AdminAction::activate: return "activate";
            case AdminAction::rollback: return "rollback";
            case AdminAction::operation: return "operation";
            case AdminAction::packs: return "packs";
            case AdminAction::nodes: return "nodes";
            case AdminAction::policy: return "policy";
            case AdminAction::quarantine: return "quarantine";
            case AdminAction::trace: return "trace";
            case AdminAction::capture: return "capture";
            case AdminAction::backfill: return "backfill";
            case AdminAction::outbox: return "outbox";
            case AdminAction::deadletters: return "deadletters";
            case AdminAction::purge: return "purge";
            case AdminAction::audit: return "audit";
            default: return "unknown";
        }
    }

} // namespace rule_engine::python::tools
