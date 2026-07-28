#pragma once

#include "rule_engine/python/tools/filesystem.hpp"
#include "rule_engine/python/tools/resident_service.hpp"

namespace rule_engine::python::tools {

    [[nodiscard]] std::expected<ResidentAdminRequest, ToolFailure>
    build_resident_admin_request(const AdminCommand &command, std::uint64_t at_unix_ms);

    // Production adapter for the standalone CLI. Every command creates one
    // mutually authenticated TLS session, sends one canonical bounded admin
    // request, validates the correlated response, and closes the connection.
    struct ResidentAdminClientAdapter final: LocalControlPlaneAdapter {
        [[nodiscard]] std::expected<AdminToolResult, ToolFailure> execute(const AdminEndpointConfiguration &endpoint,
                                                                          const AdminCommand &command) override;
    };

} // namespace rule_engine::python::tools
