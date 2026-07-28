#pragma once

#include "rule_engine/python/packaging/source_pack.hpp"
#include "rule_engine/python/tools/admin.hpp"
#include "rule_engine/python/tools/authoring.hpp"

#include <expected>
#include <filesystem>
#include <string>
#include <utility>

namespace rule_engine::python::tools {

    struct FilesystemToolDefaults {
        std::filesystem::path sdk_root;
    };

    struct FilesystemPackagingBackend final: PackagingToolBackend {
        explicit FilesystemPackagingBackend(FilesystemToolDefaults defaults = {}): defaults_ {std::move(defaults)} {}

        [[nodiscard]] std::expected<PackToolResult, ToolFailure> execute(const PackCommand &command) override;

    private:
        FilesystemToolDefaults defaults_;
    };

    struct FilesystemCompilerBackend final: CompilerToolBackend {
        [[nodiscard]] std::expected<CheckToolResult, ToolFailure> check(const CheckCommand &command,
                                                                        std::stop_token cancellation) override;
    };

    struct TrustFileConfiguration {
        packaging::TrustPolicy policy;
        std::filesystem::path crypto_library;
    };

    [[nodiscard]] std::expected<TrustFileConfiguration, ToolFailure> load_trust_file(const std::filesystem::path &path);

    struct AdminEndpointConfiguration {
        std::string endpoint;
        std::string server_uri;
        std::filesystem::path client_certificate;
        std::filesystem::path client_key;
        std::filesystem::path trust_bundle;
    };

    [[nodiscard]] std::expected<AdminEndpointConfiguration, ToolFailure>
    load_admin_endpoint_file(const std::filesystem::path &path);

    struct LocalControlPlaneAdapter {
        virtual ~LocalControlPlaneAdapter() = default;
        [[nodiscard]] virtual std::expected<AdminToolResult, ToolFailure>
        execute(const AdminEndpointConfiguration &endpoint, const AdminCommand &command) = 0;
    };

    struct FilesystemAdminBackend final: AdminToolBackend {
        explicit FilesystemAdminBackend(LocalControlPlaneAdapter *adapter = nullptr) noexcept: adapter_ {adapter} {}

        [[nodiscard]] std::expected<AdminToolResult, ToolFailure> execute(const AdminCommand &command) override;

    private:
        LocalControlPlaneAdapter *adapter_ {};
    };

} // namespace rule_engine::python::tools
