#include "rule_engine/python/packaging/runtime.hpp"

namespace rule_engine::python::packaging {
    namespace {

        constexpr auto official_version = "3.14.6";
        constexpr auto official_windows_url = "https://www.python.org/ftp/python/3.14.6/python-3.14.6-embed-amd64.zip";
        constexpr auto official_windows_sha256 = "df901e84a896ff1ee720ad03377e0c8d8c2244fda79808aeeaff6316df1cb75c";

        PackagingError runtime_error(const PackagingErrorCode code, std::string message) {
            return PackagingError {.code = code, .message = std::move(message), .subject = std::nullopt};
        }

    } // namespace

    PythonRuntimeDescriptor official_windows_cpython_3146() {
        return PythonRuntimeDescriptor {
            .python_version = official_version,
            .platform = RuntimePlatform::windows_x86_64,
            .artifact_url = official_windows_url,
            .artifact_sha256 = official_windows_sha256,
            .worker_protocol = python_worker_protocol_v1,
        };
    }

    std::expected<void, PackagingError> validate_exact_private_runtime(const PrivatePythonRuntime &runtime) {
        if (runtime.origin != RuntimeOrigin::private_bundle) {
            return std::unexpected(
                runtime_error(PackagingErrorCode::runtime_mismatch, "system Python fallback is forbidden"));
        }
        if (!runtime.installation_manifest_verified || runtime.runtime_root.empty() ||
            runtime.worker_executable.empty()) {
            return std::unexpected(runtime_error(PackagingErrorCode::runtime_missing,
                                                 "private Python installation is missing or unverified"));
        }
        const auto &required = official_windows_cpython_3146();
        if (runtime.descriptor != required || runtime.verified_artifact_sha256 != required.artifact_sha256) {
            return std::unexpected(
                runtime_error(PackagingErrorCode::runtime_mismatch,
                              "private Python runtime is not the exact pinned CPython 3.14.6 artifact"));
        }
        return {};
    }

} // namespace rule_engine::python::packaging
