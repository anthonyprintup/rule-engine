#pragma once

#include "rule_engine/python/packaging/error.hpp"

#include <cstdint>
#include <expected>
#include <filesystem>
#include <string>
#include <string_view>

namespace rule_engine::python::packaging {

    inline constexpr std::uint32_t python_worker_protocol_v1 = 1;

    enum struct RuntimePlatform { windows_x86_64 };
    enum struct RuntimeOrigin { private_bundle, system_installation };

    struct PythonRuntimeDescriptor {
        std::string python_version;
        RuntimePlatform platform {RuntimePlatform::windows_x86_64};
        std::string artifact_url;
        std::string artifact_sha256;
        std::uint32_t worker_protocol {python_worker_protocol_v1};
        auto operator<=>(const PythonRuntimeDescriptor &) const = default;
    };

    struct PrivatePythonRuntime {
        PythonRuntimeDescriptor descriptor;
        RuntimeOrigin origin {RuntimeOrigin::private_bundle};
        std::filesystem::path runtime_root;
        std::filesystem::path python_executable;
        std::filesystem::path worker_script;
        std::filesystem::path crypto_library;
        std::filesystem::path installation_manifest;
        std::string verified_artifact_sha256;
    };

    struct PythonRuntimeStageRequest {
        std::filesystem::path artifact_archive;
        std::filesystem::path extracted_distribution;
        std::filesystem::path destination;
        std::filesystem::path worker_script;
    };

    [[nodiscard]] PythonRuntimeDescriptor official_windows_cpython_3146();
    [[nodiscard]] std::string_view private_python_worker_script_sha256() noexcept;
    [[nodiscard]] std::expected<PrivatePythonRuntime, PackagingError>
    stage_exact_private_runtime(const PythonRuntimeStageRequest &request);
    [[nodiscard]] std::expected<PrivatePythonRuntime, PackagingError>
    load_exact_private_runtime(const std::filesystem::path &runtime_root);
    [[nodiscard]] std::expected<void, PackagingError>
    validate_exact_private_runtime(const PrivatePythonRuntime &runtime);

} // namespace rule_engine::python::packaging
