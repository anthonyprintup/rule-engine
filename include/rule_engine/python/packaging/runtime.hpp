#pragma once

#include "rule_engine/python/packaging/error.hpp"

#include <cstdint>
#include <expected>
#include <string>

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
        std::string runtime_root;
        std::string worker_executable;
        std::string verified_artifact_sha256;
        bool installation_manifest_verified {};
    };

    [[nodiscard]] PythonRuntimeDescriptor official_windows_cpython_3146();
    [[nodiscard]] std::expected<void, PackagingError>
    validate_exact_private_runtime(const PrivatePythonRuntime &runtime);

} // namespace rule_engine::python::packaging
