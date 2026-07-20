#pragma once

#include "rule_engine/python/contract/budget.hpp"
#include "rule_engine/python/contract/core.hpp"
#include "rule_engine/python/packaging/error.hpp"
#include "rule_engine/python/packaging/runtime.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace rule_engine::python::packaging {

    inline constexpr std::string_view static_source_schema_v1 = "rule-engine.source/1";
    inline constexpr std::string_view static_ast_schema_v1 = "rule-engine.ast/1";
    inline constexpr std::string_view generator_request_schema_v1 = "rule-engine.generator-request/1";
    inline constexpr std::string_view generated_bindings_schema_v1 = "rule-engine.bindings/1";

    enum struct WorkerMode { static_parse, trusted_generator };
    enum struct WorkerResponseStatus { ok, rejected };

    struct OpaqueWorkerPayload {
        std::string schema;
        SourceId source;
        SourceDigest source_digest;
        std::vector<std::byte> bytes;
    };

    struct WorkerRequest {
        std::uint32_t protocol {python_worker_protocol_v1};
        RequestId request_id;
        WorkerMode mode {WorkerMode::static_parse};
        PythonRuntimeDescriptor runtime {official_windows_cpython_3146()};
        OpaqueWorkerPayload payload;
        std::uint32_t hash_seed {};
        bool generator_execution_authorized {};
    };

    struct WorkerResponse {
        std::uint32_t protocol {python_worker_protocol_v1};
        RequestId request_id;
        WorkerMode mode {WorkerMode::static_parse};
        std::string runtime_version;
        std::string runtime_artifact_sha256;
        WorkerResponseStatus status {WorkerResponseStatus::ok};
        OpaqueWorkerPayload payload;
    };

    struct WorkerLimits {
        std::size_t maximum_frame_bytes {256U * mebibyte};
        std::size_t maximum_payload_bytes {64U * mebibyte};
        std::size_t maximum_stderr_bytes {64U * kibibyte};
    };

    struct WorkerProcessResult {
        std::int32_t exit_code {};
        bool crashed {};
        bool timed_out {};
        bool output_limited {};
        bool process_tree_terminated {true};
        std::vector<std::byte> stdout_bytes;
        std::string stderr_excerpt;
    };

    struct WorkerLauncher {
        virtual ~WorkerLauncher() = default;

        // The platform implementation must bound and reap the process tree for
        // availability. These limits are not a hostile-code sandbox boundary.
        [[nodiscard]] virtual std::expected<WorkerProcessResult, PackagingError>
        launch(const PrivatePythonRuntime &runtime, WorkerMode mode, std::span<const std::byte> framed_request,
               const WorkerLimits &limits) = 0;
    };

    [[nodiscard]] std::expected<std::vector<std::byte>, PackagingError>
    encode_worker_frame(std::string_view json, std::size_t maximum_frame_bytes);
    [[nodiscard]] std::expected<std::string, PackagingError> decode_worker_frame(std::span<const std::byte> frame,
                                                                                 std::size_t maximum_frame_bytes);
    [[nodiscard]] std::expected<std::vector<std::byte>, PackagingError>
    encode_worker_request_frame(const WorkerRequest &request, const WorkerLimits &limits = {});
    [[nodiscard]] std::expected<std::vector<std::byte>, PackagingError>
    encode_worker_response_frame(const WorkerResponse &response, const WorkerLimits &limits = {});
    [[nodiscard]] std::expected<WorkerResponse, PackagingError>
    decode_worker_response_frame(std::span<const std::byte> frame, const WorkerLimits &limits = {});

    struct WorkerClient {
        PrivatePythonRuntime runtime;
        WorkerLauncher &launcher;
        WorkerLimits limits;

        [[nodiscard]] std::expected<WorkerResponse, PackagingError> invoke(const WorkerRequest &request);
    };

} // namespace rule_engine::python::packaging
