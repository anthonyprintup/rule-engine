#include "rule_engine/python/packaging/worker.hpp"

#include <algorithm>
#include <charconv>
#include <limits>
#include <string>
#include <utility>

namespace rule_engine::python::packaging {
    namespace {

        PackagingError worker_error(const PackagingErrorCode code, std::string message,
                                    std::optional<std::string> subject = std::nullopt) {
            return PackagingError {.code = code, .message = std::move(message), .subject = std::move(subject)};
        }

        bool safe_json_atom(const std::string_view value) noexcept {
            return std::ranges::all_of(value, [](const char character) {
                return character >= 0x20 && character <= 0x7e && character != '"' && character != '\\';
            });
        }

        std::string base64_encode(const std::span<const std::byte> bytes) {
            constexpr std::string_view alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            std::string output;
            output.reserve((bytes.size() + 2U) / 3U * 4U);
            for (std::size_t index = 0; index < bytes.size(); index += 3U) {
                const auto remaining = bytes.size() - index;
                const auto first = std::to_integer<std::uint32_t>(bytes[index]);
                const auto second = remaining > 1U ? std::to_integer<std::uint32_t>(bytes[index + 1U]) : 0U;
                const auto third = remaining > 2U ? std::to_integer<std::uint32_t>(bytes[index + 2U]) : 0U;
                const auto value = (first << 16U) | (second << 8U) | third;
                output.push_back(alphabet[(value >> 18U) & 0x3fU]);
                output.push_back(alphabet[(value >> 12U) & 0x3fU]);
                output.push_back(remaining > 1U ? alphabet[(value >> 6U) & 0x3fU] : '=');
                output.push_back(remaining > 2U ? alphabet[value & 0x3fU] : '=');
            }
            return output;
        }

        std::expected<std::vector<std::byte>, PackagingError> base64_decode(const std::string_view text) {
            if (text.size() % 4U != 0U) {
                return std::unexpected(worker_error(PackagingErrorCode::worker_frame_malformed,
                                                    "worker payload base64 length is invalid"));
            }
            auto decode = [](const char character) -> int {
                if (character >= 'A' && character <= 'Z') {
                    return character - 'A';
                }
                if (character >= 'a' && character <= 'z') {
                    return character - 'a' + 26;
                }
                if (character >= '0' && character <= '9') {
                    return character - '0' + 52;
                }
                if (character == '+') {
                    return 62;
                }
                if (character == '/') {
                    return 63;
                }
                return -1;
            };
            std::vector<std::byte> output;
            output.reserve(text.size() / 4U * 3U);
            for (std::size_t index = 0; index < text.size(); index += 4U) {
                const bool pad2 = text[index + 2U] == '=';
                const bool pad3 = text[index + 3U] == '=';
                if (pad2 && !pad3) {
                    return std::unexpected(worker_error(PackagingErrorCode::worker_frame_malformed,
                                                        "worker payload base64 padding is invalid"));
                }
                if ((pad2 || pad3) && index + 4U != text.size()) {
                    return std::unexpected(worker_error(PackagingErrorCode::worker_frame_malformed,
                                                        "worker payload base64 padding is not final"));
                }
                const auto first = decode(text[index]);
                const auto second = decode(text[index + 1U]);
                const auto third = pad2 ? 0 : decode(text[index + 2U]);
                const auto fourth = pad3 ? 0 : decode(text[index + 3U]);
                if (first < 0 || second < 0 || third < 0 || fourth < 0) {
                    return std::unexpected(worker_error(PackagingErrorCode::worker_frame_malformed,
                                                        "worker payload base64 contains invalid data"));
                }
                const auto value = (static_cast<std::uint32_t>(first) << 18U) |
                                   (static_cast<std::uint32_t>(second) << 12U) |
                                   (static_cast<std::uint32_t>(third) << 6U) | static_cast<std::uint32_t>(fourth);
                output.push_back(static_cast<std::byte>((value >> 16U) & 0xffU));
                if (!pad2) {
                    output.push_back(static_cast<std::byte>((value >> 8U) & 0xffU));
                }
                if (!pad3) {
                    output.push_back(static_cast<std::byte>(value & 0xffU));
                }
                if ((pad2 && (value & 0xffffU) != 0U) || (pad3 && !pad2 && (value & 0xffU) != 0U)) {
                    return std::unexpected(worker_error(PackagingErrorCode::worker_frame_malformed,
                                                        "worker payload base64 has nonzero padding bits"));
                }
            }
            return output;
        }

        std::string mode_name(const WorkerMode mode) { return mode == WorkerMode::static_parse ? "parse" : "generate"; }

        std::string status_name(const WorkerResponseStatus status) {
            return status == WorkerResponseStatus::ok ? "ok" : "rejected";
        }

        std::expected<WorkerMode, PackagingError> parse_mode(const std::string_view value) {
            if (value == "parse") {
                return WorkerMode::static_parse;
            }
            if (value == "generate") {
                return WorkerMode::trusted_generator;
            }
            return std::unexpected(
                worker_error(PackagingErrorCode::worker_frame_malformed, "worker response mode is invalid"));
        }

        std::expected<WorkerResponseStatus, PackagingError> parse_status(const std::string_view value) {
            if (value == "ok") {
                return WorkerResponseStatus::ok;
            }
            if (value == "rejected") {
                return WorkerResponseStatus::rejected;
            }
            return std::unexpected(
                worker_error(PackagingErrorCode::worker_frame_malformed, "worker response status is invalid"));
        }

        std::expected<void, PackagingError> validate_payload(const OpaqueWorkerPayload &payload,
                                                             const std::size_t maximum_payload_bytes) {
            if (payload.schema.empty() || payload.source.empty() || payload.source_digest.empty() ||
                payload.bytes.size() > maximum_payload_bytes || !safe_json_atom(payload.schema) ||
                !safe_json_atom(payload.source.value) || !safe_json_atom(payload.source_digest.value)) {
                return std::unexpected(worker_error(PackagingErrorCode::worker_response_mismatch,
                                                    "opaque worker payload identity or bounds are invalid"));
            }
            return {};
        }

        std::expected<std::string, PackagingError> request_json(const WorkerRequest &request,
                                                                const WorkerLimits &limits) {
            const auto payload_valid = validate_payload(request.payload, limits.maximum_payload_bytes);
            if (!payload_valid) {
                return std::unexpected(payload_valid.error());
            }
            if (request.protocol != python_worker_protocol_v1 || request.request_id.empty() ||
                request.runtime != official_windows_cpython_3146() || !safe_json_atom(request.request_id.value)) {
                return std::unexpected(worker_error(PackagingErrorCode::worker_protocol_mismatch,
                                                    "worker request protocol/runtime identity is invalid"));
            }
            const auto expected_schema =
                request.mode == WorkerMode::static_parse ? static_source_schema_v1 : generator_request_schema_v1;
            if (request.payload.schema != expected_schema) {
                return std::unexpected(worker_error(PackagingErrorCode::worker_response_mismatch,
                                                    "worker request payload schema does not match its mode"));
            }
            if (request.mode == WorkerMode::trusted_generator && !request.generator_execution_authorized) {
                return std::unexpected(worker_error(PackagingErrorCode::worker_unauthorized,
                                                    "generator mode requires an explicit verified-pack authorization"));
            }
            return "{\"hash_seed\":" + std::to_string(request.hash_seed) + ",\"mode\":\"" + mode_name(request.mode) +
                   "\",\"payload\":\"" + base64_encode(request.payload.bytes) + "\",\"payload_schema\":\"" +
                   request.payload.schema + "\",\"protocol\":" + std::to_string(request.protocol) +
                   ",\"request_id\":\"" + request.request_id.value + "\",\"runtime_sha256\":\"" +
                   request.runtime.artifact_sha256 + "\",\"runtime_version\":\"" + request.runtime.python_version +
                   "\",\"source_digest\":\"" + request.payload.source_digest.value + "\",\"source_id\":\"" +
                   request.payload.source.value + "\"}";
        }

        std::expected<std::string, PackagingError> response_json(const WorkerResponse &response,
                                                                 const WorkerLimits &limits) {
            const auto payload_valid = validate_payload(response.payload, limits.maximum_payload_bytes);
            if (!payload_valid) {
                return std::unexpected(payload_valid.error());
            }
            if (response.request_id.empty() || !safe_json_atom(response.request_id.value) ||
                !safe_json_atom(response.runtime_version) || !safe_json_atom(response.runtime_artifact_sha256)) {
                return std::unexpected(
                    worker_error(PackagingErrorCode::worker_response_mismatch, "worker response identity is invalid"));
            }
            return "{\"mode\":\"" + mode_name(response.mode) + "\",\"payload\":\"" +
                   base64_encode(response.payload.bytes) + "\",\"payload_schema\":\"" + response.payload.schema +
                   "\",\"protocol\":" + std::to_string(response.protocol) + ",\"request_id\":\"" +
                   response.request_id.value + "\",\"runtime_sha256\":\"" + response.runtime_artifact_sha256 +
                   "\",\"runtime_version\":\"" + response.runtime_version + "\",\"source_digest\":\"" +
                   response.payload.source_digest.value + "\",\"source_id\":\"" + response.payload.source.value +
                   "\",\"status\":\"" + status_name(response.status) + "\"}";
        }

        struct ResponseCursor {
            std::string_view input;
            std::size_t offset {};

            bool consume(const std::string_view expected) noexcept {
                if (!input.substr(offset).starts_with(expected)) {
                    return false;
                }
                offset += expected.size();
                return true;
            }

            std::expected<std::string, PackagingError> quoted(const std::string_view field) {
                const auto end = input.find('"', offset);
                if (end == std::string_view::npos) {
                    return std::unexpected(worker_error(PackagingErrorCode::worker_frame_malformed,
                                                        "worker response string is unterminated", std::string {field}));
                }
                const auto value = input.substr(offset, end - offset);
                if (!safe_json_atom(value)) {
                    return std::unexpected(worker_error(PackagingErrorCode::worker_frame_malformed,
                                                        "worker response string is not canonical",
                                                        std::string {field}));
                }
                offset = end;
                return std::string {value};
            }
        };

    } // namespace

    std::expected<std::vector<std::byte>, PackagingError> encode_worker_frame(const std::string_view json,
                                                                              const std::size_t maximum_frame_bytes) {
        if (json.size() > maximum_frame_bytes || json.size() > std::numeric_limits<std::uint32_t>::max()) {
            return std::unexpected(
                worker_error(PackagingErrorCode::worker_frame_too_large, "worker frame exceeds its configured bound"));
        }
        const auto length = static_cast<std::uint32_t>(json.size());
        std::vector<std::byte> frame;
        frame.reserve(json.size() + 4U);
        for (unsigned shift = 0; shift < 32U; shift += 8U) {
            frame.push_back(static_cast<std::byte>((length >> shift) & 0xffU));
        }
        frame.insert(frame.end(), reinterpret_cast<const std::byte *>(json.data()),
                     reinterpret_cast<const std::byte *>(json.data() + json.size()));
        return frame;
    }

    std::expected<std::string, PackagingError> decode_worker_frame(const std::span<const std::byte> frame,
                                                                   const std::size_t maximum_frame_bytes) {
        if (frame.size() < 4U) {
            return std::unexpected(worker_error(PackagingErrorCode::worker_frame_malformed,
                                                "worker frame is truncated before its length"));
        }
        const auto length =
            std::to_integer<std::uint32_t>(frame[0]) | (std::to_integer<std::uint32_t>(frame[1]) << 8U) |
            (std::to_integer<std::uint32_t>(frame[2]) << 16U) | (std::to_integer<std::uint32_t>(frame[3]) << 24U);
        if (length > maximum_frame_bytes) {
            return std::unexpected(
                worker_error(PackagingErrorCode::worker_frame_too_large, "worker frame declares an excessive payload"));
        }
        if (frame.size() != static_cast<std::size_t>(length) + 4U) {
            return std::unexpected(worker_error(PackagingErrorCode::worker_frame_malformed,
                                                "worker frame length does not match its bytes"));
        }
        const auto body = frame.subspan(4U);
        return std::string {reinterpret_cast<const char *>(body.data()), body.size()};
    }

    std::expected<std::vector<std::byte>, PackagingError> encode_worker_request_frame(const WorkerRequest &request,
                                                                                      const WorkerLimits &limits) {
        const auto json = request_json(request, limits);
        if (!json) {
            return std::unexpected(json.error());
        }
        return encode_worker_frame(*json, limits.maximum_frame_bytes);
    }

    std::expected<std::vector<std::byte>, PackagingError> encode_worker_response_frame(const WorkerResponse &response,
                                                                                       const WorkerLimits &limits) {
        const auto json = response_json(response, limits);
        if (!json) {
            return std::unexpected(json.error());
        }
        return encode_worker_frame(*json, limits.maximum_frame_bytes);
    }

    std::expected<WorkerResponse, PackagingError> decode_worker_response_frame(const std::span<const std::byte> frame,
                                                                               const WorkerLimits &limits) {
        const auto decoded = decode_worker_frame(frame, limits.maximum_frame_bytes);
        if (!decoded) {
            return std::unexpected(decoded.error());
        }
        ResponseCursor cursor {.input = *decoded};
        if (!cursor.consume("{\"mode\":\"")) {
            return std::unexpected(
                worker_error(PackagingErrorCode::worker_frame_malformed, "worker response is not canonical JSON"));
        }
        auto mode_text = cursor.quoted("mode");
        if (!mode_text || !cursor.consume("\",\"payload\":\"")) {
            return std::unexpected(mode_text ? worker_error(PackagingErrorCode::worker_frame_malformed,
                                                            "worker response payload field is missing") :
                                               mode_text.error());
        }
        auto payload_text = cursor.quoted("payload");
        if (!payload_text || !cursor.consume("\",\"payload_schema\":\"")) {
            return std::unexpected(payload_text ? worker_error(PackagingErrorCode::worker_frame_malformed,
                                                               "worker response payload schema is missing") :
                                                  payload_text.error());
        }
        auto schema = cursor.quoted("payload_schema");
        if (!schema || !cursor.consume("\",\"protocol\":")) {
            return std::unexpected(schema ? worker_error(PackagingErrorCode::worker_frame_malformed,
                                                         "worker response protocol is missing") :
                                            schema.error());
        }
        std::uint32_t protocol {};
        const auto protocol_begin = decoded->data() + cursor.offset;
        const auto [protocol_end, protocol_error] =
            std::from_chars(protocol_begin, decoded->data() + decoded->size(), protocol);
        if (protocol_error != std::errc {} || protocol_end == protocol_begin) {
            return std::unexpected(
                worker_error(PackagingErrorCode::worker_frame_malformed, "worker response protocol is invalid"));
        }
        cursor.offset = static_cast<std::size_t>(protocol_end - decoded->data());
        if (!cursor.consume(",\"request_id\":\"")) {
            return std::unexpected(
                worker_error(PackagingErrorCode::worker_frame_malformed, "worker response request ID is missing"));
        }
        auto request_id = cursor.quoted("request_id");
        if (!request_id || !cursor.consume("\",\"runtime_sha256\":\"")) {
            return std::unexpected(request_id ? worker_error(PackagingErrorCode::worker_frame_malformed,
                                                             "worker response runtime digest is missing") :
                                                request_id.error());
        }
        auto runtime_sha256 = cursor.quoted("runtime_sha256");
        if (!runtime_sha256 || !cursor.consume("\",\"runtime_version\":\"")) {
            return std::unexpected(runtime_sha256 ? worker_error(PackagingErrorCode::worker_frame_malformed,
                                                                 "worker response runtime version is missing") :
                                                    runtime_sha256.error());
        }
        auto runtime_version = cursor.quoted("runtime_version");
        if (!runtime_version || !cursor.consume("\",\"source_digest\":\"")) {
            return std::unexpected(runtime_version ? worker_error(PackagingErrorCode::worker_frame_malformed,
                                                                  "worker response source digest is missing") :
                                                     runtime_version.error());
        }
        auto source_digest = cursor.quoted("source_digest");
        if (!source_digest || !cursor.consume("\",\"source_id\":\"")) {
            return std::unexpected(source_digest ? worker_error(PackagingErrorCode::worker_frame_malformed,
                                                                "worker response source ID is missing") :
                                                   source_digest.error());
        }
        auto source_id = cursor.quoted("source_id");
        if (!source_id || !cursor.consume("\",\"status\":\"")) {
            return std::unexpected(source_id ? worker_error(PackagingErrorCode::worker_frame_malformed,
                                                            "worker response status is missing") :
                                               source_id.error());
        }
        auto status_text = cursor.quoted("status");
        if (!status_text || !cursor.consume("\"}") || cursor.offset != decoded->size()) {
            return std::unexpected(status_text ? worker_error(PackagingErrorCode::worker_frame_malformed,
                                                              "worker response has trailing or malformed bytes") :
                                                 status_text.error());
        }
        auto mode = parse_mode(*mode_text);
        auto status = parse_status(*status_text);
        auto payload = base64_decode(*payload_text);
        if (!mode || !status || !payload) {
            return std::unexpected(!mode ? mode.error() : !status ? status.error() : payload.error());
        }
        if (payload->size() > limits.maximum_payload_bytes) {
            return std::unexpected(worker_error(PackagingErrorCode::worker_output_limit,
                                                "worker response payload exceeds its configured bound"));
        }
        WorkerResponse response {
            .protocol = protocol,
            .request_id = RequestId {*request_id},
            .mode = *mode,
            .runtime_version = *runtime_version,
            .runtime_artifact_sha256 = *runtime_sha256,
            .status = *status,
            .payload =
                OpaqueWorkerPayload {
                    .schema = *schema,
                    .source = SourceId {*source_id},
                    .source_digest = SourceDigest {*source_digest},
                    .bytes = std::move(*payload),
                },
        };
        const auto canonical = response_json(response, limits);
        if (!canonical || *canonical != *decoded) {
            return std::unexpected(canonical ? worker_error(PackagingErrorCode::worker_frame_malformed,
                                                            "worker response JSON is not canonical") :
                                               canonical.error());
        }
        return response;
    }

    std::expected<WorkerResponse, PackagingError> WorkerClient::invoke(const WorkerRequest &request) {
        const auto runtime_valid = validate_exact_private_runtime(runtime);
        if (!runtime_valid) {
            return std::unexpected(runtime_valid.error());
        }
        if (request.runtime != runtime.descriptor) {
            return std::unexpected(worker_error(PackagingErrorCode::runtime_mismatch,
                                                "request does not name the exact installed private runtime"));
        }
        const auto request_frame = encode_worker_request_frame(request, limits);
        if (!request_frame) {
            return std::unexpected(request_frame.error());
        }
        auto process = launcher.launch(runtime, request.mode, *request_frame, limits);
        if (!process) {
            return std::unexpected(process.error());
        }
        if (process->timed_out) {
            return std::unexpected(
                worker_error(PackagingErrorCode::worker_timed_out, "worker exceeded its elapsed deadline"));
        }
        if (process->output_limited || process->stderr_excerpt.size() > limits.maximum_stderr_bytes) {
            return std::unexpected(
                worker_error(PackagingErrorCode::worker_output_limit, "worker exceeded an output bound"));
        }
        if (process->crashed || process->exit_code != 0 || !process->process_tree_terminated) {
            return std::unexpected(worker_error(PackagingErrorCode::worker_crashed,
                                                "worker failed or its process tree was not contained"));
        }
        auto response = decode_worker_response_frame(process->stdout_bytes, limits);
        if (!response) {
            return std::unexpected(response.error());
        }
        const auto expected_schema =
            request.mode == WorkerMode::static_parse ? static_ast_schema_v1 : generated_bindings_schema_v1;
        if (response->protocol != python_worker_protocol_v1 || response->request_id != request.request_id ||
            response->mode != request.mode ||
            response->runtime_version != official_windows_cpython_3146().python_version ||
            response->runtime_artifact_sha256 != official_windows_cpython_3146().artifact_sha256 ||
            response->payload.schema != expected_schema || response->payload.source != request.payload.source ||
            response->payload.source_digest != request.payload.source_digest) {
            return std::unexpected(worker_error(PackagingErrorCode::worker_response_mismatch,
                                                "worker response does not match its request/runtime/schema"));
        }
        if (response->status != WorkerResponseStatus::ok) {
            return std::unexpected(worker_error(PackagingErrorCode::worker_rejected, "worker rejected the request"));
        }
        return response;
    }

} // namespace rule_engine::python::packaging
