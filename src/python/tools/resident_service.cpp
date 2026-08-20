#include "rule_engine/python/tools/resident_service.hpp"

#include "rule_engine/python/runtime/adapters.hpp"

#include <algorithm>
#include <array>
#include <condition_variable>
#include <deque>
#include <limits>
#include <map>
#include <mutex>
#include <ranges>
#include <string_view>
#include <thread>
#include <utility>

namespace rule_engine::python::tools {
    namespace {

        constexpr std::size_t maximum_admin_string_bytes = 1U * kibibyte;
        constexpr std::size_t maximum_admin_work_ids = 4'096U;
        constexpr std::uint64_t maximum_admin_upload_bytes = balanced_v1.compile.source_closure_bytes;
        constexpr std::size_t queued_session_reservation_bytes = 16U * kibibyte;
        constexpr std::size_t worker_fixed_reservation_bytes = 64U * kibibyte;

        [[nodiscard]] constexpr std::uint64_t saturating_add(const std::uint64_t left,
                                                             const std::uint64_t right) noexcept {
            constexpr auto maximum = (std::numeric_limits<std::uint64_t>::max)();
            return left > maximum - right ? maximum : left + right;
        }

        [[nodiscard]] bool printable_ascii(const std::string_view value, const bool allow_empty = true) noexcept {
            return (allow_empty || !value.empty()) && std::ranges::all_of(value, [](const unsigned char character) {
                       return character >= 0x20U && character <= 0x7eU;
                   });
        }

        [[nodiscard]] bool canonical_source_digest(const SourceDigest &digest) noexcept {
            constexpr std::string_view prefix {"sha256:"};
            if (!digest.value.starts_with(prefix) || digest.value.size() != prefix.size() + 64U) {
                return false;
            }
            return std::ranges::all_of(std::string_view {digest.value}.substr(prefix.size()), [](const char value) {
                return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f');
            });
        }

        [[nodiscard]] protocol_v2::ProtocolError error(const protocol_v2::ProtocolErrorCode code, std::string message) {
            return {.code = code, .message = std::move(message), .byte_offset = 0U};
        }

        [[nodiscard]] std::chrono::steady_clock::time_point
        bounded_deadline(const std::chrono::steady_clock::time_point session_deadline,
                         const std::chrono::milliseconds operation_timeout = std::chrono::seconds {5}) noexcept {
            return (std::min) (session_deadline, std::chrono::steady_clock::now() + operation_timeout);
        }

        struct Writer {
            std::vector<std::byte> bytes;
            std::size_t maximum {};

            [[nodiscard]] bool append_u8(const std::uint8_t value) {
                if (bytes.size() >= maximum) {
                    return false;
                }
                bytes.push_back(static_cast<std::byte>(value));
                return true;
            }

            [[nodiscard]] bool append_u32(const std::uint32_t value) {
                if (maximum - bytes.size() < 4U) {
                    return false;
                }
                bytes.push_back(static_cast<std::byte>((value >> 24U) & 0xffU));
                bytes.push_back(static_cast<std::byte>((value >> 16U) & 0xffU));
                bytes.push_back(static_cast<std::byte>((value >> 8U) & 0xffU));
                bytes.push_back(static_cast<std::byte>(value & 0xffU));
                return true;
            }

            [[nodiscard]] bool append_u64(const std::uint64_t value) {
                if (maximum - bytes.size() < 8U) {
                    return false;
                }
                for (auto shift = 56U;; shift -= 8U) {
                    bytes.push_back(static_cast<std::byte>((value >> shift) & 0xffU));
                    if (shift == 0U) {
                        break;
                    }
                }
                return true;
            }

            [[nodiscard]] bool append_string(const std::string_view value) {
                if (value.size() > maximum_admin_string_bytes ||
                    value.size() > static_cast<std::size_t>((std::numeric_limits<std::uint32_t>::max)()) ||
                    maximum - bytes.size() < 4U + value.size()) {
                    return false;
                }
                if (!append_u32(static_cast<std::uint32_t>(value.size()))) {
                    return false;
                }
                for (const auto character : value) {
                    bytes.push_back(static_cast<std::byte>(static_cast<unsigned char>(character)));
                }
                return true;
            }

            [[nodiscard]] bool append_blob(const std::span<const std::byte> value) {
                if (value.size() > static_cast<std::size_t>((std::numeric_limits<std::uint32_t>::max)()) ||
                    maximum - bytes.size() < 4U + value.size() ||
                    !append_u32(static_cast<std::uint32_t>(value.size()))) {
                    return false;
                }
                bytes.insert(bytes.end(), value.begin(), value.end());
                return true;
            }
        };

        struct Reader {
            std::span<const std::byte> bytes;
            std::size_t offset {};

            [[nodiscard]] std::optional<std::uint8_t> read_u8() {
                if (offset >= bytes.size()) {
                    return std::nullopt;
                }
                return std::to_integer<std::uint8_t>(bytes[offset++]);
            }

            [[nodiscard]] std::optional<std::uint32_t> read_u32() {
                if (bytes.size() - offset < 4U) {
                    return std::nullopt;
                }
                const auto value = (std::to_integer<std::uint32_t>(bytes[offset]) << 24U) |
                                   (std::to_integer<std::uint32_t>(bytes[offset + 1U]) << 16U) |
                                   (std::to_integer<std::uint32_t>(bytes[offset + 2U]) << 8U) |
                                   std::to_integer<std::uint32_t>(bytes[offset + 3U]);
                offset += 4U;
                return value;
            }

            [[nodiscard]] std::optional<std::uint64_t> read_u64() {
                if (bytes.size() - offset < 8U) {
                    return std::nullopt;
                }
                std::uint64_t value {};
                for (std::size_t index = 0U; index < 8U; ++index) {
                    value = (value << 8U) | std::to_integer<std::uint64_t>(bytes[offset + index]);
                }
                offset += 8U;
                return value;
            }

            [[nodiscard]] std::optional<std::string> read_string() {
                const auto size = read_u32();
                if (!size || *size > maximum_admin_string_bytes || bytes.size() - offset < *size) {
                    return std::nullopt;
                }
                std::string value;
                value.reserve(*size);
                for (std::size_t index = 0U; index < *size; ++index) {
                    const auto byte = std::to_integer<unsigned char>(bytes[offset + index]);
                    if (byte < 0x20U || byte > 0x7eU) {
                        return std::nullopt;
                    }
                    value.push_back(static_cast<char>(byte));
                }
                offset += *size;
                return value;
            }

            [[nodiscard]] std::optional<std::vector<std::byte>> read_blob() {
                const auto size = read_u32();
                if (!size || bytes.size() - offset < *size) {
                    return std::nullopt;
                }
                std::vector<std::byte> value(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                                             bytes.begin() + static_cast<std::ptrdiff_t>(offset + *size));
                offset += *size;
                return value;
            }
        };

        [[nodiscard]] bool common_admin_request_valid(const ResidentAdminRequest &request) noexcept {
            return !request.request_id.empty() && !request.tenant.empty() && !request.pack.empty() &&
                   request.at_unix_ms != 0U && request.request_id.size() <= maximum_admin_string_bytes &&
                   request.tenant.value.size() <= maximum_admin_string_bytes &&
                   request.pack.value.size() <= maximum_admin_string_bytes &&
                   printable_ascii(request.request_id, false) && printable_ascii(request.tenant.value, false) &&
                   printable_ascii(request.pack.value, false);
        }

        [[nodiscard]] bool admin_request_shape_valid(const ResidentAdminRequest &request) noexcept {
            const auto mutation_identity = [&] {
                return !request.operation_id.empty() && !request.idempotency_key.empty() &&
                       printable_ascii(request.operation_id, false) && printable_ascii(request.idempotency_key, false);
            };
            const auto work_ids_valid =
                request.work_ids.size() <= maximum_admin_work_ids &&
                std::ranges::all_of(request.work_ids, [](const std::string &work_id) {
                    return work_id.size() <= maximum_admin_string_bytes && printable_ascii(work_id, false);
                });
            const auto no_upload =
                request.upload_offset == 0U && request.upload_total_bytes == 0U && request.payload.empty();
            const auto no_stage =
                request.source_digest.empty() && request.state_schema_hash.empty() && request.state_namespace.empty();
            const auto no_rollback = request.rollback_source_generation == 0U;
            switch (request.kind) {
                case ResidentAdminRequestKind::pack_snapshot:
                    return request.operation_id.empty() && request.idempotency_key.empty() &&
                           request.expected_pack_version == 0U && request.reason.empty() &&
                           request.target_generation == 0U && request.drain_boundary == 0U &&
                           request.work_ids.empty() && no_upload && no_stage && no_rollback;
                case ResidentAdminRequestKind::operation_snapshot:
                    return !request.operation_id.empty() && request.idempotency_key.empty() &&
                           request.expected_pack_version == 0U && printable_ascii(request.operation_id, false) &&
                           request.reason.empty() && request.target_generation == 0U && request.drain_boundary == 0U &&
                           request.work_ids.empty() && no_upload && no_stage && no_rollback;
                case ResidentAdminRequestKind::activation_flip:
                    return mutation_identity() && request.reason.empty() && request.target_generation == 0U &&
                           request.drain_boundary == 0U && request.work_ids.empty() && no_upload && no_stage &&
                           no_rollback;
                case ResidentAdminRequestKind::activation_preview:
                    return mutation_identity() && printable_ascii(request.reason, false) &&
                           request.target_generation != 0U && request.drain_boundary == 0U &&
                           request.work_ids.empty() && no_upload && no_stage && no_rollback;
                case ResidentAdminRequestKind::activation_drain:
                    return mutation_identity() && request.reason.empty() && request.target_generation == 0U &&
                           request.drain_boundary != 0U && request.work_ids.empty() && no_upload && no_stage &&
                           no_rollback;
                case ResidentAdminRequestKind::activation_fence:
                    return mutation_identity() && request.reason.empty() && request.target_generation == 0U &&
                           request.drain_boundary == 0U && work_ids_valid && no_upload && no_stage && no_rollback;
                case ResidentAdminRequestKind::upload_begin:
                    return !request.operation_id.empty() && request.idempotency_key.empty() &&
                           printable_ascii(request.operation_id, false) && printable_ascii(request.reason, false) &&
                           request.expected_pack_version == 0U && request.target_generation == 0U &&
                           request.drain_boundary == 0U && request.work_ids.empty() && request.upload_offset == 0U &&
                           request.upload_total_bytes != 0U &&
                           request.upload_total_bytes <= maximum_admin_upload_bytes && request.payload.empty() &&
                           no_stage && no_rollback;
                case ResidentAdminRequestKind::upload_chunk:
                    return !request.operation_id.empty() && request.idempotency_key.empty() &&
                           printable_ascii(request.operation_id, false) && request.reason.empty() &&
                           request.expected_pack_version == 0U && request.target_generation == 0U &&
                           request.drain_boundary == 0U && request.work_ids.empty() &&
                           request.upload_total_bytes != 0U &&
                           request.upload_total_bytes <= maximum_admin_upload_bytes &&
                           request.upload_offset <= request.upload_total_bytes &&
                           request.payload.size() <= request.upload_total_bytes - request.upload_offset &&
                           !request.payload.empty() && no_stage && no_rollback;
                case ResidentAdminRequestKind::upload_finalize:
                    return !request.operation_id.empty() && request.idempotency_key.empty() &&
                           printable_ascii(request.operation_id, false) && request.reason.empty() &&
                           request.expected_pack_version == 0U && request.target_generation == 0U &&
                           request.drain_boundary == 0U && request.work_ids.empty() &&
                           request.upload_total_bytes != 0U &&
                           request.upload_total_bytes <= maximum_admin_upload_bytes &&
                           request.upload_offset == request.upload_total_bytes && request.payload.empty() && no_stage &&
                           no_rollback;
                case ResidentAdminRequestKind::stage_preview:
                    return mutation_identity() && printable_ascii(request.reason, false) &&
                           request.target_generation != 0U && request.drain_boundary == 0U &&
                           request.work_ids.empty() && no_upload && canonical_source_digest(request.source_digest) &&
                           printable_ascii(request.state_schema_hash) &&
                           printable_ascii(request.state_namespace, false) && no_rollback;
                case ResidentAdminRequestKind::stage_apply:
                    return mutation_identity() && request.reason.empty() && request.target_generation != 0U &&
                           request.drain_boundary == 0U && request.work_ids.empty() && no_upload &&
                           canonical_source_digest(request.source_digest) &&
                           printable_ascii(request.state_schema_hash) &&
                           printable_ascii(request.state_namespace, false) && no_rollback;
                case ResidentAdminRequestKind::rollback_preview:
                    return mutation_identity() && printable_ascii(request.reason, false) &&
                           request.target_generation != 0U && request.rollback_source_generation != 0U &&
                           request.drain_boundary == 0U && request.work_ids.empty() && no_upload && no_stage;
                case ResidentAdminRequestKind::rollback_apply:
                    return mutation_identity() && request.reason.empty() && request.target_generation != 0U &&
                           request.rollback_source_generation != 0U && request.drain_boundary == 0U &&
                           request.work_ids.empty() && no_upload && no_stage;
                default: return false;
            }
        }

        [[nodiscard]] std::string_view operation_phase_name(const cluster::AdminOperationPhase phase) noexcept {
            using enum cluster::AdminOperationPhase;
            switch (phase) {
                case previewed: return "previewed";
                case staged: return "staged";
                case draining: return "draining";
                case fenced: return "fenced";
                case applied: return "applied";
                case failed: return "failed";
                default: return "unknown";
            }
        }

        [[nodiscard]] std::string_view admin_error_code(const cluster::AuthorizedAdminErrorCode code) noexcept {
            using enum cluster::AuthorizedAdminErrorCode;
            switch (code) {
                case unauthenticated: return "ADMIN-UNAUTHENTICATED";
                case unauthorized: return "ADMIN-UNAUTHORIZED";
                case authorizer_unavailable: return "ADMIN-AUTHORIZER-UNAVAILABLE";
                case invalid_resource: return "ADMIN-INVALID-RESOURCE";
                case resource_mismatch: return "ADMIN-RESOURCE-MISMATCH";
                case store_failure: return "ADMIN-STORE-FAILURE";
                default: return "ADMIN-REJECTED";
            }
        }

        [[nodiscard]] ResidentAdminResponse rejected_response(const ResidentAdminRequest &request,
                                                              const cluster::AuthorizedAdminError &failure) {
            return {
                .status = failure.code == cluster::AuthorizedAdminErrorCode::store_failure || failure.retryable ?
                              ResidentAdminResponseStatus::unavailable :
                              ResidentAdminResponseStatus::rejected,
                .request_id = request.request_id,
                .code = std::string {admin_error_code(failure.code)},
                .diagnostic =
                    failure.retryable ? "authorized admin backend unavailable" : "authorized admin request rejected",
                .storage_revision = 0U,
                .resource_version = 0U,
                .active_generation = std::nullopt,
                .previous_active_generation = std::nullopt,
                .operation_phase = {},
                .target_generation = 0U,
                .drain_boundary = 0U,
                .assignment_fence = 0U,
                .work_ids = {},
                .upload_received_bytes = 0U,
                .upload_total_bytes = 0U,
                .source_digest = std::nullopt,
            };
        }

        struct IgnoreCancel final: runtime::IProtocolV2CancelSink {
            void cancel(const protocol_v2::WorkLeaseMessage &, std::span<const RequestId>) noexcept override {}
        };

        struct AgentSessionCloser {
            IResidentAgentBackend &backend;
            ResidentAgentSession &session;

            ~AgentSessionCloser() { backend.close(session); }
        };

        [[nodiscard]] std::expected<void, protocol_v2::ProtocolError>
        validate_result(const std::map<std::string, protocol_v2::WorkLeaseMessage, std::less<>> &outstanding,
                        const protocol_v2::WorkResultMessage &result) {
            const auto found = outstanding.find(result.work_id);
            if (found == outstanding.end()) {
                return std::unexpected(error(protocol_v2::ProtocolErrorCode::stale_fence,
                                             "work result does not target an outstanding lease"));
            }
            IgnoreCancel cancel;
            auto port = runtime::ProtocolV2ProviderResponsePort::create(found->second, cancel);
            if (!port) {
                return std::unexpected(std::move(port.error()));
            }
            return port->admit(result);
        }

        [[nodiscard]] protocol_v2::PeerEnvelope server_envelope(const ResidentAgentSession &session,
                                                                std::string message_id, protocol_v2::MessageBody body) {
            return {
                .protocol_major = protocol_v2::major_version,
                .protocol_minor = protocol_v2::initial_minor_version,
                .message_id = std::move(message_id),
                .session = session.session,
                .agent_epoch = session.agent_epoch,
                .agent_sequence = 0U,
                .acknowledged_agent_sequence = session.acknowledged_through,
                .body = std::move(body),
            };
        }

        struct TlsResidentChannel final: IResidentSecureChannel {
            explicit TlsResidentChannel(protocol_v2::TlsPeerConnection connection):
                connection_ {std::move(connection)} {}

            [[nodiscard]] std::expected<protocol_v2::PeerEnvelope, protocol_v2::ProtocolError>
            receive_protocol(const std::chrono::steady_clock::time_point deadline,
                             const std::stop_token cancellation) noexcept override {
                return connection_.receive_until(deadline, cancellation);
            }

            [[nodiscard]] std::expected<bool, protocol_v2::ProtocolError>
            wait_protocol_input(const std::chrono::steady_clock::time_point deadline,
                                const std::stop_token cancellation) noexcept override {
                return connection_.wait_readable_until(deadline, cancellation);
            }

            [[nodiscard]] std::expected<void, protocol_v2::ProtocolError>
            send_protocol(const protocol_v2::PeerEnvelope &envelope,
                          const std::chrono::steady_clock::time_point deadline,
                          const std::stop_token cancellation) noexcept override {
                return connection_.send_until(envelope, deadline, cancellation);
            }

            [[nodiscard]] std::expected<std::vector<std::byte>, protocol_v2::ProtocolError>
            receive_application_frame(const std::chrono::steady_clock::time_point deadline,
                                      const std::stop_token cancellation) noexcept override {
                return connection_.receive_application_frame_until(deadline, cancellation);
            }

            [[nodiscard]] std::expected<void, protocol_v2::ProtocolError>
            send_application_frame(const std::span<const std::byte> payload,
                                   const std::chrono::steady_clock::time_point deadline,
                                   const std::stop_token cancellation) noexcept override {
                return connection_.send_application_frame_until(payload, deadline, cancellation);
            }

            void shutdown() noexcept override { connection_.shutdown(); }

        private:
            protocol_v2::TlsPeerConnection connection_;
        };

    } // namespace

    std::expected<void, protocol_v2::ProtocolError>
    validate_resident_service_limits(const ResidentServiceLimits &limits) noexcept {
        if (limits.worker_threads == 0U || limits.worker_threads > 256U || limits.maximum_queued_sessions == 0U ||
            limits.maximum_queued_sessions > 65'536U || limits.maximum_frame_bytes < 1U * kibibyte ||
            limits.maximum_frame_bytes > protocol_v2_pre_negotiation_frame_limit ||
            limits.maximum_messages_per_session == 0U || limits.maximum_messages_per_session > 1'000'000U ||
            limits.maximum_inflight_work_per_session == 0U || limits.maximum_inflight_work_per_session > 4'096U ||
            limits.maximum_session_duration < std::chrono::milliseconds {100} ||
            limits.maximum_session_duration > std::chrono::hours {24} ||
            limits.work_poll_interval < std::chrono::milliseconds {10} ||
            limits.work_poll_interval > limits.maximum_session_duration || limits.inbound_credit.bytes == 0U ||
            limits.inbound_credit.bytes > limits.maximum_memory_bytes || limits.inbound_credit.messages == 0U ||
            limits.inbound_credit.work_attempts == 0U) {
            return std::unexpected(
                error(protocol_v2::ProtocolErrorCode::limit_exceeded, "resident service limits are invalid"));
        }
        constexpr auto maximum = (std::numeric_limits<std::size_t>::max)();
        if (limits.maximum_frame_bytes > (maximum - worker_fixed_reservation_bytes) / 4U) {
            return std::unexpected(
                error(protocol_v2::ProtocolErrorCode::limit_exceeded, "resident worker memory bound overflows"));
        }
        // One decoded body, its canonical fingerprint, the contiguous copy,
        // and one outbound frame can coexist in a worker.
        const auto per_worker = worker_fixed_reservation_bytes + 4U * limits.maximum_frame_bytes;
        if (limits.worker_threads > maximum / per_worker ||
            limits.maximum_queued_sessions > maximum / queued_session_reservation_bytes) {
            return std::unexpected(
                error(protocol_v2::ProtocolErrorCode::limit_exceeded, "resident scheduler memory bound overflows"));
        }
        const auto workers = limits.worker_threads * per_worker;
        const auto queue = limits.maximum_queued_sessions * queued_session_reservation_bytes;
        if (workers > limits.maximum_memory_bytes || queue > limits.maximum_memory_bytes - workers) {
            return std::unexpected(error(protocol_v2::ProtocolErrorCode::limit_exceeded,
                                         "resident worker and queue reservations exceed the memory bound"));
        }
        return {};
    }

    std::unique_ptr<IResidentSecureChannel> make_resident_tls_channel(protocol_v2::TlsPeerConnection connection) {
        return std::make_unique<TlsResidentChannel>(std::move(connection));
    }

    std::expected<std::vector<std::byte>, protocol_v2::ProtocolError>
    encode_resident_admin_request(const ResidentAdminRequest &request, const std::size_t maximum_frame_bytes) {
        if (maximum_frame_bytes == 0U || !common_admin_request_valid(request) || !admin_request_shape_valid(request) ||
            request.operation_id.size() > maximum_admin_string_bytes ||
            request.idempotency_key.size() > maximum_admin_string_bytes ||
            request.reason.size() > maximum_admin_string_bytes ||
            request.source_digest.value.size() > maximum_admin_string_bytes ||
            request.state_schema_hash.size() > maximum_admin_string_bytes ||
            request.state_namespace.size() > maximum_admin_string_bytes) {
            return std::unexpected(error(protocol_v2::ProtocolErrorCode::malformed, "admin request is invalid"));
        }
        Writer writer {.bytes = {}, .maximum = maximum_frame_bytes};
        if (!writer.append_u8(6U) || !writer.append_u8(static_cast<std::uint8_t>(request.kind)) ||
            !writer.append_string(request.request_id) || !writer.append_string(request.tenant.value) ||
            !writer.append_string(request.pack.value) || !writer.append_string(request.operation_id) ||
            !writer.append_string(request.idempotency_key) || !writer.append_u64(request.expected_pack_version) ||
            !writer.append_u64(request.at_unix_ms) || !writer.append_string(request.reason) ||
            !writer.append_u64(request.target_generation) || !writer.append_u64(request.rollback_source_generation) ||
            !writer.append_u64(request.drain_boundary) ||
            request.work_ids.size() > (std::numeric_limits<std::uint32_t>::max)() ||
            !writer.append_u32(static_cast<std::uint32_t>(request.work_ids.size())) ||
            !std::ranges::all_of(request.work_ids,
                                 [&](const std::string &work_id) { return writer.append_string(work_id); }) ||
            !writer.append_u64(request.upload_offset) || !writer.append_u64(request.upload_total_bytes) ||
            !writer.append_blob(request.payload) || !writer.append_string(request.source_digest.value) ||
            !writer.append_string(request.state_schema_hash) || !writer.append_string(request.state_namespace)) {
            return std::unexpected(
                error(protocol_v2::ProtocolErrorCode::limit_exceeded, "admin request exceeds its frame bound"));
        }
        return std::move(writer.bytes);
    }

    std::expected<ResidentAdminRequest, protocol_v2::ProtocolError>
    decode_resident_admin_request(const std::span<const std::byte> payload, const std::size_t maximum_frame_bytes) {
        if (payload.empty() || payload.size() > maximum_frame_bytes) {
            return std::unexpected(error(payload.empty() ? protocol_v2::ProtocolErrorCode::malformed :
                                                           protocol_v2::ProtocolErrorCode::limit_exceeded,
                                         "admin request frame length is invalid"));
        }
        Reader reader {.bytes = payload};
        const auto version = reader.read_u8();
        const auto kind = reader.read_u8();
        const auto request_id = reader.read_string();
        const auto tenant = reader.read_string();
        const auto pack = reader.read_string();
        const auto operation = reader.read_string();
        const auto idempotency = reader.read_string();
        const auto expected = reader.read_u64();
        const auto at = reader.read_u64();
        const auto reason = reader.read_string();
        const auto target_generation = reader.read_u64();
        const auto rollback_source_generation = reader.read_u64();
        const auto drain_boundary = reader.read_u64();
        const auto work_count = reader.read_u32();
        std::vector<std::string> work_ids;
        if (work_count && *work_count <= maximum_admin_work_ids) {
            work_ids.reserve(*work_count);
            for (std::uint32_t index = 0U; index < *work_count; ++index) {
                auto work_id = reader.read_string();
                if (!work_id) {
                    break;
                }
                work_ids.push_back(std::move(*work_id));
            }
        }
        const auto upload_offset = reader.read_u64();
        const auto upload_total = reader.read_u64();
        auto upload_payload = reader.read_blob();
        auto source_digest = reader.read_string();
        auto state_schema_hash = reader.read_string();
        auto state_namespace = reader.read_string();
        if (!version || *version != 6U || !kind || *kind < 1U || *kind > 13U || !request_id || !tenant || !pack ||
            !operation || !idempotency || !expected || !at || !reason || !target_generation || !drain_boundary ||
            !rollback_source_generation || !work_count || work_ids.size() != *work_count || !upload_offset ||
            !upload_total || !upload_payload || !source_digest || !state_schema_hash || !state_namespace ||
            reader.offset != payload.size()) {
            return std::unexpected(
                error(protocol_v2::ProtocolErrorCode::malformed, "admin request frame is malformed"));
        }
        ResidentAdminRequest request {
            .kind = static_cast<ResidentAdminRequestKind>(*kind),
            .request_id = std::move(*request_id),
            .tenant = TenantId {std::move(*tenant)},
            .pack = PackId {std::move(*pack)},
            .operation_id = std::move(*operation),
            .idempotency_key = std::move(*idempotency),
            .expected_pack_version = *expected,
            .at_unix_ms = *at,
            .reason = std::move(*reason),
            .target_generation = *target_generation,
            .rollback_source_generation = *rollback_source_generation,
            .drain_boundary = *drain_boundary,
            .work_ids = std::move(work_ids),
            .upload_offset = *upload_offset,
            .upload_total_bytes = *upload_total,
            .payload = std::move(*upload_payload),
            .source_digest = SourceDigest {std::move(*source_digest)},
            .state_schema_hash = std::move(*state_schema_hash),
            .state_namespace = std::move(*state_namespace),
        };
        auto canonical = encode_resident_admin_request(request, maximum_frame_bytes);
        if (!canonical || *canonical != std::vector<std::byte> {payload.begin(), payload.end()}) {
            return std::unexpected(error(protocol_v2::ProtocolErrorCode::malformed, "admin request is not canonical"));
        }
        return request;
    }

    std::expected<std::vector<std::byte>, protocol_v2::ProtocolError>
    encode_resident_admin_response(const ResidentAdminResponse &response, const std::size_t maximum_frame_bytes) {
        if (maximum_frame_bytes == 0U || response.request_id.empty() ||
            response.request_id.size() > maximum_admin_string_bytes ||
            response.code.size() > maximum_admin_string_bytes ||
            response.diagnostic.size() > maximum_admin_string_bytes ||
            response.operation_phase.size() > maximum_admin_string_bytes ||
            (response.source_digest && !canonical_source_digest(*response.source_digest)) ||
            response.work_ids.size() > maximum_admin_work_ids || !printable_ascii(response.request_id, false) ||
            !printable_ascii(response.code) || !printable_ascii(response.diagnostic) ||
            !printable_ascii(response.operation_phase) ||
            (response.source_digest && !printable_ascii(response.source_digest->value, false)) ||
            !std::ranges::all_of(response.work_ids,
                                 [](const std::string &work_id) {
                                     return work_id.size() <= maximum_admin_string_bytes &&
                                            printable_ascii(work_id, false);
                                 }) ||
            static_cast<std::uint8_t>(response.status) >
                static_cast<std::uint8_t>(ResidentAdminResponseStatus::unavailable)) {
            return std::unexpected(error(protocol_v2::ProtocolErrorCode::malformed, "admin response is invalid"));
        }
        Writer writer {.bytes = {}, .maximum = maximum_frame_bytes};
        const auto flags = static_cast<std::uint8_t>((response.active_generation ? 1U : 0U) |
                                                     (response.previous_active_generation ? 2U : 0U) |
                                                     (response.source_digest ? 4U : 0U));
        if (!writer.append_u8(4U) || !writer.append_u8(static_cast<std::uint8_t>(response.status)) ||
            !writer.append_u8(flags) || !writer.append_string(response.request_id) ||
            !writer.append_string(response.code) || !writer.append_string(response.diagnostic) ||
            !writer.append_u64(response.storage_revision) || !writer.append_u64(response.resource_version) ||
            !writer.append_u64(response.active_generation.value_or(0U)) ||
            !writer.append_u64(response.previous_active_generation.value_or(0U)) ||
            !writer.append_string(response.operation_phase) || !writer.append_u64(response.target_generation) ||
            !writer.append_u64(response.drain_boundary) || !writer.append_u64(response.assignment_fence) ||
            !writer.append_u32(static_cast<std::uint32_t>(response.work_ids.size())) ||
            !std::ranges::all_of(response.work_ids,
                                 [&](const std::string &work_id) { return writer.append_string(work_id); }) ||
            !writer.append_u64(response.upload_received_bytes) || !writer.append_u64(response.upload_total_bytes) ||
            !writer.append_string(response.source_digest ? std::string_view {response.source_digest->value} :
                                                           std::string_view {}) ||
            !writer.append_u64(response.registry_maintenance_runs) ||
            !writer.append_u64(response.registry_last_maintenance_unix_ms) ||
            !writer.append_u64(response.registry_expired_partial_sessions) ||
            !writer.append_u64(response.registry_removed_completion_records) ||
            !writer.append_u64(response.registry_removed_objects) ||
            !writer.append_u64(response.registry_reclaimed_bytes)) {
            return std::unexpected(
                error(protocol_v2::ProtocolErrorCode::limit_exceeded, "admin response exceeds its frame bound"));
        }
        return std::move(writer.bytes);
    }

    std::expected<ResidentAdminResponse, protocol_v2::ProtocolError>
    decode_resident_admin_response(const std::span<const std::byte> payload, const std::size_t maximum_frame_bytes) {
        if (payload.empty() || payload.size() > maximum_frame_bytes) {
            return std::unexpected(error(payload.empty() ? protocol_v2::ProtocolErrorCode::malformed :
                                                           protocol_v2::ProtocolErrorCode::limit_exceeded,
                                         "admin response frame length is invalid"));
        }
        Reader reader {.bytes = payload};
        const auto version = reader.read_u8();
        const auto status = reader.read_u8();
        const auto flags = reader.read_u8();
        const auto request_id = reader.read_string();
        const auto code = reader.read_string();
        const auto diagnostic = reader.read_string();
        const auto storage = reader.read_u64();
        const auto resource = reader.read_u64();
        const auto active = reader.read_u64();
        const auto previous = reader.read_u64();
        const auto operation_phase = reader.read_string();
        const auto target_generation = reader.read_u64();
        const auto drain_boundary = reader.read_u64();
        const auto assignment_fence = reader.read_u64();
        const auto work_count = reader.read_u32();
        std::vector<std::string> work_ids;
        if (work_count && *work_count <= maximum_admin_work_ids) {
            work_ids.reserve(*work_count);
            for (std::uint32_t index = 0U; index < *work_count; ++index) {
                auto work_id = reader.read_string();
                if (!work_id) {
                    break;
                }
                work_ids.push_back(std::move(*work_id));
            }
        }
        const auto upload_received = reader.read_u64();
        const auto upload_total = reader.read_u64();
        auto source_digest = reader.read_string();
        const auto maintenance_runs = reader.read_u64();
        const auto last_maintenance = reader.read_u64();
        const auto expired_partials = reader.read_u64();
        const auto removed_completions = reader.read_u64();
        const auto removed_objects = reader.read_u64();
        const auto reclaimed_bytes = reader.read_u64();
        if (!version || *version != 4U || !status || *status > 2U || !flags || (*flags & 0xf8U) != 0U || !request_id ||
            !code || !diagnostic || !storage || !resource || !active || !previous || !operation_phase ||
            !target_generation || !drain_boundary || !assignment_fence || !work_count ||
            work_ids.size() != *work_count || !upload_received || !upload_total || !source_digest ||
            !maintenance_runs || !last_maintenance || !expired_partials || !removed_completions || !removed_objects ||
            !reclaimed_bytes || (((*flags & 4U) != 0U) == source_digest->empty()) || reader.offset != payload.size()) {
            return std::unexpected(
                error(protocol_v2::ProtocolErrorCode::malformed, "admin response frame is malformed"));
        }
        ResidentAdminResponse response {
            .status = static_cast<ResidentAdminResponseStatus>(*status),
            .request_id = std::move(*request_id),
            .code = std::move(*code),
            .diagnostic = std::move(*diagnostic),
            .storage_revision = *storage,
            .resource_version = *resource,
            .active_generation = (*flags & 1U) != 0U ? std::optional<std::uint64_t> {*active} : std::nullopt,
            .previous_active_generation = (*flags & 2U) != 0U ? std::optional<std::uint64_t> {*previous} : std::nullopt,
            .operation_phase = std::move(*operation_phase),
            .target_generation = *target_generation,
            .drain_boundary = *drain_boundary,
            .assignment_fence = *assignment_fence,
            .work_ids = std::move(work_ids),
            .upload_received_bytes = *upload_received,
            .upload_total_bytes = *upload_total,
            .source_digest = (*flags & 4U) != 0U ?
                                 std::optional<SourceDigest> {SourceDigest {std::move(*source_digest)}} :
                                 std::nullopt,
            .registry_maintenance_runs = *maintenance_runs,
            .registry_last_maintenance_unix_ms = *last_maintenance,
            .registry_expired_partial_sessions = *expired_partials,
            .registry_removed_completion_records = *removed_completions,
            .registry_removed_objects = *removed_objects,
            .registry_reclaimed_bytes = *reclaimed_bytes,
        };
        auto canonical = encode_resident_admin_response(response, maximum_frame_bytes);
        if (!canonical || *canonical != std::vector<std::byte> {payload.begin(), payload.end()}) {
            return std::unexpected(error(protocol_v2::ProtocolErrorCode::malformed, "admin response is not canonical"));
        }
        return response;
    }

    AuthorizedResidentAdminBackend::AuthorizedResidentAdminBackend(cluster::IActivationControlStore &store,
                                                                   const IResidentAdminAccessPolicy &policy,
                                                                   cluster::IAdminSecurityAuditSink *security_audit,
                                                                   IResidentPackUploadBackend *uploads,
                                                                   IResidentStageSourceBackend *stages,
                                                                   IResidentAgentBackend *activation_target) noexcept:
        durable_ {store},
        policy_ {policy},
        security_audit_ {security_audit},
        uploads_ {uploads},
        stages_ {stages},
        activation_target_ {activation_target} {}

    ResidentAdminResponse AuthorizedResidentAdminBackend::execute(const protocol_v2::AuthenticatedPeer &peer,
                                                                  const ResidentAdminRequest &request) noexcept {
        auto principal = policy_.principal_for(peer);
        if (!principal) {
            return rejected_response(request, principal.error());
        }
        cluster::AuthorizedActivationAdmin admin {durable_, std::addressof(policy_), security_audit_};
        const cluster::AdminCallContext context {.principal = std::move(*principal), .at_unix_ms = request.at_unix_ms};
        const auto operation_version = [&](const std::string_view operation_id) -> std::optional<std::uint64_t> {
            const auto operation = durable_.operation_snapshot(operation_id);
            return operation && *operation ? std::optional<std::uint64_t> {(*operation)->expected_pack_version} :
                                             std::nullopt;
        };
        const auto unavailable_after_commit = [&] {
            return ResidentAdminResponse {.status = ResidentAdminResponseStatus::unavailable,
                                          .request_id = request.request_id,
                                          .code = "ADMIN-STORE-FAILURE",
                                          .diagnostic = "authorized admin backend unavailable",
                                          .storage_revision = 0U,
                                          .resource_version = 0U,
                                          .active_generation = std::nullopt,
                                          .previous_active_generation = std::nullopt,
                                          .operation_phase = {},
                                          .target_generation = 0U,
                                          .drain_boundary = 0U,
                                          .assignment_fence = 0U,
                                          .work_ids = {},
                                          .upload_received_bytes = 0U,
                                          .upload_total_bytes = 0U,
                                          .source_digest = std::nullopt};
        };
        if (request.kind == ResidentAdminRequestKind::upload_begin ||
            request.kind == ResidentAdminRequestKind::upload_chunk ||
            request.kind == ResidentAdminRequestKind::upload_finalize) {
            if (auto authorized = admin.authorize_pack_upload(context, request.tenant, request.pack); !authorized) {
                return rejected_response(request, authorized.error());
            }
            if (uploads_ == nullptr) {
                auto response = unavailable_after_commit();
                response.code = "ADMIN-UPLOAD-UNAVAILABLE";
                return response;
            }
            std::expected<ResidentPackUploadReceipt, protocol_v2::ProtocolError> uploaded =
                request.kind == ResidentAdminRequestKind::upload_begin ?
                    uploads_->begin(request.tenant, request.pack, request.operation_id, request.upload_total_bytes) :
                request.kind == ResidentAdminRequestKind::upload_chunk ?
                    uploads_->append(request.tenant, request.pack, request.operation_id, request.upload_offset,
                                     request.payload) :
                    uploads_->finalize(request.tenant, request.pack, request.operation_id);
            if (!uploaded) {
                const auto unavailable =
                    uploaded.error().code == protocol_v2::ProtocolErrorCode::dependency_unavailable ||
                    uploaded.error().code == protocol_v2::ProtocolErrorCode::transport_error ||
                    uploaded.error().code == protocol_v2::ProtocolErrorCode::timed_out;
                auto response = unavailable_after_commit();
                response.status =
                    unavailable ? ResidentAdminResponseStatus::unavailable : ResidentAdminResponseStatus::rejected;
                response.code = unavailable ? "ADMIN-UPLOAD-UNAVAILABLE" : "ADMIN-UPLOAD-REJECTED";
                response.diagnostic =
                    unavailable ? "authorized upload backend unavailable" : "authorized upload request rejected";
                return response;
            }
            auto response = unavailable_after_commit();
            response.status = ResidentAdminResponseStatus::ok;
            response.code = "OK";
            response.diagnostic.clear();
            response.upload_received_bytes = uploaded->received_bytes;
            response.upload_total_bytes = uploaded->total_bytes;
            response.source_digest = std::move(uploaded->source_digest);
            return response;
        }
        if (request.kind == ResidentAdminRequestKind::pack_snapshot) {
            auto snapshot = admin.pack_snapshot(context, request.tenant, request.pack);
            if (!snapshot) {
                return rejected_response(request, snapshot.error());
            }
            std::optional<ResidentPackRegistryObservation> registry;
            if (uploads_ != nullptr && admin.authorize_registry_observation(context)) {
                auto observed = uploads_->observe_maintenance();
                if (!observed) {
                    auto response = unavailable_after_commit();
                    response.code = "ADMIN-REGISTRY-OBSERVATION-UNAVAILABLE";
                    return response;
                }
                registry = std::move(*observed);
            }
            ResidentAdminResponse response {
                .status = ResidentAdminResponseStatus::ok,
                .request_id = request.request_id,
                .code = "OK",
                .diagnostic = {},
                .storage_revision = snapshot->storage_revision,
                .resource_version = 0U,
                .active_generation = std::nullopt,
                .previous_active_generation = std::nullopt,
                .operation_phase = {},
                .target_generation = 0U,
                .drain_boundary = 0U,
                .assignment_fence = 0U,
                .work_ids = {},
                .upload_received_bytes = 0U,
                .upload_total_bytes = 0U,
                .source_digest = std::nullopt,
                .registry_maintenance_runs = registry ? registry->successful_maintenance_runs : 0U,
                .registry_last_maintenance_unix_ms = registry ? registry->last_maintenance_unix_ms : 0U,
                .registry_expired_partial_sessions = registry ? registry->expired_partial_sessions : 0U,
                .registry_removed_completion_records = registry ? registry->removed_completion_records : 0U,
                .registry_removed_objects = registry ? registry->removed_objects : 0U,
                .registry_reclaimed_bytes = registry ? registry->reclaimed_bytes : 0U};
            if (snapshot->control) {
                response.resource_version = snapshot->control->resource_version;
                response.active_generation = snapshot->control->active_generation;
            }
            return response;
        }
        if (request.kind == ResidentAdminRequestKind::operation_snapshot) {
            auto operation = admin.operation_snapshot(context, request.tenant, request.pack, request.operation_id);
            if (!operation) {
                return rejected_response(request, operation.error());
            }
            return {.status = ResidentAdminResponseStatus::ok,
                    .request_id = request.request_id,
                    .code = *operation ? "OK" : "NOT-FOUND",
                    .diagnostic = *operation ? (*operation)->failure : std::string {},
                    .storage_revision = 0U,
                    .resource_version = 0U,
                    .active_generation =
                        *operation ? std::optional<std::uint64_t> {(*operation)->target_generation} : std::nullopt,
                    .previous_active_generation = *operation ? (*operation)->rollback_source_generation : std::nullopt,
                    .operation_phase =
                        *operation ? std::string {operation_phase_name((*operation)->phase)} : std::string {},
                    .target_generation = *operation ? (*operation)->target_generation : 0U,
                    .drain_boundary = *operation ? (*operation)->drain_boundary.value_or(0U) : 0U,
                    .assignment_fence = 0U,
                    .work_ids = *operation ? (*operation)->requeued_work : std::vector<std::string> {},
                    .upload_received_bytes = 0U,
                    .upload_total_bytes = 0U,
                    .source_digest = std::nullopt};
        }
        if (request.kind == ResidentAdminRequestKind::stage_preview ||
            request.kind == ResidentAdminRequestKind::stage_apply) {
            const auto apply_stage = request.kind == ResidentAdminRequestKind::stage_apply;
            if (auto authorized = admin.authorize_stage_source(context, request.tenant, request.pack,
                                                               request.operation_id, apply_stage);
                !authorized) {
                return rejected_response(request, authorized.error());
            }
            if (stages_ == nullptr) {
                auto response = unavailable_after_commit();
                response.code = "ADMIN-STAGE-UNAVAILABLE";
                return response;
            }
            auto generation = stages_->resolve(request.pack, request.source_digest, request.target_generation,
                                               request.state_schema_hash, request.state_namespace);
            if (!generation) {
                auto response = unavailable_after_commit();
                response.status = generation.error().code == protocol_v2::ProtocolErrorCode::dependency_unavailable ?
                                      ResidentAdminResponseStatus::unavailable :
                                      ResidentAdminResponseStatus::rejected;
                response.code = response.status == ResidentAdminResponseStatus::unavailable ?
                                    "ADMIN-STAGE-UNAVAILABLE" :
                                    "ADMIN-STAGE-REJECTED";
                return response;
            }
            if (!apply_stage) {
                const cluster::AdminMutationRequest mutation {
                    .operation_id = request.operation_id,
                    .request_id = RequestId {request.request_id},
                    .idempotency_key = request.idempotency_key,
                    .actor = context.principal->principal_id,
                    .reason = request.reason,
                    .expected_pack_version = request.expected_pack_version,
                    .at_unix_ms = request.at_unix_ms,
                };
                auto preview = durable_.preview_server_stage(mutation, *generation);
                if (!preview) {
                    return rejected_response(request, cluster::AuthorizedAdminError {
                                                          .code = cluster::AuthorizedAdminErrorCode::store_failure,
                                                          .message = preview.error().message,
                                                          .retryable = preview.error().retryable,
                                                          .store_code = preview.error().code});
                }
                return {.status = ResidentAdminResponseStatus::ok,
                        .request_id = request.request_id,
                        .code = "OK",
                        .diagnostic = {},
                        .storage_revision = 0U,
                        .resource_version = preview->expected_pack_version,
                        .active_generation = std::nullopt,
                        .previous_active_generation = std::nullopt,
                        .operation_phase = std::string {operation_phase_name(preview->phase)},
                        .target_generation = preview->target_generation,
                        .drain_boundary = 0U,
                        .assignment_fence = 0U,
                        .work_ids = {},
                        .upload_received_bytes = 0U,
                        .upload_total_bytes = 0U,
                        .source_digest = generation->source_digest};
            }
            const cluster::AdminApplyRequest apply {
                .operation_id = request.operation_id,
                .idempotency_key = request.idempotency_key,
                .expected_pack_version = request.expected_pack_version,
                .at_unix_ms = request.at_unix_ms,
            };
            auto compiling = durable_.begin_server_stage(apply, *generation);
            if (!compiling) {
                return rejected_response(
                    request, cluster::AuthorizedAdminError {.code = cluster::AuthorizedAdminErrorCode::store_failure,
                                                            .message = compiling.error().message,
                                                            .retryable = compiling.error().retryable,
                                                            .store_code = compiling.error().code});
            }
            const auto resource_version = operation_version(request.operation_id);
            if (!resource_version) {
                return unavailable_after_commit();
            }
            return {.status = ResidentAdminResponseStatus::ok,
                    .request_id = request.request_id,
                    .code = "OK",
                    .diagnostic = {},
                    .storage_revision = 0U,
                    .resource_version = *resource_version,
                    .active_generation = std::nullopt,
                    .previous_active_generation = std::nullopt,
                    .operation_phase = "previewed",
                    .target_generation = compiling->request.generation,
                    .drain_boundary = 0U,
                    .assignment_fence = 0U,
                    .work_ids = compiling->target_nodes,
                    .upload_received_bytes = 0U,
                    .upload_total_bytes = 0U,
                    .source_digest = compiling->request.source_digest};
        }
        if (request.kind == ResidentAdminRequestKind::rollback_preview ||
            request.kind == ResidentAdminRequestKind::rollback_apply) {
            const auto apply_rollback = request.kind == ResidentAdminRequestKind::rollback_apply;
            if (!apply_rollback) {
                const cluster::AdminMutationRequest mutation {
                    .operation_id = request.operation_id,
                    .request_id = RequestId {request.request_id},
                    .idempotency_key = request.idempotency_key,
                    .actor = {},
                    .reason = request.reason,
                    .expected_pack_version = request.expected_pack_version,
                    .at_unix_ms = request.at_unix_ms,
                };
                auto preview =
                    admin.preview_rollback(context, request.tenant, mutation, request.pack,
                                           request.rollback_source_generation, request.target_generation,
                                           cluster::StateTransitionPlan {.mode = cluster::StateTransitionMode::carry,
                                                                         .source_namespace = {},
                                                                         .target_namespace = {},
                                                                         .migration_id = {},
                                                                         .reset_authorized = false,
                                                                         .accept_state_gap = false});
                if (!preview) {
                    return rejected_response(request, preview.error());
                }
                return {.status = ResidentAdminResponseStatus::ok,
                        .request_id = request.request_id,
                        .code = "OK",
                        .diagnostic = {},
                        .storage_revision = 0U,
                        .resource_version = preview->expected_pack_version,
                        .active_generation = std::nullopt,
                        .previous_active_generation = preview->rollback_source_generation,
                        .operation_phase = std::string {operation_phase_name(preview->phase)},
                        .target_generation = preview->target_generation,
                        .drain_boundary = 0U,
                        .assignment_fence = 0U,
                        .work_ids = {},
                        .upload_received_bytes = 0U,
                        .upload_total_bytes = 0U,
                        .source_digest = std::nullopt};
            }
            const cluster::AdminApplyRequest apply {
                .operation_id = request.operation_id,
                .idempotency_key = request.idempotency_key,
                .expected_pack_version = request.expected_pack_version,
                .at_unix_ms = request.at_unix_ms,
            };
            auto compiling = admin.begin_server_rollback(context, request.tenant, request.pack, apply,
                                                         request.rollback_source_generation, request.target_generation);
            if (!compiling) {
                return rejected_response(request, compiling.error());
            }
            const auto resource_version = operation_version(request.operation_id);
            if (!resource_version) {
                return unavailable_after_commit();
            }
            return {.status = ResidentAdminResponseStatus::ok,
                    .request_id = request.request_id,
                    .code = "OK",
                    .diagnostic = {},
                    .storage_revision = 0U,
                    .resource_version = *resource_version,
                    .active_generation = std::nullopt,
                    .previous_active_generation = compiling->request.rollback_from,
                    .operation_phase = "previewed",
                    .target_generation = compiling->request.generation,
                    .drain_boundary = 0U,
                    .assignment_fence = 0U,
                    .work_ids = compiling->target_nodes,
                    .upload_received_bytes = 0U,
                    .upload_total_bytes = 0U,
                    .source_digest = compiling->request.source_digest};
        }
        if (request.kind == ResidentAdminRequestKind::activation_preview) {
            const cluster::AdminMutationRequest mutation {
                .operation_id = request.operation_id,
                .request_id = RequestId {request.request_id},
                .idempotency_key = request.idempotency_key,
                .actor = {},
                .reason = request.reason,
                .expected_pack_version = request.expected_pack_version,
                .at_unix_ms = request.at_unix_ms,
            };
            auto preview =
                admin.preview_activation(context, request.tenant, mutation, request.pack, request.target_generation);
            if (!preview) {
                return rejected_response(request, preview.error());
            }
            return {.status = ResidentAdminResponseStatus::ok,
                    .request_id = request.request_id,
                    .code = "OK",
                    .diagnostic = {},
                    .storage_revision = 0U,
                    .resource_version = preview->expected_pack_version,
                    .active_generation = std::nullopt,
                    .previous_active_generation = preview->previous_active_generation,
                    .operation_phase = std::string {operation_phase_name(preview->phase)},
                    .target_generation = preview->target_generation,
                    .drain_boundary = preview->drain_boundary.value_or(0U),
                    .assignment_fence = 0U,
                    .work_ids = preview->requeued_work,
                    .upload_received_bytes = 0U,
                    .upload_total_bytes = 0U,
                    .source_digest = std::nullopt};
        }
        const cluster::AdminApplyRequest apply {
            .operation_id = request.operation_id,
            .idempotency_key = request.idempotency_key,
            .expected_pack_version = request.expected_pack_version,
            .at_unix_ms = request.at_unix_ms,
        };
        if (request.kind == ResidentAdminRequestKind::activation_drain) {
            auto drained = admin.begin_drain(context, request.tenant, request.pack, apply, request.drain_boundary);
            if (!drained) {
                return rejected_response(request, drained.error());
            }
            const auto resource_version = operation_version(request.operation_id);
            if (!resource_version) {
                return unavailable_after_commit();
            }
            return {.status = ResidentAdminResponseStatus::ok,
                    .request_id = request.request_id,
                    .code = "OK",
                    .diagnostic = {},
                    .storage_revision = 0U,
                    .resource_version = *resource_version,
                    .active_generation = drained->old_generation,
                    .previous_active_generation = std::nullopt,
                    .operation_phase = "draining",
                    .target_generation = drained->target_generation,
                    .drain_boundary = drained->drain_boundary,
                    .assignment_fence = drained->successor_assignment_fence,
                    .work_ids = drained->in_flight_work,
                    .upload_received_bytes = 0U,
                    .upload_total_bytes = 0U,
                    .source_digest = std::nullopt};
        }
        if (request.kind == ResidentAdminRequestKind::activation_fence) {
            auto fenced = admin.fence_stragglers(context, request.tenant, request.pack, apply, request.work_ids);
            if (!fenced) {
                return rejected_response(request, fenced.error());
            }
            const auto resource_version = operation_version(request.operation_id);
            if (!resource_version) {
                return unavailable_after_commit();
            }
            return {.status = ResidentAdminResponseStatus::ok,
                    .request_id = request.request_id,
                    .code = "OK",
                    .diagnostic = {},
                    .storage_revision = 0U,
                    .resource_version = *resource_version,
                    .active_generation = std::nullopt,
                    .previous_active_generation = std::nullopt,
                    .operation_phase = "fenced",
                    .target_generation = 0U,
                    .drain_boundary = 0U,
                    .assignment_fence = 0U,
                    .work_ids = std::move(*fenced),
                    .upload_received_bytes = 0U,
                    .upload_total_bytes = 0U,
                    .source_digest = std::nullopt};
        }
        auto flipped = admin.flip(context, request.tenant, request.pack, apply);
        if (!flipped) {
            return rejected_response(request, flipped.error());
        }
        if (activation_target_ != nullptr) {
            activation_target_->fence_activation();
        }
        const auto resource_version = operation_version(request.operation_id);
        if (!resource_version) {
            return unavailable_after_commit();
        }
        return {.status = ResidentAdminResponseStatus::ok,
                .request_id = request.request_id,
                .code = "OK",
                .diagnostic = {},
                .resource_version = *resource_version,
                .active_generation = flipped->active_generation,
                .previous_active_generation = flipped->retired_generation,
                .operation_phase = "applied",
                .target_generation = flipped->active_generation,
                .drain_boundary = flipped->activation_cursor,
                .assignment_fence = flipped->assignment_fence,
                .work_ids = flipped->requeued_work,
                .upload_received_bytes = 0U,
                .upload_total_bytes = 0U,
                .source_digest = std::nullopt};
    }

    struct ResidentServiceScheduler::Impl {
        Impl(ResidentServiceLimits configured, IResidentSessionHandler &target):
            limits {configured}, handler {target} {}

        void worker(const std::stop_token cancellation) noexcept {
            while (true) {
                ResidentSessionJob job;
                {
                    std::unique_lock lock {mutex};
                    ready.wait(lock, cancellation, [&] { return !queue.empty() || stopping; });
                    if ((cancellation.stop_requested() || stopping) && queue.empty()) {
                        return;
                    }
                    job = std::move(queue.front());
                    queue.pop_front();
                    ++active;
                }
                handler.run(std::move(job), cancellation);
                {
                    std::scoped_lock lock {mutex};
                    --active;
                }
            }
        }

        ResidentServiceLimits limits;
        IResidentSessionHandler &handler;
        mutable std::mutex mutex;
        std::condition_variable_any ready;
        std::deque<ResidentSessionJob> queue;
        std::vector<std::jthread> workers;
        std::size_t active {};
        std::size_t accepted {};
        std::size_t rejected {};
        bool stopping {};
        bool joined {};
    };

    ResidentServiceScheduler::ResidentServiceScheduler(std::unique_ptr<Impl> impl) noexcept: impl_ {std::move(impl)} {}

    std::expected<std::unique_ptr<ResidentServiceScheduler>, protocol_v2::ProtocolError>
    ResidentServiceScheduler::create(ResidentServiceLimits limits, IResidentSessionHandler &handler) {
        if (auto valid = validate_resident_service_limits(limits); !valid) {
            return std::unexpected(std::move(valid.error()));
        }
        auto impl = std::make_unique<Impl>(limits, handler);
        auto scheduler = std::unique_ptr<ResidentServiceScheduler> {new ResidentServiceScheduler {std::move(impl)}};
        scheduler->impl_->workers.reserve(limits.worker_threads);
        for (std::size_t index = 0U; index < limits.worker_threads; ++index) {
            scheduler->impl_->workers.emplace_back(
                [state = scheduler->impl_.get()](const std::stop_token cancellation) { state->worker(cancellation); });
        }
        return scheduler;
    }

    ResidentServiceScheduler::~ResidentServiceScheduler() {
        request_stop();
        join();
    }

    ResidentAdmission ResidentServiceScheduler::submit(ResidentSessionJob job) noexcept {
        if (impl_ == nullptr || job.channel == nullptr) {
            if (job.channel) {
                job.channel->shutdown();
            }
            return ResidentAdmission::stopped;
        }
        std::unique_lock lock {impl_->mutex};
        if (impl_->stopping) {
            lock.unlock();
            job.channel->shutdown();
            return ResidentAdmission::stopped;
        }
        if (impl_->queue.size() >= impl_->limits.maximum_queued_sessions) {
            ++impl_->rejected;
            lock.unlock();
            job.channel->shutdown();
            return ResidentAdmission::overloaded;
        }
        impl_->queue.push_back(std::move(job));
        ++impl_->accepted;
        impl_->ready.notify_one();
        return ResidentAdmission::accepted;
    }

    void ResidentServiceScheduler::request_stop() noexcept {
        if (impl_ == nullptr) {
            return;
        }
        std::deque<ResidentSessionJob> abandoned;
        {
            std::scoped_lock lock {impl_->mutex};
            if (impl_->stopping) {
                return;
            }
            impl_->stopping = true;
            abandoned.swap(impl_->queue);
            impl_->rejected += abandoned.size();
            for (auto &worker : impl_->workers) { worker.request_stop(); }
        }
        for (auto &job : abandoned) {
            if (job.channel) {
                job.channel->shutdown();
            }
        }
        impl_->ready.notify_all();
    }

    void ResidentServiceScheduler::join() noexcept {
        if (impl_ == nullptr || impl_->joined) {
            return;
        }
        request_stop();
        impl_->workers.clear();
        impl_->joined = true;
    }

    ResidentSchedulerSnapshot ResidentServiceScheduler::snapshot() const noexcept {
        if (impl_ == nullptr) {
            return {.stopping = true};
        }
        std::scoped_lock lock {impl_->mutex};
        return {.queued_sessions = impl_->queue.size(),
                .active_sessions = impl_->active,
                .accepted_sessions = impl_->accepted,
                .rejected_sessions = impl_->rejected,
                .stopping = impl_->stopping};
    }

    void ResidentWorkPollSnapshot::merge(const ResidentWorkPollSnapshot &other) noexcept {
        empty_polls = saturating_add(empty_polls, other.empty_polls);
        nonempty_polls = saturating_add(nonempty_polls, other.nonempty_polls);
        delivered_work = saturating_add(delivered_work, other.delivered_work);
        delivery_delay_samples = saturating_add(delivery_delay_samples, other.delivery_delay_samples);
        delivery_delay_total_microseconds =
            saturating_add(delivery_delay_total_microseconds, other.delivery_delay_total_microseconds);
        delivery_delay_max_microseconds =
            (std::max) (delivery_delay_max_microseconds, other.delivery_delay_max_microseconds);
        if (delivery_delay_samples == 0U) {
            delivery_delay_total_microseconds = 0U;
            delivery_delay_max_microseconds = 0U;
            return;
        }
        delivery_delay_total_microseconds = (std::max) (delivery_delay_total_microseconds, std::uint64_t {1U});
        delivery_delay_max_microseconds = (std::max) (delivery_delay_max_microseconds, std::uint64_t {1U});
        delivery_delay_total_microseconds =
            (std::max) (delivery_delay_total_microseconds, delivery_delay_max_microseconds);
    }

    struct ResidentApplicationService::Impl {
        ResidentServiceLimits limits;
        const protocol_v2::ITrustPolicy &peer_trust;
        IResidentAgentBackend &agents;
        IResidentAdminBackend &admin;
        mutable std::mutex work_poll_metrics_mutex;
        ResidentWorkPollSnapshot work_poll_metrics;
        WorkPollTestHook before_delay_publish {};
        WorkPollTestHook before_snapshot_lock {};
        void *test_hook_context {};

        Impl(ResidentServiceLimits service_limits, const protocol_v2::ITrustPolicy &trust,
             IResidentAgentBackend &agent_backend, IResidentAdminBackend &admin_backend) noexcept:
            limits {service_limits}, peer_trust {trust}, agents {agent_backend}, admin {admin_backend} {}

        Impl(const Impl &other) noexcept:
            limits {other.limits}, peer_trust {other.peer_trust}, agents {other.agents}, admin {other.admin} {
            std::scoped_lock lock {other.work_poll_metrics_mutex};
            work_poll_metrics = other.work_poll_metrics;
        }
    };

    ResidentApplicationService::ResidentApplicationService(ResidentServiceLimits limits,
                                                           const protocol_v2::ITrustPolicy &peer_trust,
                                                           IResidentAgentBackend &agents,
                                                           IResidentAdminBackend &admin) noexcept:
        impl_ {std::make_unique<Impl>(limits, peer_trust, agents, admin)} {}

    ResidentApplicationService::ResidentApplicationService(const ResidentApplicationService &other) noexcept:
        impl_ {std::make_unique<Impl>(*other.impl_)} {}

    ResidentApplicationService::ResidentApplicationService(ResidentApplicationService &&other) noexcept:
        ResidentApplicationService {static_cast<const ResidentApplicationService &>(other)} {}

    ResidentApplicationService::~ResidentApplicationService() = default;

    void ResidentApplicationService::run(ResidentSessionJob job, const std::stop_token cancellation) noexcept {
        if (job.channel == nullptr) {
            return;
        }
        if (job.role == ResidentSessionRole::agent) {
            run_agent(job, cancellation);
        } else {
            run_admin(job, cancellation);
        }
        job.channel->shutdown();
    }

    ResidentWorkPollSnapshot ResidentApplicationService::work_poll_snapshot() const noexcept {
        if (impl_->before_snapshot_lock != nullptr) {
            impl_->before_snapshot_lock(impl_->test_hook_context);
        }
        std::scoped_lock lock {impl_->work_poll_metrics_mutex};
        return impl_->work_poll_metrics;
    }

    void ResidentApplicationService::set_work_poll_test_hooks(const WorkPollTestHook before_delay_publish,
                                                              const WorkPollTestHook before_snapshot_lock,
                                                              void *const context) noexcept {
        std::scoped_lock lock {impl_->work_poll_metrics_mutex};
        impl_->before_delay_publish = before_delay_publish;
        impl_->before_snapshot_lock = before_snapshot_lock;
        impl_->test_hook_context = context;
    }

    void ResidentApplicationService::run_agent(ResidentSessionJob &job, const std::stop_token cancellation) noexcept {
        const auto session_deadline = std::chrono::steady_clock::now() + impl_->limits.maximum_session_duration;
        auto first = job.channel->receive_protocol(bounded_deadline(session_deadline), cancellation);
        if (!first || !std::holds_alternative<protocol_v2::AgentHelloMessage>(first->body) || first->session ||
            first->agent_sequence != 0U || first->protocol_major != protocol_v2::major_version) {
            return;
        }
        const auto &hello = std::get<protocol_v2::AgentHelloMessage>(first->body);
        if (hello.minimum_minor > protocol_v2::initial_minor_version || hello.maximum_minor < hello.minimum_minor ||
            hello.agent_epoch.empty() || hello.agent_epoch != first->agent_epoch || hello.next_sequence == 0U ||
            !impl_->peer_trust.authorize_capabilities(job.peer, hello.capabilities)) {
            return;
        }
        auto session = impl_->agents.establish(job.peer, hello, cancellation);
        if (!session) {
            return;
        }
        const AgentSessionCloser close_session {.backend = impl_->agents, .session = *session};
        if (session->authenticated_peer.tenant != job.peer.tenant ||
            session->authenticated_peer.peer != job.peer.peer || session->session.empty() ||
            session->session_fence == 0U || session->agent_epoch != hello.agent_epoch ||
            session->acknowledged_through >= hello.next_sequence ||
            session->credit.bytes > impl_->limits.inbound_credit.bytes ||
            session->credit.messages > impl_->limits.inbound_credit.messages ||
            session->credit.work_attempts > impl_->limits.inbound_credit.work_attempts ||
            session->credit.snapshot_chunks > impl_->limits.inbound_credit.snapshot_chunks) {
            return;
        }
        auto gate = runtime::ProtocolV2DurableSequenceGate::create(
            job.peer.peer, session->session, session->session_fence, session->agent_epoch,
            session->acknowledged_through, protocol_v2::initial_minor_version,
            protocol_v2::ProtocolLimits {.maximum_frame_bytes = impl_->limits.maximum_frame_bytes,
                                         .maximum_sequence_gap = 1U});
        if (!gate) {
            return;
        }
        const protocol_v2::ServerHelloMessage welcome {
            .selected_minor = protocol_v2::initial_minor_version,
            .session = session->session,
            .peer = job.peer.peer,
            .session_fence = session->session_fence,
            .acknowledged_sequence = session->acknowledged_through,
            .schemas = session->schemas,
            .capabilities = session->capabilities,
            .credit = session->credit,
            .heartbeat_interval_ms = static_cast<std::uint64_t>(impl_->limits.maximum_session_duration.count()),
        };
        if (auto sent = job.channel->send_protocol(
                server_envelope(*session, "server:" + session->session.value + ":hello", welcome),
                bounded_deadline(session_deadline), cancellation);
            !sent) {
            return;
        }

        std::map<std::string, protocol_v2::WorkLeaseMessage, std::less<>> outstanding;
        const auto peer_work_limit = (std::min) ({impl_->limits.maximum_inflight_work_per_session,
                                                  static_cast<std::size_t>(hello.receive_limit.work_attempts),
                                                  static_cast<std::size_t>(hello.receive_limit.messages)});
        std::uint64_t server_sequence {};
        std::size_t sent_work_bytes {};
        constexpr auto maximum_size = (std::numeric_limits<std::size_t>::max)();
        const auto peer_byte_limit =
            static_cast<std::size_t>((std::min) (hello.receive_limit.bytes, static_cast<std::uint64_t>(maximum_size)));
        const auto send_work = [&](std::vector<protocol_v2::WorkLeaseMessage> work, std::size_t &delivered) {
            for (auto &lease : work) {
                lease.session = session->session;
                lease.peer = job.peer.peer;
                lease.session_fence = session->session_fence;
                lease.server_sequence = ++server_sequence;
                IgnoreCancel cancel;
                auto valid = runtime::ProtocolV2ProviderResponsePort::create(lease, cancel);
                if (!valid || outstanding.contains(lease.work_id) ||
                    outstanding.size() >= impl_->limits.maximum_inflight_work_per_session) {
                    return false;
                }
                const auto message_id = "server:" + session->session.value + ":work:" + std::to_string(server_sequence);
                auto outbound = server_envelope(*session, message_id, lease);
                auto measured = protocol_v2::encode_frame(
                    outbound, protocol_v2::ProtocolLimits {.maximum_frame_bytes = impl_->limits.maximum_frame_bytes});
                if (!measured || sent_work_bytes > peer_byte_limit ||
                    measured->size() > peer_byte_limit - sent_work_bytes) {
                    return false;
                }
                sent_work_bytes += measured->size();
                if (auto sent = job.channel->send_protocol(outbound, bounded_deadline(session_deadline), cancellation);
                    !sent) {
                    return false;
                }
                outstanding.emplace(lease.work_id, std::move(lease));
                ++delivered;
            }
            return true;
        };
        std::optional<std::chrono::steady_clock::time_point> observed_idle_since;
        const auto poll_work = [&]() {
            const auto available = peer_work_limit - outstanding.size();
            if (available == 0U) {
                return true;
            }
            const auto poll_started = std::chrono::steady_clock::now();
            auto work = impl_->agents.take_work(*session, available, cancellation);
            if (!work) {
                return false;
            }
            if (work->empty()) {
                {
                    std::scoped_lock lock {impl_->work_poll_metrics_mutex};
                    impl_->work_poll_metrics.empty_polls = saturating_add(impl_->work_poll_metrics.empty_polls, 1U);
                }
                if (!observed_idle_since) {
                    observed_idle_since = poll_started;
                }
                return true;
            }

            if (work->size() > available) {
                std::scoped_lock lock {impl_->work_poll_metrics_mutex};
                impl_->work_poll_metrics.nonempty_polls = saturating_add(impl_->work_poll_metrics.nonempty_polls, 1U);
                return false;
            }
            std::size_t delivered {};
            const auto sent = send_work(std::move(*work), delivered);
            {
                std::scoped_lock lock {impl_->work_poll_metrics_mutex};
                impl_->work_poll_metrics.nonempty_polls = saturating_add(impl_->work_poll_metrics.nonempty_polls, 1U);
                impl_->work_poll_metrics.delivered_work =
                    saturating_add(impl_->work_poll_metrics.delivered_work, static_cast<std::uint64_t>(delivered));
                if (delivered == 0U) {
                    return sent;
                }
                const auto delay = std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::steady_clock::now() - observed_idle_since.value_or(poll_started));
                const auto delay_microseconds = delay.count() <= 0 ? 1U : static_cast<std::uint64_t>(delay.count());
                impl_->work_poll_metrics.delivery_delay_samples =
                    saturating_add(impl_->work_poll_metrics.delivery_delay_samples, 1U);
                if (impl_->before_delay_publish != nullptr) {
                    impl_->before_delay_publish(impl_->test_hook_context);
                }
                impl_->work_poll_metrics.delivery_delay_total_microseconds =
                    saturating_add(impl_->work_poll_metrics.delivery_delay_total_microseconds, delay_microseconds);
                impl_->work_poll_metrics.delivery_delay_max_microseconds =
                    (std::max) (impl_->work_poll_metrics.delivery_delay_max_microseconds, delay_microseconds);
            }
            observed_idle_since.reset();
            return sent;
        };
        if (!poll_work()) {
            return;
        }

        std::size_t received_messages {};
        while (received_messages < impl_->limits.maximum_messages_per_session &&
               std::chrono::steady_clock::now() < session_deadline && !cancellation.stop_requested()) {
            auto readable = job.channel->wait_protocol_input(
                bounded_deadline(session_deadline, impl_->limits.work_poll_interval), cancellation);
            if (!readable) {
                break;
            }
            if (!*readable) {
                if (!poll_work()) {
                    return;
                }
                continue;
            }
            auto received = job.channel->receive_protocol(bounded_deadline(session_deadline), cancellation);
            if (!received) {
                break;
            }
            ++received_messages;
            const auto sequence = received->agent_sequence;
            auto admitted = gate->admit(std::move(*received));
            if (!admitted) {
                const protocol_v2::NackMessage nack {.agent_epoch = session->agent_epoch,
                                                     .sequence = sequence,
                                                     .reason = admitted.error().code,
                                                     .permanent = false,
                                                     .diagnostic = admitted.error().message.substr(0U, 512U)};
                static_cast<void>(job.channel->send_protocol(
                    server_envelope(*session, "server:" + session->session.value + ":nack", nack),
                    bounded_deadline(session_deadline), cancellation));
                break;
            }
            if (*admitted == protocol_v2::SequenceDisposition::duplicate) {
                const protocol_v2::AckMessage ack {.agent_epoch = session->agent_epoch,
                                                   .acknowledged_through = gate->acknowledged_through(),
                                                   .credit = session->credit};
                static_cast<void>(job.channel->send_protocol(
                    server_envelope(*session, "server:" + session->session.value + ":ack", ack),
                    bounded_deadline(session_deadline), cancellation));
                continue;
            }
            while (auto contiguous = gate->next_contiguous()) {
                if (const auto *result = std::get_if<protocol_v2::WorkResultMessage>(&contiguous->body)) {
                    if (auto valid = validate_result(outstanding, *result); !valid) {
                        const protocol_v2::NackMessage nack {.agent_epoch = session->agent_epoch,
                                                             .sequence = contiguous->sequence,
                                                             .reason = valid.error().code,
                                                             .permanent = false,
                                                             .diagnostic = valid.error().message.substr(0U, 512U)};
                        static_cast<void>(job.channel->send_protocol(
                            server_envelope(*session, "server:" + session->session.value + ":nack", nack),
                            bounded_deadline(session_deadline), cancellation));
                        return;
                    }
                }
                auto durable = impl_->agents.persist(*session, contiguous->sequence, contiguous->body, cancellation);
                const auto credit_valid =
                    durable && durable->credit.bytes <= impl_->limits.inbound_credit.bytes &&
                    durable->credit.messages <= impl_->limits.inbound_credit.messages &&
                    durable->credit.work_attempts <= impl_->limits.inbound_credit.work_attempts &&
                    durable->credit.snapshot_chunks <= impl_->limits.inbound_credit.snapshot_chunks;
                if (!durable || durable->acknowledged_through != contiguous->sequence || !credit_valid) {
                    const auto reason =
                        durable ? protocol_v2::ProtocolErrorCode::persistence_error : durable.error().code;
                    const protocol_v2::NackMessage nack {.agent_epoch = session->agent_epoch,
                                                         .sequence = contiguous->sequence,
                                                         .reason = reason,
                                                         .permanent = false,
                                                         .diagnostic = "durable agent receipt was not committed"};
                    static_cast<void>(job.channel->send_protocol(
                        server_envelope(*session, "server:" + session->session.value + ":nack", nack),
                        bounded_deadline(session_deadline), cancellation));
                    return;
                }
                auto settled = gate->mark_durable(contiguous->sequence);
                if (!settled || *settled != durable->acknowledged_through) {
                    return;
                }
                session->acknowledged_through = *settled;
                session->credit = durable->credit;
                if (const auto *result = std::get_if<protocol_v2::WorkResultMessage>(&contiguous->body)) {
                    outstanding.erase(result->work_id);
                }
                const protocol_v2::AckMessage ack {
                    .agent_epoch = session->agent_epoch, .acknowledged_through = *settled, .credit = durable->credit};
                if (auto sent = job.channel->send_protocol(
                        server_envelope(*session, "server:" + session->session.value + ":ack", ack),
                        bounded_deadline(session_deadline), cancellation);
                    !sent) {
                    return;
                }
                if (!poll_work()) {
                    return;
                }
            }
        }
    }

    void ResidentApplicationService::run_admin(ResidentSessionJob &job, const std::stop_token cancellation) noexcept {
        const auto session_deadline = std::chrono::steady_clock::now() + impl_->limits.maximum_session_duration;
        for (std::size_t count = 0U;
             count < impl_->limits.maximum_messages_per_session &&
             std::chrono::steady_clock::now() < session_deadline && !cancellation.stop_requested();
             ++count) {
            auto payload = job.channel->receive_application_frame(bounded_deadline(session_deadline), cancellation);
            if (!payload || payload->size() > impl_->limits.maximum_frame_bytes) {
                return;
            }
            auto request = decode_resident_admin_request(*payload, impl_->limits.maximum_frame_bytes);
            if (!request) {
                return;
            }
            auto response = impl_->admin.execute(job.peer, *request);
            auto encoded = encode_resident_admin_response(response, impl_->limits.maximum_frame_bytes);
            if (!encoded ||
                !job.channel->send_application_frame(*encoded, bounded_deadline(session_deadline), cancellation)) {
                return;
            }
        }
    }

} // namespace rule_engine::python::tools
