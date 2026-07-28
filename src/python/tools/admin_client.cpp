#include "rule_engine/python/tools/admin_client.hpp"

#include "rule_engine/python/protocol/network.hpp"
#include "rule_engine/python/tools/resident_service.hpp"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <fstream>
#include <limits>
#include <optional>
#include <ranges>
#include <string_view>
#include <utility>

namespace rule_engine::python::tools {
    namespace {

        constexpr std::size_t maximum_pem_bytes = 1U * mebibyte;
        constexpr std::size_t maximum_admin_frame_bytes = 4U * mebibyte;
        constexpr std::size_t upload_chunk_bytes = 1U * mebibyte;
        constexpr std::size_t maximum_upload_identity_bytes = 960U;

        [[nodiscard]] ToolFailure failure(const ToolFailureKind kind, std::string code, std::string message) {
            return {.kind = kind, .code = std::move(code), .message = std::move(message), .diagnostics = {}};
        }

        [[nodiscard]] std::expected<std::string, ToolFailure> read_pem(const std::filesystem::path &path) {
            std::error_code filesystem_error;
            const auto size = std::filesystem::file_size(path, filesystem_error);
            if (filesystem_error || size == 0U || size > maximum_pem_bytes) {
                return std::unexpected(
                    failure(ToolFailureKind::authentication, "ADMIN-MTLS", "mTLS material has an invalid size"));
            }
            std::ifstream input {path, std::ios::binary};
            if (!input) {
                return std::unexpected(
                    failure(ToolFailureKind::authentication, "ADMIN-MTLS", "mTLS material cannot be opened"));
            }
            std::string result(static_cast<std::size_t>(size), '\0');
            input.read(result.data(), static_cast<std::streamsize>(result.size()));
            if (!input || input.gcount() != static_cast<std::streamsize>(result.size())) {
                return std::unexpected(
                    failure(ToolFailureKind::authentication, "ADMIN-MTLS", "mTLS material cannot be read completely"));
            }
            return result;
        }

        [[nodiscard]] std::expected<std::vector<std::byte>, ToolFailure>
        read_upload_archive(const std::filesystem::path &path) {
            std::error_code filesystem_error;
            const auto status = std::filesystem::symlink_status(path, filesystem_error);
            if (filesystem_error || !std::filesystem::is_regular_file(status) || std::filesystem::is_symlink(status)) {
                return std::unexpected(failure(ToolFailureKind::operation, "ADMIN-UPLOAD-FILE",
                                               "upload archive must be a real regular file"));
            }
            const auto size = std::filesystem::file_size(path, filesystem_error);
            if (filesystem_error || size == 0U || size > balanced_v1.compile.source_closure_bytes) {
                return std::unexpected(failure(ToolFailureKind::operation, "ADMIN-UPLOAD-SIZE",
                                               "upload archive exceeds the balanced.v1 source-closure bound"));
            }
            std::ifstream input {path, std::ios::binary};
            std::vector<std::byte> result(static_cast<std::size_t>(size));
            input.read(reinterpret_cast<char *>(result.data()), static_cast<std::streamsize>(result.size()));
            if (!input || input.gcount() != static_cast<std::streamsize>(result.size())) {
                return std::unexpected(failure(ToolFailureKind::operation, "ADMIN-UPLOAD-READ",
                                               "upload archive cannot be read completely"));
            }
            return result;
        }

        [[nodiscard]] std::expected<protocol_v2::TcpEndpoint, ToolFailure>
        parse_endpoint(const std::string_view endpoint) {
            constexpr std::string_view scheme {"https://"};
            if (!endpoint.starts_with(scheme)) {
                return std::unexpected(
                    failure(ToolFailureKind::authentication, "ADMIN-ENDPOINT", "admin endpoint must use HTTPS"));
            }
            auto authority = endpoint.substr(scheme.size());
            const auto path = authority.find('/');
            authority = authority.substr(0U, path);
            std::string_view host;
            std::string_view port_text;
            if (authority.starts_with('[')) {
                const auto close = authority.find(']');
                if (close == std::string_view::npos || close + 2U > authority.size() || authority[close + 1U] != ':') {
                    return std::unexpected(failure(ToolFailureKind::authentication, "ADMIN-ENDPOINT",
                                                   "bracketed admin endpoint requires an explicit port"));
                }
                host = authority.substr(1U, close - 1U);
                port_text = authority.substr(close + 2U);
            } else {
                const auto colon = authority.rfind(':');
                if (colon == std::string_view::npos) {
                    return std::unexpected(failure(ToolFailureKind::authentication, "ADMIN-ENDPOINT",
                                                   "admin endpoint requires an explicit port"));
                }
                host = authority.substr(0U, colon);
                port_text = authority.substr(colon + 1U);
            }
            std::uint32_t port {};
            const auto parsed = std::from_chars(port_text.data(), port_text.data() + port_text.size(), port);
            if (host.empty() || parsed.ec != std::errc {} || parsed.ptr != port_text.data() + port_text.size() ||
                port == 0U || port > (std::numeric_limits<std::uint16_t>::max)()) {
                return std::unexpected(
                    failure(ToolFailureKind::authentication, "ADMIN-ENDPOINT", "admin endpoint authority is invalid"));
            }
            return protocol_v2::TcpEndpoint {.host = std::string {host}, .port = static_cast<std::uint16_t>(port)};
        }

        [[nodiscard]] std::expected<std::uint64_t, ToolFailure>
        unsigned_option(const AdminCommand &command, const std::string_view name, const bool required = false) {
            const auto found = command.options.find(name);
            if (found == command.options.end()) {
                if (required) {
                    return std::unexpected(failure(ToolFailureKind::operation, "ADMIN-ARGUMENT",
                                                   "admin command is missing a required numeric option"));
                }
                return 0U;
            }
            std::uint64_t value {};
            const auto parsed =
                std::from_chars(found->second.data(), found->second.data() + found->second.size(), value);
            if (parsed.ec != std::errc {} || parsed.ptr != found->second.data() + found->second.size()) {
                return std::unexpected(failure(ToolFailureKind::operation, "ADMIN-ARGUMENT",
                                               "admin command has an invalid numeric option"));
            }
            return value;
        }

        [[nodiscard]] std::string option(const AdminCommand &command, const std::string_view name,
                                         std::string fallback = {}) {
            const auto found = command.options.find(name);
            return found == command.options.end() ? std::move(fallback) : found->second;
        }

        [[nodiscard]] std::vector<std::string> work_ids(const AdminCommand &command) {
            const auto encoded = option(command, "work-ids");
            if (encoded.empty()) {
                return {};
            }
            std::vector<std::string> result;
            std::string_view remaining = encoded;
            while (true) {
                const auto comma = remaining.find(',');
                result.emplace_back(remaining.substr(0U, comma));
                if (comma == std::string_view::npos) {
                    return result;
                }
                remaining.remove_prefix(comma + 1U);
            }
        }

        [[nodiscard]] std::uint64_t now_unix_ms() noexcept {
            const auto value = std::chrono::duration_cast<std::chrono::milliseconds>(
                                   std::chrono::system_clock::now().time_since_epoch())
                                   .count();
            return value > 0 ? static_cast<std::uint64_t>(value) : 1U;
        }

        [[nodiscard]] std::expected<ResidentAdminRequest, ToolFailure> make_request(const AdminCommand &command,
                                                                                    const std::uint64_t at_unix_ms) {
            if (at_unix_ms == 0U) {
                return std::unexpected(
                    failure(ToolFailureKind::operation, "ADMIN-TIME", "admin request time must be non-zero"));
            }
            if (command.wait) {
                return std::unexpected(failure(ToolFailureKind::operation, "ADMIN-NOT-IMPLEMENTED",
                                               "bounded operation polling is not implemented yet"));
            }
            const auto tenant = option(command, "tenant");
            if (tenant.empty()) {
                return std::unexpected(
                    failure(ToolFailureKind::operation, "ADMIN-TENANT", "admin command requires --tenant ID"));
            }
            if (command.action != AdminAction::packs && command.action != AdminAction::operation &&
                command.action != AdminAction::activate) {
                return std::unexpected(failure(ToolFailureKind::operation, "ADMIN-NOT-IMPLEMENTED",
                                               "admin command is not available on the resident v2 control channel"));
            }
            if (command.action == AdminAction::activate && !command.options.contains("expected-version")) {
                return std::unexpected(failure(ToolFailureKind::operation, "ADMIN-EXPECTED-VERSION",
                                               "activation mutation requires --expected-version N"));
            }
            const auto expected_version = unsigned_option(command, "expected-version");
            if (!expected_version) {
                return std::unexpected(expected_version.error());
            }
            const auto request_id =
                command.request_id.empty() ? "read:" + std::to_string(at_unix_ms) : command.request_id;
            ResidentAdminRequest request {
                .kind = ResidentAdminRequestKind::pack_snapshot,
                .request_id = request_id,
                .tenant = TenantId {tenant},
                .pack = {},
                .operation_id = {},
                .idempotency_key = {},
                .expected_pack_version = *expected_version,
                .at_unix_ms = at_unix_ms,
                .reason = {},
                .target_generation = 0U,
                .drain_boundary = 0U,
                .work_ids = {},
                .upload_offset = 0U,
                .upload_total_bytes = 0U,
                .payload = {},
            };
            if (command.action == AdminAction::packs) {
                if (command.operands.size() != 1U || *expected_version != 0U) {
                    return std::unexpected(
                        failure(ToolFailureKind::operation, "ADMIN-ARGUMENT", "packs requires exactly one pack ID"));
                }
                request.pack = PackId {command.operands.front()};
                return request;
            }
            if (command.action == AdminAction::operation) {
                if (command.operands.size() != 2U || *expected_version != 0U) {
                    return std::unexpected(failure(ToolFailureKind::operation, "ADMIN-ARGUMENT",
                                                   "operation requires PACK_ID and OPERATION_ID"));
                }
                request.kind = ResidentAdminRequestKind::operation_snapshot;
                request.pack = PackId {command.operands[0]};
                request.operation_id = command.operands[1];
                return request;
            }

            const auto phase = option(command, "phase", "preview");
            if (command.request_id.empty()) {
                return std::unexpected(failure(ToolFailureKind::operation, "ADMIN-REQUEST-ID",
                                               "activation mutation requires --request-id ID"));
            }
            request.operation_id = option(command, "operation-id", command.request_id);
            request.idempotency_key = option(command, "idempotency-key", command.request_id);
            if (phase == "preview") {
                if (command.operands.size() != 2U || command.reason.empty()) {
                    return std::unexpected(
                        failure(ToolFailureKind::operation, "ADMIN-ARGUMENT",
                                "activation preview requires PACK_ID, GENERATION, --request-id, and --reason"));
                }
                std::uint64_t generation {};
                const auto text = std::string_view {command.operands[1]};
                const auto parsed = std::from_chars(text.data(), text.data() + text.size(), generation);
                if (parsed.ec != std::errc {} || parsed.ptr != text.data() + text.size() || generation == 0U) {
                    return std::unexpected(
                        failure(ToolFailureKind::operation, "ADMIN-ARGUMENT", "activation generation is invalid"));
                }
                request.kind = ResidentAdminRequestKind::activation_preview;
                request.pack = PackId {command.operands[0]};
                request.reason = command.reason;
                request.target_generation = generation;
                return request;
            }
            if (command.preview || command.operands.size() != 1U) {
                return std::unexpected(failure(ToolFailureKind::operation, "ADMIN-APPLY",
                                               "drain, fence, and flip require one PACK_ID and --apply"));
            }
            request.pack = PackId {command.operands[0]};
            if (phase == "drain") {
                const auto boundary = unsigned_option(command, "boundary", true);
                if (!boundary || *boundary == 0U) {
                    return std::unexpected(boundary ? failure(ToolFailureKind::operation, "ADMIN-ARGUMENT",
                                                              "activation drain boundary must be non-zero") :
                                                      boundary.error());
                }
                request.kind = ResidentAdminRequestKind::activation_drain;
                request.drain_boundary = *boundary;
                return request;
            }
            if (phase == "fence") {
                request.kind = ResidentAdminRequestKind::activation_fence;
                request.work_ids = work_ids(command);
                if (std::ranges::any_of(request.work_ids, &std::string::empty)) {
                    return std::unexpected(
                        failure(ToolFailureKind::operation, "ADMIN-ARGUMENT", "activation work IDs cannot be empty"));
                }
                return request;
            }
            if (phase == "flip") {
                request.kind = ResidentAdminRequestKind::activation_flip;
                return request;
            }
            return std::unexpected(
                failure(ToolFailureKind::operation, "ADMIN-ARGUMENT", "activation phase is invalid"));
        }

        [[nodiscard]] std::expected<ResidentAdminResponse, ToolFailure>
        exchange_mtls(const AdminEndpointConfiguration &endpoint, const ResidentAdminRequest &request) {
            auto trust = read_pem(endpoint.trust_bundle);
            auto certificate = read_pem(endpoint.client_certificate);
            auto key = read_pem(endpoint.client_key);
            auto address = parse_endpoint(endpoint.endpoint);
            if (!trust || !certificate || !key || !address) {
                return std::unexpected(!trust       ? trust.error() :
                                       !certificate ? certificate.error() :
                                       !key         ? key.error() :
                                                      address.error());
            }
            auto context = protocol_v2::OpenSslTlsContext::create(protocol_v2::TlsConfiguration {
                .role = protocol_v2::TlsEndpointRole::client,
                .trust_anchors_pem = std::move(*trust),
                .certificate_chain_pem = std::move(*certificate),
                .private_key_pem = std::move(*key),
                .crl_pem = {},
                .expected_server_name = address->host,
                .require_crl = false,
                .verification_time_unix_seconds = std::nullopt,
                .protocol_limits = {.maximum_frame_bytes = maximum_admin_frame_bytes},
            });
            if (!context) {
                return std::unexpected(
                    failure(ToolFailureKind::authentication, "ADMIN-TLS", "admin TLS context could not be created"));
            }
            auto dialer = protocol_v2::TlsSessionDialer::create(
                std::move(*context), {*address},
                protocol_v2::TlsPeerRequirement {.canonical_uri_san = endpoint.server_uri,
                                                 .certificate_sha256 = std::nullopt},
                {},
                {.maximum_rounds = 1U,
                 .maximum_endpoints = 1U,
                 .maximum_addresses_per_endpoint = 8U,
                 .maximum_connection_attempts = 8U,
                 .require_hard_resolver_bounds = false});
            if (!dialer) {
                return std::unexpected(failure(ToolFailureKind::unavailable_transport, "ADMIN-TRANSPORT",
                                               "admin TLS dialer could not be configured"));
            }
            auto connection = dialer->connect();
            if (!connection) {
                return std::unexpected(
                    failure(connection.error().code == protocol_v2::ProtocolErrorCode::unauthenticated ?
                                ToolFailureKind::authentication :
                                ToolFailureKind::unavailable_transport,
                            "ADMIN-CONNECT", "authenticated admin connection could not be established"));
            }
            auto payload = encode_resident_admin_request(request, maximum_admin_frame_bytes);
            if (!payload) {
                return std::unexpected(
                    failure(ToolFailureKind::operation, "ADMIN-REQUEST", "admin request is invalid"));
            }
            const auto write_deadline = std::chrono::steady_clock::now() + std::chrono::seconds {5};
            if (auto sent = connection->send_application_frame_until(*payload, write_deadline); !sent) {
                return std::unexpected(
                    failure(ToolFailureKind::unavailable_transport, "ADMIN-SEND", "admin request could not be sent"));
            }
            const auto read_deadline = std::chrono::steady_clock::now() + std::chrono::seconds {30};
            auto response = connection->receive_application_frame_until(read_deadline);
            connection->shutdown();
            if (!response) {
                return std::unexpected(failure(ToolFailureKind::unavailable_transport, "ADMIN-RECEIVE",
                                               "admin response was not received"));
            }
            auto decoded = decode_resident_admin_response(*response, maximum_admin_frame_bytes);
            if (!decoded || decoded->request_id != request.request_id) {
                return std::unexpected(failure(ToolFailureKind::unavailable_transport, "ADMIN-RESPONSE",
                                               "admin response is malformed or uncorrelated"));
            }
            return std::move(*decoded);
        }

        [[nodiscard]] std::expected<ResidentAdminResponse, ToolFailure>
        exchange_request(IResidentAdminRequestTransport *transport, const AdminEndpointConfiguration &endpoint,
                         const ResidentAdminRequest &request) {
            return transport == nullptr ? exchange_mtls(endpoint, request) : transport->exchange(endpoint, request);
        }

        [[nodiscard]] std::expected<ResidentAdminResponse, ToolFailure>
        require_successful_response(std::expected<ResidentAdminResponse, ToolFailure> response) {
            if (!response) {
                return std::unexpected(response.error());
            }
            if (response->status == ResidentAdminResponseStatus::unavailable) {
                return std::unexpected(failure(ToolFailureKind::unavailable_transport, response->code,
                                               "authorized admin backend is unavailable"));
            }
            if (response->status == ResidentAdminResponseStatus::rejected &&
                (response->code == "ADMIN-UNAUTHENTICATED" || response->code == "ADMIN-UNAUTHORIZED" ||
                 response->code == "ADMIN-AUTHORIZER-UNAVAILABLE")) {
                return std::unexpected(failure(response->code == "ADMIN-UNAUTHORIZED" ? ToolFailureKind::authorization :
                                                                                        ToolFailureKind::authentication,
                                               response->code, "admin request was not authorized"));
            }
            return std::move(*response);
        }

        [[nodiscard]] std::expected<ResidentAdminResponse, ToolFailure>
        require_upload_success(std::expected<ResidentAdminResponse, ToolFailure> response) {
            auto checked = require_successful_response(std::move(response));
            if (!checked) {
                return std::unexpected(checked.error());
            }
            if (checked->status != ResidentAdminResponseStatus::ok) {
                return std::unexpected(
                    failure(ToolFailureKind::operation, checked->code,
                            checked->diagnostic.empty() ? "source-pack upload was rejected" : checked->diagnostic));
            }
            return checked;
        }

        void add_field(std::vector<DisplayField> &fields, std::string name, std::string value) {
            fields.push_back(DisplayField {
                .name = std::move(name), .value = std::move(value), .label = {}, .secret_reference = false});
        }

        [[nodiscard]] AdminToolResult result_for(const ResidentAdminResponse &response) {
            AdminToolResult result {.success = response.status == ResidentAdminResponseStatus::ok,
                                    .diagnostics = {},
                                    .sources = {},
                                    .fields = {}};
            add_field(result.fields, "status", response.status == ResidentAdminResponseStatus::ok ? "ok" : "rejected");
            add_field(result.fields, "code", response.code);
            add_field(result.fields, "request_id", response.request_id);
            add_field(result.fields, "storage_revision", std::to_string(response.storage_revision));
            add_field(result.fields, "resource_version", std::to_string(response.resource_version));
            if (response.active_generation) {
                add_field(result.fields, "active_generation", std::to_string(*response.active_generation));
            }
            if (response.previous_active_generation) {
                add_field(result.fields, "previous_active_generation",
                          std::to_string(*response.previous_active_generation));
            }
            if (!response.operation_phase.empty()) {
                add_field(result.fields, "operation_phase", response.operation_phase);
            }
            if (response.target_generation != 0U) {
                add_field(result.fields, "target_generation", std::to_string(response.target_generation));
            }
            if (response.drain_boundary != 0U) {
                add_field(result.fields, "drain_boundary", std::to_string(response.drain_boundary));
            }
            if (response.assignment_fence != 0U) {
                add_field(result.fields, "assignment_fence", std::to_string(response.assignment_fence));
            }
            if (!response.work_ids.empty()) {
                add_field(result.fields, "work_count", std::to_string(response.work_ids.size()));
            }
            if (response.upload_total_bytes != 0U) {
                add_field(result.fields, "received_bytes", std::to_string(response.upload_received_bytes));
                add_field(result.fields, "total_bytes", std::to_string(response.upload_total_bytes));
            }
            if (response.source_digest) {
                add_field(result.fields, "source_digest", response.source_digest->value);
            }
            if (!result.success) {
                result.diagnostics.push_back(Diagnostic {
                    .code = response.code,
                    .severity = DiagnosticSeverity::error,
                    .message = response.diagnostic.empty() ? "admin request was rejected" : response.diagnostic,
                    .span = std::nullopt,
                    .related = {}});
            }
            return result;
        }

        [[nodiscard]] ResidentAdminRequest
        upload_request(const ResidentAdminRequestKind kind, std::string request_id, const std::string_view tenant,
                       const std::string_view pack, const std::string_view upload_id, const std::uint64_t total_bytes,
                       const std::uint64_t offset, std::vector<std::byte> payload = {}, std::string reason = {}) {
            return ResidentAdminRequest {
                .kind = kind,
                .request_id = std::move(request_id),
                .tenant = TenantId {std::string {tenant}},
                .pack = PackId {std::string {pack}},
                .operation_id = std::string {upload_id},
                .idempotency_key = {},
                .expected_pack_version = 0U,
                .at_unix_ms = now_unix_ms(),
                .reason = std::move(reason),
                .target_generation = 0U,
                .drain_boundary = 0U,
                .work_ids = {},
                .upload_offset = offset,
                .upload_total_bytes = total_bytes,
                .payload = std::move(payload),
            };
        }

        [[nodiscard]] std::expected<AdminToolResult, ToolFailure>
        upload_archive(IResidentAdminRequestTransport *transport, const AdminEndpointConfiguration &endpoint,
                       const AdminCommand &command) {
            const auto tenant = option(command, "tenant");
            if (command.operands.size() != 2U || tenant.empty() || command.request_id.empty() ||
                command.request_id.size() > maximum_upload_identity_bytes || command.reason.empty() || command.wait ||
                command.preview) {
                return std::unexpected(
                    failure(ToolFailureKind::operation, "ADMIN-UPLOAD-ARGUMENT",
                            "upload requires PACK_ID, ARCHIVE, --tenant, --request-id, and --reason"));
            }
            auto archive = read_upload_archive(command.operands[1]);
            if (!archive) {
                return std::unexpected(archive.error());
            }
            const auto total_bytes = static_cast<std::uint64_t>(archive->size());
            auto begin = require_upload_success(exchange_request(
                transport, endpoint,
                upload_request(ResidentAdminRequestKind::upload_begin, command.request_id + ":begin", tenant,
                               command.operands[0], command.request_id, total_bytes, 0U, {}, command.reason)));
            if (!begin) {
                return std::unexpected(begin.error());
            }
            if (begin->upload_total_bytes != total_bytes || begin->upload_received_bytes > total_bytes ||
                (begin->source_digest && begin->upload_received_bytes != total_bytes)) {
                return std::unexpected(failure(ToolFailureKind::unavailable_transport, "ADMIN-UPLOAD-RESPONSE",
                                               "upload begin returned inconsistent progress"));
            }
            if (begin->source_digest) {
                return result_for(*begin);
            }

            auto offset = begin->upload_received_bytes;
            while (offset < total_bytes) {
                const auto count = (std::min) (upload_chunk_bytes, static_cast<std::size_t>(total_bytes - offset));
                std::vector<std::byte> chunk(archive->begin() + static_cast<std::ptrdiff_t>(offset),
                                             archive->begin() + static_cast<std::ptrdiff_t>(offset + count));
                auto response = require_upload_success(exchange_request(
                    transport, endpoint,
                    upload_request(ResidentAdminRequestKind::upload_chunk,
                                   command.request_id + ":chunk:" + std::to_string(offset), tenant, command.operands[0],
                                   command.request_id, total_bytes, offset, std::move(chunk))));
                if (!response) {
                    return std::unexpected(response.error());
                }
                const auto expected = offset + count;
                if (response->upload_total_bytes != total_bytes || response->upload_received_bytes != expected ||
                    response->source_digest) {
                    return std::unexpected(failure(ToolFailureKind::unavailable_transport, "ADMIN-UPLOAD-RESPONSE",
                                                   "upload chunk returned inconsistent progress"));
                }
                offset = response->upload_received_bytes;
            }

            auto finalized = require_upload_success(exchange_request(
                transport, endpoint,
                upload_request(ResidentAdminRequestKind::upload_finalize, command.request_id + ":finalize", tenant,
                               command.operands[0], command.request_id, total_bytes, total_bytes)));
            if (!finalized) {
                return std::unexpected(finalized.error());
            }
            if (finalized->upload_received_bytes != total_bytes || finalized->upload_total_bytes != total_bytes ||
                !finalized->source_digest) {
                return std::unexpected(failure(ToolFailureKind::unavailable_transport, "ADMIN-UPLOAD-RESPONSE",
                                               "upload finalize returned inconsistent publication evidence"));
            }
            return result_for(*finalized);
        }

    } // namespace

    std::expected<ResidentAdminRequest, ToolFailure> build_resident_admin_request(const AdminCommand &command,
                                                                                  const std::uint64_t at_unix_ms) {
        return make_request(command, at_unix_ms);
    }

    std::expected<AdminToolResult, ToolFailure>
    ResidentAdminClientAdapter::execute(const AdminEndpointConfiguration &endpoint, const AdminCommand &command) {
        if (command.action == AdminAction::upload) {
            return upload_archive(transport_, endpoint, command);
        }
        auto request = build_resident_admin_request(command, now_unix_ms());
        if (!request) {
            return std::unexpected(request.error());
        }
        auto response = require_successful_response(exchange_request(transport_, endpoint, *request));
        if (!response) {
            return std::unexpected(response.error());
        }
        return result_for(*response);
    }

} // namespace rule_engine::python::tools
