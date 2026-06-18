#include <rule_engine/client_protocol.hpp>
#include <rule_engine/pattern_fixture_provider.hpp>
#include <rule_engine/windows/pe_provider.hpp>
#include <rule_engine/windows/process_provider.hpp>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <exception>

namespace asio::detail {
    template<typename Exception> [[noreturn]] void throw_exception(const Exception &) { std::terminate(); }
} // namespace asio::detail

#include <asio/buffer.hpp>
#include <asio/connect.hpp>
#include <asio/detail/socket_types.hpp>
#include <asio/error.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/address.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/read.hpp>
#include <asio/write.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace {
    using asio::ip::tcp;

    constexpr std::uint32_t max_payload_size = 16u * 1024u * 1024u;
    constexpr std::chrono::milliseconds shutdown_poll_interval {10};
    constexpr std::string_view provider_request_cancelled_diagnostic {"provider request cancelled by listener shutdown"};

    [[nodiscard]] bool is_timeout_error(const asio::error_code &ec) noexcept {
        if (ec == asio::error::timed_out || ec == asio::error::would_block || ec == asio::error::try_again) {
            return true;
        }
#if defined(_WIN32)
        return ec.value() == WSAETIMEDOUT;
#else
        return false;
#endif
    }

    [[nodiscard]] rule_engine::ErrorSet asio_error(const std::string_view where, const asio::error_code &ec) {
        if (is_timeout_error(ec)) {
            return rule_engine::single_error(std::string {where}, "operation timed out");
        }
        return rule_engine::single_error(std::string {where}, ec.message());
    }

    [[nodiscard]] rule_engine::ErrorSet socket_option_error(const std::string_view where) {
#if defined(_WIN32)
        return rule_engine::single_error(std::string {where},
                                         "setsockopt failed: " + std::to_string(::WSAGetLastError()));
#else
        return rule_engine::single_error(std::string {where}, "setsockopt failed");
#endif
    }

    [[nodiscard]] std::expected<void, rule_engine::ErrorSet>
    set_socket_timeouts(tcp::socket &socket, const std::chrono::milliseconds timeout) {
#if defined(_WIN32)
        const auto clamped_timeout =
            std::clamp(timeout.count(), std::int64_t {1}, static_cast<std::int64_t>(std::numeric_limits<DWORD>::max()));
        const auto timeout_ms = static_cast<DWORD>(clamped_timeout);
        const auto *raw_timeout = reinterpret_cast<const char *>(std::addressof(timeout_ms));
        if (::setsockopt(socket.native_handle(), SOL_SOCKET, SO_RCVTIMEO, raw_timeout,
                         static_cast<int>(sizeof(timeout_ms))) != 0) {
            return std::unexpected(socket_option_error("protocol.receive_timeout"));
        }
        if (::setsockopt(socket.native_handle(), SOL_SOCKET, SO_SNDTIMEO, raw_timeout,
                         static_cast<int>(sizeof(timeout_ms))) != 0) {
            return std::unexpected(socket_option_error("protocol.send_timeout"));
        }
        return {};
#else
        static_cast<void>(socket);
        static_cast<void>(timeout);
        return {};
#endif
    }

    [[nodiscard]] std::expected<void, rule_engine::ErrorSet> write_payload(tcp::socket &socket,
                                                                           const std::span<const std::byte> payload) {
        auto frame = rule_engine::protocol::encode_frame(payload);
        if (!frame) {
            return std::unexpected(std::move(frame.error()));
        }

        asio::error_code ec;
        asio::write(socket, asio::buffer(frame->data(), frame->size()), ec);
        if (ec) {
            return std::unexpected(asio_error("protocol.write", ec));
        }
        return {};
    }

    [[nodiscard]] std::uint32_t decode_frame_size(const std::array<std::byte, 4u> &header) noexcept {
        return (static_cast<std::uint32_t>(header[0]) << 24u) | (static_cast<std::uint32_t>(header[1]) << 16u) |
               (static_cast<std::uint32_t>(header[2]) << 8u) | static_cast<std::uint32_t>(header[3]);
    }

    [[nodiscard]] std::expected<std::optional<std::vector<std::byte>>, rule_engine::ErrorSet>
    read_payload(tcp::socket &socket) {
        std::array<std::byte, 4u> header {};
        asio::error_code ec;
        const auto header_read = asio::read(socket, asio::buffer(header.data(), header.size()), ec);
        if (ec == asio::error::eof && header_read == 0u) {
            return std::optional<std::vector<std::byte>> {};
        }
        if (ec) {
            return std::unexpected(asio_error("protocol.read_header", ec));
        }

        const auto size = decode_frame_size(header);
        if (size > max_payload_size) {
            return std::unexpected(rule_engine::single_error("protocol", "frame payload exceeds v1 limit"));
        }

        std::vector<std::byte> payload(static_cast<std::size_t>(size));
        if (payload.empty()) {
            return std::optional<std::vector<std::byte>> {std::move(payload)};
        }

        asio::read(socket, asio::buffer(payload.data(), payload.size()), ec);
        if (ec) {
            return std::unexpected(asio_error("protocol.read_payload", ec));
        }
        return std::optional<std::vector<std::byte>> {std::move(payload)};
    }

    [[nodiscard]] rule_engine::Fact make_unavailable_fact(const rule_engine::protocol::FactKey &key,
                                                          const std::string_view diagnostic) {
        return rule_engine::Fact {
            .subject_id = key.subject_id,
            .key = key.key,
            .value = rule_engine::Value::undefined(),
            .status = rule_engine::FactStatus::unavailable,
            .diagnostic = std::string {diagnostic},
            .ttl = std::chrono::seconds {0},
        };
    }

    [[nodiscard]] rule_engine::protocol::FactBatchResponseMessage
    make_cancelled_fact_batch_response(const rule_engine::protocol::FactBatchRequestMessage &request) {
        rule_engine::protocol::FactBatchResponseMessage response;
        response.route = request.route;
        response.values.reserve(request.keys.size());
        for (const auto &key : request.keys) {
            response.values.push_back(make_unavailable_fact(key, provider_request_cancelled_diagnostic));
        }
        return response;
    }

    [[nodiscard]] rule_engine::protocol::CandidateProviderResponseMessage
    make_cancelled_candidate_provider_response(
        const rule_engine::protocol::CandidateProviderRequestMessage &request) {
        rule_engine::protocol::CandidateProviderResponseMessage response;
        response.route = request.route;
        response.results.reserve(request.filters.size());
        for (const auto &filter : request.filters) {
            response.results.push_back(rule_engine::protocol::CandidateProviderSubjectSet {
                .request_id = filter.request_id,
                .filter_key = filter.filter_key,
                .status = rule_engine::FactStatus::unavailable,
                .subject_ids = {},
                .diagnostic = std::string {provider_request_cancelled_diagnostic},
                .ttl = std::chrono::seconds {0},
            });
        }
        return response;
    }

    [[nodiscard]] std::vector<rule_engine::windows::ProcessFactKey>
    to_process_keys(const std::span<const rule_engine::protocol::FactKey> keys) {
        std::vector<rule_engine::windows::ProcessFactKey> out;
        out.reserve(keys.size());
        for (const auto &key : keys) {
            out.push_back(rule_engine::windows::ProcessFactKey {
                .subject_id = key.subject_id,
                .key = key.key,
            });
        }
        return out;
    }

    [[nodiscard]] const rule_engine::Fact *find_fact(const std::vector<rule_engine::Fact> &facts,
                                                     const rule_engine::protocol::FactKey &key) {
        const auto found = std::ranges::find_if(
            facts, [&](const auto &fact) { return fact.subject_id == key.subject_id && fact.key == key.key; });
        if (found == facts.end()) {
            return nullptr;
        }
        return std::addressof(*found);
    }

    void add_capability(std::vector<rule_engine::protocol::Capability> &capabilities,
                        rule_engine::protocol::Capability capability) {
        if (capability.route.empty()) {
            return;
        }
        const auto exists = std::ranges::any_of(capabilities, [&](const auto &existing) {
            return existing.route == capability.route && existing.filter_key == capability.filter_key &&
                   existing.argument_types == capability.argument_types &&
                   existing.result_kind == capability.result_kind;
        });
        if (exists) {
            return;
        }
        capabilities.push_back(std::move(capability));
    }

    [[nodiscard]] bool has_capability(const rule_engine::protocol::HandshakeMessage &handshake,
                                      const std::string_view route) {
        return std::ranges::any_of(handshake.capabilities,
                                   [&](const auto &capability) { return capability.route == route; });
    }

    [[nodiscard]] bool has_candidate_provider_capability(const rule_engine::protocol::HandshakeMessage &handshake,
                                                         const std::string_view route,
                                                         const std::string_view filter_key) {
        return std::ranges::any_of(handshake.capabilities, [&](const auto &capability) {
            return capability.route == route && capability.filter_key == filter_key &&
                   capability.result_kind == "subject_set";
        });
    }

    [[nodiscard]] std::string value_type_name(const rule_engine::ValueType type) {
        switch (type) {
            case rule_engine::ValueType::boolean: return "boolean";
            case rule_engine::ValueType::integer: return "integer";
            case rule_engine::ValueType::floating: return "floating";
            case rule_engine::ValueType::string: return "string";
            case rule_engine::ValueType::bytes: return "bytes";
            case rule_engine::ValueType::array: return "array";
            case rule_engine::ValueType::pattern: return "pattern";
            case rule_engine::ValueType::object: return "object";
            case rule_engine::ValueType::undefined: return "undefined";
            default: return "unknown";
        }
    }

    [[nodiscard]] bool value_matches_type(const rule_engine::Value &value, const rule_engine::ValueType type) {
        switch (type) {
            case rule_engine::ValueType::boolean: return value.as_bool().has_value();
            case rule_engine::ValueType::integer: return value.as_i64().has_value();
            case rule_engine::ValueType::floating: return value.as_f64().has_value();
            case rule_engine::ValueType::string: return value.as_string() != nullptr;
            case rule_engine::ValueType::bytes: return value.as_bytes() != nullptr;
            case rule_engine::ValueType::array: return value.as_array() != nullptr;
            case rule_engine::ValueType::pattern: return value.as_pattern() != nullptr;
            case rule_engine::ValueType::object: return value.as_object() != nullptr;
            case rule_engine::ValueType::undefined: return true;
            default: return false;
        }
    }

    [[nodiscard]] std::optional<rule_engine::ValueType>
    expected_type_for_fact(const rule_engine::protocol::FactBatchRequestMessage &request,
                           const rule_engine::protocol::FactKey &key) {
        if (request.expected_types.size() != request.keys.size()) {
            return std::nullopt;
        }
        for (std::size_t index = 0; index < request.keys.size(); ++index) {
            if (request.keys[index].subject_id == key.subject_id && request.keys[index].key == key.key) {
                return request.expected_types[index];
            }
        }
        return std::nullopt;
    }

    [[nodiscard]] std::optional<std::vector<std::byte>> read_binary_file(const std::filesystem::path &path) {
        std::ifstream file {path, std::ios::binary};
        if (!file) {
            return std::nullopt;
        }

        std::vector<std::byte> out;
        char ch {};
        while (file.get(ch)) { out.push_back(static_cast<std::byte>(static_cast<unsigned char>(ch))); }
        if (!file.eof()) {
            return std::nullopt;
        }
        return out;
    }

    constexpr std::string_view process_image_bytes_key {"process.image.bytes"};

    [[nodiscard]] bool requests_process_image_bytes(const std::span<const rule_engine::protocol::FactKey> keys) {
        return std::ranges::any_of(keys, [](const auto &key) { return key.key == process_image_bytes_key; });
    }

    void append_process_image_scan_spaces(rule_engine::patterns::PatternFixtureSet &fixtures,
                                          const std::span<const rule_engine::protocol::FactKey> keys,
                                          const std::span<const rule_engine::PatternScanPlan> scan_plans) {
        if (scan_plans.empty() && !requests_process_image_bytes(keys)) {
            return;
        }

        std::vector<std::string> seen_subjects;
        for (const auto &key : keys) {
            if (std::ranges::find(seen_subjects, key.subject_id) != seen_subjects.end()) {
                continue;
            }
            seen_subjects.push_back(key.subject_id);

            auto path = rule_engine::windows::resolve_process_image_path(key.subject_id);
            if (!path) {
                continue;
            }
            auto bytes = read_binary_file(*path);
            if (!bytes.has_value()) {
                continue;
            }
            fixtures.scan_spaces.push_back(rule_engine::patterns::PatternScanSpace {
                .subject_id = key.subject_id,
                .scan_space = "process.image.bytes",
                .permissions = "r--",
                .bytes = std::move(*bytes),
            });
        }
    }

    void append_process_image_section_scan_spaces(rule_engine::patterns::PatternFixtureSet &fixtures,
                                                  const std::span<const rule_engine::protocol::FactKey> keys,
                                                  const std::span<const rule_engine::PatternScanPlan> scan_plans) {
        if (!fixtures.scan_process_image_sections || scan_plans.empty()) {
            return;
        }

        std::vector<std::string> seen_subjects;
        for (const auto &key : keys) {
            if (std::ranges::find(seen_subjects, key.subject_id) != seen_subjects.end()) {
                continue;
            }
            seen_subjects.push_back(key.subject_id);

            auto path = rule_engine::windows::resolve_process_image_path(key.subject_id);
            if (!path) {
                continue;
            }
            auto spaces = rule_engine::windows::read_pe_image_section_scan_spaces(key.subject_id, *path);
            if (!spaces) {
                continue;
            }
            fixtures.scan_spaces.insert(fixtures.scan_spaces.end(), std::make_move_iterator(spaces->begin()),
                                        std::make_move_iterator(spaces->end()));
        }
    }

    void append_readable_memory_scan_spaces(rule_engine::patterns::PatternFixtureSet &fixtures,
                                            const std::span<const rule_engine::protocol::FactKey> keys,
                                            const std::span<const rule_engine::PatternScanPlan> scan_plans) {
        if (!fixtures.scan_readable_memory_regions || scan_plans.empty()) {
            return;
        }

        std::vector<std::string> seen_subjects;
        for (const auto &key : keys) {
            if (std::ranges::find(seen_subjects, key.subject_id) != seen_subjects.end()) {
                continue;
            }
            seen_subjects.push_back(key.subject_id);

            auto spaces = rule_engine::windows::read_process_readable_memory_scan_spaces(
                key.subject_id, scan_plans, fixtures.readable_memory_scopes);
            if (!spaces) {
                continue;
            }
            fixtures.scan_spaces.insert(fixtures.scan_spaces.end(), std::make_move_iterator(spaces->begin()),
                                        std::make_move_iterator(spaces->end()));
        }
    }

    [[nodiscard]] bool has_explicit_scan_space_config(const rule_engine::patterns::PatternFixtureSet &fixtures) {
        return !fixtures.scan_spaces.empty() || fixtures.scan_process_image_sections ||
               fixtures.scan_readable_memory_regions;
    }

    [[nodiscard]] std::vector<rule_engine::Fact>
    process_snapshot_response(const std::span<const rule_engine::protocol::FactKey> keys) {
        const auto process_keys = to_process_keys(keys);
        auto facts = rule_engine::windows::read_process_snapshot_facts(process_keys);
        if (!facts) {
            std::vector<rule_engine::Fact> out;
            out.reserve(keys.size());
            const auto diagnostic = facts.error().diagnostics.empty() ? std::string {"process provider failed"} :
                                                                        facts.error().diagnostics[0].message;
            for (const auto &key : keys) { out.push_back(make_unavailable_fact(key, diagnostic)); }
            return out;
        }
        return *facts;
    }

    [[nodiscard]] std::vector<rule_engine::Fact>
    process_handle_response(const std::span<const rule_engine::protocol::FactKey> keys) {
        const auto process_keys = to_process_keys(keys);
        auto facts = rule_engine::windows::read_process_handle_facts(process_keys);
        if (!facts) {
            std::vector<rule_engine::Fact> out;
            out.reserve(keys.size());
            const auto diagnostic = facts.error().diagnostics.empty() ? std::string {"process handle provider failed"} :
                                                                        facts.error().diagnostics[0].message;
            for (const auto &key : keys) { out.push_back(make_unavailable_fact(key, diagnostic)); }
            return out;
        }
        return *facts;
    }

    [[nodiscard]] std::vector<rule_engine::Fact>
    process_signer_response(const std::span<const rule_engine::protocol::FactKey> keys,
                            const std::chrono::milliseconds timeout) {
        const auto process_keys = to_process_keys(keys);
        auto facts = rule_engine::windows::read_process_signer_facts(process_keys, timeout);
        if (!facts) {
            std::vector<rule_engine::Fact> out;
            out.reserve(keys.size());
            const auto diagnostic = facts.error().diagnostics.empty() ? std::string {"process signer provider failed"} :
                                                                        facts.error().diagnostics[0].message;
            for (const auto &key : keys) { out.push_back(make_unavailable_fact(key, diagnostic)); }
            return out;
        }
        return *facts;
    }

    [[nodiscard]] bool is_pe_identity_fact_key(const std::string_view key) noexcept {
        return key == "pe.identity.path" || key == "pe.identity.file_id" || key == "pe.identity.file_size" ||
               key == "pe.identity.last_write_time" || key == "pe.identity.scan_space_name" ||
               key == "pe.identity.scan_space_version";
    }

    [[nodiscard]] std::vector<rule_engine::Fact>
    pe_response(const std::span<const rule_engine::protocol::FactKey> keys) {
        std::vector<rule_engine::Fact> out;
        out.reserve(keys.size());

        std::unordered_map<std::string, bool> subject_needs_full_pe;
        for (const auto &key : keys) {
            auto found = subject_needs_full_pe.try_emplace(key.subject_id, false);
            if (!is_pe_identity_fact_key(key.key)) {
                found.first->second = true;
            }
        }

        std::unordered_map<std::string, std::vector<rule_engine::Fact>> pe_facts_by_subject;
        for (const auto &key : keys) {
            if (!pe_facts_by_subject.contains(key.subject_id)) {
                auto path = rule_engine::windows::resolve_process_image_path(key.subject_id);
                if (!path) {
                    const auto diagnostic = path.error().diagnostics.empty() ?
                                                std::string {"failed to resolve PE image"} :
                                                path.error().diagnostics[0].message;
                    pe_facts_by_subject.emplace(
                        key.subject_id, std::vector<rule_engine::Fact> {make_unavailable_fact(key, diagnostic)});
                    continue;
                }

                const auto needs_full_pe = subject_needs_full_pe.find(key.subject_id);
                auto facts = needs_full_pe != subject_needs_full_pe.end() && needs_full_pe->second
                                 ? rule_engine::windows::read_pe_image_facts(key.subject_id, *path)
                                 : rule_engine::windows::read_pe_image_identity_facts(key.subject_id, *path);
                if (!facts) {
                    const auto diagnostic = facts.error().diagnostics.empty() ? std::string {"PE provider failed"} :
                                                                                facts.error().diagnostics[0].message;
                    pe_facts_by_subject.emplace(
                        key.subject_id, std::vector<rule_engine::Fact> {make_unavailable_fact(key, diagnostic)});
                    continue;
                }
                pe_facts_by_subject.emplace(key.subject_id, std::move(*facts));
            }

            const auto found_subject = pe_facts_by_subject.find(key.subject_id);
            if (found_subject == pe_facts_by_subject.end()) {
                out.push_back(make_unavailable_fact(key, "PE provider failed"));
                continue;
            }

            const auto *fact = find_fact(found_subject->second, key);
            if (fact == nullptr) {
                out.push_back(make_unavailable_fact(key, "unsupported PE fact"));
                continue;
            }
            out.push_back(*fact);
        }

        return out;
    }

    [[nodiscard]] rule_engine::protocol::FactBatchResponseMessage
    handle_client_fact_batch_with_fixtures(const rule_engine::protocol::FactBatchRequestMessage &request,
                                           const rule_engine::patterns::PatternFixtureSet &pattern_fixtures,
                                           const rule_engine::client_protocol::ExtraFactBatchHandler &extra_handler,
                                           const rule_engine::client_protocol::ExtraFactBatchHandlerWithContext
                                               &extra_handler_with_context,
                                           const rule_engine::client_protocol::ProviderRequestContext &context) {
        rule_engine::protocol::FactBatchResponseMessage response;
        response.route = request.route;
        if (request.route == "endpoint.process.snapshot") {
            response.values = process_snapshot_response(request.keys);
            return response;
        }
        if (request.route == "endpoint.process.handles") {
            response.values = process_handle_response(request.keys);
            return response;
        }
        if (request.route == "endpoint.process.signer") {
            response.values = process_signer_response(request.keys, request.timeout);
            return response;
        }
        if (request.route == "endpoint.process.image.pe") {
            response.values = pe_response(request.keys);
            return response;
        }
        if (request.route == "endpoint.scan.patterns") {
            auto effective_fixtures = pattern_fixtures;
            append_process_image_section_scan_spaces(effective_fixtures, request.keys, request.scan_plans);
            append_readable_memory_scan_spaces(effective_fixtures, request.keys, request.scan_plans);
            if (requests_process_image_bytes(request.keys) || !has_explicit_scan_space_config(pattern_fixtures)) {
                append_process_image_scan_spaces(effective_fixtures, request.keys, request.scan_plans);
            }
            response.values =
                rule_engine::patterns::read_fixture_pattern_facts(request.keys, effective_fixtures, request.scan_plans);
            return response;
        }
        if (extra_handler_with_context) {
            auto custom_response = extra_handler_with_context(request, context);
            if (custom_response.has_value()) {
                if (custom_response->route.empty()) {
                    custom_response->route = request.route;
                }
                return *custom_response;
            }
        }
        if (extra_handler) {
            auto custom_response = extra_handler(request);
            if (custom_response.has_value()) {
                if (custom_response->route.empty()) {
                    custom_response->route = request.route;
                }
                return *custom_response;
            }
        }

        response.values.reserve(request.keys.size());
        for (const auto &key : request.keys) {
            response.values.push_back(make_unavailable_fact(key, "unsupported provider route"));
        }
        return response;
    }

    [[nodiscard]] rule_engine::protocol::CandidateProviderResponseMessage handle_client_candidate_provider_request(
        const rule_engine::protocol::CandidateProviderRequestMessage &request,
        const rule_engine::client_protocol::ExtraCandidateProviderHandler &extra_handler,
        const rule_engine::client_protocol::ExtraCandidateProviderHandlerWithContext &extra_handler_with_context,
        const rule_engine::client_protocol::ProviderRequestContext &context) {
        if (extra_handler_with_context) {
            auto custom_response = extra_handler_with_context(request, context);
            if (custom_response.has_value()) {
                if (custom_response->route.empty()) {
                    custom_response->route = request.route;
                }
                return *custom_response;
            }
        }
        if (extra_handler) {
            auto custom_response = extra_handler(request);
            if (custom_response.has_value()) {
                if (custom_response->route.empty()) {
                    custom_response->route = request.route;
                }
                return *custom_response;
            }
        }

        rule_engine::protocol::CandidateProviderResponseMessage response;
        response.route = request.route;
        response.results.reserve(request.filters.size());
        for (const auto &filter : request.filters) {
            response.results.push_back(rule_engine::protocol::CandidateProviderSubjectSet {
                .request_id = filter.request_id,
                .filter_key = filter.filter_key,
                .status = rule_engine::FactStatus::unavailable,
                .subject_ids = {},
                .diagnostic = "unsupported candidate provider route",
                .ttl = std::chrono::seconds {0},
            });
        }
        return response;
    }

    [[nodiscard]] std::expected<void, rule_engine::ErrorSet>
    send_handshake_and_subjects(tcp::socket &socket,
                                const std::span<const rule_engine::protocol::Capability> extra_capabilities) {
        auto handshake =
            rule_engine::protocol::encode_handshake(rule_engine::client_protocol::client_handshake(extra_capabilities));
        if (!handshake) {
            return std::unexpected(std::move(handshake.error()));
        }
        if (auto result = write_payload(socket, *handshake); !result) {
            return result;
        }

        auto subjects = rule_engine::client_protocol::enumerate_client_subjects();
        if (!subjects) {
            return std::unexpected(std::move(subjects.error()));
        }
        auto encoded_subjects = rule_engine::protocol::encode_subject_list(*subjects);
        if (!encoded_subjects) {
            return std::unexpected(std::move(encoded_subjects.error()));
        }
        return write_payload(socket, *encoded_subjects);
    }

    [[nodiscard]] std::expected<void, rule_engine::ErrorSet>
    connect_socket(tcp::socket &socket, const rule_engine::client_protocol::ClientConnectionOptions &options) {
        asio::error_code ec;
        const auto address = asio::ip::make_address(options.host, ec);
        if (ec) {
            return std::unexpected(asio_error("client.connect.host", ec));
        }

        socket.connect(tcp::endpoint {address, options.port}, ec);
        if (ec) {
            return std::unexpected(asio_error("client.connect.connect", ec));
        }
        return set_socket_timeouts(socket, options.io_timeout);
    }

    struct ClientPreamble {
        rule_engine::protocol::HandshakeMessage handshake;
        rule_engine::protocol::SubjectListMessage subjects;
    };

    [[nodiscard]] std::expected<ClientPreamble, rule_engine::ErrorSet> read_client_preamble(tcp::socket &socket) {
        auto handshake_payload = read_payload(socket);
        if (!handshake_payload || !handshake_payload->has_value()) {
            return std::unexpected(handshake_payload ?
                                       rule_engine::single_error("client.connect", "missing handshake") :
                                       std::move(handshake_payload.error()));
        }
        auto handshake = rule_engine::protocol::decode_handshake(**handshake_payload);
        if (!handshake) {
            return std::unexpected(std::move(handshake.error()));
        }

        auto subject_payload = read_payload(socket);
        if (!subject_payload || !subject_payload->has_value()) {
            return std::unexpected(subject_payload ?
                                       rule_engine::single_error("client.connect", "missing subject list") :
                                       std::move(subject_payload.error()));
        }
        auto subjects = rule_engine::protocol::decode_subject_list(**subject_payload);
        if (!subjects) {
            return std::unexpected(std::move(subjects.error()));
        }

        return ClientPreamble {
            .handshake = std::move(*handshake),
            .subjects = std::move(*subjects),
        };
    }

    [[nodiscard]] std::expected<void, rule_engine::ErrorSet>
    validate_fact_response(const rule_engine::protocol::FactBatchRequestMessage &request,
                           const rule_engine::protocol::FactBatchResponseMessage &response);
    [[nodiscard]] std::expected<void, rule_engine::ErrorSet>
    validate_candidate_provider_response(const rule_engine::protocol::CandidateProviderRequestMessage &request,
                                         const rule_engine::protocol::CandidateProviderResponseMessage &response);

    [[nodiscard]] std::expected<rule_engine::protocol::FactBatchResponseMessage, rule_engine::ErrorSet>
    send_request_and_read_response(tcp::socket &socket, const rule_engine::protocol::FactBatchRequestMessage &request) {
        if (auto result = set_socket_timeouts(socket, request.timeout); !result) {
            return std::unexpected(std::move(result.error()));
        }

        auto encoded_request = rule_engine::protocol::encode_fact_batch_request(request);
        if (!encoded_request) {
            return std::unexpected(std::move(encoded_request.error()));
        }
        if (auto result = write_payload(socket, *encoded_request); !result) {
            return std::unexpected(std::move(result.error()));
        }

        auto response_payload = read_payload(socket);
        if (!response_payload || !response_payload->has_value()) {
            return std::unexpected(response_payload ?
                                       rule_engine::single_error("client.connect", "missing fact response") :
                                       std::move(response_payload.error()));
        }
        auto response = rule_engine::protocol::decode_fact_batch_response(**response_payload);
        if (!response) {
            return std::unexpected(std::move(response.error()));
        }
        if (auto valid = validate_fact_response(request, *response); !valid) {
            return std::unexpected(std::move(valid.error()));
        }
        return *response;
    }

    [[nodiscard]] std::expected<rule_engine::protocol::CandidateProviderResponseMessage, rule_engine::ErrorSet>
    send_request_and_read_response(tcp::socket &socket,
                                   const rule_engine::protocol::CandidateProviderRequestMessage &request) {
        if (auto result = set_socket_timeouts(socket, request.timeout); !result) {
            return std::unexpected(std::move(result.error()));
        }

        auto encoded_request = rule_engine::protocol::encode_candidate_provider_request(request);
        if (!encoded_request) {
            return std::unexpected(std::move(encoded_request.error()));
        }
        if (auto result = write_payload(socket, *encoded_request); !result) {
            return std::unexpected(std::move(result.error()));
        }

        auto response_payload = read_payload(socket);
        if (!response_payload || !response_payload->has_value()) {
            return std::unexpected(
                response_payload ? rule_engine::single_error("client.connect", "missing candidate provider response") :
                                   std::move(response_payload.error()));
        }
        auto response = rule_engine::protocol::decode_candidate_provider_response(**response_payload);
        if (!response) {
            return std::unexpected(std::move(response.error()));
        }
        if (auto valid = validate_candidate_provider_response(request, *response); !valid) {
            return std::unexpected(std::move(valid.error()));
        }
        return *response;
    }

    void close_socket(tcp::socket &socket) {
        asio::error_code ec;
        socket.shutdown(tcp::socket::shutdown_both, ec);
        socket.close(ec);
    }

    [[nodiscard]] std::expected<void, rule_engine::ErrorSet>
    serve_connected_client(tcp::socket socket, const rule_engine::client_protocol::ClientListenOptions &options,
                           const rule_engine::patterns::PatternFixtureSet &pattern_fixtures) {
        const rule_engine::client_protocol::ProviderRequestContext request_context {
            .stop_token = options.stop_token,
        };

        if (auto result = set_socket_timeouts(socket, options.io_timeout); !result) {
            return result;
        }
        if (options.stop_token.stop_requested()) {
            close_socket(socket);
            return {};
        }

        if (auto result = send_handshake_and_subjects(socket, options.extra_capabilities); !result) {
            return result;
        }

        for (;;) {
            if (options.stop_token.stop_requested()) {
                break;
            }

            auto payload = read_payload(socket);
            if (!payload) {
                return std::unexpected(std::move(payload.error()));
            }
            if (!payload->has_value()) {
                break;
            }

            auto request = rule_engine::protocol::decode_fact_batch_request(**payload);
            if (request) {
                auto response = rule_engine::protocol::encode_fact_batch_response(
                    options.stop_token.stop_requested() ?
                        make_cancelled_fact_batch_response(*request) :
                        handle_client_fact_batch_with_fixtures(*request,
                                                               pattern_fixtures,
                                                               options.extra_fact_handler,
                                                               options.extra_fact_handler_with_context,
                                                               request_context));
                if (!response) {
                    return std::unexpected(std::move(response.error()));
                }
                if (auto result = write_payload(socket, *response); !result) {
                    return result;
                }
                if (options.stop_token.stop_requested()) {
                    break;
                }
                continue;
            }

            auto candidate_request = rule_engine::protocol::decode_candidate_provider_request(**payload);
            if (!candidate_request) {
                return std::unexpected(std::move(request.error()));
            }
            auto candidate_response = rule_engine::protocol::encode_candidate_provider_response(
                options.stop_token.stop_requested() ?
                    make_cancelled_candidate_provider_response(*candidate_request) :
                    handle_client_candidate_provider_request(*candidate_request,
                                                             options.extra_candidate_provider_handler,
                                                             options.extra_candidate_provider_handler_with_context,
                                                             request_context));
            if (!candidate_response) {
                return std::unexpected(std::move(candidate_response.error()));
            }
            if (auto result = write_payload(socket, *candidate_response); !result) {
                return result;
            }
            if (options.stop_token.stop_requested()) {
                break;
            }
        }
        close_socket(socket);
        return {};
    }

    void capture_first_session_error(std::optional<rule_engine::ErrorSet> &first_error, std::mutex &error_mutex,
                                     rule_engine::ErrorSet error) {
        const std::lock_guard lock {error_mutex};
        if (!first_error.has_value()) {
            first_error = std::move(error);
        }
    }

    [[nodiscard]] bool same_fact_key(const rule_engine::protocol::FactKey &lhs,
                                     const rule_engine::protocol::FactKey &rhs) noexcept {
        return lhs.subject_id == rhs.subject_id && lhs.key == rhs.key;
    }

    [[nodiscard]] bool contains_fact_key(const std::vector<rule_engine::protocol::FactKey> &keys,
                                         const rule_engine::protocol::FactKey &key) {
        return std::ranges::any_of(keys, [&](const auto &existing) { return same_fact_key(existing, key); });
    }

    [[nodiscard]] std::expected<void, rule_engine::ErrorSet>
    validate_request_capability(const rule_engine::protocol::HandshakeMessage &handshake,
                                const rule_engine::protocol::FactBatchRequestMessage &request) {
        if (has_capability(handshake, request.route)) {
            return {};
        }
        return std::unexpected(
            rule_engine::single_error("client.evaluator", "client does not advertise provider route " + request.route));
    }

    [[nodiscard]] std::expected<void, rule_engine::ErrorSet>
    validate_request_capability(const rule_engine::protocol::HandshakeMessage &handshake,
                                const rule_engine::protocol::CandidateProviderRequestMessage &request) {
        for (const auto &filter : request.filters) {
            if (has_candidate_provider_capability(handshake, request.route, filter.filter_key)) {
                continue;
            }
            return std::unexpected(
                rule_engine::single_error("client.evaluator", "client does not advertise candidate provider filter " +
                                                                  request.route + "/" + filter.filter_key));
        }
        return {};
    }

    [[nodiscard]] std::expected<void, rule_engine::ErrorSet>
    validate_program_capabilities(const rule_engine::protocol::HandshakeMessage &handshake,
                                  const rule_engine::VerifiedProgram &program) {
        for (const auto &route : rule_engine::required_provider_routes(program)) {
            if (has_capability(handshake, route)) {
                continue;
            }
            return std::unexpected(rule_engine::single_error(
                "client.evaluator", "client does not advertise required provider route " + route));
        }
        return {};
    }

    [[nodiscard]] std::expected<void, rule_engine::ErrorSet>
    validate_fact_response(const rule_engine::protocol::FactBatchRequestMessage &request,
                           const rule_engine::protocol::FactBatchResponseMessage &response) {
        if (response.route != request.route) {
            return std::unexpected(rule_engine::single_error("client.evaluator", "provider response route mismatch"));
        }

        std::vector<rule_engine::protocol::FactKey> seen;
        seen.reserve(response.values.size());
        for (const auto &fact : response.values) {
            rule_engine::protocol::FactKey key {
                .subject_id = fact.subject_id,
                .key = fact.key,
            };
            if (!contains_fact_key(request.keys, key)) {
                return std::unexpected(
                    rule_engine::single_error("client.evaluator", "provider returned unrequested fact " + fact.key));
            }
            if (contains_fact_key(seen, key)) {
                return std::unexpected(
                    rule_engine::single_error("client.evaluator", "provider returned duplicate fact " + fact.key));
            }
            const auto expected_type = expected_type_for_fact(request, key);
            if (expected_type.has_value() && *expected_type != rule_engine::ValueType::undefined &&
                fact.status == rule_engine::FactStatus::available && !value_matches_type(fact.value, *expected_type)) {
                return std::unexpected(rule_engine::single_error(
                    "client.evaluator", "provider returned fact " + fact.key + " with wrong type; expected " +
                                            value_type_name(*expected_type)));
            }
            seen.push_back(std::move(key));
        }

        for (const auto &key : request.keys) {
            if (!contains_fact_key(seen, key)) {
                return std::unexpected(rule_engine::single_error(
                    "client.evaluator", "provider response omitted requested fact " + key.key));
            }
        }
        return {};
    }

    [[nodiscard]] bool
    same_candidate_provider_filter(const rule_engine::protocol::CandidateProviderFilterRequest &lhs,
                                   const rule_engine::protocol::CandidateProviderSubjectSet &rhs) noexcept {
        return lhs.request_id == rhs.request_id && lhs.filter_key == rhs.filter_key;
    }

    [[nodiscard]] bool
    contains_candidate_provider_result(const std::vector<rule_engine::protocol::CandidateProviderSubjectSet> &results,
                                       const rule_engine::protocol::CandidateProviderFilterRequest &filter) {
        return std::ranges::any_of(results,
                                   [&](const auto &result) { return same_candidate_provider_filter(filter, result); });
    }

    [[nodiscard]] std::expected<void, rule_engine::ErrorSet>
    validate_candidate_provider_response(const rule_engine::protocol::CandidateProviderRequestMessage &request,
                                         const rule_engine::protocol::CandidateProviderResponseMessage &response) {
        if (response.route != request.route) {
            return std::unexpected(
                rule_engine::single_error("client.evaluator", "candidate provider response route mismatch"));
        }

        std::vector<rule_engine::protocol::CandidateProviderSubjectSet> seen;
        seen.reserve(response.results.size());
        for (const auto &result : response.results) {
            const auto matching_filter = std::ranges::find_if(
                request.filters, [&](const auto &filter) { return same_candidate_provider_filter(filter, result); });
            if (matching_filter == request.filters.end()) {
                return std::unexpected(rule_engine::single_error(
                    "client.evaluator", "candidate provider returned unrequested filter " + result.filter_key));
            }
            const auto duplicate = std::ranges::any_of(seen, [&](const auto &existing) {
                return existing.request_id == result.request_id && existing.filter_key == result.filter_key;
            });
            if (duplicate) {
                return std::unexpected(rule_engine::single_error(
                    "client.evaluator", "candidate provider returned duplicate filter " + result.filter_key));
            }
            seen.push_back(result);
        }

        for (const auto &filter : request.filters) {
            if (!contains_candidate_provider_result(seen, filter)) {
                return std::unexpected(rule_engine::single_error(
                    "client.evaluator", "candidate provider omitted requested filter " + filter.filter_key));
            }
        }
        return {};
    }

    struct ProviderFactRequestMetadata {
        std::string subject_id;
        std::string key;
        rule_engine::ProviderRetryPolicy retry_policy {rule_engine::ProviderRetryPolicy::none};
        std::uint8_t retry_budget {};
        std::string cancellation_diagnostic;
    };

    struct PlannedFactRequest {
        rule_engine::protocol::FactBatchRequestMessage message;
        std::vector<ProviderFactRequestMetadata> metadata;
    };

    [[nodiscard]] std::string provider_fact_attempt_key(const std::string_view subject_id,
                                                        const std::string_view key) {
        std::string out;
        out.reserve(subject_id.size() + key.size() + 1u);
        out.append(subject_id);
        out.push_back('\0');
        out.append(key);
        return out;
    }

    [[nodiscard]] ProviderFactRequestMetadata fact_request_metadata(
        const rule_engine::Subject &subject, const rule_engine::FactRequestBatch &batch, const std::size_t index) {
        return ProviderFactRequestMetadata {
            .subject_id = subject.id,
            .key = index < batch.keys.size() ? batch.keys[index] : std::string {},
            .retry_policy = index < batch.retry_policies.size() ? batch.retry_policies[index] :
                                                                  rule_engine::ProviderRetryPolicy::none,
            .retry_budget = index < batch.retry_budgets.size() ? batch.retry_budgets[index] :
                                                                  static_cast<std::uint8_t>(0u),
            .cancellation_diagnostic = index < batch.cancellation_diagnostics.size() ?
                                           batch.cancellation_diagnostics[index] :
                                           std::string {},
        };
    }

    void add_fact_request(std::vector<PlannedFactRequest> &requests, const rule_engine::Subject &subject,
                          const rule_engine::FactRequestBatch &batch) {
        auto found =
            std::ranges::find_if(requests, [&](const auto &request) { return request.message.route == batch.route; });
        if (found == requests.end()) {
            PlannedFactRequest request;
            request.message.route = batch.route;
            request.message.timeout = std::chrono::duration_cast<std::chrono::milliseconds>(batch.timeout);
            requests.push_back(std::move(request));
            found = std::prev(requests.end());
        }

        const auto timeout = std::chrono::duration_cast<std::chrono::milliseconds>(batch.timeout);
        if (found->message.timeout < timeout) {
            found->message.timeout = timeout;
        }
        for (std::size_t index = 0; index < batch.keys.size(); ++index) {
            const auto &key = batch.keys[index];
            rule_engine::protocol::FactKey fact_key {
                .subject_id = subject.id,
                .key = key,
            };
            if (!contains_fact_key(found->message.keys, fact_key)) {
                found->message.keys.push_back(std::move(fact_key));
                const auto type = index < batch.types.size() ? batch.types[index] : rule_engine::ValueType::undefined;
                found->message.expected_types.push_back(type);
                found->metadata.push_back(fact_request_metadata(subject, batch, index));
            }
        }
        for (const auto &scan_plan : batch.scan_plans) {
            const auto exists = std::ranges::any_of(found->message.scan_plans, [&](const auto &existing) {
                return existing.pattern_key == scan_plan.pattern_key;
            });
            if (!exists) {
                found->message.scan_plans.push_back(scan_plan);
            }
        }
    }

    struct SubjectEvaluationState {
        rule_engine::Subject subject;
        rule_engine::FactCache facts;
        std::optional<rule_engine::EvaluationStep> final_step;
    };

    struct OptimizedSubjectEvaluationState {
        rule_engine::Subject subject;
        rule_engine::FactCache facts;
        std::vector<std::string> exact_vm_rule_identifiers;
        std::optional<rule_engine::EvaluationStep> final_step;
    };

    void record_vm_queue_pressure(rule_engine::client_protocol::ClientEvaluationOptions &options,
                                  const std::size_t pending_subjects) {
        if (options.instrumentation == nullptr) {
            return;
        }

        options.instrumentation->peak_pending_vm_subjects =
            std::max(options.instrumentation->peak_pending_vm_subjects, static_cast<std::uint64_t>(pending_subjects));
        if (options.vm_backpressure_subject_threshold != 0u &&
            pending_subjects > options.vm_backpressure_subject_threshold) {
            ++options.instrumentation->vm_backpressure_events;
        }
    }

    void record_provider_queue_pressure(rule_engine::client_protocol::ClientEvaluationOptions &options,
                                        const std::size_t pending_requests) {
        if (options.instrumentation == nullptr) {
            return;
        }

        options.instrumentation->peak_pending_provider_requests = std::max(
            options.instrumentation->peak_pending_provider_requests, static_cast<std::uint64_t>(pending_requests));
        if (options.provider_backpressure_request_threshold != 0u &&
            pending_requests > options.provider_backpressure_request_threshold) {
            ++options.instrumentation->provider_backpressure_events;
        }
    }

    [[nodiscard]] std::size_t
    pending_exact_vm_subjects(const std::vector<OptimizedSubjectEvaluationState> &states) noexcept {
        return static_cast<std::size_t>(
            std::ranges::count_if(states, [](const auto &state) { return !state.exact_vm_rule_identifiers.empty(); }));
    }

    void store_fact_for_matching_subjects(std::vector<SubjectEvaluationState> &states, const rule_engine::Fact &fact) {
        for (auto &state : states) {
            if (state.subject.id == fact.subject_id) {
                state.facts.store(fact);
            }
        }
    }

    void store_fact_for_matching_subjects(std::vector<OptimizedSubjectEvaluationState> &states,
                                          const rule_engine::Fact &fact) {
        for (auto &state : states) {
            if (state.subject.id == fact.subject_id) {
                state.facts.store(fact);
            }
        }
    }

    [[nodiscard]] const ProviderFactRequestMetadata *
    find_metadata_for_fact(const PlannedFactRequest &request, const rule_engine::Fact &fact) {
        const auto found = std::ranges::find_if(request.metadata, [&](const auto &metadata) {
            return metadata.subject_id == fact.subject_id && metadata.key == fact.key;
        });
        if (found == request.metadata.end()) {
            return nullptr;
        }
        return std::addressof(*found);
    }

    [[nodiscard]] bool retryable_provider_fact(const ProviderFactRequestMetadata &metadata,
                                               const rule_engine::Fact &fact,
                                               std::unordered_map<std::string, std::uint8_t> &retry_attempts) {
        if (metadata.retry_policy != rule_engine::ProviderRetryPolicy::timed_out ||
            fact.status != rule_engine::FactStatus::timed_out || metadata.retry_budget == 0u) {
            return false;
        }

        const auto attempt_key = provider_fact_attempt_key(metadata.subject_id, metadata.key);
        const auto attempts = retry_attempts[attempt_key];
        if (attempts >= metadata.retry_budget) {
            return false;
        }
        retry_attempts[attempt_key] = static_cast<std::uint8_t>(attempts + 1u);
        return true;
    }

    [[nodiscard]] rule_engine::Fact cancellation_fact_for_metadata(const ProviderFactRequestMetadata &metadata) {
        const auto diagnostic = metadata.cancellation_diagnostic.empty() ?
                                    std::string {"provider request cancelled by evaluator shutdown"} :
                                    metadata.cancellation_diagnostic;
        return rule_engine::Fact {
            .subject_id = metadata.subject_id,
            .key = metadata.key,
            .value = rule_engine::Value::undefined(),
            .status = rule_engine::FactStatus::unavailable,
            .diagnostic = diagnostic,
            .ttl = std::chrono::seconds {0},
        };
    }

    template<typename States>
    void store_cancellation_facts(States &states, const std::vector<PlannedFactRequest> &requests) {
        for (const auto &request : requests) {
            for (const auto &metadata : request.metadata) {
                store_fact_for_matching_subjects(states, cancellation_fact_for_metadata(metadata));
            }
        }
    }

    template<typename States>
    void store_response_facts_with_retry(States &states, const PlannedFactRequest &request,
                                         const rule_engine::protocol::FactBatchResponseMessage &response,
                                         std::unordered_map<std::string, std::uint8_t> &retry_attempts) {
        for (const auto &fact : response.values) {
            const auto *metadata = find_metadata_for_fact(request, fact);
            if (metadata != nullptr && retryable_provider_fact(*metadata, fact, retry_attempts)) {
                continue;
            }
            store_fact_for_matching_subjects(states, fact);
        }
    }

    [[nodiscard]] bool
    same_static_fact_cache_candidate(const rule_engine::optimizer::StaticFactCacheCandidate &lhs,
                                     const rule_engine::optimizer::StaticFactCacheCandidate &rhs) noexcept {
        return lhs.route == rhs.route && lhs.subject_id == rhs.subject_id && lhs.key == rhs.key;
    }

    void append_static_fact_cache_candidate(std::vector<rule_engine::optimizer::StaticFactCacheCandidate> &candidates,
                                            rule_engine::optimizer::StaticFactCacheCandidate candidate) {
        const auto duplicate = std::ranges::any_of(
            candidates, [&](const auto &existing) { return same_static_fact_cache_candidate(existing, candidate); });
        if (duplicate) {
            return;
        }
        candidates.push_back(std::move(candidate));
    }

    struct StaticFactIdentityRequestKey {
        std::string key;
        rule_engine::ValueType type {rule_engine::ValueType::undefined};
    };

    void append_static_fact_identity_request_key(std::vector<StaticFactIdentityRequestKey> &keys, std::string key,
                                                 const rule_engine::ValueType type) {
        if (key.empty()) {
            return;
        }
        const auto duplicate = std::ranges::any_of(keys, [&](const auto &existing) { return existing.key == key; });
        if (duplicate) {
            return;
        }
        keys.push_back(StaticFactIdentityRequestKey {
            .key = std::move(key),
            .type = type,
        });
    }

    [[nodiscard]] std::vector<StaticFactIdentityRequestKey>
    static_fact_identity_request_keys(const rule_engine::optimizer::StaticFactIdentityFactKeys &keys) {
        std::vector<StaticFactIdentityRequestKey> out;
        out.reserve(8u);
        append_static_fact_identity_request_key(out, keys.path, rule_engine::ValueType::string);
        append_static_fact_identity_request_key(out, keys.file_id, rule_engine::ValueType::string);
        append_static_fact_identity_request_key(out, keys.file_size, rule_engine::ValueType::integer);
        append_static_fact_identity_request_key(out, keys.last_write_time, rule_engine::ValueType::integer);
        append_static_fact_identity_request_key(out, keys.content_hash, rule_engine::ValueType::string);
        append_static_fact_identity_request_key(out, keys.signature_identity, rule_engine::ValueType::string);
        append_static_fact_identity_request_key(out, keys.scan_space_name, rule_engine::ValueType::string);
        append_static_fact_identity_request_key(out, keys.scan_space_version, rule_engine::ValueType::string);
        return out;
    }

    [[nodiscard]] rule_engine::protocol::FactBatchRequestMessage static_fact_identity_request(
        const std::string &route, const rule_engine::optimizer::StaticFactIdentityFactKeys &identity_keys,
        const std::span<const rule_engine::Subject> subjects, const std::chrono::milliseconds timeout) {
        rule_engine::protocol::FactBatchRequestMessage request;
        request.route = route;
        request.timeout = timeout;

        const auto keys = static_fact_identity_request_keys(identity_keys);
        request.keys.reserve(subjects.size() * keys.size());
        request.expected_types.reserve(subjects.size() * keys.size());
        for (const auto &subject : subjects) {
            for (const auto &key : keys) {
                request.keys.push_back(rule_engine::protocol::FactKey {
                    .subject_id = subject.id,
                    .key = key.key,
                });
                request.expected_types.push_back(key.type);
            }
        }
        return request;
    }

    [[nodiscard]] std::expected<std::optional<rule_engine::FactCache>, rule_engine::ErrorSet>
    prefetch_static_fact_identity_facts(tcp::socket &socket, const rule_engine::protocol::HandshakeMessage &handshake,
                                        rule_engine::client_protocol::ClientEvaluationOptions &options,
                                        const std::span<const rule_engine::Subject> subjects,
                                        const std::chrono::milliseconds timeout) {
        if (options.static_fact_identity_route.empty() || !options.static_fact_identity_fact_keys.has_value()) {
            return std::optional<rule_engine::FactCache> {};
        }

        auto request = static_fact_identity_request(options.static_fact_identity_route,
                                                    *options.static_fact_identity_fact_keys, subjects, timeout);
        if (request.keys.empty()) {
            return std::optional<rule_engine::FactCache> {};
        }
        if (auto valid = validate_request_capability(handshake, request); !valid) {
            return std::unexpected(std::move(valid.error()));
        }

        record_provider_queue_pressure(options, 1u);
        if (options.instrumentation != nullptr) {
            ++options.instrumentation->provider_rounds;
            ++options.instrumentation->provider_requests;
            options.instrumentation->provider_fact_keys_requested += request.keys.size();
        }

        const auto request_started = std::chrono::steady_clock::now();
        auto response = send_request_and_read_response(socket, request);
        if (options.instrumentation != nullptr) {
            const auto elapsed = std::chrono::steady_clock::now() - request_started;
            options.instrumentation->provider_elapsed_us +=
                static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count());
        }
        if (!response) {
            return std::unexpected(std::move(response.error()));
        }
        if (options.instrumentation != nullptr) {
            options.instrumentation->provider_facts_returned += response->values.size();
        }

        rule_engine::FactCache facts;
        for (auto &fact : response->values) { facts.store(std::move(fact)); }
        return std::optional<rule_engine::FactCache> {std::move(facts)};
    }

    void append_static_fact_cache_candidates_from_identity_facts(
        rule_engine::client_protocol::ClientEvaluationOptions &options,
        const rule_engine::optimizer::OptimizerPlan &plan, const std::span<const rule_engine::Subject> subjects) {
        if (options.static_fact_cache == nullptr || options.static_fact_identity_facts == nullptr ||
            !options.static_fact_identity_fact_keys.has_value()) {
            return;
        }

        auto derived = rule_engine::optimizer::derive_static_fact_cache_candidates(
            plan.provider_requirements, subjects, *options.static_fact_identity_facts,
            *options.static_fact_identity_fact_keys);
        for (auto &candidate : derived) {
            append_static_fact_cache_candidate(options.static_fact_cache_candidates, std::move(candidate));
        }
    }

    [[nodiscard]] const rule_engine::optimizer::StaticFactCacheCandidate *
    find_static_fact_cache_candidate(const rule_engine::client_protocol::ClientEvaluationOptions &options,
                                     const std::string_view route, const rule_engine::protocol::FactKey &key) {
        const auto found = std::ranges::find_if(options.static_fact_cache_candidates, [&](const auto &candidate) {
            return candidate.route == route && candidate.subject_id == key.subject_id && candidate.key == key.key;
        });
        if (found == options.static_fact_cache_candidates.end()) {
            return nullptr;
        }
        return std::addressof(*found);
    }

    void record_static_fact_cache_lookup(rule_engine::client_protocol::ClientEvaluationOptions &options,
                                         const rule_engine::optimizer::StaticFactCacheLookupStatus status) {
        if (options.instrumentation == nullptr) {
            return;
        }
        switch (status) {
            case rule_engine::optimizer::StaticFactCacheLookupStatus::hit:
                ++options.instrumentation->static_fact_cache_lookups;
                ++options.instrumentation->static_fact_cache_hits;
                ++options.instrumentation->static_fact_cache_reuses;
                ++options.instrumentation->static_fact_cache_provider_fact_keys_avoided;
                return;
            case rule_engine::optimizer::StaticFactCacheLookupStatus::miss:
                ++options.instrumentation->static_fact_cache_lookups;
                ++options.instrumentation->static_fact_cache_misses;
                return;
            case rule_engine::optimizer::StaticFactCacheLookupStatus::invalidated:
                ++options.instrumentation->static_fact_cache_lookups;
                ++options.instrumentation->static_fact_cache_misses;
                ++options.instrumentation->static_fact_cache_invalidations;
                return;
            case rule_engine::optimizer::StaticFactCacheLookupStatus::unsupported: return;
            default: return;
        }
    }

    void record_static_fact_cache_store(rule_engine::client_protocol::ClientEvaluationOptions &options,
                                        const rule_engine::optimizer::StaticFactCacheStoreResult &result) {
        if (options.instrumentation == nullptr || !result.subject_scoped) {
            return;
        }
        ++options.instrumentation->static_fact_cache_subject_scoped;
    }

    [[nodiscard]] bool
    filter_static_fact_cache_hits(rule_engine::client_protocol::ClientEvaluationOptions &options,
                                  std::vector<OptimizedSubjectEvaluationState> &states,
                                  std::vector<PlannedFactRequest> &requests,
                                  std::vector<rule_engine::optimizer::OptimizerTraceEvent> &trace_events) {
        if (options.static_fact_cache == nullptr || options.static_fact_cache_candidates.empty()) {
            return false;
        }

        bool served_from_cache {};
        std::vector<PlannedFactRequest> filtered_requests;
        filtered_requests.reserve(requests.size());

        for (const auto &request : requests) {
            PlannedFactRequest filtered;
            filtered.message.route = request.message.route;
            filtered.message.timeout = request.message.timeout;
            filtered.message.scan_plans = request.message.scan_plans;

            for (std::size_t index = 0; index < request.message.keys.size(); ++index) {
                const auto &key = request.message.keys[index];
                const auto *candidate = find_static_fact_cache_candidate(options, request.message.route, key);
                if (candidate != nullptr) {
                    auto lookup = options.static_fact_cache->lookup(*candidate);
                    record_static_fact_cache_lookup(options, lookup.status);
                    if (lookup.trace_event.has_value()) {
                        trace_events.push_back(*lookup.trace_event);
                    }
                    if (lookup.status == rule_engine::optimizer::StaticFactCacheLookupStatus::hit &&
                        lookup.fact.has_value()) {
                        store_fact_for_matching_subjects(states, *lookup.fact);
                        served_from_cache = true;
                        continue;
                    }
                }

                filtered.message.keys.push_back(key);
                const auto type = index < request.message.expected_types.size() ?
                                      request.message.expected_types[index] :
                                      rule_engine::ValueType::undefined;
                filtered.message.expected_types.push_back(type);
                if (index < request.metadata.size()) {
                    filtered.metadata.push_back(request.metadata[index]);
                }
            }

            if (!filtered.message.keys.empty()) {
                filtered_requests.push_back(std::move(filtered));
            }
        }

        requests = std::move(filtered_requests);
        return served_from_cache;
    }

    void store_static_fact_cache_fact(rule_engine::client_protocol::ClientEvaluationOptions &options,
                                      const std::string_view route, const rule_engine::Fact &fact) {
        if (options.static_fact_cache == nullptr) {
            return;
        }
        const rule_engine::protocol::FactKey key {
            .subject_id = fact.subject_id,
            .key = fact.key,
        };
        const auto *candidate = find_static_fact_cache_candidate(options, route, key);
        if (candidate == nullptr) {
            return;
        }
        auto store_result = options.static_fact_cache->store(*candidate, fact);
        record_static_fact_cache_store(options, store_result);
    }

    struct CandidateProviderRequestSelection {
        std::vector<rule_engine::protocol::CandidateProviderRequestMessage> requests;
        std::uint64_t filters_not_advertised {};
    };

    [[nodiscard]] CandidateProviderRequestSelection
    candidate_provider_requests_for_optimizer_plan(const rule_engine::protocol::HandshakeMessage &handshake,
                                                   const rule_engine::optimizer::OptimizerPlan &plan,
                                                   const std::chrono::milliseconds timeout) {
        CandidateProviderRequestSelection out;
        for (const auto &request : plan.candidate_provider_requests) {
            if (!has_candidate_provider_capability(handshake, request.route, request.filter_key)) {
                ++out.filters_not_advertised;
                continue;
            }

            auto found =
                std::ranges::find_if(out.requests, [&](const auto &message) { return message.route == request.route; });
            if (found == out.requests.end()) {
                rule_engine::protocol::CandidateProviderRequestMessage message;
                message.route = request.route;
                message.timeout = timeout;
                out.requests.push_back(std::move(message));
                found = std::prev(out.requests.end());
            }

            found->filters.push_back(rule_engine::protocol::CandidateProviderFilterRequest {
                .request_id = request.id,
                .filter_key = request.filter_key,
                .argument_kind = request.argument_kind,
                .argument_value = request.argument_value,
            });
        }
        return out;
    }

    [[nodiscard]] const rule_engine::optimizer::OptimizedEvaluationSubject *
    find_optimized_subject_report(const rule_engine::optimizer::OptimizedEvaluationSweep &sweep,
                                  const std::string_view subject_id) {
        const auto found = std::ranges::find_if(
            sweep.subjects, [&](const auto &subject_report) { return subject_report.subject_id == subject_id; });
        if (found == sweep.subjects.end()) {
            return nullptr;
        }
        return std::addressof(*found);
    }

    void store_subject_facts(rule_engine::FactCache &target, const rule_engine::FactCache &source,
                             const std::string_view subject_id) {
        for (auto fact : source.snapshot_for_subject(subject_id)) { target.store(std::move(fact)); }
    }

    [[nodiscard]] std::vector<rule_engine::Fact>
    snapshot_subject_facts(const rule_engine::FactCache &facts, const std::span<const rule_engine::Subject> subjects) {
        std::vector<rule_engine::Fact> out;
        for (const auto &subject : subjects) {
            auto subject_facts = facts.snapshot_for_subject(subject.id);
            out.insert(out.end(), std::make_move_iterator(subject_facts.begin()),
                       std::make_move_iterator(subject_facts.end()));
        }
        return out;
    }

    [[nodiscard]] bool
    candidate_provider_subject_set_covers_subjects(const rule_engine::protocol::CandidateProviderSubjectSet &result,
                                                   const std::span<const rule_engine::Subject> subjects) {
        if (subjects.empty() || result.status != rule_engine::FactStatus::available) {
            return false;
        }
        return std::ranges::all_of(subjects, [&](const auto &subject) {
            return std::ranges::find(result.subject_ids, subject.id) != result.subject_ids.end();
        });
    }

    [[nodiscard]] bool source_spans_equal(const rule_engine::SourceSpan &lhs,
                                          const rule_engine::SourceSpan &rhs) noexcept {
        return lhs.source_id == rhs.source_id && lhs.start == rhs.start && lhs.end == rhs.end &&
               lhs.source == rhs.source;
    }

    [[nodiscard]] bool diagnostics_equal(const std::vector<rule_engine::Diagnostic> &lhs,
                                         const std::vector<rule_engine::Diagnostic> &rhs) noexcept {
        if (lhs.size() != rhs.size()) {
            return false;
        }
        for (std::size_t index = 0; index < lhs.size(); ++index) {
            if (lhs[index].source != rhs[index].source || lhs[index].message != rhs[index].message ||
                !source_spans_equal(lhs[index].span, rhs[index].span)) {
                return false;
            }
        }
        return true;
    }

    [[nodiscard]] bool rule_results_equal(const rule_engine::RuleResult &lhs,
                                          const rule_engine::RuleResult &rhs) noexcept {
        return lhs.identifier == rhs.identifier && lhs.matched == rhs.matched &&
               diagnostics_equal(lhs.diagnostics, rhs.diagnostics);
    }

    [[nodiscard]] bool trace_events_equal(const rule_engine::optimizer::OptimizerTraceEvent &lhs,
                                          const rule_engine::optimizer::OptimizerTraceEvent &rhs) noexcept {
        return lhs.event == rhs.event && lhs.predicate_id == rhs.predicate_id &&
               lhs.rule_identifier == rhs.rule_identifier && lhs.subject_id == rhs.subject_id &&
               lhs.reason == rhs.reason && lhs.cost_class == rhs.cost_class && source_spans_equal(lhs.span, rhs.span) &&
               lhs.matched_subject_count == rhs.matched_subject_count &&
               lhs.candidate_subject_count == rhs.candidate_subject_count &&
               lhs.candidate_set_bytes == rhs.candidate_set_bytes;
    }

    template<typename Value, typename Equals> [[nodiscard]] std::uint64_t
    count_vector_mismatches(const std::vector<Value> &lhs, const std::vector<Value> &rhs, Equals equals) {
        const auto shared_size = std::min(lhs.size(), rhs.size());
        auto out = static_cast<std::uint64_t>(std::max(lhs.size(), rhs.size()) - shared_size);
        for (std::size_t index = 0; index < shared_size; ++index) {
            if (!equals(lhs[index], rhs[index])) {
                ++out;
            }
        }
        return out;
    }

    [[nodiscard]] std::uint64_t count_rule_result_mismatches(const std::vector<rule_engine::RuleResult> &lhs,
                                                             const std::vector<rule_engine::RuleResult> &rhs) {
        return count_vector_mismatches(lhs, rhs, rule_results_equal);
    }

    [[nodiscard]] std::uint64_t
    count_trace_event_mismatches(const std::vector<rule_engine::optimizer::OptimizerTraceEvent> &lhs,
                                 const std::vector<rule_engine::optimizer::OptimizerTraceEvent> &rhs) {
        return count_vector_mismatches(lhs, rhs, trace_events_equal);
    }

    [[nodiscard]] std::uint64_t
    count_subject_mismatches(const std::vector<rule_engine::optimizer::OptimizedEvaluationSubject> &lhs,
                             const std::vector<rule_engine::optimizer::OptimizedEvaluationSubject> &rhs) {
        return count_vector_mismatches(lhs, rhs, [](const auto &captured, const auto &replayed) {
            return captured.subject_id == replayed.subject_id &&
                   captured.exact_vm_rule_identifiers == replayed.exact_vm_rule_identifiers &&
                   captured.pruned_rule_identifiers == replayed.pruned_rule_identifiers;
        });
    }

    [[nodiscard]] std::uint64_t
    count_subject_rule_result_mismatches(const std::vector<rule_engine::optimizer::OptimizedEvaluationSubject> &lhs,
                                         const std::vector<rule_engine::optimizer::OptimizedEvaluationSubject> &rhs) {
        const auto shared_size = std::min(lhs.size(), rhs.size());
        std::uint64_t out {};
        for (std::size_t index = 0; index < shared_size; ++index) {
            out += count_rule_result_mismatches(lhs[index].rule_results, rhs[index].rule_results);
        }
        return out + static_cast<std::uint64_t>(std::max(lhs.size(), rhs.size()) - shared_size);
    }

    [[nodiscard]] std::uint64_t
    count_sweep_metric_mismatches(const rule_engine::optimizer::OptimizedEvaluationSweep &lhs,
                                  const rule_engine::optimizer::OptimizedEvaluationSweep &rhs) {
        std::uint64_t out {};
        const auto count_if_different = [&out](const auto &left, const auto &right) {
            if (left != right) {
                ++out;
            }
        };

        count_if_different(lhs.incomplete_subjects, rhs.incomplete_subjects);
        count_if_different(lhs.baseline_exact_vm_rule_executions, rhs.baseline_exact_vm_rule_executions);
        count_if_different(lhs.optimized_exact_vm_rule_executions, rhs.optimized_exact_vm_rule_executions);
        count_if_different(lhs.exact_vm_rule_executions_avoided, rhs.exact_vm_rule_executions_avoided);
        count_if_different(lhs.candidate_provider_requests, rhs.candidate_provider_requests);
        count_if_different(lhs.candidate_provider_subjects_returned, rhs.candidate_provider_subjects_returned);
        count_if_different(lhs.candidate_provider_broad_results, rhs.candidate_provider_broad_results);
        count_if_different(lhs.candidate_provider_fallback_predicate_evaluations,
                           rhs.candidate_provider_fallback_predicate_evaluations);
        count_if_different(lhs.shared_dag.predicate_order, rhs.shared_dag.predicate_order);
        count_if_different(lhs.shared_dag.predicate_evaluations, rhs.shared_dag.predicate_evaluations);
        count_if_different(lhs.shared_dag.pruned_rule_subjects, rhs.shared_dag.pruned_rule_subjects);
        count_if_different(lhs.shared_dag.dropped_rule_branches, rhs.shared_dag.dropped_rule_branches);
        count_if_different(lhs.shared_dag.peak_candidate_set_subjects, rhs.shared_dag.peak_candidate_set_subjects);
        count_if_different(lhs.shared_dag.peak_candidate_set_bytes, rhs.shared_dag.peak_candidate_set_bytes);
        return out;
    }
} // namespace

namespace rule_engine::client_protocol {
    protocol::HandshakeMessage client_handshake(const std::span<const protocol::Capability> extra_capabilities) {
        protocol::HandshakeMessage message;
        message.protocol = "rule-engine-client";
        message.version = 1u;
        add_capability(message.capabilities, protocol::Capability {.route = "endpoint.process.snapshot"});
        add_capability(message.capabilities, protocol::Capability {.route = "endpoint.process.handles"});
        add_capability(message.capabilities, protocol::Capability {.route = "endpoint.process.signer"});
        add_capability(message.capabilities, protocol::Capability {.route = "endpoint.process.image.pe"});
        add_capability(message.capabilities, protocol::Capability {.route = "endpoint.scan.patterns"});
        for (const auto &capability : extra_capabilities) { add_capability(message.capabilities, capability); }
        return message;
    }

    std::expected<protocol::SubjectListMessage, ErrorSet> enumerate_client_subjects() {
        auto subjects = windows::enumerate_process_subjects();
        if (!subjects) {
            return std::unexpected(std::move(subjects.error()));
        }
        return protocol::SubjectListMessage {.subjects = std::move(*subjects)};
    }

    protocol::FactBatchResponseMessage handle_client_fact_batch(const protocol::FactBatchRequestMessage &request) {
        return handle_client_fact_batch_with_fixtures(
            request, patterns::default_pattern_fixtures(), {}, {}, client_protocol::ProviderRequestContext {});
    }

    std::expected<void, ErrorSet> serve_client(const ClientListenOptions &options,
                                               const ListeningCallback &on_listening) {
        auto pattern_fixtures = patterns::default_pattern_fixtures();
        if (!options.pattern_fixture_path.empty()) {
            auto loaded = patterns::load_pattern_fixture_file(options.pattern_fixture_path);
            if (!loaded) {
                return std::unexpected(std::move(loaded.error()));
            }
            pattern_fixtures = std::move(*loaded);
        }

        asio::io_context io;
        asio::error_code ec;
        const auto address = asio::ip::make_address(options.bind_address, ec);
        if (ec) {
            return std::unexpected(asio_error("client.bind_address", ec));
        }

        tcp::acceptor acceptor {io};
        const tcp::endpoint endpoint {address, options.port};
        acceptor.open(endpoint.protocol(), ec);
        if (ec) {
            return std::unexpected(asio_error("client.acceptor.open", ec));
        }
        acceptor.set_option(tcp::acceptor::reuse_address(true), ec);
        if (ec) {
            return std::unexpected(asio_error("client.acceptor.reuse_address", ec));
        }
        acceptor.bind(endpoint, ec);
        if (ec) {
            return std::unexpected(asio_error("client.acceptor.bind", ec));
        }
        acceptor.listen(asio::socket_base::max_listen_connections, ec);
        if (ec) {
            return std::unexpected(asio_error("client.acceptor.listen", ec));
        }
        acceptor.non_blocking(true, ec);
        if (ec) {
            return std::unexpected(asio_error("client.acceptor.non_blocking", ec));
        }

        const auto local_endpoint = acceptor.local_endpoint(ec);
        if (ec) {
            return std::unexpected(asio_error("client.acceptor.local_endpoint", ec));
        }
        if (on_listening) {
            on_listening(local_endpoint.port());
        }

        const auto max_session_workers = std::max<std::size_t>(options.max_session_workers, 1u);
        std::vector<std::thread> session_workers;
        std::mutex error_mutex;
        std::optional<ErrorSet> first_worker_error;
        const auto join_oldest_worker = [&] {
            if (session_workers.empty()) {
                return;
            }
            if (session_workers.front().joinable()) {
                session_workers.front().join();
            }
            session_workers.erase(session_workers.begin());
        };
        const auto join_all_workers = [&] {
            for (auto &worker : session_workers) {
                if (worker.joinable()) {
                    worker.join();
                }
            }
            session_workers.clear();
        };

        std::size_t served_sessions = 0u;
        while ((options.max_sessions == 0u || served_sessions < options.max_sessions) &&
               !options.stop_token.stop_requested()) {
            if (max_session_workers > 1u && session_workers.size() >= max_session_workers) {
                join_oldest_worker();
                if (first_worker_error.has_value()) {
                    join_all_workers();
                    return std::unexpected(std::move(*first_worker_error));
                }
            }

            tcp::socket socket {io};
            acceptor.accept(socket, ec);
            if (ec) {
                if (is_timeout_error(ec)) {
                    std::this_thread::sleep_for(shutdown_poll_interval);
                    continue;
                }
                join_all_workers();
                return std::unexpected(asio_error("client.accept", ec));
            }
            ++served_sessions;

            if (max_session_workers == 1u) {
                if (auto result = serve_connected_client(std::move(socket), options, pattern_fixtures); !result) {
                    return result;
                }
                continue;
            }

            session_workers.emplace_back([session_socket = std::move(socket), &options, &pattern_fixtures,
                                          &first_worker_error, &error_mutex]() mutable {
                auto result = serve_connected_client(std::move(session_socket), options, pattern_fixtures);
                if (!result) {
                    capture_first_session_error(first_worker_error, error_mutex, std::move(result.error()));
                }
            });
        }

        join_all_workers();
        if (first_worker_error.has_value()) {
            return std::unexpected(std::move(*first_worker_error));
        }
        return {};
    }

    std::expected<void, ErrorSet> serve_client_once(const ClientListenOptions &options,
                                                    const ListeningCallback &on_listening) {
        auto once_options = options;
        once_options.max_sessions = 1u;
        return serve_client(once_options, on_listening);
    }

    std::expected<ClientSession, ErrorSet>
    run_client_session(const ClientConnectionOptions &options,
                       const std::vector<protocol::FactBatchRequestMessage> &requests,
                       const std::vector<protocol::CandidateProviderRequestMessage> &candidate_provider_requests) {
        asio::io_context io;
        tcp::socket socket {io};
        if (auto result = connect_socket(socket, options); !result) {
            return std::unexpected(std::move(result.error()));
        }

        auto preamble = read_client_preamble(socket);
        if (!preamble) {
            return std::unexpected(std::move(preamble.error()));
        }

        ClientSession session {
            .handshake = std::move(preamble->handshake),
            .subjects = std::move(preamble->subjects),
            .responses = {},
            .candidate_provider_responses = {},
        };
        session.responses.reserve(requests.size());
        session.candidate_provider_responses.reserve(candidate_provider_requests.size());

        for (const auto &request : requests) {
            if (auto valid = validate_request_capability(session.handshake, request); !valid) {
                return std::unexpected(std::move(valid.error()));
            }
            auto response = send_request_and_read_response(socket, request);
            if (!response) {
                return std::unexpected(std::move(response.error()));
            }
            session.responses.push_back(std::move(*response));
        }

        for (const auto &request : candidate_provider_requests) {
            if (auto valid = validate_request_capability(session.handshake, request); !valid) {
                return std::unexpected(std::move(valid.error()));
            }
            auto response = send_request_and_read_response(socket, request);
            if (!response) {
                return std::unexpected(std::move(response.error()));
            }
            session.candidate_provider_responses.push_back(std::move(*response));
        }

        close_socket(socket);
        return session;
    }

    std::expected<ClientEvaluationSession, ErrorSet>
    evaluate_subject_with_client(const ClientConnectionOptions &options, const VerifiedProgram &program,
                                 const Subject &subject) {
        auto multi = evaluate_subjects_with_client(options, program, std::vector<Subject> {subject},
                                                   ClientEvaluationOptions {
                                                       .max_subject_concurrency = 1u,
                                                       .max_provider_rounds = 16u,
                                                   });
        if (!multi) {
            return std::unexpected(std::move(multi.error()));
        }
        if (multi->evaluations.empty()) {
            return std::unexpected(single_error("client.evaluator", "missing subject evaluation result"));
        }
        return ClientEvaluationSession {
            .handshake = std::move(multi->handshake),
            .subjects = std::move(multi->subjects),
            .final_step = std::move(multi->evaluations[0].final_step),
        };
    }

    std::expected<ClientMultiEvaluationSession, ErrorSet>
    evaluate_subjects_with_client(const ClientConnectionOptions &options, const VerifiedProgram &program,
                                  const std::vector<Subject> &subjects, ClientEvaluationOptions evaluation_options) {
        asio::io_context io;
        tcp::socket socket {io};
        if (auto result = connect_socket(socket, options); !result) {
            return std::unexpected(std::move(result.error()));
        }

        auto preamble = read_client_preamble(socket);
        if (!preamble) {
            return std::unexpected(std::move(preamble.error()));
        }
        if (auto valid = validate_program_capabilities(preamble->handshake, program); !valid) {
            return std::unexpected(std::move(valid.error()));
        }

        auto requested_subjects = subjects;
        if (requested_subjects.empty()) {
            requested_subjects = preamble->subjects.subjects;
        }
        if (requested_subjects.empty()) {
            return std::unexpected(single_error("client.evaluator", "no subjects available for evaluation"));
        }

        const auto subject_concurrency = std::max<std::size_t>(evaluation_options.max_subject_concurrency, 1u);
        const auto max_rounds = std::max<std::size_t>(evaluation_options.max_provider_rounds, 1u);
        ClientMultiEvaluationSession session {
            .handshake = std::move(preamble->handshake),
            .subjects = std::move(preamble->subjects),
            .evaluations = {},
        };
        session.evaluations.reserve(requested_subjects.size());

        for (std::size_t offset = 0; offset < requested_subjects.size(); offset += subject_concurrency) {
            const auto end = std::min(offset + subject_concurrency, requested_subjects.size());
            std::vector<SubjectEvaluationState> states;
            states.reserve(end - offset);
            for (std::size_t index = offset; index < end; ++index) {
                states.push_back(SubjectEvaluationState {
                    .subject = requested_subjects[index],
                    .facts = {},
                    .final_step = {},
                });
            }
            record_vm_queue_pressure(evaluation_options, states.size());
            std::unordered_map<std::string, std::uint8_t> retry_attempts;

            for (std::size_t round = 0; round < max_rounds; ++round) {
                bool all_complete {true};
                std::vector<PlannedFactRequest> requests;
                for (auto &state : states) {
                    if (state.final_step.has_value()) {
                        continue;
                    }

                    const Evaluator evaluator {program, state.facts};
                    auto step = evaluator.step(state.subject);
                    if (step.state == EvaluationState::complete) {
                        state.final_step = std::move(step);
                        continue;
                    }
                    all_complete = false;
                    if (step.requests.empty()) {
                        return std::unexpected(
                            single_error("client.evaluator", "evaluation waited without fact requests"));
                    }
                    for (const auto &batch : step.requests) { add_fact_request(requests, state.subject, batch); }
                }

                if (all_complete) {
                    break;
                }
                if (requests.empty()) {
                    return std::unexpected(single_error("client.evaluator", "evaluation had no provider requests"));
                }
                if (evaluation_options.stop_token.stop_requested()) {
                    store_cancellation_facts(states, requests);
                    continue;
                }
                record_provider_queue_pressure(evaluation_options, requests.size());
                if (evaluation_options.instrumentation != nullptr) {
                    ++evaluation_options.instrumentation->provider_rounds;
                }

                for (const auto &request : requests) {
                    if (auto valid = validate_request_capability(session.handshake, request.message); !valid) {
                        return std::unexpected(std::move(valid.error()));
                    }
                    if (evaluation_options.instrumentation != nullptr) {
                        ++evaluation_options.instrumentation->provider_requests;
                        evaluation_options.instrumentation->provider_fact_keys_requested += request.message.keys.size();
                    }
                    const auto request_started = std::chrono::steady_clock::now();
                    auto response = send_request_and_read_response(socket, request.message);
                    if (evaluation_options.instrumentation != nullptr) {
                        const auto elapsed = std::chrono::steady_clock::now() - request_started;
                        evaluation_options.instrumentation->provider_elapsed_us += static_cast<std::uint64_t>(
                            std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count());
                    }
                    if (!response) {
                        return std::unexpected(std::move(response.error()));
                    }
                    if (evaluation_options.instrumentation != nullptr) {
                        evaluation_options.instrumentation->provider_facts_returned += response->values.size();
                    }
                    store_response_facts_with_retry(states, request, *response, retry_attempts);
                }
            }

            for (auto &state : states) {
                if (!state.final_step.has_value()) {
                    return std::unexpected(
                        single_error("client.evaluator", "evaluation did not converge after provider rounds"));
                }
                session.evaluations.push_back(ClientSubjectEvaluation {
                    .subject = std::move(state.subject),
                    .final_step = std::move(*state.final_step),
                });
            }
        }

        close_socket(socket);
        return session;
    }

    std::expected<OptimizedClientEvaluationSession, ErrorSet>
    evaluate_subjects_with_optimizer_plan(const ClientConnectionOptions &options, const VerifiedProgram &program,
                                          const optimizer::OptimizerPlan &plan, const std::vector<Subject> &subjects,
                                          ClientEvaluationOptions evaluation_options) {
        asio::io_context io;
        tcp::socket socket {io};
        if (auto result = connect_socket(socket, options); !result) {
            return std::unexpected(std::move(result.error()));
        }

        auto preamble = read_client_preamble(socket);
        if (!preamble) {
            return std::unexpected(std::move(preamble.error()));
        }

        auto requested_subjects = subjects;
        if (requested_subjects.empty()) {
            requested_subjects = preamble->subjects.subjects;
        }
        if (requested_subjects.empty()) {
            return std::unexpected(single_error("client.evaluator", "no subjects available for evaluation"));
        }

        auto prefetched_identity_facts = prefetch_static_fact_identity_facts(
            socket, preamble->handshake, evaluation_options, requested_subjects, options.io_timeout);
        if (!prefetched_identity_facts) {
            return std::unexpected(std::move(prefetched_identity_facts.error()));
        }
        auto prefetched_identity_fact_cache = std::move(*prefetched_identity_facts);
        if (prefetched_identity_fact_cache.has_value()) {
            evaluation_options.static_fact_identity_facts = std::addressof(*prefetched_identity_fact_cache);
        }

        append_static_fact_cache_candidates_from_identity_facts(evaluation_options, plan, requested_subjects);

        const auto candidate_selection =
            candidate_provider_requests_for_optimizer_plan(preamble->handshake, plan, options.io_timeout);
        if (evaluation_options.instrumentation != nullptr) {
            evaluation_options.instrumentation->candidate_provider_filters_not_advertised +=
                candidate_selection.filters_not_advertised;
        }

        std::vector<optimizer::CandidateProviderResult> candidate_provider_results;
        for (const auto &request : candidate_selection.requests) {
            if (auto valid = validate_request_capability(preamble->handshake, request); !valid) {
                return std::unexpected(std::move(valid.error()));
            }
            if (evaluation_options.instrumentation != nullptr) {
                ++evaluation_options.instrumentation->candidate_provider_requests;
                evaluation_options.instrumentation->candidate_provider_filters_requested += request.filters.size();
            }
            const auto request_started = std::chrono::steady_clock::now();
            auto response = send_request_and_read_response(socket, request);
            if (evaluation_options.instrumentation != nullptr) {
                const auto elapsed = std::chrono::steady_clock::now() - request_started;
                evaluation_options.instrumentation->candidate_provider_elapsed_us +=
                    static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count());
            }
            if (!response) {
                return std::unexpected(std::move(response.error()));
            }
            if (evaluation_options.instrumentation != nullptr) {
                for (const auto &result : response->results) {
                    evaluation_options.instrumentation->candidate_provider_subjects_returned +=
                        result.subject_ids.size();
                    if (candidate_provider_subject_set_covers_subjects(result, requested_subjects)) {
                        ++evaluation_options.instrumentation->candidate_provider_broad_results;
                    }
                }
            }
            auto results = optimizer::candidate_provider_results_from_protocol(response->results);
            candidate_provider_results.insert(candidate_provider_results.end(),
                                              std::make_move_iterator(results.begin()),
                                              std::make_move_iterator(results.end()));
        }

        const FactCache planning_facts;
        const auto planning_sweep = optimizer::evaluate_with_optimizer_plan(program, plan, requested_subjects,
                                                                            planning_facts, candidate_provider_results);
        if (planning_sweep.subjects.size() != requested_subjects.size()) {
            return std::unexpected(single_error("client.evaluator", "optimizer plan returned incomplete subject plan"));
        }

        const auto subject_concurrency = std::max<std::size_t>(evaluation_options.max_subject_concurrency, 1u);
        const auto max_rounds = std::max<std::size_t>(evaluation_options.max_provider_rounds, 1u);
        FactCache optimized_facts;
        std::vector<optimizer::OptimizerTraceEvent> static_fact_cache_trace_events;

        for (std::size_t offset = 0; offset < requested_subjects.size(); offset += subject_concurrency) {
            const auto end = std::min(offset + subject_concurrency, requested_subjects.size());
            std::vector<OptimizedSubjectEvaluationState> states;
            states.reserve(end - offset);
            for (std::size_t index = offset; index < end; ++index) {
                const auto *subject_report =
                    find_optimized_subject_report(planning_sweep, requested_subjects[index].id);
                if (subject_report == nullptr) {
                    return std::unexpected(single_error("client.evaluator", "optimizer plan omitted subject " +
                                                                                requested_subjects[index].id));
                }
                states.push_back(OptimizedSubjectEvaluationState {
                    .subject = requested_subjects[index],
                    .facts = {},
                    .exact_vm_rule_identifiers = subject_report->exact_vm_rule_identifiers,
                    .final_step = {},
                });
            }
            record_vm_queue_pressure(evaluation_options, pending_exact_vm_subjects(states));
            std::unordered_map<std::string, std::uint8_t> retry_attempts;

            for (std::size_t round = 0; round < max_rounds; ++round) {
                bool all_complete {true};
                std::vector<PlannedFactRequest> requests;
                for (auto &state : states) {
                    if (state.final_step.has_value() || state.exact_vm_rule_identifiers.empty()) {
                        continue;
                    }

                    const Evaluator evaluator {
                        program,
                        state.facts,
                        EvaluationOptions {.enabled_rule_identifiers = &state.exact_vm_rule_identifiers},
                    };
                    auto step = evaluator.step(state.subject);
                    if (step.state == EvaluationState::complete) {
                        state.final_step = std::move(step);
                        continue;
                    }
                    all_complete = false;
                    if (step.requests.empty()) {
                        return std::unexpected(
                            single_error("client.evaluator", "evaluation waited without fact requests"));
                    }
                    for (const auto &batch : step.requests) { add_fact_request(requests, state.subject, batch); }
                }

                if (all_complete) {
                    break;
                }
                const auto served_from_static_cache =
                    filter_static_fact_cache_hits(evaluation_options, states, requests, static_fact_cache_trace_events);
                if (requests.empty()) {
                    if (served_from_static_cache) {
                        continue;
                    }
                    return std::unexpected(single_error("client.evaluator", "evaluation had no provider requests"));
                }
                if (evaluation_options.stop_token.stop_requested()) {
                    store_cancellation_facts(states, requests);
                    continue;
                }
                record_provider_queue_pressure(evaluation_options, requests.size());
                if (evaluation_options.instrumentation != nullptr) {
                    ++evaluation_options.instrumentation->provider_rounds;
                }

                for (const auto &request : requests) {
                    if (auto valid = validate_request_capability(preamble->handshake, request.message); !valid) {
                        return std::unexpected(std::move(valid.error()));
                    }
                    if (evaluation_options.instrumentation != nullptr) {
                        ++evaluation_options.instrumentation->provider_requests;
                        evaluation_options.instrumentation->provider_fact_keys_requested += request.message.keys.size();
                    }
                    const auto request_started = std::chrono::steady_clock::now();
                    auto response = send_request_and_read_response(socket, request.message);
                    if (evaluation_options.instrumentation != nullptr) {
                        const auto elapsed = std::chrono::steady_clock::now() - request_started;
                        evaluation_options.instrumentation->provider_elapsed_us += static_cast<std::uint64_t>(
                            std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count());
                    }
                    if (!response) {
                        return std::unexpected(std::move(response.error()));
                    }
                    if (evaluation_options.instrumentation != nullptr) {
                        evaluation_options.instrumentation->provider_facts_returned += response->values.size();
                    }
                    for (const auto &fact : response->values) {
                        const auto *metadata = find_metadata_for_fact(request, fact);
                        if (metadata != nullptr && retryable_provider_fact(*metadata, fact, retry_attempts)) {
                            continue;
                        }
                        store_static_fact_cache_fact(evaluation_options, request.message.route, fact);
                        store_fact_for_matching_subjects(states, fact);
                    }
                }
            }

            for (auto &state : states) {
                if (!state.exact_vm_rule_identifiers.empty() && !state.final_step.has_value()) {
                    return std::unexpected(
                        single_error("client.evaluator", "evaluation did not converge after provider rounds"));
                }
                store_subject_facts(optimized_facts, state.facts, state.subject.id);
            }
        }

        auto final_sweep = optimizer::evaluate_with_optimizer_plan(program, plan, requested_subjects, optimized_facts,
                                                                   candidate_provider_results);
        final_sweep.trace_events.insert(final_sweep.trace_events.end(), static_fact_cache_trace_events.begin(),
                                        static_fact_cache_trace_events.end());
        OptimizedClientEvaluationSession session {
            .handshake = std::move(preamble->handshake),
            .subjects = std::move(preamble->subjects),
            .evaluated_subjects = requested_subjects,
            .facts = snapshot_subject_facts(optimized_facts, requested_subjects),
            .candidate_provider_results = std::move(candidate_provider_results),
            .static_fact_cache_trace_events = std::move(static_fact_cache_trace_events),
            .sweep = std::move(final_sweep),
        };

        close_socket(socket);
        return session;
    }

    optimizer::OptimizedEvaluationSweep
    replay_optimized_client_evaluation(const VerifiedProgram &program, const optimizer::OptimizerPlan &plan,
                                       const OptimizedClientEvaluationSession &session) {
        FactCache facts;
        for (const auto &fact : session.facts) { facts.store(fact); }
        auto sweep = optimizer::evaluate_with_optimizer_plan(program, plan, session.evaluated_subjects, facts,
                                                             session.candidate_provider_results);
        sweep.trace_events.insert(sweep.trace_events.end(), session.static_fact_cache_trace_events.begin(),
                                  session.static_fact_cache_trace_events.end());
        return sweep;
    }

    OptimizedClientReplayReport
    replay_optimized_client_evaluation_with_parity_report(const VerifiedProgram &program,
                                                          const optimizer::OptimizerPlan &plan,
                                                          const OptimizedClientEvaluationSession &session) {
        auto replayed_sweep = replay_optimized_client_evaluation(program, plan, session);
        OptimizedClientReplayReport out {
            .sweep = std::move(replayed_sweep),
        };
        out.subject_mismatches = count_subject_mismatches(session.sweep.subjects, out.sweep.subjects);
        out.rule_result_mismatches = count_subject_rule_result_mismatches(session.sweep.subjects, out.sweep.subjects);
        out.trace_event_mismatches =
            count_trace_event_mismatches(session.sweep.trace_events, out.sweep.trace_events) +
            count_trace_event_mismatches(session.sweep.shared_dag.trace_events, out.sweep.shared_dag.trace_events);
        out.sweep_metric_mismatches = count_sweep_metric_mismatches(session.sweep, out.sweep);
        return out;
    }
} // namespace rule_engine::client_protocol
