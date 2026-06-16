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
    template <typename Exception>
    [[noreturn]] void throw_exception(const Exception &) {
        std::terminate();
    }
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
#include <iterator>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace {
    using asio::ip::tcp;

    constexpr std::uint32_t max_payload_size = 16u * 1024u * 1024u;

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
        if (::setsockopt(socket.native_handle(),
                         SOL_SOCKET,
                         SO_RCVTIMEO,
                         raw_timeout,
                         static_cast<int>(sizeof(timeout_ms))) != 0) {
            return std::unexpected(socket_option_error("protocol.receive_timeout"));
        }
        if (::setsockopt(socket.native_handle(),
                         SOL_SOCKET,
                         SO_SNDTIMEO,
                         raw_timeout,
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
        return (static_cast<std::uint32_t>(header[0]) << 24u) |
               (static_cast<std::uint32_t>(header[1]) << 16u) |
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
        const auto found = std::ranges::find_if(facts, [&](const auto &fact) {
            return fact.subject_id == key.subject_id && fact.key == key.key;
        });
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
            return existing.route == capability.route;
        });
        if (exists) {
            return;
        }
        capabilities.push_back(std::move(capability));
    }

    [[nodiscard]] bool has_capability(const rule_engine::protocol::HandshakeMessage &handshake,
                                      const std::string_view route) {
        return std::ranges::any_of(handshake.capabilities, [&](const auto &capability) {
            return capability.route == route;
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

    [[nodiscard]] std::vector<rule_engine::Fact>
    process_snapshot_response(const std::span<const rule_engine::protocol::FactKey> keys) {
        const auto process_keys = to_process_keys(keys);
        auto facts = rule_engine::windows::read_process_snapshot_facts(process_keys);
        if (!facts) {
            std::vector<rule_engine::Fact> out;
            out.reserve(keys.size());
            const auto diagnostic = facts.error().diagnostics.empty() ? std::string {"process provider failed"}
                                                                      : facts.error().diagnostics[0].message;
            for (const auto &key : keys) {
                out.push_back(make_unavailable_fact(key, diagnostic));
            }
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
            const auto diagnostic = facts.error().diagnostics.empty() ? std::string {"process handle provider failed"}
                                                                      : facts.error().diagnostics[0].message;
            for (const auto &key : keys) {
                out.push_back(make_unavailable_fact(key, diagnostic));
            }
            return out;
        }
        return *facts;
    }

    [[nodiscard]] std::vector<rule_engine::Fact>
    process_signer_response(const std::span<const rule_engine::protocol::FactKey> keys) {
        const auto process_keys = to_process_keys(keys);
        auto facts = rule_engine::windows::read_process_signer_facts(process_keys);
        if (!facts) {
            std::vector<rule_engine::Fact> out;
            out.reserve(keys.size());
            const auto diagnostic = facts.error().diagnostics.empty() ? std::string {"process signer provider failed"}
                                                                      : facts.error().diagnostics[0].message;
            for (const auto &key : keys) {
                out.push_back(make_unavailable_fact(key, diagnostic));
            }
            return out;
        }
        return *facts;
    }

    [[nodiscard]] std::vector<rule_engine::Fact>
    pe_response(const std::span<const rule_engine::protocol::FactKey> keys) {
        std::vector<rule_engine::Fact> out;
        out.reserve(keys.size());

        std::unordered_map<std::string, std::vector<rule_engine::Fact>> pe_facts_by_subject;
        for (const auto &key : keys) {
            if (!pe_facts_by_subject.contains(key.subject_id)) {
                auto path = rule_engine::windows::resolve_process_image_path(key.subject_id);
                if (!path) {
                    const auto diagnostic = path.error().diagnostics.empty() ? std::string {"failed to resolve PE image"}
                                                                             : path.error().diagnostics[0].message;
                    pe_facts_by_subject.emplace(key.subject_id,
                                                std::vector<rule_engine::Fact> {make_unavailable_fact(key, diagnostic)});
                    continue;
                }

                auto facts = rule_engine::windows::read_pe_image_facts(key.subject_id, *path);
                if (!facts) {
                    const auto diagnostic = facts.error().diagnostics.empty() ? std::string {"PE provider failed"}
                                                                             : facts.error().diagnostics[0].message;
                    pe_facts_by_subject.emplace(key.subject_id,
                                                std::vector<rule_engine::Fact> {make_unavailable_fact(key, diagnostic)});
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
                                           const rule_engine::client_protocol::ExtraFactBatchHandler &extra_handler) {
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
            response.values = process_signer_response(request.keys);
            return response;
        }
        if (request.route == "endpoint.process.image.pe") {
            response.values = pe_response(request.keys);
            return response;
        }
        if (request.route == "endpoint.scan.patterns") {
            response.values = rule_engine::patterns::read_fixture_pattern_facts(request.keys, pattern_fixtures);
            return response;
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
            return std::unexpected(handshake_payload ? rule_engine::single_error("client.connect", "missing handshake")
                                                     : std::move(handshake_payload.error()));
        }
        auto handshake = rule_engine::protocol::decode_handshake(**handshake_payload);
        if (!handshake) {
            return std::unexpected(std::move(handshake.error()));
        }

        auto subject_payload = read_payload(socket);
        if (!subject_payload || !subject_payload->has_value()) {
            return std::unexpected(subject_payload ? rule_engine::single_error("client.connect", "missing subject list")
                                                   : std::move(subject_payload.error()));
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

    [[nodiscard]] std::expected<rule_engine::protocol::FactBatchResponseMessage, rule_engine::ErrorSet>
    send_request_and_read_response(tcp::socket &socket,
                                   const rule_engine::protocol::FactBatchRequestMessage &request) {
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
            return std::unexpected(response_payload ? rule_engine::single_error("client.connect", "missing fact response")
                                                    : std::move(response_payload.error()));
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

    void close_socket(tcp::socket &socket) {
        asio::error_code ec;
        socket.shutdown(tcp::socket::shutdown_both, ec);
        socket.close(ec);
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
        return std::unexpected(rule_engine::single_error("client.evaluator",
                                                         "client does not advertise provider route " + request.route));
    }

    [[nodiscard]] std::expected<void, rule_engine::ErrorSet>
    validate_program_capabilities(const rule_engine::protocol::HandshakeMessage &handshake,
                                  const rule_engine::VerifiedProgram &program) {
        for (const auto &route : rule_engine::required_provider_routes(program)) {
            if (has_capability(handshake, route)) {
                continue;
            }
            return std::unexpected(rule_engine::single_error(
                "client.evaluator",
                "client does not advertise required provider route " + route));
        }
        return {};
    }

    [[nodiscard]] std::expected<void, rule_engine::ErrorSet>
    validate_fact_response(const rule_engine::protocol::FactBatchRequestMessage &request,
                           const rule_engine::protocol::FactBatchResponseMessage &response) {
        if (response.route != request.route) {
            return std::unexpected(rule_engine::single_error("client.evaluator",
                                                             "provider response route mismatch"));
        }

        std::vector<rule_engine::protocol::FactKey> seen;
        seen.reserve(response.values.size());
        for (const auto &fact : response.values) {
            rule_engine::protocol::FactKey key {
                .subject_id = fact.subject_id,
                .key = fact.key,
            };
            if (!contains_fact_key(request.keys, key)) {
                return std::unexpected(rule_engine::single_error("client.evaluator",
                                                                 "provider returned unrequested fact " + fact.key));
            }
            if (contains_fact_key(seen, key)) {
                return std::unexpected(rule_engine::single_error("client.evaluator",
                                                                 "provider returned duplicate fact " + fact.key));
            }
            const auto expected_type = expected_type_for_fact(request, key);
            if (expected_type.has_value() && *expected_type != rule_engine::ValueType::undefined &&
                fact.status == rule_engine::FactStatus::available && !value_matches_type(fact.value, *expected_type)) {
                return std::unexpected(rule_engine::single_error(
                    "client.evaluator",
                    "provider returned fact " + fact.key + " with wrong type; expected " +
                        value_type_name(*expected_type)));
            }
            seen.push_back(std::move(key));
        }

        for (const auto &key : request.keys) {
            if (!contains_fact_key(seen, key)) {
                return std::unexpected(rule_engine::single_error("client.evaluator",
                                                                 "provider response omitted requested fact " + key.key));
            }
        }
        return {};
    }

    void add_fact_request(std::vector<rule_engine::protocol::FactBatchRequestMessage> &requests,
                          const rule_engine::Subject &subject,
                          const rule_engine::FactRequestBatch &batch) {
        auto found = std::ranges::find_if(requests, [&](const auto &request) { return request.route == batch.route; });
        if (found == requests.end()) {
            rule_engine::protocol::FactBatchRequestMessage request;
            request.route = batch.route;
            request.timeout = std::chrono::duration_cast<std::chrono::milliseconds>(batch.timeout);
            requests.push_back(std::move(request));
            found = std::prev(requests.end());
        }

        const auto timeout = std::chrono::duration_cast<std::chrono::milliseconds>(batch.timeout);
        if (found->timeout < timeout) {
            found->timeout = timeout;
        }
        for (std::size_t index = 0; index < batch.keys.size(); ++index) {
            const auto &key = batch.keys[index];
            rule_engine::protocol::FactKey fact_key {
                .subject_id = subject.id,
                .key = key,
            };
            if (!contains_fact_key(found->keys, fact_key)) {
                found->keys.push_back(std::move(fact_key));
                const auto type = index < batch.types.size() ? batch.types[index] : rule_engine::ValueType::undefined;
                found->expected_types.push_back(type);
            }
        }
    }

    struct SubjectEvaluationState {
        rule_engine::Subject subject;
        rule_engine::FactCache facts;
        std::optional<rule_engine::EvaluationStep> final_step;
    };

    void store_fact_for_matching_subjects(std::vector<SubjectEvaluationState> &states, const rule_engine::Fact &fact) {
        for (auto &state : states) {
            if (state.subject.id == fact.subject_id) {
                state.facts.store(fact);
            }
        }
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
        for (const auto &capability : extra_capabilities) {
            add_capability(message.capabilities, capability);
        }
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
        return handle_client_fact_batch_with_fixtures(request, patterns::default_pattern_fixtures(), {});
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

        const auto local_endpoint = acceptor.local_endpoint(ec);
        if (ec) {
            return std::unexpected(asio_error("client.acceptor.local_endpoint", ec));
        }
        if (on_listening) {
            on_listening(local_endpoint.port());
        }

        for (std::size_t served_sessions = 0u; options.max_sessions == 0u || served_sessions < options.max_sessions;
             ++served_sessions) {
            tcp::socket socket {io};
            acceptor.accept(socket, ec);
            if (ec) {
                return std::unexpected(asio_error("client.accept", ec));
            }
            if (auto result = set_socket_timeouts(socket, options.io_timeout); !result) {
                return result;
            }

            if (auto result = send_handshake_and_subjects(socket, options.extra_capabilities); !result) {
                return result;
            }

            for (;;) {
                auto payload = read_payload(socket);
                if (!payload) {
                    return std::unexpected(std::move(payload.error()));
                }
                if (!payload->has_value()) {
                    break;
                }

                auto request = protocol::decode_fact_batch_request(**payload);
                if (!request) {
                    return std::unexpected(std::move(request.error()));
                }
                auto response = protocol::encode_fact_batch_response(
                    handle_client_fact_batch_with_fixtures(*request, pattern_fixtures, options.extra_fact_handler));
                if (!response) {
                    return std::unexpected(std::move(response.error()));
                }
                if (auto result = write_payload(socket, *response); !result) {
                    return result;
                }
            }
            close_socket(socket);
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
                            const std::vector<protocol::FactBatchRequestMessage> &requests) {
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
        };
        session.responses.reserve(requests.size());

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

        close_socket(socket);
        return session;
    }

    std::expected<ClientEvaluationSession, ErrorSet>
    evaluate_subject_with_client(const ClientConnectionOptions &options, const VerifiedProgram &program, const Subject &subject) {
        auto multi = evaluate_subjects_with_client(options,
                                                 program,
                                                 std::vector<Subject> {subject},
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
    evaluate_subjects_with_client(const ClientConnectionOptions &options,
                                const VerifiedProgram &program,
                                const std::vector<Subject> &subjects,
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

            for (std::size_t round = 0; round < max_rounds; ++round) {
                bool all_complete {true};
                std::vector<protocol::FactBatchRequestMessage> requests;
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
                        return std::unexpected(single_error("client.evaluator", "evaluation waited without fact requests"));
                    }
                    for (const auto &batch : step.requests) {
                        add_fact_request(requests, state.subject, batch);
                    }
                }

                if (all_complete) {
                    break;
                }
                if (requests.empty()) {
                    return std::unexpected(single_error("client.evaluator", "evaluation had no provider requests"));
                }

                for (const auto &request : requests) {
                    if (auto valid = validate_request_capability(session.handshake, request); !valid) {
                        return std::unexpected(std::move(valid.error()));
                    }
                    auto response = send_request_and_read_response(socket, request);
                    if (!response) {
                        return std::unexpected(std::move(response.error()));
                    }
                    for (const auto &fact : response->values) {
                        store_fact_for_matching_subjects(states, fact);
                    }
                }
            }

            for (auto &state : states) {
                if (!state.final_step.has_value()) {
                    return std::unexpected(single_error("client.evaluator",
                                                        "evaluation did not converge after provider rounds"));
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
} // namespace rule_engine::client_protocol
