#include <rule_engine/client_protocol.hpp>
#include <rule_engine/protocol.hpp>
#include <rule_engine/modules.hpp>
#include <rule_engine/windows/pe_provider.hpp>
#include <rule_engine/windows/process_provider.hpp>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <asio/io_context.hpp>
#include <asio/ip/address.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/read.hpp>
#include <asio/write.hpp>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <expected>
#include <filesystem>
#include <fstream>
#include <future>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace {
    [[nodiscard]] std::optional<rule_engine::Fact> find_fact(const std::vector<rule_engine::Fact> &facts,
                                                             const std::string_view key) {
        const auto found = std::ranges::find_if(facts, [&](const auto &fact) { return fact.key == key; });
        if (found == facts.end()) {
            return std::nullopt;
        }
        return *found;
    }

    [[nodiscard]] std::optional<std::string> write_protocol_frame(asio::ip::tcp::socket &socket,
                                                                  const std::vector<std::byte> &payload) {
        auto frame = rule_engine::protocol::encode_frame(payload);
        if (!frame) {
            return frame.error().diagnostics.empty() ? std::string {"frame encode failed"}
                                                     : frame.error().diagnostics[0].message;
        }
        asio::error_code ec;
        asio::write(socket, asio::buffer(frame->data(), frame->size()), ec);
        if (ec) {
            return ec.message();
        }
        return std::nullopt;
    }

    [[nodiscard]] std::expected<std::vector<std::byte>, std::string>
    read_protocol_frame(asio::ip::tcp::socket &socket) {
        std::array<std::byte, 4u> header {};
        asio::error_code ec;
        asio::read(socket, asio::buffer(header.data(), header.size()), ec);
        if (ec) {
            return std::unexpected(ec.message());
        }
        const auto size = (static_cast<std::uint32_t>(header[0]) << 24u) |
                          (static_cast<std::uint32_t>(header[1]) << 16u) |
                          (static_cast<std::uint32_t>(header[2]) << 8u) | static_cast<std::uint32_t>(header[3]);
        std::vector<std::byte> payload(size);
        if (!payload.empty()) {
            asio::read(socket, asio::buffer(payload.data(), payload.size()), ec);
            if (ec) {
                return std::unexpected(ec.message());
            }
        }
        return payload;
    }

    void append_u8(std::vector<std::byte> &out, const std::uint8_t value) {
        out.push_back(static_cast<std::byte>(value));
    }

    void append_u32(std::vector<std::byte> &out, const std::uint32_t value) {
        out.push_back(static_cast<std::byte>(value & 0xffu));
        out.push_back(static_cast<std::byte>((value >> 8u) & 0xffu));
        out.push_back(static_cast<std::byte>((value >> 16u) & 0xffu));
        out.push_back(static_cast<std::byte>((value >> 24u) & 0xffu));
    }

    void append_string(std::vector<std::byte> &out, const std::string_view value) {
        append_u32(out, static_cast<std::uint32_t>(value.size()));
        for (const auto ch : value) {
            out.push_back(static_cast<std::byte>(static_cast<unsigned char>(ch)));
        }
    }

    void append_protocol_header(std::vector<std::byte> &out, const std::uint8_t kind) {
        out.push_back(static_cast<std::byte>('R'));
        out.push_back(static_cast<std::byte>('E'));
        out.push_back(static_cast<std::byte>('P'));
        out.push_back(static_cast<std::byte>('V'));
        append_u8(out, kind);
        append_u32(out, 1u);
    }
} // namespace

TEST_CASE("protocol frame codec round-trips binary payloads") {
    const std::vector<std::byte> payload {
        std::byte {0x00},
        std::byte {0x7f},
        std::byte {0xff},
    };

    const auto encoded = rule_engine::protocol::encode_frame(payload);
    REQUIRE(encoded.has_value());

    auto decoded = rule_engine::protocol::try_decode_frame(*encoded);
    REQUIRE(decoded.has_value());
    CHECK(decoded->payload == payload);
    CHECK(decoded->bytes_consumed == encoded->size());
}

TEST_CASE("protocol typed messages round-trip handshake subjects and fact batches") {
    rule_engine::protocol::HandshakeMessage handshake;
    handshake.protocol = "rule-engine-client";
    handshake.version = 1u;
    handshake.capabilities.push_back(rule_engine::protocol::Capability {.route = "endpoint.process.snapshot"});
    handshake.capabilities.push_back(rule_engine::protocol::Capability {.route = "endpoint.scan.patterns"});

    const auto handshake_payload = rule_engine::protocol::encode_handshake(handshake);
    REQUIRE(handshake_payload.has_value());
    const auto decoded_handshake = rule_engine::protocol::decode_handshake(*handshake_payload);
    REQUIRE(decoded_handshake.has_value());
    CHECK(decoded_handshake->protocol == "rule-engine-client");
    CHECK(decoded_handshake->version == 1u);
    REQUIRE(decoded_handshake->capabilities.size() == 2u);
    CHECK(decoded_handshake->capabilities[0].route == "endpoint.process.snapshot");
    CHECK(decoded_handshake->capabilities[1].route == "endpoint.scan.patterns");

    rule_engine::protocol::SubjectListMessage subjects;
    subjects.subjects.push_back(rule_engine::Subject {.kind = "process", .id = "pid:1"});
    subjects.subjects.push_back(rule_engine::Subject {.kind = "process", .id = "pid:2"});
    const auto subject_payload = rule_engine::protocol::encode_subject_list(subjects);
    REQUIRE(subject_payload.has_value());
    const auto decoded_subjects = rule_engine::protocol::decode_subject_list(*subject_payload);
    REQUIRE(decoded_subjects.has_value());
    REQUIRE(decoded_subjects->subjects.size() == 2u);
    CHECK(decoded_subjects->subjects[0].id == "pid:1");
    CHECK(decoded_subjects->subjects[1].id == "pid:2");

    rule_engine::protocol::FactBatchRequestMessage request;
    request.route = "endpoint.process.snapshot";
    request.timeout = std::chrono::milliseconds {2500};
    request.keys.push_back(rule_engine::protocol::FactKey {.subject_id = "pid:1", .key = "process.name"});
    request.keys.push_back(rule_engine::protocol::FactKey {.subject_id = "pid:1", .key = "process.pid"});
    const auto request_payload = rule_engine::protocol::encode_fact_batch_request(request);
    REQUIRE(request_payload.has_value());
    const auto decoded_request = rule_engine::protocol::decode_fact_batch_request(*request_payload);
    REQUIRE(decoded_request.has_value());
    CHECK(decoded_request->route == "endpoint.process.snapshot");
    CHECK(decoded_request->timeout == std::chrono::milliseconds {2500});
    REQUIRE(decoded_request->keys.size() == 2u);
    CHECK(decoded_request->keys[0].subject_id == "pid:1");
    CHECK(decoded_request->keys[1].key == "process.pid");

    rule_engine::protocol::FactBatchResponseMessage response;
    response.route = "endpoint.process.snapshot";
    response.values.push_back(rule_engine::Fact {
        .subject_id = "pid:1",
        .key = "process.name",
        .value = rule_engine::Value::string("cmd.exe"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {0},
    });
    response.values.push_back(rule_engine::Fact {
        .subject_id = "pid:1",
        .key = "process.pid",
        .value = rule_engine::Value::integer(1),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {0},
    });
    const auto response_payload = rule_engine::protocol::encode_fact_batch_response(response);
    REQUIRE(response_payload.has_value());
    const auto decoded_response = rule_engine::protocol::decode_fact_batch_response(*response_payload);
    REQUIRE(decoded_response.has_value());
    CHECK(decoded_response->route == "endpoint.process.snapshot");
    REQUIRE(decoded_response->values.size() == 2u);
    CHECK(decoded_response->values[0].value.as_string() != nullptr);
    CHECK(*decoded_response->values[0].value.as_string() == "cmd.exe");
    CHECK(decoded_response->values[1].value.as_i64() == 1);
}

TEST_CASE("protocol typed messages round-trip pattern fact metadata") {
    rule_engine::PatternValue pattern;
    pattern.matched = true;
    pattern.matches.push_back(rule_engine::PatternMatchContext {
        .offset = 128u,
        .length = 4u,
        .bytes = {std::byte {'t'}, std::byte {'e'}, std::byte {'s'}, std::byte {'t'}},
        .before = {std::byte {'>'}},
        .after = {std::byte {'<'}},
        .scan_space = "process.memory",
        .region_permissions = "rx",
    });

    rule_engine::protocol::FactBatchResponseMessage response;
    response.route = "endpoint.scan.patterns";
    response.values.push_back(rule_engine::Fact {
        .subject_id = "pid:1",
        .key = "$a.pattern",
        .value = rule_engine::Value::pattern(std::move(pattern)),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {0},
    });

    const auto encoded = rule_engine::protocol::encode_fact_batch_response(response);
    REQUIRE(encoded.has_value());
    const auto decoded = rule_engine::protocol::decode_fact_batch_response(*encoded);
    REQUIRE(decoded.has_value());
    REQUIRE(decoded->values.size() == 1u);
    const auto *decoded_pattern = decoded->values[0].value.as_pattern();
    REQUIRE(decoded_pattern != nullptr);
    CHECK(decoded_pattern->matched);
    REQUIRE(decoded_pattern->matches.size() == 1u);
    CHECK(decoded_pattern->matches[0].offset == 128u);
    CHECK(decoded_pattern->matches[0].length == 4u);
    CHECK(decoded_pattern->matches[0].bytes == std::vector<std::byte> {
                                             std::byte {'t'}, std::byte {'e'}, std::byte {'s'}, std::byte {'t'}});
    CHECK(decoded_pattern->matches[0].before == std::vector<std::byte> {std::byte {'>'}});
    CHECK(decoded_pattern->matches[0].after == std::vector<std::byte> {std::byte {'<'}});
    CHECK(decoded_pattern->matches[0].scan_space == "process.memory");
    CHECK(decoded_pattern->matches[0].region_permissions == "rx");
}

TEST_CASE("protocol decoders reject oversized counts before reading entries") {
    std::vector<std::byte> subjects;
    append_protocol_header(subjects, 2u);
    append_u32(subjects, 100000u);

    const auto decoded_subjects = rule_engine::protocol::decode_subject_list(subjects);
    REQUIRE_FALSE(decoded_subjects.has_value());
    REQUIRE_FALSE(decoded_subjects.error().diagnostics.empty());
    CHECK(decoded_subjects.error().diagnostics[0].message.find("count exceeds") != std::string::npos);

    std::vector<std::byte> response;
    append_protocol_header(response, 4u);
    append_string(response, "endpoint.scan.patterns");
    append_u32(response, 1u);
    append_string(response, "pid:1");
    append_string(response, "$a.pattern");
    append_u8(response, 1u);
    append_u8(response, 5u);
    append_u8(response, 1u);
    append_u32(response, 100000u);
    append_string(response, {});
    append_u32(response, 30u);

    const auto decoded_response = rule_engine::protocol::decode_fact_batch_response(response);
    REQUIRE_FALSE(decoded_response.has_value());
    REQUIRE_FALSE(decoded_response.error().diagnostics.empty());
    CHECK(decoded_response.error().diagnostics[0].message.find("count exceeds") != std::string::npos);
}

TEST_CASE("Windows PE provider extracts image facts from the current executable") {
    std::wstring path;
    path.resize(32768u);
    const auto size = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    REQUIRE(size > 0u);
    path.resize(size);

    auto facts = rule_engine::windows::read_pe_image_facts("pid:self", std::filesystem::path {path});
    REQUIRE(facts.has_value());

    const auto valid = find_fact(*facts, "pe.is_valid");
    REQUIRE(valid.has_value());
    CHECK(valid->status == rule_engine::FactStatus::available);
    CHECK(valid->value.as_bool() == true);

    const auto machine = find_fact(*facts, "pe.machine");
    REQUIRE(machine.has_value());
    CHECK(machine->status == rule_engine::FactStatus::available);
    CHECK(machine->value.as_i64().value_or(0) > 0);

    const auto sections = find_fact(*facts, "pe.number_of_sections");
    REQUIRE(sections.has_value());
    CHECK(sections->status == rule_engine::FactStatus::available);
    CHECK(sections->value.as_i64().value_or(0) > 0);

    const auto image_size = find_fact(*facts, "pe.size_of_image");
    REQUIRE(image_size.has_value());
    CHECK(image_size->status == rule_engine::FactStatus::available);
    CHECK(image_size->value.as_i64().value_or(0) > 0);
}

TEST_CASE("Windows process provider can enumerate at least the current process") {
    auto subjects = rule_engine::windows::enumerate_process_subjects();
    REQUIRE(subjects.has_value());
    CHECK_FALSE(subjects->empty());
}

TEST_CASE("localhost client session advertises subjects and returns process and PE facts") {
    std::promise<std::uint16_t> listening_port;
    auto listening = listening_port.get_future();
    std::optional<rule_engine::ErrorSet> server_error;

    std::thread server {[&] {
        auto result = rule_engine::client_protocol::serve_client_once(
            rule_engine::client_protocol::ClientListenOptions {
                .bind_address = "127.0.0.1",
                .port = 0u,
                .pattern_fixture_path = {},
                .io_timeout = std::chrono::milliseconds {5000},
            },
            [&](const std::uint16_t port) { listening_port.set_value(port); });
        if (!result) {
            server_error = std::move(result.error());
        }
    }};

    REQUIRE(listening.wait_for(std::chrono::seconds {5}) == std::future_status::ready);
    const auto port = listening.get();

    const auto current_subject_id = "pid:" + std::to_string(GetCurrentProcessId());
    rule_engine::protocol::FactBatchRequestMessage process_request;
    process_request.route = "endpoint.process.snapshot";
    process_request.keys.push_back(rule_engine::protocol::FactKey {
        .subject_id = current_subject_id,
        .key = "process.pid",
    });
    process_request.keys.push_back(rule_engine::protocol::FactKey {
        .subject_id = current_subject_id,
        .key = "process.name",
    });

    rule_engine::protocol::FactBatchRequestMessage pe_request;
    pe_request.route = "endpoint.process.image.pe";
    pe_request.keys.push_back(rule_engine::protocol::FactKey {
        .subject_id = current_subject_id,
        .key = "pe.is_valid",
    });
    pe_request.keys.push_back(rule_engine::protocol::FactKey {
        .subject_id = current_subject_id,
        .key = "pe.number_of_sections",
    });

    auto session = rule_engine::client_protocol::run_client_session(
        rule_engine::client_protocol::ClientConnectionOptions {
            .host = "127.0.0.1",
            .port = port,
            .io_timeout = std::chrono::milliseconds {5000},
        },
        std::vector<rule_engine::protocol::FactBatchRequestMessage> {process_request, pe_request});
    REQUIRE(session.has_value());

    server.join();
    REQUIRE_FALSE(server_error.has_value());

    CHECK(session->handshake.protocol == "rule-engine-client");
    CHECK(session->handshake.version == 1u);
    CHECK(std::ranges::any_of(session->handshake.capabilities, [](const auto &capability) {
        return capability.route == "endpoint.process.snapshot";
    }));
    CHECK(std::ranges::any_of(session->handshake.capabilities, [](const auto &capability) {
        return capability.route == "endpoint.process.image.pe";
    }));
    CHECK(std::ranges::any_of(session->subjects.subjects, [&](const auto &subject) {
        return subject.kind == "process" && subject.id == current_subject_id;
    }));

    REQUIRE(session->responses.size() == 2u);
    REQUIRE(session->responses[0].values.size() == 2u);
    CHECK(session->responses[0].values[0].key == "process.pid");
    CHECK(session->responses[0].values[0].status == rule_engine::FactStatus::available);
    CHECK(session->responses[0].values[0].value.as_i64() == static_cast<std::int64_t>(GetCurrentProcessId()));
    CHECK(session->responses[0].values[1].key == "process.name");
    CHECK(session->responses[0].values[1].status == rule_engine::FactStatus::available);
    CHECK(session->responses[0].values[1].value.as_string() != nullptr);

    REQUIRE(session->responses[1].values.size() == 2u);
    CHECK(session->responses[1].values[0].key == "pe.is_valid");
    CHECK(session->responses[1].values[0].status == rule_engine::FactStatus::available);
    CHECK(session->responses[1].values[0].value.as_bool() == true);
    CHECK(session->responses[1].values[1].key == "pe.number_of_sections");
    CHECK(session->responses[1].values[1].status == rule_engine::FactStatus::available);
    CHECK(session->responses[1].values[1].value.as_i64().value_or(0) > 0);
}

TEST_CASE("client connection times out when handshake is not received") {
    using namespace std::chrono_literals;
    using asio::ip::tcp;

    std::promise<std::uint16_t> listening_port;
    auto listening = listening_port.get_future();
    std::optional<asio::error_code> server_error;

    std::thread server {[&] {
        asio::io_context io;
        asio::error_code ec;
        tcp::acceptor acceptor {io};
        const tcp::endpoint endpoint {asio::ip::make_address("127.0.0.1", ec), 0u};
        if (ec) {
            server_error = ec;
            listening_port.set_value(0u);
            return;
        }
        acceptor.open(endpoint.protocol(), ec);
        if (ec) {
            server_error = ec;
            listening_port.set_value(0u);
            return;
        }
        acceptor.set_option(tcp::acceptor::reuse_address(true), ec);
        if (ec) {
            server_error = ec;
            listening_port.set_value(0u);
            return;
        }
        acceptor.bind(endpoint, ec);
        if (ec) {
            server_error = ec;
            listening_port.set_value(0u);
            return;
        }
        acceptor.listen(asio::socket_base::max_listen_connections, ec);
        if (ec) {
            server_error = ec;
            listening_port.set_value(0u);
            return;
        }
        const auto local = acceptor.local_endpoint(ec);
        if (ec) {
            server_error = ec;
            listening_port.set_value(0u);
            return;
        }
        listening_port.set_value(local.port());
        tcp::socket socket {io};
        acceptor.accept(socket, ec);
        if (ec) {
            server_error = ec;
            return;
        }
        std::this_thread::sleep_for(400ms);
    }};

    REQUIRE(listening.wait_for(5s) == std::future_status::ready);
    const auto port = listening.get();
    REQUIRE(port != 0u);

    auto session = rule_engine::client_protocol::run_client_session(
        rule_engine::client_protocol::ClientConnectionOptions {
            .host = "127.0.0.1",
            .port = port,
            .io_timeout = 100ms,
        },
        {});

    server.join();
    REQUIRE_FALSE(server_error.has_value());
    REQUIRE_FALSE(session.has_value());
    REQUIRE_FALSE(session.error().diagnostics.empty());
    CHECK(session.error().diagnostics[0].message.find("timed out") != std::string::npos);
}

TEST_CASE("client connection applies fact request timeout while waiting for a response") {
    using namespace std::chrono_literals;
    using asio::ip::tcp;

    std::promise<std::uint16_t> listening_port;
    auto listening = listening_port.get_future();
    std::optional<std::string> server_error;

    std::thread server {[&] {
        asio::io_context io;
        asio::error_code ec;
        tcp::acceptor acceptor {io};
        const tcp::endpoint endpoint {asio::ip::make_address("127.0.0.1", ec), 0u};
        if (ec) {
            server_error = ec.message();
            listening_port.set_value(0u);
            return;
        }
        acceptor.open(endpoint.protocol(), ec);
        if (ec) {
            server_error = ec.message();
            listening_port.set_value(0u);
            return;
        }
        acceptor.set_option(tcp::acceptor::reuse_address(true), ec);
        if (ec) {
            server_error = ec.message();
            listening_port.set_value(0u);
            return;
        }
        acceptor.bind(endpoint, ec);
        if (ec) {
            server_error = ec.message();
            listening_port.set_value(0u);
            return;
        }
        acceptor.listen(asio::socket_base::max_listen_connections, ec);
        if (ec) {
            server_error = ec.message();
            listening_port.set_value(0u);
            return;
        }
        const auto local = acceptor.local_endpoint(ec);
        if (ec) {
            server_error = ec.message();
            listening_port.set_value(0u);
            return;
        }
        listening_port.set_value(local.port());

        tcp::socket socket {io};
        acceptor.accept(socket, ec);
        if (ec) {
            server_error = ec.message();
            return;
        }

        rule_engine::protocol::HandshakeMessage handshake;
        handshake.protocol = "rule-engine-client";
        handshake.version = 1u;
        handshake.capabilities.push_back(rule_engine::protocol::Capability {.route = "endpoint.process.snapshot"});
        auto handshake_payload = rule_engine::protocol::encode_handshake(handshake);
        if (!handshake_payload) {
            server_error = "handshake encode failed";
            return;
        }
        if (auto error = write_protocol_frame(socket, *handshake_payload); error.has_value()) {
            server_error = std::move(*error);
            return;
        }

        rule_engine::protocol::SubjectListMessage subjects;
        subjects.subjects.push_back(rule_engine::Subject {.kind = "process", .id = "pid:self"});
        auto subjects_payload = rule_engine::protocol::encode_subject_list(subjects);
        if (!subjects_payload) {
            server_error = "subject list encode failed";
            return;
        }
        if (auto error = write_protocol_frame(socket, *subjects_payload); error.has_value()) {
            server_error = std::move(*error);
            return;
        }

        std::this_thread::sleep_for(1200ms);
    }};

    REQUIRE(listening.wait_for(5s) == std::future_status::ready);
    const auto port = listening.get();
    REQUIRE(port != 0u);

    rule_engine::protocol::FactBatchRequestMessage request;
    request.route = "endpoint.process.snapshot";
    request.timeout = 100ms;
    request.keys.push_back(rule_engine::protocol::FactKey {
        .subject_id = "pid:self",
        .key = "process.pid",
    });

    const auto started = std::chrono::steady_clock::now();
    auto session = rule_engine::client_protocol::run_client_session(
        rule_engine::client_protocol::ClientConnectionOptions {
            .host = "127.0.0.1",
            .port = port,
            .io_timeout = 2500ms,
        },
        std::vector<rule_engine::protocol::FactBatchRequestMessage> {request});
    const auto elapsed = std::chrono::steady_clock::now() - started;

    server.join();
    REQUIRE_FALSE(server_error.has_value());
    REQUIRE_FALSE(session.has_value());
    REQUIRE_FALSE(session.error().diagnostics.empty());
    CHECK(session.error().diagnostics[0].message.find("timed out") != std::string::npos);
    CHECK(elapsed < 1s);
}

TEST_CASE("client evaluator rejects provider responses with unrequested facts") {
    using namespace std::chrono_literals;
    using asio::ip::tcp;

    constexpr std::string_view source = R"(
import "process"

global rule allow_scan {
    condition:
        scan_mode == "on"
}

rule injected_process_name {
    condition:
        process.name == "evil.exe"
}
)";

    rule_engine::ModuleRegistry registry = rule_engine::default_module_registry();
    registry.globals.push_back(rule_engine::GlobalDescriptor {
        .name = "scan_mode",
        .type = rule_engine::ValueType::string,
        .key = "global.scan_mode",
        .route = "endpoint.globals",
        .ttl = std::chrono::seconds {30},
        .cheap_prefetch = true,
    });

    auto parsed = rule_engine::parse_source("injected_fact.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, registry);
    REQUIRE(verified.has_value());

    std::promise<std::uint16_t> listening_port;
    auto listening = listening_port.get_future();
    std::optional<std::string> server_error;

    std::thread server {[&] {
        asio::io_context io;
        asio::error_code ec;
        tcp::acceptor acceptor {io};
        const tcp::endpoint endpoint {asio::ip::make_address("127.0.0.1", ec), 0u};
        if (ec) {
            server_error = ec.message();
            listening_port.set_value(0u);
            return;
        }
        acceptor.open(endpoint.protocol(), ec);
        if (ec) {
            server_error = ec.message();
            listening_port.set_value(0u);
            return;
        }
        acceptor.set_option(tcp::acceptor::reuse_address(true), ec);
        if (ec) {
            server_error = ec.message();
            listening_port.set_value(0u);
            return;
        }
        acceptor.bind(endpoint, ec);
        if (ec) {
            server_error = ec.message();
            listening_port.set_value(0u);
            return;
        }
        acceptor.listen(asio::socket_base::max_listen_connections, ec);
        if (ec) {
            server_error = ec.message();
            listening_port.set_value(0u);
            return;
        }
        const auto local = acceptor.local_endpoint(ec);
        if (ec) {
            server_error = ec.message();
            listening_port.set_value(0u);
            return;
        }
        listening_port.set_value(local.port());

        tcp::socket socket {io};
        acceptor.accept(socket, ec);
        if (ec) {
            server_error = ec.message();
            return;
        }

        rule_engine::protocol::HandshakeMessage handshake;
        handshake.protocol = "rule-engine-client";
        handshake.version = 1u;
        handshake.capabilities.push_back(rule_engine::protocol::Capability {.route = "endpoint.globals"});
        handshake.capabilities.push_back(rule_engine::protocol::Capability {.route = "endpoint.process.snapshot"});
        auto handshake_payload = rule_engine::protocol::encode_handshake(handshake);
        if (!handshake_payload || write_protocol_frame(socket, *handshake_payload).has_value()) {
            server_error = "handshake write failed";
            return;
        }

        rule_engine::protocol::SubjectListMessage subjects;
        subjects.subjects.push_back(rule_engine::Subject {.kind = "process", .id = "pid:1"});
        auto subjects_payload = rule_engine::protocol::encode_subject_list(subjects);
        if (!subjects_payload || write_protocol_frame(socket, *subjects_payload).has_value()) {
            server_error = "subject write failed";
            return;
        }

        auto request_payload = read_protocol_frame(socket);
        if (!request_payload) {
            server_error = std::move(request_payload.error());
            return;
        }

        rule_engine::protocol::FactBatchResponseMessage response;
        response.route = "endpoint.globals";
        response.values.push_back(rule_engine::Fact {
            .subject_id = "pid:1",
            .key = "global.scan_mode",
            .value = rule_engine::Value::string("on"),
            .status = rule_engine::FactStatus::available,
            .diagnostic = {},
            .ttl = std::chrono::seconds {30},
        });
        response.values.push_back(rule_engine::Fact {
            .subject_id = "pid:1",
            .key = "process.name",
            .value = rule_engine::Value::string("evil.exe"),
            .status = rule_engine::FactStatus::available,
            .diagnostic = {},
            .ttl = std::chrono::seconds {0},
        });
        auto response_payload = rule_engine::protocol::encode_fact_batch_response(response);
        if (!response_payload || write_protocol_frame(socket, *response_payload).has_value()) {
            server_error = "fact response write failed";
        }
    }};

    REQUIRE(listening.wait_for(5s) == std::future_status::ready);
    const auto port = listening.get();
    REQUIRE(port != 0u);

    auto evaluation = rule_engine::client_protocol::evaluate_subject_with_client(
        rule_engine::client_protocol::ClientConnectionOptions {
            .host = "127.0.0.1",
            .port = port,
            .io_timeout = 2500ms,
        },
        *verified,
        rule_engine::Subject {.kind = "process", .id = "pid:1"});

    server.join();
    REQUIRE_FALSE(server_error.has_value());
    REQUIRE_FALSE(evaluation.has_value());
    REQUIRE_FALSE(evaluation.error().diagnostics.empty());
    CHECK(evaluation.error().diagnostics[0].message.find("unrequested fact") != std::string::npos);
}

TEST_CASE("localhost client session resolves custom module function facts") {
    constexpr std::string_view source = R"(
import "process"
import "demo"

rule custom_module_function {
    condition:
        demo.score(process.pid, "alpha") > 7
}
)";
    rule_engine::ModuleRegistry registry = rule_engine::default_module_registry();
    registry.modules.push_back(rule_engine::ModuleDescriptor {
        .name = "demo",
        .fields = {},
        .functions = {
            rule_engine::FunctionDescriptor {
                .name = "score",
                .parameters = {rule_engine::ValueType::integer, rule_engine::ValueType::string},
                .return_type = rule_engine::ValueType::integer,
                .key_prefix = "demo.score",
                .route = "endpoint.demo.functions",
                .ttl = std::chrono::seconds {30},
                .cheap_prefetch = false,
            },
        },
    });

    auto parsed = rule_engine::parse_source("custom_function_eval.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, registry);
    REQUIRE(verified.has_value());

    std::promise<std::uint16_t> listening_port;
    auto listening = listening_port.get_future();
    std::optional<rule_engine::ErrorSet> server_error;
    std::string observed_route;
    std::vector<std::string> observed_keys;

    std::thread server {[&] {
        auto result = rule_engine::client_protocol::serve_client_once(
            rule_engine::client_protocol::ClientListenOptions {
                .bind_address = "127.0.0.1",
                .port = 0u,
                .pattern_fixture_path = {},
                .io_timeout = std::chrono::milliseconds {5000},
                .extra_fact_handler = [&](const rule_engine::protocol::FactBatchRequestMessage &request)
                    -> std::optional<rule_engine::protocol::FactBatchResponseMessage> {
                    if (request.route != "endpoint.demo.functions") {
                        return std::nullopt;
                    }

                    observed_route = request.route;
                    rule_engine::protocol::FactBatchResponseMessage response;
                    response.route = request.route;
                    response.values.reserve(request.keys.size());
                    for (const auto &key : request.keys) {
                        observed_keys.push_back(key.key);
                        response.values.push_back(rule_engine::Fact {
                            .subject_id = key.subject_id,
                            .key = key.key,
                            .value = rule_engine::Value::integer(9),
                            .status = rule_engine::FactStatus::available,
                            .diagnostic = {},
                            .ttl = std::chrono::seconds {30},
                        });
                    }
                    return response;
                },
            },
            [&](const std::uint16_t port) { listening_port.set_value(port); });
        if (!result) {
            server_error = std::move(result.error());
        }
    }};

    REQUIRE(listening.wait_for(std::chrono::seconds {5}) == std::future_status::ready);
    const auto port = listening.get();
    auto evaluation = rule_engine::client_protocol::evaluate_subject_with_client(
        rule_engine::client_protocol::ClientConnectionOptions {
            .host = "127.0.0.1",
            .port = port,
            .io_timeout = std::chrono::milliseconds {5000},
        },
        *verified,
        rule_engine::Subject {
            .kind = "process",
            .id = "pid:" + std::to_string(GetCurrentProcessId()),
        });
    REQUIRE(evaluation.has_value());

    server.join();
    REQUIRE_FALSE(server_error.has_value());

    CHECK(observed_route == "endpoint.demo.functions");
    CHECK(observed_keys == std::vector<std::string> {
                               "demo.score(i:" + std::to_string(GetCurrentProcessId()) + ",s:alpha)"});
    CHECK(evaluation->final_step.state == rule_engine::EvaluationState::complete);
    REQUIRE(evaluation->final_step.rule_results.size() == 1u);
    CHECK(evaluation->final_step.rule_results[0].identifier == "custom_module_function");
    CHECK(evaluation->final_step.rule_results[0].matched);
}

TEST_CASE("localhost client session resumes VM evaluation with provider facts") {
    constexpr std::string_view source = R"(
import "process"
import "pe"

rule current_test_process {
    condition:
        process.name == "rule_engine_tests.exe" and pe.number_of_sections > 0
}
)";
    auto parsed = rule_engine::parse_source("client_eval.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());

    std::promise<std::uint16_t> listening_port;
    auto listening = listening_port.get_future();
    std::optional<rule_engine::ErrorSet> server_error;

    std::thread server {[&] {
        auto result = rule_engine::client_protocol::serve_client_once(
            rule_engine::client_protocol::ClientListenOptions {
                .bind_address = "127.0.0.1",
                .port = 0u,
                .pattern_fixture_path = {},
                .io_timeout = std::chrono::milliseconds {5000},
            },
            [&](const std::uint16_t port) { listening_port.set_value(port); });
        if (!result) {
            server_error = std::move(result.error());
        }
    }};

    REQUIRE(listening.wait_for(std::chrono::seconds {5}) == std::future_status::ready);
    const auto port = listening.get();
    auto evaluation = rule_engine::client_protocol::evaluate_subject_with_client(
        rule_engine::client_protocol::ClientConnectionOptions {
            .host = "127.0.0.1",
            .port = port,
            .io_timeout = std::chrono::milliseconds {5000},
        },
        *verified,
        rule_engine::Subject {
            .kind = "process",
            .id = "pid:" + std::to_string(GetCurrentProcessId()),
        });
    REQUIRE(evaluation.has_value());

    server.join();
    REQUIRE_FALSE(server_error.has_value());

    CHECK(evaluation->final_step.state == rule_engine::EvaluationState::complete);
    REQUIRE(evaluation->final_step.rule_results.size() == 1u);
    CHECK(evaluation->final_step.rule_results[0].identifier == "current_test_process");
    CHECK(evaluation->final_step.rule_results[0].matched);
}

TEST_CASE("localhost client session evaluates multiple subjects with provider batching") {
    constexpr std::string_view source = R"(
import "process"

rule has_pid {
    condition:
        process.pid > 0
}
)";
    auto parsed = rule_engine::parse_source("client_multi_eval.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());

    std::promise<std::uint16_t> listening_port;
    auto listening = listening_port.get_future();
    std::optional<rule_engine::ErrorSet> server_error;

    std::thread server {[&] {
        auto result = rule_engine::client_protocol::serve_client_once(
            rule_engine::client_protocol::ClientListenOptions {
                .bind_address = "127.0.0.1",
                .port = 0u,
                .pattern_fixture_path = {},
                .io_timeout = std::chrono::milliseconds {5000},
            },
            [&](const std::uint16_t port) { listening_port.set_value(port); });
        if (!result) {
            server_error = std::move(result.error());
        }
    }};

    REQUIRE(listening.wait_for(std::chrono::seconds {5}) == std::future_status::ready);
    const auto port = listening.get();
    auto evaluation = rule_engine::client_protocol::evaluate_subjects_with_client(
        rule_engine::client_protocol::ClientConnectionOptions {
            .host = "127.0.0.1",
            .port = port,
            .io_timeout = std::chrono::milliseconds {5000},
        },
        *verified,
        std::vector<rule_engine::Subject> {
            rule_engine::Subject {
                .kind = "process",
                .id = "pid:" + std::to_string(GetCurrentProcessId()),
            },
            rule_engine::Subject {
                .kind = "process",
                .id = "pid:0",
            },
        },
        rule_engine::client_protocol::ClientEvaluationOptions {
            .max_subject_concurrency = 2u,
        });
    REQUIRE(evaluation.has_value());

    server.join();
    REQUIRE_FALSE(server_error.has_value());

    CHECK(evaluation->evaluations.size() == 2u);
    REQUIRE(evaluation->evaluations[0].final_step.rule_results.size() == 1u);
    CHECK(evaluation->evaluations[0].subject.id == "pid:" + std::to_string(GetCurrentProcessId()));
    CHECK(evaluation->evaluations[0].final_step.rule_results[0].identifier == "has_pid");
    CHECK(evaluation->evaluations[0].final_step.rule_results[0].matched);
    CHECK(evaluation->evaluations[1].subject.id == "pid:0");
    CHECK(evaluation->evaluations[1].final_step.state == rule_engine::EvaluationState::complete);
}

TEST_CASE("localhost client session evaluates fixture-backed pattern facts") {
    constexpr std::string_view source = R"(
rule fixture_pattern {
    strings:
        $needle = "needle" ascii
    condition:
        $needle and #needle == 1 and @needle[1] == 4096 and !needle[1] == 6
}
)";
    auto parsed = rule_engine::parse_source("client_pattern_eval.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());

    std::promise<std::uint16_t> listening_port;
    auto listening = listening_port.get_future();
    std::optional<rule_engine::ErrorSet> server_error;

    std::thread server {[&] {
        auto result = rule_engine::client_protocol::serve_client_once(
            rule_engine::client_protocol::ClientListenOptions {
                .bind_address = "127.0.0.1",
                .port = 0u,
                .pattern_fixture_path = {},
                .io_timeout = std::chrono::milliseconds {5000},
            },
            [&](const std::uint16_t port) { listening_port.set_value(port); });
        if (!result) {
            server_error = std::move(result.error());
        }
    }};

    REQUIRE(listening.wait_for(std::chrono::seconds {5}) == std::future_status::ready);
    const auto port = listening.get();
    auto evaluation = rule_engine::client_protocol::evaluate_subject_with_client(
        rule_engine::client_protocol::ClientConnectionOptions {
            .host = "127.0.0.1",
            .port = port,
            .io_timeout = std::chrono::milliseconds {5000},
        },
        *verified,
        rule_engine::Subject {
            .kind = "process",
            .id = "pid:" + std::to_string(GetCurrentProcessId()),
        });
    REQUIRE(evaluation.has_value());

    server.join();
    REQUIRE_FALSE(server_error.has_value());

    CHECK(evaluation->final_step.state == rule_engine::EvaluationState::complete);
    REQUIRE(evaluation->final_step.rule_results.size() == 1u);
    CHECK(evaluation->final_step.rule_results[0].identifier == "fixture_pattern");
    CHECK(evaluation->final_step.rule_results[0].matched);
}

TEST_CASE("localhost client session evaluates configured pattern fixture facts") {
    const auto fixture_path =
        std::filesystem::temp_directory_path() / ("rule-engine-pattern-fixture-" +
                                                 std::to_string(GetCurrentProcessId()) + ".txt");
    {
        std::ofstream fixture {fixture_path};
        REQUIRE(fixture);
        fixture << "$custom true 8192 5 configured.scan rw 68656c6c6f\n";
    }

    constexpr std::string_view source = R"(
rule configured_pattern {
    strings:
        $custom = "hello" ascii
    condition:
        $custom and #custom == 1 and @custom[1] == 8192 and !custom[1] == 5
}
)";
    auto parsed = rule_engine::parse_source("configured_pattern_eval.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());

    std::promise<std::uint16_t> listening_port;
    auto listening = listening_port.get_future();
    std::optional<rule_engine::ErrorSet> server_error;

    std::thread server {[&] {
        auto result = rule_engine::client_protocol::serve_client_once(
            rule_engine::client_protocol::ClientListenOptions {
                .bind_address = "127.0.0.1",
                .port = 0u,
                .pattern_fixture_path = fixture_path,
                .io_timeout = std::chrono::milliseconds {5000},
            },
            [&](const std::uint16_t port) { listening_port.set_value(port); });
        if (!result) {
            server_error = std::move(result.error());
        }
    }};

    REQUIRE(listening.wait_for(std::chrono::seconds {5}) == std::future_status::ready);
    const auto port = listening.get();
    auto evaluation = rule_engine::client_protocol::evaluate_subject_with_client(
        rule_engine::client_protocol::ClientConnectionOptions {
            .host = "127.0.0.1",
            .port = port,
            .io_timeout = std::chrono::milliseconds {5000},
        },
        *verified,
        rule_engine::Subject {
            .kind = "process",
            .id = "pid:" + std::to_string(GetCurrentProcessId()),
        });
    REQUIRE(evaluation.has_value());

    server.join();
    REQUIRE_FALSE(server_error.has_value());
    std::filesystem::remove(fixture_path);

    CHECK(evaluation->final_step.state == rule_engine::EvaluationState::complete);
    REQUIRE(evaluation->final_step.rule_results.size() == 1u);
    CHECK(evaluation->final_step.rule_results[0].identifier == "configured_pattern");
    CHECK(evaluation->final_step.rule_results[0].matched);
}
