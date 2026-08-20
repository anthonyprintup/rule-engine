#include "rule_engine/python/protocol/snapshot.hpp"
#include "rule_engine/python/windows/agent.hpp"

#include <catch2/catch_test_macros.hpp>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace py = rule_engine::python;
namespace proto = rule_engine::python::protocol_v2;
namespace win = rule_engine::python::windows;

namespace {

    template<typename Type>
    concept HasPredicate = requires(Type value) { value.predicate; };

    template<typename Type>
    concept HasVerdict = requires(Type value) { value.verdict; };

    struct TemporarySpool {
        TemporarySpool() {
            static std::atomic<std::uint64_t> next {};
            path =
                std::filesystem::temp_directory_path() / ("rule-engine-agent-" + std::to_string(GetCurrentProcessId()) +
                                                          "-" + std::to_string(next.fetch_add(1U)) + ".sqlite3");
        }

        ~TemporarySpool() {
            std::error_code ignored;
            std::filesystem::remove(path, ignored);
            std::filesystem::remove(path.string() + "-wal", ignored);
            std::filesystem::remove(path.string() + "-shm", ignored);
        }

        std::filesystem::path path;
    };

    [[nodiscard]] win::WindowsAgentConfig test_configuration(const std::filesystem::path &spool) {
        win::WindowsAgentConfig configuration;
        configuration.spool_path = spool;
        configuration.peer = py::PeerId {"peer:test"};
        configuration.active_generation = 3U;
        configuration.inventory_refresh_interval = std::chrono::seconds {1};
        configuration.require_hard_resolver_bounds = true;
        configuration.reconnect_policy.require_hard_resolver_bounds = true;
        configuration.reconnect_policy.initial_backoff = std::chrono::milliseconds {1};
        configuration.spool_limits = proto::AgentSpoolLimits {
            .maximum_records = 128U,
            .maximum_bytes = 4U * py::mebibyte,
            .high_water_bytes = 3U * py::mebibyte,
            .low_water_bytes = 2U * py::mebibyte,
        };
        return configuration;
    }

    [[nodiscard]] proto::ServerHelloMessage hello(std::string session, const std::uint64_t fence,
                                                  const std::uint64_t acknowledged = 0U) {
        return proto::ServerHelloMessage {
            .selected_minor = proto::initial_minor_version,
            .session = py::SessionId {std::move(session)},
            .peer = py::PeerId {"peer:test"},
            .session_fence = fence,
            .acknowledged_sequence = acknowledged,
            .schemas = {},
            .capabilities = {},
            .credit = {.bytes = 4U * py::mebibyte, .messages = 64U, .work_attempts = 64U, .snapshot_chunks = 64U},
            .heartbeat_interval_ms = 5'000U,
        };
    }

    [[nodiscard]] py::SubjectKey subject() {
        return py::SubjectKey {.peer = py::PeerId {"peer:test"},
                               .descriptor = py::SchemaId {"windows.process.v1"},
                               .identity = {{.field_id = 1U, .value = std::uint64_t {42U}}},
                               .parent = nullptr};
    }

    [[nodiscard]] proto::WorkLeaseMessage work(const proto::ServerHelloMessage &server,
                                               const std::uint64_t sequence = 1U) {
        const auto descriptor = win::find_windows_fact_descriptor(py::SchemaId {"windows.process.v1"}, "process.path");
        REQUIRE(descriptor.has_value());
        return proto::WorkLeaseMessage {
            .session = server.session,
            .peer = server.peer,
            .session_fence = server.session_fence,
            .work_id = "work:test",
            .attempt_id = "attempt:1",
            .work_fence = 11U,
            .generation = 3U,
            .server_sequence = sequence,
            .route = "windows",
            .facts = {{.request_id = py::RequestId {"fact:test"},
                       .subject = subject(),
                       .route = {.provider = "windows", .fact = "process.path"},
                       .expected_schema = descriptor->value_schema.id,
                       .expected_schema_hash = descriptor->value_schema.canonical_hash,
                       .deadline_unix_ms = win::unix_time_ms() + 60'000U}},
            .scans = {},
        };
    }

    [[nodiscard]] proto::CancelWorkMessage cancel(const proto::WorkLeaseMessage &lease, const std::uint64_t sequence) {
        return proto::CancelWorkMessage {.session = lease.session,
                                         .peer = lease.peer,
                                         .session_fence = lease.session_fence,
                                         .work_id = lease.work_id,
                                         .attempt_id = lease.attempt_id,
                                         .work_fence = lease.work_fence,
                                         .server_sequence = sequence,
                                         .route = lease.route,
                                         .requests = {lease.facts.front().request_id}};
    }

    [[nodiscard]] proto::ProtocolError canceled() {
        return proto::ProtocolError {.code = proto::ProtocolErrorCode::canceled, .message = "test complete"};
    }

    [[nodiscard]] proto::ProtocolError disconnected() {
        return proto::ProtocolError {.code = proto::ProtocolErrorCode::transport_error,
                                     .message = "test transport disconnected"};
    }

    [[nodiscard]] proto::PeerEnvelope envelope(const proto::ServerHelloMessage &server, std::string epoch,
                                               proto::MessageBody body) {
        return proto::PeerEnvelope {.message_id = "server:test",
                                    .session = server.session,
                                    .agent_epoch = std::move(epoch),
                                    .body = std::move(body)};
    }

    struct ReceiveEvent {
        std::optional<proto::PeerEnvelope> message;
        std::optional<proto::ProtocolError> error;
    };

    [[nodiscard]] ReceiveEvent incoming(proto::PeerEnvelope value) {
        return ReceiveEvent {.message = std::move(value), .error = std::nullopt};
    }

    [[nodiscard]] ReceiveEvent failure(proto::ProtocolError value) {
        return ReceiveEvent {.message = std::nullopt, .error = std::move(value)};
    }

    struct FakeSessionState {
        std::vector<proto::ServerHelloMessage> hellos;
        std::vector<std::vector<ReceiveEvent>> incoming_by_connection;
        std::vector<std::vector<bool>> readability_by_connection;
        std::vector<std::size_t> receive_offsets;
        std::vector<std::size_t> readability_offsets;
        std::vector<proto::AgentHelloMessage> agent_hellos;
        std::vector<proto::PeerEnvelope> sent;
        std::vector<std::size_t> pending_at_send;
        proto::SqliteAgentSpool *spool {};
        std::size_t reconnects {};
        bool fail_next_send {};
    };

    struct FakeSession final: win::IWindowsAgentSession {
        explicit FakeSession(std::shared_ptr<FakeSessionState> state): state_ {std::move(state)} {}

        [[nodiscard]] std::expected<win::AgentSessionHandshake, proto::ProtocolError>
        reconnect(proto::PersistentAgentSession &session, proto::AgentHelloMessage hello_message,
                  const std::stop_token cancellation) noexcept override {
            if (cancellation.stop_requested()) {
                return std::unexpected(canceled());
            }
            if (state_->reconnects >= state_->hellos.size()) {
                return std::unexpected(canceled());
            }
            const auto index = state_->reconnects++;
            hello_message.agent_epoch = session.agent_epoch();
            hello_message.next_sequence = session.next_sequence();
            state_->agent_hellos.push_back(std::move(hello_message));
            session.disconnect();
            if (auto established = session.establish(state_->hellos[index]); !established) {
                return std::unexpected(std::move(established.error()));
            }
            auto replay = session.take_transmit_batch();
            if (!replay) {
                return std::unexpected(std::move(replay.error()));
            }
            for (auto &item : *replay) { state_->sent.push_back(std::move(item)); }
            return win::AgentSessionHandshake {.server_hello = state_->hellos[index],
                                               .replayed_records = replay->size()};
        }

        [[nodiscard]] std::expected<proto::PeerEnvelope, proto::ProtocolError>
        receive(const std::stop_token cancellation) noexcept override {
            if (cancellation.stop_requested()) {
                return std::unexpected(canceled());
            }
            const auto connection = state_->reconnects - 1U;
            if (connection >= state_->incoming_by_connection.size()) {
                return std::unexpected(canceled());
            }
            if (state_->receive_offsets.size() <= connection) {
                state_->receive_offsets.resize(connection + 1U);
            }
            auto &offset = state_->receive_offsets[connection];
            auto &events = state_->incoming_by_connection[connection];
            if (offset >= events.size()) {
                return std::unexpected(canceled());
            }
            auto event = std::move(events[offset++]);
            if (event.error.has_value()) {
                return std::unexpected(std::move(*event.error));
            }
            return std::move(*event.message);
        }

        [[nodiscard]] std::expected<bool, proto::ProtocolError>
        wait_readable_until(const std::chrono::steady_clock::time_point,
                            const std::stop_token cancellation) noexcept override {
            if (cancellation.stop_requested()) {
                return std::unexpected(canceled());
            }
            const auto connection = state_->reconnects - 1U;
            if (connection >= state_->readability_by_connection.size()) {
                return true;
            }
            if (state_->readability_offsets.size() <= connection) {
                state_->readability_offsets.resize(connection + 1U);
            }
            auto &offset = state_->readability_offsets[connection];
            const auto &events = state_->readability_by_connection[connection];
            return offset >= events.size() ? true : events[offset++];
        }

        [[nodiscard]] std::expected<void, proto::ProtocolError>
        send(const proto::PeerEnvelope &message, const std::stop_token cancellation) noexcept override {
            if (cancellation.stop_requested()) {
                return std::unexpected(canceled());
            }
            if (state_->spool != nullptr) {
                state_->pending_at_send.push_back(state_->spool->pending_records());
            }
            if (state_->fail_next_send) {
                state_->fail_next_send = false;
                return std::unexpected(disconnected());
            }
            state_->sent.push_back(message);
            return {};
        }

        void shutdown() noexcept override {}

    private:
        std::shared_ptr<FakeSessionState> state_;
    };

    struct FakeProviderState {
        std::size_t dispatches {};
        std::size_t cancellations {};
        std::size_t inventories {};
        bool publish_inventory {};
        std::vector<bool> authoritative_inventories;
        std::vector<std::uint64_t> inventory_generations;
    };

    struct FakeProvider final: win::IWindowsAgentProviderRuntime {
        FakeProvider(std::shared_ptr<FakeProviderState> state, win::WindowsAgentRuntimeIdentity identity):
            state_ {std::move(state)}, identity_ {std::move(identity)} {}

        [[nodiscard]] std::expected<proto::WorkResultMessage, win::AgentRuntimeError>
        dispatch(const proto::WorkLeaseMessage &lease) override {
            ++state_->dispatches;
            std::vector<py::FactResponse> facts;
            facts.reserve(lease.facts.size());
            for (const auto &request : lease.facts) {
                facts.push_back(py::FactResponse {
                    .request_id = request.request_id,
                    .subject = request.subject,
                    .status = py::FactTerminalStatus::unsupported,
                    .value = std::nullopt,
                    .returned_schema = std::nullopt,
                    .diagnostic = py::Diagnostic {.code = "test.unsupported",
                                                  .severity = py::DiagnosticSeverity::error,
                                                  .message = "fake data-only provider",
                                                  .span = std::nullopt,
                                                  .related = {}},
                });
            }
            return proto::WorkResultMessage {.originating_session = lease.session,
                                             .peer = lease.peer,
                                             .originating_session_fence = lease.session_fence,
                                             .work_id = lease.work_id,
                                             .attempt_id = lease.attempt_id,
                                             .work_fence = lease.work_fence,
                                             .generation = lease.generation,
                                             .facts = std::move(facts),
                                             .scans = {}};
        }

        [[nodiscard]] std::expected<void, win::AgentRuntimeError> cancel(const proto::CancelWorkMessage &) override {
            ++state_->cancellations;
            return {};
        }

        [[nodiscard]] std::expected<std::optional<win::InventoryProjection>, win::AgentRuntimeError>
        process_inventory(std::string snapshot_id, const std::uint64_t inventory_generation) override {
            ++state_->inventories;
            state_->inventory_generations.push_back(inventory_generation);
            const auto attempt = state_->inventories - 1U;
            const auto authoritative = attempt < state_->authoritative_inventories.size() ?
                                           state_->authoritative_inventories[attempt] :
                                           state_->publish_inventory;
            if (!authoritative) {
                return std::optional<win::InventoryProjection> {};
            }
            const std::vector<py::SubjectKey> subjects;
            auto digest = proto::authoritative_snapshot_digest(subjects);
            REQUIRE(digest.has_value());
            std::vector<proto::DurableAgentBody> messages;
            messages.emplace_back(
                proto::AuthoritativeSnapshotBegin {.session = identity_.session,
                                                   .peer = identity_.peer,
                                                   .session_fence = identity_.session_fence,
                                                   .snapshot_id = snapshot_id,
                                                   .parent = std::nullopt,
                                                   .subject_schema = py::SchemaId {std::string {win::process_schema}},
                                                   .generation = inventory_generation,
                                                   .expected_count = 0U,
                                                   .expected_digest = *digest});
            messages.emplace_back(proto::AuthoritativeSnapshotCommit {.session = identity_.session,
                                                                      .peer = identity_.peer,
                                                                      .session_fence = identity_.session_fence,
                                                                      .snapshot_id = snapshot_id,
                                                                      .generation = inventory_generation,
                                                                      .item_count = 0U,
                                                                      .canonical_digest = *digest});
            return std::optional<win::InventoryProjection> {win::InventoryProjection {
                .generation = inventory_generation,
                .inventory_digest = *digest,
                .protocol_digest = *digest,
                .durable_messages = std::move(messages),
                .observations = {},
                .removals = {},
                .duplicate = false,
            }};
        }

    private:
        std::shared_ptr<FakeProviderState> state_;
        win::WindowsAgentRuntimeIdentity identity_;
    };

    struct FakeProviderFactory final: win::IWindowsAgentProviderFactory {
        explicit FakeProviderFactory(std::shared_ptr<FakeProviderState> state): state_ {std::move(state)} {}

        [[nodiscard]] std::expected<std::unique_ptr<win::IWindowsAgentProviderRuntime>, win::AgentFailure>
        create(win::WindowsAgentRuntimeIdentity identity) noexcept override {
            return std::unique_ptr<win::IWindowsAgentProviderRuntime> {
                std::make_unique<FakeProvider>(state_, std::move(identity))};
        }

    private:
        std::shared_ptr<FakeProviderState> state_;
    };

    [[nodiscard]] std::expected<proto::SqliteAgentSpool, proto::ProtocolError>
    open_spool(const win::WindowsAgentConfig &configuration) {
        return proto::SqliteAgentSpool::open(configuration.spool_path.string(), configuration.spool_limits,
                                             configuration.protocol_limits);
    }

} // namespace

TEST_CASE("Windows agent configuration and command line are strict and production bounded") {
    const std::string valid = "schema_version = 2\n"
                              "spool_path = C:\\agent\\spool.sqlite3\n"
                              "certificate_path = C:\\agent\\client.pem\n"
                              "private_key_path = C:\\agent\\client-key.pem\n"
                              "ca_path = C:\\agent\\ca.pem\n"
                              "server_endpoint = 127.0.0.1:7443\n"
                              "server_endpoint = [::1]:7443\n"
                              "server_name = coordinator.example\n"
                              "server_uri = urn:rule-engine:server\n"
                              "server_fingerprint_sha256 = " +
                              std::string(64U, 'a') +
                              "\n"
                              "peer_id = peer:test\n"
                              "active_generation = 3\n"
                              "inventory_refresh_interval_ms = 300000\n";

    const auto parsed = win::parse_windows_agent_config(valid);
    REQUIRE(parsed.has_value());
    CHECK(parsed->endpoints.size() == 2U);
    CHECK(parsed->require_hard_resolver_bounds);
    CHECK(parsed->reconnect_policy.require_hard_resolver_bounds);
    CHECK_FALSE(parsed->require_crl);
    CHECK(parsed->crl_path.empty());

    const auto with_crl = valid + "crl_path = C:\\agent\\server.crl.pem\nrequire_crl = true\n";
    const auto parsed_crl = win::parse_windows_agent_config(with_crl);
    REQUIRE(parsed_crl.has_value());
    CHECK(parsed_crl->require_crl);
    CHECK(parsed_crl->crl_path == std::filesystem::path {"C:\\agent\\server.crl.pem"});
    CHECK(parsed->inventory_refresh_interval == std::chrono::minutes {5});

    auto legacy_schema = valid;
    legacy_schema.replace(legacy_schema.find("schema_version = 2"), std::string_view {"schema_version = 2"}.size(),
                          "schema_version = 1");
    CHECK_FALSE(win::parse_windows_agent_config(legacy_schema).has_value());

    CHECK_FALSE(win::parse_windows_agent_config(valid + "unknown_key = value\n").has_value());
    CHECK_FALSE(win::parse_windows_agent_config(valid + "peer_id = duplicate\n").has_value());
    auto unsafe = valid + "require_hard_resolver_bounds = false\n";
    CHECK_FALSE(win::parse_windows_agent_config(unsafe).has_value());
    CHECK_FALSE(win::parse_windows_agent_config(valid + "require_crl = true\n").has_value());
    CHECK_FALSE(win::parse_windows_agent_config(valid + "crl_path = C:\\agent\\server.crl.pem\n").has_value());
    CHECK_FALSE(win::parse_windows_agent_config(valid + "crl_path = server.crl.pem\nrequire_crl = true\n").has_value());
    auto dns = valid;
    dns.replace(dns.find("127.0.0.1:7443"), std::string_view {"127.0.0.1:7443"}.size(), "example.test:7443");
    CHECK_FALSE(win::parse_windows_agent_config(dns).has_value());
    auto relative = valid;
    relative.replace(relative.find("C:\\agent\\spool.sqlite3"), std::string_view {"C:\\agent\\spool.sqlite3"}.size(),
                     "spool.sqlite3");
    CHECK_FALSE(win::parse_windows_agent_config(relative).has_value());
    auto too_fast = valid;
    too_fast.replace(too_fast.find("300000"), std::string_view {"300000"}.size(), "999");
    CHECK_FALSE(win::parse_windows_agent_config(too_fast).has_value());
    auto too_slow = valid;
    too_slow.replace(too_slow.find("300000"), std::string_view {"300000"}.size(), "86400001");
    CHECK_FALSE(win::parse_windows_agent_config(too_slow).has_value());
    auto missing_interval = valid;
    missing_interval.erase(missing_interval.find("inventory_refresh_interval_ms"));
    CHECK_FALSE(win::parse_windows_agent_config(missing_interval).has_value());

    const std::vector<std::string_view> run {"--config", "agent.conf"};
    const std::vector<std::string_view> validate {"--config", "agent.conf", "--validate-config"};
    const std::vector<std::string_view> reordered {"--validate-config", "--config", "agent.conf"};
    REQUIRE(win::parse_windows_agent_command(run).has_value());
    REQUIRE(win::parse_windows_agent_command(validate).has_value());
    CHECK_FALSE(win::parse_windows_agent_command(reordered).has_value());

    TemporarySpool temporary;
    auto missing_crl = test_configuration(temporary.path);
    const auto existing_file = std::filesystem::path {__FILE__};
    missing_crl.certificate_path = existing_file;
    missing_crl.private_key_path = existing_file;
    missing_crl.ca_path = existing_file;
    missing_crl.crl_path = temporary.path.string() + ".crl.pem";
    missing_crl.require_crl = true;
    CHECK_FALSE(win::validate_windows_agent_config_files(missing_crl).has_value());
}

TEST_CASE("Windows agent spools an entire typed inventory projection before its first send") {
    if (!proto::spool_backend_status().available) {
        SKIP("SQLite spool backend is unavailable");
    }
    TemporarySpool temporary;
    auto configuration = test_configuration(temporary.path);
    auto spool = open_spool(configuration);
    REQUIRE(spool.has_value());
    const auto server = hello("session:inventory", 7U);
    auto session_state = std::make_shared<FakeSessionState>();
    session_state->hellos = {server};
    session_state->incoming_by_connection = {{failure(canceled())}};
    session_state->spool = &*spool;
    auto provider_state = std::make_shared<FakeProviderState>();
    provider_state->publish_inventory = true;

    win::WindowsAgentService service {configuration, *spool, std::make_unique<FakeSession>(session_state),
                                      std::make_unique<FakeProviderFactory>(provider_state)};
    const auto result = service.run({});
    REQUIRE(result.has_value());
    CHECK(result->snapshot_records_spooled == 2U);
    CHECK(result->inventory_refreshes_attempted == 1U);
    CHECK(result->inventory_generations_spooled == 1U);
    CHECK(provider_state->inventories == 1U);
    CHECK(provider_state->inventory_generations == std::vector<std::uint64_t> {4U});
    REQUIRE(session_state->sent.size() == 2U);
    REQUIRE_FALSE(session_state->pending_at_send.empty());
    CHECK(session_state->pending_at_send.front() == 2U);
    CHECK(std::holds_alternative<proto::AuthoritativeSnapshotBegin>(session_state->sent[0].body));
    CHECK(std::holds_alternative<proto::AuthoritativeSnapshotCommit>(session_state->sent[1].body));
}

TEST_CASE("Windows agent periodically publishes complete durable process inventories and skips failed enumeration") {
    if (!proto::spool_backend_status().available) {
        SKIP("SQLite spool backend is unavailable");
    }
    TemporarySpool temporary;
    auto configuration = test_configuration(temporary.path);
    auto spool = open_spool(configuration);
    REQUIRE(spool.has_value());
    const auto server = hello("session:periodic-inventory", 7U);
    auto session_state = std::make_shared<FakeSessionState>();
    session_state->hellos = {server};
    session_state->incoming_by_connection = {{failure(canceled())}};
    session_state->readability_by_connection = {{false, false, true}};
    session_state->spool = &*spool;
    auto provider_state = std::make_shared<FakeProviderState>();
    provider_state->authoritative_inventories = {true, false, true};

    win::WindowsAgentService service {configuration, *spool, std::make_unique<FakeSession>(session_state),
                                      std::make_unique<FakeProviderFactory>(provider_state)};
    const auto result = service.run({});
    REQUIRE(result.has_value());
    CHECK(result->inventory_refreshes_attempted == 3U);
    CHECK(result->inventory_generations_spooled == 2U);
    CHECK(result->inventory_refreshes_without_authority == 1U);
    CHECK(result->snapshot_records_spooled == 4U);
    CHECK(provider_state->inventory_generations == std::vector<std::uint64_t> {4U, 6U, 6U});
    REQUIRE(session_state->sent.size() == 4U);
    const auto *first_begin = std::get_if<proto::AuthoritativeSnapshotBegin>(&session_state->sent[0].body);
    const auto *first_commit = std::get_if<proto::AuthoritativeSnapshotCommit>(&session_state->sent[1].body);
    const auto *second_begin = std::get_if<proto::AuthoritativeSnapshotBegin>(&session_state->sent[2].body);
    const auto *second_commit = std::get_if<proto::AuthoritativeSnapshotCommit>(&session_state->sent[3].body);
    REQUIRE(first_begin != nullptr);
    REQUIRE(first_commit != nullptr);
    REQUIRE(second_begin != nullptr);
    REQUIRE(second_commit != nullptr);
    CHECK(first_begin->generation == 4U);
    CHECK(first_commit->generation == first_begin->generation);
    CHECK(second_begin->generation == 6U);
    CHECK(second_commit->generation == second_begin->generation);
    CHECK(first_begin->snapshot_id == first_commit->snapshot_id);
    CHECK(second_begin->snapshot_id == second_commit->snapshot_id);
    CHECK(first_begin->snapshot_id != second_begin->snapshot_id);
}

TEST_CASE("SQLite snapshot batch admission is atomic at the record limit") {
    if (!proto::spool_backend_status().available) {
        SKIP("SQLite spool backend is unavailable");
    }
    TemporarySpool temporary;
    auto configuration = test_configuration(temporary.path);
    configuration.spool_limits.maximum_records = 1U;
    auto spool = open_spool(configuration);
    REQUIRE(spool.has_value());
    const auto server = hello("session:atomic", 7U);
    const std::vector<py::SubjectKey> subjects;
    const auto digest = proto::authoritative_snapshot_digest(subjects);
    REQUIRE(digest.has_value());
    const std::vector<proto::DurableAgentBody> batch {
        proto::AuthoritativeSnapshotBegin {.session = server.session,
                                           .peer = server.peer,
                                           .session_fence = server.session_fence,
                                           .snapshot_id = "snapshot:atomic",
                                           .parent = std::nullopt,
                                           .subject_schema = py::SchemaId {std::string {win::process_schema}},
                                           .generation = 3U,
                                           .expected_count = 0U,
                                           .expected_digest = *digest},
        proto::AuthoritativeSnapshotCommit {.session = server.session,
                                            .peer = server.peer,
                                            .session_fence = server.session_fence,
                                            .snapshot_id = "snapshot:atomic",
                                            .generation = 3U,
                                            .item_count = 0U,
                                            .canonical_digest = *digest},
    };
    const auto inserted = spool->enqueue_batch(batch);
    REQUIRE_FALSE(inserted.has_value());
    CHECK(inserted.error().code == proto::ProtocolErrorCode::backpressured);
    CHECK(spool->pending_records() == 0U);
}

TEST_CASE("Windows agent reconnects and replays a durable result without duplicate provider dispatch") {
    if (!proto::spool_backend_status().available) {
        SKIP("SQLite spool backend is unavailable");
    }
    TemporarySpool temporary;
    auto configuration = test_configuration(temporary.path);
    auto spool = open_spool(configuration);
    REQUIRE(spool.has_value());
    const auto first = hello("session:first", 7U);
    const auto second = hello("session:second", 8U);
    const auto epoch = spool->agent_epoch();
    auto first_work = work(first);
    auto repeated_work = work(second);
    auto session_state = std::make_shared<FakeSessionState>();
    session_state->hellos = {first, second};
    session_state->incoming_by_connection = {
        {incoming(envelope(first, epoch, first_work))},
        {incoming(envelope(second, epoch, repeated_work)), failure(canceled())},
    };
    session_state->spool = &*spool;
    session_state->fail_next_send = true;
    auto provider_state = std::make_shared<FakeProviderState>();

    win::WindowsAgentService service {configuration, *spool, std::make_unique<FakeSession>(session_state),
                                      std::make_unique<FakeProviderFactory>(provider_state)};
    const auto result = service.run({});
    REQUIRE(result.has_value());
    CHECK(result->successful_connections == 2U);
    CHECK(result->replayed_records == 1U);
    CHECK(result->duplicate_leases == 1U);
    CHECK(provider_state->dispatches == 1U);
    CHECK(provider_state->inventories == 1U);
    REQUIRE(session_state->sent.size() == 1U);
    CHECK(std::holds_alternative<proto::WorkResultMessage>(session_state->sent.front().body));
}

TEST_CASE("Windows agent deduplicates a repeated lease and forwards cancellation only to the data provider") {
    if (!proto::spool_backend_status().available) {
        SKIP("SQLite spool backend is unavailable");
    }
    TemporarySpool temporary;
    auto configuration = test_configuration(temporary.path);
    auto spool = open_spool(configuration);
    REQUIRE(spool.has_value());
    const auto server = hello("session:dedupe", 7U);
    const auto epoch = spool->agent_epoch();
    const auto lease = work(server);
    auto session_state = std::make_shared<FakeSessionState>();
    session_state->hellos = {server};
    session_state->incoming_by_connection = {
        {incoming(envelope(server, epoch, lease)), incoming(envelope(server, epoch, lease)),
         incoming(envelope(server, epoch, cancel(lease, 2U))), failure(canceled())}};
    session_state->spool = &*spool;
    auto provider_state = std::make_shared<FakeProviderState>();

    win::WindowsAgentService service {configuration, *spool, std::make_unique<FakeSession>(session_state),
                                      std::make_unique<FakeProviderFactory>(provider_state)};
    const auto result = service.run({});
    REQUIRE(result.has_value());
    CHECK(result->accepted_leases == 1U);
    CHECK(result->duplicate_leases == 1U);
    CHECK(result->canceled_work == 1U);
    CHECK(provider_state->dispatches == 1U);
    CHECK(provider_state->cancellations == 1U);
}

TEST_CASE("Windows agent applies NACK retry and cumulative ACK to its durable spool") {
    if (!proto::spool_backend_status().available) {
        SKIP("SQLite spool backend is unavailable");
    }
    TemporarySpool temporary;
    auto configuration = test_configuration(temporary.path);
    auto spool = open_spool(configuration);
    REQUIRE(spool.has_value());
    const auto server = hello("session:control", 7U);
    const auto epoch = spool->agent_epoch();
    const auto lease = work(server);
    auto session_state = std::make_shared<FakeSessionState>();
    session_state->hellos = {server};
    session_state->incoming_by_connection = {{
        incoming(envelope(server, epoch, lease)),
        incoming(envelope(server, epoch,
                          proto::NackMessage {.agent_epoch = epoch,
                                              .sequence = 1U,
                                              .reason = proto::ProtocolErrorCode::transport_error,
                                              .permanent = false,
                                              .diagnostic = "retry"})),
        incoming(
            envelope(server, epoch,
                     proto::AckMessage {.agent_epoch = epoch, .acknowledged_through = 1U, .credit = server.credit})),
        failure(canceled()),
    }};
    session_state->spool = &*spool;
    auto provider_state = std::make_shared<FakeProviderState>();

    win::WindowsAgentService service {configuration, *spool, std::make_unique<FakeSession>(session_state),
                                      std::make_unique<FakeProviderFactory>(provider_state)};
    const auto result = service.run({});
    REQUIRE(result.has_value());
    CHECK(result->rejections == 1U);
    CHECK(result->acknowledgements == 1U);
    CHECK(spool->pending_records() == 0U);
    CHECK(session_state->sent.size() == 2U);
}

TEST_CASE("Windows agent rejects stale session fences before provider dispatch and exposes facts-only messages") {
    STATIC_REQUIRE_FALSE(HasPredicate<proto::WorkLeaseMessage>);
    STATIC_REQUIRE_FALSE(HasVerdict<proto::WorkResultMessage>);
    STATIC_REQUIRE_FALSE(HasPredicate<win::IWindowsAgentProviderRuntime>);
    STATIC_REQUIRE_FALSE(HasVerdict<win::IWindowsAgentProviderRuntime>);

    if (!proto::spool_backend_status().available) {
        SKIP("SQLite spool backend is unavailable");
    }
    TemporarySpool temporary;
    auto configuration = test_configuration(temporary.path);
    auto spool = open_spool(configuration);
    REQUIRE(spool.has_value());
    const auto server = hello("session:fence", 7U);
    const auto epoch = spool->agent_epoch();
    auto stale = work(server);
    --stale.session_fence;
    auto session_state = std::make_shared<FakeSessionState>();
    session_state->hellos = {server};
    session_state->incoming_by_connection = {{incoming(envelope(server, epoch, stale))}};
    session_state->spool = &*spool;
    auto provider_state = std::make_shared<FakeProviderState>();

    win::WindowsAgentService service {configuration, *spool, std::make_unique<FakeSession>(session_state),
                                      std::make_unique<FakeProviderFactory>(provider_state)};
    const auto result = service.run({});
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == win::AgentFailureCode::protocol);
    CHECK(provider_state->dispatches == 0U);
    CHECK(spool->pending_records() == 0U);
}

TEST_CASE("Windows agent rejects deadlines beyond its local execution horizon") {
    if (!proto::spool_backend_status().available) {
        SKIP("SQLite spool backend is unavailable");
    }
    TemporarySpool temporary;
    auto configuration = test_configuration(temporary.path);
    auto spool = open_spool(configuration);
    REQUIRE(spool.has_value());
    const auto server = hello("session:deadline", 7U);
    const auto epoch = spool->agent_epoch();
    auto unbounded = work(server);
    unbounded.facts.front().deadline_unix_ms = win::unix_time_ms() + 5U * 60U * 1'000U;
    auto session_state = std::make_shared<FakeSessionState>();
    session_state->hellos = {server};
    session_state->incoming_by_connection = {{incoming(envelope(server, epoch, unbounded))}};
    session_state->spool = &*spool;
    auto provider_state = std::make_shared<FakeProviderState>();

    win::WindowsAgentService service {configuration, *spool, std::make_unique<FakeSession>(session_state),
                                      std::make_unique<FakeProviderFactory>(provider_state)};
    const auto result = service.run({});
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == win::AgentFailureCode::protocol);
    CHECK(provider_state->dispatches == 0U);
    CHECK(spool->pending_records() == 0U);
}
