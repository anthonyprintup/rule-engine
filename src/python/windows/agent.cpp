#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <WS2tcpip.h>
#include <WinSock2.h>

#include "rule_engine/python/windows/agent.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <concepts>
#include <condition_variable>
#include <limits>
#include <mutex>
#include <ranges>
#include <span>
#include <thread>
#include <type_traits>
#include <utility>

namespace rule_engine::python::windows {
    namespace {

        using protocol_v2::AckMessage;
        using protocol_v2::AgentHelloMessage;
        using protocol_v2::AuthoritativeSnapshotBegin;
        using protocol_v2::AuthoritativeSnapshotChunk;
        using protocol_v2::AuthoritativeSnapshotCommit;
        using protocol_v2::CancelWorkMessage;
        using protocol_v2::CreditUpdateMessage;
        using protocol_v2::NackMessage;
        using protocol_v2::PeerEnvelope;
        using protocol_v2::ProtocolError;
        using protocol_v2::ProtocolErrorCode;
        using protocol_v2::ServerHelloMessage;
        using protocol_v2::WorkLeaseMessage;
        using protocol_v2::WorkResultMessage;

        [[nodiscard]] AgentFailure protocol_failure(const ProtocolError &error) {
            auto code = AgentFailureCode::protocol;
            if (error.code == ProtocolErrorCode::dependency_unavailable) {
                code = AgentFailureCode::dependency;
            } else if (error.code == ProtocolErrorCode::transport_error) {
                code = AgentFailureCode::transport;
            } else if (error.code == ProtocolErrorCode::unauthenticated) {
                code = AgentFailureCode::authentication;
            } else if (error.code == ProtocolErrorCode::persistence_error ||
                       error.code == ProtocolErrorCode::backpressured) {
                code = AgentFailureCode::persistence;
            } else if (error.code == ProtocolErrorCode::canceled) {
                code = AgentFailureCode::canceled;
            }
            return AgentFailure {.code = code, .message = error.message};
        }

        [[nodiscard]] AgentFailure provider_failure(const AgentRuntimeError &error) {
            const auto code =
                error.code == AgentRuntimeErrorCode::canceled ? AgentFailureCode::canceled : AgentFailureCode::provider;
            return AgentFailure {.code = code, .message = error.message};
        }

        [[nodiscard]] ProtocolError session_error(const ProtocolErrorCode code, std::string message) {
            return ProtocolError {.code = code, .message = std::move(message), .byte_offset = 0U};
        }

        [[nodiscard]] bool retryable(const AgentFailure &failure) noexcept {
            return failure.code == AgentFailureCode::transport;
        }

        [[nodiscard]] bool wait_for_retry(const std::chrono::milliseconds delay, const std::stop_token cancellation) {
            std::condition_variable_any condition;
            std::mutex mutex;
            std::unique_lock lock {mutex};
            condition.wait_for(lock, cancellation, delay, [] { return false; });
            return !cancellation.stop_requested();
        }

        [[nodiscard]] bool numeric_address(const std::string_view host,
                                           protocol_v2::TcpAddressFamily &family) noexcept {
            const auto text = std::string {host};
            in_addr address4 {};
            if (InetPtonA(AF_INET, text.c_str(), &address4) == 1) {
                family = protocol_v2::TcpAddressFamily::ipv4;
                return true;
            }
            in6_addr address6 {};
            if (InetPtonA(AF_INET6, text.c_str(), &address6) == 1) {
                family = protocol_v2::TcpAddressFamily::ipv6;
                return true;
            }
            return false;
        }

        struct NumericEndpointResolver final: protocol_v2::IEndpointResolver {
            [[nodiscard]] bool hard_bounds_guaranteed() const noexcept override { return true; }

            [[nodiscard]] std::expected<std::vector<protocol_v2::ResolvedTcpAddress>, ProtocolError>
            resolve(const protocol_v2::TcpEndpoint &endpoint, const std::size_t maximum_addresses,
                    const std::chrono::steady_clock::time_point deadline,
                    const std::stop_token cancellation) noexcept override {
                if (cancellation.stop_requested()) {
                    return std::unexpected(
                        session_error(ProtocolErrorCode::canceled, "numeric endpoint resolution canceled"));
                }
                if (std::chrono::steady_clock::now() >= deadline) {
                    return std::unexpected(
                        session_error(ProtocolErrorCode::transport_error, "numeric endpoint resolution timed out"));
                }
                protocol_v2::TcpAddressFamily family;
                if (maximum_addresses == 0U || endpoint.port == 0U || !numeric_address(endpoint.host, family)) {
                    return std::unexpected(
                        session_error(ProtocolErrorCode::malformed, "configured endpoint is not a numeric IP address"));
                }
                return std::vector<protocol_v2::ResolvedTcpAddress> {
                    {.family = family, .address = endpoint.host, .port = endpoint.port}};
            }
        };

        struct TlsWindowsAgentSession final: IWindowsAgentSession {
            explicit TlsWindowsAgentSession(protocol_v2::TlsSessionDialer dialer) noexcept:
                dialer_ {std::move(dialer)} {}

            [[nodiscard]] std::expected<AgentSessionHandshake, ProtocolError>
            reconnect(protocol_v2::PersistentAgentSession &session, AgentHelloMessage hello,
                      const std::stop_token cancellation) noexcept override {
                shutdown();
                auto connected = dialer_.reconnect(session, std::move(hello), resolver_, jitter_, cancellation);
                if (!connected) {
                    return std::unexpected(std::move(connected.error()));
                }
                auto handshake = AgentSessionHandshake {.server_hello = std::move(connected->server_hello),
                                                        .replayed_records = connected->replayed_records};
                connection_.emplace(std::move(connected->connection));
                return handshake;
            }

            [[nodiscard]] std::expected<PeerEnvelope, ProtocolError>
            receive(const std::stop_token cancellation) noexcept override {
                if (!connection_.has_value()) {
                    return std::unexpected(
                        session_error(ProtocolErrorCode::transport_error, "TLS agent session is disconnected"));
                }
                return connection_->receive(cancellation);
            }

            [[nodiscard]] std::expected<void, ProtocolError>
            send(const PeerEnvelope &envelope, const std::stop_token cancellation) noexcept override {
                if (!connection_.has_value()) {
                    return std::unexpected(
                        session_error(ProtocolErrorCode::transport_error, "TLS agent session is disconnected"));
                }
                return connection_->send(envelope, cancellation);
            }

            void shutdown() noexcept override {
                if (connection_.has_value()) {
                    connection_->shutdown();
                    connection_.reset();
                }
            }

        private:
            protocol_v2::TlsSessionDialer dialer_;
            NumericEndpointResolver resolver_;
            protocol_v2::XorShiftBackoffJitter jitter_;
            std::optional<protocol_v2::TlsPeerConnection> connection_;
        };

        struct ProductionProviderRuntime final: IWindowsAgentProviderRuntime {
            explicit ProductionProviderRuntime(WindowsAgentRuntimeIdentity identity):
                peer_ {identity.peer}, generation_ {identity.generation}, runtime_ {std::move(identity)} {}

            [[nodiscard]] std::expected<WorkResultMessage, AgentRuntimeError>
            dispatch(const WorkLeaseMessage &work) override {
                return runtime_.dispatch(work);
            }

            [[nodiscard]] std::expected<void, AgentRuntimeError> cancel(const CancelWorkMessage &message) override {
                return runtime_.cancel(message);
            }

            [[nodiscard]] std::expected<std::optional<InventoryProjection>, AgentRuntimeError>
            initial_process_inventory(std::string snapshot_id) override {
                auto inventory = enumerate_process_inventory(peer_, generation_, unix_time_ms() + 15'000U);
                if (!inventory.authoritative || inventory.status != FactTerminalStatus::value) {
                    return std::optional<InventoryProjection> {};
                }
                auto projection = runtime_.project_inventory(
                    InventoryProjectionRequest {.snapshot_id = std::move(snapshot_id),
                                                .parent = std::nullopt,
                                                .subject_schema = SchemaId {std::string {process_schema}},
                                                .chunk_items = 1'024U},
                    inventory);
                if (!projection) {
                    return std::unexpected(std::move(projection.error()));
                }
                return std::optional<InventoryProjection> {std::move(*projection)};
            }

        private:
            PeerId peer_;
            std::uint64_t generation_ {};
            WindowsAgentProviderRuntime runtime_;
        };

        struct ProductionProviderFactory final: IWindowsAgentProviderFactory {
            [[nodiscard]] std::expected<std::unique_ptr<IWindowsAgentProviderRuntime>, AgentFailure>
            create(WindowsAgentRuntimeIdentity identity) noexcept override {
                if (identity.session.empty() || identity.peer.empty() || identity.session_fence == 0U ||
                    identity.generation == 0U || identity.route != provider_name) {
                    return std::unexpected(AgentFailure {.code = AgentFailureCode::invariant,
                                                         .message = "provider runtime identity is incomplete"});
                }
                return std::unique_ptr<IWindowsAgentProviderRuntime> {
                    std::make_unique<ProductionProviderRuntime>(std::move(identity))};
            }
        };

        [[nodiscard]] bool work_result_matches(const WorkResultMessage &result, const WorkLeaseMessage &work) {
            if (result.peer != work.peer || result.work_id != work.work_id || result.attempt_id != work.attempt_id ||
                result.work_fence != work.work_fence || result.generation != work.generation ||
                result.facts.size() != work.facts.size() || result.scans.size() != work.scans.size()) {
                return false;
            }
            for (std::size_t index = 0U; index < work.facts.size(); ++index) {
                if (result.facts[index].request_id != work.facts[index].request_id) {
                    return false;
                }
            }
            for (std::size_t index = 0U; index < work.scans.size(); ++index) {
                if (result.scans[index].request_id != work.scans[index].request_id) {
                    return false;
                }
            }
            return true;
        }

        [[nodiscard]] bool deadlines_are_locally_bounded(const WorkLeaseMessage &work,
                                                         const std::chrono::milliseconds maximum_horizon) noexcept {
            if (maximum_horizon <= std::chrono::milliseconds::zero()) {
                return false;
            }
            const auto now = unix_time_ms();
            const auto horizon = static_cast<std::uint64_t>(maximum_horizon.count());
            const auto latest = horizon > (std::numeric_limits<std::uint64_t>::max)() - now ?
                                    (std::numeric_limits<std::uint64_t>::max)() :
                                    now + horizon;
            return std::ranges::all_of(
                       work.facts,
                       [latest](const FactRequest &request) { return request.deadline_unix_ms <= latest; }) &&
                   std::ranges::all_of(
                       work.scans, [latest](const ScanRequest &request) { return request.deadline_unix_ms <= latest; });
        }

        [[nodiscard]] bool snapshot_matches(const protocol_v2::DurableAgentBody &body,
                                            const std::string_view snapshot_id) {
            return std::visit(
                [snapshot_id](const auto &message) {
                    using Type = std::remove_cvref_t<decltype(message)>;
                    if constexpr (std::same_as<Type, WorkResultMessage>) {
                        return false;
                    } else {
                        return message.snapshot_id == snapshot_id;
                    }
                },
                body);
        }

        [[nodiscard]] bool valid_snapshot_projection(const InventoryProjection &projection, const SessionId &session,
                                                     const PeerId &peer, const std::uint64_t session_fence,
                                                     const std::uint64_t generation,
                                                     const std::string_view snapshot_id) {
            if (projection.duplicate || projection.generation != generation || projection.protocol_digest.empty() ||
                projection.durable_messages.size() < 2U) {
                return false;
            }
            const auto *begin = std::get_if<AuthoritativeSnapshotBegin>(&projection.durable_messages.front());
            const auto *commit = std::get_if<AuthoritativeSnapshotCommit>(&projection.durable_messages.back());
            if (begin == nullptr || commit == nullptr || begin->session != session || begin->peer != peer ||
                begin->session_fence != session_fence || begin->snapshot_id != snapshot_id ||
                begin->parent.has_value() || begin->subject_schema != SchemaId {std::string {process_schema}} ||
                begin->generation != generation || begin->expected_digest != projection.protocol_digest ||
                commit->session != session || commit->peer != peer || commit->session_fence != session_fence ||
                commit->snapshot_id != snapshot_id || commit->generation != generation ||
                commit->canonical_digest != projection.protocol_digest || commit->item_count != begin->expected_count) {
                return false;
            }
            std::uint64_t item_count {};
            std::uint32_t chunk_index {};
            for (std::size_t index = 1U; index + 1U < projection.durable_messages.size(); ++index) {
                const auto *chunk = std::get_if<AuthoritativeSnapshotChunk>(&projection.durable_messages[index]);
                if (chunk == nullptr || chunk->session != session || chunk->peer != peer ||
                    chunk->session_fence != session_fence || chunk->snapshot_id != snapshot_id ||
                    chunk->generation != generation || chunk->chunk_index != chunk_index++ ||
                    chunk->subjects.size() > (std::numeric_limits<std::uint64_t>::max)() - item_count) {
                    return false;
                }
                item_count += chunk->subjects.size();
            }
            return item_count == begin->expected_count;
        }

        [[nodiscard]] protocol_v2::SchemaAdvertisement schema(const std::string_view identifier) {
            const auto bytes = std::as_bytes(std::span {identifier.data(), identifier.size()});
            return protocol_v2::SchemaAdvertisement {
                .schema = SchemaId {std::string {identifier}}, .major = 1U, .canonical_hash = sha256_digest(bytes)};
        }

    } // namespace

    std::expected<std::unique_ptr<IWindowsAgentSession>, AgentFailure>
    make_tls_windows_agent_session(const WindowsAgentConfig &configuration) noexcept {
        if (!configuration.require_hard_resolver_bounds ||
            !configuration.reconnect_policy.require_hard_resolver_bounds) {
            return std::unexpected(AgentFailure {.code = AgentFailureCode::configuration,
                                                 .message = "production TLS session requires hard resolver bounds"});
        }
        auto context = protocol_v2::OpenSslTlsContext::create(protocol_v2::TlsConfiguration {
            .role = protocol_v2::TlsEndpointRole::client,
            .trust_anchors_pem = configuration.ca_path.string(),
            .certificate_chain_pem = configuration.certificate_path.string(),
            .private_key_pem = configuration.private_key_path.string(),
            .crl_pem = {},
            .expected_server_name = configuration.server_name,
            .require_crl = false,
            .verification_time_unix_seconds = std::nullopt,
            .protocol_limits = configuration.protocol_limits,
        });
        if (!context) {
            return std::unexpected(protocol_failure(context.error()));
        }
        auto dialer = protocol_v2::TlsSessionDialer::create(
            std::move(*context), configuration.endpoints,
            protocol_v2::TlsPeerRequirement {.canonical_uri_san = configuration.server_uri,
                                             .certificate_sha256 = configuration.server_fingerprint_sha256},
            configuration.socket_timeouts, configuration.reconnect_policy);
        if (!dialer) {
            return std::unexpected(protocol_failure(dialer.error()));
        }
        return std::unique_ptr<IWindowsAgentSession> {std::make_unique<TlsWindowsAgentSession>(std::move(*dialer))};
    }

    std::unique_ptr<IWindowsAgentProviderFactory> make_windows_agent_provider_factory() {
        return std::make_unique<ProductionProviderFactory>();
    }

    AgentHelloMessage make_windows_agent_hello() noexcept {
        AgentHelloMessage hello;
        hello.agent_version =
            "rule_engine_agent/" + std::string {agent_version} + ";windows;" + std::string {provider_name};
        constexpr std::array schema_ids {
            std::string_view {"rule-engine.fact-request.v1"},
            std::string_view {"rule-engine.fact-response.v1"},
            std::string_view {"rule-engine.scan-request.v1"},
            std::string_view {"rule-engine.scan-response.v1"},
            std::string_view {process_schema},
            std::string_view {image_schema},
            std::string_view {memory_region_schema},
        };
        hello.schemas.reserve(schema_ids.size());
        for (const auto identifier : schema_ids) { hello.schemas.push_back(schema(identifier)); }
        hello.capabilities = {
            {.capability = CapabilityId {"windows.fact.v1"},
             .version = 1U,
             .request_schema = SchemaId {"rule-engine.fact-request.v1"},
             .response_schema = SchemaId {"rule-engine.fact-response.v1"}},
            {.capability = CapabilityId {"windows.scan.v1"},
             .version = 1U,
             .request_schema = SchemaId {"rule-engine.scan-request.v1"},
             .response_schema = SchemaId {"rule-engine.scan-response.v1"}},
        };
        hello.receive_limit = protocol_v2::CreditWindow {
            .bytes = 16U * mebibyte, .messages = 1'024U, .work_attempts = 256U, .snapshot_chunks = 256U};
        return hello;
    }

    WindowsAgentService::WindowsAgentService(WindowsAgentConfig configuration, protocol_v2::SqliteAgentSpool &spool,
                                             std::unique_ptr<IWindowsAgentSession> session,
                                             std::unique_ptr<IWindowsAgentProviderFactory> providers) noexcept:
        configuration_ {std::move(configuration)},
        spool_ {&spool},
        persistent_session_ {configuration_.peer, spool},
        session_ {std::move(session)},
        providers_ {std::move(providers)},
        inventory_snapshot_id_ {persistent_session_.agent_epoch() +
                                ":windows.process:" + std::to_string(configuration_.active_generation)} {}

    std::expected<AgentRunStats, AgentFailure> WindowsAgentService::run(const std::stop_token cancellation) noexcept {
        if (spool_ == nullptr || session_ == nullptr || providers_ == nullptr || configuration_.peer.empty() ||
            configuration_.active_generation == 0U ||
            configuration_.maximum_work_horizon <= std::chrono::milliseconds::zero()) {
            return std::unexpected(
                AgentFailure {.code = AgentFailureCode::invariant, .message = "agent service is not fully configured"});
        }

        while (!cancellation.stop_requested()) {
            auto connected = session_->reconnect(persistent_session_, make_windows_agent_hello(), cancellation);
            if (!connected) {
                const auto failure = protocol_failure(connected.error());
                session_->shutdown();
                persistent_session_.disconnect();
                active_session_.reset();
                active_session_fence_ = 0U;
                if (failure.code == AgentFailureCode::canceled) {
                    return stats_;
                }
                if (!retryable(failure)) {
                    return std::unexpected(failure);
                }
                if (!wait_for_retry(configuration_.reconnect_policy.initial_backoff, cancellation)) {
                    return stats_;
                }
                continue;
            }
            if (!persistent_session_.established() || connected->server_hello.peer != configuration_.peer ||
                connected->server_hello.session.empty() || connected->server_hello.session_fence == 0U) {
                session_->shutdown();
                persistent_session_.disconnect();
                active_session_.reset();
                active_session_fence_ = 0U;
                return std::unexpected(AgentFailure {.code = AgentFailureCode::protocol,
                                                     .message = "server hello did not establish the configured peer"});
            }
            active_session_ = connected->server_hello.session;
            active_session_fence_ = connected->server_hello.session_fence;
            ++stats_.successful_connections;
            stats_.replayed_records += connected->replayed_records;
            auto provider = providers_->create(WindowsAgentRuntimeIdentity {
                .session = connected->server_hello.session,
                .peer = connected->server_hello.peer,
                .session_fence = connected->server_hello.session_fence,
                .generation = configuration_.active_generation,
                .route = std::string {provider_name},
            });
            if (!provider) {
                session_->shutdown();
                persistent_session_.disconnect();
                active_session_.reset();
                active_session_fence_ = 0U;
                return std::unexpected(std::move(provider.error()));
            }
            if (auto inventory = publish_initial_inventory(**provider); !inventory) {
                session_->shutdown();
                persistent_session_.disconnect();
                active_session_.reset();
                active_session_fence_ = 0U;
                return std::unexpected(std::move(inventory.error()));
            }

            bool reconnect_required {};
            while (!cancellation.stop_requested()) {
                if (auto flushed = flush(cancellation); !flushed) {
                    if (!retryable(flushed.error()) && flushed.error().code != AgentFailureCode::canceled) {
                        session_->shutdown();
                        persistent_session_.disconnect();
                        active_session_.reset();
                        active_session_fence_ = 0U;
                        return std::unexpected(std::move(flushed.error()));
                    }
                    reconnect_required = flushed.error().code != AgentFailureCode::canceled;
                    break;
                }
                auto envelope = session_->receive(cancellation);
                if (!envelope) {
                    const auto failure = protocol_failure(envelope.error());
                    if (!retryable(failure) && failure.code != AgentFailureCode::canceled) {
                        session_->shutdown();
                        persistent_session_.disconnect();
                        active_session_.reset();
                        active_session_fence_ = 0U;
                        return std::unexpected(failure);
                    }
                    reconnect_required = failure.code != AgentFailureCode::canceled;
                    break;
                }
                if (cancellation.stop_requested()) {
                    break;
                }
                if (auto processed = process(*envelope, **provider); !processed) {
                    session_->shutdown();
                    persistent_session_.disconnect();
                    active_session_.reset();
                    active_session_fence_ = 0U;
                    return std::unexpected(std::move(processed.error()));
                }
            }
            session_->shutdown();
            persistent_session_.disconnect();
            active_session_.reset();
            active_session_fence_ = 0U;
            if (!reconnect_required || cancellation.stop_requested()) {
                return stats_;
            }
            if (!wait_for_retry(configuration_.reconnect_policy.initial_backoff, cancellation)) {
                return stats_;
            }
        }
        session_->shutdown();
        persistent_session_.disconnect();
        active_session_.reset();
        active_session_fence_ = 0U;
        return stats_;
    }

    std::expected<void, AgentFailure> WindowsAgentService::flush(const std::stop_token cancellation) noexcept {
        auto batch = persistent_session_.take_transmit_batch();
        if (!batch) {
            return std::unexpected(protocol_failure(batch.error()));
        }
        for (const auto &envelope : *batch) {
            if (auto sent = session_->send(envelope, cancellation); !sent) {
                return std::unexpected(protocol_failure(sent.error()));
            }
        }
        return {};
    }

    std::expected<void, AgentFailure> WindowsAgentService::process(const PeerEnvelope &envelope,
                                                                   IWindowsAgentProviderRuntime &provider) noexcept {
        if (!active_session_.has_value() || !envelope.session.has_value() || envelope.session != active_session_ ||
            envelope.agent_epoch != persistent_session_.agent_epoch()) {
            return std::unexpected(AgentFailure {.code = AgentFailureCode::protocol,
                                                 .message = "server envelope session or epoch is stale"});
        }

        if (const auto *work = std::get_if<WorkLeaseMessage>(&envelope.body)) {
            auto accepted = persistent_session_.accept_work(*work);
            if (!accepted) {
                return std::unexpected(protocol_failure(accepted.error()));
            }
            if (accepted->disposition == protocol_v2::WorkAcceptance::Disposition::duplicate) {
                ++stats_.duplicate_leases;
                return {};
            }
            if (work->generation != configuration_.active_generation || work->route != provider_name) {
                return std::unexpected(AgentFailure {.code = AgentFailureCode::protocol,
                                                     .message = "work generation or provider route is not active"});
            }
            if (!deadlines_are_locally_bounded(*work, configuration_.maximum_work_horizon)) {
                return std::unexpected(AgentFailure {.code = AgentFailureCode::protocol,
                                                     .message = "work deadline exceeds the local execution horizon"});
            }
            auto pending = result_is_pending(*work);
            if (!pending) {
                return std::unexpected(std::move(pending.error()));
            }
            if (*pending) {
                ++stats_.duplicate_leases;
                return {};
            }
            if (persistent_session_.backpressured()) {
                return std::unexpected(
                    AgentFailure {.code = AgentFailureCode::persistence, .message = "durable spool is backpressured"});
            }
            auto result = provider.dispatch(*work);
            if (!result) {
                return std::unexpected(provider_failure(result.error()));
            }
            if (auto sequence = persistent_session_.enqueue(protocol_v2::DurableAgentBody {std::move(*result)});
                !sequence) {
                return std::unexpected(protocol_failure(sequence.error()));
            }
            ++stats_.accepted_leases;
            ++stats_.work_results_spooled;
            return {};
        }
        if (const auto *cancel = std::get_if<CancelWorkMessage>(&envelope.body)) {
            auto accepted = persistent_session_.accept_cancel(*cancel);
            if (!accepted) {
                return std::unexpected(protocol_failure(accepted.error()));
            }
            if (auto canceled = provider.cancel(*cancel); !canceled) {
                return std::unexpected(provider_failure(canceled.error()));
            }
            ++stats_.canceled_work;
            return {};
        }
        if (const auto *ack = std::get_if<AckMessage>(&envelope.body)) {
            if (auto acknowledged = persistent_session_.acknowledge(*ack); !acknowledged) {
                return std::unexpected(protocol_failure(acknowledged.error()));
            }
            ++stats_.acknowledgements;
            return {};
        }
        if (const auto *nack = std::get_if<NackMessage>(&envelope.body)) {
            if (auto rejected = persistent_session_.reject(*nack); !rejected) {
                return std::unexpected(protocol_failure(rejected.error()));
            }
            ++stats_.rejections;
            return {};
        }
        if (const auto *credit = std::get_if<CreditUpdateMessage>(&envelope.body)) {
            persistent_session_.update_credit(credit->credit);
            return {};
        }
        return std::unexpected(AgentFailure {.code = AgentFailureCode::protocol,
                                             .message = "agent received a message type that servers cannot send"});
    }

    std::expected<void, AgentFailure>
    WindowsAgentService::publish_initial_inventory(IWindowsAgentProviderRuntime &provider) noexcept {
        if (inventory_attempted_) {
            return {};
        }
        auto pending = snapshot_is_pending(inventory_snapshot_id_);
        if (!pending) {
            return std::unexpected(std::move(pending.error()));
        }
        if (*pending) {
            inventory_attempted_ = true;
            return {};
        }
        auto projection = provider.initial_process_inventory(inventory_snapshot_id_);
        if (!projection) {
            return std::unexpected(provider_failure(projection.error()));
        }
        inventory_attempted_ = true;
        if (!projection->has_value() || (*projection)->duplicate || (*projection)->durable_messages.empty()) {
            return {};
        }
        if (!active_session_.has_value() ||
            !valid_snapshot_projection(**projection, *active_session_, configuration_.peer, active_session_fence_,
                                       configuration_.active_generation, inventory_snapshot_id_)) {
            return std::unexpected(
                AgentFailure {.code = AgentFailureCode::provider,
                              .message = "provider returned an invalid initial inventory projection"});
        }
        auto sequences = spool_->enqueue_batch((*projection)->durable_messages);
        if (!sequences) {
            return std::unexpected(protocol_failure(sequences.error()));
        }
        stats_.snapshot_records_spooled += sequences->size();
        return {};
    }

    std::expected<bool, AgentFailure>
    WindowsAgentService::result_is_pending(const WorkLeaseMessage &work) const noexcept {
        auto records =
            spool_->pending(configuration_.spool_limits.maximum_records, configuration_.spool_limits.maximum_bytes);
        if (!records) {
            return std::unexpected(protocol_failure(records.error()));
        }
        return std::ranges::any_of(*records, [&](const auto &record) {
            const auto *result = std::get_if<WorkResultMessage>(&record.body);
            return result != nullptr && work_result_matches(*result, work);
        });
    }

    std::expected<bool, AgentFailure>
    WindowsAgentService::snapshot_is_pending(const std::string_view snapshot_id) const noexcept {
        auto records =
            spool_->pending(configuration_.spool_limits.maximum_records, configuration_.spool_limits.maximum_bytes);
        if (!records) {
            return std::unexpected(protocol_failure(records.error()));
        }
        return std::ranges::any_of(*records,
                                   [&](const auto &record) { return snapshot_matches(record.body, snapshot_id); });
    }

} // namespace rule_engine::python::windows
