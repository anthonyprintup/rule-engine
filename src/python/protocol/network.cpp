#include "rule_engine/python/protocol/network.hpp"

#include <exception>

namespace asio::detail {
    template<typename Exception> [[noreturn]] void throw_exception(const Exception &) { std::terminate(); }
} // namespace asio::detail

#include <asio/error.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/address.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/post.hpp>
#include <asio/steady_timer.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <limits>
#include <mutex>
#include <optional>
#include <string_view>
#include <unordered_set>
#include <utility>

namespace rule_engine::python::protocol_v2 {
    namespace {
        using asio::ip::tcp;
        using Clock = std::chrono::steady_clock;

        constexpr auto maximum_operation_timeout = std::chrono::minutes {5};
        constexpr auto maximum_total_dial_timeout = std::chrono::minutes {30};
        constexpr std::size_t maximum_listen_backlog = 1'024;

        [[nodiscard]] ProtocolError network_error(const ProtocolErrorCode code, std::string message) {
            return ProtocolError {.code = code, .message = std::move(message), .byte_offset = 0};
        }

        [[nodiscard]] ProtocolError asio_error(const std::string_view activity, const asio::error_code &error) {
            return network_error(ProtocolErrorCode::transport_error,
                                 std::string {activity} + " failed: " + error.message());
        }

        [[nodiscard]] ProtocolError timeout_error(const std::string_view activity) {
            return network_error(ProtocolErrorCode::timed_out, std::string {activity} + " timed out");
        }

        [[nodiscard]] ProtocolError canceled_error(const std::string_view activity) {
            return network_error(ProtocolErrorCode::canceled, std::string {activity} + " was canceled");
        }

        [[nodiscard]] bool positive_bounded(const std::chrono::milliseconds value,
                                            const std::chrono::milliseconds maximum) noexcept {
            return value > std::chrono::milliseconds::zero() && value <= maximum;
        }

        [[nodiscard]] bool valid_timeouts(const SocketTimeouts &timeouts) noexcept {
            return positive_bounded(timeouts.resolve, maximum_operation_timeout) &&
                   positive_bounded(timeouts.connect, maximum_operation_timeout) &&
                   positive_bounded(timeouts.accept, maximum_operation_timeout) &&
                   positive_bounded(timeouts.handshake, maximum_operation_timeout) &&
                   positive_bounded(timeouts.read, maximum_operation_timeout) &&
                   positive_bounded(timeouts.write, maximum_operation_timeout) &&
                   positive_bounded(timeouts.total_dial, maximum_total_dial_timeout);
        }

        [[nodiscard]] bool valid_reconnect_policy(const ReconnectPolicy &policy) noexcept {
            return positive_bounded(policy.initial_backoff, maximum_operation_timeout) &&
                   policy.maximum_backoff >= policy.initial_backoff &&
                   policy.maximum_backoff <= maximum_operation_timeout && policy.maximum_rounds > 0 &&
                   policy.maximum_rounds <= 64 && policy.maximum_endpoints > 0 && policy.maximum_endpoints <= 64 &&
                   policy.maximum_addresses_per_endpoint > 0 && policy.maximum_addresses_per_endpoint <= 64 &&
                   policy.maximum_connection_attempts > 0 && policy.maximum_connection_attempts <= 1'024;
        }

        [[nodiscard]] bool valid_endpoint(const TcpEndpoint &endpoint) noexcept {
            return !endpoint.host.empty() && endpoint.host.size() <= 1'024 && endpoint.port != 0;
        }

        [[nodiscard]] bool lowercase_sha256(const std::string_view value) noexcept {
            return value.size() == 64 && std::ranges::all_of(value, [](const char character) {
                       return (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f');
                   });
        }

        [[nodiscard]] Clock::time_point deadline_after(const std::chrono::milliseconds duration) noexcept {
            return Clock::now() + duration;
        }

        [[nodiscard]] Clock::time_point bounded_deadline(const Clock::time_point overall,
                                                         const std::chrono::milliseconds duration) noexcept {
            return (std::min) (overall, deadline_after(duration));
        }

        [[nodiscard]] std::expected<void, ProtocolError> interruptible_delay(const std::chrono::milliseconds delay,
                                                                             const Clock::time_point overall,
                                                                             const std::stop_token cancellation) {
            if (cancellation.stop_requested()) {
                return std::unexpected(canceled_error("TLS reconnect delay"));
            }
            if (delay <= std::chrono::milliseconds::zero()) {
                return Clock::now() >= overall ? std::unexpected(timeout_error("TLS dial")) :
                                                 std::expected<void, ProtocolError> {};
            }
            const auto deadline = (std::min) (overall, deadline_after(delay));
            if (Clock::now() >= deadline) {
                return std::unexpected(timeout_error("TLS dial"));
            }

            std::mutex mutex;
            std::condition_variable condition;
            std::stop_callback on_stop {cancellation, [&] {
                                            std::scoped_lock lock {mutex};
                                            condition.notify_all();
                                        }};
            std::unique_lock lock {mutex};
            condition.wait_until(lock, deadline, [&cancellation] { return cancellation.stop_requested(); });
            if (cancellation.stop_requested()) {
                return std::unexpected(canceled_error("TLS reconnect delay"));
            }
            if (deadline == overall && Clock::now() >= overall) {
                return std::unexpected(timeout_error("TLS dial"));
            }
            return {};
        }

        struct ConnectedTcpSocket {
            std::shared_ptr<asio::io_context> io;
            tcp::socket socket;
            TcpEndpoint remote;

            ConnectedTcpSocket(std::shared_ptr<asio::io_context> context, tcp::socket value, TcpEndpoint endpoint):
                io {std::move(context)}, socket {std::move(value)}, remote {std::move(endpoint)} {}
            ConnectedTcpSocket(ConnectedTcpSocket &&) noexcept = default;
            ConnectedTcpSocket(const ConnectedTcpSocket &) = delete;
            ConnectedTcpSocket &operator=(const ConnectedTcpSocket &) = delete;
        };

        [[nodiscard]] std::expected<ConnectedTcpSocket, ProtocolError>
        connect_address(const ResolvedTcpAddress &resolved, const Clock::time_point deadline,
                        const std::stop_token cancellation) {
            if (cancellation.stop_requested()) {
                return std::unexpected(canceled_error("TCP connect"));
            }
            if (Clock::now() >= deadline) {
                return std::unexpected(timeout_error("TCP connect"));
            }

            auto io = std::make_shared<asio::io_context>();
            asio::error_code error;
            const auto address = asio::ip::make_address(resolved.address, error);
            if (error || (resolved.family == TcpAddressFamily::ipv4) != address.is_v4()) {
                return std::unexpected(
                    network_error(ProtocolErrorCode::malformed, "resolver returned an invalid numeric TCP address"));
            }

            tcp::socket socket {*io};
            socket.open(address.is_v4() ? tcp::v4() : tcp::v6(), error);
            if (error) {
                return std::unexpected(asio_error("TCP socket open", error));
            }

            asio::steady_timer timer {*io};
            bool completed {};
            bool timed_out {};
            bool canceled {};
            asio::error_code connect_error;
            timer.expires_at(deadline);
            socket.async_connect(tcp::endpoint {address, resolved.port}, [&](const asio::error_code &result) {
                connect_error = result;
                completed = true;
                timer.cancel();
            });
            timer.async_wait([&](const asio::error_code &result) {
                if (!result && !completed) {
                    timed_out = true;
                    asio::error_code ignored;
                    socket.cancel(ignored);
                    socket.close(ignored);
                }
            });
            std::stop_callback on_stop {cancellation, [&] {
                                            asio::post(*io, [&] {
                                                if (!completed) {
                                                    canceled = true;
                                                    timer.cancel();
                                                    asio::error_code ignored;
                                                    socket.cancel(ignored);
                                                    socket.close(ignored);
                                                }
                                            });
                                        }};
            io->run();

            if (canceled || cancellation.stop_requested()) {
                return std::unexpected(canceled_error("TCP connect"));
            }
            if (timed_out) {
                return std::unexpected(timeout_error("TCP connect"));
            }
            if (connect_error) {
                return std::unexpected(asio_error("TCP connect", connect_error));
            }

            socket.set_option(tcp::no_delay {true}, error);
            if (!error) {
                socket.native_non_blocking(true, error);
            }
            if (error) {
                return std::unexpected(asio_error("TCP socket setup", error));
            }
            return ConnectedTcpSocket {std::move(io), std::move(socket),
                                       TcpEndpoint {.host = resolved.address, .port = resolved.port}};
        }

        [[nodiscard]] std::chrono::milliseconds backoff_cap(const ReconnectPolicy &policy,
                                                            const std::size_t failed_rounds) noexcept {
            auto cap = policy.initial_backoff;
            for (std::size_t round = 1; round < failed_rounds && cap < policy.maximum_backoff; ++round) {
                cap = (std::min) (policy.maximum_backoff, cap * 2);
            }
            return cap;
        }

        [[nodiscard]] bool identity_matches(const TlsPeerIdentity &identity,
                                            const TlsPeerRequirement &requirement) noexcept {
            return identity.canonical_uri_san == requirement.canonical_uri_san &&
                   (!requirement.certificate_sha256.has_value() ||
                    identity.certificate_sha256 == *requirement.certificate_sha256);
        }

    } // namespace

    struct TlsPeerConnection::Impl {
        std::shared_ptr<asio::io_context> io;
        tcp::socket socket;
        OpenSslTlsSession tls;
        TlsPeerIdentity identity;
        TcpEndpoint remote;
        SocketTimeouts timeouts;

        Impl(std::shared_ptr<asio::io_context> context, tcp::socket value, OpenSslTlsSession session,
             TlsPeerIdentity peer_identity, TcpEndpoint endpoint, SocketTimeouts configured_timeouts):
            io {std::move(context)},
            socket {std::move(value)},
            tls {std::move(session)},
            identity {std::move(peer_identity)},
            remote {std::move(endpoint)},
            timeouts {configured_timeouts} {}
    };

    struct TlsSessionListener::Impl {
        std::shared_ptr<asio::io_context> io;
        tcp::acceptor acceptor;
        OpenSslTlsContext context;
        TcpEndpoint local;
        SocketTimeouts timeouts;
        std::stop_source cancellation;
        std::mutex accept_mutex;

        Impl(std::shared_ptr<asio::io_context> execution_context, tcp::acceptor value, OpenSslTlsContext tls_context,
             TcpEndpoint endpoint, SocketTimeouts configured_timeouts):
            io {std::move(execution_context)},
            acceptor {std::move(value)},
            context {std::move(tls_context)},
            local {std::move(endpoint)},
            timeouts {configured_timeouts} {}
    };

    struct TlsSessionDialer::Impl {
        OpenSslTlsContext context;
        std::vector<TcpEndpoint> endpoints;
        TlsPeerRequirement peer_requirement;
        SocketTimeouts timeouts;
        ReconnectPolicy reconnect;

        Impl(OpenSslTlsContext tls_context, std::vector<TcpEndpoint> configured_endpoints,
             TlsPeerRequirement requirement, SocketTimeouts configured_timeouts, ReconnectPolicy reconnect_policy):
            context {std::move(tls_context)},
            endpoints {std::move(configured_endpoints)},
            peer_requirement {std::move(requirement)},
            timeouts {configured_timeouts},
            reconnect {reconnect_policy} {}
    };

    std::expected<std::vector<ResolvedTcpAddress>, ProtocolError>
    SystemEndpointResolver::resolve(const TcpEndpoint &endpoint, const std::size_t maximum_addresses,
                                    const Clock::time_point deadline, const std::stop_token cancellation) noexcept {
        if (!valid_endpoint(endpoint) || maximum_addresses == 0 || maximum_addresses > 64) {
            return std::unexpected(network_error(ProtocolErrorCode::malformed, "DNS resolution request is invalid"));
        }
        if (cancellation.stop_requested()) {
            return std::unexpected(canceled_error("DNS resolution"));
        }
        if (Clock::now() >= deadline) {
            return std::unexpected(timeout_error("DNS resolution"));
        }

        asio::io_context io;
        tcp::resolver resolver {io};
        asio::steady_timer timer {io};
        std::vector<ResolvedTcpAddress> addresses;
        asio::error_code resolve_error;
        bool completed {};
        bool timed_out {};
        bool canceled {};
        timer.expires_at(deadline);
        resolver.async_resolve(endpoint.host, std::to_string(endpoint.port),
                               [&](const asio::error_code &error, const tcp::resolver::results_type &results) {
                                   resolve_error = error;
                                   if (!error) {
                                       std::unordered_set<std::string> seen;
                                       for (const auto &result : results) {
                                           auto text = result.endpoint().address().to_string();
                                           if (text.empty() || !seen.insert(text).second) {
                                               continue;
                                           }
                                           addresses.push_back(ResolvedTcpAddress {
                                               .family = result.endpoint().address().is_v4() ? TcpAddressFamily::ipv4 :
                                                                                               TcpAddressFamily::ipv6,
                                               .address = std::move(text),
                                               .port = result.endpoint().port(),
                                           });
                                           if (addresses.size() == maximum_addresses) {
                                               break;
                                           }
                                       }
                                   }
                                   completed = true;
                                   timer.cancel();
                               });
        timer.async_wait([&](const asio::error_code &error) {
            if (!error && !completed) {
                timed_out = true;
                resolver.cancel();
            }
        });
        std::stop_callback on_stop {cancellation, [&] {
                                        asio::post(io, [&] {
                                            if (!completed) {
                                                canceled = true;
                                                resolver.cancel();
                                                timer.cancel();
                                            }
                                        });
                                    }};
        io.run();

        if (canceled || cancellation.stop_requested()) {
            return std::unexpected(canceled_error("DNS resolution"));
        }
        if (timed_out) {
            return std::unexpected(timeout_error("DNS resolution"));
        }
        if (resolve_error) {
            return std::unexpected(asio_error("DNS resolution", resolve_error));
        }
        if (addresses.empty()) {
            return std::unexpected(
                network_error(ProtocolErrorCode::transport_error, "DNS resolution returned no usable addresses"));
        }
        return addresses;
    }

    XorShiftBackoffJitter::XorShiftBackoffJitter(std::uint64_t seed) noexcept:
        state_ {seed == 0 ? static_cast<std::uint64_t>(Clock::now().time_since_epoch().count()) : seed} {
        if (state_ == 0) {
            state_ = 0x9e3779b97f4a7c15ULL;
        }
    }

    std::chrono::milliseconds
    XorShiftBackoffJitter::choose(const std::chrono::milliseconds inclusive_upper_bound) noexcept {
        state_ ^= state_ << 13U;
        state_ ^= state_ >> 7U;
        state_ ^= state_ << 17U;
        if (inclusive_upper_bound <= std::chrono::milliseconds::zero()) {
            return std::chrono::milliseconds::zero();
        }
        const auto upper = static_cast<std::uint64_t>(inclusive_upper_bound.count());
        return std::chrono::milliseconds {static_cast<std::int64_t>(state_ % (upper + 1U))};
    }

    TlsPeerConnection::TlsPeerConnection(std::unique_ptr<Impl> impl) noexcept: impl_ {std::move(impl)} {}
    TlsPeerConnection::TlsPeerConnection(TlsPeerConnection &&) noexcept = default;
    TlsPeerConnection &TlsPeerConnection::operator=(TlsPeerConnection &&) noexcept = default;
    TlsPeerConnection::~TlsPeerConnection() = default;

    std::expected<void, ProtocolError> TlsPeerConnection::send(const PeerEnvelope &envelope,
                                                               const std::stop_token cancellation) noexcept {
        return send_until(envelope, Clock::time_point::max(), cancellation);
    }

    std::expected<void, ProtocolError> TlsPeerConnection::send_until(const PeerEnvelope &envelope,
                                                                     const Clock::time_point deadline,
                                                                     const std::stop_token cancellation) noexcept {
        if (!established()) {
            return std::unexpected(
                network_error(ProtocolErrorCode::transport_error, "owned TLS connection is not established"));
        }
        return impl_->tls.send(
            envelope, TransportOperation {.deadline = (std::min) (deadline, deadline_after(impl_->timeouts.write)),
                                          .cancellation = cancellation});
    }

    std::expected<PeerEnvelope, ProtocolError> TlsPeerConnection::receive(const std::stop_token cancellation) noexcept {
        return receive_until(Clock::time_point::max(), cancellation);
    }

    std::expected<PeerEnvelope, ProtocolError>
    TlsPeerConnection::receive_until(const Clock::time_point deadline, const std::stop_token cancellation) noexcept {
        if (!established()) {
            return std::unexpected(
                network_error(ProtocolErrorCode::transport_error, "owned TLS connection is not established"));
        }
        return impl_->tls.receive(TransportOperation {
            .deadline = (std::min) (deadline, deadline_after(impl_->timeouts.read)), .cancellation = cancellation});
    }

    std::expected<bool, ProtocolError>
    TlsPeerConnection::wait_readable_until(const Clock::time_point deadline,
                                           const std::stop_token cancellation) noexcept {
        if (!established()) {
            return std::unexpected(
                network_error(ProtocolErrorCode::transport_error, "owned TLS connection is not established"));
        }
        if (cancellation.stop_requested()) {
            return std::unexpected(canceled_error("TLS input wait"));
        }

        std::mutex mutex;
        std::condition_variable condition;
        std::stop_callback on_stop {cancellation, [&] {
                                        std::scoped_lock lock {mutex};
                                        condition.notify_all();
                                    }};
        std::unique_lock lock {mutex};
        constexpr auto readiness_poll = std::chrono::milliseconds {10};
        while (!cancellation.stop_requested()) {
            if (impl_->tls.pending_input()) {
                return true;
            }
            asio::error_code error;
            const auto available = impl_->socket.available(error);
            if (error) {
                return std::unexpected(asio_error("TLS input readiness", error));
            }
            if (available != 0U) {
                return true;
            }
            const auto now = Clock::now();
            if (now >= deadline) {
                return false;
            }
            condition.wait_until(lock, (std::min) (deadline, now + readiness_poll),
                                 [&cancellation] { return cancellation.stop_requested(); });
        }
        return std::unexpected(canceled_error("TLS input wait"));
    }

    std::expected<void, ProtocolError>
    TlsPeerConnection::send_application_frame_until(const std::span<const std::byte> payload,
                                                    const Clock::time_point deadline,
                                                    const std::stop_token cancellation) noexcept {
        if (!established()) {
            return std::unexpected(
                network_error(ProtocolErrorCode::transport_error, "owned TLS connection is not established"));
        }
        return impl_->tls.send_application_frame(
            payload, TransportOperation {.deadline = (std::min) (deadline, deadline_after(impl_->timeouts.write)),
                                         .cancellation = cancellation});
    }

    std::expected<std::vector<std::byte>, ProtocolError>
    TlsPeerConnection::receive_application_frame_until(const Clock::time_point deadline,
                                                       const std::stop_token cancellation) noexcept {
        if (!established()) {
            return std::unexpected(
                network_error(ProtocolErrorCode::transport_error, "owned TLS connection is not established"));
        }
        return impl_->tls.receive_application_frame(TransportOperation {
            .deadline = (std::min) (deadline, deadline_after(impl_->timeouts.read)), .cancellation = cancellation});
    }

    TlsPeerIdentity TlsPeerConnection::peer_identity() const {
        return impl_ == nullptr ? TlsPeerIdentity {} : impl_->identity;
    }

    TcpEndpoint TlsPeerConnection::remote_endpoint() const { return impl_ == nullptr ? TcpEndpoint {} : impl_->remote; }

    bool TlsPeerConnection::established() const noexcept {
        return impl_ != nullptr && impl_->socket.is_open() && impl_->tls.established();
    }

    void TlsPeerConnection::shutdown() noexcept {
        if (impl_ == nullptr) {
            return;
        }
        impl_->tls.shutdown();
        asio::error_code ignored;
        impl_->socket.cancel(ignored);
        impl_->socket.close(ignored);
    }

    TlsSessionListener::TlsSessionListener(std::unique_ptr<Impl> impl) noexcept: impl_ {std::move(impl)} {}
    TlsSessionListener::TlsSessionListener(TlsSessionListener &&) noexcept = default;
    TlsSessionListener &TlsSessionListener::operator=(TlsSessionListener &&) noexcept = default;
    TlsSessionListener::~TlsSessionListener() = default;

    std::expected<TlsSessionListener, ProtocolError>
    TlsSessionListener::bind(OpenSslTlsContext context, TcpEndpoint endpoint, const SocketTimeouts timeouts,
                             const std::size_t listen_backlog) noexcept {
        if (!tls_backend_status().available) {
            return std::unexpected(
                network_error(ProtocolErrorCode::dependency_unavailable, "TLS listener requires the OpenSSL backend"));
        }
        if (!context.valid() || context.role() != TlsEndpointRole::server || endpoint.host.empty() ||
            endpoint.host.size() > 1'024 || !valid_timeouts(timeouts) || listen_backlog == 0 ||
            listen_backlog > maximum_listen_backlog) {
            return std::unexpected(
                network_error(ProtocolErrorCode::malformed, "TLS listener configuration is invalid"));
        }

        asio::error_code error;
        const auto address = asio::ip::make_address(endpoint.host, error);
        if (error) {
            return std::unexpected(
                network_error(ProtocolErrorCode::malformed, "TLS listener bind address must be numeric"));
        }
        auto io = std::make_shared<asio::io_context>();
        tcp::acceptor acceptor {*io};
        const tcp::endpoint bind_endpoint {address, endpoint.port};
        acceptor.open(bind_endpoint.protocol(), error);
        if (!error) {
            acceptor.set_option(tcp::acceptor::reuse_address {true}, error);
        }
        if (!error) {
            acceptor.bind(bind_endpoint, error);
        }
        if (!error) {
            acceptor.listen(static_cast<int>(listen_backlog), error);
        }
        if (error) {
            return std::unexpected(asio_error("TLS listener bind", error));
        }
        const auto local = acceptor.local_endpoint(error);
        if (error) {
            return std::unexpected(asio_error("TLS listener endpoint query", error));
        }
        return TlsSessionListener {
            std::make_unique<Impl>(std::move(io), std::move(acceptor), std::move(context),
                                   TcpEndpoint {.host = local.address().to_string(), .port = local.port()}, timeouts)};
    }

    std::expected<AuthenticatedTlsPeer, ProtocolError>
    TlsSessionListener::accept(const ITrustPolicy &trust_policy, const std::stop_token cancellation) noexcept {
        if (impl_ == nullptr || impl_->cancellation.stop_requested()) {
            return std::unexpected(canceled_error("TLS listener accept"));
        }
        std::scoped_lock accept_lock {impl_->accept_mutex};
        if (impl_->cancellation.stop_requested() || cancellation.stop_requested()) {
            return std::unexpected(canceled_error("TLS listener accept"));
        }

        impl_->io->restart();
        tcp::socket socket {*impl_->io};
        asio::error_code accept_error;
        bool completed {};
        impl_->acceptor.async_accept(socket, [&](const asio::error_code &error) {
            accept_error = error;
            completed = true;
        });

        std::stop_source operation_cancellation;
        std::stop_callback on_caller_stop {cancellation, [&] { operation_cancellation.request_stop(); }};
        std::stop_callback on_listener_stop {impl_->cancellation.get_token(),
                                             [&] { operation_cancellation.request_stop(); }};
        constexpr auto cancellation_poll = std::chrono::milliseconds {25};
        const auto accept_deadline = deadline_after(impl_->timeouts.accept);
        while (!completed && !operation_cancellation.stop_requested() && Clock::now() < accept_deadline) {
            const auto remaining = std::chrono::ceil<std::chrono::milliseconds>(accept_deadline - Clock::now());
            impl_->io->run_for((std::min) (cancellation_poll, remaining));
            if (impl_->io->stopped() && !completed) {
                impl_->io->restart();
            }
        }
        const auto canceled = operation_cancellation.stop_requested();
        const auto timed_out = !completed && Clock::now() >= accept_deadline;
        if (!completed) {
            asio::error_code ignored;
            impl_->acceptor.cancel(ignored);
            if (impl_->io->stopped()) {
                impl_->io->restart();
            }
            impl_->io->run();
        }
        if (canceled) {
            return std::unexpected(canceled_error("TLS listener accept"));
        }
        if (timed_out) {
            return std::unexpected(timeout_error("TLS listener accept"));
        }
        if (accept_error) {
            return std::unexpected(asio_error("TLS listener accept", accept_error));
        }

        asio::error_code error;
        const auto remote = socket.remote_endpoint(error);
        if (!error) {
            socket.set_option(tcp::no_delay {true}, error);
        }
        if (!error) {
            socket.native_non_blocking(true, error);
        }
        if (error) {
            return std::unexpected(asio_error("accepted TCP socket setup", error));
        }
        auto attached = impl_->context.attach_connected_socket(static_cast<std::intptr_t>(socket.native_handle()));
        if (!attached) {
            return std::unexpected(std::move(attached.error()));
        }
        auto identity = attached->handshake(TransportOperation {.deadline = deadline_after(impl_->timeouts.handshake),
                                                                .cancellation = operation_cancellation.get_token()});
        if (!identity) {
            return std::unexpected(std::move(identity.error()));
        }
        if (operation_cancellation.stop_requested()) {
            return std::unexpected(canceled_error("TLS listener accept"));
        }
        auto peer = authenticate_transport(*identity, trust_policy);
        if (!peer) {
            return std::unexpected(std::move(peer.error()));
        }
        if (operation_cancellation.stop_requested()) {
            return std::unexpected(canceled_error("TLS listener accept"));
        }
        auto connection = TlsPeerConnection {std::make_unique<TlsPeerConnection::Impl>(
            impl_->io, std::move(socket), std::move(*attached), std::move(*identity),
            TcpEndpoint {.host = remote.address().to_string(), .port = remote.port()}, impl_->timeouts)};
        return AuthenticatedTlsPeer {.connection = std::move(connection), .peer = std::move(*peer)};
    }

    TcpEndpoint TlsSessionListener::local_endpoint() const noexcept {
        return impl_ == nullptr ? TcpEndpoint {} : impl_->local;
    }

    void TlsSessionListener::cancel() noexcept {
        if (impl_ == nullptr) {
            return;
        }
        impl_->cancellation.request_stop();
    }

    TlsSessionDialer::TlsSessionDialer(std::unique_ptr<Impl> impl) noexcept: impl_ {std::move(impl)} {}
    TlsSessionDialer::TlsSessionDialer(TlsSessionDialer &&) noexcept = default;
    TlsSessionDialer &TlsSessionDialer::operator=(TlsSessionDialer &&) noexcept = default;
    TlsSessionDialer::~TlsSessionDialer() = default;

    std::expected<TlsSessionDialer, ProtocolError> TlsSessionDialer::create(OpenSslTlsContext context,
                                                                            std::vector<TcpEndpoint> endpoints,
                                                                            TlsPeerRequirement peer_requirement,
                                                                            const SocketTimeouts timeouts,
                                                                            const ReconnectPolicy reconnect) noexcept {
        if (!tls_backend_status().available) {
            return std::unexpected(
                network_error(ProtocolErrorCode::dependency_unavailable, "TLS dialer requires the OpenSSL backend"));
        }
        if (!context.valid() || context.role() != TlsEndpointRole::client || endpoints.empty() ||
            !valid_timeouts(timeouts) || !valid_reconnect_policy(reconnect) ||
            endpoints.size() > reconnect.maximum_endpoints || peer_requirement.canonical_uri_san.empty() ||
            peer_requirement.canonical_uri_san.size() > 1'024 ||
            (peer_requirement.certificate_sha256.has_value() &&
             !lowercase_sha256(*peer_requirement.certificate_sha256)) ||
            !std::ranges::all_of(endpoints, valid_endpoint)) {
            return std::unexpected(network_error(ProtocolErrorCode::malformed, "TLS dialer configuration is invalid"));
        }
        return TlsSessionDialer {std::make_unique<Impl>(std::move(context), std::move(endpoints),
                                                        std::move(peer_requirement), timeouts, reconnect)};
    }

    std::expected<TlsPeerConnection, ProtocolError>
    TlsSessionDialer::connect(const std::stop_token cancellation) noexcept {
        SystemEndpointResolver resolver;
        XorShiftBackoffJitter jitter;
        return connect(resolver, jitter, cancellation);
    }

    std::expected<TlsPeerConnection, ProtocolError>
    TlsSessionDialer::connect(IEndpointResolver &resolver, IBackoffJitter &jitter,
                              const std::stop_token cancellation) noexcept {
        if (impl_ == nullptr) {
            return std::unexpected(network_error(ProtocolErrorCode::malformed, "TLS dialer is not configured"));
        }
        if (impl_->reconnect.require_hard_resolver_bounds && !resolver.hard_bounds_guaranteed()) {
            return std::unexpected(
                network_error(ProtocolErrorCode::dependency_unavailable,
                              "TLS dialer requires an injected resolver with hard deadline guarantees"));
        }
        const auto overall_deadline = deadline_after(impl_->timeouts.total_dial);
        ProtocolError last_error = network_error(ProtocolErrorCode::transport_error, "no TLS endpoint was attempted");
        std::size_t connection_attempts {};

        for (std::size_t round = 0; round < impl_->reconnect.maximum_rounds; ++round) {
            for (const auto &endpoint : impl_->endpoints) {
                if (cancellation.stop_requested()) {
                    return std::unexpected(canceled_error("TLS dial"));
                }
                if (Clock::now() >= overall_deadline) {
                    return std::unexpected(timeout_error("TLS dial"));
                }
                auto addresses =
                    resolver.resolve(endpoint, impl_->reconnect.maximum_addresses_per_endpoint,
                                     bounded_deadline(overall_deadline, impl_->timeouts.resolve), cancellation);
                if (!addresses) {
                    if (addresses.error().code == ProtocolErrorCode::canceled) {
                        return std::unexpected(std::move(addresses.error()));
                    }
                    last_error = std::move(addresses.error());
                    continue;
                }
                if (addresses->empty() || addresses->size() > impl_->reconnect.maximum_addresses_per_endpoint) {
                    last_error =
                        network_error(ProtocolErrorCode::limit_exceeded, "resolver returned an invalid address count");
                    continue;
                }
                if (!std::ranges::all_of(*addresses, [&endpoint](const ResolvedTcpAddress &address) {
                        return !address.address.empty() && address.port == endpoint.port;
                    })) {
                    last_error =
                        network_error(ProtocolErrorCode::malformed, "resolver returned an invalid TCP address");
                    continue;
                }

                for (const auto &address : *addresses) {
                    if (++connection_attempts > impl_->reconnect.maximum_connection_attempts) {
                        return std::unexpected(network_error(ProtocolErrorCode::limit_exceeded,
                                                             "TLS connection attempt limit was reached"));
                    }
                    auto connected = connect_address(
                        address, bounded_deadline(overall_deadline, impl_->timeouts.connect), cancellation);
                    if (!connected) {
                        if (connected.error().code == ProtocolErrorCode::canceled) {
                            return std::unexpected(std::move(connected.error()));
                        }
                        last_error = std::move(connected.error());
                        continue;
                    }
                    auto attached = impl_->context.attach_connected_socket(
                        static_cast<std::intptr_t>(connected->socket.native_handle()));
                    if (!attached) {
                        last_error = std::move(attached.error());
                        continue;
                    }
                    auto identity = attached->handshake(
                        TransportOperation {.deadline = bounded_deadline(overall_deadline, impl_->timeouts.handshake),
                                            .cancellation = cancellation});
                    if (!identity) {
                        if (identity.error().code == ProtocolErrorCode::canceled) {
                            return std::unexpected(std::move(identity.error()));
                        }
                        last_error = std::move(identity.error());
                        continue;
                    }
                    if (!identity_matches(*identity, impl_->peer_requirement)) {
                        last_error = network_error(ProtocolErrorCode::unauthenticated,
                                                   "TLS server identity does not match the configured peer");
                        continue;
                    }
                    return TlsPeerConnection {std::make_unique<TlsPeerConnection::Impl>(
                        std::move(connected->io), std::move(connected->socket), std::move(*attached),
                        std::move(*identity), std::move(connected->remote), impl_->timeouts)};
                }
            }

            if (round + 1 >= impl_->reconnect.maximum_rounds ||
                connection_attempts >= impl_->reconnect.maximum_connection_attempts) {
                break;
            }
            const auto cap = backoff_cap(impl_->reconnect, round + 1);
            const auto selected = jitter.choose(cap);
            const auto delay = (std::clamp) (selected, std::chrono::milliseconds::zero(), cap);
            if (auto waited = interruptible_delay(delay, overall_deadline, cancellation); !waited) {
                return std::unexpected(std::move(waited.error()));
            }
        }
        return std::unexpected(std::move(last_error));
    }

    std::expected<AgentReconnectResult, ProtocolError>
    TlsSessionDialer::reconnect(PersistentAgentSession &session, AgentHelloMessage hello,
                                const std::stop_token cancellation) noexcept {
        SystemEndpointResolver resolver;
        XorShiftBackoffJitter jitter;
        return reconnect(session, std::move(hello), resolver, jitter, cancellation);
    }

    std::expected<AgentReconnectResult, ProtocolError>
    TlsSessionDialer::reconnect(PersistentAgentSession &session, AgentHelloMessage hello, IEndpointResolver &resolver,
                                IBackoffJitter &jitter, const std::stop_token cancellation) noexcept {
        session.disconnect();
        auto connection = connect(resolver, jitter, cancellation);
        if (!connection) {
            return std::unexpected(std::move(connection.error()));
        }

        hello.agent_epoch = session.agent_epoch();
        hello.next_sequence = session.next_sequence();
        PeerEnvelope hello_envelope {
            .protocol_major = major_version,
            .protocol_minor = initial_minor_version,
            .message_id = session.agent_epoch() + ":hello",
            .session = std::nullopt,
            .agent_epoch = session.agent_epoch(),
            .agent_sequence = 0,
            .acknowledged_agent_sequence = 0,
            .body = std::move(hello),
        };
        if (auto sent = connection->send(hello_envelope, cancellation); !sent) {
            session.disconnect();
            connection->shutdown();
            return std::unexpected(std::move(sent.error()));
        }
        auto received = connection->receive(cancellation);
        if (!received) {
            session.disconnect();
            connection->shutdown();
            return std::unexpected(std::move(received.error()));
        }
        if (!std::holds_alternative<ServerHelloMessage>(received->body)) {
            session.disconnect();
            connection->shutdown();
            return std::unexpected(
                network_error(ProtocolErrorCode::unexpected_message, "agent reconnect expected a server hello"));
        }
        if (received->agent_epoch != session.agent_epoch()) {
            session.disconnect();
            connection->shutdown();
            return std::unexpected(
                network_error(ProtocolErrorCode::stale_session, "server hello does not bind the local agent epoch"));
        }
        auto server_hello = std::get<ServerHelloMessage>(std::move(received->body));
        if (auto established = session.establish(server_hello); !established) {
            session.disconnect();
            connection->shutdown();
            return std::unexpected(std::move(established.error()));
        }
        auto batch = session.take_transmit_batch();
        if (!batch) {
            session.disconnect();
            connection->shutdown();
            return std::unexpected(std::move(batch.error()));
        }
        for (const auto &envelope : *batch) {
            if (auto sent = connection->send(envelope, cancellation); !sent) {
                session.disconnect();
                connection->shutdown();
                return std::unexpected(std::move(sent.error()));
            }
        }
        return AgentReconnectResult {
            .connection = std::move(*connection),
            .server_hello = std::move(server_hello),
            .replayed_records = batch->size(),
        };
    }

} // namespace rule_engine::python::protocol_v2
