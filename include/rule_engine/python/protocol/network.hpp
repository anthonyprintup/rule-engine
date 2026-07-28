#pragma once

#include "rule_engine/python/protocol/spool.hpp"
#include "rule_engine/python/protocol/transport.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <vector>

namespace rule_engine::python::protocol_v2 {

    struct TcpEndpoint {
        std::string host;
        std::uint16_t port {};
    };

    enum struct TcpAddressFamily : std::uint8_t { ipv4, ipv6 };

    struct ResolvedTcpAddress {
        TcpAddressFamily family {TcpAddressFamily::ipv4};
        std::string address;
        std::uint16_t port {};
    };

    struct IEndpointResolver {
        virtual ~IEndpointResolver() = default;
        // True only when an in-flight lookup is guaranteed to honor the deadline and cancellation.
        [[nodiscard]] virtual bool hard_bounds_guaranteed() const noexcept = 0;
        [[nodiscard]] virtual std::expected<std::vector<ResolvedTcpAddress>, ProtocolError>
        resolve(const TcpEndpoint &endpoint, std::size_t maximum_addresses,
                std::chrono::steady_clock::time_point deadline, std::stop_token cancellation) noexcept = 0;
    };

    struct SystemEndpointResolver final: IEndpointResolver {
        [[nodiscard]] bool hard_bounds_guaranteed() const noexcept override { return false; }
        [[nodiscard]] std::expected<std::vector<ResolvedTcpAddress>, ProtocolError>
        resolve(const TcpEndpoint &endpoint, std::size_t maximum_addresses,
                std::chrono::steady_clock::time_point deadline, std::stop_token cancellation) noexcept override;
    };

    struct IBackoffJitter {
        virtual ~IBackoffJitter() = default;
        [[nodiscard]] virtual std::chrono::milliseconds
        choose(std::chrono::milliseconds inclusive_upper_bound) noexcept = 0;
    };

    struct XorShiftBackoffJitter final: IBackoffJitter {
        explicit XorShiftBackoffJitter(std::uint64_t seed = 0) noexcept;
        [[nodiscard]] std::chrono::milliseconds
        choose(std::chrono::milliseconds inclusive_upper_bound) noexcept override;

    private:
        std::uint64_t state_ {};
    };

    struct SocketTimeouts {
        std::chrono::milliseconds resolve {5'000};
        std::chrono::milliseconds connect {5'000};
        std::chrono::milliseconds accept {30'000};
        std::chrono::milliseconds handshake {5'000};
        std::chrono::milliseconds read {30'000};
        std::chrono::milliseconds write {30'000};
        std::chrono::milliseconds total_dial {60'000};
    };

    struct ReconnectPolicy {
        std::chrono::milliseconds initial_backoff {250};
        std::chrono::milliseconds maximum_backoff {30'000};
        std::size_t maximum_rounds {8};
        std::size_t maximum_endpoints {8};
        std::size_t maximum_addresses_per_endpoint {8};
        std::size_t maximum_connection_attempts {64};
        bool require_hard_resolver_bounds {};
    };

    struct TlsPeerRequirement {
        std::string canonical_uri_san;
        std::optional<std::string> certificate_sha256;
    };

    struct TlsPeerConnection {
        TlsPeerConnection(TlsPeerConnection &&) noexcept;
        TlsPeerConnection &operator=(TlsPeerConnection &&) noexcept;
        TlsPeerConnection(const TlsPeerConnection &) = delete;
        TlsPeerConnection &operator=(const TlsPeerConnection &) = delete;
        ~TlsPeerConnection();

        [[nodiscard]] std::expected<void, ProtocolError> send(const PeerEnvelope &envelope,
                                                              std::stop_token cancellation = {}) noexcept;
        [[nodiscard]] std::expected<void, ProtocolError> send_until(const PeerEnvelope &envelope,
                                                                    std::chrono::steady_clock::time_point deadline,
                                                                    std::stop_token cancellation = {}) noexcept;
        [[nodiscard]] std::expected<PeerEnvelope, ProtocolError> receive(std::stop_token cancellation = {}) noexcept;
        [[nodiscard]] std::expected<PeerEnvelope, ProtocolError>
        receive_until(std::chrono::steady_clock::time_point deadline, std::stop_token cancellation = {}) noexcept;
        // Returns false at the deadline without consuming TLS or frame bytes.
        [[nodiscard]] std::expected<bool, ProtocolError>
        wait_readable_until(std::chrono::steady_clock::time_point deadline, std::stop_token cancellation = {}) noexcept;
        [[nodiscard]] std::expected<void, ProtocolError>
        send_application_frame_until(std::span<const std::byte> payload, std::chrono::steady_clock::time_point deadline,
                                     std::stop_token cancellation = {}) noexcept;
        [[nodiscard]] std::expected<std::vector<std::byte>, ProtocolError>
        receive_application_frame_until(std::chrono::steady_clock::time_point deadline,
                                        std::stop_token cancellation = {}) noexcept;
        [[nodiscard]] TlsPeerIdentity peer_identity() const;
        [[nodiscard]] TcpEndpoint remote_endpoint() const;
        [[nodiscard]] bool established() const noexcept;
        void shutdown() noexcept;

    private:
        struct Impl;
        explicit TlsPeerConnection(std::unique_ptr<Impl> impl) noexcept;
        std::unique_ptr<Impl> impl_;
        friend struct TlsSessionDialer;
        friend struct TlsSessionListener;
    };

    struct AuthenticatedTlsPeer {
        TlsPeerConnection connection;
        AuthenticatedPeer peer;
    };

    struct TlsSessionListener {
        TlsSessionListener(TlsSessionListener &&) noexcept;
        TlsSessionListener &operator=(TlsSessionListener &&) noexcept;
        TlsSessionListener(const TlsSessionListener &) = delete;
        TlsSessionListener &operator=(const TlsSessionListener &) = delete;
        ~TlsSessionListener();

        [[nodiscard]] static std::expected<TlsSessionListener, ProtocolError>
        bind(OpenSslTlsContext context, TcpEndpoint endpoint, SocketTimeouts timeouts = {},
             std::size_t listen_backlog = 128) noexcept;

        [[nodiscard]] std::expected<AuthenticatedTlsPeer, ProtocolError>
        accept(const ITrustPolicy &trust_policy, std::stop_token cancellation = {}) noexcept;
        [[nodiscard]] TcpEndpoint local_endpoint() const noexcept;
        void cancel() noexcept;

    private:
        struct Impl;
        explicit TlsSessionListener(std::unique_ptr<Impl> impl) noexcept;
        std::unique_ptr<Impl> impl_;
    };

    struct AgentReconnectResult {
        TlsPeerConnection connection;
        ServerHelloMessage server_hello;
        std::size_t replayed_records {};
    };

    struct TlsSessionDialer {
        TlsSessionDialer(TlsSessionDialer &&) noexcept;
        TlsSessionDialer &operator=(TlsSessionDialer &&) noexcept;
        TlsSessionDialer(const TlsSessionDialer &) = delete;
        TlsSessionDialer &operator=(const TlsSessionDialer &) = delete;
        ~TlsSessionDialer();

        [[nodiscard]] static std::expected<TlsSessionDialer, ProtocolError>
        create(OpenSslTlsContext context, std::vector<TcpEndpoint> endpoints, TlsPeerRequirement peer_requirement,
               SocketTimeouts timeouts = {}, ReconnectPolicy reconnect = {}) noexcept;

        [[nodiscard]] std::expected<TlsPeerConnection, ProtocolError>
        connect(std::stop_token cancellation = {}) noexcept;
        [[nodiscard]] std::expected<TlsPeerConnection, ProtocolError>
        connect(IEndpointResolver &resolver, IBackoffJitter &jitter, std::stop_token cancellation = {}) noexcept;

        [[nodiscard]] std::expected<AgentReconnectResult, ProtocolError>
        reconnect(PersistentAgentSession &session, AgentHelloMessage hello, std::stop_token cancellation = {}) noexcept;
        [[nodiscard]] std::expected<AgentReconnectResult, ProtocolError>
        reconnect(PersistentAgentSession &session, AgentHelloMessage hello, IEndpointResolver &resolver,
                  IBackoffJitter &jitter, std::stop_token cancellation = {}) noexcept;

    private:
        struct Impl;
        explicit TlsSessionDialer(std::unique_ptr<Impl> impl) noexcept;
        std::unique_ptr<Impl> impl_;
    };

} // namespace rule_engine::python::protocol_v2
