#pragma once

#include "rule_engine/python/protocol/codec.hpp"
#include "rule_engine/python/protocol/session.hpp"

#include <chrono>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <vector>

namespace rule_engine::python::protocol_v2 {

    enum struct TlsEndpointRole : std::uint8_t { client, server };

    struct TlsConfiguration {
        TlsEndpointRole role {TlsEndpointRole::client};
        std::string trust_anchors_pem;
        std::string certificate_chain_pem;
        std::string private_key_pem;
        std::string crl_pem;
        std::string expected_server_name;
        bool require_crl {};
        std::optional<std::int64_t> verification_time_unix_seconds;
        ProtocolLimits protocol_limits;
    };

    struct TlsBackendStatus {
        bool available {};
        std::string implementation;
        std::string diagnostic;
    };

    [[nodiscard]] TlsBackendStatus tls_backend_status() noexcept;

    struct TransportOperation {
        std::chrono::steady_clock::time_point deadline {std::chrono::steady_clock::time_point::max()};
        std::stop_token cancellation;
    };

    struct OpenSslTlsSession {
        OpenSslTlsSession(OpenSslTlsSession &&) noexcept;
        OpenSslTlsSession &operator=(OpenSslTlsSession &&) noexcept;
        OpenSslTlsSession(const OpenSslTlsSession &) = delete;
        OpenSslTlsSession &operator=(const OpenSslTlsSession &) = delete;
        ~OpenSslTlsSession();

        [[nodiscard]] std::expected<TlsPeerIdentity, ProtocolError> handshake() noexcept;
        [[nodiscard]] std::expected<TlsPeerIdentity, ProtocolError>
        handshake(const TransportOperation &operation) noexcept;
        [[nodiscard]] std::expected<void, ProtocolError> send(const PeerEnvelope &envelope) noexcept;
        [[nodiscard]] std::expected<void, ProtocolError> send(const PeerEnvelope &envelope,
                                                              const TransportOperation &operation) noexcept;
        [[nodiscard]] std::expected<PeerEnvelope, ProtocolError> receive() noexcept;
        [[nodiscard]] std::expected<PeerEnvelope, ProtocolError> receive(const TransportOperation &operation) noexcept;
        // The admin listener uses the same authenticated TLS transport but has
        // its own bounded application codec. These methods preserve the
        // canonical four-byte network-order frame prefix without interpreting
        // the payload as a protocol-v2 peer envelope.
        [[nodiscard]] std::expected<void, ProtocolError>
        send_application_frame(std::span<const std::byte> payload, const TransportOperation &operation = {}) noexcept;
        [[nodiscard]] std::expected<std::vector<std::byte>, ProtocolError>
        receive_application_frame(const TransportOperation &operation = {}) noexcept;
        [[nodiscard]] bool established() const noexcept;
        void shutdown() noexcept;

    private:
        struct Impl;
        explicit OpenSslTlsSession(std::unique_ptr<Impl> impl) noexcept;
        std::unique_ptr<Impl> impl_;
        friend struct OpenSslTlsContext;
    };

    struct OpenSslTlsContext {
        OpenSslTlsContext(OpenSslTlsContext &&) noexcept;
        OpenSslTlsContext &operator=(OpenSslTlsContext &&) noexcept;
        OpenSslTlsContext(const OpenSslTlsContext &) = delete;
        OpenSslTlsContext &operator=(const OpenSslTlsContext &) = delete;
        ~OpenSslTlsContext();

        [[nodiscard]] static std::expected<OpenSslTlsContext, ProtocolError>
        create(TlsConfiguration configuration) noexcept;

        // The caller owns the connected socket and must keep it open for the session lifetime.
        // Deadline/cancellation overloads require a nonblocking socket; network.hpp supplies one.
        // The value is SOCKET on Windows and fd on POSIX.
        [[nodiscard]] std::expected<OpenSslTlsSession, ProtocolError>
        attach_connected_socket(std::intptr_t native_socket) const noexcept;
        [[nodiscard]] bool valid() const noexcept;
        [[nodiscard]] TlsEndpointRole role() const noexcept;

    private:
        struct Impl;
        explicit OpenSslTlsContext(std::shared_ptr<Impl> impl) noexcept;
        std::shared_ptr<Impl> impl_;
        friend struct OpenSslTlsSession;
    };

} // namespace rule_engine::python::protocol_v2
