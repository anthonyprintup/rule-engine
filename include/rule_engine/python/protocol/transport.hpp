#pragma once

#include "rule_engine/python/protocol/codec.hpp"
#include "rule_engine/python/protocol/session.hpp"

#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <string>

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

    struct OpenSslTlsSession {
        OpenSslTlsSession(OpenSslTlsSession &&) noexcept;
        OpenSslTlsSession &operator=(OpenSslTlsSession &&) noexcept;
        OpenSslTlsSession(const OpenSslTlsSession &) = delete;
        OpenSslTlsSession &operator=(const OpenSslTlsSession &) = delete;
        ~OpenSslTlsSession();

        [[nodiscard]] std::expected<TlsPeerIdentity, ProtocolError> handshake() noexcept;
        [[nodiscard]] std::expected<void, ProtocolError> send(const PeerEnvelope &envelope) noexcept;
        [[nodiscard]] std::expected<PeerEnvelope, ProtocolError> receive() noexcept;
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

        // The caller owns the connected blocking socket and must keep it open
        // for the session lifetime. The value is SOCKET on Windows and fd on POSIX.
        [[nodiscard]] std::expected<OpenSslTlsSession, ProtocolError>
        attach_connected_socket(std::intptr_t native_socket) const noexcept;

    private:
        struct Impl;
        explicit OpenSslTlsContext(std::shared_ptr<Impl> impl) noexcept;
        std::shared_ptr<Impl> impl_;
        friend struct OpenSslTlsSession;
    };

} // namespace rule_engine::python::protocol_v2
