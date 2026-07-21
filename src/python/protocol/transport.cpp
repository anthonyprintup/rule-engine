#include "rule_engine/python/protocol/transport.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <ctime>
#include <limits>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <WinSock2.h>
#else
#include <poll.h>
#endif

#if RULE_ENGINE_PROTOCOL_HAS_OPENSSL
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#endif

namespace rule_engine::python::protocol_v2 {
    namespace {

        [[nodiscard]] ProtocolError transport_error(const ProtocolErrorCode code, std::string message) {
            return ProtocolError {.code = code, .message = std::move(message), .byte_offset = 0};
        }

#if RULE_ENGINE_PROTOCOL_HAS_OPENSSL
        constexpr std::string_view peer_alpn = "rule-engine-peer/2";

        enum struct SocketReadiness : std::uint8_t { read, write };

        [[nodiscard]] std::expected<void, ProtocolError> wait_for_socket(const int socket,
                                                                         const SocketReadiness readiness,
                                                                         const TransportOperation &operation,
                                                                         const std::string_view activity) {
            constexpr auto cancellation_poll = std::chrono::milliseconds {25};
            while (true) {
                if (operation.cancellation.stop_requested()) {
                    return std::unexpected(
                        transport_error(ProtocolErrorCode::canceled, std::string {activity} + " was canceled"));
                }

                const auto now = std::chrono::steady_clock::now();
                if (operation.deadline != std::chrono::steady_clock::time_point::max() && now >= operation.deadline) {
                    return std::unexpected(
                        transport_error(ProtocolErrorCode::timed_out, std::string {activity} + " timed out"));
                }
                auto wait = cancellation_poll;
                if (operation.deadline != std::chrono::steady_clock::time_point::max()) {
                    wait = std::min(wait, std::chrono::ceil<std::chrono::milliseconds>(operation.deadline - now));
                }
                const auto wait_ms = static_cast<int>((std::max) (std::chrono::milliseconds {1}, wait).count());

#ifdef _WIN32
                WSAPOLLFD descriptor {
                    .fd = static_cast<SOCKET>(socket),
                    .events = static_cast<SHORT>(readiness == SocketReadiness::read ? POLLRDNORM : POLLWRNORM),
                    .revents = 0};
                const auto result = WSAPoll(&descriptor, 1, wait_ms);
                if (result > 0) {
                    return {};
                }
                if (result < 0 && WSAGetLastError() != WSAEINTR) {
                    return std::unexpected(transport_error(ProtocolErrorCode::transport_error,
                                                           std::string {activity} + " socket wait failed"));
                }
#else
                pollfd descriptor {.fd = socket,
                                   .events = static_cast<short>(readiness == SocketReadiness::read ? POLLIN : POLLOUT),
                                   .revents = 0};
                const auto result = poll(&descriptor, 1, wait_ms);
                if (result > 0) {
                    return {};
                }
                if (result < 0 && errno != EINTR) {
                    return std::unexpected(transport_error(ProtocolErrorCode::transport_error,
                                                           std::string {activity} + " socket wait failed"));
                }
#endif
            }
        }

        [[nodiscard]] std::expected<void, ProtocolError> wait_for_ssl(const SSL *ssl, const int error,
                                                                      const TransportOperation &operation,
                                                                      const std::string_view activity) {
            if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) {
                return std::unexpected(
                    transport_error(ProtocolErrorCode::transport_error, std::string {activity} + " failed"));
            }
            const auto socket = SSL_get_fd(ssl);
            if (socket < 0) {
                return std::unexpected(
                    transport_error(ProtocolErrorCode::transport_error, std::string {activity} + " has no socket"));
            }
            return wait_for_socket(socket,
                                   error == SSL_ERROR_WANT_READ ? SocketReadiness::read : SocketReadiness::write,
                                   operation, activity);
        }

        [[nodiscard]] int select_peer_alpn(SSL *, const unsigned char **output, unsigned char *output_size,
                                           const unsigned char *input, const unsigned int input_size, void *) {
            const auto expected_size = static_cast<unsigned int>(peer_alpn.size());
            std::size_t offset {};
            while (offset < input_size) {
                const auto candidate_size = static_cast<std::size_t>(input[offset++]);
                if (candidate_size > input_size - offset) {
                    return SSL_TLSEXT_ERR_ALERT_FATAL;
                }
                if (candidate_size == expected_size &&
                    std::memcmp(input + offset, peer_alpn.data(), candidate_size) == 0) {
                    *output = input + offset;
                    *output_size = static_cast<unsigned char>(candidate_size);
                    return SSL_TLSEXT_ERR_OK;
                }
                offset += candidate_size;
            }
            return SSL_TLSEXT_ERR_ALERT_FATAL;
        }

        [[nodiscard]] std::array<unsigned char, 1 + peer_alpn.size()> encoded_peer_alpn() {
            std::array<unsigned char, 1 + peer_alpn.size()> result {};
            result[0] = static_cast<unsigned char>(peer_alpn.size());
            std::ranges::copy(peer_alpn, result.begin() + 1);
            return result;
        }

        [[nodiscard]] std::expected<TlsPeerIdentity, ProtocolError> extract_peer_identity(SSL *ssl,
                                                                                          const TlsEndpointRole role) {
            if (SSL_version(ssl) != TLS1_3_VERSION || SSL_get_verify_result(ssl) != X509_V_OK) {
                return std::unexpected(
                    transport_error(ProtocolErrorCode::unauthenticated, "TLS peer verification failed"));
            }
            const unsigned char *selected {};
            unsigned int selected_size {};
            SSL_get0_alpn_selected(ssl, &selected, &selected_size);
            if (selected_size != peer_alpn.size() || selected == nullptr ||
                std::memcmp(selected, peer_alpn.data(), peer_alpn.size()) != 0) {
                return std::unexpected(
                    transport_error(ProtocolErrorCode::unauthenticated, "required protocol ALPN was not negotiated"));
            }

            auto *certificate = SSL_get1_peer_certificate(ssl);
            if (certificate == nullptr) {
                return std::unexpected(
                    transport_error(ProtocolErrorCode::unauthenticated, "TLS peer certificate is missing"));
            }

            TlsPeerIdentity identity {
                .tls_major = 1,
                .tls_minor = 3,
                .mutual_authentication = true,
                .certificate_chain_verified = true,
                .client_auth_eku = role == TlsEndpointRole::server,
                .revoked = false,
                .canonical_uri_san = {},
                .certificate_sha256 = {},
            };

            unsigned int fingerprint_size {};
            std::array<unsigned char, EVP_MAX_MD_SIZE> fingerprint {};
            if (X509_digest(certificate, EVP_sha256(), fingerprint.data(), &fingerprint_size) != 1 ||
                fingerprint_size != 32) {
                X509_free(certificate);
                return std::unexpected(
                    transport_error(ProtocolErrorCode::unauthenticated, "TLS certificate fingerprint failed"));
            }
            constexpr char hex[] = "0123456789abcdef";
            identity.certificate_sha256.reserve(fingerprint_size * 2);
            for (std::size_t index = 0; index < fingerprint_size; ++index) {
                identity.certificate_sha256.push_back(hex[fingerprint[index] >> 4U]);
                identity.certificate_sha256.push_back(hex[fingerprint[index] & 0x0fU]);
            }

            auto *names =
                static_cast<GENERAL_NAMES *>(X509_get_ext_d2i(certificate, NID_subject_alt_name, nullptr, nullptr));
            std::size_t uri_count {};
            if (names != nullptr) {
                const auto count = sk_GENERAL_NAME_num(names);
                for (int index = 0; index < count; ++index) {
                    const auto *name = sk_GENERAL_NAME_value(names, index);
                    if (name == nullptr || name->type != GEN_URI) {
                        continue;
                    }
                    ++uri_count;
                    const auto *data = ASN1_STRING_get0_data(name->d.uniformResourceIdentifier);
                    const auto size = ASN1_STRING_length(name->d.uniformResourceIdentifier);
                    if (data == nullptr || size <= 0 ||
                        std::memchr(data, '\0', static_cast<std::size_t>(size)) != nullptr) {
                        continue;
                    }
                    identity.canonical_uri_san.assign(reinterpret_cast<const char *>(data),
                                                      static_cast<std::size_t>(size));
                }
                GENERAL_NAMES_free(names);
            }
            X509_free(certificate);
            if (uri_count != 1 || identity.canonical_uri_san.empty()) {
                return std::unexpected(transport_error(ProtocolErrorCode::unauthenticated,
                                                       "TLS peer certificate requires one canonical URI SAN"));
            }
            return identity;
        }

        [[nodiscard]] std::expected<void, ProtocolError> write_all(SSL *ssl, const std::span<const std::byte> bytes,
                                                                   const TransportOperation &operation) {
            std::size_t offset {};
            while (offset < bytes.size()) {
                if (operation.cancellation.stop_requested()) {
                    return std::unexpected(
                        transport_error(ProtocolErrorCode::canceled, "TLS record write was canceled"));
                }
                if (operation.deadline != std::chrono::steady_clock::time_point::max() &&
                    std::chrono::steady_clock::now() >= operation.deadline) {
                    return std::unexpected(transport_error(ProtocolErrorCode::timed_out, "TLS record write timed out"));
                }
                std::size_t written {};
                const auto result = SSL_write_ex(ssl, bytes.data() + offset, bytes.size() - offset, &written);
                if (result == 1 && written != 0) {
                    offset += written;
                    continue;
                }
                const auto code = SSL_get_error(ssl, result);
                if (code == SSL_ERROR_WANT_READ || code == SSL_ERROR_WANT_WRITE) {
                    if (auto ready = wait_for_ssl(ssl, code, operation, "TLS record write"); !ready) {
                        return ready;
                    }
                    continue;
                }
                return std::unexpected(transport_error(ProtocolErrorCode::transport_error, "TLS record write failed"));
            }
            return {};
        }

        [[nodiscard]] std::expected<void, ProtocolError> read_all(SSL *ssl, const std::span<std::byte> bytes,
                                                                  const TransportOperation &operation) {
            std::size_t offset {};
            while (offset < bytes.size()) {
                if (operation.cancellation.stop_requested()) {
                    return std::unexpected(
                        transport_error(ProtocolErrorCode::canceled, "TLS record read was canceled"));
                }
                if (operation.deadline != std::chrono::steady_clock::time_point::max() &&
                    std::chrono::steady_clock::now() >= operation.deadline) {
                    return std::unexpected(transport_error(ProtocolErrorCode::timed_out, "TLS record read timed out"));
                }
                std::size_t received {};
                const auto result = SSL_read_ex(ssl, bytes.data() + offset, bytes.size() - offset, &received);
                if (result == 1 && received != 0) {
                    offset += received;
                    continue;
                }
                const auto code = SSL_get_error(ssl, result);
                if (code == SSL_ERROR_WANT_READ || code == SSL_ERROR_WANT_WRITE) {
                    if (auto ready = wait_for_ssl(ssl, code, operation, "TLS record read"); !ready) {
                        return ready;
                    }
                    continue;
                }
                return std::unexpected(transport_error(ProtocolErrorCode::transport_error, "TLS record read failed"));
            }
            return {};
        }
#endif

    } // namespace

    struct OpenSslTlsContext::Impl {
        TlsConfiguration configuration;
#if RULE_ENGINE_PROTOCOL_HAS_OPENSSL
        SSL_CTX *context {};

        ~Impl() {
            if (context != nullptr) {
                SSL_CTX_free(context);
            }
        }
#endif
    };

    struct OpenSslTlsSession::Impl {
        std::shared_ptr<OpenSslTlsContext::Impl> context;
#if RULE_ENGINE_PROTOCOL_HAS_OPENSSL
        SSL *ssl {};
#endif
        bool established {};

        ~Impl() {
#if RULE_ENGINE_PROTOCOL_HAS_OPENSSL
            if (ssl != nullptr) {
                SSL_free(ssl);
            }
#endif
        }
    };

    TlsBackendStatus tls_backend_status() noexcept {
#if RULE_ENGINE_PROTOCOL_HAS_OPENSSL
        return TlsBackendStatus {.available = true,
                                 .implementation = OpenSSL_version(OPENSSL_VERSION),
                                 .diagnostic = "OpenSSL TLS 1.3 backend is linked"};
#else
        return TlsBackendStatus {.available = false,
                                 .implementation = {},
                                 .diagnostic =
                                     "OpenSSL 3 or newer was not found when the protocol component was configured"};
#endif
    }

    OpenSslTlsContext::OpenSslTlsContext(std::shared_ptr<Impl> impl) noexcept: impl_ {std::move(impl)} {}
    OpenSslTlsContext::OpenSslTlsContext(OpenSslTlsContext &&) noexcept = default;
    OpenSslTlsContext &OpenSslTlsContext::operator=(OpenSslTlsContext &&) noexcept = default;
    OpenSslTlsContext::~OpenSslTlsContext() = default;

    std::expected<OpenSslTlsContext, ProtocolError> OpenSslTlsContext::create(TlsConfiguration configuration) noexcept {
#if RULE_ENGINE_PROTOCOL_HAS_OPENSSL
        if (configuration.trust_anchors_pem.empty() || configuration.certificate_chain_pem.empty() ||
            configuration.private_key_pem.empty() ||
            (configuration.role == TlsEndpointRole::client && configuration.expected_server_name.empty()) ||
            (configuration.require_crl && configuration.crl_pem.empty())) {
            return std::unexpected(transport_error(ProtocolErrorCode::malformed, "TLS configuration is incomplete"));
        }

        auto impl = std::make_shared<Impl>();
        impl->configuration = std::move(configuration);
        impl->context = SSL_CTX_new(TLS_method());
        if (impl->context == nullptr) {
            return std::unexpected(
                transport_error(ProtocolErrorCode::transport_error, "OpenSSL context creation failed"));
        }
        if (SSL_CTX_set_min_proto_version(impl->context, TLS1_3_VERSION) != 1 ||
            SSL_CTX_set_max_proto_version(impl->context, TLS1_3_VERSION) != 1) {
            return std::unexpected(
                transport_error(ProtocolErrorCode::transport_error, "OpenSSL cannot enforce TLS 1.3"));
        }
        SSL_CTX_set_options(impl->context, SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION | SSL_OP_NO_TICKET);
        SSL_CTX_set_session_cache_mode(impl->context, SSL_SESS_CACHE_OFF);
        SSL_CTX_set_num_tickets(impl->context, 0);
        SSL_CTX_set_max_early_data(impl->context, 0);
        SSL_CTX_set_verify_depth(impl->context, 8);

        if (SSL_CTX_load_verify_locations(impl->context, impl->configuration.trust_anchors_pem.c_str(), nullptr) != 1 ||
            SSL_CTX_use_certificate_chain_file(impl->context, impl->configuration.certificate_chain_pem.c_str()) != 1 ||
            SSL_CTX_use_PrivateKey_file(impl->context, impl->configuration.private_key_pem.c_str(), SSL_FILETYPE_PEM) !=
                1 ||
            SSL_CTX_check_private_key(impl->context) != 1) {
            return std::unexpected(transport_error(ProtocolErrorCode::unauthenticated,
                                                   "TLS trust, certificate, or private-key loading failed"));
        }

        auto *store = SSL_CTX_get_cert_store(impl->context);
        if (!impl->configuration.crl_pem.empty()) {
            if (X509_STORE_load_file(store, impl->configuration.crl_pem.c_str()) != 1 ||
                X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL) != 1) {
                return std::unexpected(
                    transport_error(ProtocolErrorCode::unauthenticated, "TLS revocation policy loading failed"));
            }
        }

        auto *parameters = SSL_CTX_get0_param(impl->context);
        const auto purpose =
            impl->configuration.role == TlsEndpointRole::server ? X509_PURPOSE_SSL_CLIENT : X509_PURPOSE_SSL_SERVER;
        if (X509_VERIFY_PARAM_set_purpose(parameters, purpose) != 1) {
            return std::unexpected(
                transport_error(ProtocolErrorCode::transport_error, "TLS certificate purpose setup failed"));
        }
        if (impl->configuration.verification_time_unix_seconds.has_value()) {
            X509_VERIFY_PARAM_set_time(parameters,
                                       static_cast<std::time_t>(*impl->configuration.verification_time_unix_seconds));
        }
        const auto verify_mode = impl->configuration.role == TlsEndpointRole::server ?
                                     SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT :
                                     SSL_VERIFY_PEER;
        SSL_CTX_set_verify(impl->context, verify_mode, nullptr);
        if (impl->configuration.role == TlsEndpointRole::server) {
            SSL_CTX_set_alpn_select_cb(impl->context, select_peer_alpn, nullptr);
        }
        return OpenSslTlsContext {std::move(impl)};
#else
        static_cast<void>(configuration);
        return std::unexpected(
            transport_error(ProtocolErrorCode::dependency_unavailable,
                            "secure protocol transport is unavailable because OpenSSL 3 or newer was not linked"));
#endif
    }

    std::expected<OpenSslTlsSession, ProtocolError>
    OpenSslTlsContext::attach_connected_socket(const std::intptr_t native_socket) const noexcept {
#if RULE_ENGINE_PROTOCOL_HAS_OPENSSL
        if (impl_ == nullptr || impl_->context == nullptr || native_socket < 0 ||
            static_cast<std::uint64_t>(native_socket) > static_cast<std::uint64_t>((std::numeric_limits<int>::max)())) {
            return std::unexpected(
                transport_error(ProtocolErrorCode::transport_error, "connected TLS socket is invalid"));
        }
        auto session = std::make_unique<OpenSslTlsSession::Impl>();
        session->context = impl_;
        session->ssl = SSL_new(impl_->context);
        if (session->ssl == nullptr || SSL_set_fd(session->ssl, static_cast<int>(native_socket)) != 1) {
            return std::unexpected(
                transport_error(ProtocolErrorCode::transport_error, "OpenSSL socket attachment failed"));
        }
        if (impl_->configuration.role == TlsEndpointRole::client) {
            const auto alpn = encoded_peer_alpn();
            auto *parameters = SSL_get0_param(session->ssl);
            if (SSL_set_alpn_protos(session->ssl, alpn.data(), static_cast<unsigned int>(alpn.size())) != 0 ||
                SSL_set_tlsext_host_name(session->ssl, impl_->configuration.expected_server_name.c_str()) != 1 ||
                X509_VERIFY_PARAM_set1_host(parameters, impl_->configuration.expected_server_name.c_str(), 0) != 1) {
                return std::unexpected(
                    transport_error(ProtocolErrorCode::transport_error, "TLS client identity setup failed"));
            }
        }
        return OpenSslTlsSession {std::move(session)};
#else
        static_cast<void>(native_socket);
        return std::unexpected(
            transport_error(ProtocolErrorCode::dependency_unavailable,
                            "secure protocol transport is unavailable because OpenSSL 3 or newer was not linked"));
#endif
    }

    bool OpenSslTlsContext::valid() const noexcept { return impl_ != nullptr; }

    TlsEndpointRole OpenSslTlsContext::role() const noexcept {
        return impl_ == nullptr ? TlsEndpointRole::client : impl_->configuration.role;
    }

    OpenSslTlsSession::OpenSslTlsSession(std::unique_ptr<Impl> impl) noexcept: impl_ {std::move(impl)} {}
    OpenSslTlsSession::OpenSslTlsSession(OpenSslTlsSession &&) noexcept = default;
    OpenSslTlsSession &OpenSslTlsSession::operator=(OpenSslTlsSession &&) noexcept = default;
    OpenSslTlsSession::~OpenSslTlsSession() = default;

    std::expected<TlsPeerIdentity, ProtocolError> OpenSslTlsSession::handshake() noexcept {
        return handshake(TransportOperation {});
    }

    std::expected<TlsPeerIdentity, ProtocolError>
    OpenSslTlsSession::handshake(const TransportOperation &operation) noexcept {
#if RULE_ENGINE_PROTOCOL_HAS_OPENSSL
        if (impl_ == nullptr || impl_->ssl == nullptr || impl_->established) {
            return std::unexpected(
                transport_error(ProtocolErrorCode::transport_error, "TLS session cannot begin a handshake"));
        }
        while (true) {
            if (operation.cancellation.stop_requested()) {
                return std::unexpected(transport_error(ProtocolErrorCode::canceled, "TLS handshake was canceled"));
            }
            if (operation.deadline != std::chrono::steady_clock::time_point::max() &&
                std::chrono::steady_clock::now() >= operation.deadline) {
                return std::unexpected(transport_error(ProtocolErrorCode::timed_out, "TLS handshake timed out"));
            }
            const auto result = impl_->context->configuration.role == TlsEndpointRole::server ? SSL_accept(impl_->ssl) :
                                                                                                SSL_connect(impl_->ssl);
            if (result == 1) {
                break;
            }
            const auto code = SSL_get_error(impl_->ssl, result);
            if (code != SSL_ERROR_WANT_READ && code != SSL_ERROR_WANT_WRITE) {
                return std::unexpected(
                    transport_error(ProtocolErrorCode::unauthenticated, "TLS handshake or peer verification failed"));
            }
            if (auto ready = wait_for_ssl(impl_->ssl, code, operation, "TLS handshake"); !ready) {
                return std::unexpected(std::move(ready.error()));
            }
        }
        auto identity = extract_peer_identity(impl_->ssl, impl_->context->configuration.role);
        if (!identity) {
            return std::unexpected(std::move(identity.error()));
        }
        impl_->established = true;
        return identity;
#else
        static_cast<void>(operation);
        return std::unexpected(
            transport_error(ProtocolErrorCode::dependency_unavailable,
                            "secure protocol transport is unavailable because OpenSSL 3 or newer was not linked"));
#endif
    }

    std::expected<void, ProtocolError> OpenSslTlsSession::send(const PeerEnvelope &envelope) noexcept {
        return send(envelope, TransportOperation {});
    }

    std::expected<void, ProtocolError> OpenSslTlsSession::send(const PeerEnvelope &envelope,
                                                               const TransportOperation &operation) noexcept {
#if RULE_ENGINE_PROTOCOL_HAS_OPENSSL
        if (!established()) {
            return std::unexpected(
                transport_error(ProtocolErrorCode::transport_error, "TLS session is not established"));
        }
        auto frame = encode_frame(envelope, impl_->context->configuration.protocol_limits);
        if (!frame) {
            return std::unexpected(std::move(frame.error()));
        }
        return write_all(impl_->ssl, *frame, operation);
#else
        static_cast<void>(envelope);
        static_cast<void>(operation);
        return std::unexpected(
            transport_error(ProtocolErrorCode::dependency_unavailable,
                            "secure protocol transport is unavailable because OpenSSL 3 or newer was not linked"));
#endif
    }

    std::expected<PeerEnvelope, ProtocolError> OpenSslTlsSession::receive() noexcept {
        return receive(TransportOperation {});
    }

    std::expected<PeerEnvelope, ProtocolError>
    OpenSslTlsSession::receive(const TransportOperation &operation) noexcept {
#if RULE_ENGINE_PROTOCOL_HAS_OPENSSL
        if (!established()) {
            return std::unexpected(
                transport_error(ProtocolErrorCode::transport_error, "TLS session is not established"));
        }
        std::array<std::byte, 4> header {};
        if (auto read = read_all(impl_->ssl, header, operation); !read) {
            return std::unexpected(std::move(read.error()));
        }
        const auto size = (std::to_integer<std::uint32_t>(header[0]) << 24U) |
                          (std::to_integer<std::uint32_t>(header[1]) << 16U) |
                          (std::to_integer<std::uint32_t>(header[2]) << 8U) | std::to_integer<std::uint32_t>(header[3]);
        if (size == 0 || size > impl_->context->configuration.protocol_limits.maximum_frame_bytes) {
            return std::unexpected(
                transport_error(size == 0 ? ProtocolErrorCode::malformed : ProtocolErrorCode::limit_exceeded,
                                "TLS protocol frame length is invalid"));
        }
        std::vector<std::byte> frame(static_cast<std::size_t>(size) + header.size());
        std::ranges::copy(header, frame.begin());
        if (auto read = read_all(impl_->ssl, std::span {frame}.subspan(header.size()), operation); !read) {
            return std::unexpected(std::move(read.error()));
        }
        auto decoded = decode_frame(frame, impl_->context->configuration.protocol_limits);
        if (!decoded) {
            return std::unexpected(std::move(decoded.error()));
        }
        return std::move(decoded->envelope);
#else
        static_cast<void>(operation);
        return std::unexpected(
            transport_error(ProtocolErrorCode::dependency_unavailable,
                            "secure protocol transport is unavailable because OpenSSL 3 or newer was not linked"));
#endif
    }

    bool OpenSslTlsSession::established() const noexcept { return impl_ != nullptr && impl_->established; }

    void OpenSslTlsSession::shutdown() noexcept {
#if RULE_ENGINE_PROTOCOL_HAS_OPENSSL
        if (impl_ != nullptr && impl_->ssl != nullptr && impl_->established) {
            SSL_shutdown(impl_->ssl);
            impl_->established = false;
        }
#endif
    }

} // namespace rule_engine::python::protocol_v2
