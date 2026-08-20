#include "rule_engine/python/protocol.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <WS2tcpip.h>
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace {
    using namespace rule_engine::python;
    using namespace rule_engine::python::protocol_v2;

    template<typename Type>
    concept HasPredicate = requires(Type value) { value.predicate; };

    template<typename Type>
    concept HasVerdict = requires(Type value) { value.verdict; };

    static_assert(!HasPredicate<WindowsProviderSpoolAdapter>);
    static_assert(!HasVerdict<WindowsProviderSpoolAdapter>);
    static_assert(!HasPredicate<SnapshotEnumerationRequest>);
    static_assert(!HasVerdict<SpoolPublication>);

    struct TemporaryDirectory {
        std::filesystem::path path;

        TemporaryDirectory() {
            static std::atomic<std::uint64_t> counter;
            std::error_code error;
            auto root = std::filesystem::temp_directory_path(error);
            if (error) {
                error.clear();
                root = std::filesystem::current_path(error);
            }
            const auto stamp = static_cast<std::uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count());
            path =
                root / ("rule-engine-protocol-" + std::to_string(stamp) + "-" + std::to_string(counter.fetch_add(1)));
            std::filesystem::create_directories(path, error);
        }

        TemporaryDirectory(const TemporaryDirectory &) = delete;
        TemporaryDirectory &operator=(const TemporaryDirectory &) = delete;
        ~TemporaryDirectory() {
            std::error_code error;
            std::filesystem::remove_all(path, error);
        }
    };

#ifdef _WIN32
    using TestSocketValue = SOCKET;
    inline constexpr TestSocketValue invalid_test_socket = INVALID_SOCKET;
#else
    using TestSocketValue = int;
    inline constexpr TestSocketValue invalid_test_socket = -1;
#endif

    struct SocketRuntime {
        bool available {true};
#ifdef _WIN32
        WSADATA data {};
        SocketRuntime(): available {WSAStartup(MAKEWORD(2, 2), &data) == 0} {}
        ~SocketRuntime() {
            if (available) {
                WSACleanup();
            }
        }
#endif
    };

    struct TestSocket {
        TestSocketValue value {invalid_test_socket};
        explicit TestSocket(const TestSocketValue socket) noexcept: value {socket} {}
        TestSocket(const TestSocket &) = delete;
        TestSocket &operator=(const TestSocket &) = delete;
        TestSocket(TestSocket &&other) noexcept: value {std::exchange(other.value, invalid_test_socket)} {}
        TestSocket &operator=(TestSocket &&) = delete;
        ~TestSocket() {
            if (value == invalid_test_socket) {
                return;
            }
#ifdef _WIN32
            closesocket(value);
#else
            close(value);
#endif
        }

        [[nodiscard]] std::intptr_t native() const noexcept { return static_cast<std::intptr_t>(value); }
    };

    void set_socket_timeout(const TestSocketValue socket) {
#ifdef _WIN32
        const DWORD timeout = 5'000;
        setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char *>(&timeout), sizeof(timeout));
        setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char *>(&timeout), sizeof(timeout));
#else
        const timeval timeout {.tv_sec = 5, .tv_usec = 0};
        setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
#endif
    }

    struct LoopbackListener {
        TestSocket socket;
        std::uint16_t port {};
    };

    std::optional<LoopbackListener> listen_loopback() {
        TestSocket socket {::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)};
        if (socket.value == invalid_test_socket) {
            return std::nullopt;
        }
        sockaddr_in address {};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = 0;
        if (bind(socket.value, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) != 0 ||
            listen(socket.value, 1) != 0) {
            return std::nullopt;
        }
        int size = sizeof(address);
        if (getsockname(socket.value, reinterpret_cast<sockaddr *>(&address), &size) != 0) {
            return std::nullopt;
        }
        return LoopbackListener {.socket = std::move(socket), .port = ntohs(address.sin_port)};
    }

    std::optional<TestSocket> connect_loopback(const std::uint16_t port) {
        TestSocket socket {::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)};
        if (socket.value == invalid_test_socket) {
            return std::nullopt;
        }
        set_socket_timeout(socket.value);
        sockaddr_in address {};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = htons(port);
        if (connect(socket.value, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) != 0) {
            return std::nullopt;
        }
        return socket;
    }

#ifdef RULE_ENGINE_PROTOCOL_OPENSSL_EXECUTABLE
    std::string quoted(const std::filesystem::path &path) { return "\"" + path.string() + "\""; }

    bool run_openssl(const std::string &arguments) {
        std::string command = std::string {"\"" RULE_ENGINE_PROTOCOL_OPENSSL_EXECUTABLE "\" "} + arguments;
#ifdef _WIN32
        command += " >NUL 2>&1";
        command = "\"" + command + "\"";
#else
        command += " >/dev/null 2>&1";
#endif
        return std::system(command.c_str()) == 0;
    }

    struct CertificateFixture {
        std::filesystem::path ca;
        std::filesystem::path alternate_ca;
        std::filesystem::path server_certificate;
        std::filesystem::path server_key;
        std::filesystem::path client_certificate;
        std::filesystem::path client_key;
        std::filesystem::path wrong_eku_certificate;
        std::filesystem::path wrong_eku_key;
        std::filesystem::path clean_crl;
        std::filesystem::path revoked_crl;
        std::filesystem::path stale_crl;
        std::filesystem::path wrong_issuer_crl;
        std::filesystem::path malformed_crl;

        [[nodiscard]] static std::optional<CertificateFixture> generate(const std::filesystem::path &root) {
            CertificateFixture result {
                .ca = root / "ca.pem",
                .alternate_ca = root / "alternate-ca.pem",
                .server_certificate = root / "server.pem",
                .server_key = root / "server.key",
                .client_certificate = root / "client.pem",
                .client_key = root / "client.key",
                .wrong_eku_certificate = root / "wrong-eku.pem",
                .wrong_eku_key = root / "wrong-eku.key",
                .clean_crl = root / "clean.crl.pem",
                .revoked_crl = root / "revoked.crl.pem",
                .stale_crl = root / "stale.crl.pem",
                .wrong_issuer_crl = root / "wrong-issuer.crl.pem",
                .malformed_crl = root / "malformed.crl.pem",
            };
            const auto ca_key = root / "ca.key";
            const auto alternate_key = root / "alternate-ca.key";
            const auto server_request = root / "server.csr";
            const auto client_request = root / "client.csr";
            const auto wrong_request = root / "wrong-eku.csr";
            const auto serial = root / "ca.srl";
            if (!run_openssl("req -x509 -newkey rsa:2048 -nodes -sha256 -days 2 -subj \"/CN=Rule Engine Test CA\" "
                             "-addext \"basicConstraints=critical,CA:TRUE\" "
                             "-addext \"keyUsage=critical,keyCertSign,cRLSign\" -keyout " +
                             quoted(ca_key) + " -out " + quoted(result.ca)) ||
                !run_openssl("req -x509 -newkey rsa:2048 -nodes -sha256 -days 2 -subj \"/CN=Other Test CA\" "
                             "-addext \"basicConstraints=critical,CA:TRUE\" "
                             "-addext \"keyUsage=critical,keyCertSign,cRLSign\" -keyout " +
                             quoted(alternate_key) + " -out " + quoted(result.alternate_ca)) ||
                !run_openssl("req -new -newkey rsa:2048 -nodes -sha256 -subj \"/CN=localhost\" "
                             "-addext \"basicConstraints=critical,CA:FALSE\" "
                             "-addext \"keyUsage=critical,digitalSignature,keyEncipherment\" "
                             "-addext \"extendedKeyUsage=serverAuth\" "
                             "-addext \"subjectAltName=DNS:localhost,URI:urn:rule-engine:server\" -keyout " +
                             quoted(result.server_key) + " -out " + quoted(server_request)) ||
                !run_openssl("x509 -req -sha256 -days 1 -CA " + quoted(result.ca) + " -CAkey " + quoted(ca_key) +
                             " -CAserial " + quoted(serial) + " -CAcreateserial -copy_extensions copyall -in " +
                             quoted(server_request) + " -out " + quoted(result.server_certificate)) ||
                !run_openssl("req -new -newkey rsa:2048 -nodes -sha256 -subj \"/CN=Peer One\" "
                             "-addext \"basicConstraints=critical,CA:FALSE\" "
                             "-addext \"keyUsage=critical,digitalSignature,keyEncipherment\" "
                             "-addext \"extendedKeyUsage=clientAuth\" "
                             "-addext \"subjectAltName=URI:urn:rule-engine:peer-1\" -keyout " +
                             quoted(result.client_key) + " -out " + quoted(client_request)) ||
                !run_openssl("x509 -req -sha256 -days 1 -CA " + quoted(result.ca) + " -CAkey " + quoted(ca_key) +
                             " -CAserial " + quoted(serial) + " -copy_extensions copyall -in " +
                             quoted(client_request) + " -out " + quoted(result.client_certificate)) ||
                !run_openssl("req -new -newkey rsa:2048 -nodes -sha256 -subj \"/CN=Wrong EKU\" "
                             "-addext \"basicConstraints=critical,CA:FALSE\" "
                             "-addext \"keyUsage=critical,digitalSignature,keyEncipherment\" "
                             "-addext \"extendedKeyUsage=serverAuth\" "
                             "-addext \"subjectAltName=URI:urn:rule-engine:peer-1\" -keyout " +
                             quoted(result.wrong_eku_key) + " -out " + quoted(wrong_request)) ||
                !run_openssl("x509 -req -sha256 -days 1 -CA " + quoted(result.ca) + " -CAkey " + quoted(ca_key) +
                             " -CAserial " + quoted(serial) + " -copy_extensions copyall -in " + quoted(wrong_request) +
                             " -out " + quoted(result.wrong_eku_certificate))) {
                return std::nullopt;
            }

            const auto write_ca_config = [&](const std::filesystem::path &path,
                                             const std::filesystem::path &certificate, const std::filesystem::path &key,
                                             const std::string_view stem) {
                const auto database = root / (std::string {stem} + "-index.txt");
                const auto serial_path = root / (std::string {stem} + "-serial");
                const auto crl_number = root / (std::string {stem} + "-crlnumber");
                const auto new_certificates = root / (std::string {stem} + "-newcerts");
                std::error_code error;
                std::filesystem::create_directories(new_certificates, error);
                std::ofstream {database, std::ios::binary};
                std::ofstream {serial_path, std::ios::binary} << "1000\n";
                std::ofstream {crl_number, std::ios::binary} << "1000\n";
                std::ofstream output {path, std::ios::binary};
                output << "[ca]\n"
                          "default_ca = CA_default\n"
                          "[CA_default]\n"
                          "database = \""
                       << database.generic_string() << "\"\nnew_certs_dir = \"" << new_certificates.generic_string()
                       << "\"\ncertificate = \"" << certificate.generic_string() << "\"\nprivate_key = \""
                       << key.generic_string() << "\"\nserial = \"" << serial_path.generic_string()
                       << "\"\ncrlnumber = \"" << crl_number.generic_string()
                       << "\"\ndefault_md = sha256\ndefault_days = 30\ndefault_crl_days = 1\n"
                          "unique_subject = no\npolicy = policy_any\n[policy_any]\ncommonName = supplied\n";
                return !error && output.good();
            };

            const auto ca_config = root / "ca.cnf";
            const auto alternate_config = root / "alternate-ca.cnf";
            if (!write_ca_config(ca_config, result.ca, ca_key, "ca") ||
                !write_ca_config(alternate_config, result.alternate_ca, alternate_key, "alternate") ||
                !run_openssl("ca -batch -gencrl -config " + quoted(ca_config) + " -out " + quoted(result.clean_crl)) ||
                !run_openssl("ca -batch -gencrl -config " + quoted(ca_config) +
                             " -crl_lastupdate 20200101000000Z -crl_nextupdate 20200102000000Z -out " +
                             quoted(result.stale_crl)) ||
                !run_openssl("ca -batch -gencrl -config " + quoted(alternate_config) + " -out " +
                             quoted(result.wrong_issuer_crl)) ||
                !run_openssl("ca -batch -config " + quoted(ca_config) + " -revoke " +
                             quoted(result.server_certificate)) ||
                !run_openssl("ca -batch -gencrl -config " + quoted(ca_config) + " -out " +
                             quoted(result.revoked_crl))) {
                return std::nullopt;
            }
            std::ofstream {result.malformed_crl, std::ios::binary} << "not a PEM CRL\n";
            return result;
        }
    };

    TlsConfiguration orchestration_server_configuration(const CertificateFixture &certificates) {
        return TlsConfiguration {
            .role = TlsEndpointRole::server,
            .trust_anchors_pem = certificates.ca.string(),
            .certificate_chain_pem = certificates.server_certificate.string(),
            .private_key_pem = certificates.server_key.string(),
            .crl_pem = {},
            .expected_server_name = {},
            .require_crl = false,
            .verification_time_unix_seconds = std::nullopt,
            .protocol_limits = {},
        };
    }

    TlsConfiguration orchestration_client_configuration(const CertificateFixture &certificates) {
        return TlsConfiguration {
            .role = TlsEndpointRole::client,
            .trust_anchors_pem = certificates.ca.string(),
            .certificate_chain_pem = certificates.client_certificate.string(),
            .private_key_pem = certificates.client_key.string(),
            .crl_pem = {},
            .expected_server_name = "localhost",
            .require_crl = false,
            .verification_time_unix_seconds = std::nullopt,
            .protocol_limits = {},
        };
    }

    SocketTimeouts orchestration_timeouts() {
        return SocketTimeouts {
            .resolve = std::chrono::milliseconds {500},
            .connect = std::chrono::milliseconds {500},
            .accept = std::chrono::seconds {2},
            .handshake = std::chrono::seconds {2},
            .read = std::chrono::seconds {2},
            .write = std::chrono::seconds {2},
            .total_dial = std::chrono::seconds {5},
        };
    }

    ReconnectPolicy one_round_reconnect() {
        return ReconnectPolicy {
            .initial_backoff = std::chrono::milliseconds {10},
            .maximum_backoff = std::chrono::milliseconds {20},
            .maximum_rounds = 1,
            .maximum_endpoints = 4,
            .maximum_addresses_per_endpoint = 8,
            .maximum_connection_attempts = 16,
        };
    }

    struct FixedResolver final: IEndpointResolver {
        std::vector<ResolvedTcpAddress> addresses;
        bool use_endpoint_port {};
        std::atomic_size_t calls {};

        explicit FixedResolver(std::vector<ResolvedTcpAddress> resolved, const bool inherit_endpoint_port = false):
            addresses {std::move(resolved)}, use_endpoint_port {inherit_endpoint_port} {}

        [[nodiscard]] bool hard_bounds_guaranteed() const noexcept override { return true; }

        [[nodiscard]] std::expected<std::vector<ResolvedTcpAddress>, ProtocolError>
        resolve(const TcpEndpoint &endpoint, const std::size_t, const std::chrono::steady_clock::time_point deadline,
                const std::stop_token cancellation) noexcept override {
            ++calls;
            if (cancellation.stop_requested()) {
                return std::unexpected(ProtocolError {
                    .code = ProtocolErrorCode::canceled, .message = "fixed resolver canceled", .byte_offset = 0});
            }
            if (std::chrono::steady_clock::now() >= deadline) {
                return std::unexpected(ProtocolError {.code = ProtocolErrorCode::transport_error,
                                                      .message = "fixed resolver timed out",
                                                      .byte_offset = 0});
            }
            auto result = addresses;
            if (use_endpoint_port) {
                for (auto &address : result) { address.port = endpoint.port; }
            }
            return result;
        }
    };

    struct RecordingJitter final: IBackoffJitter {
        std::vector<std::chrono::milliseconds> bounds;
        std::atomic_size_t calls {};

        [[nodiscard]] std::chrono::milliseconds
        choose(const std::chrono::milliseconds inclusive_upper_bound) noexcept override {
            bounds.push_back(inclusive_upper_bound);
            calls.store(bounds.size());
            return inclusive_upper_bound;
        }
    };

    struct TlsPairResult {
        std::optional<std::expected<TlsPeerIdentity, ProtocolError>> server_handshake;
        std::optional<std::expected<TlsPeerIdentity, ProtocolError>> client_handshake;
        std::optional<std::expected<PeerEnvelope, ProtocolError>> server_received;
    };

    TlsPairResult run_tls_pair(OpenSslTlsContext &server_context, OpenSslTlsContext &client_context,
                               const std::optional<PeerEnvelope> &client_message = std::nullopt) {
        TlsPairResult result;
        auto listener = listen_loopback();
        if (!listener) {
            return result;
        }
        std::jthread server {[&] {
            sockaddr_in address {};
#ifdef _WIN32
            int address_size = sizeof(address);
#else
            socklen_t address_size = sizeof(address);
#endif
            TestSocket socket {accept(listener->socket.value, reinterpret_cast<sockaddr *>(&address), &address_size)};
            if (socket.value == invalid_test_socket) {
                return;
            }
            set_socket_timeout(socket.value);
            auto attached = server_context.attach_connected_socket(socket.native());
            if (!attached) {
                result.server_handshake = std::unexpected(attached.error());
                return;
            }
            result.server_handshake = attached->handshake();
            if (client_message.has_value() && result.server_handshake->has_value()) {
                result.server_received = attached->receive();
            }
        }};

        auto socket = connect_loopback(listener->port);
        if (socket) {
            auto attached = client_context.attach_connected_socket(socket->native());
            if (!attached) {
                result.client_handshake = std::unexpected(attached.error());
            } else {
                result.client_handshake = attached->handshake();
                if (client_message.has_value() && result.client_handshake->has_value()) {
                    const auto sent = attached->send(*client_message);
                    if (!sent) {
                        result.client_handshake = std::unexpected(sent.error());
                    }
                }
            }
        }
        server.join();
        return result;
    }
#endif

    SubjectKey runtime_subject(const std::uint64_t process_id = 42) {
        return SubjectKey {
            .peer = PeerId {"peer-1"},
            .descriptor = SchemaId {"process/v1"},
            .identity = {{.field_id = 1, .value = process_id}, {.field_id = 2, .value = std::uint64_t {100}}},
            .parent = {},
        };
    }

    FactRequest runtime_fact_request() {
        return FactRequest {
            .request_id = RequestId {"fact-1"},
            .subject = runtime_subject(),
            .route = FactRoute {.provider = "windows.process", .fact = "process.image"},
            .expected_schema = SchemaId {"unicode/v1"},
            .expected_schema_hash = "sha256:unicode-v1",
            .deadline_unix_ms = 10'000,
        };
    }

    WorkResultMessage runtime_work_result() {
        return WorkResultMessage {
            .originating_session = SessionId {"session-1"},
            .peer = PeerId {"peer-1"},
            .originating_session_fence = 7,
            .work_id = "work-1",
            .attempt_id = "attempt-1",
            .work_fence = 11,
            .generation = 3,
            .facts = {FactResponse {
                .request_id = RequestId {"fact-1"},
                .subject = runtime_subject(),
                .status = FactTerminalStatus::unavailable,
                .value = std::nullopt,
                .returned_schema = std::nullopt,
                .diagnostic = std::nullopt,
            }},
            .scans = {},
        };
    }

    WorkLeaseMessage runtime_work_lease() {
        return WorkLeaseMessage {
            .session = SessionId {"session-1"},
            .peer = PeerId {"peer-1"},
            .session_fence = 7,
            .work_id = "work-1",
            .attempt_id = "attempt-1",
            .work_fence = 11,
            .generation = 3,
            .server_sequence = 1,
            .route = "windows.process",
            .facts = {runtime_fact_request()},
            .scans = {},
        };
    }

    ServerHelloMessage runtime_server_hello() {
        return ServerHelloMessage {
            .selected_minor = 0,
            .session = SessionId {"session-1"},
            .peer = PeerId {"peer-1"},
            .session_fence = 7,
            .acknowledged_sequence = 0,
            .schemas = {},
            .capabilities = {},
            .credit = CreditWindow {.bytes = 1 * mebibyte, .messages = 1, .work_attempts = 1, .snapshot_chunks = 1},
            .heartbeat_interval_ms = 5'000,
        };
    }

    AgentHelloMessage runtime_agent_hello() {
        return AgentHelloMessage {
            .minimum_minor = 0,
            .maximum_minor = 0,
            .agent_version = "agent/test",
            .agent_epoch = "replaced-by-reconnect",
            .next_sequence = 1,
            .schemas = {},
            .capabilities = {},
            .receive_limit = {.bytes = 1 * mebibyte, .messages = 4, .work_attempts = 2, .snapshot_chunks = 2},
        };
    }

    bool write_bytes(const std::filesystem::path &path, const std::span<const std::byte> bytes) {
        std::ofstream output {path, std::ios::binary | std::ios::trunc};
        return output && static_cast<bool>(output.write(reinterpret_cast<const char *>(bytes.data()),
                                                        static_cast<std::streamsize>(bytes.size())));
    }

    std::vector<std::byte> read_bytes(const std::filesystem::path &path) {
        std::ifstream input {path, std::ios::binary | std::ios::ate};
        if (!input) {
            return {};
        }
        const auto size = input.tellg();
        if (size <= 0) {
            return {};
        }
        std::vector<std::byte> result(static_cast<std::size_t>(size));
        input.seekg(0);
        if (!input.read(reinterpret_cast<char *>(result.data()), size)) {
            return {};
        }
        return result;
    }

    TEST_CASE("protocol codec is canonical across a separate fixture process") {
        PeerEnvelope envelope {
            .protocol_major = 2,
            .protocol_minor = 0,
            .message_id = "cross-process-message",
            .session = SessionId {"session-1"},
            .agent_epoch = "epoch-1",
            .agent_sequence = 1,
            .acknowledged_agent_sequence = 0,
            .body = runtime_work_result(),
        };
        const auto frame = encode_frame(envelope);
        REQUIRE(frame.has_value());

        TemporaryDirectory temporary;
        const auto input = temporary.path / "input.frame";
        const auto output = temporary.path / "output.frame";
        REQUIRE(write_bytes(input, *frame));
        std::string command = std::string {"\"" RULE_ENGINE_PROTOCOL_FIXTURE_PATH "\" roundtrip \""} + input.string() +
                              "\" \"" + output.string() + "\"";
#ifdef _WIN32
        command = "\"" + command + "\"";
#endif
        REQUIRE(std::system(command.c_str()) == 0);
        REQUIRE(read_bytes(output) == *frame);
    }

    TEST_CASE("SQLite spool survives restart and preserves reconnect ACK NACK and backpressure semantics") {
        TemporaryDirectory temporary;
        const auto database = (temporary.path / "agent-spool.sqlite3").string();
        const AgentSpoolLimits spool_limits {
            .maximum_records = 8,
            .maximum_bytes = 1 * mebibyte,
            .high_water_bytes = 1,
            .low_water_bytes = 0,
        };
        if (!spool_backend_status().available) {
            const auto unavailable = SqliteAgentSpool::open(database, spool_limits);
            REQUIRE_FALSE(unavailable.has_value());
            REQUIRE(unavailable.error().code == ProtocolErrorCode::dependency_unavailable);
            return;
        }

        std::string epoch;
        std::vector<std::byte> first_body;
        {
            auto opened = SqliteAgentSpool::open(database, spool_limits);
            REQUIRE(opened.has_value());
            auto &spool = *opened;
            epoch = spool.agent_epoch();
            REQUIRE(epoch.size() == 32);
            REQUIRE(spool.enqueue(DurableAgentBody {runtime_work_result()}) == 1);
            REQUIRE(spool.enqueue(DurableAgentBody {runtime_work_result()}) == 2);
            REQUIRE(spool.next_sequence() == 3);
            REQUIRE(spool.backpressured());
            const auto pending = spool.pending(8, 1 * mebibyte);
            REQUIRE(pending.has_value());
            REQUIRE(pending->size() == 2);
            first_body = pending->front().canonical_body;
        }

        auto reopened = SqliteAgentSpool::open(database, spool_limits);
        REQUIRE(reopened.has_value());
        auto &spool = *reopened;
        REQUIRE(spool.agent_epoch() == epoch);
        REQUIRE(spool.pending_records() == 2);
        REQUIRE(spool.pending(8, 1 * mebibyte)->front().canonical_body == first_body);

        PersistentAgentSession session {PeerId {"peer-1"}, spool};
        auto hello = runtime_server_hello();
        REQUIRE(session.establish(hello).has_value());
        auto batch = session.take_transmit_batch();
        REQUIRE(batch.has_value());
        REQUIRE(batch->size() == 1);
        REQUIRE(batch->front().agent_sequence == 1);
        REQUIRE(std::get<WorkResultMessage>(batch->front().body).originating_session_fence == 7);

        hello.session = SessionId {"session-2"};
        hello.session_fence = 8;
        REQUIRE(session.establish(hello).has_value());
        batch = session.take_transmit_batch();
        REQUIRE(batch.has_value());
        REQUIRE(batch->front().session == hello.session);
        REQUIRE(batch->front().agent_sequence == 1);
        REQUIRE(spool.pending(8, 1 * mebibyte)->front().transmit_attempts == 2);

        REQUIRE(session
                    .acknowledge(AckMessage {
                        .agent_epoch = epoch,
                        .acknowledged_through = 1,
                        .credit = hello.credit,
                    })
                    .has_value());
        REQUIRE(spool.pending_records() == 1);
        REQUIRE(spool.backpressured());
        REQUIRE(session
                    .reject(NackMessage {
                        .agent_epoch = epoch,
                        .sequence = 2,
                        .reason = ProtocolErrorCode::schema_mismatch,
                        .permanent = true,
                        .diagnostic = "schema rejected",
                    })
                    .has_value());
        REQUIRE(spool.pending_records() == 0);
        REQUIRE_FALSE(spool.backpressured());
        REQUIRE_FALSE(spool.acknowledge(epoch, 3).has_value());

        const auto old_epoch = spool.agent_epoch();
        REQUIRE(spool.reset_epoch().has_value());
        REQUIRE(spool.agent_epoch() != old_epoch);
        REQUIRE(spool.next_sequence() == 1);
    }

    TEST_CASE("operator enrollment fails closed for URI fingerprint disabled peers and capability escalation") {
        const TlsPeerIdentity certificate {
            .tls_major = 1,
            .tls_minor = 3,
            .mutual_authentication = true,
            .certificate_chain_verified = true,
            .client_auth_eku = true,
            .revoked = false,
            .canonical_uri_san = "urn:rule-engine:peer-1",
            .certificate_sha256 = "001122",
        };
        const CapabilityAdvertisement allowed {
            .capability = CapabilityId {"windows.process"},
            .version = 1,
            .request_schema = SchemaId {"request/v1"},
            .response_schema = SchemaId {"response/v1"},
        };

        OperatorTrustPolicy policy;
        REQUIRE(policy
                    .enroll(PeerEnrollment {
                        .canonical_uri_san = certificate.canonical_uri_san,
                        .certificate_sha256 = certificate.certificate_sha256,
                        .identity = AuthenticatedPeer {.tenant = TenantId {"tenant-1"}, .peer = PeerId {"peer-1"}},
                        .disabled = false,
                        .capabilities = {{.capability = allowed.capability,
                                          .maximum_version = 1,
                                          .request_schema = allowed.request_schema,
                                          .response_schema = allowed.response_schema}},
                    })
                    .has_value());
        REQUIRE(authenticate_and_authorize(certificate, policy, std::span {&allowed, 1}).has_value());

        auto wrong_uri = certificate;
        wrong_uri.canonical_uri_san = "urn:rule-engine:peer-2";
        REQUIRE_FALSE(authenticate_transport(wrong_uri, policy).has_value());
        auto wrong_fingerprint = certificate;
        wrong_fingerprint.certificate_sha256 = "deadbeef";
        REQUIRE_FALSE(authenticate_transport(wrong_fingerprint, policy).has_value());
        auto escalation = allowed;
        escalation.version = 2;
        REQUIRE_FALSE(authenticate_and_authorize(certificate, policy, std::span {&escalation, 1}).has_value());

        OperatorTrustPolicy disabled;
        REQUIRE(disabled
                    .enroll(PeerEnrollment {
                        .canonical_uri_san = certificate.canonical_uri_san,
                        .certificate_sha256 = certificate.certificate_sha256,
                        .identity = AuthenticatedPeer {.tenant = TenantId {"tenant-1"}, .peer = PeerId {"peer-1"}},
                        .disabled = true,
                        .capabilities = {},
                    })
                    .has_value());
        REQUIRE_FALSE(authenticate_transport(certificate, disabled).has_value());
    }

    TEST_CASE("OpenSSL transport performs TLS 1.3 mTLS and rejects chain time EKU and SAN failures") {
        if (!tls_backend_status().available) {
            const auto unavailable = OpenSslTlsContext::create({});
            REQUIRE_FALSE(unavailable.has_value());
            REQUIRE(unavailable.error().code == ProtocolErrorCode::dependency_unavailable);
            return;
        }
#ifndef RULE_ENGINE_PROTOCOL_OPENSSL_EXECUTABLE
        SKIP("OpenSSL library is linked but no certificate-generation executable is available");
#else
        SocketRuntime sockets;
        REQUIRE(sockets.available);
        TemporaryDirectory temporary;
        const auto certificates = CertificateFixture::generate(temporary.path);
        REQUIRE(certificates.has_value());

        const auto server_configuration = [&certificates](const std::filesystem::path &certificate,
                                                          const std::filesystem::path &key) {
            return TlsConfiguration {
                .role = TlsEndpointRole::server,
                .trust_anchors_pem = certificates->ca.string(),
                .certificate_chain_pem = certificate.string(),
                .private_key_pem = key.string(),
                .crl_pem = {},
                .expected_server_name = {},
                .require_crl = false,
                .verification_time_unix_seconds = std::nullopt,
                .protocol_limits = {},
            };
        };
        const auto client_configuration = [](const std::filesystem::path &trust,
                                             const std::filesystem::path &certificate, const std::filesystem::path &key,
                                             std::string hostname = "localhost") {
            return TlsConfiguration {
                .role = TlsEndpointRole::client,
                .trust_anchors_pem = trust.string(),
                .certificate_chain_pem = certificate.string(),
                .private_key_pem = key.string(),
                .crl_pem = {},
                .expected_server_name = std::move(hostname),
                .require_crl = false,
                .verification_time_unix_seconds = std::nullopt,
                .protocol_limits = {},
            };
        };

        auto server =
            OpenSslTlsContext::create(server_configuration(certificates->server_certificate, certificates->server_key));
        auto client = OpenSslTlsContext::create(
            client_configuration(certificates->ca, certificates->client_certificate, certificates->client_key));
        REQUIRE(server.has_value());
        REQUIRE(client.has_value());

        AgentHelloMessage hello {
            .minimum_minor = 0,
            .maximum_minor = 0,
            .agent_version = "agent/test",
            .agent_epoch = "epoch-1",
            .next_sequence = 1,
            .schemas = {},
            .capabilities = {{.capability = CapabilityId {"windows.process"},
                              .version = 1,
                              .request_schema = SchemaId {"request/v1"},
                              .response_schema = SchemaId {"response/v1"}}},
            .receive_limit = {.bytes = 1 * mebibyte, .messages = 4, .work_attempts = 2, .snapshot_chunks = 2},
        };
        PeerEnvelope hello_envelope {
            .protocol_major = 2,
            .protocol_minor = 0,
            .message_id = "tls-hello",
            .session = std::nullopt,
            .agent_epoch = "epoch-1",
            .agent_sequence = 0,
            .acknowledged_agent_sequence = 0,
            .body = hello,
        };
        const auto valid = run_tls_pair(*server, *client, hello_envelope);
        REQUIRE(valid.server_handshake.has_value());
        REQUIRE(valid.server_handshake->has_value());
        REQUIRE(valid.client_handshake.has_value());
        REQUIRE(valid.client_handshake->has_value());
        REQUIRE(valid.server_received.has_value());
        REQUIRE(valid.server_received->has_value());
        REQUIRE(std::get<AgentHelloMessage>((*valid.server_received)->body).agent_epoch == "epoch-1");
        REQUIRE((*valid.server_handshake)->canonical_uri_san == "urn:rule-engine:peer-1");
        REQUIRE((*valid.server_handshake)->tls_minor == 3);

        OperatorTrustPolicy enrollment;
        REQUIRE(enrollment
                    .enroll(PeerEnrollment {
                        .canonical_uri_san = "urn:rule-engine:peer-1",
                        .certificate_sha256 = (*valid.server_handshake)->certificate_sha256,
                        .identity = AuthenticatedPeer {.tenant = TenantId {"tenant-1"}, .peer = PeerId {"peer-1"}},
                        .disabled = false,
                        .capabilities = {{.capability = CapabilityId {"windows.process"},
                                          .maximum_version = 1,
                                          .request_schema = SchemaId {"request/v1"},
                                          .response_schema = SchemaId {"response/v1"}}},
                    })
                    .has_value());
        REQUIRE(authenticate_and_authorize(**valid.server_handshake, enrollment, hello.capabilities).has_value());

        const auto succeeds = [](TlsConfiguration server_config, TlsConfiguration client_config) {
            auto server_context = OpenSslTlsContext::create(std::move(server_config));
            auto client_context = OpenSslTlsContext::create(std::move(client_config));
            if (!server_context || !client_context) {
                return false;
            }
            const auto pair = run_tls_pair(*server_context, *client_context);
            return pair.server_handshake.has_value() && pair.server_handshake->has_value() &&
                   pair.client_handshake.has_value() && pair.client_handshake->has_value();
        };

        REQUIRE_FALSE(succeeds(server_configuration(certificates->server_certificate, certificates->server_key),
                               client_configuration(certificates->alternate_ca, certificates->client_certificate,
                                                    certificates->client_key)));
        REQUIRE_FALSE(succeeds(server_configuration(certificates->server_certificate, certificates->server_key),
                               client_configuration(certificates->ca, certificates->client_certificate,
                                                    certificates->client_key, "wrong-host.invalid")));

        auto future_client =
            client_configuration(certificates->ca, certificates->client_certificate, certificates->client_key);
        future_client.verification_time_unix_seconds =
            std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch() +
                                                             std::chrono::hours {72})
                .count();
        REQUIRE_FALSE(succeeds(server_configuration(certificates->server_certificate, certificates->server_key),
                               std::move(future_client)));
        REQUIRE_FALSE(succeeds(
            server_configuration(certificates->server_certificate, certificates->server_key),
            client_configuration(certificates->ca, certificates->wrong_eku_certificate, certificates->wrong_eku_key)));

        auto missing_crl = server_configuration(certificates->server_certificate, certificates->server_key);
        missing_crl.require_crl = true;
        REQUIRE_FALSE(OpenSslTlsContext::create(std::move(missing_crl)).has_value());
        auto disabled_crl = server_configuration(certificates->server_certificate, certificates->server_key);
        disabled_crl.crl_pem = certificates->clean_crl.string();
        REQUIRE_FALSE(OpenSslTlsContext::create(std::move(disabled_crl)).has_value());

        const auto client_with_crl = [&](const std::filesystem::path &path) {
            auto configuration =
                client_configuration(certificates->ca, certificates->client_certificate, certificates->client_key);
            configuration.crl_pem = path.string();
            configuration.require_crl = true;
            return configuration;
        };
        REQUIRE(succeeds(server_configuration(certificates->server_certificate, certificates->server_key),
                         client_with_crl(certificates->clean_crl)));

        auto missing_crl_file = client_with_crl(temporary.path / "missing.crl.pem");
        REQUIRE_FALSE(OpenSslTlsContext::create(std::move(missing_crl_file)).has_value());
        auto malformed_crl = client_with_crl(certificates->malformed_crl);
        REQUIRE_FALSE(OpenSslTlsContext::create(std::move(malformed_crl)).has_value());
        REQUIRE_FALSE(succeeds(server_configuration(certificates->server_certificate, certificates->server_key),
                               client_with_crl(certificates->stale_crl)));
        REQUIRE_FALSE(succeeds(server_configuration(certificates->server_certificate, certificates->server_key),
                               client_with_crl(certificates->wrong_issuer_crl)));
        REQUIRE_FALSE(succeeds(server_configuration(certificates->server_certificate, certificates->server_key),
                               client_with_crl(certificates->revoked_crl)));
#endif
    }

    TEST_CASE("owned TLS orchestration replays the durable agent spool and wakes on idle peer close") {
        if (!tls_backend_status().available || !spool_backend_status().available) {
            SUCCEED("TLS and SQLite backends are required for the reconnect integration test");
            return;
        }
#ifndef RULE_ENGINE_PROTOCOL_OPENSSL_EXECUTABLE
        SUCCEED("OpenSSL certificate-generation executable is unavailable");
        return;
#else
        SocketRuntime sockets;
        REQUIRE(sockets.available);
        TemporaryDirectory temporary;
        const auto certificates = CertificateFixture::generate(temporary.path);
        REQUIRE(certificates.has_value());

        auto server_context = OpenSslTlsContext::create(orchestration_server_configuration(*certificates));
        auto client_context = OpenSslTlsContext::create(orchestration_client_configuration(*certificates));
        REQUIRE(server_context.has_value());
        REQUIRE(client_context.has_value());
        const auto timeouts = orchestration_timeouts();
        auto listener = TlsSessionListener::bind(std::move(*server_context),
                                                 TcpEndpoint {.host = "127.0.0.1", .port = 0}, timeouts);
        REQUIRE(listener.has_value());
        const auto endpoint = listener->local_endpoint();
        auto dialer = TlsSessionDialer::create(
            std::move(*client_context), {TcpEndpoint {.host = "localhost", .port = endpoint.port}},
            TlsPeerRequirement {.canonical_uri_san = "urn:rule-engine:server", .certificate_sha256 = std::nullopt},
            timeouts, one_round_reconnect());
        REQUIRE(dialer.has_value());

        OperatorTrustPolicy policy;
        REQUIRE(policy
                    .enroll(PeerEnrollment {
                        .canonical_uri_san = "urn:rule-engine:peer-1",
                        .certificate_sha256 = {},
                        .identity = AuthenticatedPeer {.tenant = TenantId {"tenant-1"}, .peer = PeerId {"peer-1"}},
                        .disabled = false,
                        .capabilities = {},
                    })
                    .has_value());

        auto spool = SqliteAgentSpool::open((temporary.path / "network-spool.sqlite3").string());
        REQUIRE(spool.has_value());
        PersistentAgentSession persistent {PeerId {"peer-1"}, *spool};
        REQUIRE(persistent.enqueue(runtime_work_result()).has_value());

        std::optional<ProtocolError> server_error;
        std::optional<AuthenticatedPeer> authenticated_peer;
        std::optional<AgentHelloMessage> received_hello;
        std::optional<std::uint64_t> replayed_sequence;
        std::optional<bool> idle_readable;
        std::optional<bool> replay_readable;
        std::jthread server {[&] {
            auto accepted = listener->accept(policy);
            if (!accepted) {
                server_error = accepted.error();
                return;
            }
            authenticated_peer = accepted->peer;
            auto hello = accepted->connection.receive();
            if (!hello) {
                server_error = hello.error();
                return;
            }
            if (!std::holds_alternative<AgentHelloMessage>(hello->body)) {
                server_error = ProtocolError {.code = ProtocolErrorCode::unexpected_message,
                                              .message = "server expected agent hello",
                                              .byte_offset = 0};
                return;
            }
            received_hello = std::get<AgentHelloMessage>(std::move(hello->body));
            auto idle = accepted->connection.wait_readable_until(std::chrono::steady_clock::now() +
                                                                 std::chrono::milliseconds {25});
            if (!idle) {
                server_error = idle.error();
                return;
            }
            idle_readable = *idle;

            const auto welcome = runtime_server_hello();
            PeerEnvelope welcome_envelope {
                .protocol_major = 2,
                .protocol_minor = 0,
                .message_id = "server-welcome",
                .session = welcome.session,
                .agent_epoch = received_hello->agent_epoch,
                .agent_sequence = 0,
                .acknowledged_agent_sequence = 0,
                .body = welcome,
            };
            if (auto sent = accepted->connection.send(welcome_envelope); !sent) {
                server_error = sent.error();
                return;
            }
            auto ready =
                accepted->connection.wait_readable_until(std::chrono::steady_clock::now() + std::chrono::seconds {2});
            if (!ready) {
                server_error = ready.error();
                return;
            }
            replay_readable = *ready;
            auto replay = accepted->connection.receive();
            if (!replay) {
                server_error = replay.error();
                return;
            }
            if (!std::holds_alternative<WorkResultMessage>(replay->body)) {
                server_error = ProtocolError {.code = ProtocolErrorCode::unexpected_message,
                                              .message = "server expected replayed work result",
                                              .byte_offset = 0};
                return;
            }
            replayed_sequence = replay->agent_sequence;
        }};

        auto connected = dialer->reconnect(persistent, runtime_agent_hello());
        server.join();
        REQUIRE(connected.has_value());
        const auto close_wait_started = std::chrono::steady_clock::now();
        auto peer_closed = connected->connection.wait_readable_until(close_wait_started + std::chrono::seconds {2});
        REQUIRE(peer_closed.has_value());
        REQUIRE(*peer_closed);
        CHECK(std::chrono::steady_clock::now() - close_wait_started < std::chrono::seconds {1});
        auto eof =
            connected->connection.receive_until(std::chrono::steady_clock::now() + std::chrono::milliseconds {250});
        REQUIRE_FALSE(eof.has_value());
        CHECK(eof.error().code == ProtocolErrorCode::transport_error);
        REQUIRE_FALSE(server_error.has_value());
        REQUIRE(authenticated_peer.has_value());
        REQUIRE(authenticated_peer->tenant.value == "tenant-1");
        REQUIRE(authenticated_peer->peer.value == "peer-1");
        REQUIRE(received_hello.has_value());
        REQUIRE(received_hello->agent_epoch == spool->agent_epoch());
        REQUIRE(received_hello->next_sequence == 2);
        REQUIRE(idle_readable == false);
        REQUIRE(replay_readable == true);
        REQUIRE(replayed_sequence == 1);
        REQUIRE(connected->replayed_records == 1);
        REQUIRE(connected->server_hello.session.value == "session-1");
        REQUIRE(connected->connection.peer_identity().canonical_uri_san == "urn:rule-engine:server");
        REQUIRE(connected->connection.remote_endpoint().port == endpoint.port);
        REQUIRE(persistent.established());

        PeerEnvelope extra {
            .protocol_major = 2,
            .protocol_minor = 0,
            .message_id = "expired-write",
            .session = SessionId {"session-1"},
            .agent_epoch = spool->agent_epoch(),
            .agent_sequence = 1,
            .acknowledged_agent_sequence = 0,
            .body = runtime_work_result(),
        };
        const auto expired_write =
            connected->connection.send_until(extra, std::chrono::steady_clock::now() - std::chrono::milliseconds {1});
        REQUIRE_FALSE(expired_write.has_value());
        REQUIRE(expired_write.error().code == ProtocolErrorCode::timed_out);
        REQUIRE(expired_write.error().message.find("timed out") != std::string::npos);
#endif
    }

    TEST_CASE("TLS socket orchestration bounds refusal timeout cancellation backoff and address failover") {
        if (!tls_backend_status().available) {
            SUCCEED("OpenSSL backend is unavailable");
            return;
        }
#ifndef RULE_ENGINE_PROTOCOL_OPENSSL_EXECUTABLE
        SUCCEED("OpenSSL certificate-generation executable is unavailable");
        return;
#else
        SocketRuntime sockets;
        REQUIRE(sockets.available);
        TemporaryDirectory temporary;
        const auto certificates = CertificateFixture::generate(temporary.path);
        REQUIRE(certificates.has_value());

        OperatorTrustPolicy policy;
        REQUIRE(policy
                    .enroll(PeerEnrollment {
                        .canonical_uri_san = "urn:rule-engine:peer-1",
                        .certificate_sha256 = {},
                        .identity = AuthenticatedPeer {.tenant = TenantId {"tenant-1"}, .peer = PeerId {"peer-1"}},
                        .disabled = false,
                        .capabilities = {},
                    })
                    .has_value());

        auto timeout_context = OpenSslTlsContext::create(orchestration_server_configuration(*certificates));
        REQUIRE(timeout_context.has_value());
        auto accept_timeouts = orchestration_timeouts();
        accept_timeouts.accept = std::chrono::milliseconds {50};
        auto timeout_listener = TlsSessionListener::bind(std::move(*timeout_context),
                                                         TcpEndpoint {.host = "127.0.0.1", .port = 0}, accept_timeouts);
        REQUIRE(timeout_listener.has_value());
        const auto accept_started = std::chrono::steady_clock::now();
        const auto accept_timeout = timeout_listener->accept(policy);
        REQUIRE_FALSE(accept_timeout.has_value());
        REQUIRE(accept_timeout.error().code == ProtocolErrorCode::timed_out);
        REQUIRE(accept_timeout.error().message.find("timed out") != std::string::npos);
        REQUIRE(std::chrono::steady_clock::now() - accept_started < std::chrono::seconds {1});

        auto cancel_context = OpenSslTlsContext::create(orchestration_server_configuration(*certificates));
        REQUIRE(cancel_context.has_value());
        auto cancel_timeouts = orchestration_timeouts();
        cancel_timeouts.accept = std::chrono::seconds {5};
        auto cancel_listener = TlsSessionListener::bind(std::move(*cancel_context),
                                                        TcpEndpoint {.host = "127.0.0.1", .port = 0}, cancel_timeouts);
        REQUIRE(cancel_listener.has_value());
        std::optional<std::expected<AuthenticatedTlsPeer, ProtocolError>> canceled_accept;
        std::jthread accepting {
            [&](const std::stop_token stop) { canceled_accept = cancel_listener->accept(policy, stop); }};
        std::this_thread::sleep_for(std::chrono::milliseconds {25});
        accepting.request_stop();
        accepting.join();
        REQUIRE(canceled_accept.has_value());
        REQUIRE_FALSE(canceled_accept->has_value());
        REQUIRE(canceled_accept->error().code == ProtocolErrorCode::canceled);

        std::optional<std::expected<AuthenticatedTlsPeer, ProtocolError>> listener_canceled_accept;
        std::jthread listener_accepting {[&] { listener_canceled_accept = cancel_listener->accept(policy); }};
        std::this_thread::sleep_for(std::chrono::milliseconds {25});
        cancel_listener->cancel();
        listener_accepting.join();
        REQUIRE(listener_canceled_accept.has_value());
        REQUIRE_FALSE(listener_canceled_accept->has_value());
        REQUIRE(listener_canceled_accept->error().code == ProtocolErrorCode::canceled);

        auto handshake_cancel_context = OpenSslTlsContext::create(orchestration_server_configuration(*certificates));
        REQUIRE(handshake_cancel_context.has_value());
        auto handshake_cancel_timeouts = orchestration_timeouts();
        handshake_cancel_timeouts.handshake = std::chrono::seconds {5};
        auto handshake_cancel_listener =
            TlsSessionListener::bind(std::move(*handshake_cancel_context), TcpEndpoint {.host = "127.0.0.1", .port = 0},
                                     handshake_cancel_timeouts);
        REQUIRE(handshake_cancel_listener.has_value());
        std::optional<std::expected<AuthenticatedTlsPeer, ProtocolError>> canceled_handshake;
        std::jthread handshake_accepting {[&] { canceled_handshake = handshake_cancel_listener->accept(policy); }};
        auto raw_handshake_client = connect_loopback(handshake_cancel_listener->local_endpoint().port);
        REQUIRE(raw_handshake_client.has_value());
        std::this_thread::sleep_for(std::chrono::milliseconds {25});
        const auto handshake_cancel_started = std::chrono::steady_clock::now();
        handshake_cancel_listener->cancel();
        handshake_accepting.join();
        REQUIRE(canceled_handshake.has_value());
        REQUIRE_FALSE(canceled_handshake->has_value());
        REQUIRE(canceled_handshake->error().code == ProtocolErrorCode::canceled);
        REQUIRE(std::chrono::steady_clock::now() - handshake_cancel_started < std::chrono::seconds {1});

        auto released_listener = listen_loopback();
        REQUIRE(released_listener.has_value());
        const auto refused_port = released_listener->port;
        released_listener.reset();
        auto refused_context = OpenSslTlsContext::create(orchestration_client_configuration(*certificates));
        REQUIRE(refused_context.has_value());
        auto refusal_timeouts = orchestration_timeouts();
        refusal_timeouts.connect = std::chrono::milliseconds {100};
        refusal_timeouts.total_dial = std::chrono::seconds {2};
        ReconnectPolicy refusal_policy {
            .initial_backoff = std::chrono::milliseconds {10},
            .maximum_backoff = std::chrono::milliseconds {25},
            .maximum_rounds = 4,
            .maximum_endpoints = 1,
            .maximum_addresses_per_endpoint = 1,
            .maximum_connection_attempts = 4,
            .require_hard_resolver_bounds = true,
        };
        auto refused_dialer = TlsSessionDialer::create(
            std::move(*refused_context), {TcpEndpoint {.host = "refused.test", .port = refused_port}},
            TlsPeerRequirement {.canonical_uri_san = "urn:rule-engine:server", .certificate_sha256 = std::nullopt},
            refusal_timeouts, refusal_policy);
        REQUIRE(refused_dialer.has_value());
        const auto moved_context_rejected = TlsSessionDialer::create(
            std::move(*refused_context), {TcpEndpoint {.host = "refused.test", .port = refused_port}},
            TlsPeerRequirement {.canonical_uri_san = "urn:rule-engine:server", .certificate_sha256 = std::nullopt},
            refusal_timeouts, refusal_policy);
        REQUIRE_FALSE(moved_context_rejected.has_value());
        REQUIRE(moved_context_rejected.error().code == ProtocolErrorCode::malformed);
        const auto system_resolver_rejected = refused_dialer->connect();
        REQUIRE_FALSE(system_resolver_rejected.has_value());
        REQUIRE(system_resolver_rejected.error().code == ProtocolErrorCode::dependency_unavailable);
        FixedResolver refused_resolver {
            {{.family = TcpAddressFamily::ipv4, .address = "127.0.0.1", .port = refused_port}}};
        RecordingJitter refusal_jitter;
        const auto refused = refused_dialer->connect(refused_resolver, refusal_jitter);
        REQUIRE_FALSE(refused.has_value());
        REQUIRE((refused.error().code == ProtocolErrorCode::transport_error ||
                 refused.error().code == ProtocolErrorCode::timed_out));
        REQUIRE(refusal_jitter.bounds == std::vector {std::chrono::milliseconds {10}, std::chrono::milliseconds {20},
                                                      std::chrono::milliseconds {25}});
        REQUIRE(refused_resolver.calls.load() == 4);

        auto cancel_dial_context = OpenSslTlsContext::create(orchestration_client_configuration(*certificates));
        REQUIRE(cancel_dial_context.has_value());
        ReconnectPolicy cancel_dial_policy = refusal_policy;
        cancel_dial_policy.initial_backoff = std::chrono::seconds {5};
        cancel_dial_policy.maximum_backoff = std::chrono::seconds {5};
        cancel_dial_policy.maximum_rounds = 8;
        cancel_dial_policy.maximum_connection_attempts = 8;
        refusal_timeouts.total_dial = std::chrono::seconds {30};
        auto cancel_dialer = TlsSessionDialer::create(
            std::move(*cancel_dial_context), {TcpEndpoint {.host = "refused.test", .port = refused_port}},
            TlsPeerRequirement {.canonical_uri_san = "urn:rule-engine:server", .certificate_sha256 = std::nullopt},
            refusal_timeouts, cancel_dial_policy);
        REQUIRE(cancel_dialer.has_value());
        FixedResolver cancel_resolver {
            {{.family = TcpAddressFamily::ipv4, .address = "127.0.0.1", .port = refused_port}}};
        RecordingJitter cancel_jitter;
        std::optional<std::expected<TlsPeerConnection, ProtocolError>> canceled_dial;
        std::jthread dialing {[&](const std::stop_token stop) {
            canceled_dial = cancel_dialer->connect(cancel_resolver, cancel_jitter, stop);
        }};
        for (std::size_t poll = 0; poll < 1'000 && cancel_jitter.calls.load() == 0; ++poll) {
            std::this_thread::sleep_for(std::chrono::milliseconds {1});
        }
        REQUIRE(cancel_jitter.calls.load() == 1);
        dialing.request_stop();
        dialing.join();
        REQUIRE(canceled_dial.has_value());
        REQUIRE_FALSE(canceled_dial->has_value());
        REQUIRE(canceled_dial->error().code == ProtocolErrorCode::canceled);

        auto silent_listener = listen_loopback();
        REQUIRE(silent_listener.has_value());
        std::jthread silent_server {[&] {
            sockaddr_in address {};
#ifdef _WIN32
            int address_size = sizeof(address);
#else
            socklen_t address_size = sizeof(address);
#endif
            TestSocket socket {
                accept(silent_listener->socket.value, reinterpret_cast<sockaddr *>(&address), &address_size)};
            if (socket.value != invalid_test_socket) {
                std::this_thread::sleep_for(std::chrono::milliseconds {200});
            }
        }};
        auto handshake_context = OpenSslTlsContext::create(orchestration_client_configuration(*certificates));
        REQUIRE(handshake_context.has_value());
        auto handshake_timeouts = orchestration_timeouts();
        handshake_timeouts.handshake = std::chrono::milliseconds {50};
        handshake_timeouts.total_dial = std::chrono::seconds {1};
        auto handshake_dialer = TlsSessionDialer::create(
            std::move(*handshake_context), {TcpEndpoint {.host = "silent.test", .port = silent_listener->port}},
            TlsPeerRequirement {.canonical_uri_san = "urn:rule-engine:server", .certificate_sha256 = std::nullopt},
            handshake_timeouts, one_round_reconnect());
        REQUIRE(handshake_dialer.has_value());
        FixedResolver silent_resolver {
            {{.family = TcpAddressFamily::ipv4, .address = "127.0.0.1", .port = silent_listener->port}}};
        RecordingJitter silent_jitter;
        const auto handshake_timeout = handshake_dialer->connect(silent_resolver, silent_jitter);
        silent_server.join();
        REQUIRE_FALSE(handshake_timeout.has_value());
        REQUIRE(handshake_timeout.error().code == ProtocolErrorCode::timed_out);
        REQUIRE(handshake_timeout.error().message.find("timed out") != std::string::npos);

        auto failover_server_context = OpenSslTlsContext::create(orchestration_server_configuration(*certificates));
        auto failover_client_context = OpenSslTlsContext::create(orchestration_client_configuration(*certificates));
        REQUIRE(failover_server_context.has_value());
        REQUIRE(failover_client_context.has_value());
        auto failover_timeouts = orchestration_timeouts();
        failover_timeouts.read = std::chrono::milliseconds {50};
        auto failover_listener = TlsSessionListener::bind(
            std::move(*failover_server_context), TcpEndpoint {.host = "127.0.0.1", .port = 0}, failover_timeouts);
        REQUIRE(failover_listener.has_value());
        const auto failover_port = failover_listener->local_endpoint().port;
        auto failover_dialer = TlsSessionDialer::create(
            std::move(*failover_client_context),
            {TcpEndpoint {.host = "refused.test", .port = refused_port},
             TcpEndpoint {.host = "multi-address.test", .port = failover_port}},
            TlsPeerRequirement {.canonical_uri_san = "urn:rule-engine:server", .certificate_sha256 = std::nullopt},
            failover_timeouts, one_round_reconnect());
        REQUIRE(failover_dialer.has_value());
        FixedResolver failover_resolver {{{.family = TcpAddressFamily::ipv4, .address = "127.0.0.2", .port = 0},
                                          {.family = TcpAddressFamily::ipv4, .address = "127.0.0.1", .port = 0}},
                                         true};
        RecordingJitter failover_jitter;
        std::optional<ProtocolError> failover_server_error;
        std::optional<AuthenticatedPeer> failover_peer;
        std::jthread failover_server {[&] {
            auto accepted = failover_listener->accept(policy);
            if (!accepted) {
                failover_server_error = accepted.error();
                return;
            }
            failover_peer = accepted->peer;
            std::this_thread::sleep_for(std::chrono::milliseconds {200});
        }};
        auto failover = failover_dialer->connect(failover_resolver, failover_jitter);
        REQUIRE(failover.has_value());
        REQUIRE(failover->remote_endpoint().host == "127.0.0.1");
        REQUIRE(failover_resolver.calls.load() == 2);
        const auto read_timeout = failover->receive();
        failover_server.join();
        REQUIRE_FALSE(failover_server_error.has_value());
        REQUIRE(failover_peer.has_value());
        REQUIRE_FALSE(read_timeout.has_value());
        REQUIRE(read_timeout.error().code == ProtocolErrorCode::timed_out);
        REQUIRE(read_timeout.error().message.find("timed out") != std::string::npos);

        auto identity_server_context = OpenSslTlsContext::create(orchestration_server_configuration(*certificates));
        auto identity_client_context = OpenSslTlsContext::create(orchestration_client_configuration(*certificates));
        REQUIRE(identity_server_context.has_value());
        REQUIRE(identity_client_context.has_value());
        auto identity_listener =
            TlsSessionListener::bind(std::move(*identity_server_context), TcpEndpoint {.host = "127.0.0.1", .port = 0},
                                     orchestration_timeouts());
        REQUIRE(identity_listener.has_value());
        const auto identity_port = identity_listener->local_endpoint().port;
        auto identity_dialer = TlsSessionDialer::create(
            std::move(*identity_client_context), {TcpEndpoint {.host = "identity.test", .port = identity_port}},
            TlsPeerRequirement {.canonical_uri_san = "urn:rule-engine:wrong-server",
                                .certificate_sha256 = std::nullopt},
            orchestration_timeouts(), one_round_reconnect());
        REQUIRE(identity_dialer.has_value());
        FixedResolver identity_resolver {
            {{.family = TcpAddressFamily::ipv4, .address = "127.0.0.1", .port = identity_port}}};
        RecordingJitter identity_jitter;
        std::jthread identity_server {[&] { static_cast<void>(identity_listener->accept(policy)); }};
        const auto identity_mismatch = identity_dialer->connect(identity_resolver, identity_jitter);
        identity_server.join();
        REQUIRE_FALSE(identity_mismatch.has_value());
        REQUIRE(identity_mismatch.error().code == ProtocolErrorCode::unauthenticated);

        auto fingerprint_client_context = OpenSslTlsContext::create(orchestration_client_configuration(*certificates));
        REQUIRE(fingerprint_client_context.has_value());
        auto fingerprint_dialer = TlsSessionDialer::create(
            std::move(*fingerprint_client_context), {TcpEndpoint {.host = "fingerprint.test", .port = identity_port}},
            TlsPeerRequirement {.canonical_uri_san = "urn:rule-engine:server",
                                .certificate_sha256 = std::string(64, '0')},
            orchestration_timeouts(), one_round_reconnect());
        REQUIRE(fingerprint_dialer.has_value());
        FixedResolver fingerprint_resolver {
            {{.family = TcpAddressFamily::ipv4, .address = "127.0.0.1", .port = identity_port}}};
        RecordingJitter fingerprint_jitter;
        std::jthread fingerprint_server {[&] { static_cast<void>(identity_listener->accept(policy)); }};
        const auto fingerprint_mismatch = fingerprint_dialer->connect(fingerprint_resolver, fingerprint_jitter);
        fingerprint_server.join();
        REQUIRE_FALSE(fingerprint_mismatch.has_value());
        REQUIRE(fingerprint_mismatch.error().code == ProtocolErrorCode::unauthenticated);
#endif
    }

    TEST_CASE("Windows provider adapter spools only typed work results and authoritative snapshots") {
        if (!spool_backend_status().available) {
            SKIP("SQLite spool backend is unavailable in this configuration");
        }
        struct Provider final: IWindowsAgentProvider {
            [[nodiscard]] std::expected<std::vector<FactResponse>, ProviderDispatchError>
            resolve_facts(const std::span<const FactRequest> requests) noexcept override {
                std::vector<FactResponse> responses;
                for (const auto &request : requests) {
                    responses.push_back(FactResponse {
                        .request_id = request.request_id,
                        .subject = request.subject,
                        .status = FactTerminalStatus::unavailable,
                        .value = std::nullopt,
                        .returned_schema = std::nullopt,
                        .diagnostic = std::nullopt,
                    });
                }
                return responses;
            }
            [[nodiscard]] std::expected<std::vector<ScanResponse>, ProviderDispatchError>
            resolve_scans(std::span<const ScanRequest>) noexcept override {
                return std::vector<ScanResponse> {};
            }
            void cancel(std::span<const RequestId>) noexcept override {}
        } provider;
        struct Enumerator final: IWindowsSubjectEnumerator {
            [[nodiscard]] std::expected<std::vector<SubjectKey>, ProviderDispatchError>
            enumerate(const SnapshotEnumerationRequest &) noexcept override {
                return std::vector {runtime_subject(20), runtime_subject(10)};
            }
        } enumerator;

        TemporaryDirectory temporary;
        auto opened = SqliteAgentSpool::open((temporary.path / "provider-spool.sqlite3").string());
        REQUIRE(opened.has_value());
        WindowsAgentProviderRouter router;
        REQUIRE(router.bind("windows.process", provider).has_value());
        WindowsProviderSpoolAdapter adapter {router, *opened};
        REQUIRE(adapter.dispatch_and_spool(runtime_work_lease()).has_value());

        const SnapshotEnumerationRequest snapshot {
            .session = SessionId {"session-1"},
            .peer = PeerId {"peer-1"},
            .session_fence = 7,
            .snapshot_id = "snapshot-1",
            .parent = std::nullopt,
            .subject_schema = SchemaId {"process/v1"},
            .generation = 1,
            .chunk_items = 1,
        };
        const auto publication = adapter.enumerate_and_spool(snapshot, enumerator);
        REQUIRE(publication.has_value());
        REQUIRE(publication->sequences.size() == 4);
        const auto pending = opened->pending(16, 16 * mebibyte);
        REQUIRE(pending.has_value());
        REQUIRE(pending->size() == 5);
        REQUIRE(std::holds_alternative<WorkResultMessage>((*pending)[0].body));
        REQUIRE(std::holds_alternative<AuthoritativeSnapshotBegin>((*pending)[1].body));
        REQUIRE(std::holds_alternative<AuthoritativeSnapshotChunk>((*pending)[2].body));
        REQUIRE(std::holds_alternative<AuthoritativeSnapshotChunk>((*pending)[3].body));
        REQUIRE(std::holds_alternative<AuthoritativeSnapshotCommit>((*pending)[4].body));
        const auto &first_chunk = std::get<AuthoritativeSnapshotChunk>((*pending)[2].body);
        REQUIRE(canonical_subject_key(first_chunk.subjects.front()) == canonical_subject_key(runtime_subject(10)));
    }

} // namespace
