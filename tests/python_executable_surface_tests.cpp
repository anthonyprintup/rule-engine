#include <catch2/catch_test_macros.hpp>

#include "rule_engine/python/tools/benchmark.hpp"
#include "rule_engine/python/tools/server.hpp"
#include "rule_engine/python/protocol/codec.hpp"

#ifndef RULE_ENGINE_PYTHON_SERVER_PATH
#define RULE_ENGINE_PYTHON_SERVER_PATH ""
#endif

#ifndef RULE_ENGINE_PYTHON_BENCHMARK_PATH
#define RULE_ENGINE_PYTHON_BENCHMARK_PATH ""
#endif

#include <chrono>
#include <atomic>
#include <array>
#include <condition_variable>
#include <cstdlib>
#include <deque>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <mutex>
#include <thread>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#if !defined(_WIN32)
#include <sys/wait.h>
#endif

namespace {

    struct TemporaryDirectory {
        std::filesystem::path path;

        TemporaryDirectory() {
            const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
            std::error_code error;
            path = std::filesystem::temp_directory_path(error) /
                   ("rule-engine-python-executables-" + std::to_string(nonce));
            REQUIRE_FALSE(error);
            REQUIRE(std::filesystem::create_directory(path, error));
            REQUIRE_FALSE(error);
        }

        TemporaryDirectory(const TemporaryDirectory &) = delete;
        TemporaryDirectory &operator=(const TemporaryDirectory &) = delete;

        ~TemporaryDirectory() {
            std::error_code ignored;
            std::filesystem::remove_all(path, ignored);
        }
    };

    struct ProcessResult {
        int exit_code {};
        std::string standard_output;
        std::string standard_error;
    };

    [[nodiscard]] std::string shell_quote(const std::filesystem::path &path) {
        auto value = path.string();
        std::string result {'"'};
        for (const auto character : value) {
            if (character == '"') {
                result += "\\\"";
            } else {
                result.push_back(character);
            }
        }
        result.push_back('"');
        return result;
    }

    [[nodiscard]] std::string read_file(const std::filesystem::path &path) {
        std::ifstream input {path, std::ios::binary};
        return {std::istreambuf_iterator<char> {input}, std::istreambuf_iterator<char> {}};
    }

    [[nodiscard]] ProcessResult run_process(const std::filesystem::path &executable, const std::string_view arguments,
                                            const TemporaryDirectory &temporary, const std::string_view name) {
        const auto output_path = temporary.path / (std::string {name} + ".stdout");
        const auto error_path = temporary.path / (std::string {name} + ".stderr");
        const auto invocation = shell_quote(executable) + ' ' + std::string {arguments} + " 1>" +
                                shell_quote(output_path) + " 2>" + shell_quote(error_path);
#if defined(_WIN32)
        // system() delegates to cmd.exe, whose leading-quoted-command grammar
        // otherwise strips the executable's closing quote.
        const auto command = "call " + invocation;
#else
        const auto &command = invocation;
#endif
        const auto raw_exit_code = std::system(command.c_str());
#if defined(_WIN32)
        const auto exit_code = raw_exit_code;
#else
        const auto exit_code = WIFEXITED(raw_exit_code) ? WEXITSTATUS(raw_exit_code) : -1;
#endif
        return {
            .exit_code = exit_code,
            .standard_output = read_file(output_path),
            .standard_error = read_file(error_path),
        };
    }

    void write_file(const std::filesystem::path &path, const std::string_view text) {
        std::ofstream output {path, std::ios::binary};
        REQUIRE(output.good());
        output.write(text.data(), static_cast<std::streamsize>(text.size()));
        REQUIRE(output.good());
    }

    [[nodiscard]] std::string development_config(const TemporaryDirectory &temporary) {
        const auto database = (temporary.path / "runtime.sqlite").generic_string();
        return "schema.version = 1\n"
               "deployment.mode = \"single_node_dev\"\n"
               "node.id = \"node-dev\"\n"
               "node.platform_abi = \"windows-x86_64-clang\"\n"
               "node.lease_duration_ms = 30000\n"
               "node.lease_renew_interval_ms = 10000\n"
               "store.backend = \"sqlite_dev\"\n"
               "store.server_processes = 1\n"
               "store.sqlite_path = \"" +
               database +
               "\"\n"
               "store.busy_timeout_ms = 5000\n"
               "listener.agent_endpoint = \"127.0.0.1:9443\"\n"
               "listener.admin_endpoint = \"127.0.0.1:9444\"\n"
               "listener.accept_timeout_ms = 1000\n"
               "listener.handshake_timeout_ms = 5000\n"
               "listener.read_timeout_ms = 30000\n"
               "listener.write_timeout_ms = 30000\n"
               "listener.backlog = 128\n"
               "listener.maximum_consecutive_failures = 16\n"
               "service.worker_threads = 4\n"
               "service.maximum_queued_sessions = 128\n"
               "service.maximum_memory_bytes = 134217728\n"
               "service.maximum_frame_bytes = 4194304\n"
               "service.maximum_messages_per_session = 4096\n"
               "service.maximum_inflight_work_per_session = 64\n"
               "service.maximum_session_duration_ms = 30000\n"
               "service.inbound_credit_bytes = 16777216\n"
               "service.inbound_credit_messages = 256\n"
               "service.inbound_credit_work_attempts = 64\n"
               "service.inbound_credit_snapshot_chunks = 64\n"
               "network.require_hard_resolver_bounds = true\n"
               "runtime.root = \"missing-runtime\"\n"
               "pack.registry_path = \"missing-registry\"\n"
               "bindings.operator_path = \"missing-bindings.json\"\n"
               "schemas.catalog_path = \"missing-schemas.json\"\n"
               "profiles.budget_path = \"missing-budget.json\"\n"
               "profiles.retention_path = \"missing-retention.json\"\n"
               "observability.prometheus_endpoint = \"127.0.0.1:9464\"\n"
               "observability.json_log_path = \"server.jsonl\"\n"
               "observability.audit_path = \"audit.jsonl\"\n"
               "development.allow_unsigned_packs = true\n"
               "development.allow_loopback_plaintext = true\n"
               "development.allow_empty_activation = true\n";
    }

    [[nodiscard]] std::string production_config() {
        return "schema.version = 1\n"
               "deployment.mode = \"production_cluster\"\n"
               "node.id = \"node-production\"\n"
               "node.platform_abi = \"windows-x86_64-clang\"\n"
               "node.lease_duration_ms = 30000\n"
               "node.lease_renew_interval_ms = 10000\n"
               "store.backend = \"postgresql17\"\n"
               "store.connection_reference = \"env:RULE_ENGINE_SERVER_TEST_DSN\"\n"
               "store.server_major = 17\n"
               "store.server_processes = 2\n"
               "store.pool_size = 16\n"
               "store.statement_timeout_ms = 5000\n"
               "store.verify_tls_peer = true\n"
               "store.external_ha_configured = true\n"
               "listener.agent_endpoint = \"0.0.0.0:9443\"\n"
               "listener.admin_endpoint = \"127.0.0.1:9444\"\n"
               "listener.accept_timeout_ms = 1000\n"
               "listener.handshake_timeout_ms = 5000\n"
               "listener.read_timeout_ms = 30000\n"
               "listener.write_timeout_ms = 30000\n"
               "listener.backlog = 128\n"
               "listener.maximum_consecutive_failures = 16\n"
               "service.worker_threads = 4\n"
               "service.maximum_queued_sessions = 128\n"
               "service.maximum_memory_bytes = 134217728\n"
               "service.maximum_frame_bytes = 4194304\n"
               "service.maximum_messages_per_session = 4096\n"
               "service.maximum_inflight_work_per_session = 64\n"
               "service.maximum_session_duration_ms = 30000\n"
               "service.inbound_credit_bytes = 16777216\n"
               "service.inbound_credit_messages = 256\n"
               "service.inbound_credit_work_attempts = 64\n"
               "service.inbound_credit_snapshot_chunks = 64\n"
               "network.require_hard_resolver_bounds = true\n"
               "tls.trust_anchors_pem = \"missing-ca.pem\"\n"
               "tls.certificate_chain_pem = \"missing-server.pem\"\n"
               "tls.private_key_pem = \"missing-server-key.pem\"\n"
               "tls.crl_pem = \"missing-crl.pem\"\n"
               "tls.require_crl = true\n"
               "runtime.root = \"missing-runtime\"\n"
               "pack.registry_path = \"missing-registry\"\n"
               "trust.trusted_signers_path = \"missing-signers.json\"\n"
               "trust.revocations_path = \"missing-revocations.json\"\n"
               "trust.peer_enrollment_path = \"missing-peers.json\"\n"
               "bindings.operator_path = \"missing-bindings.json\"\n"
               "schemas.catalog_path = \"missing-schemas.json\"\n"
               "profiles.budget_path = \"missing-budget.json\"\n"
               "profiles.retention_path = \"missing-retention.json\"\n"
               "profiles.trace_path = \"missing-trace.json\"\n"
               "profiles.capture_path = \"missing-capture.json\"\n"
               "profiles.service_path = \"missing-service.json\"\n"
               "profiles.sink_path = \"missing-sink.json\"\n"
               "observability.prometheus_endpoint = \"127.0.0.1:9464\"\n"
               "observability.json_log_path = \"server.jsonl\"\n"
               "observability.audit_path = \"audit.jsonl\"\n";
    }

    void replace_once(std::string &text, const std::string_view before, const std::string_view after) {
        const auto position = text.find(before);
        REQUIRE(position != std::string::npos);
        text.replace(position, before.size(), after);
    }

} // namespace

TEST_CASE("server executable accepts only its bounded command surface") {
    TemporaryDirectory temporary;
    const std::filesystem::path server {RULE_ENGINE_PYTHON_SERVER_PATH};
    REQUIRE_FALSE(server.empty());

    const auto help = run_process(server, "--help", temporary, "help");
    CHECK(help.exit_code == 0);
    CHECK(help.standard_output.find("Usage: rule_engine_server --config PATH") != std::string::npos);
    CHECK(help.standard_error.empty());

    const auto rejected = run_process(server, "--host 127.0.0.1", temporary, "rejected");
    CHECK(rejected.exit_code == 2);
    CHECK(rejected.standard_output.empty());
    CHECK(rejected.standard_error.find("SRV-CLI-USAGE") != std::string::npos);
    CHECK(rejected.standard_error.find("127.0.0.1") == std::string::npos);

    const auto equals_form = run_process(server, "--config=server.toml --validate-config", temporary, "equals-form");
    CHECK(equals_form.exit_code == 2);
    CHECK(equals_form.standard_error.find("unknown option") != std::string::npos);
}

TEST_CASE("resident backend seam remains injectable and stop-aware") {
    using namespace rule_engine::python;
    using namespace rule_engine::python::tools;

    struct EmptyActivationStore final: cluster::IActivationControlStore {
        [[nodiscard]] std::expected<cluster::DurableControlState, StoreError> load_state() const override {
            return cluster::DurableControlState {};
        }
        [[nodiscard]] std::expected<std::optional<cluster::AdminOperationRecord>, StoreError>
        find_operation(std::string_view) const override {
            return std::optional<cluster::AdminOperationRecord> {};
        }
        [[nodiscard]] std::expected<std::optional<cluster::AdminOperationRecord>, StoreError>
        find_operation_by_idempotency(std::string_view) const override {
            return std::optional<cluster::AdminOperationRecord> {};
        }
        [[nodiscard]] std::expected<void, StoreError> commit(const cluster::ControlPlaneCommit &) override {
            return {};
        }
        [[nodiscard]] std::expected<cluster::ControlPlaneInspection, StoreError> inspect() const override {
            return cluster::ControlPlaneInspection {};
        }
        [[nodiscard]] cluster::RuntimeStoreHealth health() const override {
            return {.backend = cluster::StoreBackendKind::in_memory_reference,
                    .driver_available = true,
                    .connected = true,
                    .migrations_compatible = true,
                    .schema_version = 1U,
                    .server_version = "test",
                    .detail = {}};
        }
    };

    struct InjectedFailureBackend final: ResidentServerBackend {
        bool stopped {};

        [[nodiscard]] std::expected<void, ToolFailure>
        qualify_activation(const ResidentServerContext &) noexcept override {
            return std::unexpected(ToolFailure {.kind = ToolFailureKind::unavailable_dependency,
                                                .code = "TEST-ACTIVATION",
                                                .message = "injected activation failure",
                                                .diagnostics = {}});
        }
        [[nodiscard]] std::expected<void, ToolFailure> serve(const ResidentServerContext &) noexcept override {
            return std::unexpected(ToolFailure {.kind = ToolFailureKind::unavailable_transport,
                                                .code = "TEST-NETWORK",
                                                .message = "injected network failure",
                                                .diagnostics = {}});
        }
        void request_stop() noexcept override { stopped = true; }
    };

    cluster::AuditTrail audit;
    cluster::InMemoryRuntimeStore store {audit};
    EmptyActivationStore activation_store;
    const ServerConfig config;
    const packaging::PrivatePythonRuntime runtime;
    const cluster::StoreBackendCapabilities capabilities {
        .kind = cluster::StoreBackendKind::in_memory_reference,
        .implementation_available = true,
        .production_allowed = false,
        .active_active = false,
        .multi_process = false,
        .atomic_event_transaction = true,
        .row_fences = true,
        .outbox_leases = true,
        .database_time_leases = false,
        .required_driver = {},
        .limitation = {},
    };
    const packaging::TrustPolicy pack_trust {
        .mode = packaging::TrustMode::development,
        .allow_unsigned_packs = true,
        .allow_unsigned_generators = false,
        .signers = {},
    };
    const protocol_v2::OperatorTrustPolicy peer_trust;
    const ResidentServerContext context {
        .config = config,
        .store = store,
        .activation_store = activation_store,
        .store_capabilities = capabilities,
        .runtime = runtime,
        .pack_trust_policy = pack_trust,
        .peer_trust_policy = peer_trust,
        .agent_tls = nullptr,
        .admin_tls = nullptr,
    };
    InjectedFailureBackend backend;

    const auto activation = backend.qualify_activation(context);
    REQUIRE_FALSE(activation.has_value());
    CHECK(activation.error().code == "TEST-ACTIVATION");
    CHECK(exit_code_for(activation.error()) == ExitCode::unavailable);

    const auto network = backend.serve(context);
    REQUIRE_FALSE(network.has_value());
    CHECK(network.error().code == "TEST-NETWORK");
    CHECK(exit_code_for(network.error()) == ExitCode::unavailable);
    backend.request_stop();
    CHECK(backend.stopped);
}

TEST_CASE("server configuration parser bounds hostile input and duplicate state") {
    using rule_engine::python::tools::parse_server_config;

    const auto oversized = parse_server_config(std::string((1U << 20U) + 1U, 'x'));
    REQUIRE_FALSE(oversized.has_value());
    CHECK(oversized.error().code == "SRV-CONFIG-SIZE");

    TemporaryDirectory temporary;
    const auto duplicate = parse_server_config(development_config(temporary) + "schema.version = 1\n");
    REQUIRE_FALSE(duplicate.has_value());
    CHECK(duplicate.error().code == "SRV-CONFIG-DUPLICATE-KEY");

    auto excessive_duration = development_config(temporary);
    replace_once(excessive_duration, "node.lease_duration_ms = 30000", "node.lease_duration_ms = 18446744073709551615");
    const auto ranged = parse_server_config(excessive_duration);
    REQUIRE_FALSE(ranged.has_value());
    CHECK(ranged.error().code == "SRV-CONFIG-RANGE");

    const auto mixed_store = parse_server_config(development_config(temporary) + "store.pool_size = 16\n");
    REQUIRE_FALSE(mixed_store.has_value());
    CHECK(mixed_store.error().code == "SRV-CONFIG-INAPPLICABLE-KEY");

    auto named_listener = development_config(temporary);
    replace_once(named_listener, "127.0.0.1:9443", "localhost:9443");
    const auto non_numeric = parse_server_config(named_listener);
    REQUIRE_FALSE(non_numeric.has_value());
    CHECK(non_numeric.error().code == "SRV-CONFIG-NUMERIC-ENDPOINT");

    auto soft_resolver = development_config(temporary);
    replace_once(soft_resolver, "network.require_hard_resolver_bounds = true",
                 "network.require_hard_resolver_bounds = false");
    const auto unbounded = parse_server_config(soft_resolver);
    REQUIRE_FALSE(unbounded.has_value());
    CHECK(unbounded.error().code == "SRV-CONFIG-LISTENER-BOUNDS");

    auto lease_overlap = development_config(temporary);
    replace_once(lease_overlap, "listener.accept_timeout_ms = 1000", "listener.accept_timeout_ms = 25000");
    const auto unsafe_renewal = parse_server_config(lease_overlap);
    REQUIRE_FALSE(unsafe_renewal.has_value());
    CHECK(unsafe_renewal.error().code == "SRV-CONFIG-LISTENER-BOUNDS");

    auto unbounded_service = development_config(temporary);
    replace_once(unbounded_service, "service.maximum_memory_bytes = 134217728",
                 "service.maximum_memory_bytes = 1024");
    const auto unsafe_service = parse_server_config(unbounded_service);
    REQUIRE_FALSE(unsafe_service.has_value());
    CHECK(unsafe_service.error().code == "SRV-CONFIG-SERVICE-BOUNDS");
}

TEST_CASE("server validates explicit configuration and fails closed before resident startup") {
    TemporaryDirectory temporary;
    const std::filesystem::path server {RULE_ENGINE_PYTHON_SERVER_PATH};
    const auto config_path = temporary.path / "server.toml";
    write_file(config_path, development_config(temporary));

    const auto config_argument = "--config " + shell_quote(config_path);
    const auto validated = run_process(server, config_argument + " --validate-config", temporary, "validated");
    CHECK(validated.exit_code == 0);
    CHECK(validated.standard_output.find("configuration valid") != std::string::npos);
    CHECK(validated.standard_output.find("startup qualification: not run") != std::string::npos);
    CHECK(validated.standard_error.empty());

    const auto startup = run_process(server, config_argument, temporary, "startup");
    CHECK(startup.exit_code == 3);
    CHECK(startup.standard_output.empty());
    CHECK(startup.standard_error.find("SRV-LOCAL-REFERENCE-UNAVAILABLE") != std::string::npos);
    CHECK(startup.standard_error.find("listening") == std::string::npos);

    const auto invalid_path = temporary.path / "invalid.toml";
    write_file(invalid_path, development_config(temporary) + "unexpected.key = true\n");
    const auto invalid =
        run_process(server, "--config " + shell_quote(invalid_path) + " --validate-config", temporary, "invalid");
    CHECK(invalid.exit_code == 2);
    CHECK(invalid.standard_error.find("SRV-CONFIG-UNKNOWN-KEY") != std::string::npos);
    CHECK(invalid.standard_error.find("unexpected.key") == std::string::npos);

    auto exposed_text = development_config(temporary);
    replace_once(exposed_text, "127.0.0.1:9443", "0.0.0.0:9443");
    const auto exposed_path = temporary.path / "exposed.toml";
    write_file(exposed_path, exposed_text);
    const auto exposed =
        run_process(server, "--config " + shell_quote(exposed_path) + " --validate-config", temporary, "exposed");
    CHECK(exposed.exit_code == 2);
    CHECK(exposed.standard_error.find("SRV-CONFIG-PLAINTEXT") != std::string::npos);
}

TEST_CASE("production startup qualifies PostgreSQL capability and rejects inline secrets") {
    TemporaryDirectory temporary;
    const std::filesystem::path server {RULE_ENGINE_PYTHON_SERVER_PATH};
    const auto config_path = temporary.path / "production.toml";
    write_file(config_path, production_config());

    const auto config_argument = "--config " + shell_quote(config_path);
    const auto validated = run_process(server, config_argument + " --validate-config", temporary, "production-valid");
    CHECK(validated.exit_code == 0);
    CHECK(validated.standard_output.find("mode: production_cluster") != std::string::npos);
    CHECK(validated.standard_output.find("store: postgresql17") != std::string::npos);

    const auto startup = run_process(server, config_argument, temporary, "production-startup");
    CHECK(startup.exit_code == 3);
#if defined(RULE_ENGINE_HAS_POSTGRESQL)
    CHECK(startup.standard_error.find("SRV-LOCAL-REFERENCE-UNAVAILABLE") != std::string::npos);
#else
    CHECK(startup.standard_error.find("SRV-POSTGRES-DRIVER-UNAVAILABLE") != std::string::npos);
#endif

    auto inline_secret = production_config();
    replace_once(inline_secret, "env:RULE_ENGINE_SERVER_TEST_DSN", "postgresql://inline-secret");
    const auto inline_path = temporary.path / "inline-secret.toml";
    write_file(inline_path, inline_secret);
    const auto rejected =
        run_process(server, "--config " + shell_quote(inline_path) + " --validate-config", temporary, "inline-secret");
    CHECK(rejected.exit_code == 2);
    CHECK(rejected.standard_error.find("SRV-CONFIG-POSTGRES") != std::string::npos);
    CHECK(rejected.standard_error.find("inline-secret") == std::string::npos);
}

TEST_CASE("benchmark executable drives exact VM and validated optimized parity") {
    TemporaryDirectory temporary;
    const std::filesystem::path benchmark {RULE_ENGINE_PYTHON_BENCHMARK_PATH};
    REQUIRE_FALSE(benchmark.empty());

    const auto measured = run_process(benchmark, "--peers 8 --format json", temporary, "measured");
    CHECK(measured.exit_code == 0);
    CHECK(measured.standard_error.empty());
    CHECK(measured.standard_output.find("\"schema\":\"rule-engine.python-benchmark.v2\"") != std::string::npos);
    CHECK(measured.standard_output.find("\"exact_vm_sessions\":8") != std::string::npos);
    CHECK(measured.standard_output.find("\"optimized_vm_sessions\":0") != std::string::npos);
    CHECK(measured.standard_output.find("\"optimizer_certificate_validated\":true") != std::string::npos);
    CHECK(measured.standard_output.find("\"parity_equivalent\":true") != std::string::npos);
    CHECK(measured.standard_output.find("\"parity_mismatches\":0") != std::string::npos);
    CHECK(measured.standard_output.find("\"resident_network_simulated\":false") != std::string::npos);
    CHECK(measured.standard_output.find("\"resident_postgresql_simulated\":false") != std::string::npos);
    CHECK(measured.standard_output.find("\"resident_work_enqueued\":8") != std::string::npos);
    CHECK(measured.standard_output.find("\"resident_work_committed\":8") != std::string::npos);
    CHECK(measured.standard_output.find("\"resident_retry_attempts\":1") != std::string::npos);
    CHECK(measured.standard_output.find("\"resident_stale_fence_rejections\":1") != std::string::npos);
    CHECK(measured.standard_output.find("\"resident_ordering_violations\":0") != std::string::npos);
    CHECK(measured.standard_output.find("\"resident_backpressure_transitions\":8") != std::string::npos);

    const auto rejected = run_process(benchmark, "--format sarif", temporary, "rejected");
    CHECK(rejected.exit_code == 2);
    CHECK(rejected.standard_error.find("BENCH-CLI-USAGE") != std::string::npos);
}

TEST_CASE("benchmark bounds a ten-thousand-peer in-memory resident simulation") {
    const auto measured = rule_engine::python::tools::run_python_benchmark({
        .peers = 10'000U,
        .format = rule_engine::python::tools::OutputFormat::json,
    });

    REQUIRE(measured);
    CHECK(measured->resident_simulation_model == "bounded-in-memory-coordinator-and-agent-spool-v1");
    CHECK_FALSE(measured->resident_network_simulated);
    CHECK_FALSE(measured->resident_postgresql_simulated);
    CHECK(measured->resident_work_enqueued == 10'000U);
    CHECK(measured->resident_work_committed == 10'000U);
    CHECK(measured->resident_retry_attempts == 100U);
    CHECK(measured->resident_stale_fence_rejections == 100U);
    CHECK(measured->resident_ordering_violations == 0U);
    CHECK(measured->resident_claim_batch_limit == 512U);
    CHECK(measured->resident_peak_claim_batch > 0U);
    CHECK(measured->resident_peak_claim_batch <= measured->resident_claim_batch_limit);
    CHECK(measured->resident_peak_active_leases <= measured->resident_claim_batch_limit);
    CHECK(measured->resident_final_ready_work == 0U);
    CHECK(measured->resident_final_active_leases == 0U);
    CHECK(measured->resident_backpressure_transitions == 10'000U);
    CHECK(measured->resident_backpressure_clears == 10'000U);
    CHECK(measured->resident_peak_agent_sessions == 1U);
    CHECK(measured->resident_peak_pending_records == 2U);
    CHECK(measured->resident_peak_pending_bytes == 160U);
}

namespace {

    namespace py = rule_engine::python;
    namespace proto = rule_engine::python::protocol_v2;
    namespace tools = rule_engine::python::tools;

    [[nodiscard]] proto::ProtocolError timeout_error() {
        return {.code = proto::ProtocolErrorCode::timed_out, .message = "fake channel empty"};
    }

    struct FakeChannelState {
        std::mutex mutex;
        std::deque<std::vector<std::byte>> protocol_input;
        std::deque<std::vector<std::byte>> application_input;
        std::vector<std::vector<std::byte>> protocol_output;
        std::vector<std::vector<std::byte>> application_output;
        std::atomic<bool> shutdown {};
    };

    struct FakeByteChannel final: tools::IResidentSecureChannel {
        explicit FakeByteChannel(std::shared_ptr<FakeChannelState> state): state_ {std::move(state)} {}

        [[nodiscard]] std::expected<proto::PeerEnvelope, proto::ProtocolError>
        receive_protocol(std::chrono::steady_clock::time_point, std::stop_token cancellation) noexcept override {
            if (cancellation.stop_requested()) {
                return std::unexpected(proto::ProtocolError {.code = proto::ProtocolErrorCode::canceled,
                                                             .message = "fake channel canceled"});
            }
            std::vector<std::byte> frame;
            {
                std::scoped_lock lock {state_->mutex};
                if (state_->protocol_input.empty()) {
                    return std::unexpected(timeout_error());
                }
                frame = std::move(state_->protocol_input.front());
                state_->protocol_input.pop_front();
            }
            auto decoded = proto::decode_frame(frame);
            if (!decoded) {
                return std::unexpected(std::move(decoded.error()));
            }
            return std::move(decoded->envelope);
        }

        [[nodiscard]] std::expected<void, proto::ProtocolError>
        send_protocol(const proto::PeerEnvelope &envelope, std::chrono::steady_clock::time_point,
                      std::stop_token cancellation) noexcept override {
            if (cancellation.stop_requested()) {
                return std::unexpected(proto::ProtocolError {.code = proto::ProtocolErrorCode::canceled,
                                                             .message = "fake channel canceled"});
            }
            auto encoded = proto::encode_frame(envelope);
            if (!encoded) {
                return std::unexpected(std::move(encoded.error()));
            }
            std::scoped_lock lock {state_->mutex};
            state_->protocol_output.push_back(std::move(*encoded));
            return {};
        }

        [[nodiscard]] std::expected<std::vector<std::byte>, proto::ProtocolError>
        receive_application_frame(std::chrono::steady_clock::time_point,
                                  std::stop_token cancellation) noexcept override {
            if (cancellation.stop_requested()) {
                return std::unexpected(proto::ProtocolError {.code = proto::ProtocolErrorCode::canceled,
                                                             .message = "fake channel canceled"});
            }
            std::scoped_lock lock {state_->mutex};
            if (state_->application_input.empty()) {
                return std::unexpected(timeout_error());
            }
            auto payload = std::move(state_->application_input.front());
            state_->application_input.pop_front();
            return payload;
        }

        [[nodiscard]] std::expected<void, proto::ProtocolError>
        send_application_frame(const std::span<const std::byte> payload, std::chrono::steady_clock::time_point,
                               std::stop_token cancellation) noexcept override {
            if (cancellation.stop_requested()) {
                return std::unexpected(proto::ProtocolError {.code = proto::ProtocolErrorCode::canceled,
                                                             .message = "fake channel canceled"});
            }
            std::scoped_lock lock {state_->mutex};
            state_->application_output.emplace_back(payload.begin(), payload.end());
            return {};
        }

        void shutdown() noexcept override { state_->shutdown = true; }

    private:
        std::shared_ptr<FakeChannelState> state_;
    };

    struct AllowTrust final: proto::ITrustPolicy {
        [[nodiscard]] std::expected<proto::AuthenticatedPeer, proto::ProtocolError>
        authenticate(const proto::TlsPeerIdentity &) const noexcept override {
            return proto::AuthenticatedPeer {.tenant = py::TenantId {"tenant:test"},
                                             .peer = py::PeerId {"peer:test"}};
        }
    };

    [[nodiscard]] py::SubjectKey service_subject() {
        return {.peer = py::PeerId {"peer:test"},
                .descriptor = py::SchemaId {"windows.process.v1"},
                .identity = {{.field_id = 1U, .value = std::uint64_t {42U}}},
                .parent = nullptr};
    }

    constexpr std::string_view service_schema_hash = "sha256:test-schema";

    [[nodiscard]] proto::WorkLeaseMessage service_work() {
        return {.session = {},
                .peer = {},
                .session_fence = 0U,
                .work_id = "work:test",
                .attempt_id = "attempt:test",
                .work_fence = 7U,
                .generation = 3U,
                .server_sequence = 0U,
                .route = "windows",
                .facts = {{.request_id = py::RequestId {"fact:test"},
                           .subject = service_subject(),
                           .route = {.provider = "windows", .fact = "process.image-path"},
                           .expected_schema = py::SchemaId {"schema:string"},
                           .expected_schema_hash = std::string {service_schema_hash},
                           .deadline_unix_ms = 100'000U}},
                .scans = {}};
    }

    struct DurableFakeAgentBackend final: tools::IResidentAgentBackend {
        std::uint64_t fence {9U};
        std::size_t persists {};
        std::size_t closes {};

        [[nodiscard]] std::expected<tools::ResidentAgentSession, proto::ProtocolError>
        establish(const proto::AuthenticatedPeer &peer, const proto::AgentHelloMessage &hello,
                  std::stop_token) noexcept override {
            return tools::ResidentAgentSession {.authenticated_peer = peer,
                                                .session = py::SessionId {"session:test"},
                                                .session_fence = fence,
                                                .agent_epoch = hello.agent_epoch,
                                                .acknowledged_through = 0U,
                                                .credit = {.bytes = 64U * py::kibibyte,
                                                           .messages = 8U,
                                                           .work_attempts = 1U,
                                                           .snapshot_chunks = 1U}};
        }

        [[nodiscard]] std::expected<std::vector<proto::WorkLeaseMessage>, proto::ProtocolError>
        take_work(const tools::ResidentAgentSession &, std::size_t, std::stop_token) noexcept override {
            return std::vector<proto::WorkLeaseMessage> {service_work()};
        }

        [[nodiscard]] std::expected<tools::DurableAgentReceipt, proto::ProtocolError>
        persist(const tools::ResidentAgentSession &, const std::uint64_t sequence,
                const proto::DurableAgentBody &, std::stop_token) noexcept override {
            ++persists;
            return tools::DurableAgentReceipt {
                .acknowledged_through = sequence,
                .credit = {.bytes = 64U * py::kibibyte,
                           .messages = 8U,
                           .work_attempts = 1U,
                           .snapshot_chunks = 1U},
            };
        }

        void close(const tools::ResidentAgentSession &) noexcept override { ++closes; }
    };

    struct RejectAdmin final: tools::IResidentAdminBackend {
        [[nodiscard]] tools::ResidentAdminResponse execute(const proto::AuthenticatedPeer &,
                                                           const tools::ResidentAdminRequest &request) noexcept override {
            return {.status = tools::ResidentAdminResponseStatus::rejected,
                    .request_id = request.request_id,
                    .code = "TEST-REJECTED",
                    .diagnostic = "test",
                    .storage_revision = 0U,
                    .resource_version = 0U,
                    .active_generation = std::nullopt,
                    .previous_active_generation = std::nullopt};
        }
    };

    [[nodiscard]] tools::ResidentServiceLimits test_service_limits() {
        return {.worker_threads = 1U,
                .maximum_queued_sessions = 1U,
                .maximum_memory_bytes = 1U * py::mebibyte,
                .maximum_frame_bytes = 4U * py::kibibyte,
                .maximum_messages_per_session = 8U,
                .maximum_inflight_work_per_session = 1U,
                .maximum_session_duration = std::chrono::milliseconds {500},
                .inbound_credit = {.bytes = 64U * py::kibibyte,
                                   .messages = 8U,
                                   .work_attempts = 1U,
                                   .snapshot_chunks = 1U}};
    }

    [[nodiscard]] proto::PeerEnvelope agent_hello_envelope() {
        const proto::AgentHelloMessage hello {.minimum_minor = proto::initial_minor_version,
                                              .maximum_minor = proto::initial_minor_version,
                                              .agent_version = "test",
                                              .agent_epoch = "epoch:test",
                                              .next_sequence = 1U,
                                              .schemas = {},
                                              .capabilities = {},
                                              .receive_limit = {.bytes = 1U << 20U,
                                                                .messages = 8U,
                                                                .work_attempts = 1U,
                                                                .snapshot_chunks = 1U}};
        return {.protocol_major = proto::major_version,
                .protocol_minor = proto::initial_minor_version,
                .message_id = "agent:hello",
                .session = std::nullopt,
                .agent_epoch = hello.agent_epoch,
                .agent_sequence = 0U,
                .acknowledged_agent_sequence = 0U,
                .body = hello};
    }

    [[nodiscard]] proto::PeerEnvelope agent_result_envelope(
        const std::uint64_t inner_fence = 9U,
        const std::string_view returned_schema_hash = service_schema_hash) {
        const proto::WorkResultMessage result {
            .originating_session = py::SessionId {"session:test"},
            .peer = py::PeerId {"peer:test"},
            .originating_session_fence = inner_fence,
            .work_id = "work:test",
            .attempt_id = "attempt:test",
            .work_fence = 7U,
            .generation = 3U,
            .facts = {{.request_id = py::RequestId {"fact:test"},
                       .subject = service_subject(),
                       .status = py::FactTerminalStatus::value,
                       .value = py::make_fact(py::UnicodeValue {.utf8 = "C:/test.exe"}),
                       .returned_schema = py::SchemaIdentity {
                           .id = py::SchemaId {"schema:string"},
                           .canonical_hash = std::string {returned_schema_hash},
                       },
                       .diagnostic = std::nullopt}},
            .scans = {},
        };
        return {.message_id = "agent:result",
                .session = py::SessionId {"session:test"},
                .agent_epoch = "epoch:test",
                .agent_sequence = 1U,
                .body = result};
    }

    void enqueue_protocol(const std::shared_ptr<FakeChannelState> &state, const proto::PeerEnvelope &envelope) {
        auto encoded = proto::encode_frame(envelope);
        REQUIRE(encoded);
        state->protocol_input.push_back(std::move(*encoded));
    }

    struct CountingControlStore final: py::cluster::IActivationControlStore {
        mutable std::size_t reads {};
        std::size_t commits {};

        [[nodiscard]] std::expected<py::cluster::DurableControlState, py::StoreError> load_state() const override {
            ++reads;
            return py::cluster::DurableControlState {};
        }
        [[nodiscard]] std::expected<std::optional<py::cluster::AdminOperationRecord>, py::StoreError>
        find_operation(std::string_view) const override {
            ++reads;
            return std::optional<py::cluster::AdminOperationRecord> {};
        }
        [[nodiscard]] std::expected<std::optional<py::cluster::AdminOperationRecord>, py::StoreError>
        find_operation_by_idempotency(std::string_view) const override {
            ++reads;
            return std::optional<py::cluster::AdminOperationRecord> {};
        }
        [[nodiscard]] std::expected<void, py::StoreError>
        commit(const py::cluster::ControlPlaneCommit &) override {
            ++commits;
            return {};
        }
        [[nodiscard]] std::expected<py::cluster::ControlPlaneInspection, py::StoreError> inspect() const override {
            ++reads;
            return py::cluster::ControlPlaneInspection {};
        }
        [[nodiscard]] py::cluster::RuntimeStoreHealth health() const override { return {}; }
    };

    struct DenyAdminPolicy final: tools::IResidentAdminAccessPolicy {
        [[nodiscard]] std::expected<py::cluster::AuthenticatedAdminPrincipal, py::cluster::AuthorizedAdminError>
        principal_for(const proto::AuthenticatedPeer &) const noexcept override {
            return py::cluster::AuthenticatedAdminPrincipal {.principal_id = "principal:test",
                                                             .home_tenant = py::TenantId {"tenant:test"},
                                                             .kind = py::cluster::AdminPrincipalKind::administrator,
                                                             .authentication_id = "cert:test"};
        }

        [[nodiscard]] std::expected<py::cluster::AdminAuthorizationDecision, py::cluster::AdminAuthorizerFailure>
        authorize(const py::cluster::AuthenticatedAdminPrincipal &,
                  const py::cluster::AdminAuthorizationRequest &) const override {
            return py::cluster::AdminAuthorizationDecision {.outcome = py::cluster::AdminAuthorizationOutcome::denied,
                                                            .decision_id = "test-deny",
                                                            .detail = "denied"};
        }
    };

    struct BlockingHandler final: tools::IResidentSessionHandler {
        std::atomic<std::size_t> entered {};
        void run(tools::ResidentSessionJob job, const std::stop_token cancellation) noexcept override {
            ++entered;
            while (!cancellation.stop_requested()) {
                std::this_thread::yield();
            }
            if (job.channel) {
                job.channel->shutdown();
            }
        }
    };

} // namespace

TEST_CASE("resident agent service consumes framed bytes and ACKs only a durable facts-only result") {
    AllowTrust trust;
    DurableFakeAgentBackend agents;
    RejectAdmin admin;
    tools::ResidentApplicationService service {test_service_limits(), trust, agents, admin};
    auto state = std::make_shared<FakeChannelState>();
    enqueue_protocol(state, agent_hello_envelope());
    enqueue_protocol(state, agent_result_envelope());

    service.run({.role = tools::ResidentSessionRole::agent,
                 .peer = {.tenant = py::TenantId {"tenant:test"}, .peer = py::PeerId {"peer:test"}},
                 .channel = std::make_unique<FakeByteChannel>(state)},
                {});

    REQUIRE(state->protocol_output.size() == 3U);
    const auto hello = proto::decode_frame(state->protocol_output[0]);
    const auto work = proto::decode_frame(state->protocol_output[1]);
    const auto ack = proto::decode_frame(state->protocol_output[2]);
    REQUIRE(hello);
    REQUIRE(work);
    REQUIRE(ack);
    CHECK(std::holds_alternative<proto::ServerHelloMessage>(hello->envelope.body));
    REQUIRE(std::holds_alternative<proto::WorkLeaseMessage>(work->envelope.body));
    const auto &lease = std::get<proto::WorkLeaseMessage>(work->envelope.body);
    CHECK(lease.facts.size() == 1U);
    CHECK(lease.scans.empty());
    REQUIRE(std::holds_alternative<proto::AckMessage>(ack->envelope.body));
    CHECK(std::get<proto::AckMessage>(ack->envelope.body).acknowledged_through == 1U);
    CHECK(agents.persists == 1U);
    CHECK(agents.closes == 1U);
    CHECK(state->shutdown);
}

TEST_CASE("resident agent service rejects a stale inner fence without persistence or ACK") {
    AllowTrust trust;
    DurableFakeAgentBackend agents;
    RejectAdmin admin;
    tools::ResidentApplicationService service {test_service_limits(), trust, agents, admin};
    auto state = std::make_shared<FakeChannelState>();
    enqueue_protocol(state, agent_hello_envelope());
    enqueue_protocol(state, agent_result_envelope(8U));

    service.run({.role = tools::ResidentSessionRole::agent,
                 .peer = {.tenant = py::TenantId {"tenant:test"}, .peer = py::PeerId {"peer:test"}},
                 .channel = std::make_unique<FakeByteChannel>(state)},
                {});

    CHECK(agents.persists == 0U);
    REQUIRE(state->protocol_output.size() == 3U);
    const auto nack = proto::decode_frame(state->protocol_output.back());
    REQUIRE(nack);
    REQUIRE(std::holds_alternative<proto::NackMessage>(nack->envelope.body));
    CHECK(std::get<proto::NackMessage>(nack->envelope.body).reason == proto::ProtocolErrorCode::stale_fence);
    CHECK_FALSE(std::get<proto::NackMessage>(nack->envelope.body).permanent);
}

TEST_CASE("resident agent service rejects a mismatched fact schema before persistence or ACK") {
    AllowTrust trust;
    DurableFakeAgentBackend agents;
    RejectAdmin admin;
    tools::ResidentApplicationService service {test_service_limits(), trust, agents, admin};
    auto state = std::make_shared<FakeChannelState>();
    enqueue_protocol(state, agent_hello_envelope());
    enqueue_protocol(state, agent_result_envelope(9U, "sha256:wrong-schema"));

    service.run({.role = tools::ResidentSessionRole::agent,
                 .peer = {.tenant = py::TenantId {"tenant:test"}, .peer = py::PeerId {"peer:test"}},
                 .channel = std::make_unique<FakeByteChannel>(state)},
                {});

    CHECK(agents.persists == 0U);
    REQUIRE(state->protocol_output.size() == 3U);
    const auto nack = proto::decode_frame(state->protocol_output.back());
    REQUIRE(nack);
    REQUIRE(std::holds_alternative<proto::NackMessage>(nack->envelope.body));
    CHECK(std::get<proto::NackMessage>(nack->envelope.body).reason ==
          proto::ProtocolErrorCode::provider_violation);
    CHECK_FALSE(std::holds_alternative<proto::AckMessage>(nack->envelope.body));
}

TEST_CASE("resident application codecs reject malformed frames and deny admin mutation before store access") {
    const std::array malformed {std::byte {1}, std::byte {3}, std::byte {0}};
    const auto rejected = tools::decode_resident_admin_request(malformed, 4U * py::kibibyte);
    REQUIRE_FALSE(rejected);
    CHECK(rejected.error().code == proto::ProtocolErrorCode::malformed);

    CountingControlStore store;
    DenyAdminPolicy policy;
    tools::AuthorizedResidentAdminBackend backend {store, policy};
    const tools::ResidentAdminRequest request {.kind = tools::ResidentAdminRequestKind::activation_flip,
                                               .request_id = "request:test",
                                               .tenant = py::TenantId {"tenant:test"},
                                               .pack = py::PackId {"pack:test"},
                                               .operation_id = "operation:test",
                                               .idempotency_key = "idempotency:test",
                                               .expected_pack_version = 1U,
                                               .at_unix_ms = 10U};
    auto bytes = tools::encode_resident_admin_request(request, 4U * py::kibibyte);
    REQUIRE(bytes);
    auto decoded = tools::decode_resident_admin_request(*bytes, 4U * py::kibibyte);
    REQUIRE(decoded);
    const auto admin_peer = proto::AuthenticatedPeer {.tenant = py::TenantId {"tenant:test"},
                                                      .peer = py::PeerId {"peer:admin"}};
    const auto response = backend.execute(admin_peer, *decoded);
    CHECK(response.status == tools::ResidentAdminResponseStatus::rejected);
    CHECK(response.code == "ADMIN-UNAUTHORIZED");
    CHECK(store.reads == 0U);
    CHECK(store.commits == 0U);

    AllowTrust trust;
    DurableFakeAgentBackend agents;
    tools::ResidentApplicationService service {test_service_limits(), trust, agents, backend};
    auto channel = std::make_shared<FakeChannelState>();
    channel->application_input.push_back(std::move(*bytes));
    service.run({.role = tools::ResidentSessionRole::administrator,
                 .peer = admin_peer,
                 .channel = std::make_unique<FakeByteChannel>(channel)},
                {});
    REQUIRE(channel->application_output.size() == 1U);
    const auto wire_response =
        tools::decode_resident_admin_response(channel->application_output.front(), 4U * py::kibibyte);
    REQUIRE(wire_response);
    CHECK(wire_response->status == tools::ResidentAdminResponseStatus::rejected);
    CHECK(store.reads == 0U);
    CHECK(store.commits == 0U);
}

TEST_CASE("resident scheduler rejects overload and joins owned workers on shutdown") {
    auto limits = test_service_limits();
    BlockingHandler handler;
    auto scheduler = tools::ResidentServiceScheduler::create(limits, handler);
    REQUIRE(scheduler);

    auto first = std::make_shared<FakeChannelState>();
    auto second = std::make_shared<FakeChannelState>();
    auto third = std::make_shared<FakeChannelState>();
    CHECK((*scheduler)->submit({.role = tools::ResidentSessionRole::agent,
                                .peer = {},
                                .channel = std::make_unique<FakeByteChannel>(first)}) ==
          tools::ResidentAdmission::accepted);
    for (std::size_t attempt = 0U; attempt < 10'000U && handler.entered.load() == 0U; ++attempt) {
        std::this_thread::yield();
    }
    REQUIRE(handler.entered.load() == 1U);
    CHECK((*scheduler)->submit({.role = tools::ResidentSessionRole::agent,
                                .peer = {},
                                .channel = std::make_unique<FakeByteChannel>(second)}) ==
          tools::ResidentAdmission::accepted);
    CHECK((*scheduler)->submit({.role = tools::ResidentSessionRole::agent,
                                .peer = {},
                                .channel = std::make_unique<FakeByteChannel>(third)}) ==
          tools::ResidentAdmission::overloaded);
    CHECK(third->shutdown);

    (*scheduler)->request_stop();
    (*scheduler)->join();
    const auto snapshot = (*scheduler)->snapshot();
    CHECK(snapshot.stopping);
    CHECK(snapshot.queued_sessions == 0U);
    CHECK(snapshot.active_sessions == 0U);
    CHECK(snapshot.rejected_sessions == 2U);
    CHECK(first->shutdown);
    CHECK(second->shutdown);
}
