#include <catch2/catch_test_macros.hpp>

#include "rule_engine/python/packaging/source_pack.hpp"
#include "rule_engine/python/protocol/codec.hpp"
#include "rule_engine/python/tools/admin_client.hpp"
#include "rule_engine/python/tools/benchmark.hpp"
#include "rule_engine/python/tools/pack_upload.hpp"
#include "rule_engine/python/tools/server.hpp"

#ifndef RULE_ENGINE_PYTHON_SERVER_PATH
#define RULE_ENGINE_PYTHON_SERVER_PATH ""
#endif

#ifndef RULE_ENGINE_PYTHON_BENCHMARK_PATH
#define RULE_ENGINE_PYTHON_BENCHMARK_PATH ""
#endif

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <deque>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <memory>
#include <mutex>
#include <ranges>
#include <string>
#include <string_view>
#include <thread>
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
        [[nodiscard]] std::expected<void, StoreError> upsert_node(const cluster::DurableResidentNode &) override {
            return {};
        }
        [[nodiscard]] std::expected<std::vector<cluster::DurableResidentNode>, StoreError>
        node_snapshot() const override {
            return std::vector<cluster::DurableResidentNode> {};
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

    auto slow_handshake = development_config(temporary);
    replace_once(slow_handshake, "listener.handshake_timeout_ms = 5000", "listener.handshake_timeout_ms = 19000");
    const auto unsafe_handshake = parse_server_config(slow_handshake);
    REQUIRE_FALSE(unsafe_handshake.has_value());
    CHECK(unsafe_handshake.error().code == "SRV-CONFIG-LISTENER-BOUNDS");

    auto overflowing_window = development_config(temporary);
    replace_once(overflowing_window, "node.lease_duration_ms = 30000", "node.lease_duration_ms = 9223372036854775807");
    replace_once(overflowing_window, "node.lease_renew_interval_ms = 10000",
                 "node.lease_renew_interval_ms = 9223372036854775307");
    const auto unsafe_overflow = parse_server_config(overflowing_window);
    REQUIRE_FALSE(unsafe_overflow.has_value());
    CHECK(unsafe_overflow.error().code == "SRV-CONFIG-LISTENER-BOUNDS");

    auto unbounded_service = development_config(temporary);
    replace_once(unbounded_service, "service.maximum_memory_bytes = 134217728", "service.maximum_memory_bytes = 1024");
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
            return proto::AuthenticatedPeer {.tenant = py::TenantId {"tenant:test"}, .peer = py::PeerId {"peer:test"}};
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
        std::size_t take_calls {};
        std::size_t activation_fences {};
        bool return_invalid_session {};

        [[nodiscard]] std::expected<tools::ResidentAgentSession, proto::ProtocolError>
        establish(const proto::AuthenticatedPeer &peer, const proto::AgentHelloMessage &hello,
                  std::stop_token) noexcept override {
            return tools::ResidentAgentSession {
                .authenticated_peer = peer,
                .session = py::SessionId {"session:test"},
                .session_fence = return_invalid_session ? 0U : fence,
                .agent_epoch = hello.agent_epoch,
                .acknowledged_through = 0U,
                .credit = {.bytes = 64U * py::kibibyte, .messages = 8U, .work_attempts = 1U, .snapshot_chunks = 1U},
                .schemas = {},
                .capabilities = {}};
        }

        [[nodiscard]] std::expected<std::vector<proto::WorkLeaseMessage>, proto::ProtocolError>
        take_work(const tools::ResidentAgentSession &, std::size_t, std::stop_token) noexcept override {
            if (take_calls++ != 0U) {
                return std::vector<proto::WorkLeaseMessage> {};
            }
            return std::vector<proto::WorkLeaseMessage> {service_work()};
        }

        [[nodiscard]] std::expected<tools::DurableAgentReceipt, proto::ProtocolError>
        persist(const tools::ResidentAgentSession &, const std::uint64_t sequence, const proto::DurableAgentBody &,
                std::stop_token) noexcept override {
            ++persists;
            return tools::DurableAgentReceipt {
                .acknowledged_through = sequence,
                .credit = {.bytes = 64U * py::kibibyte, .messages = 8U, .work_attempts = 1U, .snapshot_chunks = 1U},
            };
        }

        void close(const tools::ResidentAgentSession &) noexcept override { ++closes; }
        void fence_activation() noexcept override { ++activation_fences; }
    };

    struct RejectAdmin final: tools::IResidentAdminBackend {
        [[nodiscard]] tools::ResidentAdminResponse
        execute(const proto::AuthenticatedPeer &, const tools::ResidentAdminRequest &request) noexcept override {
            return {.status = tools::ResidentAdminResponseStatus::rejected,
                    .request_id = request.request_id,
                    .code = "TEST-REJECTED",
                    .diagnostic = "test",
                    .storage_revision = 0U,
                    .resource_version = 0U,
                    .active_generation = std::nullopt,
                    .previous_active_generation = std::nullopt,
                    .source_digest = std::nullopt};
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
                .inbound_credit = {
                    .bytes = 64U * py::kibibyte, .messages = 8U, .work_attempts = 1U, .snapshot_chunks = 1U}};
    }

    [[nodiscard]] proto::PeerEnvelope agent_hello_envelope() {
        const proto::AgentHelloMessage hello {
            .minimum_minor = proto::initial_minor_version,
            .maximum_minor = proto::initial_minor_version,
            .agent_version = "test",
            .agent_epoch = "epoch:test",
            .next_sequence = 1U,
            .schemas = {},
            .capabilities = {},
            .receive_limit = {.bytes = 1U << 20U, .messages = 8U, .work_attempts = 1U, .snapshot_chunks = 1U}};
        return {.protocol_major = proto::major_version,
                .protocol_minor = proto::initial_minor_version,
                .message_id = "agent:hello",
                .session = std::nullopt,
                .agent_epoch = hello.agent_epoch,
                .agent_sequence = 0U,
                .acknowledged_agent_sequence = 0U,
                .body = hello};
    }

    [[nodiscard]] proto::PeerEnvelope
    agent_result_envelope(const std::uint64_t inner_fence = 9U,
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
                       .returned_schema =
                           py::SchemaIdentity {
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
        upsert_node(const py::cluster::DurableResidentNode &) override {
            return {};
        }
        [[nodiscard]] std::expected<std::vector<py::cluster::DurableResidentNode>, py::StoreError>
        node_snapshot() const override {
            ++reads;
            return std::vector<py::cluster::DurableResidentNode> {};
        }
        [[nodiscard]] std::expected<void, py::StoreError> commit(const py::cluster::ControlPlaneCommit &) override {
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

    struct AllowAdminPolicy final: tools::IResidentAdminAccessPolicy {
        mutable std::vector<py::cluster::AdminControlOperation> operations;

        [[nodiscard]] std::expected<py::cluster::AuthenticatedAdminPrincipal, py::cluster::AuthorizedAdminError>
        principal_for(const proto::AuthenticatedPeer &) const noexcept override {
            return py::cluster::AuthenticatedAdminPrincipal {.principal_id = "principal:test",
                                                             .home_tenant = py::TenantId {"tenant:test"},
                                                             .kind = py::cluster::AdminPrincipalKind::administrator,
                                                             .authentication_id = "cert:test"};
        }

        [[nodiscard]] std::expected<py::cluster::AdminAuthorizationDecision, py::cluster::AdminAuthorizerFailure>
        authorize(const py::cluster::AuthenticatedAdminPrincipal &,
                  const py::cluster::AdminAuthorizationRequest &request) const override {
            operations.push_back(request.operation);
            return py::cluster::AdminAuthorizationDecision {
                .outcome = py::cluster::AdminAuthorizationOutcome::allowed,
                .decision_id = "test-allow-" + std::to_string(operations.size()),
                .detail = "allowed",
            };
        }
    };

    struct RecordingUploadBackend final: tools::IResidentPackUploadBackend {
        std::vector<tools::ResidentAdminRequestKind> calls;
        std::vector<std::byte> bytes;
        std::uint64_t total_bytes {};

        [[nodiscard]] std::expected<tools::ResidentPackUploadReceipt, proto::ProtocolError>
        begin(const py::PackId &, std::string_view, const std::uint64_t total) noexcept override {
            calls.push_back(tools::ResidentAdminRequestKind::upload_begin);
            total_bytes = total;
            return tools::ResidentPackUploadReceipt {
                .received_bytes = bytes.size(), .total_bytes = total_bytes, .source_digest = std::nullopt};
        }

        [[nodiscard]] std::expected<tools::ResidentPackUploadReceipt, proto::ProtocolError>
        append(const py::PackId &, std::string_view, const std::uint64_t offset,
               const std::span<const std::byte> payload) noexcept override {
            calls.push_back(tools::ResidentAdminRequestKind::upload_chunk);
            if (offset != bytes.size() || offset > total_bytes || payload.size() > total_bytes - offset) {
                return std::unexpected(proto::ProtocolError {.code = proto::ProtocolErrorCode::digest_mismatch,
                                                             .message = "test upload mismatch"});
            }
            bytes.insert(bytes.end(), payload.begin(), payload.end());
            return tools::ResidentPackUploadReceipt {
                .received_bytes = bytes.size(), .total_bytes = total_bytes, .source_digest = std::nullopt};
        }

        [[nodiscard]] std::expected<tools::ResidentPackUploadReceipt, proto::ProtocolError>
        finalize(const py::PackId &, std::string_view) noexcept override {
            calls.push_back(tools::ResidentAdminRequestKind::upload_finalize);
            if (bytes.size() != total_bytes) {
                return std::unexpected(proto::ProtocolError {.code = proto::ProtocolErrorCode::digest_mismatch,
                                                             .message = "test upload incomplete"});
            }
            return tools::ResidentPackUploadReceipt {
                .received_bytes = bytes.size(),
                .total_bytes = total_bytes,
                .source_digest =
                    py::SourceDigest {"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
            };
        }
    };

    struct RecordingStageSourceBackend final: tools::IResidentStageSourceBackend {
        std::size_t calls {};

        [[nodiscard]] std::expected<py::cluster::GenerationRequest, proto::ProtocolError>
        resolve(const py::PackId &pack, const py::SourceDigest &source_digest, const std::uint64_t generation,
                const std::string_view state_schema_hash, const std::string_view state_namespace) noexcept override {
            ++calls;
            return py::cluster::GenerationRequest {
                .pack = pack,
                .version = py::PackVersion {"1.0.0"},
                .source_digest = source_digest,
                .generation = generation,
                .state_schema_hash = std::string {state_schema_hash},
                .state_namespace = std::string {state_namespace},
                .required_capability_hashes = {},
                .state_transition = {.mode = py::cluster::StateTransitionMode::carry,
                                     .source_namespace = std::string {state_namespace},
                                     .target_namespace = std::string {state_namespace},
                                     .migration_id = {},
                                     .reset_authorized = false,
                                     .accept_state_gap = false},
                .rollback_from = std::nullopt,
                .signature_verified = true,
            };
        }
    };

    struct ResumingUploadTransport final: tools::IResidentAdminRequestTransport {
        std::vector<tools::ResidentAdminRequest> requests;

        [[nodiscard]] std::expected<tools::ResidentAdminResponse, tools::ToolFailure>
        exchange(const tools::AdminEndpointConfiguration &, const tools::ResidentAdminRequest &request) override {
            requests.push_back(request);
            tools::ResidentAdminResponse response {
                .status = tools::ResidentAdminResponseStatus::ok,
                .request_id = request.request_id,
                .code = "OK",
                .diagnostic = {},
                .storage_revision = 0U,
                .resource_version = 0U,
                .active_generation = std::nullopt,
                .previous_active_generation = std::nullopt,
                .operation_phase = {},
                .target_generation = 0U,
                .drain_boundary = 0U,
                .assignment_fence = 0U,
                .work_ids = {},
                .upload_received_bytes = 0U,
                .upload_total_bytes = request.upload_total_bytes,
                .source_digest = std::nullopt,
            };
            if (request.kind == tools::ResidentAdminRequestKind::upload_begin) {
                response.upload_received_bytes = 2U;
                return response;
            }
            if (request.kind == tools::ResidentAdminRequestKind::upload_chunk) {
                response.upload_received_bytes = request.upload_offset + request.payload.size();
                return response;
            }
            if (request.kind == tools::ResidentAdminRequestKind::upload_finalize) {
                response.upload_received_bytes = request.upload_total_bytes;
                response.source_digest =
                    py::SourceDigest {"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"};
                return response;
            }
            return std::unexpected(tools::ToolFailure {
                .kind = tools::ToolFailureKind::operation,
                .code = "TEST-REQUEST",
                .message = "unexpected test request",
                .diagnostics = {},
            });
        }
    };

    struct PollingAdminTransport final: tools::IResidentAdminRequestTransport {
        std::vector<tools::ResidentAdminRequest> requests;
        std::size_t polls {};

        [[nodiscard]] std::expected<tools::ResidentAdminResponse, tools::ToolFailure>
        exchange(const tools::AdminEndpointConfiguration &, const tools::ResidentAdminRequest &request) override {
            requests.push_back(request);
            const auto poll = request.kind == tools::ResidentAdminRequestKind::operation_snapshot;
            if (poll) {
                ++polls;
            }
            return tools::ResidentAdminResponse {
                .status = tools::ResidentAdminResponseStatus::ok,
                .request_id = request.request_id,
                .code = "OK",
                .diagnostic = {},
                .storage_revision = 0U,
                .resource_version = poll && polls >= 2U ? 4U : 3U,
                .active_generation = poll && polls >= 2U ? std::optional<std::uint64_t> {7U} : std::nullopt,
                .previous_active_generation = std::nullopt,
                .operation_phase = poll ? (polls >= 2U ? "applied" : "draining") : "previewed",
                .target_generation = 7U,
                .drain_boundary = poll ? 99U : 0U,
                .assignment_fence = poll && polls >= 2U ? 2U : 0U,
                .work_ids = {},
                .upload_received_bytes = 0U,
                .upload_total_bytes = 0U,
                .source_digest = std::nullopt,
            };
        }
    };

    [[nodiscard]] std::vector<std::byte> archive_bytes(const std::string_view value) {
        return {reinterpret_cast<const std::byte *>(value.data()),
                reinterpret_cast<const std::byte *>(value.data() + value.size())};
    }

    [[nodiscard]] py::packaging::SourcePackArchive unsigned_upload_archive() {
        using namespace py::packaging;
        SourcePackManifest manifest {
            .format = 1,
            .pack = py::PackId {"com.acme.upload"},
            .version = py::PackVersion {"1.0.0"},
            .kind = PackKind::rules,
            .engine_api = 1,
            .python_version = "3.14.6",
            .entry_modules = {"acme.rules"},
            .budget_profile = "balanced.v1",
            .policy_profile = "development.v1",
            .generator = std::nullopt,
            .dependencies = {},
            .required_capabilities = {},
            .optional_capabilities = {},
        };
        std::vector<ArchiveEntry> payloads {
            {.path = "rulepack.toml", .bytes = archive_bytes(canonical_manifest(manifest))},
            {.path = "src/acme/rules.py", .bytes = archive_bytes("def sample() -> bool:\n    return True\n")},
        };
        std::ranges::sort(payloads, {}, &ArchiveEntry::path);
        SourceIndex index;
        for (const auto &payload : payloads) {
            index.entries.push_back(SourceIndexEntry {
                .media_type = payload.path.ends_with(".py") ? "text/x-python" : "application/toml",
                .path = payload.path,
                .sha256 = sha256_hex(payload.bytes),
                .size = payload.bytes.size(),
            });
        }
        SourcePackArchive archive;
        archive.entries.push_back(
            ArchiveEntry {.path = "META-INF/index.json", .bytes = archive_bytes(canonical_index(index))});
        archive.entries.insert(archive.entries.end(), payloads.begin(), payloads.end());
        std::ranges::sort(archive.entries, {}, &ArchiveEntry::path);
        return archive;
    }

    struct StatefulControlStore final: py::cluster::IActivationControlStore {
        py::cluster::DurableControlState state;
        std::map<std::string, py::cluster::AdminOperationRecord, std::less<>> operations;
        std::vector<py::cluster::AuditRecord> audit;
        std::vector<py::cluster::DurableResidentNode> nodes;

        [[nodiscard]] std::expected<py::cluster::DurableControlState, py::StoreError> load_state() const override {
            return state;
        }

        [[nodiscard]] std::expected<std::optional<py::cluster::AdminOperationRecord>, py::StoreError>
        find_operation(const std::string_view operation_id) const override {
            const auto found = operations.find(operation_id);
            return found == operations.end() ? std::optional<py::cluster::AdminOperationRecord> {} :
                                               std::optional<py::cluster::AdminOperationRecord> {found->second};
        }

        [[nodiscard]] std::expected<std::optional<py::cluster::AdminOperationRecord>, py::StoreError>
        find_operation_by_idempotency(const std::string_view idempotency_key) const override {
            const auto found = std::ranges::find_if(
                operations, [&](const auto &entry) { return entry.second.idempotency_key == idempotency_key; });
            return found == operations.end() ? std::optional<py::cluster::AdminOperationRecord> {} :
                                               std::optional<py::cluster::AdminOperationRecord> {found->second};
        }

        [[nodiscard]] std::expected<void, py::StoreError>
        upsert_node(const py::cluster::DurableResidentNode &node) override {
            const auto found = std::ranges::find(nodes, node.node_id, &py::cluster::DurableResidentNode::node_id);
            if (found == nodes.end()) {
                nodes.push_back(node);
            } else {
                *found = node;
            }
            return {};
        }

        [[nodiscard]] std::expected<std::vector<py::cluster::DurableResidentNode>, py::StoreError>
        node_snapshot() const override {
            return nodes;
        }

        [[nodiscard]] std::expected<void, py::StoreError>
        commit(const py::cluster::ControlPlaneCommit &commit) override {
            if (commit.expected_storage_revision != state.storage_revision ||
                commit.state.storage_revision != state.storage_revision + 1U) {
                return std::unexpected(py::StoreError {.code = py::StoreErrorCode::conflict,
                                                       .message = "test storage revision conflict",
                                                       .retryable = true});
            }
            state = commit.state;
            operations.insert_or_assign(commit.operation.operation_id, commit.operation);
            audit.push_back(commit.audit);
            return {};
        }

        [[nodiscard]] std::expected<py::cluster::ControlPlaneInspection, py::StoreError> inspect() const override {
            std::vector<py::cluster::AdminOperationRecord> operation_values;
            operation_values.reserve(operations.size());
            for (const auto &[identity, operation] : operations) {
                static_cast<void>(identity);
                operation_values.push_back(operation);
            }
            return py::cluster::ControlPlaneInspection {
                .state = state, .operations = std::move(operation_values), .audit = audit};
        }

        [[nodiscard]] py::cluster::RuntimeStoreHealth health() const override { return {}; }
    };

    [[nodiscard]] py::cluster::GenerationSnapshot resident_ready_generation() {
        const std::string semantic {"sha256:semantic:test"};
        const std::string binding {"sha256:binding:test"};
        return {.request = {.pack = py::PackId {"pack:test"},
                            .version = py::PackVersion {"1.0.0"},
                            .source_digest = py::SourceDigest {"sha256:source:test"},
                            .generation = 7U,
                            .state_schema_hash = "sha256:state:test",
                            .state_namespace = "state:test",
                            .required_capability_hashes = {},
                            .state_transition = {.mode = py::cluster::StateTransitionMode::carry,
                                                 .source_namespace = {},
                                                 .target_namespace = "state:test",
                                                 .migration_id = {},
                                                 .reset_authorized = false,
                                                 .accept_state_gap = false},
                            .rollback_from = std::nullopt,
                            .signature_verified = true},
                .phase = py::cluster::GenerationPhase::ready,
                .target_nodes = {"node:test"},
                .reports = {{.node_id = "node:test",
                             .node_lease_fence = 1U,
                             .success = true,
                             .semantic_hash = semantic,
                             .binding_hash = binding,
                             .executable_hash = "sha256:executable:test",
                             .capability_hashes = {},
                             .diagnostics = {}}},
                .semantic_hash = semantic,
                .binding_hash = binding,
                .requeued_work = {},
                .failure = {}};
    }

    struct BlockingHandler final: tools::IResidentSessionHandler {
        std::atomic<std::size_t> entered {};
        void run(tools::ResidentSessionJob job, const std::stop_token cancellation) noexcept override {
            ++entered;
            while (!cancellation.stop_requested()) { std::this_thread::yield(); }
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

TEST_CASE("resident agent service closes an established session that fails value validation") {
    AllowTrust trust;
    DurableFakeAgentBackend agents;
    agents.return_invalid_session = true;
    RejectAdmin admin;
    tools::ResidentApplicationService service {test_service_limits(), trust, agents, admin};
    auto state = std::make_shared<FakeChannelState>();
    enqueue_protocol(state, agent_hello_envelope());

    service.run({.role = tools::ResidentSessionRole::agent,
                 .peer = {.tenant = py::TenantId {"tenant:test"}, .peer = py::PeerId {"peer:test"}},
                 .channel = std::make_unique<FakeByteChannel>(state)},
                {});

    CHECK(agents.closes == 1U);
    CHECK(agents.persists == 0U);
    CHECK(state->protocol_output.empty());
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
    CHECK(agents.closes == 1U);
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
    CHECK(agents.closes == 1U);
    REQUIRE(state->protocol_output.size() == 3U);
    const auto nack = proto::decode_frame(state->protocol_output.back());
    REQUIRE(nack);
    REQUIRE(std::holds_alternative<proto::NackMessage>(nack->envelope.body));
    CHECK(std::get<proto::NackMessage>(nack->envelope.body).reason == proto::ProtocolErrorCode::provider_violation);
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
    const std::array requests {
        tools::ResidentAdminRequest {.kind = tools::ResidentAdminRequestKind::pack_snapshot,
                                     .request_id = "request:pack",
                                     .tenant = py::TenantId {"tenant:test"},
                                     .pack = py::PackId {"pack:test"},
                                     .at_unix_ms = 10U,
                                     .payload = {}},
        tools::ResidentAdminRequest {.kind = tools::ResidentAdminRequestKind::operation_snapshot,
                                     .request_id = "request:operation",
                                     .tenant = py::TenantId {"tenant:test"},
                                     .pack = py::PackId {"pack:test"},
                                     .operation_id = "operation:test",
                                     .at_unix_ms = 10U,
                                     .payload = {}},
        tools::ResidentAdminRequest {.kind = tools::ResidentAdminRequestKind::activation_preview,
                                     .request_id = "request:preview",
                                     .tenant = py::TenantId {"tenant:test"},
                                     .pack = py::PackId {"pack:test"},
                                     .operation_id = "operation:test",
                                     .idempotency_key = "idempotency:test",
                                     .expected_pack_version = 1U,
                                     .at_unix_ms = 10U,
                                     .reason = "test activation",
                                     .target_generation = 2U,
                                     .payload = {}},
        tools::ResidentAdminRequest {.kind = tools::ResidentAdminRequestKind::activation_drain,
                                     .request_id = "request:drain",
                                     .tenant = py::TenantId {"tenant:test"},
                                     .pack = py::PackId {"pack:test"},
                                     .operation_id = "operation:test",
                                     .idempotency_key = "idempotency:test",
                                     .expected_pack_version = 1U,
                                     .at_unix_ms = 10U,
                                     .drain_boundary = 42U,
                                     .payload = {}},
        tools::ResidentAdminRequest {.kind = tools::ResidentAdminRequestKind::activation_fence,
                                     .request_id = "request:fence",
                                     .tenant = py::TenantId {"tenant:test"},
                                     .pack = py::PackId {"pack:test"},
                                     .operation_id = "operation:test",
                                     .idempotency_key = "idempotency:test",
                                     .expected_pack_version = 2U,
                                     .at_unix_ms = 10U,
                                     .work_ids = {"work:b", "work:a"},
                                     .payload = {}},
        tools::ResidentAdminRequest {.kind = tools::ResidentAdminRequestKind::activation_flip,
                                     .request_id = "request:flip",
                                     .tenant = py::TenantId {"tenant:test"},
                                     .pack = py::PackId {"pack:test"},
                                     .operation_id = "operation:test",
                                     .idempotency_key = "idempotency:test",
                                     .expected_pack_version = 3U,
                                     .at_unix_ms = 10U,
                                     .payload = {}},
        tools::ResidentAdminRequest {.kind = tools::ResidentAdminRequestKind::upload_begin,
                                     .request_id = "request:upload:begin",
                                     .tenant = py::TenantId {"tenant:test"},
                                     .pack = py::PackId {"pack:test"},
                                     .operation_id = "upload:test",
                                     .at_unix_ms = 10U,
                                     .reason = "approved upload",
                                     .upload_total_bytes = 3U,
                                     .payload = {}},
        tools::ResidentAdminRequest {.kind = tools::ResidentAdminRequestKind::upload_chunk,
                                     .request_id = "request:upload:chunk",
                                     .tenant = py::TenantId {"tenant:test"},
                                     .pack = py::PackId {"pack:test"},
                                     .operation_id = "upload:test",
                                     .at_unix_ms = 10U,
                                     .upload_offset = 0U,
                                     .upload_total_bytes = 3U,
                                     .payload = {std::byte {1}, std::byte {2}, std::byte {3}}},
        tools::ResidentAdminRequest {.kind = tools::ResidentAdminRequestKind::upload_finalize,
                                     .request_id = "request:upload:finalize",
                                     .tenant = py::TenantId {"tenant:test"},
                                     .pack = py::PackId {"pack:test"},
                                     .operation_id = "upload:test",
                                     .at_unix_ms = 10U,
                                     .upload_offset = 3U,
                                     .upload_total_bytes = 3U,
                                     .payload = {}},
        tools::ResidentAdminRequest {
            .kind = tools::ResidentAdminRequestKind::stage_preview,
            .request_id = "request:stage:preview",
            .tenant = py::TenantId {"tenant:test"},
            .pack = py::PackId {"pack:test"},
            .operation_id = "operation:stage",
            .idempotency_key = "idempotency:stage",
            .expected_pack_version = 0U,
            .at_unix_ms = 10U,
            .reason = "approved stage",
            .target_generation = 1U,
            .payload = {},
            .source_digest =
                py::SourceDigest {"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
            .state_schema_hash = "sha256:state",
            .state_namespace = "state:live"},
    };
    for (const auto &request : requests) {
        auto encoded = tools::encode_resident_admin_request(request, 4U * py::kibibyte);
        REQUIRE(encoded);
        auto decoded = tools::decode_resident_admin_request(*encoded, 4U * py::kibibyte);
        REQUIRE(decoded);
        CHECK(decoded->kind == request.kind);
        CHECK(decoded->request_id == request.request_id);
        CHECK(decoded->reason == request.reason);
        CHECK(decoded->target_generation == request.target_generation);
        CHECK(decoded->drain_boundary == request.drain_boundary);
        CHECK(decoded->work_ids == request.work_ids);
        CHECK(decoded->upload_offset == request.upload_offset);
        CHECK(decoded->upload_total_bytes == request.upload_total_bytes);
        CHECK(decoded->payload == request.payload);
        CHECK(decoded->source_digest == request.source_digest);
        CHECK(decoded->state_schema_hash == request.state_schema_hash);
        CHECK(decoded->state_namespace == request.state_namespace);
    }
    auto bytes = tools::encode_resident_admin_request(requests.back(), 4U * py::kibibyte);
    REQUIRE(bytes);
    auto decoded = tools::decode_resident_admin_request(*bytes, 4U * py::kibibyte);
    REQUIRE(decoded);
    const auto admin_peer =
        proto::AuthenticatedPeer {.tenant = py::TenantId {"tenant:test"}, .peer = py::PeerId {"peer:admin"}};
    for (const auto &request : requests) {
        const auto response = backend.execute(admin_peer, request);
        CHECK(response.status == tools::ResidentAdminResponseStatus::rejected);
        CHECK(response.code == "ADMIN-UNAUTHORIZED");
    }
    CHECK(store.reads == 0U);
    CHECK(store.commits == 0U);

    const tools::ResidentAdminResponse rich_response {
        .status = tools::ResidentAdminResponseStatus::ok,
        .request_id = "request:rich",
        .code = "OK",
        .diagnostic = {},
        .storage_revision = 7U,
        .resource_version = 8U,
        .active_generation = 3U,
        .previous_active_generation = 2U,
        .operation_phase = "fenced",
        .target_generation = 3U,
        .drain_boundary = 99U,
        .assignment_fence = 12U,
        .work_ids = {"work:a", "work:b"},
        .upload_received_bytes = 17U,
        .upload_total_bytes = 17U,
        .source_digest = py::SourceDigest {"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
    };
    const auto rich_bytes = tools::encode_resident_admin_response(rich_response, 4U * py::kibibyte);
    REQUIRE(rich_bytes);
    const auto rich_decoded = tools::decode_resident_admin_response(*rich_bytes, 4U * py::kibibyte);
    REQUIRE(rich_decoded);
    CHECK(rich_decoded->operation_phase == "fenced");
    CHECK(rich_decoded->target_generation == 3U);
    CHECK(rich_decoded->drain_boundary == 99U);
    CHECK(rich_decoded->assignment_fence == 12U);
    CHECK(rich_decoded->work_ids == std::vector<std::string> {"work:a", "work:b"});
    CHECK(rich_decoded->upload_received_bytes == 17U);
    CHECK(rich_decoded->upload_total_bytes == 17U);
    REQUIRE(rich_decoded->source_digest);
    CHECK(*rich_decoded->source_digest == *rich_response.source_digest);

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

TEST_CASE("standalone admin client maps explicit lifecycle commands without trusting an actor field") {
    const std::string source_digest {"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"};
    tools::AdminCommand stage {.action = tools::AdminAction::stage,
                               .operands = {"pack:test", source_digest, "6"},
                               .options = {{"tenant", "tenant:test"},
                                           {"expected-version", "2"},
                                           {"state-schema", "sha256:state"},
                                           {"state-namespace", "state:live"}},
                               .request_id = "request:stage",
                               .reason = "compile approved source",
                               .preview = true};
    const auto stage_request = tools::build_resident_admin_request(stage, 99U);
    REQUIRE(stage_request);
    CHECK(stage_request->kind == tools::ResidentAdminRequestKind::stage_preview);
    CHECK(stage_request->source_digest == py::SourceDigest {source_digest});
    CHECK(stage_request->target_generation == 6U);
    CHECK(stage_request->state_schema_hash == "sha256:state");
    CHECK(stage_request->state_namespace == "state:live");

    stage.preview = false;
    stage.reason.clear();
    stage.options["expected-version"] = "3";
    const auto stage_apply = tools::build_resident_admin_request(stage, 100U);
    REQUIRE(stage_apply);
    CHECK(stage_apply->kind == tools::ResidentAdminRequestKind::stage_apply);

    tools::AdminCommand preview {.action = tools::AdminAction::activate,
                                 .operands = {"pack:test", "7"},
                                 .options = {{"tenant", "tenant:test"}, {"expected-version", "3"}},
                                 .request_id = "request:activate",
                                 .reason = "deploy approved generation",
                                 .preview = true};
    const auto preview_request = tools::build_resident_admin_request(preview, 100U);
    REQUIRE(preview_request);
    CHECK(preview_request->kind == tools::ResidentAdminRequestKind::activation_preview);
    CHECK(preview_request->operation_id == "request:activate");
    CHECK(preview_request->idempotency_key == "request:activate");
    CHECK(preview_request->target_generation == 7U);
    CHECK(preview_request->expected_pack_version == 3U);
    CHECK(preview_request->at_unix_ms == 100U);

    tools::AdminCommand drain {.action = tools::AdminAction::activate,
                               .operands = {"pack:test"},
                               .options = {{"tenant", "tenant:test"},
                                           {"phase", "drain"},
                                           {"operation-id", "operation:activate"},
                                           {"idempotency-key", "idempotency:activate"},
                                           {"expected-version", "4"},
                                           {"boundary", "99"}},
                               .request_id = "request:drain",
                               .preview = false};
    const auto drain_request = tools::build_resident_admin_request(drain, 101U);
    REQUIRE(drain_request);
    CHECK(drain_request->kind == tools::ResidentAdminRequestKind::activation_drain);
    CHECK(drain_request->operation_id == "operation:activate");
    CHECK(drain_request->idempotency_key == "idempotency:activate");
    CHECK(drain_request->drain_boundary == 99U);

    preview.options.erase("tenant");
    const auto missing_tenant = tools::build_resident_admin_request(preview, 102U);
    REQUIRE_FALSE(missing_tenant);
    CHECK(missing_tenant.error().code == "ADMIN-TENANT");
}

TEST_CASE("resident stage authorization runs before source resolution") {
    CountingControlStore store;
    DenyAdminPolicy policy;
    RecordingStageSourceBackend stages;
    tools::AuthorizedResidentAdminBackend backend {store, policy, nullptr, nullptr, &stages};
    const tools::ResidentAdminRequest request {
        .kind = tools::ResidentAdminRequestKind::stage_preview,
        .request_id = "request:stage",
        .tenant = py::TenantId {"tenant:test"},
        .pack = py::PackId {"pack:test"},
        .operation_id = "operation:stage",
        .idempotency_key = "idempotency:stage",
        .expected_pack_version = 0U,
        .at_unix_ms = 10U,
        .reason = "approved stage",
        .target_generation = 1U,
        .payload = {},
        .source_digest = py::SourceDigest {"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
        .state_schema_hash = "sha256:state",
        .state_namespace = "state:live",
    };
    const auto response = backend.execute(
        proto::AuthenticatedPeer {.tenant = py::TenantId {"tenant:test"}, .peer = py::PeerId {"peer:admin"}}, request);
    CHECK(response.status == tools::ResidentAdminResponseStatus::rejected);
    CHECK(stages.calls == 0U);
    CHECK(store.reads == 0U);
    CHECK(store.commits == 0U);
}

TEST_CASE("standalone admin client resumes bounded upload and returns publication identity") {
    TemporaryDirectory temporary;
    const auto archive_path = temporary.path / "pack.rpack";
    write_file(archive_path, "0123456789");
    ResumingUploadTransport transport;
    tools::ResidentAdminClientAdapter client {&transport};
    const tools::AdminCommand command {
        .action = tools::AdminAction::upload,
        .operands = {"pack:test", archive_path.string()},
        .options = {{"tenant", "tenant:test"}},
        .format = tools::OutputFormat::text,
        .config_path = {},
        .request_id = "upload:test",
        .reason = "approved upload",
        .wait = false,
        .preview = false,
    };
    const auto result = client.execute({}, command);
    REQUIRE(result);
    REQUIRE(result->success);
    REQUIRE(transport.requests.size() == 3U);
    CHECK(transport.requests[0].kind == tools::ResidentAdminRequestKind::upload_begin);
    CHECK(transport.requests[0].reason == "approved upload");
    CHECK(transport.requests[0].operation_id == "upload:test");
    CHECK(transport.requests[1].kind == tools::ResidentAdminRequestKind::upload_chunk);
    CHECK(transport.requests[1].upload_offset == 2U);
    CHECK(transport.requests[1].payload == archive_bytes("23456789"));
    CHECK(transport.requests[2].kind == tools::ResidentAdminRequestKind::upload_finalize);
    CHECK(transport.requests[2].upload_offset == 10U);
    const auto digest = std::ranges::find(result->fields, "source_digest", &tools::DisplayField::name);
    REQUIRE(digest != result->fields.end());
    CHECK(digest->value == "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
}

TEST_CASE("standalone admin client polls one durable operation to a bounded terminal phase") {
    PollingAdminTransport transport;
    tools::ResidentAdminClientAdapter client {&transport};
    const tools::AdminCommand command {
        .action = tools::AdminAction::activate,
        .operands = {"pack:test", "7"},
        .options = {{"tenant", "tenant:test"},
                    {"expected-version", "3"},
                    {"wait-timeout-ms", "100"},
                    {"poll-interval-ms", "1"}},
        .format = tools::OutputFormat::text,
        .config_path = {},
        .request_id = "request:wait",
        .reason = "approved activation",
        .wait = true,
        .preview = true,
    };
    const auto result = client.execute({}, command);
    REQUIRE(result);
    REQUIRE(result->success);
    REQUIRE(transport.requests.size() == 3U);
    CHECK(transport.requests[0].kind == tools::ResidentAdminRequestKind::activation_preview);
    CHECK(transport.requests[1].kind == tools::ResidentAdminRequestKind::operation_snapshot);
    CHECK(transport.requests[1].operation_id == "request:wait");
    CHECK(transport.requests[1].request_id == "request:wait:poll:1");
    CHECK(transport.requests[2].request_id == "request:wait:poll:2");
    const auto phase = std::ranges::find(result->fields, "operation_phase", &tools::DisplayField::name);
    REQUIRE(phase != result->fields.end());
    CHECK(phase->value == "applied");
}

TEST_CASE("resident upload authorizes every phase before touching the bounded backend") {
    CountingControlStore store;
    AllowAdminPolicy policy;
    RecordingUploadBackend uploads;
    tools::AuthorizedResidentAdminBackend backend {store, policy, nullptr, &uploads};
    const proto::AuthenticatedPeer peer {.tenant = py::TenantId {"tenant:test"}, .peer = py::PeerId {"peer:admin"}};
    tools::ResidentAdminRequest request {
        .kind = tools::ResidentAdminRequestKind::upload_begin,
        .request_id = "request:upload:begin",
        .tenant = py::TenantId {"tenant:test"},
        .pack = py::PackId {"pack:test"},
        .operation_id = "upload:test",
        .at_unix_ms = 10U,
        .reason = "approved source pack",
        .upload_total_bytes = 3U,
        .payload = {},
    };
    const auto begun = backend.execute(peer, request);
    REQUIRE(begun.status == tools::ResidentAdminResponseStatus::ok);
    CHECK(begun.upload_received_bytes == 0U);
    CHECK(begun.upload_total_bytes == 3U);

    request.kind = tools::ResidentAdminRequestKind::upload_chunk;
    request.request_id = "request:upload:chunk";
    request.at_unix_ms = 11U;
    request.reason.clear();
    request.payload = {std::byte {1}, std::byte {2}, std::byte {3}};
    const auto appended = backend.execute(peer, request);
    REQUIRE(appended.status == tools::ResidentAdminResponseStatus::ok);
    CHECK(appended.upload_received_bytes == 3U);

    request.kind = tools::ResidentAdminRequestKind::upload_finalize;
    request.request_id = "request:upload:finalize";
    request.at_unix_ms = 12U;
    request.upload_offset = 3U;
    request.payload.clear();
    const auto finalized = backend.execute(peer, request);
    REQUIRE(finalized.status == tools::ResidentAdminResponseStatus::ok);
    REQUIRE(finalized.source_digest);
    CHECK(finalized.source_digest->value == "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    CHECK(uploads.calls == std::vector<tools::ResidentAdminRequestKind> {
                               tools::ResidentAdminRequestKind::upload_begin,
                               tools::ResidentAdminRequestKind::upload_chunk,
                               tools::ResidentAdminRequestKind::upload_finalize,
                           });
    CHECK(policy.operations == std::vector<py::cluster::AdminControlOperation> {
                                   py::cluster::AdminControlOperation::pack_upload,
                                   py::cluster::AdminControlOperation::pack_upload,
                                   py::cluster::AdminControlOperation::pack_upload,
                               });
    CHECK(store.reads == 0U);
    CHECK(store.commits == 0U);
}

TEST_CASE("filesystem upload resumes exact bytes and replays immutable publication evidence") {
    TemporaryDirectory temporary;
    const std::filesystem::path crypto_library {RULE_ENGINE_PYTHON_SERVER_PATH};
    REQUIRE_FALSE(crypto_library.empty());
    py::packaging::TrustPolicy trust {
        .mode = py::packaging::TrustMode::development,
        .allow_unsigned_packs = true,
        .allow_unsigned_generators = false,
        .signers = {},
    };
    auto archive = unsigned_upload_archive();
    auto encoded = py::packaging::encode_canonical_source_pack(archive);
    REQUIRE(encoded);
    auto backend = tools::FilesystemResidentPackUploadBackend::create(temporary.path, trust, crypto_library);
    REQUIRE(backend);

    const auto split = encoded->size() / 2U;
    auto begun = (*backend)->begin(py::PackId {"com.acme.upload"}, "upload:restart", encoded->size());
    REQUIRE(begun);
    CHECK(begun->received_bytes == 0U);
    auto first = (*backend)->append(py::PackId {"com.acme.upload"}, "upload:restart", 0U,
                                    std::span<const std::byte> {*encoded}.first(split));
    REQUIRE(first);
    CHECK(first->received_bytes == split);
    auto replayed = (*backend)->append(py::PackId {"com.acme.upload"}, "upload:restart", 0U,
                                       std::span<const std::byte> {*encoded}.first(split));
    REQUIRE(replayed);
    CHECK(replayed->received_bytes == split);

    backend->reset();
    backend = tools::FilesystemResidentPackUploadBackend::create(temporary.path, trust, crypto_library);
    REQUIRE(backend);
    auto resumed = (*backend)->begin(py::PackId {"com.acme.upload"}, "upload:restart", encoded->size());
    REQUIRE(resumed);
    CHECK(resumed->received_bytes == split);
    auto second = (*backend)->append(py::PackId {"com.acme.upload"}, "upload:restart", split,
                                     std::span<const std::byte> {*encoded}.subspan(split));
    REQUIRE(second);
    CHECK(second->received_bytes == encoded->size());
    auto finalized = (*backend)->finalize(py::PackId {"com.acme.upload"}, "upload:restart");
    REQUIRE(finalized);
    REQUIRE(finalized->source_digest);

    auto destination = py::packaging::content_addressed_source_pack_path(temporary.path, *finalized->source_digest);
    REQUIRE(destination);
    CHECK(std::filesystem::is_regular_file(*destination));
    backend->reset();
    backend = tools::FilesystemResidentPackUploadBackend::create(temporary.path, trust, crypto_library);
    REQUIRE(backend);
    auto replayed_finalize = (*backend)->finalize(py::PackId {"com.acme.upload"}, "upload:restart");
    REQUIRE(replayed_finalize);
    CHECK(replayed_finalize->source_digest == finalized->source_digest);
    CHECK(replayed_finalize->received_bytes == encoded->size());

    std::error_code filesystem_error;
    std::size_t partial_files {};
    for (const auto &entry : std::filesystem::directory_iterator {temporary.path / ".uploads", filesystem_error}) {
        REQUIRE_FALSE(filesystem_error);
        if (entry.path().extension() == ".part" || entry.path().extension() == ".meta") {
            ++partial_files;
        }
    }
    CHECK_FALSE(filesystem_error);
    CHECK(partial_files == 0U);
}

TEST_CASE("resident admin v2 activation sequence is durable and idempotent across lost responses") {
    StatefulControlStore store;
    store.state.storage_revision = 0U;
    store.state.generations = {resident_ready_generation()};
    store.state.packs = {{.pack = py::PackId {"pack:test"},
                          .resource_version = 1U,
                          .active_generation = std::nullopt,
                          .assignment_fence = 0U,
                          .accepting_assignments = false,
                          .drain_boundary = std::nullopt,
                          .drain_target = std::nullopt,
                          .pending_requeues = {}}};
    AllowAdminPolicy policy;
    DurableFakeAgentBackend agents;
    tools::AuthorizedResidentAdminBackend backend {store, policy, nullptr, nullptr, nullptr, &agents};
    const proto::AuthenticatedPeer peer {.tenant = py::TenantId {"tenant:test"}, .peer = py::PeerId {"peer:admin"}};

    const tools::ResidentAdminRequest preview {.kind = tools::ResidentAdminRequestKind::activation_preview,
                                               .request_id = "request:preview",
                                               .tenant = py::TenantId {"tenant:test"},
                                               .pack = py::PackId {"pack:test"},
                                               .operation_id = "operation:activate",
                                               .idempotency_key = "idempotency:activate",
                                               .expected_pack_version = 1U,
                                               .at_unix_ms = 10U,
                                               .reason = "approved rollout",
                                               .target_generation = 7U,
                                               .payload = {}};
    const auto previewed = backend.execute(peer, preview);
    REQUIRE(previewed.status == tools::ResidentAdminResponseStatus::ok);
    CHECK(previewed.operation_phase == "previewed");
    CHECK(previewed.resource_version == 1U);

    auto drain = preview;
    drain.kind = tools::ResidentAdminRequestKind::activation_drain;
    drain.request_id = "request:drain";
    drain.at_unix_ms = 11U;
    drain.reason.clear();
    drain.target_generation = 0U;
    drain.drain_boundary = 500U;
    const auto drained = backend.execute(peer, drain);
    REQUIRE(drained.status == tools::ResidentAdminResponseStatus::ok);
    CHECK(drained.operation_phase == "draining");
    CHECK(drained.resource_version == 2U);
    CHECK(drained.assignment_fence == 1U);

    auto fence = drain;
    fence.kind = tools::ResidentAdminRequestKind::activation_fence;
    fence.request_id = "request:fence";
    fence.expected_pack_version = 2U;
    fence.at_unix_ms = 12U;
    fence.drain_boundary = 0U;
    fence.work_ids = {"work:b", "work:a", "work:a"};
    const auto fenced = backend.execute(peer, fence);
    REQUIRE(fenced.status == tools::ResidentAdminResponseStatus::ok);
    CHECK(fenced.operation_phase == "fenced");
    CHECK(fenced.resource_version == 3U);
    CHECK(fenced.work_ids == std::vector<std::string> {"work:a", "work:b"});

    auto flip = fence;
    flip.kind = tools::ResidentAdminRequestKind::activation_flip;
    flip.request_id = "request:flip";
    flip.expected_pack_version = 3U;
    flip.at_unix_ms = 13U;
    flip.work_ids.clear();
    const auto flipped = backend.execute(peer, flip);
    REQUIRE(flipped.status == tools::ResidentAdminResponseStatus::ok);
    CHECK(flipped.operation_phase == "applied");
    CHECK(flipped.resource_version == 4U);
    CHECK(flipped.active_generation == 7U);
    CHECK(flipped.assignment_fence == 2U);
    CHECK(flipped.work_ids == std::vector<std::string> {"work:a", "work:b"});

    const auto flip_after_lost_response = backend.execute(peer, flip);
    REQUIRE(flip_after_lost_response.status == tools::ResidentAdminResponseStatus::ok);
    CHECK(flip_after_lost_response.resource_version == 4U);
    CHECK(flip_after_lost_response.active_generation == 7U);

    const auto preview_after_lost_response = backend.execute(peer, preview);
    REQUIRE(preview_after_lost_response.status == tools::ResidentAdminResponseStatus::ok);
    CHECK(preview_after_lost_response.operation_phase == "applied");
    CHECK(preview_after_lost_response.resource_version == 4U);
    CHECK(agents.activation_fences == 2U);
    CHECK(store.state.storage_revision == 4U);
    CHECK(store.audit.size() == 4U);
    CHECK(policy.operations == std::vector<py::cluster::AdminControlOperation> {
                                   py::cluster::AdminControlOperation::activation_preview,
                                   py::cluster::AdminControlOperation::activation_drain,
                                   py::cluster::AdminControlOperation::activation_fence,
                                   py::cluster::AdminControlOperation::activation_flip,
                                   py::cluster::AdminControlOperation::activation_flip,
                                   py::cluster::AdminControlOperation::activation_preview,
                               });
}

TEST_CASE("resident admin stage resolves trusted server metadata and freezes durable nodes") {
    StatefulControlStore store;
    store.nodes = {{.node_id = "node:test",
                    .platform_abi = "windows-x64-v1",
                    .lease_fence = 4U,
                    .lease_until_unix_ms = 10'000U,
                    .updated_at_unix_ms = 1U,
                    .serving = true,
                    .capability_hashes = {}}};
    AllowAdminPolicy policy;
    RecordingStageSourceBackend stages;
    tools::AuthorizedResidentAdminBackend backend {store, policy, nullptr, nullptr, &stages};
    const proto::AuthenticatedPeer peer {.tenant = py::TenantId {"tenant:test"}, .peer = py::PeerId {"peer:admin"}};
    const py::SourceDigest digest {"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"};
    const tools::ResidentAdminRequest preview {
        .kind = tools::ResidentAdminRequestKind::stage_preview,
        .request_id = "request:stage:preview",
        .tenant = py::TenantId {"tenant:test"},
        .pack = py::PackId {"pack:test"},
        .operation_id = "operation:stage",
        .idempotency_key = "idempotency:stage",
        .expected_pack_version = 0U,
        .at_unix_ms = 10U,
        .reason = "approved source",
        .target_generation = 1U,
        .payload = {},
        .source_digest = digest,
        .state_schema_hash = "sha256:state",
        .state_namespace = "state:live",
    };
    const auto previewed = backend.execute(peer, preview);
    REQUIRE(previewed.status == tools::ResidentAdminResponseStatus::ok);
    CHECK(previewed.operation_phase == "previewed");
    CHECK(stages.calls == 1U);

    auto apply = preview;
    apply.kind = tools::ResidentAdminRequestKind::stage_apply;
    apply.request_id = "request:stage:apply";
    apply.at_unix_ms = 11U;
    apply.reason.clear();
    const auto compiling = backend.execute(peer, apply);
    REQUIRE(compiling.status == tools::ResidentAdminResponseStatus::ok);
    CHECK(compiling.operation_phase == "previewed");
    CHECK(compiling.resource_version == 1U);
    CHECK(compiling.work_ids == std::vector<std::string> {"node:test"});
    REQUIRE(store.state.generations.size() == 1U);
    CHECK(store.state.generations.front().phase == py::cluster::GenerationPhase::compiling);
    CHECK(store.state.generations.front().targets.front().lease_fence == 4U);
    CHECK(stages.calls == 2U);
    CHECK(policy.operations == std::vector<py::cluster::AdminControlOperation> {
                                   py::cluster::AdminControlOperation::stage_preview,
                                   py::cluster::AdminControlOperation::stage_apply,
                               });
}

TEST_CASE("resident scheduler rejects overload and joins owned workers on shutdown") {
    auto limits = test_service_limits();
    BlockingHandler handler;
    auto scheduler = tools::ResidentServiceScheduler::create(limits, handler);
    REQUIRE(scheduler);

    auto first = std::make_shared<FakeChannelState>();
    auto second = std::make_shared<FakeChannelState>();
    auto third = std::make_shared<FakeChannelState>();
    CHECK((*scheduler)
              ->submit({.role = tools::ResidentSessionRole::agent,
                        .peer = {},
                        .channel = std::make_unique<FakeByteChannel>(first)}) == tools::ResidentAdmission::accepted);
    for (std::size_t attempt = 0U; attempt < 10'000U && handler.entered.load() == 0U; ++attempt) {
        std::this_thread::yield();
    }
    REQUIRE(handler.entered.load() == 1U);
    CHECK((*scheduler)
              ->submit({.role = tools::ResidentSessionRole::agent,
                        .peer = {},
                        .channel = std::make_unique<FakeByteChannel>(second)}) == tools::ResidentAdmission::accepted);
    CHECK((*scheduler)
              ->submit({.role = tools::ResidentSessionRole::agent,
                        .peer = {},
                        .channel = std::make_unique<FakeByteChannel>(third)}) == tools::ResidentAdmission::overloaded);
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
