#include <catch2/catch_test_macros.hpp>

#include "rule_engine/python/tools/server.hpp"

#ifndef RULE_ENGINE_PYTHON_SERVER_PATH
#define RULE_ENGINE_PYTHON_SERVER_PATH ""
#endif

#ifndef RULE_ENGINE_PYTHON_BENCHMARK_PATH
#define RULE_ENGINE_PYTHON_BENCHMARK_PATH ""
#endif

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <string_view>
#include <utility>

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

TEST_CASE("default resident backend exposes activation and network gaps as stable failures") {
    using namespace rule_engine::python;
    using namespace rule_engine::python::tools;

    cluster::AuditTrail audit;
    cluster::InMemoryRuntimeStore store {audit};
    const ServerConfig config;
    const packaging::PrivatePythonRuntime runtime;
    const ResidentServerContext context {
        .config = config,
        .store = store,
        .runtime = runtime,
        .tls = nullptr,
    };
    UnavailableResidentServerBackend backend;

    const auto activation = backend.qualify_activation(context);
    REQUIRE_FALSE(activation.has_value());
    CHECK(activation.error().code == "SRV-ACTIVATION-UNAVAILABLE");
    CHECK(exit_code_for(activation.error()) == ExitCode::unavailable);

    const auto network = backend.serve(context);
    REQUIRE_FALSE(network.has_value());
    CHECK(network.error().code == "SRV-NETWORK-UNAVAILABLE");
    CHECK(exit_code_for(network.error()) == ExitCode::unavailable);
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
    CHECK(measured.standard_output.find("\"schema\":\"rule-engine.python-benchmark.v1\"") != std::string::npos);
    CHECK(measured.standard_output.find("\"exact_vm_sessions\":8") != std::string::npos);
    CHECK(measured.standard_output.find("\"optimized_vm_sessions\":0") != std::string::npos);
    CHECK(measured.standard_output.find("\"optimizer_certificate_validated\":true") != std::string::npos);
    CHECK(measured.standard_output.find("\"parity_equivalent\":true") != std::string::npos);
    CHECK(measured.standard_output.find("\"parity_mismatches\":0") != std::string::npos);

    const auto rejected = run_process(benchmark, "--format sarif", temporary, "rejected");
    CHECK(rejected.exit_code == 2);
    CHECK(rejected.standard_error.find("BENCH-CLI-USAGE") != std::string::npos);
}
