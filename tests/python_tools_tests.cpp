#include "rule_engine/python/packaging.hpp"
#include "rule_engine/python/tools.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <stop_token>
#include <string>
#include <string_view>
#include <utility>

namespace {

    using namespace rule_engine::python;
    using namespace rule_engine::python::tools;

#ifndef RULE_ENGINE_TOOLING_SDK_ROOT
#define RULE_ENGINE_TOOLING_SDK_ROOT ""
#endif

#ifndef RULE_ENGINE_TOOLING_STAGED_RUNTIME_ROOT
#define RULE_ENGINE_TOOLING_STAGED_RUNTIME_ROOT ""
#endif

    struct TemporaryDirectory {
        std::filesystem::path path;
        bool created {};

        TemporaryDirectory() {
            std::error_code filesystem_error;
            const auto parent = std::filesystem::temp_directory_path(filesystem_error);
            if (filesystem_error) {
                return;
            }
            static std::atomic<std::uint64_t> sequence {};
            for (std::uint32_t attempt = 0; attempt < 8U && !created; ++attempt) {
                const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
                path = parent / ("rule-engine-python-tools-" + std::to_string(nonce) + '-' +
                                 std::to_string(sequence.fetch_add(1U)));
                created = std::filesystem::create_directory(path, filesystem_error);
                if (filesystem_error) {
                    filesystem_error.clear();
                }
            }
        }

        TemporaryDirectory(const TemporaryDirectory &) = delete;
        TemporaryDirectory &operator=(const TemporaryDirectory &) = delete;

        ~TemporaryDirectory() {
            if (!created) {
                return;
            }
            std::error_code ignored;
            std::filesystem::remove_all(path, ignored);
        }
    };

    bool write_text_file(const std::filesystem::path &path, const std::string_view content) {
        std::error_code filesystem_error;
        std::filesystem::create_directories(path.parent_path(), filesystem_error);
        if (filesystem_error) {
            return false;
        }
        std::ofstream output {path, std::ios::binary | std::ios::trunc};
        if (!output) {
            return false;
        }
        output.write(content.data(), static_cast<std::streamsize>(content.size()));
        output.flush();
        return output.good();
    }

    packaging::SourcePackManifest static_smoke_manifest() {
        return packaging::SourcePackManifest {
            .format = 1,
            .pack = PackId {"com.example.tooling-smoke"},
            .version = PackVersion {"1.0.0"},
            .kind = packaging::PackKind::rules,
            .engine_api = 1,
            .python_version = "3.14.6",
            .entry_modules = {"tooling.rules"},
            .budget_profile = "balanced.v1",
            .policy_profile = "development.v1",
            .generator = std::nullopt,
            .dependencies = {},
            .required_capabilities = {},
            .optional_capabilities = {},
        };
    }

    bool write_static_smoke_source(const std::filesystem::path &root) {
        return write_text_file(root / "rulepack.toml", packaging::canonical_manifest(static_smoke_manifest())) &&
               write_text_file(root / "src/tooling/rules.py", "@rule(\"com.example.tooling.constant\")\n"
                                                              "def constant() -> bool:\n"
                                                              "    return True\n");
    }

    struct FakeCompilerBackend final: CompilerToolBackend {
        CheckToolResult result {
            .success = true,
            .diagnostics = {},
            .sources = {},
            .fields = {},
            .facts = {},
            .plans = {},
        };
        std::optional<ToolFailure> failure;
        std::optional<CheckCommand> command;
        std::stop_token cancellation;
        std::uint32_t calls {};

        std::expected<CheckToolResult, ToolFailure> check(const CheckCommand &requested,
                                                          const std::stop_token token) override {
            ++calls;
            command = requested;
            cancellation = token;
            if (failure.has_value()) {
                return std::unexpected(*failure);
            }
            return result;
        }
    };

    struct FakePackagingBackend final: PackagingToolBackend {
        PackToolResult result {
            .success = true,
            .diagnostics = {},
            .sources = {},
            .fields = {},
            .generated_paths = {},
        };
        std::optional<ToolFailure> failure;
        std::optional<PackCommand> command;
        std::uint32_t calls {};

        std::expected<PackToolResult, ToolFailure> execute(const PackCommand &requested) override {
            ++calls;
            command = requested;
            if (failure.has_value()) {
                return std::unexpected(*failure);
            }
            return result;
        }
    };

    struct FakeAdminBackend final: AdminToolBackend {
        AdminToolResult result {
            .success = true,
            .diagnostics = {},
            .sources = {},
            .fields = {},
        };
        std::optional<ToolFailure> failure;
        std::optional<AdminCommand> command;
        std::uint32_t calls {};

        std::expected<AdminToolResult, ToolFailure> execute(const AdminCommand &requested) override {
            ++calls;
            command = requested;
            if (failure.has_value()) {
                return std::unexpected(*failure);
            }
            return result;
        }
    };

    struct RecordingControlPlaneAdapter final: LocalControlPlaneAdapter {
        std::optional<AdminEndpointConfiguration> endpoint;
        std::optional<AdminCommand> command;
        std::uint32_t calls {};

        std::expected<AdminToolResult, ToolFailure> execute(const AdminEndpointConfiguration &requested_endpoint,
                                                            const AdminCommand &requested_command) override {
            ++calls;
            endpoint = requested_endpoint;
            command = requested_command;
            return AdminToolResult {
                .success = true,
                .diagnostics = {},
                .sources = {},
                .fields = {{.name = "transport", .value = "local-adapter", .label = {}, .secret_reference = false}},
            };
        }
    };

    SourceDocument unicode_source() {
        return SourceDocument {
            .id = SourceId {"rules.main"},
            .path = "rules/main.py",
            .utf8 = "\xCE\xB1\n\xCE\xB2\n",
        };
    }

    Diagnostic example_diagnostic() {
        return Diagnostic {
            .code = "PY-TYPE-001",
            .severity = DiagnosticSeverity::error,
            .message = "expected bool; token=do-not-print",
            .span = SourceSpan {.source = SourceId {"rules.main"}, .begin_byte = 3, .end_byte = 5},
            .related = {{.span = SourceSpan {.source = SourceId {"rules.main"}, .begin_byte = 0, .end_byte = 2},
                         .message = "declared here"}},
        };
    }

    TEST_CASE("public tool exit codes and informational surfaces are stable") {
        STATIC_REQUIRE(static_cast<std::uint8_t>(ExitCode::success) == 0);
        STATIC_REQUIRE(static_cast<std::uint8_t>(ExitCode::operation_failed) == 1);
        STATIC_REQUIRE(static_cast<std::uint8_t>(ExitCode::command_line_error) == 2);
        STATIC_REQUIRE(static_cast<std::uint8_t>(ExitCode::unavailable) == 3);
        STATIC_REQUIRE(static_cast<std::uint8_t>(ExitCode::authentication_or_authorization_failed) == 4);
        STATIC_REQUIRE(static_cast<std::uint8_t>(ExitCode::internal_invariant_failed) == 5);

        FakeCompilerBackend compiler;
        const std::array help_arguments {std::string_view {"--help"}};
        const auto help = run_rule_engine_check(help_arguments, compiler);
        CHECK(help.exit_code == ExitCode::success);
        CHECK(help.standard_output.find("never imported or executed") != std::string::npos);
        CHECK(compiler.calls == 0);

        FakePackagingBackend packaging;
        const std::array version_arguments {std::string_view {"--version"}};
        const auto version = run_rule_engine_pack(version_arguments, packaging);
        CHECK(version.exit_code == ExitCode::success);
        CHECK(version.standard_output == "rule_engine_pack 1.0.0\n");
        CHECK(packaging.calls == 0);
    }

    TEST_CASE("portable process entrypoints preserve argv streams and stable exits") {
        char executable[] = "rule_engine_pack";
        char help[] = "--help";
        char *argument_values[] {executable, help, nullptr};
        const auto arguments = process_arguments(3, argument_values);
        REQUIRE(arguments.size() == 2U);
        CHECK(arguments[0] == "--help");
        CHECK(arguments[1].empty());

        FakePackagingBackend backend;
        const std::array help_arguments {std::string_view {"--help"}};
        std::ostringstream standard_output;
        std::ostringstream standard_error;
        CHECK(run_pack_process(help_arguments, backend, standard_output, standard_error) == 0);
        CHECK(standard_output.str().find("rule_engine_pack COMMAND") != std::string::npos);
        CHECK(standard_error.str().empty());
        CHECK(backend.calls == 0U);

        std::ostringstream failed_output;
        std::ostringstream writable_error;
        failed_output.setstate(std::ios::badbit);
        CHECK(
            write_command_output(
                CommandOutput {.exit_code = ExitCode::success, .standard_output = "not-written", .standard_error = {}},
                failed_output, writable_error) == static_cast<int>(ExitCode::internal_invariant_failed));
    }

    TEST_CASE("command-line failures use exit two and do not invoke a backend") {
        FakeCompilerBackend compiler;
        const std::array missing_pack {std::string_view {"--format"}, std::string_view {"yaml"}};
        const auto check = run_rule_engine_check(missing_pack, compiler);
        CHECK(check.exit_code == ExitCode::command_line_error);
        CHECK(check.standard_error.find("format must be") != std::string::npos);
        CHECK(compiler.calls == 0);

        FakePackagingBackend packaging;
        const std::array unknown {std::string_view {"explode"}, std::string_view {"rules"}};
        const auto pack = run_rule_engine_pack(unknown, packaging);
        CHECK(pack.exit_code == ExitCode::command_line_error);
        CHECK(packaging.calls == 0);

        FakeAdminBackend admin;
        const std::array missing {std::string_view {"--format"}};
        const auto admin_output = run_rule_engine_admin(missing, admin);
        CHECK(admin_output.exit_code == ExitCode::command_line_error);
        CHECK(admin.calls == 0);
    }

    TEST_CASE("UTF-8 byte spans render consistently in text JSON and SARIF") {
        const auto source = unicode_source();
        const auto diagnostic = example_diagnostic();
        const DiagnosticSet diagnostics {diagnostic};
        const std::array sources {source};

        const auto location = resolve_source_span(*diagnostic.span, sources);
        REQUIRE(location.has_value());
        CHECK(location->begin_byte == 3);
        CHECK(location->end_byte == 5);
        CHECK(location->start_line == 2);
        CHECK(location->start_column == 1);
        CHECK(location->end_line == 2);
        CHECK(location->end_column == 3);

        const auto text = render_diagnostics_text(diagnostics, sources);
        CHECK(text.find("rules/main.py:2:1: error PY-TYPE-001") != std::string::npos);
        CHECK(text.find("do-not-print") == std::string::npos);
        CHECK(text.find(redacted_value) != std::string::npos);

        const auto json = render_diagnostics_json(diagnostics, sources);
        CHECK(json.find("\"beginByte\":3") != std::string::npos);
        CHECK(json.find("\"startLine\":2") != std::string::npos);
        CHECK(json.find("do-not-print") == std::string::npos);

        const auto sarif = render_diagnostics_sarif(diagnostics, sources, "rule_engine_check");
        CHECK(sarif.find("\"version\":\"2.1.0\"") != std::string::npos);
        CHECK(sarif.find("\"byteOffset\":3") != std::string::npos);
        CHECK(sarif.find("\"byteLength\":2") != std::string::npos);
        CHECK(sarif.find("\"ruleId\":\"PY-TYPE-001\"") != std::string::npos);
    }

    TEST_CASE("check JSON distinguishes logical fact routes and physical prefetch plans") {
        FakeCompilerBackend backend;
        backend.result = CheckToolResult {
            .success = true,
            .diagnostics = {},
            .sources = {},
            .fields = {{.name = "semantic_hash", .value = "sha256:one", .label = {}, .secret_reference = false}},
            .facts = {{.executable = "rules.main.detect",
                       .logical_route = "process.signer.publisher",
                       .physical_prefetch = "process.signer",
                       .conditional = true}},
            .plans = {{.executable = "rules.main.detect",
                       .path = PlanPath::optimized,
                       .certificate_reason = "pure prefix proved false"}},
        };
        const std::array arguments {
            std::string_view {"--pack"},         std::string_view {"rules"},
            std::string_view {"--format=json"},  std::string_view {"--explain-facts"},
            std::string_view {"--explain-plan"},
        };

        const auto output = run_rule_engine_check(arguments, backend);

        CHECK(output.exit_code == ExitCode::success);
        CHECK(output.standard_output.find("rule-engine.check.v1") != std::string::npos);
        CHECK(output.standard_output.find("\"logicalRoute\":\"process.signer.publisher\"") != std::string::npos);
        CHECK(output.standard_output.find("\"physicalPrefetch\":\"process.signer\"") != std::string::npos);
        CHECK(output.standard_output.find("\"path\":\"optimized\"") != std::string::npos);
        REQUIRE(backend.command.has_value());
        CHECK(backend.command->explain_facts);
        CHECK(backend.command->explain_plan);
    }

    TEST_CASE("pack command models expose deterministic build sign verify inspect and stubs operations") {
        FakePackagingBackend backend;

        SECTION("build allows only a manifest-authorized generator") {
            const std::array arguments {
                std::string_view {"build"},    std::string_view {"rules"},
                std::string_view {"--output"}, std::string_view {"out.rpack"},
                std::string_view {"--signer"}, std::string_view {"vault:key-one"},
                std::string_view {"--key-id"}, std::string_view {"sha256:expected"},
            };
            const auto output = run_rule_engine_pack(arguments, backend);
            CHECK(output.exit_code == ExitCode::success);
            REQUIRE(backend.command.has_value());
            CHECK(backend.command->action == PackAction::build);
            CHECK(backend.command->generator_policy == GeneratorPolicy::manifest_authorized_only);
            CHECK(backend.command->signer_reference == "vault:key-one");
            CHECK(backend.command->requested_key_id == "sha256:expected");
            CHECK(output.standard_output.find("vault:key-one") == std::string::npos);
        }

        SECTION("non-build operations cannot request generator execution") {
            constexpr std::array actions {
                std::pair {std::string_view {"sign"}, PackAction::sign},
                std::pair {std::string_view {"verify"}, PackAction::verify},
                std::pair {std::string_view {"inspect"}, PackAction::inspect},
                std::pair {std::string_view {"stubs"}, PackAction::stubs},
            };
            for (const auto &[name, action] : actions) {
                backend.command.reset();
                const std::array arguments {name, std::string_view {"rules.rpack"}};
                const auto output = run_rule_engine_pack(arguments, backend);
                CHECK(output.exit_code == ExitCode::success);
                REQUIRE(backend.command.has_value());
                CHECK(backend.command->action == action);
                CHECK(backend.command->generator_policy == GeneratorPolicy::disabled);
            }
        }

        SECTION("a later production trust mode removes earlier development authorization") {
            const std::array arguments {
                std::string_view {"build"},       std::string_view {"rules"},        std::string_view {"--trust-mode"},
                std::string_view {"development"}, std::string_view {"--trust-mode"}, std::string_view {"production"},
            };
            const auto output = run_rule_engine_pack(arguments, backend);
            CHECK(output.exit_code == ExitCode::success);
            REQUIRE(backend.command.has_value());
            CHECK_FALSE(backend.command->development_unsigned);
        }
    }

    TEST_CASE("filesystem pack backend builds verifies inspects and emits only pinned SDK stubs") {
        TemporaryDirectory temporary;
        REQUIRE(temporary.created);
        const auto source = temporary.path / "source";
        const auto archive = temporary.path / "tooling.rpack";
        const auto stubs = temporary.path / "stubs";
        REQUIRE(write_static_smoke_source(source));

        FilesystemPackagingBackend backend {
            FilesystemToolDefaults {.sdk_root = std::filesystem::path {RULE_ENGINE_TOOLING_SDK_ROOT}}};
        PackCommand build;
        build.action = PackAction::build;
        build.input_path = source.string();
        build.output_path = archive.string();
        build.generator_policy = GeneratorPolicy::manifest_authorized_only;
        const auto built = backend.execute(build);
        REQUIRE(built.has_value());
        CHECK(built->success);
        CHECK(std::filesystem::is_regular_file(archive));

        PackCommand clobber_sign;
        clobber_sign.action = PackAction::sign;
        clobber_sign.input_path = archive.string();
        clobber_sign.output_path = archive.string();
        clobber_sign.signer_reference = "file:C:/must-not-be-opened.seed";
        const auto clobber_rejected = backend.execute(clobber_sign);
        REQUIRE_FALSE(clobber_rejected.has_value());
        CHECK(clobber_rejected.error().code == "PACK-OUTPUT");
        CHECK(packaging::read_canonical_source_pack(archive).has_value());

        PackCommand missing_signer;
        missing_signer.action = PackAction::sign;
        missing_signer.input_path = archive.string();
        missing_signer.output_path = (temporary.path / "signed.rpack").string();
        const auto signer_rejected = backend.execute(missing_signer);
        REQUIRE_FALSE(signer_rejected.has_value());
        CHECK(signer_rejected.error().code == "PACK-SIGNER");
        CHECK_FALSE(std::filesystem::exists(missing_signer.output_path));

        FilesystemCompilerBackend compiler_backend;
        CheckCommand check_without_runtime;
        check_without_runtime.pack_path = archive.string();
        check_without_runtime.development_unsigned = true;
        const auto runtime_required = compiler_backend.check(check_without_runtime, {});
        REQUIRE_FALSE(runtime_required.has_value());
        CHECK(runtime_required.error().kind == ToolFailureKind::unavailable_dependency);
        CHECK(runtime_required.error().code == "PY-RUNTIME");

        PackCommand verify;
        verify.action = PackAction::verify;
        verify.input_path = archive.string();
        verify.development_unsigned = true;
        const auto verified = backend.execute(verify);
        REQUIRE(verified.has_value());
        CHECK(verified->success);
        CHECK(std::ranges::find(verified->fields, std::string {"com.example.tooling-smoke"}, &DisplayField::value) !=
              verified->fields.end());

        PackCommand inspect = verify;
        inspect.action = PackAction::inspect;
        const auto inspected = backend.execute(inspect);
        REQUIRE(inspected.has_value());
        CHECK(std::ranges::find(inspected->fields, std::string {"none"}, &DisplayField::value) !=
              inspected->fields.end());

        PackCommand production = verify;
        production.development_unsigned = false;
        const auto rejected = backend.execute(production);
        REQUIRE_FALSE(rejected.has_value());
        CHECK(rejected.error().kind == ToolFailureKind::unavailable_dependency);

        PackCommand emit_stubs;
        emit_stubs.action = PackAction::stubs;
        emit_stubs.input_path = archive.string();
        emit_stubs.output_path = stubs.string();
        const auto emitted = backend.execute(emit_stubs);
        REQUIRE(emitted.has_value());
        CHECK(std::filesystem::is_regular_file(stubs / "manifest.json"));
        CHECK(std::filesystem::is_regular_file(stubs / "rule_engine/__init__.pyi"));
        CHECK(std::filesystem::is_regular_file(stubs / "rule_engine_generator/bindings.pyi"));
        CHECK_FALSE(std::filesystem::exists(stubs / "__pycache__"));

        const auto overwrite = backend.execute(emit_stubs);
        REQUIRE_FALSE(overwrite.has_value());
        CHECK(overwrite.error().code == "SDK-OUTPUT");
    }

    TEST_CASE("pack build rejects an unauthorized generator before resolving or launching Python") {
        TemporaryDirectory temporary;
        REQUIRE(temporary.created);
        auto manifest = static_smoke_manifest();
        manifest.generator = packaging::GeneratorDeclaration {
            .module = "tooling.generate",
            .callable = "generate",
            .lock_path = "generator.lock",
            .inputs = {},
        };
        const auto source = temporary.path / "source";
        REQUIRE(write_text_file(source / "rulepack.toml", packaging::canonical_manifest(manifest)));
        REQUIRE(write_text_file(source / "src/tooling/rules.py", "@rule_template(\"com.example.tooling.template\")\n"
                                                                 "def template() -> bool:\n"
                                                                 "    return True\n"));
        REQUIRE(write_text_file(source / "generator.lock", "format = 1\n"));
        REQUIRE(write_text_file(source / "generator/tooling/generate.py",
                                "raise RuntimeError(\"unauthorized generator executed\")\n"
                                "def generate(context):\n"
                                "    return None\n"));

        FilesystemPackagingBackend backend;
        PackCommand command;
        command.action = PackAction::build;
        command.input_path = source.string();
        command.output_path = (temporary.path / "generator.rpack").string();
        command.generator_policy = GeneratorPolicy::manifest_authorized_only;
        const auto rejected = backend.execute(command);
        REQUIRE_FALSE(rejected.has_value());
        CHECK(rejected.error().kind == ToolFailureKind::authorization);
        CHECK(rejected.error().code == "PACK-GENERATOR-AUTH");

        command.development_unsigned = true;
        const auto no_runtime = backend.execute(command);
        REQUIRE_FALSE(no_runtime.has_value());
        CHECK(no_runtime.error().kind == ToolFailureKind::unavailable_dependency);
        CHECK(no_runtime.error().code == "PY-RUNTIME");
    }

    TEST_CASE("real exact-runtime pack to check smoke preserves the shared compiler ABI") {
        TemporaryDirectory temporary;
        REQUIRE(temporary.created);
        const auto runtime =
            packaging::load_exact_private_runtime(std::filesystem::path {RULE_ENGINE_TOOLING_STAGED_RUNTIME_ROOT});
        if (!runtime.has_value()) {
            INFO(runtime.error().message);
        }
        REQUIRE(runtime.has_value());
        std::error_code filesystem_error;
        const auto worker_temporary_root = temporary.path / "workers";
        REQUIRE(std::filesystem::create_directory(worker_temporary_root, filesystem_error));
        REQUIRE_FALSE(filesystem_error);

        const auto source = temporary.path / "source";
        const auto archive = temporary.path / "tooling.rpack";
        REQUIRE(write_static_smoke_source(source));
        FilesystemPackagingBackend packaging_backend {
            FilesystemToolDefaults {.sdk_root = std::filesystem::path {RULE_ENGINE_TOOLING_SDK_ROOT}}};
        const std::string source_text = source.string();
        const std::string archive_text = archive.string();
        const std::array pack_arguments {
            std::string_view {"build"},       std::string_view {"--source"},      std::string_view {source_text},
            std::string_view {"--output"},    std::string_view {archive_text},    std::string_view {"--trust-mode"},
            std::string_view {"development"}, std::string_view {"--format=json"},
        };
        std::ostringstream pack_output;
        std::ostringstream pack_error;
        CHECK(run_pack_process(pack_arguments, packaging_backend, pack_output, pack_error) == 0);
        INFO(pack_output.str());
        INFO(pack_error.str());
        REQUIRE(std::filesystem::is_regular_file(archive));

        FilesystemCompilerBackend compiler_backend;
        const std::string staged_root_text = runtime->runtime_root.string();
        const std::string temporary_root_text = worker_temporary_root.string();
        const std::array check_arguments {
            std::string_view {"--pack"},           std::string_view {archive_text},
            std::string_view {"--runtime-root"},   std::string_view {staged_root_text},
            std::string_view {"--temporary-root"}, std::string_view {temporary_root_text},
            std::string_view {"--trust-mode"},     std::string_view {"development"},
            std::string_view {"--format=json"},    std::string_view {"--explain-plan"},
        };
        std::ostringstream check_output;
        std::ostringstream check_error;
        const auto check_exit =
            run_check_process(check_arguments, compiler_backend, check_output, check_error, nullptr);
        INFO(check_output.str());
        INFO(check_error.str());
        CHECK(check_exit == 0);
        CHECK(check_output.str().find("rule-engine.check.v1") != std::string::npos);
        CHECK(check_output.str().find("semantic_hash") != std::string::npos);
        CHECK(check_output.str().find("com.example.tooling.constant") != std::string::npos);
        CHECK(check_error.str().empty());
    }

    TEST_CASE("watch generations cancel predecessors and never publish stale or failed results") {
        CheckWatchCoordinator watch;
        auto first = watch.begin_generation();
        CHECK(first.generation == 1);
        CHECK_FALSE(first.cancellation.stop_requested());

        auto second = watch.begin_generation();
        CHECK(first.cancellation.stop_requested());
        CHECK(second.generation == 2);
        CHECK(watch.complete(
                  first,
                  CheckToolResult {
                      .success = true, .diagnostics = {}, .sources = {}, .fields = {}, .facts = {}, .plans = {}}) ==
              WatchCompletion::stale);
        CHECK_FALSE(watch.last_published().has_value());

        CHECK(watch.complete(
                  second,
                  CheckToolResult {
                      .success = false, .diagnostics = {}, .sources = {}, .fields = {}, .facts = {}, .plans = {}}) ==
              WatchCompletion::failed);
        CHECK_FALSE(watch.last_published().has_value());

        auto third = watch.begin_generation();
        CheckToolResult published {
            .success = true,
            .diagnostics = {},
            .sources = {},
            .fields = {},
            .facts = {},
            .plans = {},
        };
        published.fields.push_back(DisplayField {
            .name = "semantic_hash",
            .value = "sha256:three",
            .label = {},
            .secret_reference = false,
        });
        CHECK(watch.complete(third, published) == WatchCompletion::published);
        REQUIRE(watch.last_published().has_value());
        CHECK(watch.last_published()->fields.front().value == "sha256:three");

        auto fourth = watch.begin_generation();
        watch.cancel_current();
        CHECK(fourth.cancellation.stop_requested());
        CHECK(watch.complete(
                  fourth,
                  CheckToolResult {
                      .success = true, .diagnostics = {}, .sources = {}, .fields = {}, .facts = {}, .plans = {}}) ==
              WatchCompletion::cancelled);
        REQUIRE(watch.last_published().has_value());
        CHECK(watch.last_published()->fields.front().value == "sha256:three");
    }

    TEST_CASE("check watch passes a cancellable generation token to the compiler backend") {
        FakeCompilerBackend backend;
        CheckWatchCoordinator watch;
        const std::array arguments {std::string_view {"--pack=rules"}, std::string_view {"--watch"}};

        const auto output = run_rule_engine_check(arguments, backend, &watch);

        CHECK(output.exit_code == ExitCode::success);
        CHECK(backend.cancellation.stop_possible());
        CHECK(watch.current_generation() == 1);
        CHECK(watch.last_published().has_value());
    }

    TEST_CASE("admin command models preserve explicit idempotency and conservative preview semantics") {
        FakeAdminBackend backend;
        const std::array preview_arguments {
            std::string_view {"rollback"}, std::string_view {"pack.one"},       std::string_view {"--request-id=req-7"},
            std::string_view {"--reason"}, std::string_view {"incident INC-7"}, std::string_view {"--state"},
            std::string_view {"reset"},
        };

        const auto preview = run_rule_engine_admin(preview_arguments, backend);

        CHECK(preview.exit_code == ExitCode::success);
        REQUIRE(backend.command.has_value());
        CHECK(backend.command->action == AdminAction::rollback);
        CHECK(backend.command->preview);
        CHECK(backend.command->request_id == "req-7");
        CHECK(backend.command->reason == "incident INC-7");
        CHECK(backend.command->options.at("state") == "reset");
        CHECK(preview.standard_output.find("incident INC-7") == std::string::npos);

        backend.command.reset();
        const std::array apply_arguments {
            std::string_view {"purge"},
            std::string_view {"events"},
            std::string_view {"--apply"},
        };
        const auto applied = run_rule_engine_admin(apply_arguments, backend);
        CHECK(applied.exit_code == ExitCode::success);
        REQUIRE(backend.command.has_value());
        CHECK_FALSE(backend.command->preview);

        CHECK(admin_action_mutates(AdminAction::activate));
        CHECK_FALSE(admin_action_mutates(AdminAction::packs));
        CHECK(admin_action_defaults_to_preview(AdminAction::activate));
        CHECK(admin_action_defaults_to_preview(AdminAction::backfill));
        CHECK(admin_action_defaults_to_preview(AdminAction::stage));
    }

    TEST_CASE("filesystem admin backend requires canonical mTLS configuration and an injected transport") {
        TemporaryDirectory temporary;
        REQUIRE(temporary.created);
        REQUIRE(write_text_file(temporary.path / "client.pem", "client certificate\n"));
        REQUIRE(write_text_file(temporary.path / "client.key", "private key\n"));
        REQUIRE(write_text_file(temporary.path / "trust.pem", "trust bundle\n"));
        const auto configuration = temporary.path / "admin.conf";
        REQUIRE(write_text_file(configuration, "format=2\n"
                                               "endpoint=https://control.example.test/v1\n"
                                               "server_uri=urn:rule-engine:control:test\n"
                                               "client_certificate=client.pem\n"
                                               "client_key=client.key\n"
                                               "trust_bundle=trust.pem\n"));

        RecordingControlPlaneAdapter adapter;
        FilesystemAdminBackend backend {&adapter};
        const std::string configuration_text = configuration.string();
        const std::array valid_arguments {
            std::string_view {"packs"},         std::string_view {"active"},
            std::string_view {"--config"},      std::string_view {configuration_text},
            std::string_view {"--format=json"},
        };
        const auto accepted = run_rule_engine_admin(valid_arguments, backend);
        CHECK(accepted.exit_code == ExitCode::success);
        CHECK(accepted.standard_output.find("rule-engine.admin.v1") != std::string::npos);
        REQUIRE(adapter.endpoint.has_value());
        CHECK(adapter.endpoint->endpoint == "https://control.example.test/v1");
        CHECK(adapter.endpoint->server_uri == "urn:rule-engine:control:test");
        CHECK(adapter.endpoint->client_certificate == temporary.path / "client.pem");
        REQUIRE(adapter.command.has_value());
        CHECK(adapter.command->config_path == configuration_text);

        FilesystemAdminBackend unavailable;
        const auto no_transport = run_rule_engine_admin(valid_arguments, unavailable);
        CHECK(no_transport.exit_code == ExitCode::unavailable);

        const std::array missing_configuration {std::string_view {"packs"}, std::string_view {"active"}};
        const auto no_configuration = run_rule_engine_admin(missing_configuration, backend);
        CHECK(no_configuration.exit_code == ExitCode::unavailable);

        const auto invalid_configuration = temporary.path / "invalid.conf";
        REQUIRE(write_text_file(invalid_configuration, "format=2\n"
                                                       "endpoint=http://control.example.test\n"
                                                       "server_uri=urn:rule-engine:control:test\n"
                                                       "client_certificate=client.pem\n"
                                                       "client_key=client.key\n"
                                                       "trust_bundle=trust.pem\n"));
        const std::string invalid_text = invalid_configuration.string();
        const std::array invalid_arguments {
            std::string_view {"packs"},
            std::string_view {"active"},
            std::string_view {"--config"},
            std::string_view {invalid_text},
        };
        const auto invalid = run_rule_engine_admin(invalid_arguments, backend);
        CHECK(invalid.exit_code == ExitCode::authentication_or_authorization_failed);
        CHECK(adapter.calls == 1U);
    }

    TEST_CASE("configured trust files bind key identities and explicit relative crypto paths") {
        TemporaryDirectory temporary;
        REQUIRE(temporary.created);
        const auto crypto = temporary.path / "crypto.dll";
        REQUIRE(write_text_file(crypto, "test-only library placeholder\n"));
        const std::vector<std::byte> public_key(32U, std::byte {0x2a});
        std::string public_key_hex;
        for (std::size_t index = 0; index < public_key.size(); ++index) { public_key_hex += "2a"; }
        const auto key_id = "sha256:" + packaging::sha256_hex(public_key);
        const std::string trust_text = "format=1\nmode=production\ncrypto_library=crypto.dll\nsigner=" + key_id + '|' +
                                       public_key_hex + "|com.example.,org.example.|active\n";
        const auto trust = temporary.path / "trust.conf";
        REQUIRE(write_text_file(trust, trust_text));

        const auto loaded = load_trust_file(trust);
        REQUIRE(loaded.has_value());
        CHECK(loaded->crypto_library == crypto);
        REQUIRE(loaded->policy.signers.size() == 1U);
        CHECK(loaded->policy.signers.front().key_id == key_id);
        CHECK(loaded->policy.signers.front().allowed_pack_prefixes ==
              std::vector<std::string> {"com.example.", "org.example."});

        const auto wrong_key = temporary.path / "wrong-key.conf";
        REQUIRE(write_text_file(wrong_key,
                                "format=1\nmode=production\ncrypto_library=crypto.dll\n"
                                "signer=sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff|" +
                                    std::string(64U, '2') + "|com.example.|active\n"));
        const auto rejected = load_trust_file(wrong_key);
        REQUIRE_FALSE(rejected.has_value());
        CHECK(rejected.error().code == "TRUST-CONFIG");
    }

    TEST_CASE("all output formats redact labeled fields credentials and private material") {
        const DisplayField public_field {
            .name = "operation_id",
            .value = "op-1",
            .label = {},
            .secret_reference = false,
        };
        const DisplayField sensitive_field {
            .name = "payload",
            .value = "customer-value",
            .label = DataLabel {.classification = Classification::sensitive, .categories = {}},
            .secret_reference = false,
        };
        const DisplayField secret_name {
            .name = "connection_string",
            .value = "postgres://user:hunter2@db/rules",
            .label = {},
            .secret_reference = false,
        };
        const std::array fields {public_field, sensitive_field, secret_name};

        const auto text = render_fields_text(fields);
        CHECK(text.find("op-1") != std::string::npos);
        CHECK(text.find("customer-value") == std::string::npos);
        CHECK(text.find("hunter2") == std::string::npos);

        const auto json = render_fields_json(fields);
        CHECK(json.find("customer-value") == std::string::npos);
        CHECK(json.find("hunter2") == std::string::npos);

        const auto unstructured =
            redact_text("Authorization: Bearer abc.def password='open-sesame' postgres://alice:db-pass@db/rules\n"
                        "-----BEGIN PRIVATE KEY-----\nmaterial\n-----END PRIVATE KEY-----");
        CHECK(unstructured.find("abc.def") == std::string::npos);
        CHECK(unstructured.find("open-sesame") == std::string::npos);
        CHECK(unstructured.find("db-pass") == std::string::npos);
        CHECK(unstructured.find("material") == std::string::npos);
    }

    TEST_CASE("backend failures map to stable dependency authorization and invariant exits") {
        FakeAdminBackend backend;
        const std::array arguments {std::string_view {"packs"}, std::string_view {"active"}};

        backend.failure = ToolFailure {
            .kind = ToolFailureKind::unavailable_transport,
            .code = "ADMIN_UNAVAILABLE",
            .message = "connection failed password=hunter2",
            .diagnostics = {},
        };
        const auto unavailable = run_rule_engine_admin(arguments, backend);
        CHECK(unavailable.exit_code == ExitCode::unavailable);
        CHECK(unavailable.standard_output.find("hunter2") == std::string::npos);

        backend.failure->kind = ToolFailureKind::authorization;
        const auto unauthorized = run_rule_engine_admin(arguments, backend);
        CHECK(unauthorized.exit_code == ExitCode::authentication_or_authorization_failed);

        backend.failure->kind = ToolFailureKind::internal_invariant;
        const auto invariant = run_rule_engine_admin(arguments, backend);
        CHECK(invariant.exit_code == ExitCode::internal_invariant_failed);
    }

    TEST_CASE("operation diagnostics force exit one even when a backend marks its result successful") {
        FakeCompilerBackend backend;
        backend.result.success = true;
        backend.result.sources.push_back(unicode_source());
        backend.result.diagnostics.push_back(example_diagnostic());
        const std::array arguments {
            std::string_view {"--pack"},
            std::string_view {"rules"},
            std::string_view {"--format=sarif"},
        };

        const auto output = run_rule_engine_check(arguments, backend);

        CHECK(output.exit_code == ExitCode::operation_failed);
        CHECK(output.standard_output.find("PY-TYPE-001") != std::string::npos);
        CHECK(output.standard_output.find("do-not-print") == std::string::npos);
    }

} // namespace
