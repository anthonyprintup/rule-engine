#include "rule_engine/python/tools.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstdint>
#include <expected>
#include <optional>
#include <stop_token>
#include <string>
#include <string_view>
#include <utility>

namespace {

    using namespace rule_engine::python;
    using namespace rule_engine::python::tools;

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
        CHECK(help.standard_output.find("rule modules are never imported or executed") != std::string::npos);
        CHECK(compiler.calls == 0);

        FakePackagingBackend packaging;
        const std::array version_arguments {std::string_view {"--version"}};
        const auto version = run_rule_engine_pack(version_arguments, packaging);
        CHECK(version.exit_code == ExitCode::success);
        CHECK(version.standard_output == "rule_engine_pack 1.0.0\n");
        CHECK(packaging.calls == 0);
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

    TEST_CASE("pack command models expose deterministic build verify inspect and stubs operations") {
        FakePackagingBackend backend;

        SECTION("build allows only a manifest-authorized generator") {
            const std::array arguments {
                std::string_view {"build"},     std::string_view {"rules"},    std::string_view {"--output"},
                std::string_view {"out.rpack"}, std::string_view {"--signer"}, std::string_view {"vault:key-one"},
            };
            const auto output = run_rule_engine_pack(arguments, backend);
            CHECK(output.exit_code == ExitCode::success);
            REQUIRE(backend.command.has_value());
            CHECK(backend.command->action == PackAction::build);
            CHECK(backend.command->generator_policy == GeneratorPolicy::manifest_authorized_only);
            CHECK(backend.command->signer_reference == "vault:key-one");
            CHECK(output.standard_output.find("vault:key-one") == std::string::npos);
        }

        SECTION("non-build operations cannot request generator execution") {
            constexpr std::array actions {
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
        CHECK(admin_action_defaults_to_preview(AdminAction::backfill));
        CHECK_FALSE(admin_action_defaults_to_preview(AdminAction::stage));
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
