#include "rule_engine/python/tools/cli.hpp"

#include "rendering.hpp"
#include "rule_engine/python/tools/redaction.hpp"

#include <array>
#include <expected>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace rule_engine::python::tools {
    namespace {

        constexpr std::string_view check_help_text = R"(Usage: rule_engine_check --pack PATH [options]

Authoritatively compile and type-check a Python rule pack with the exact private runtime.
Static rule modules are parsed but never imported or executed.

Options:
  --pack PATH          Source tree or source-only pack
  --runtime-root PATH  Staged exact private CPython 3.14.6 runtime
  --trust-config PATH  Production signer policy and explicit OpenSSL path
  --trust-mode MODE    production or development (default: production)
  --temporary-root PATH  Worker scratch directory
  --watch              Cancel stale checks and publish only the latest complete result
  --format FORMAT      text, json, or sarif (default: text)
  --explain-facts      Show logical fact routes separately from physical prefetch
  --explain-plan       Show exact/optimized selection and certificate reasons
  --help               Show this help
  --version            Show the tool API version
)";

        constexpr std::string_view pack_help_text = R"(Usage: rule_engine_pack COMMAND PATH [options]

Build and inspect deterministic source-only Python rule packs. Generator-free build validates
packaging without requiring CPython; rule_engine_check owns static-language validation.
Static rule modules are never imported or executed.

Commands:
  build                Canonicalize, validate, optionally run an authorized generator twice, and build
  verify               Verify archive, digest closure, runtime pins, and signature policy
  inspect              Emit a redacted canonical summary
  stubs                Emit PEP 561 and typed binding stubs

Options:
  --source PATH        Source directory (equivalent to positional PATH)
  --output PATH        Output archive or stub directory
  --signer REF         External signer/key-provider reference (never printed)
  --runtime-root PATH  Staged exact private CPython 3.14.6 runtime
  --sdk-root PATH      Tracked, manifest-verified author SDK
  --trust-config PATH  Production signer policy and explicit OpenSSL path
  --trust-mode MODE    production or development (default: production)
  --temporary-root PATH  Worker scratch directory
  --format FORMAT      text, json, or sarif (default: text)
  --help               Show this help
  --version            Show the tool API version
)";

        constexpr std::string_view admin_help_text = R"(Usage: rule_engine_admin COMMAND [OPERANDS] [options]

Operate the authenticated, audited Python rule-engine control plane.

Commands:
  upload stage activate rollback operation packs nodes policy quarantine trace
  capture backfill outbox deadletters purge audit

Options:
  --config PATH        Authenticated endpoint, client certificate/key, and trust bundle
  --request-id ID      Idempotent request identity for mutations
  --reason TEXT        Audited operator reason (never echoed)
  --wait               Wait by polling the durable operation record
  --preview            Force preview/dry-run
  --apply              Explicitly apply a command that defaults to preview
  --format FORMAT      text, json, or sarif (default: text)
  --help               Show this help
  --version            Show the tool API version
)";

        struct ParseError {
            std::string message;
        };

        [[nodiscard]] bool is_option(const std::string_view value) noexcept { return value.starts_with("--"); }

        [[nodiscard]] std::optional<std::string_view> inline_option_value(const std::string_view argument,
                                                                          const std::string_view name) noexcept {
            if (!argument.starts_with(name) || argument.size() <= name.size() || argument[name.size()] != '=') {
                return std::nullopt;
            }
            return argument.substr(name.size() + 1U);
        }

        [[nodiscard]] std::expected<std::string_view, ParseError>
        required_option_value(const std::span<const std::string_view> arguments, std::size_t &index,
                              const std::string_view option) {
            if (index + 1U >= arguments.size() || is_option(arguments[index + 1U])) {
                return std::unexpected(ParseError {.message = std::string {option} + " requires a value"});
            }
            ++index;
            return arguments[index];
        }

        [[nodiscard]] CommandOutput usage_error(const std::string_view tool, const std::string_view message) {
            return CommandOutput {
                .exit_code = ExitCode::command_line_error,
                .standard_output = {},
                .standard_error =
                    "error: " + redact_text(message) + "\nTry '" + std::string {tool} + " --help' for usage.\n",
            };
        }

        [[nodiscard]] CommandOutput help_output(const std::string_view help) {
            return CommandOutput {
                .exit_code = ExitCode::success,
                .standard_output = std::string {help},
                .standard_error = {},
            };
        }

        [[nodiscard]] CommandOutput version_output(const std::string_view tool) {
            return CommandOutput {
                .exit_code = ExitCode::success,
                .standard_output = std::string {tool} + ' ' + tools_api_version + '\n',
                .standard_error = {},
            };
        }

        [[nodiscard]] Diagnostic failure_diagnostic(const ToolFailure &failure) {
            return Diagnostic {
                .code = failure.code.empty() ? "TOOL_FAILURE" : failure.code,
                .severity = DiagnosticSeverity::error,
                .message = failure.message,
                .span = std::nullopt,
                .related = {},
            };
        }

        [[nodiscard]] std::string render_diagnostics(const OutputFormat format, const DiagnosticSet &diagnostics,
                                                     const std::span<const SourceDocument> sources,
                                                     const std::string_view tool_name) {
            switch (format) {
                case OutputFormat::text: return render_diagnostics_text(diagnostics, sources);
                case OutputFormat::json: return render_diagnostics_json(diagnostics, sources);
                case OutputFormat::sarif: return render_diagnostics_sarif(diagnostics, sources, tool_name);
                default: return render_diagnostics_text(diagnostics, sources);
            }
        }

        [[nodiscard]] CommandOutput backend_failure(const ToolFailure &failure, const OutputFormat format,
                                                    const std::string_view tool_name) {
            auto diagnostics = failure.diagnostics;
            if (diagnostics.empty()) {
                diagnostics.push_back(failure_diagnostic(failure));
            }
            return CommandOutput {
                .exit_code = exit_code_for(failure),
                .standard_output = render_diagnostics(format, diagnostics, {}, tool_name),
                .standard_error = {},
            };
        }

        [[nodiscard]] std::string render_pack_json(const PackToolResult &result) {
            std::ostringstream output;
            output << R"({"schema":"rule-engine.pack.v1","success":)" << (result.success ? "true" : "false")
                   << ",\"fields\":" << render_fields_json(result.fields) << ",\"generatedPaths\":[";
            for (std::size_t index = 0; index < result.generated_paths.size(); ++index) {
                if (index != 0) {
                    output << ',';
                }
                output << detail::json_quote(redact_text(result.generated_paths[index]));
            }
            output << "],\"diagnostics\":" << render_diagnostics_json(result.diagnostics, result.sources) << "}\n";
            return output.str();
        }

        [[nodiscard]] std::string render_pack_text(const PackToolResult &result) {
            auto output = render_diagnostics_text(result.diagnostics, result.sources);
            output += render_fields_text(result.fields);
            for (const auto &path : result.generated_paths) { output += "generated: " + redact_text(path) + '\n'; }
            return output;
        }

        [[nodiscard]] std::string render_check_text(const CheckToolResult &result, const CheckCommand &command) {
            auto output = render_diagnostics_text(result.diagnostics, result.sources);
            output += render_fields_text(result.fields);
            if (command.explain_facts) {
                for (const auto &fact : result.facts) {
                    output += "fact " + redact_text(fact.executable) + ": logical=" + redact_text(fact.logical_route) +
                              " physical-prefetch=" + redact_text(fact.physical_prefetch) +
                              " conditional=" + (fact.conditional ? "true\n" : "false\n");
                }
            }
            if (command.explain_plan) {
                for (const auto &plan : result.plans) {
                    output += "plan " + redact_text(plan.executable) +
                              ": path=" + std::string {plan.path == PlanPath::exact ? "exact" : "optimized"} +
                              " certificate=" + redact_text(plan.certificate_reason) + '\n';
                }
            }
            return output;
        }

        [[nodiscard]] std::string render_check_json(const CheckToolResult &result, const CheckCommand &command) {
            std::ostringstream output;
            output << R"({"schema":"rule-engine.check.v1","success":)" << (result.success ? "true" : "false")
                   << ",\"fields\":" << render_fields_json(result.fields) << ",\"facts\":[";
            if (command.explain_facts) {
                for (std::size_t index = 0; index < result.facts.size(); ++index) {
                    if (index != 0) {
                        output << ',';
                    }
                    const auto &fact = result.facts[index];
                    output << "{\"executable\":" << detail::json_quote(redact_text(fact.executable))
                           << ",\"logicalRoute\":" << detail::json_quote(redact_text(fact.logical_route))
                           << ",\"physicalPrefetch\":" << detail::json_quote(redact_text(fact.physical_prefetch))
                           << ",\"conditional\":" << (fact.conditional ? "true" : "false") << '}';
                }
            }
            output << "],\"plans\":[";
            if (command.explain_plan) {
                for (std::size_t index = 0; index < result.plans.size(); ++index) {
                    if (index != 0) {
                        output << ',';
                    }
                    const auto &plan = result.plans[index];
                    output << "{\"executable\":" << detail::json_quote(redact_text(plan.executable))
                           << ",\"path\":" << detail::json_quote(plan.path == PlanPath::exact ? "exact" : "optimized")
                           << ",\"certificateReason\":" << detail::json_quote(redact_text(plan.certificate_reason))
                           << '}';
                }
            }
            output << "],\"diagnostics\":" << render_diagnostics_json(result.diagnostics, result.sources) << "}\n";
            return output.str();
        }

        [[nodiscard]] std::string render_admin_text(const AdminToolResult &result) {
            auto output = render_diagnostics_text(result.diagnostics, result.sources);
            output += render_fields_text(result.fields);
            return output;
        }

        [[nodiscard]] std::string render_admin_json(const AdminToolResult &result) {
            std::ostringstream output;
            output << R"({"schema":"rule-engine.admin.v1","success":)" << (result.success ? "true" : "false")
                   << ",\"fields\":" << render_fields_json(result.fields)
                   << ",\"diagnostics\":" << render_diagnostics_json(result.diagnostics, result.sources) << "}\n";
            return output.str();
        }

        [[nodiscard]] std::expected<PackAction, ParseError> parse_pack_action(const std::string_view value) {
            if (value == "build") {
                return PackAction::build;
            }
            if (value == "verify") {
                return PackAction::verify;
            }
            if (value == "inspect") {
                return PackAction::inspect;
            }
            if (value == "stubs") {
                return PackAction::stubs;
            }
            return std::unexpected(ParseError {.message = "unknown pack command '" + std::string {value} + "'"});
        }

        [[nodiscard]] std::expected<AdminAction, ParseError> parse_admin_action(const std::string_view value) {
            constexpr std::array actions {
                std::pair {"upload", AdminAction::upload},         std::pair {"stage", AdminAction::stage},
                std::pair {"activate", AdminAction::activate},     std::pair {"rollback", AdminAction::rollback},
                std::pair {"operation", AdminAction::operation},   std::pair {"packs", AdminAction::packs},
                std::pair {"nodes", AdminAction::nodes},           std::pair {"policy", AdminAction::policy},
                std::pair {"quarantine", AdminAction::quarantine}, std::pair {"trace", AdminAction::trace},
                std::pair {"capture", AdminAction::capture},       std::pair {"backfill", AdminAction::backfill},
                std::pair {"outbox", AdminAction::outbox},         std::pair {"deadletters", AdminAction::deadletters},
                std::pair {"purge", AdminAction::purge},           std::pair {"audit", AdminAction::audit},
            };
            for (const auto &[name, action] : actions) {
                if (value == name) {
                    return action;
                }
            }
            return std::unexpected(ParseError {.message = "unknown admin command '" + std::string {value} + "'"});
        }

        [[nodiscard]] std::expected<CheckCommand, ParseError>
        parse_check_command(const std::span<const std::string_view> arguments) {
            CheckCommand command;
            for (std::size_t index = 0; index < arguments.size(); ++index) {
                const auto argument = arguments[index];
                if (argument == "--watch") {
                    command.watch = true;
                    continue;
                }
                if (argument == "--explain-facts") {
                    command.explain_facts = true;
                    continue;
                }
                if (argument == "--explain-plan") {
                    command.explain_plan = true;
                    continue;
                }
                if (argument == "--pack") {
                    const auto value = required_option_value(arguments, index, argument);
                    if (!value.has_value()) {
                        return std::unexpected(value.error());
                    }
                    command.pack_path = *value;
                    continue;
                }
                if (const auto value = inline_option_value(argument, "--pack"); value.has_value()) {
                    command.pack_path = *value;
                    continue;
                }
                if (argument == "--runtime-root" || argument == "--trust-config" || argument == "--temporary-root" ||
                    argument == "--trust-mode") {
                    const auto value = required_option_value(arguments, index, argument);
                    if (!value.has_value()) {
                        return std::unexpected(value.error());
                    }
                    if (argument == "--runtime-root") {
                        command.runtime_root = *value;
                    } else if (argument == "--trust-config") {
                        command.trust_config_path = *value;
                    } else if (argument == "--temporary-root") {
                        command.temporary_root = *value;
                    } else if (*value == "development") {
                        command.development_unsigned = true;
                    } else if (*value == "production") {
                        command.development_unsigned = false;
                    } else {
                        return std::unexpected(ParseError {.message = "trust mode must be production or development"});
                    }
                    continue;
                }
                if (const auto value = inline_option_value(argument, "--runtime-root"); value.has_value()) {
                    command.runtime_root = *value;
                    continue;
                }
                if (const auto value = inline_option_value(argument, "--trust-config"); value.has_value()) {
                    command.trust_config_path = *value;
                    continue;
                }
                if (const auto value = inline_option_value(argument, "--temporary-root"); value.has_value()) {
                    command.temporary_root = *value;
                    continue;
                }
                if (const auto value = inline_option_value(argument, "--trust-mode"); value.has_value()) {
                    if (*value == "development") {
                        command.development_unsigned = true;
                    } else if (*value == "production") {
                        command.development_unsigned = false;
                    } else {
                        return std::unexpected(ParseError {.message = "trust mode must be production or development"});
                    }
                    continue;
                }
                if (argument == "--format") {
                    const auto value = required_option_value(arguments, index, argument);
                    if (!value.has_value()) {
                        return std::unexpected(value.error());
                    }
                    const auto format = parse_output_format(*value);
                    if (!format.has_value()) {
                        return std::unexpected(ParseError {.message = format.error()});
                    }
                    command.format = *format;
                    continue;
                }
                if (const auto value = inline_option_value(argument, "--format"); value.has_value()) {
                    const auto format = parse_output_format(*value);
                    if (!format.has_value()) {
                        return std::unexpected(ParseError {.message = format.error()});
                    }
                    command.format = *format;
                    continue;
                }
                return std::unexpected(ParseError {.message = "unknown check option '" + std::string {argument} + "'"});
            }
            if (command.pack_path.empty()) {
                return std::unexpected(ParseError {.message = "--pack PATH is required"});
            }
            return command;
        }

        [[nodiscard]] std::expected<PackCommand, ParseError>
        parse_pack_command(const std::span<const std::string_view> arguments) {
            if (arguments.empty()) {
                return std::unexpected(ParseError {.message = "a pack command is required"});
            }
            const auto action = parse_pack_action(arguments.front());
            if (!action.has_value()) {
                return std::unexpected(action.error());
            }
            PackCommand command;
            command.action = *action;
            command.generator_policy =
                *action == PackAction::build ? GeneratorPolicy::manifest_authorized_only : GeneratorPolicy::disabled;

            for (std::size_t index = 1; index < arguments.size(); ++index) {
                const auto argument = arguments[index];
                if (argument == "--output" || argument == "--signer" || argument == "--format" ||
                    argument == "--source" || argument == "--runtime-root" || argument == "--sdk-root" ||
                    argument == "--trust-config" || argument == "--trust-mode" || argument == "--temporary-root") {
                    const auto value = required_option_value(arguments, index, argument);
                    if (!value.has_value()) {
                        return std::unexpected(value.error());
                    }
                    if (argument == "--output") {
                        command.output_path = *value;
                    } else if (argument == "--signer") {
                        command.signer_reference = *value;
                    } else if (argument == "--source") {
                        command.input_path = *value;
                    } else if (argument == "--runtime-root") {
                        command.runtime_root = *value;
                    } else if (argument == "--sdk-root") {
                        command.sdk_root = *value;
                    } else if (argument == "--trust-config") {
                        command.trust_config_path = *value;
                    } else if (argument == "--temporary-root") {
                        command.temporary_root = *value;
                    } else if (argument == "--trust-mode") {
                        if (*value == "development") {
                            command.development_unsigned = true;
                        } else if (*value == "production") {
                            command.development_unsigned = false;
                        } else {
                            return std::unexpected(
                                ParseError {.message = "trust mode must be production or development"});
                        }
                    } else {
                        const auto format = parse_output_format(*value);
                        if (!format.has_value()) {
                            return std::unexpected(ParseError {.message = format.error()});
                        }
                        command.format = *format;
                    }
                    continue;
                }
                if (const auto value = inline_option_value(argument, "--output"); value.has_value()) {
                    command.output_path = *value;
                    continue;
                }
                if (const auto value = inline_option_value(argument, "--signer"); value.has_value()) {
                    command.signer_reference = *value;
                    continue;
                }
                if (const auto value = inline_option_value(argument, "--source"); value.has_value()) {
                    command.input_path = *value;
                    continue;
                }
                if (const auto value = inline_option_value(argument, "--runtime-root"); value.has_value()) {
                    command.runtime_root = *value;
                    continue;
                }
                if (const auto value = inline_option_value(argument, "--sdk-root"); value.has_value()) {
                    command.sdk_root = *value;
                    continue;
                }
                if (const auto value = inline_option_value(argument, "--trust-config"); value.has_value()) {
                    command.trust_config_path = *value;
                    continue;
                }
                if (const auto value = inline_option_value(argument, "--temporary-root"); value.has_value()) {
                    command.temporary_root = *value;
                    continue;
                }
                if (const auto value = inline_option_value(argument, "--trust-mode"); value.has_value()) {
                    if (*value == "development") {
                        command.development_unsigned = true;
                    } else if (*value == "production") {
                        command.development_unsigned = false;
                    } else {
                        return std::unexpected(ParseError {.message = "trust mode must be production or development"});
                    }
                    continue;
                }
                if (const auto value = inline_option_value(argument, "--format"); value.has_value()) {
                    const auto format = parse_output_format(*value);
                    if (!format.has_value()) {
                        return std::unexpected(ParseError {.message = format.error()});
                    }
                    command.format = *format;
                    continue;
                }
                if (is_option(argument)) {
                    return std::unexpected(
                        ParseError {.message = "unknown pack option '" + std::string {argument} + "'"});
                }
                if (!command.input_path.empty()) {
                    return std::unexpected(ParseError {.message = "only one input path is allowed"});
                }
                command.input_path = argument;
            }
            if (command.input_path.empty()) {
                return std::unexpected(ParseError {.message = "an input path is required"});
            }
            return command;
        }

        [[nodiscard]] std::expected<AdminCommand, ParseError>
        parse_admin_command(const std::span<const std::string_view> arguments) {
            if (arguments.empty()) {
                return std::unexpected(ParseError {.message = "an admin command is required"});
            }
            const auto action = parse_admin_action(arguments.front());
            if (!action.has_value()) {
                return std::unexpected(action.error());
            }
            AdminCommand command;
            command.action = *action;
            command.preview = admin_action_defaults_to_preview(*action);
            for (std::size_t index = 1; index < arguments.size(); ++index) {
                const auto argument = arguments[index];
                if (argument == "--wait") {
                    command.wait = true;
                    continue;
                }
                if (argument == "--preview") {
                    command.preview = true;
                    continue;
                }
                if (argument == "--apply") {
                    command.preview = false;
                    continue;
                }
                if (argument == "--request-id" || argument == "--reason" || argument == "--format" ||
                    argument == "--config") {
                    const auto value = required_option_value(arguments, index, argument);
                    if (!value.has_value()) {
                        return std::unexpected(value.error());
                    }
                    if (argument == "--request-id") {
                        command.request_id = *value;
                    } else if (argument == "--reason") {
                        command.reason = *value;
                    } else if (argument == "--config") {
                        command.config_path = *value;
                    } else {
                        const auto format = parse_output_format(*value);
                        if (!format.has_value()) {
                            return std::unexpected(ParseError {.message = format.error()});
                        }
                        command.format = *format;
                    }
                    continue;
                }
                if (const auto value = inline_option_value(argument, "--request-id"); value.has_value()) {
                    command.request_id = *value;
                    continue;
                }
                if (const auto value = inline_option_value(argument, "--reason"); value.has_value()) {
                    command.reason = *value;
                    continue;
                }
                if (const auto value = inline_option_value(argument, "--config"); value.has_value()) {
                    command.config_path = *value;
                    continue;
                }
                if (const auto value = inline_option_value(argument, "--format"); value.has_value()) {
                    const auto format = parse_output_format(*value);
                    if (!format.has_value()) {
                        return std::unexpected(ParseError {.message = format.error()});
                    }
                    command.format = *format;
                    continue;
                }
                if (is_option(argument)) {
                    const auto key = std::string {argument.substr(2)};
                    if (key.empty()) {
                        return std::unexpected(ParseError {.message = "empty option name"});
                    }
                    if (index + 1U < arguments.size() && !is_option(arguments[index + 1U])) {
                        command.options.emplace(key, std::string {arguments[++index]});
                    } else {
                        command.options.emplace(key, "true");
                    }
                    continue;
                }
                command.operands.emplace_back(argument);
            }
            return command;
        }

    } // namespace

    std::string_view check_help() noexcept { return check_help_text; }

    std::string_view pack_help() noexcept { return pack_help_text; }

    std::string_view admin_help() noexcept { return admin_help_text; }

    CommandOutput run_rule_engine_check(const std::span<const std::string_view> arguments, CompilerToolBackend &backend,
                                        CheckWatchCoordinator *watch) {
        if (arguments.size() == 1 && arguments.front() == "--help") {
            return help_output(check_help());
        }
        if (arguments.size() == 1 && arguments.front() == "--version") {
            return version_output("rule_engine_check");
        }

        const auto parsed = parse_check_command(arguments);
        if (!parsed.has_value()) {
            return usage_error("rule_engine_check", parsed.error().message);
        }
        const auto &command = *parsed;

        std::optional<WatchTicket> ticket;
        std::stop_token cancellation;
        CheckWatchCoordinator local_watch;
        auto *coordinator = watch == nullptr ? &local_watch : watch;
        if (command.watch) {
            ticket = coordinator->begin_generation();
            cancellation = ticket->cancellation;
        }

        auto result = backend.check(command, cancellation);
        if (!result.has_value()) {
            return backend_failure(result.error(), command.format, "rule_engine_check");
        }

        if (ticket.has_value()) {
            const auto completion = coordinator->complete(*ticket, *result);
            if (completion == WatchCompletion::stale || completion == WatchCompletion::cancelled) {
                return CommandOutput {
                    .exit_code = ExitCode::success,
                    .standard_output = {},
                    .standard_error = "check generation cancelled before publication\n",
                };
            }
        }

        CommandOutput output;
        output.exit_code =
            result->success && !has_errors(result->diagnostics) ? ExitCode::success : ExitCode::operation_failed;
        switch (command.format) {
            case OutputFormat::text: output.standard_output = render_check_text(*result, command); break;
            case OutputFormat::json: output.standard_output = render_check_json(*result, command); break;
            case OutputFormat::sarif:
                output.standard_output =
                    render_diagnostics_sarif(result->diagnostics, result->sources, "rule_engine_check");
                break;
            default: output.standard_output = render_check_text(*result, command); break;
        }
        return output;
    }

    CommandOutput run_rule_engine_pack(const std::span<const std::string_view> arguments,
                                       PackagingToolBackend &backend) {
        if (arguments.size() == 1 && arguments.front() == "--help") {
            return help_output(pack_help());
        }
        if (arguments.size() == 1 && arguments.front() == "--version") {
            return version_output("rule_engine_pack");
        }

        const auto parsed = parse_pack_command(arguments);
        if (!parsed.has_value()) {
            return usage_error("rule_engine_pack", parsed.error().message);
        }
        const auto &command = *parsed;
        auto result = backend.execute(command);
        if (!result.has_value()) {
            return backend_failure(result.error(), command.format, "rule_engine_pack");
        }

        CommandOutput output;
        output.exit_code =
            result->success && !has_errors(result->diagnostics) ? ExitCode::success : ExitCode::operation_failed;
        switch (command.format) {
            case OutputFormat::text: output.standard_output = render_pack_text(*result); break;
            case OutputFormat::json: output.standard_output = render_pack_json(*result); break;
            case OutputFormat::sarif:
                output.standard_output =
                    render_diagnostics_sarif(result->diagnostics, result->sources, "rule_engine_pack");
                break;
            default: output.standard_output = render_pack_text(*result); break;
        }
        return output;
    }

    CommandOutput run_rule_engine_admin(const std::span<const std::string_view> arguments, AdminToolBackend &backend) {
        if (arguments.size() == 1 && arguments.front() == "--help") {
            return help_output(admin_help());
        }
        if (arguments.size() == 1 && arguments.front() == "--version") {
            return version_output("rule_engine_admin");
        }

        const auto parsed = parse_admin_command(arguments);
        if (!parsed.has_value()) {
            return usage_error("rule_engine_admin", parsed.error().message);
        }
        const auto &command = *parsed;
        auto result = backend.execute(command);
        if (!result.has_value()) {
            return backend_failure(result.error(), command.format, "rule_engine_admin");
        }

        CommandOutput output;
        output.exit_code =
            result->success && !has_errors(result->diagnostics) ? ExitCode::success : ExitCode::operation_failed;
        switch (command.format) {
            case OutputFormat::text: output.standard_output = render_admin_text(*result); break;
            case OutputFormat::json: output.standard_output = render_admin_json(*result); break;
            case OutputFormat::sarif:
                output.standard_output =
                    render_diagnostics_sarif(result->diagnostics, result->sources, "rule_engine_admin");
                break;
            default: output.standard_output = render_admin_text(*result); break;
        }
        return output;
    }

} // namespace rule_engine::python::tools
