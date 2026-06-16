#include <rule_engine/compiler.hpp>
#include <rule_engine/modules.hpp>
#include <rule_engine/client_protocol.hpp>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <fmt/format.h>

#include <charconv>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace {
    [[nodiscard]] bool parse_port(const std::string_view text, std::uint16_t &out) noexcept {
        std::uint32_t value {};
        const auto *first = text.data();
        const auto *last = first + text.size();
        const auto [ptr, ec] = std::from_chars(first, last, value);
        if (ec != std::errc {} || ptr != last || value > 65535u) {
            return false;
        }
        out = static_cast<std::uint16_t>(value);
        return true;
    }

    [[nodiscard]] bool parse_size(const std::string_view text, std::size_t &out) noexcept {
        std::size_t value {};
        const auto *first = text.data();
        const auto *last = first + text.size();
        const auto [ptr, ec] = std::from_chars(first, last, value);
        if (ec != std::errc {} || ptr != last || value == 0u) {
            return false;
        }
        out = value;
        return true;
    }

    [[nodiscard]] bool parse_milliseconds(const std::string_view text, std::chrono::milliseconds &out) noexcept {
        std::uint32_t value {};
        const auto *first = text.data();
        const auto *last = first + text.size();
        const auto [ptr, ec] = std::from_chars(first, last, value);
        if (ec != std::errc {} || ptr != last || value == 0u) {
            return false;
        }
        out = std::chrono::milliseconds {static_cast<std::chrono::milliseconds::rep>(value)};
        return true;
    }

    [[nodiscard]] bool wants_help(const std::string_view arg) noexcept {
        return arg == "--help" || arg == "-h";
    }

    [[nodiscard]] std::string status_name(const rule_engine::FactStatus status) {
        switch (status) {
            case rule_engine::FactStatus::missing: return "missing";
            case rule_engine::FactStatus::available: return "available";
            case rule_engine::FactStatus::unavailable: return "unavailable";
            case rule_engine::FactStatus::access_denied: return "access_denied";
            case rule_engine::FactStatus::timed_out: return "timed_out";
            default: return "unknown";
        }
    }

    [[nodiscard]] std::string value_text(const rule_engine::Value &value) {
        if (value.is_undefined()) {
            return "undefined";
        }
        if (const auto boolean = value.as_bool(); boolean.has_value()) {
            return *boolean ? "true" : "false";
        }
        if (const auto integer = value.as_i64(); integer.has_value()) {
            return std::to_string(*integer);
        }
        if (const auto floating = value.as_f64(); floating.has_value()) {
            return std::to_string(*floating);
        }
        if (const auto *text = value.as_string(); text != nullptr) {
            return *text;
        }
        return "<complex>";
    }

    void print_errors(const rule_engine::ErrorSet &errors) {
        for (const auto &diagnostic : errors.diagnostics) {
            fmt::print(stderr, "{}\n", diagnostic.message);
        }
    }

    void print_rule_diagnostics(const rule_engine::ErrorSet &errors) {
        for (const auto &diagnostic : errors.diagnostics) {
            fmt::print(stderr, "{}:{}: {}\n", diagnostic.source, diagnostic.span.start, diagnostic.message);
        }
    }

    void print_usage() {
        fmt::print(stderr,
                   "usage: rule_engine_server [--host <host>] [--port <port>] [-I <dir>] [--rule <rule.yar>] "
                   "[--all-subjects] [--subject-concurrency <n>] [--io-timeout-ms <ms>]\n");
    }
} // namespace

int main(int argc, char **argv) {
    std::uint16_t port {31337};
    std::size_t subject_concurrency {1};
    std::chrono::milliseconds io_timeout {5000};
    std::string host {"127.0.0.1"};
    rule_engine::ParseOptions parse_options;
    std::filesystem::path rule_path;
    bool all_subjects {};
    for (int index = 1; index < argc; ++index) {
        const std::string_view arg {argv[index]};
        if (wants_help(arg)) {
            print_usage();
            return 0;
        }
        if ((arg == "--host" || arg == "-H") && index + 1 < argc) {
            ++index;
            host = argv[index];
            continue;
        }
        if ((arg == "--port" || arg == "-p") && index + 1 < argc) {
            ++index;
            if (parse_port(argv[index], port)) {
                continue;
            }
        }
        if (arg == "--subject-concurrency" && index + 1 < argc) {
            ++index;
            if (parse_size(argv[index], subject_concurrency)) {
                continue;
            }
        }
        if (arg == "--io-timeout-ms" && index + 1 < argc) {
            ++index;
            if (parse_milliseconds(argv[index], io_timeout)) {
                continue;
            }
        }
        if (arg == "--all-subjects") {
            all_subjects = true;
            continue;
        }
        if ((arg == "-I" || arg == "--include-dir") && index + 1 < argc) {
            ++index;
            parse_options.include_dirs.emplace_back(argv[index]);
            continue;
        }
        if (arg.starts_with("-I") && arg.size() > 2u) {
            parse_options.include_dirs.emplace_back(arg.substr(2u));
            continue;
        }
        if ((arg == "--rule" || arg == "-r") && index + 1 < argc) {
            ++index;
            rule_path = std::filesystem::path {argv[index]};
            continue;
        }
        if (!arg.starts_with("-") && rule_path.empty()) {
            rule_path = std::filesystem::path {arg};
            continue;
        }

        fmt::print(stderr, "invalid argument: {}\n", arg);
        print_usage();
        return 2;
    }

    const auto subject_id = "pid:" + std::to_string(GetCurrentProcessId());
    if (!rule_path.empty()) {
        auto parsed = rule_engine::parse_file(rule_path, parse_options);
        if (!parsed) {
            print_rule_diagnostics(parsed.error());
            return 1;
        }

        auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
        if (!verified) {
            print_rule_diagnostics(verified.error());
            return 1;
        }

        const std::vector<rule_engine::Subject> requested_subjects =
            all_subjects ? std::vector<rule_engine::Subject> {}
                         : std::vector<rule_engine::Subject> {
                               rule_engine::Subject {
                                   .kind = "process",
                                   .id = subject_id,
                               },
                           };
        auto evaluation = rule_engine::client_protocol::evaluate_subjects_with_client(
            rule_engine::client_protocol::ClientConnectionOptions {
                .host = host,
                .port = port,
                .io_timeout = io_timeout,
            },
            *verified,
            requested_subjects,
            rule_engine::client_protocol::ClientEvaluationOptions {
                .max_subject_concurrency = subject_concurrency,
            });
        if (!evaluation) {
            print_errors(evaluation.error());
            return 1;
        }

        fmt::print("connected to {}:{} protocol={} version={} subjects={} evaluated={}\n",
                   host,
                   port,
                   evaluation->handshake.protocol,
                   evaluation->handshake.version,
                   evaluation->subjects.subjects.size(),
                   evaluation->evaluations.size());
        for (const auto &subject_evaluation : evaluation->evaluations) {
            fmt::print("subject {}\n", subject_evaluation.subject.id);
            for (const auto &result : subject_evaluation.final_step.rule_results) {
                fmt::print("  {} {}\n", result.identifier, result.matched ? "match" : "no_match");
                for (const auto &diagnostic : result.diagnostics) {
                    fmt::print("    diagnostic: {}\n", diagnostic.message);
                }
            }
        }
        return 0;
    }

    rule_engine::protocol::FactBatchRequestMessage process_request;
    process_request.route = "endpoint.process.snapshot";
    process_request.keys.push_back(rule_engine::protocol::FactKey {
        .subject_id = subject_id,
        .key = "process.pid",
    });
    process_request.keys.push_back(rule_engine::protocol::FactKey {
        .subject_id = subject_id,
        .key = "process.name",
    });

    rule_engine::protocol::FactBatchRequestMessage pe_request;
    pe_request.route = "endpoint.process.image.pe";
    pe_request.keys.push_back(rule_engine::protocol::FactKey {
        .subject_id = subject_id,
        .key = "pe.is_valid",
    });
    pe_request.keys.push_back(rule_engine::protocol::FactKey {
        .subject_id = subject_id,
        .key = "pe.number_of_sections",
    });

    auto session = rule_engine::client_protocol::run_client_session(
        rule_engine::client_protocol::ClientConnectionOptions {
            .host = host,
            .port = port,
            .io_timeout = io_timeout,
        },
        std::vector<rule_engine::protocol::FactBatchRequestMessage> {process_request, pe_request});
    if (!session) {
        print_errors(session.error());
        return 1;
    }

    fmt::print("connected to {}:{} protocol={} version={} subjects={}\n",
               host,
               port,
               session->handshake.protocol,
               session->handshake.version,
               session->subjects.subjects.size());
    for (const auto &capability : session->handshake.capabilities) {
        fmt::print("capability {}\n", capability.route);
    }
    for (const auto &response : session->responses) {
        fmt::print("response {}\n", response.route);
        for (const auto &fact : response.values) {
            fmt::print("  {} {} {}\n", fact.key, status_name(fact.status), value_text(fact.value));
            if (!fact.diagnostic.empty()) {
                fmt::print("    diagnostic: {}\n", fact.diagnostic);
            }
        }
    }
    return 0;
}
