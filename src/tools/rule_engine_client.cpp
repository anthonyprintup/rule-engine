#include <rule_engine/client_protocol.hpp>
#include <rule_engine/custom_fact_fixture.hpp>
#include <rule_engine/windows/process_provider.hpp>

#include <fmt/format.h>

#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string_view>
#include <utility>
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

    [[nodiscard]] bool parse_session_count(const std::string_view text, std::size_t &out) noexcept {
        std::size_t value {};
        const auto *first = text.data();
        const auto *last = first + text.size();
        const auto [ptr, ec] = std::from_chars(first, last, value);
        if (ec != std::errc {} || ptr != last) {
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

    void print_usage() {
        fmt::print("usage: rule_engine_client [--port <port>] [--pattern-fixture <file>] "
                   "[--custom-fact-fixture <file>] [--io-timeout-ms <ms>] "
                   "[--max-sessions <n>|--serve] [--enumerate]\n");
    }

    void print_errors(const rule_engine::ErrorSet &errors) {
        for (const auto &diagnostic : errors.diagnostics) {
            fmt::print(stderr, "{}\n", diagnostic.message);
        }
    }
} // namespace

int main(int argc, char **argv) {
    bool enumerate {};
    std::uint16_t port {31337};
    std::chrono::milliseconds io_timeout {5000};
    std::size_t max_sessions {1};
    std::filesystem::path pattern_fixture_path;
    std::filesystem::path custom_fact_fixture_path;
    for (int index = 1; index < argc; ++index) {
        const std::string_view arg {argv[index]};
        if (wants_help(arg)) {
            print_usage();
            return 0;
        }
        if (arg == "--enumerate") {
            enumerate = true;
            continue;
        }
        if ((arg == "--port" || arg == "-p") && index + 1 < argc) {
            ++index;
            if (parse_port(argv[index], port)) {
                continue;
            }
        }
        if (arg == "--io-timeout-ms" && index + 1 < argc) {
            ++index;
            if (parse_milliseconds(argv[index], io_timeout)) {
                continue;
            }
        }
        if (arg == "--max-sessions" && index + 1 < argc) {
            ++index;
            if (parse_session_count(argv[index], max_sessions)) {
                continue;
            }
        }
        if (arg == "--serve") {
            max_sessions = 0u;
            continue;
        }
        if (arg == "--pattern-fixture" && index + 1 < argc) {
            ++index;
            pattern_fixture_path = std::filesystem::path {argv[index]};
            continue;
        }
        if (arg == "--custom-fact-fixture" && index + 1 < argc) {
            ++index;
            custom_fact_fixture_path = std::filesystem::path {argv[index]};
            continue;
        }
        fmt::print(stderr, "invalid argument: {}\n", arg);
        print_usage();
        return 2;
    }

    if (enumerate) {
        auto subjects = rule_engine::windows::enumerate_process_subjects();
        if (!subjects) {
            print_errors(subjects.error());
            return 1;
        }
        for (const auto &subject : *subjects) {
            fmt::print("{} {}\n", subject.kind, subject.id);
        }
        return 0;
    }

    std::vector<rule_engine::protocol::Capability> extra_capabilities;
    rule_engine::client_protocol::ExtraFactBatchHandler extra_handler;
    if (!custom_fact_fixture_path.empty()) {
        auto fixtures = rule_engine::custom_facts::load_custom_fact_fixture_file(custom_fact_fixture_path);
        if (!fixtures) {
            print_errors(fixtures.error());
            return 1;
        }
        extra_capabilities = fixtures->capabilities;
        extra_handler = [custom_fixtures = std::move(*fixtures)](
                            const rule_engine::protocol::FactBatchRequestMessage &request)
            -> std::optional<rule_engine::protocol::FactBatchResponseMessage> {
            return rule_engine::custom_facts::read_custom_fact_fixture_response(request, custom_fixtures);
        };
    }

    auto result = rule_engine::client_protocol::serve_client(
        rule_engine::client_protocol::ClientListenOptions {
            .bind_address = "127.0.0.1",
            .port = port,
            .pattern_fixture_path = pattern_fixture_path,
            .io_timeout = io_timeout,
            .extra_capabilities = std::move(extra_capabilities),
            .extra_fact_handler = std::move(extra_handler),
            .max_sessions = max_sessions,
        },
        [](const std::uint16_t actual_port) {
            fmt::print("rule_engine_client v1 listening on 127.0.0.1:{}\n", actual_port);
        });
    if (!result) {
        print_errors(result.error());
        return 1;
    }

    return 0;
}
