#include <rule_engine/client_protocol.hpp>
#include <rule_engine/windows/process_provider.hpp>

#include <fmt/format.h>

#include <charconv>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string_view>

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
    std::filesystem::path pattern_fixture_path;
    for (int index = 1; index < argc; ++index) {
        const std::string_view arg {argv[index]};
        if (wants_help(arg)) {
            fmt::print("usage: rule_engine_client [--port <port>] [--pattern-fixture <file>] "
                       "[--io-timeout-ms <ms>] [--enumerate]\n");
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
        if (arg == "--pattern-fixture" && index + 1 < argc) {
            ++index;
            pattern_fixture_path = std::filesystem::path {argv[index]};
            continue;
        }
        fmt::print(stderr,
                   "invalid argument: {}\nusage: rule_engine_client [--port <port>] [--pattern-fixture <file>] "
                   "[--io-timeout-ms <ms>] [--enumerate]\n",
                   arg);
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

    auto result = rule_engine::client_protocol::serve_client_once(
        rule_engine::client_protocol::ClientListenOptions {
            .bind_address = "127.0.0.1",
            .port = port,
            .pattern_fixture_path = pattern_fixture_path,
            .io_timeout = io_timeout,
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
