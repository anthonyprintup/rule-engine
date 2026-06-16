#include <rule_engine/compiler.hpp>
#include <rule_engine/modules.hpp>

#include <fmt/format.h>

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace {
    [[nodiscard]] bool wants_help(const std::string_view arg) noexcept {
        return arg == "--help" || arg == "-h";
    }

    void print_usage() {
        fmt::print(stderr, "usage: rule_engine_check [-I <dir>] [--include-dir <dir>] <rule.yar>\n");
    }
} // namespace

int main(int argc, char **argv) {
    rule_engine::ParseOptions options;
    std::filesystem::path rule_path;

    for (int index = 1; index < argc; ++index) {
        const std::string_view arg {argv[index]};
        if (wants_help(arg)) {
            print_usage();
            return 0;
        }
        if ((arg == "-I" || arg == "--include-dir") && index + 1 < argc) {
            ++index;
            options.include_dirs.emplace_back(argv[index]);
            continue;
        }
        if (arg.starts_with("-I") && arg.size() > 2u) {
            options.include_dirs.emplace_back(arg.substr(2u));
            continue;
        }
        if (arg.starts_with("-")) {
            fmt::print(stderr, "invalid argument: {}\n", arg);
            print_usage();
            return 2;
        }
        if (!rule_path.empty()) {
            fmt::print(stderr, "multiple rule files provided\n");
            print_usage();
            return 2;
        }
        rule_path = std::filesystem::path {arg};
    }

    if (rule_path.empty()) {
        print_usage();
        return 2;
    }

    auto parsed = rule_engine::parse_file(rule_path, options);
    if (!parsed) {
        for (const auto &diagnostic : parsed.error().diagnostics) {
            fmt::print(stderr, "{}:{}: {}\n", diagnostic.source, diagnostic.span.start, diagnostic.message);
        }
        return 1;
    }

    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    if (!verified) {
        for (const auto &diagnostic : verified.error().diagnostics) {
            fmt::print(stderr, "{}:{}: {}\n", diagnostic.source, diagnostic.span.start, diagnostic.message);
        }
        return 1;
    }

    fmt::print("{}\n{}\n", verified->ir_dump(), verified->schedule_plan_dump());
    return 0;
}
