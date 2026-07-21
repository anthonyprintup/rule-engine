#include "rule_engine/python/tools/benchmark.hpp"

#include <iostream>
#include <span>
#include <string_view>
#include <vector>

int main(const int argc, const char *const argv[]) {
    std::vector<std::string_view> arguments;
    arguments.reserve(argc > 1 ? static_cast<std::size_t>(argc - 1) : 0U);
    for (auto index = 1; index < argc; ++index) { arguments.emplace_back(argv[index]); }

    auto output = rule_engine::python::tools::run_rule_engine_benchmark(arguments);
    if (!output.standard_output.empty()) {
        std::cout << output.standard_output;
    }
    if (!output.standard_error.empty()) {
        std::cerr << output.standard_error;
    }
    return static_cast<int>(output.exit_code);
}
