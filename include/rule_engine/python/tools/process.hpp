#pragma once

#include "rule_engine/python/tools/cli.hpp"

#include <iosfwd>
#include <span>
#include <string_view>
#include <vector>

namespace rule_engine::python::tools {

    [[nodiscard]] std::vector<std::string_view> process_arguments(int argument_count, char **argument_values);
    [[nodiscard]] int write_command_output(const CommandOutput &output, std::ostream &standard_output,
                                           std::ostream &standard_error);
    [[nodiscard]] int run_check_process(std::span<const std::string_view> arguments, CompilerToolBackend &backend,
                                        std::ostream &standard_output, std::ostream &standard_error,
                                        CheckWatchCoordinator *watch = nullptr);
    [[nodiscard]] int run_pack_process(std::span<const std::string_view> arguments, PackagingToolBackend &backend,
                                       std::ostream &standard_output, std::ostream &standard_error);
    [[nodiscard]] int run_admin_process(std::span<const std::string_view> arguments, AdminToolBackend &backend,
                                        std::ostream &standard_output, std::ostream &standard_error);

} // namespace rule_engine::python::tools
