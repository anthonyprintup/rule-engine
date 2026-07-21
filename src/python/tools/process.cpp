#include "rule_engine/python/tools/process.hpp"

#include <ostream>

namespace rule_engine::python::tools {

    std::vector<std::string_view> process_arguments(const int argument_count, char **argument_values) {
        std::vector<std::string_view> result;
        if (argument_count <= 1 || argument_values == nullptr) {
            return result;
        }
        result.reserve(static_cast<std::size_t>(argument_count - 1));
        for (int index = 1; index < argument_count; ++index) {
            result.emplace_back(argument_values[index] == nullptr ? "" : argument_values[index]);
        }
        return result;
    }

    int write_command_output(const CommandOutput &output, std::ostream &standard_output, std::ostream &standard_error) {
        standard_output << output.standard_output;
        standard_error << output.standard_error;
        standard_output.flush();
        standard_error.flush();
        if (!standard_output || !standard_error) {
            return static_cast<int>(ExitCode::internal_invariant_failed);
        }
        return static_cast<int>(output.exit_code);
    }

    int run_check_process(const std::span<const std::string_view> arguments, CompilerToolBackend &backend,
                          std::ostream &standard_output, std::ostream &standard_error, CheckWatchCoordinator *watch) {
        return write_command_output(run_rule_engine_check(arguments, backend, watch), standard_output, standard_error);
    }

    int run_pack_process(const std::span<const std::string_view> arguments, PackagingToolBackend &backend,
                         std::ostream &standard_output, std::ostream &standard_error) {
        return write_command_output(run_rule_engine_pack(arguments, backend), standard_output, standard_error);
    }

    int run_admin_process(const std::span<const std::string_view> arguments, AdminToolBackend &backend,
                          std::ostream &standard_output, std::ostream &standard_error) {
        return write_command_output(run_rule_engine_admin(arguments, backend), standard_output, standard_error);
    }

} // namespace rule_engine::python::tools
