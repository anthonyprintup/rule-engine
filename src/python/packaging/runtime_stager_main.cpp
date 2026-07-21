#include "rule_engine/python/packaging/runtime.hpp"

#include <cstdlib>
#include <filesystem>
#include <iostream>

namespace {

    using rule_engine::python::packaging::PackagingError;
    using rule_engine::python::packaging::PrivatePythonRuntime;
    using rule_engine::python::packaging::PythonRuntimeStageRequest;

    int report_failure(const PackagingError &error) {
        std::cerr << "private CPython runtime staging failed: " << error.message;
        if (error.subject) {
            std::cerr << " [" << *error.subject << ']';
        }
        std::cerr << '\n';
        return EXIT_FAILURE;
    }

} // namespace

int main(const int argument_count, const char *const *arguments) {
    using namespace rule_engine::python::packaging;

    if (argument_count != 5) {
        std::cerr << "usage: rule_engine_python_runtime_stager <artifact.zip> <extracted-root> "
                     "<staged-root> <worker-script>\n";
        return EXIT_FAILURE;
    }

    const std::filesystem::path destination {arguments[3]};
    std::error_code filesystem_error;
    auto destination_exists = std::filesystem::exists(destination, filesystem_error);
    if (filesystem_error) {
        std::cerr << "cannot inspect private CPython runtime destination\n";
        return EXIT_FAILURE;
    }

    // Build tools may create the custom-command output directory before this
    // process starts. Remove only that empty leaf; never replace a populated or
    // invalid runtime implicitly.
    if (destination_exists && std::filesystem::is_directory(destination, filesystem_error) && !filesystem_error &&
        std::filesystem::is_empty(destination, filesystem_error) && !filesystem_error) {
        if (!std::filesystem::remove(destination, filesystem_error) || filesystem_error) {
            std::cerr << "cannot remove empty private CPython runtime output directory\n";
            return EXIT_FAILURE;
        }
        destination_exists = false;
    }

    std::expected<PrivatePythonRuntime, PackagingError> runtime =
        destination_exists ? load_exact_private_runtime(destination) :
                             stage_exact_private_runtime(PythonRuntimeStageRequest {
                                 .artifact_archive = arguments[1],
                                 .extracted_distribution = arguments[2],
                                 .destination = destination,
                                 .worker_script = arguments[4],
                             });
    if (!runtime) {
        return report_failure(runtime.error());
    }

    const auto valid = validate_exact_private_runtime(*runtime);
    if (!valid) {
        return report_failure(valid.error());
    }
    std::cout << runtime->runtime_root.generic_string() << '\n';
    return EXIT_SUCCESS;
}
