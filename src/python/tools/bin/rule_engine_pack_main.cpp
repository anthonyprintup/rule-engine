#include "rule_engine/python/tools.hpp"

#include <filesystem>
#include <iostream>

#ifndef RULE_ENGINE_TRACKED_SDK_ROOT
#define RULE_ENGINE_TRACKED_SDK_ROOT ""
#endif

int main(const int argument_count, char **argument_values) {
    using namespace rule_engine::python::tools;
    FilesystemPackagingBackend backend {
        FilesystemToolDefaults {.sdk_root = std::filesystem::path {RULE_ENGINE_TRACKED_SDK_ROOT}}};
    const auto arguments = process_arguments(argument_count, argument_values);
    return run_pack_process(arguments, backend, std::cout, std::cerr);
}
