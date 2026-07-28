#include "rule_engine/python/tools.hpp"
#include "rule_engine/python/tools/admin_client.hpp"

#include <iostream>

int main(const int argument_count, char **argument_values) {
    using namespace rule_engine::python::tools;
    ResidentAdminClientAdapter adapter;
    FilesystemAdminBackend backend {&adapter};
    const auto arguments = process_arguments(argument_count, argument_values);
    return run_admin_process(arguments, backend, std::cout, std::cerr);
}
