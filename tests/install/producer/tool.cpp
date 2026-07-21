#include <iostream>
#include <string_view>

extern "C" int rule_engine_install_fixture_runtime_version();

int main(int argc, char** argv) {
    if (argc == 2 && std::string_view {argv[1]} == "--version" &&
        rule_engine_install_fixture_runtime_version() == 10000) {
        std::cout << RULE_ENGINE_TOOL_NAME << " 1.0.0\n";
        return 0;
    }
    return 2;
}
