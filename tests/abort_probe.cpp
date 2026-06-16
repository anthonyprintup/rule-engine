#include <rule_engine_test_runtime.hpp>

#include <cstdlib>

int main() {
    rule_engine::tests::configure_noninteractive_crash_reporting();
    std::abort();
}
