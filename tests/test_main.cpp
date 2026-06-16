#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wsign-conversion"
#endif
#include <catch2/catch_session.hpp>
#if defined(__clang__)
#pragma clang diagnostic pop
#endif

#include <rule_engine_test_runtime.hpp>

int main(int argc, char *argv[]) {
    rule_engine::tests::configure_noninteractive_crash_reporting();
    return Catch::Session().run(argc, argv);
}
