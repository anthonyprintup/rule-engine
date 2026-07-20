add_library(
    rule_engine_python_cluster
    activation.cpp
    audit.cpp
    breaker.cpp
    configuration.cpp
    coordinator.cpp
    readiness.cpp
    store.cpp
)
add_library(rule_engine::python_cluster ALIAS rule_engine_python_cluster)
target_include_directories(rule_engine_python_cluster PUBLIC ../../../include)
target_link_libraries(
    rule_engine_python_cluster
    PUBLIC
        rule_engine::python_contract
        rule_engine::project_options
)

add_executable(rule_engine_python_cluster_tests ../../../tests/python_cluster_tests.cpp)
target_link_libraries(
    rule_engine_python_cluster_tests
    PRIVATE
        rule_engine::python_cluster
        Catch2::Catch2WithMain
)
target_compile_options(
    rule_engine_python_cluster_tests
    PRIVATE
        $<$<AND:$<COMPILE_LANG_AND_ID:CXX,Clang>,$<CXX_COMPILER_FRONTEND_VARIANT:MSVC>>:/clang:-Wno-c2y-extensions>
        $<$<AND:$<COMPILE_LANG_AND_ID:CXX,Clang>,$<CXX_COMPILER_FRONTEND_VARIANT:GNU>>:-Wno-c2y-extensions>
)
enable_testing()
add_test(NAME python_cluster_tests COMMAND $<TARGET_FILE:rule_engine_python_cluster_tests>)
