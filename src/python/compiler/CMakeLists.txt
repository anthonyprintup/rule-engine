add_library(
    rule_engine_python_compiler
    ast.cpp
    ast_json.cpp
    frontend.cpp
    operands.cpp
    worker_adapter.cpp
)
add_library(rule_engine::python_compiler ALIAS rule_engine_python_compiler)
target_link_libraries(
    rule_engine_python_compiler
    PUBLIC
        rule_engine::python_contract
        rule_engine::python_packaging
    PRIVATE
        rule_engine::project_options
)

if(BUILD_TESTING)
    add_executable(rule_engine_python_compiler_tests "../../../tests/python_compiler_tests.cpp")
    target_link_libraries(
        rule_engine_python_compiler_tests
        PRIVATE
            rule_engine::python_compiler
            rule_engine::python_vm
            rule_engine_test_options
            Catch2::Catch2WithMain
    )
    file(
        TO_CMAKE_PATH
        "${PROJECT_SOURCE_DIR}/src/python/packaging/rule_engine_python_worker.py"
        compiler_test_python_worker_script
    )
    target_compile_definitions(
        rule_engine_python_compiler_tests
        PRIVATE RULE_ENGINE_COMPILER_TEST_WORKER_SCRIPT="${compiler_test_python_worker_script}"
    )
    set_source_files_properties(
        "../../../tests/python_compiler_tests.cpp"
        PROPERTIES COMPILE_OPTIONS $<$<COMPILE_LANG_AND_ID:CXX,Clang>:-Wno-c2y-extensions>
    )
    target_compile_options(
        rule_engine_python_compiler_tests
        PRIVATE $<$<COMPILE_LANG_AND_ID:CXX,Clang>:-Wno-exit-time-destructors>
    )
    enable_testing()
    add_test(NAME rule_engine_python_compiler_tests COMMAND $<TARGET_FILE:rule_engine_python_compiler_tests>)
    if(RULE_ENGINE_TEST_PYTHON_RUNTIME_ROOT AND RULE_ENGINE_TEST_PYTHON_RUNTIME_ARCHIVE)
        set_tests_properties(
            rule_engine_python_compiler_tests
            PROPERTIES
                ENVIRONMENT
                    "RULE_ENGINE_TEST_PYTHON_RUNTIME_ROOT=${RULE_ENGINE_TEST_PYTHON_RUNTIME_ROOT};RULE_ENGINE_TEST_PYTHON_RUNTIME_ARCHIVE=${RULE_ENGINE_TEST_PYTHON_RUNTIME_ARCHIVE}"
        )
    endif()
endif()
