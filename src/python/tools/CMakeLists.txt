add_library(
    rule_engine_python_tools
    admin.cpp
    authoring.cpp
    cli.cpp
    common.cpp
    diagnostics.cpp
    filesystem.cpp
    process.cpp
    redaction.cpp
)
add_library(rule_engine::python_tools ALIAS rule_engine_python_tools)
target_include_directories(rule_engine_python_tools PUBLIC "${PROJECT_SOURCE_DIR}/include")
target_link_libraries(
    rule_engine_python_tools
    PUBLIC
        rule_engine::python_contract
        rule_engine::python_compiler
        rule_engine::python_optimizer
        rule_engine::python_packaging
        rule_engine::project_options
)

add_executable(rule_engine_python_pack_cli bin/rule_engine_pack_main.cpp)
set_target_properties(rule_engine_python_pack_cli PROPERTIES OUTPUT_NAME rule_engine_pack)
target_link_libraries(rule_engine_python_pack_cli PRIVATE rule_engine::python_tools)
target_compile_definitions(
    rule_engine_python_pack_cli
    PRIVATE RULE_ENGINE_TRACKED_SDK_ROOT="${PROJECT_SOURCE_DIR}/sdk"
)

add_executable(rule_engine_python_check_cli bin/rule_engine_check_main.cpp)
set_target_properties(rule_engine_python_check_cli PROPERTIES OUTPUT_NAME rule_engine_check)
target_link_libraries(rule_engine_python_check_cli PRIVATE rule_engine::python_tools)

add_executable(rule_engine_python_admin_cli bin/rule_engine_admin_main.cpp)
set_target_properties(rule_engine_python_admin_cli PROPERTIES OUTPUT_NAME rule_engine_admin)
target_link_libraries(rule_engine_python_admin_cli PRIVATE rule_engine::python_tools)

add_executable(
    rule_engine_python_tools_tests
    "${PROJECT_SOURCE_DIR}/tests/python_tools_tests.cpp"
)
target_link_libraries(
    rule_engine_python_tools_tests
    PRIVATE
        rule_engine::python_tools
        Catch2::Catch2WithMain
)
target_compile_options(
    rule_engine_python_tools_tests
    PRIVATE
        $<$<AND:$<COMPILE_LANG_AND_ID:CXX,Clang>,$<CXX_COMPILER_FRONTEND_VARIANT:MSVC>>:/clang:-Wno-c2y-extensions>
        $<$<AND:$<COMPILE_LANG_AND_ID:CXX,Clang>,$<CXX_COMPILER_FRONTEND_VARIANT:GNU>>:-Wno-c2y-extensions>
)
target_compile_definitions(
    rule_engine_python_tools_tests
    PRIVATE
        RULE_ENGINE_TOOLING_SDK_ROOT="${PROJECT_SOURCE_DIR}/sdk"
        RULE_ENGINE_TOOLING_WORKER_SCRIPT="${PROJECT_SOURCE_DIR}/src/python/packaging/rule_engine_python_worker.py"
)
enable_testing()
add_test(NAME rule_engine_python_tools_tests COMMAND $<TARGET_FILE:rule_engine_python_tools_tests>)
if(RULE_ENGINE_TEST_PYTHON_RUNTIME_ROOT AND RULE_ENGINE_TEST_PYTHON_RUNTIME_ARCHIVE)
    set_tests_properties(
        rule_engine_python_tools_tests
        PROPERTIES
            ENVIRONMENT
                "RULE_ENGINE_TEST_PYTHON_RUNTIME_ROOT=${RULE_ENGINE_TEST_PYTHON_RUNTIME_ROOT};RULE_ENGINE_TEST_PYTHON_RUNTIME_ARCHIVE=${RULE_ENGINE_TEST_PYTHON_RUNTIME_ARCHIVE}"
    )
endif()
