add_library(
    rule_engine_python_tools
    admin.cpp
    authoring.cpp
    cli.cpp
    common.cpp
    diagnostics.cpp
    redaction.cpp
)
add_library(rule_engine::python_tools ALIAS rule_engine_python_tools)
target_include_directories(rule_engine_python_tools PUBLIC "${PROJECT_SOURCE_DIR}/include")
target_link_libraries(
    rule_engine_python_tools
    PUBLIC
        rule_engine::python_contract
        rule_engine::project_options
)

add_library(
    rule_engine_python_executable_support
    benchmark.cpp
    server.cpp
)
add_library(rule_engine::python_executable_support ALIAS rule_engine_python_executable_support)
target_include_directories(rule_engine_python_executable_support PUBLIC "${PROJECT_SOURCE_DIR}/include")
target_link_libraries(
    rule_engine_python_executable_support
    PUBLIC
        rule_engine::python_tools
        rule_engine::python_cluster
        rule_engine::python_packaging
        rule_engine::python_protocol
    PRIVATE
        asio::asio
        rule_engine::python_compiler
        rule_engine::python_optimizer
        rule_engine::python_vm
        rule_engine::project_options
)

# The root project still owns legacy targets with the public executable names.
# Unique CMake target names keep this transition slice independently buildable;
# OUTPUT_NAME provides the production-facing Python executable names in this
# subdirectory until the root cleanup lane removes the retired targets.
add_executable(rule_engine_python_server server_main.cpp)
set_target_properties(rule_engine_python_server PROPERTIES OUTPUT_NAME rule_engine_server)
target_link_libraries(rule_engine_python_server PRIVATE rule_engine::python_executable_support)

add_executable(rule_engine_python_benchmark benchmark_main.cpp)
set_target_properties(rule_engine_python_benchmark PROPERTIES OUTPUT_NAME rule_engine_benchmark)
target_link_libraries(rule_engine_python_benchmark PRIVATE rule_engine::python_executable_support)

if(BUILD_TESTING)
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

    add_executable(
        rule_engine_python_executable_surface_tests
        "${PROJECT_SOURCE_DIR}/tests/python_executable_surface_tests.cpp"
    )
    target_link_libraries(
        rule_engine_python_executable_surface_tests
        PRIVATE
            Catch2::Catch2WithMain
            rule_engine::python_executable_support
    )
    add_dependencies(
        rule_engine_python_executable_surface_tests
        rule_engine_python_server
        rule_engine_python_benchmark
    )
    target_compile_definitions(
        rule_engine_python_executable_surface_tests
        PRIVATE
            RULE_ENGINE_PYTHON_SERVER_PATH="$<TARGET_FILE:rule_engine_python_server>"
            RULE_ENGINE_PYTHON_BENCHMARK_PATH="$<TARGET_FILE:rule_engine_python_benchmark>"
    )
    target_compile_options(
        rule_engine_python_executable_surface_tests
        PRIVATE
            $<$<AND:$<COMPILE_LANG_AND_ID:CXX,Clang>,$<CXX_COMPILER_FRONTEND_VARIANT:MSVC>>:/clang:-Wno-c2y-extensions>
            $<$<AND:$<COMPILE_LANG_AND_ID:CXX,Clang>,$<CXX_COMPILER_FRONTEND_VARIANT:GNU>>:-Wno-c2y-extensions>
    )

    add_test(NAME rule_engine_python_tools_tests COMMAND $<TARGET_FILE:rule_engine_python_tools_tests>)
    add_test(
        NAME rule_engine_python_executable_surface_tests
        COMMAND $<TARGET_FILE:rule_engine_python_executable_surface_tests>
    )
endif()
