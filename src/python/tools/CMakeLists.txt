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
    PRIVATE
        rule_engine::project_options
)

add_library(
    rule_engine_python_executable_support
    admin_client.cpp
    benchmark.cpp
    pack_upload.cpp
    resident_evaluator.cpp
    resident_service.cpp
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
        rule_engine::python_runtime_adapters
        rule_engine::python_vm
        rule_engine::project_options
)

add_executable(rule_engine_python_pack_cli bin/rule_engine_pack_main.cpp)
set_target_properties(rule_engine_python_pack_cli PROPERTIES OUTPUT_NAME rule_engine_pack)
target_link_libraries(
    rule_engine_python_pack_cli
    PRIVATE rule_engine::python_tools rule_engine::project_options
)
target_compile_definitions(
    rule_engine_python_pack_cli
    PRIVATE RULE_ENGINE_TRACKED_SDK_ROOT="${PROJECT_SOURCE_DIR}/sdk"
)

add_executable(rule_engine_python_check_cli bin/rule_engine_check_main.cpp)
set_target_properties(rule_engine_python_check_cli PROPERTIES OUTPUT_NAME rule_engine_check)
target_link_libraries(
    rule_engine_python_check_cli
    PRIVATE rule_engine::python_tools rule_engine::project_options
)

add_executable(rule_engine_python_admin_cli bin/rule_engine_admin_main.cpp)
set_target_properties(rule_engine_python_admin_cli PROPERTIES OUTPUT_NAME rule_engine_admin)
target_link_libraries(
    rule_engine_python_admin_cli
    PRIVATE rule_engine::python_executable_support rule_engine::project_options
)

add_executable(rule_engine_python_server server_main.cpp)
set_target_properties(rule_engine_python_server PROPERTIES OUTPUT_NAME rule_engine_server)
target_link_libraries(
    rule_engine_python_server
    PRIVATE rule_engine::python_executable_support rule_engine::project_options
)

add_executable(rule_engine_python_benchmark benchmark_main.cpp)
set_target_properties(rule_engine_python_benchmark PROPERTIES OUTPUT_NAME rule_engine_benchmark)
target_link_libraries(
    rule_engine_python_benchmark
    PRIVATE rule_engine::python_executable_support rule_engine::project_options
)

if(BUILD_TESTING)
    if(NOT TARGET rule_engine_stage_python_runtime)
        message(FATAL_ERROR "Python tooling tests require the canonical private-runtime staging target")
    endif()
    get_property(
        tooling_private_runtime_root
        TARGET rule_engine_stage_python_runtime
        PROPERTY RULE_ENGINE_PRIVATE_PYTHON_RUNTIME_ROOT
    )
    if(NOT tooling_private_runtime_root)
        message(FATAL_ERROR "Python runtime staging target did not publish its private-runtime root")
    endif()
    file(TO_CMAKE_PATH "${tooling_private_runtime_root}" tooling_private_runtime_root_for_cxx)

    add_executable(
        rule_engine_python_tools_tests
        "${PROJECT_SOURCE_DIR}/tests/python_tools_tests.cpp"
    )
    target_link_libraries(
        rule_engine_python_tools_tests
        PRIVATE
            rule_engine::python_tools
            rule_engine_test_options
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
            RULE_ENGINE_TOOLING_STAGED_RUNTIME_ROOT="${tooling_private_runtime_root_for_cxx}"
    )
    add_dependencies(rule_engine_python_tools_tests rule_engine_stage_python_runtime)

    add_executable(
        rule_engine_python_executable_surface_tests
        "${PROJECT_SOURCE_DIR}/tests/python_executable_surface_tests.cpp"
    )
    target_link_libraries(
        rule_engine_python_executable_surface_tests
        PRIVATE
            Catch2::Catch2WithMain
            rule_engine_test_options
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

    add_executable(
        rule_engine_python_resident_evaluator_tests
        "${PROJECT_SOURCE_DIR}/tests/python_resident_evaluator_tests.cpp"
    )
    target_link_libraries(
        rule_engine_python_resident_evaluator_tests
        PRIVATE
            Catch2::Catch2WithMain
            rule_engine_test_options
            rule_engine::python_executable_support
    )

    add_test(NAME rule_engine_python_tools_tests COMMAND $<TARGET_FILE:rule_engine_python_tools_tests>)
    add_test(
        NAME rule_engine_python_executable_surface_tests
        COMMAND $<TARGET_FILE:rule_engine_python_executable_surface_tests>
    )
    add_test(
        NAME rule_engine_python_resident_evaluator_tests
        COMMAND $<TARGET_FILE:rule_engine_python_resident_evaluator_tests>
    )
    add_test(
        NAME rule_engine_python_tools_executable_smoke
        COMMAND
            "${CMAKE_COMMAND}"
            "-DRULE_ENGINE_PACK_EXE=$<TARGET_FILE:rule_engine_python_pack_cli>"
            "-DRULE_ENGINE_CHECK_EXE=$<TARGET_FILE:rule_engine_python_check_cli>"
            "-DRULE_ENGINE_RUNTIME_ROOT=${tooling_private_runtime_root}"
            "-DRULE_ENGINE_SMOKE_ROOT=${CMAKE_CURRENT_BINARY_DIR}/executable-smoke"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/executable_smoke.cmake"
    )
    if(WIN32)
        find_program(
            rule_engine_tooling_powershell
            NAMES pwsh powershell
            REQUIRED
        )
        add_test(
            NAME rule_engine_python_tools_production_signing_smoke
            COMMAND
                "${rule_engine_tooling_powershell}"
                -NoLogo
                -NoProfile
                -NonInteractive
                -ExecutionPolicy Bypass
                -File "${CMAKE_CURRENT_SOURCE_DIR}/executable_production_smoke.ps1"
                -PackExe "$<TARGET_FILE:rule_engine_python_pack_cli>"
                -CheckExe "$<TARGET_FILE:rule_engine_python_check_cli>"
                -RuntimeRoot "${tooling_private_runtime_root}"
                -SmokeRoot "${CMAKE_CURRENT_BINARY_DIR}/production-executable-smoke"
        )
    endif()
endif()
