if(NOT WIN32)
    return()
endif()

add_library(
    rule_engine_python_windows
    common.cpp
    process.cpp
    pe.cpp
    scan.cpp
)
add_library(rule_engine::python_windows ALIAS rule_engine_python_windows)
target_include_directories(rule_engine_python_windows PUBLIC "${PROJECT_SOURCE_DIR}/include")
target_link_libraries(
    rule_engine_python_windows
    PUBLIC
        rule_engine::python_contract
        rule_engine::python_optimizer
        rule_engine::project_options
    PRIVATE
        advapi32
        bcrypt
        crypt32
        wintrust
)

add_library(rule_engine_python_windows_runtime runtime.cpp)
add_library(rule_engine::python_windows_runtime ALIAS rule_engine_python_windows_runtime)
target_include_directories(rule_engine_python_windows_runtime PUBLIC "${PROJECT_SOURCE_DIR}/include")
target_link_libraries(
    rule_engine_python_windows_runtime
    PUBLIC
        rule_engine::python_windows
        rule_engine::python_protocol
        rule_engine::project_options
)

add_library(rule_engine_python_windows_agent agent.cpp agent_config.cpp)
add_library(rule_engine::python_windows_agent ALIAS rule_engine_python_windows_agent)
target_include_directories(rule_engine_python_windows_agent PUBLIC "${PROJECT_SOURCE_DIR}/include")
target_link_libraries(
    rule_engine_python_windows_agent
    PUBLIC
        rule_engine::python_windows_runtime
        rule_engine::python_protocol
        rule_engine::project_options
    PRIVATE
        ws2_32
)

add_executable(rule_engine_python_agent agent_main.cpp)
target_link_libraries(rule_engine_python_agent PRIVATE rule_engine::python_windows_agent rule_engine::project_options)
set_target_properties(
    rule_engine_python_agent
    PROPERTIES
        OUTPUT_NAME rule_engine_agent
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
)

if(BUILD_TESTING)
    add_executable(
        rule_engine_python_windows_provider_tests
        "${PROJECT_SOURCE_DIR}/tests/python_windows_provider_tests.cpp"
    )
    target_link_libraries(
        rule_engine_python_windows_provider_tests
        PRIVATE
            rule_engine::python_windows_runtime
            Catch2::Catch2WithMain
    )
    target_compile_options(
        rule_engine_python_windows_provider_tests
        PRIVATE
            $<$<AND:$<COMPILE_LANG_AND_ID:CXX,Clang>,$<CXX_COMPILER_FRONTEND_VARIANT:MSVC>>:/clang:-Wno-c2y-extensions>
            $<$<AND:$<COMPILE_LANG_AND_ID:CXX,Clang>,$<CXX_COMPILER_FRONTEND_VARIANT:GNU>>:-Wno-c2y-extensions>
    )
    set_target_properties(
        rule_engine_python_windows_provider_tests
        PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    )
    add_test(
        NAME rule_engine_python_windows_provider_tests
        COMMAND $<TARGET_FILE:rule_engine_python_windows_provider_tests>
    )

    add_executable(
        rule_engine_python_windows_agent_tests
        "${PROJECT_SOURCE_DIR}/tests/python_windows_agent_tests.cpp"
    )
    target_link_libraries(
        rule_engine_python_windows_agent_tests
        PRIVATE
            rule_engine::python_windows_agent
            Catch2::Catch2WithMain
    )
    target_compile_options(
        rule_engine_python_windows_agent_tests
        PRIVATE
            $<$<AND:$<COMPILE_LANG_AND_ID:CXX,Clang>,$<CXX_COMPILER_FRONTEND_VARIANT:MSVC>>:/clang:-Wno-c2y-extensions>
            $<$<AND:$<COMPILE_LANG_AND_ID:CXX,Clang>,$<CXX_COMPILER_FRONTEND_VARIANT:GNU>>:-Wno-c2y-extensions>
    )
    set_target_properties(
        rule_engine_python_windows_agent_tests
        PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    )
    add_test(
        NAME rule_engine_python_windows_agent_tests
        COMMAND $<TARGET_FILE:rule_engine_python_windows_agent_tests>
    )
    if(OPENSSL_ROOT_DIR AND EXISTS "${OPENSSL_ROOT_DIR}/bin")
        set_tests_properties(
            rule_engine_python_windows_provider_tests
            rule_engine_python_windows_agent_tests
            PROPERTIES ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${OPENSSL_ROOT_DIR}/bin"
        )
    endif()
endif()
