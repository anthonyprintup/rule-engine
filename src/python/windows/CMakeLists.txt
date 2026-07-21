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

add_executable(
    rule_engine_python_windows_provider_tests
    "${PROJECT_SOURCE_DIR}/tests/python_windows_provider_tests.cpp"
)
set_target_properties(
    rule_engine_python_windows_provider_tests
    PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
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
enable_testing()
add_test(
    NAME rule_engine_python_windows_provider_tests
    COMMAND $<TARGET_FILE:rule_engine_python_windows_provider_tests>
)
