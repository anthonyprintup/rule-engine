set(RE2_BUILD_TESTING OFF CACHE BOOL "Build RE2 tests and benchmarks" FORCE)
set(RE2_TEST OFF CACHE BOOL "Build RE2 tests" FORCE)
set(RE2_BENCHMARK OFF CACHE BOOL "Build RE2 benchmarks" FORCE)
set(RE2_INSTALL OFF CACHE BOOL "Install RE2" FORCE)
set(RE2_USE_ICU OFF CACHE BOOL "Use ICU from RE2" FORCE)
if(NOT TARGET re2::re2)
    FetchContent_Declare(
        rule_engine_re2
        SYSTEM
        GIT_REPOSITORY https://github.com/google/re2.git
        GIT_TAG 927f5d53caf8111721e734cf24724686bb745f55
    )
    FetchContent_MakeAvailable(rule_engine_re2)
endif()

# Protobuf's Abseil dependency is built with the static CRT on Windows, while
# the application and Catch2 use the DLL CRT. Keep RE2 and every allocation it
# owns behind a C ABI DLL so neither C++ nor CRT ownership crosses that seam.
if(WIN32)
    set_property(TARGET re2 PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    add_library(rule_engine_python_re2_bridge SHARED re2_bridge.cpp)
    set_property(
        TARGET rule_engine_python_re2_bridge
        PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
    )
    set_target_properties(
        rule_engine_python_re2_bridge
        PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    )
else()
    add_library(rule_engine_python_re2_bridge STATIC re2_bridge.cpp)
    target_compile_definitions(rule_engine_python_re2_bridge PUBLIC RULE_ENGINE_RE2_BRIDGE_STATIC=1)
endif()
target_compile_definitions(rule_engine_python_re2_bridge PRIVATE RULE_ENGINE_RE2_BRIDGE_BUILD=1)
target_link_libraries(rule_engine_python_re2_bridge PRIVATE re2::re2 rule_engine::project_options)
set_target_properties(
    rule_engine_python_re2_bridge
    PROPERTIES
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN TRUE
)

add_library(
    rule_engine_python_optimizer
    optimizer.cpp
    scan_wire.cpp
    scanner.cpp
)
add_library(rule_engine::python_optimizer ALIAS rule_engine_python_optimizer)
target_include_directories(rule_engine_python_optimizer PUBLIC "${PROJECT_SOURCE_DIR}/include")
target_link_libraries(
    rule_engine_python_optimizer
    PUBLIC
        rule_engine::python_contract
        rule_engine::project_options
    PRIVATE
        rule_engine_python_re2_bridge
)

enable_testing()
add_executable(rule_engine_python_optimizer_tests "${PROJECT_SOURCE_DIR}/tests/python_optimizer_tests.cpp")
if(WIN32)
    set_target_properties(
        rule_engine_python_optimizer_tests
        PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    )
endif()
target_link_libraries(
    rule_engine_python_optimizer_tests
    PRIVATE
        rule_engine::python_optimizer
        rule_engine::python_protocol
        Catch2::Catch2WithMain
)
target_compile_options(
    rule_engine_python_optimizer_tests
    PRIVATE
        $<$<AND:$<COMPILE_LANG_AND_ID:CXX,Clang>,$<CXX_COMPILER_FRONTEND_VARIANT:MSVC>>:/clang:-Wno-c2y-extensions>
        $<$<AND:$<COMPILE_LANG_AND_ID:CXX,Clang>,$<CXX_COMPILER_FRONTEND_VARIANT:GNU>>:-Wno-c2y-extensions>
)
add_test(NAME rule_engine_python_optimizer_tests COMMAND $<TARGET_FILE:rule_engine_python_optimizer_tests>)
