set(RE2_BUILD_TESTING OFF CACHE BOOL "Build RE2 tests and benchmarks" FORCE)
set(RE2_TEST OFF CACHE BOOL "Build RE2 tests" FORCE)
set(RE2_BENCHMARK OFF CACHE BOOL "Build RE2 benchmarks" FORCE)
set(RE2_INSTALL OFF CACHE BOOL "Install RE2" FORCE)
set(RE2_USE_ICU OFF CACHE BOOL "Use ICU from RE2" FORCE)
option(RULE_ENGINE_BUILD_FUZZERS "Build libFuzzer targets" OFF)
set(ABSL_BUILD_TESTING OFF CACHE BOOL "Build Abseil tests" FORCE)
set(ABSL_ENABLE_INSTALL OFF CACHE BOOL "Install Abseil" FORCE)
set(ABSL_PROPAGATE_CXX_STD ON CACHE BOOL "Propagate the project C++ standard through Abseil" FORCE)
if(WIN32)
    set(ABSL_MSVC_STATIC_RUNTIME ON CACHE BOOL "Keep RE2 and Abseil behind the static-CRT bridge" FORCE)
endif()

set(rule_engine_restore_optimizer_flags OFF)
if(MSVC OR CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC")
    set(rule_engine_restore_optimizer_flags ON)
    foreach(
        flag_var
        CMAKE_CXX_FLAGS
        CMAKE_CXX_FLAGS_DEBUG
        CMAKE_CXX_FLAGS_RELEASE
        CMAKE_CXX_FLAGS_RELWITHDEBINFO
        CMAKE_CXX_FLAGS_MINSIZEREL
    )
        set("rule_engine_optimizer_${flag_var}" "${${flag_var}}")
        set("${flag_var}" "${RULE_ENGINE_DEPENDENCY_${flag_var}}")
    endforeach()
endif()
if(NOT TARGET absl::base)
    FetchContent_Declare(
        rule_engine_abseil
        SYSTEM
        GIT_REPOSITORY https://github.com/abseil/abseil-cpp.git
        GIT_TAG 76bb24329e8bf5f39704eb10d21b9a80befa7c81
    )
    FetchContent_MakeAvailable(rule_engine_abseil)
endif()
if(NOT TARGET re2::re2)
    FetchContent_Declare(
        rule_engine_re2
        SYSTEM
        GIT_REPOSITORY https://github.com/google/re2.git
        GIT_TAG 927f5d53caf8111721e734cf24724686bb745f55
    )
    FetchContent_MakeAvailable(rule_engine_re2)
endif()
if(rule_engine_restore_optimizer_flags)
    foreach(
        flag_var
        CMAKE_CXX_FLAGS
        CMAKE_CXX_FLAGS_DEBUG
        CMAKE_CXX_FLAGS_RELEASE
        CMAKE_CXX_FLAGS_RELWITHDEBINFO
        CMAKE_CXX_FLAGS_MINSIZEREL
    )
        set("${flag_var}" "${rule_engine_optimizer_${flag_var}}")
    endforeach()
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
    PRIVATE
        rule_engine::project_options
        rule_engine_python_re2_bridge
)

if(BUILD_TESTING)
    enable_testing()
    add_executable(
        rule_engine_python_optimizer_tests
        "${PROJECT_SOURCE_DIR}/tests/python_optimizer_tests.cpp"
        "${PROJECT_SOURCE_DIR}/tests/python_optimizer_fuzz_tests.cpp"
        "${PROJECT_SOURCE_DIR}/tests/fuzz/python_optimizer_scan_fuzz.cpp"
    )
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
            rule_engine_test_options
            Catch2::Catch2WithMain
    )
    target_compile_options(
        rule_engine_python_optimizer_tests
        PRIVATE
            $<$<AND:$<COMPILE_LANG_AND_ID:CXX,Clang>,$<CXX_COMPILER_FRONTEND_VARIANT:MSVC>>:/clang:-Wno-c2y-extensions>
            $<$<AND:$<COMPILE_LANG_AND_ID:CXX,Clang>,$<CXX_COMPILER_FRONTEND_VARIANT:GNU>>:-Wno-c2y-extensions>
    )
    add_test(NAME rule_engine_python_optimizer_tests COMMAND $<TARGET_FILE:rule_engine_python_optimizer_tests>)
endif()

if(RULE_ENGINE_BUILD_FUZZERS)
    if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        message(FATAL_ERROR "RULE_ENGINE_BUILD_FUZZERS requires Clang and libFuzzer")
    endif()
    if(WIN32 AND NOT CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC")
        message(FATAL_ERROR "RULE_ENGINE_BUILD_FUZZERS requires clang-cl on Windows")
    endif()

    add_executable(
        rule_engine_python_scan_fuzzer
        "${PROJECT_SOURCE_DIR}/tests/fuzz/python_optimizer_scan_fuzz.cpp"
    )
    if(WIN32)
        set_target_properties(
            rule_engine_python_scan_fuzzer
            PROPERTIES
                RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
        )
    endif()
    target_link_libraries(
        rule_engine_python_scan_fuzzer
        PRIVATE
            rule_engine::python_optimizer
            rule_engine::python_protocol
            rule_engine::project_options
    )
    if(CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC")
        if(CMAKE_BUILD_TYPE STREQUAL "Debug")
            message(FATAL_ERROR
                "clang-cl AddressSanitizer does not support the Debug CRT; "
                "configure fuzzers with RelWithDebInfo"
            )
        endif()
        set_property(TARGET rule_engine_python_scan_fuzzer PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
        target_compile_definitions(
            rule_engine_python_scan_fuzzer
            PRIVATE
                _DISABLE_STRING_ANNOTATION=1
                _DISABLE_VECTOR_ANNOTATION=1
        )
        foreach(rule_engine_fuzz_instrumented_target
                rule_engine_python_contract
                rule_engine_python_protocol
                rule_engine_python_optimizer)
            set_property(
                TARGET ${rule_engine_fuzz_instrumented_target}
                PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded"
            )
            target_compile_definitions(
                ${rule_engine_fuzz_instrumented_target}
                PRIVATE
                    _DISABLE_STRING_ANNOTATION=1
                    _DISABLE_VECTOR_ANNOTATION=1
            )
            target_compile_options(
                ${rule_engine_fuzz_instrumented_target}
                PRIVATE
                    /fsanitize=address
                    /clang:-fno-omit-frame-pointer
            )
        endforeach()
        target_compile_options(
            rule_engine_python_scan_fuzzer
            PRIVATE
                /fsanitize=address
                /clang:-fsanitize=fuzzer-no-link
                /clang:-fno-omit-frame-pointer
        )
        target_link_options(
            rule_engine_python_scan_fuzzer
            PRIVATE
                /INCREMENTAL:NO
        )

        execute_process(
            COMMAND "${CMAKE_CXX_COMPILER}" /clang:-print-resource-dir
            RESULT_VARIABLE rule_engine_clang_resource_result
            OUTPUT_VARIABLE rule_engine_clang_resource_dir
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
        if(NOT rule_engine_clang_resource_result EQUAL 0)
            message(FATAL_ERROR "Unable to locate the clang-cl sanitizer runtime directory")
        endif()
        set(rule_engine_clang_runtime_dir "${rule_engine_clang_resource_dir}/lib/windows")
        set(rule_engine_clang_fuzzer_runtime
            "${rule_engine_clang_runtime_dir}/clang_rt.fuzzer-x86_64.lib")
        set(rule_engine_clang_asan_runtime
            "${rule_engine_clang_runtime_dir}/clang_rt.asan_dynamic-x86_64.lib")
        set(rule_engine_clang_asan_thunk
            "${rule_engine_clang_runtime_dir}/clang_rt.asan_static_runtime_thunk-x86_64.lib")
        set(rule_engine_clang_asan_dll
            "${rule_engine_clang_runtime_dir}/clang_rt.asan_dynamic-x86_64.dll")
        foreach(rule_engine_clang_runtime
                "${rule_engine_clang_fuzzer_runtime}"
                "${rule_engine_clang_asan_runtime}"
                "${rule_engine_clang_asan_thunk}"
                "${rule_engine_clang_asan_dll}")
            if(NOT EXISTS "${rule_engine_clang_runtime}")
                message(FATAL_ERROR "Required clang-cl fuzz runtime is unavailable: ${rule_engine_clang_runtime}")
            endif()
        endforeach()
        target_link_libraries(rule_engine_python_scan_fuzzer PRIVATE "${rule_engine_clang_asan_runtime}")
        target_link_options(
            rule_engine_python_scan_fuzzer
            PRIVATE
                "/WHOLEARCHIVE:${rule_engine_clang_fuzzer_runtime}"
                "/WHOLEARCHIVE:${rule_engine_clang_asan_thunk}"
        )
        add_custom_command(
            TARGET rule_engine_python_scan_fuzzer
            POST_BUILD
            COMMAND
                "${CMAKE_COMMAND}" -E copy_if_different
                "${rule_engine_clang_asan_dll}"
                "$<TARGET_FILE_DIR:rule_engine_python_scan_fuzzer>"
            VERBATIM
        )
    else()
        foreach(rule_engine_fuzz_instrumented_target
                rule_engine_python_contract
                rule_engine_python_protocol
                rule_engine_python_optimizer)
            target_compile_options(
                ${rule_engine_fuzz_instrumented_target}
                PRIVATE
                    -fsanitize=address
                    -fno-omit-frame-pointer
            )
        endforeach()
        target_compile_options(
            rule_engine_python_scan_fuzzer
            PRIVATE
                -fsanitize=fuzzer-no-link,address
                -fno-omit-frame-pointer
        )
        target_link_options(
            rule_engine_python_scan_fuzzer
            PRIVATE
                -fsanitize=fuzzer,address
        )
    endif()

    if(BUILD_TESTING)
        set(rule_engine_python_scan_fuzzer_smoke_corpus
            "${CMAKE_CURRENT_BINARY_DIR}/python_optimizer_scan_fuzzer_corpus")
        file(MAKE_DIRECTORY "${rule_engine_python_scan_fuzzer_smoke_corpus}")
        file(
            COPY "${PROJECT_SOURCE_DIR}/tests/fuzz/corpus/python_optimizer_scan/"
            DESTINATION "${rule_engine_python_scan_fuzzer_smoke_corpus}"
        )
        add_test(
            NAME rule_engine_python_scan_fuzzer_smoke
            COMMAND
                $<TARGET_FILE:rule_engine_python_scan_fuzzer>
                -seed=195936478
                -runs=4096
                -max_len=65536
                "${rule_engine_python_scan_fuzzer_smoke_corpus}"
        )
        set_tests_properties(rule_engine_python_scan_fuzzer_smoke PROPERTIES TIMEOUT 120)
    endif()
endif()
