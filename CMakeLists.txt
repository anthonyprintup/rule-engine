cmake_minimum_required(VERSION 3.31)
project(rule_engine VERSION 2.0.0 LANGUAGES C CXX)

if(WIN32 AND CMAKE_GENERATOR MATCHES "^Ninja")
    execute_process(
        COMMAND "${CMAKE_MAKE_PROGRAM}" --version
        RESULT_VARIABLE rule_engine_ninja_result
        OUTPUT_VARIABLE rule_engine_ninja_version
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
    if(NOT rule_engine_ninja_result EQUAL 0 OR rule_engine_ninja_version VERSION_LESS 1.13.2)
        message(FATAL_ERROR
            "Rule Engine requires Ninja 1.13.2 or newer on Windows; "
            "older Ninja dyndep handling can assert while building this graph"
        )
    endif()
endif()

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(CTest)
include(FetchContent)

FetchContent_Declare(
    asio
    SYSTEM
    GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
    GIT_TAG 231cb29bab30f82712fcd54faaea42424cc6e710
)
FetchContent_MakeAvailable(asio)

add_library(rule_engine_asio INTERFACE)
add_library(asio::asio ALIAS rule_engine_asio)
target_include_directories(rule_engine_asio SYSTEM INTERFACE "${asio_SOURCE_DIR}/asio/include")
target_compile_definitions(
    rule_engine_asio
    INTERFACE
        ASIO_NO_DEPRECATED
        ASIO_STANDALONE
        ASIO_NO_EXCEPTIONS
        ASIO_NO_TYPEID
        ASIO_NO_TS_EXECUTORS
        ASIO_DISABLE_STD_ANY
)
if(WIN32)
    target_compile_definitions(rule_engine_asio INTERFACE _WIN32_WINNT=0x0A00)
    target_link_libraries(rule_engine_asio INTERFACE ws2_32)
endif()

set(PROTOCYTE_FETCH_PROTOBUF ON CACHE BOOL "Rule Engine generates its typed Protocol v2 wire model" FORCE)
set(PROTOCYTE_INSTALL OFF CACHE BOOL "Protocyte is a private Rule Engine build dependency" FORCE)
FetchContent_Declare(
    protocyte
    SYSTEM
    GIT_REPOSITORY https://github.com/anthonyprintup/protocyte.git
    GIT_TAG ec9dada8df14306dadffaa9e00853d2e39ade83f
)
FetchContent_MakeAvailable(protocyte)

if(BUILD_TESTING)
    FetchContent_Declare(
        Catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG fa43b77429ba76c462b1898d6cd2f2d7a9416b14
    )
    FetchContent_MakeAvailable(Catch2)
endif()

# Keep the host compiler's exception/RTTI defaults for third-party dependencies
# and Catch2. Rule Engine production targets opt out through project_options;
# the MSVC defaults are removed in this directory so the opt-out is not an
# override warning. Optimizer-owned dependencies temporarily restore these
# captured values in their own subdirectory.
if(MSVC OR CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC")
    foreach(
        flag_var
        CMAKE_CXX_FLAGS
        CMAKE_CXX_FLAGS_DEBUG
        CMAKE_CXX_FLAGS_RELEASE
        CMAKE_CXX_FLAGS_RELWITHDEBINFO
        CMAKE_CXX_FLAGS_MINSIZEREL
    )
        set("RULE_ENGINE_DEPENDENCY_${flag_var}" "${${flag_var}}")
        string(REPLACE "/EHsc" "" ${flag_var} "${${flag_var}}")
        string(REPLACE "/GR" "" ${flag_var} "${${flag_var}}")
    endforeach()
endif()

add_library(rule_engine_project_options INTERFACE)
add_library(rule_engine::project_options ALIAS rule_engine_project_options)
target_compile_features(rule_engine_project_options INTERFACE cxx_std_23)
target_compile_options(
    rule_engine_project_options
    INTERFACE
        $<$<COMPILE_LANG_AND_ID:CXX,Clang>:
            -Wall
            -Wextra
            -Wshadow-all
            -Wpedantic
            -Wconversion
            -mavx2
            -Wno-gnu-string-literal-operator-template
            -Wno-gnu-conditional-omitted-operand
            -Wno-c++98-compat
            -Wno-c++98-compat-pedantic
            -Wno-c++20-compat
            -Wno-unsafe-buffer-usage
            -Wno-ctad-maybe-unsupported
            -Wno-language-extension-token
            -Wno-covered-switch-default
            -Wno-padded
        >
        $<$<AND:$<COMPILE_LANG_AND_ID:CXX,Clang>,$<CXX_COMPILER_FRONTEND_VARIANT:MSVC>>:
            /EHs-c-
            /GR-
            /clang:-fno-exceptions
            /clang:-fno-rtti
            /clang:-masm=intel
            /clang:-Wno-nrvo
        >
        $<$<AND:$<COMPILE_LANG_AND_ID:CXX,Clang>,$<CXX_COMPILER_FRONTEND_VARIANT:GNU>>:
            -masm=intel
            -Wno-nrvo
        >
        $<$<COMPILE_LANG_AND_ID:CXX,GNU>:
            -Wall
            -Wextra
            -Wshadow
            -Wpedantic
            -Wconversion
            -mavx2
            -masm=intel
            -fno-exceptions
            -fno-rtti
        >
        $<$<COMPILE_LANG_AND_ID:CXX,MSVC>:
            /W4
            /permissive-
            /arch:AVX2
            /EHs-c-
            /GR-
            /wd4530
        >
)

add_library(rule_engine_test_options INTERFACE)
target_compile_options(
    rule_engine_test_options
    INTERFACE
        $<$<OR:$<COMPILE_LANG_AND_ID:CXX,MSVC>,$<AND:$<COMPILE_LANG_AND_ID:CXX,Clang>,$<CXX_COMPILER_FRONTEND_VARIANT:MSVC>>>:
            /EHsc
            /GR
        >
)

if(BUILD_TESTING)
    add_test(
        NAME rule_engine_python_only_source_gate
        COMMAND
            "${CMAKE_COMMAND}"
            -DRULE_ENGINE_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
            -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/VerifyPythonOnly.cmake"
    )
endif()

add_library(rule_engine_python_contract src/python/contract.cpp)
add_library(rule_engine::python_contract ALIAS rule_engine_python_contract)
target_include_directories(rule_engine_python_contract PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_compile_features(rule_engine_python_contract PUBLIC cxx_std_23)
target_link_libraries(rule_engine_python_contract PRIVATE rule_engine::project_options)

add_library(rule_engine_python_engine src/python/engine.cpp)
add_library(rule_engine::python_engine ALIAS rule_engine_python_engine)
target_include_directories(rule_engine_python_engine PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(
    rule_engine_python_engine
    PUBLIC rule_engine::python_contract
    PRIVATE rule_engine::project_options
)

add_subdirectory(src/python/packaging)
add_subdirectory(src/python/compiler)
add_subdirectory(src/python/vm)
add_subdirectory(src/python/effects)
add_subdirectory(src/python/events)
add_subdirectory(src/python/protocol)
add_subdirectory(src/python/cluster)
add_subdirectory(src/python/optimizer)
add_subdirectory(src/python/runtime)
add_subdirectory(src/python/tools)
if(WIN32)
    add_subdirectory(src/python/windows)
endif()

if(BUILD_TESTING)
    include("${catch2_SOURCE_DIR}/extras/Catch.cmake")

    add_executable(rule_engine_python_contract_tests tests/python_contract_tests.cpp)
    target_link_libraries(
        rule_engine_python_contract_tests
        PRIVATE
            rule_engine::python_contract
            rule_engine_test_options
            Catch2::Catch2WithMain
    )
    target_compile_options(
        rule_engine_python_contract_tests
        PRIVATE
            $<$<AND:$<COMPILE_LANG_AND_ID:CXX,Clang>,$<CXX_COMPILER_FRONTEND_VARIANT:MSVC>>:/clang:-Wno-c2y-extensions>
            $<$<AND:$<COMPILE_LANG_AND_ID:CXX,Clang>,$<CXX_COMPILER_FRONTEND_VARIANT:GNU>>:-Wno-c2y-extensions>
    )
    catch_discover_tests(rule_engine_python_contract_tests)

    add_executable(rule_engine_python_engine_tests tests/python_engine_tests.cpp)
    target_link_libraries(
        rule_engine_python_engine_tests
        PRIVATE
            rule_engine::python_engine
            rule_engine_test_options
            Catch2::Catch2WithMain
    )
    target_compile_options(
        rule_engine_python_engine_tests
        PRIVATE
            $<$<AND:$<COMPILE_LANG_AND_ID:CXX,Clang>,$<CXX_COMPILER_FRONTEND_VARIANT:MSVC>>:
                /clang:-Wno-c2y-extensions
                /clang:-Wno-missing-designated-field-initializers
            >
            $<$<AND:$<COMPILE_LANG_AND_ID:CXX,Clang>,$<CXX_COMPILER_FRONTEND_VARIANT:GNU>>:
                -Wno-c2y-extensions
                -Wno-missing-designated-field-initializers
            >
    )
    catch_discover_tests(rule_engine_python_engine_tests)

    add_executable(rule_engine_python_integration_tests tests/python_integration_tests.cpp)
    target_link_libraries(
        rule_engine_python_integration_tests
        PRIVATE
            rule_engine::python_engine
            rule_engine::python_compiler
            rule_engine::python_vm
            rule_engine::python_cluster
            rule_engine_test_options
            Catch2::Catch2WithMain
    )
    target_compile_options(
        rule_engine_python_integration_tests
        PRIVATE
            $<$<AND:$<COMPILE_LANG_AND_ID:CXX,Clang>,$<CXX_COMPILER_FRONTEND_VARIANT:MSVC>>:
                /clang:-Wno-c2y-extensions
                /clang:-Wno-missing-designated-field-initializers
            >
            $<$<AND:$<COMPILE_LANG_AND_ID:CXX,Clang>,$<CXX_COMPILER_FRONTEND_VARIANT:GNU>>:
                -Wno-c2y-extensions
                -Wno-missing-designated-field-initializers
            >
    )
    catch_discover_tests(rule_engine_python_integration_tests)
endif()

include(cmake/RuleEngineInstall.cmake)
