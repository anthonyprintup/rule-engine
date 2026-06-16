cmake_minimum_required(VERSION 3.31)
project(rule_engine LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(MSVC OR CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC")
    foreach(flag_var CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELEASE CMAKE_CXX_FLAGS_RELWITHDEBINFO)
        string(REPLACE "/EHsc" "" ${flag_var} "${${flag_var}}")
        string(REPLACE "/GR" "" ${flag_var} "${${flag_var}}")
    endforeach()
endif()

include(FetchContent)

FetchContent_Declare(
    fmt
    SYSTEM
    GIT_REPOSITORY https://github.com/fmtlib/fmt.git
    GIT_TAG 11.1.4
)
FetchContent_MakeAvailable(fmt)

add_library(rule_engine_fmt INTERFACE)
add_library(rule_engine::fmt ALIAS rule_engine_fmt)
target_include_directories(rule_engine_fmt SYSTEM INTERFACE "${fmt_SOURCE_DIR}/include")
target_compile_definitions(rule_engine_fmt INTERFACE FMT_HEADER_ONLY=1)

FetchContent_Declare(
    spdlog
    SYSTEM
    GIT_REPOSITORY https://github.com/gabime/spdlog.git
    GIT_TAG v1.15.3
)
FetchContent_MakeAvailable(spdlog)
if(TARGET spdlog)
    set_target_properties(spdlog PROPERTIES EXCLUDE_FROM_ALL TRUE)
endif()

add_library(rule_engine_spdlog INTERFACE)
add_library(rule_engine::spdlog ALIAS rule_engine_spdlog)
target_link_libraries(rule_engine_spdlog INTERFACE spdlog::spdlog_header_only rule_engine::fmt)
target_compile_definitions(rule_engine_spdlog INTERFACE SPDLOG_FMT_EXTERNAL=1)
target_include_directories(rule_engine_spdlog SYSTEM INTERFACE "${spdlog_SOURCE_DIR}/include")

FetchContent_Declare(
    cli11
    SYSTEM
    GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
    GIT_TAG v2.5.0
)
FetchContent_MakeAvailable(cli11)

add_library(rule_engine_cli11 INTERFACE)
add_library(rule_engine::cli11 ALIAS rule_engine_cli11)
target_include_directories(rule_engine_cli11 SYSTEM INTERFACE "${cli11_SOURCE_DIR}/include")

FetchContent_Declare(
    asio
    SYSTEM
    GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
    GIT_TAG asio-1-36-0
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

FetchContent_Declare(
    boost_sml
    SYSTEM
    URL https://github.com/boost-ext/sml/archive/refs/tags/v1.1.13.tar.gz
)
FetchContent_MakeAvailable(boost_sml)

add_library(rule_engine_sml INTERFACE)
add_library(rule_engine::sml ALIAS rule_engine_sml)
target_include_directories(rule_engine_sml SYSTEM INTERFACE "${boost_sml_SOURCE_DIR}/include")

FetchContent_Declare(
    protocyte
    SYSTEM
    GIT_REPOSITORY https://github.com/anthonyprintup/protocyte.git
    GIT_TAG 143e6aad3c704794a354669dca7e34b5287a815e
)
FetchContent_MakeAvailable(protocyte)

foreach(target_name IN ITEMS protocyte_runtime protocyte_runtime_hosted protocyte_codegen)
    if(TARGET "${target_name}")
        set_target_properties("${target_name}" PROPERTIES SYSTEM ON)
        target_include_directories("${target_name}" SYSTEM INTERFACE "$<BUILD_INTERFACE:${protocyte_SOURCE_DIR}/src>")
    endif()
endforeach()

FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG v3.7.1
)
FetchContent_MakeAvailable(Catch2)

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
        >
)

find_program(RULE_ENGINE_CARGO NAMES cargo REQUIRED)
if(CMAKE_BUILD_TYPE MATCHES "^[Rr]elease$")
    set(RULE_ENGINE_CARGO_PROFILE release)
    set(RULE_ENGINE_CARGO_FLAGS --release)
else()
    set(RULE_ENGINE_CARGO_PROFILE debug)
    set(RULE_ENGINE_CARGO_FLAGS)
endif()
set(RULE_ENGINE_YARA_BRIDGE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/rust/yara_bridge")
set(RULE_ENGINE_YARA_BRIDGE_LIB "${RULE_ENGINE_YARA_BRIDGE_DIR}/target/${RULE_ENGINE_CARGO_PROFILE}/yara_bridge.lib")
set(RULE_ENGINE_YARA_BRIDGE_HEADER "${RULE_ENGINE_YARA_BRIDGE_DIR}/generated/rule_engine/yara_bridge.hpp")
file(GLOB RULE_ENGINE_YARA_BRIDGE_SOURCES CONFIGURE_DEPENDS "${RULE_ENGINE_YARA_BRIDGE_DIR}/src/*.rs")
add_custom_command(
    OUTPUT "${RULE_ENGINE_YARA_BRIDGE_LIB}" "${RULE_ENGINE_YARA_BRIDGE_HEADER}"
    COMMAND "${RULE_ENGINE_CARGO}" build ${RULE_ENGINE_CARGO_FLAGS}
    WORKING_DIRECTORY "${RULE_ENGINE_YARA_BRIDGE_DIR}"
    DEPENDS
        "${RULE_ENGINE_YARA_BRIDGE_DIR}/Cargo.toml"
        "${RULE_ENGINE_YARA_BRIDGE_DIR}/build.rs"
        "${RULE_ENGINE_YARA_BRIDGE_DIR}/cbindgen.toml"
        ${RULE_ENGINE_YARA_BRIDGE_SOURCES}
    COMMENT "Building Rust YARA-X parser bridge"
    VERBATIM
)
add_custom_target(rule_engine_yara_bridge_build DEPENDS "${RULE_ENGINE_YARA_BRIDGE_LIB}" "${RULE_ENGINE_YARA_BRIDGE_HEADER}")
add_library(rule_engine_yara_bridge STATIC IMPORTED GLOBAL)
set_target_properties(rule_engine_yara_bridge PROPERTIES IMPORTED_LOCATION "${RULE_ENGINE_YARA_BRIDGE_LIB}")
add_dependencies(rule_engine_yara_bridge rule_engine_yara_bridge_build)
target_include_directories(rule_engine_yara_bridge INTERFACE "${RULE_ENGINE_YARA_BRIDGE_DIR}/generated")
if(WIN32)
    target_link_libraries(rule_engine_yara_bridge INTERFACE ntdll userenv ws2_32 bcrypt advapi32)
endif()

find_program(RULE_ENGINE_CLANG_FORMAT NAMES clang-format clang-format.exe)
set(RULE_ENGINE_PROTOCYTE_OPTIONS "clang_format_config=${CMAKE_SOURCE_DIR}/.clang-format")
if(RULE_ENGINE_CLANG_FORMAT)
    list(APPEND RULE_ENGINE_PROTOCYTE_OPTIONS "clang_format=${RULE_ENGINE_CLANG_FORMAT}")
endif()

protocyte_add_proto_library(
    TARGET rule_engine_protocols
    ALIAS rule_engine::protocols
    PROTO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/src/proto"
    OUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated"
    DISCOVER
    OPTIONS ${RULE_ENGINE_PROTOCYTE_OPTIONS}
)
target_compile_definitions(
    rule_engine_protocols
    PUBLIC
        PROTOCYTE_ENABLE_STD_STRING_VIEW=1
        PROTOCYTE_ENABLE_FMT_FORMAT=1
        PROTOCYTE_ENABLE_HOSTED_ALLOCATOR=1
)

add_library(
    rule_engine_core
    src/compiler.cpp
    src/evaluator.cpp
    src/modules.cpp
    src/pattern_fixture_provider.cpp
    src/client_protocol.cpp
    src/protocol.cpp
    src/trace.cpp
    src/windows/pe_provider.cpp
    src/windows/process_provider.cpp
)
add_library(rule_engine::core ALIAS rule_engine_core)
target_include_directories(rule_engine_core PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_include_directories(rule_engine_core SYSTEM PUBLIC "${CMAKE_CURRENT_BINARY_DIR}/generated")
target_include_directories(rule_engine_core SYSTEM PUBLIC "${RULE_ENGINE_YARA_BRIDGE_DIR}/generated")
add_dependencies(rule_engine_core rule_engine_yara_bridge_build)
target_link_libraries(
    rule_engine_core
    PUBLIC
        rule_engine::project_options
        rule_engine::protocols
        protocyte::runtime
    PRIVATE
        rule_engine_yara_bridge
        rule_engine::fmt
        asio::asio
)
if(WIN32)
    target_link_libraries(rule_engine_core PRIVATE psapi version wintrust crypt32)
endif()

add_executable(rule_engine_check src/tools/rule_engine_check.cpp)
target_link_libraries(rule_engine_check PRIVATE rule_engine::core rule_engine::cli11 rule_engine::fmt)

add_executable(rule_engine_server src/tools/rule_engine_server.cpp)
target_link_libraries(rule_engine_server PRIVATE rule_engine::core rule_engine::cli11 rule_engine::fmt asio::asio)

add_executable(rule_engine_client src/tools/rule_engine_client.cpp)
target_link_libraries(rule_engine_client PRIVATE rule_engine::core rule_engine::cli11 rule_engine::fmt asio::asio)

enable_testing()

add_executable(
    rule_engine_tests
    tests/test_main.cpp
    tests/parser_bridge_tests.cpp
    tests/semantic_vm_tests.cpp
    tests/scheduler_tests.cpp
    tests/protocol_tests.cpp
    tests/runtime_harness_tests.cpp
    tests/trace_tests.cpp
)
target_include_directories(
    rule_engine_tests
    PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/support"
)
target_link_libraries(rule_engine_tests PRIVATE rule_engine::core Catch2::Catch2 asio::asio)
add_dependencies(rule_engine_tests rule_engine_yara_bridge_build)
add_dependencies(rule_engine_tests rule_engine_client)
target_compile_definitions(rule_engine_tests PRIVATE RULE_ENGINE_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}")
target_compile_options(
    rule_engine_tests
    PRIVATE
        $<$<AND:$<COMPILE_LANG_AND_ID:CXX,Clang>,$<CXX_COMPILER_FRONTEND_VARIANT:MSVC>>:/clang:-Wno-c2y-extensions>
        $<$<AND:$<COMPILE_LANG_AND_ID:CXX,Clang>,$<CXX_COMPILER_FRONTEND_VARIANT:GNU>>:-Wno-c2y-extensions>
)

add_executable(rule_engine_abort_probe tests/abort_probe.cpp)
target_include_directories(rule_engine_abort_probe PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/tests/support")
target_link_libraries(rule_engine_abort_probe PRIVATE rule_engine::project_options)
add_dependencies(rule_engine_tests rule_engine_abort_probe)

include(CTest)
include("${catch2_SOURCE_DIR}/extras/Catch.cmake")
catch_discover_tests(rule_engine_tests)
