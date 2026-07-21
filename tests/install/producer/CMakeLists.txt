cmake_minimum_required(VERSION 3.31)
project(rule_engine_install_fixture VERSION 1.0.0 LANGUAGES CXX)

if(NOT RULE_ENGINE_SOURCE_ROOT)
    message(FATAL_ERROR "RULE_ENGINE_SOURCE_ROOT is required")
endif()

add_library(rule_engine_project_options INTERFACE)
add_library(rule_engine::project_options ALIAS rule_engine_project_options)
target_compile_features(rule_engine_project_options INTERFACE cxx_std_23)

add_library(rule_engine_python_contract STATIC contract.cpp)
add_library(rule_engine::python_contract ALIAS rule_engine_python_contract)
target_include_directories(
    rule_engine_python_contract
    PUBLIC "${RULE_ENGINE_SOURCE_ROOT}/include"
)
target_link_libraries(rule_engine_python_contract PUBLIC rule_engine::project_options)

add_library(rule_engine_install_fixture_runtime SHARED runtime_dependency.cpp)
set_target_properties(
    rule_engine_install_fixture_runtime
    PROPERTIES
        OUTPUT_NAME rule_engine_install_fixture_runtime
        WINDOWS_EXPORT_ALL_SYMBOLS ON
)

foreach(tool IN ITEMS pack check admin)
    set(target "rule_engine_python_${tool}_cli")
    add_executable("${target}" tool.cpp)
    set_target_properties("${target}" PROPERTIES OUTPUT_NAME "rule_engine_${tool}")
    target_compile_definitions("${target}" PRIVATE RULE_ENGINE_TOOL_NAME="rule_engine_${tool}")
    target_link_libraries(
        "${target}"
        PRIVATE
            rule_engine::project_options
            rule_engine_install_fixture_runtime
    )
    if(NOT WIN32)
        set_target_properties("${target}" PROPERTIES INSTALL_RPATH "$ORIGIN/../lib")
    endif()
endforeach()

set(RULE_ENGINE_INSTALL_SOURCE_DIR "${RULE_ENGINE_SOURCE_ROOT}" CACHE PATH "" FORCE)
set(
    RULE_ENGINE_INSTALL_LIBRARY_TARGETS
    "rule_engine_project_options;rule_engine_python_contract;rule_engine_install_fixture_runtime"
    CACHE STRING "" FORCE
)
set(
    RULE_ENGINE_INSTALL_EXECUTABLE_TARGETS
    "rule_engine_python_pack_cli;rule_engine_python_check_cli;rule_engine_python_admin_cli"
    CACHE STRING "" FORCE
)
set(RULE_ENGINE_ENABLE_INSTALL_SMOKE_TEST OFF CACHE BOOL "" FORCE)
if(NOT DEFINED RULE_ENGINE_INSTALL_PRIVATE_PYTHON)
    set(RULE_ENGINE_INSTALL_PRIVATE_PYTHON OFF CACHE BOOL "")
endif()
include("${RULE_ENGINE_SOURCE_ROOT}/cmake/RuleEngineInstall.cmake")
