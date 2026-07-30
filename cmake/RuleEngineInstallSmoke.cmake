cmake_minimum_required(VERSION 3.31)

foreach(required IN ITEMS RULE_ENGINE_SOURCE_DIR RULE_ENGINE_BINARY_ROOT)
    if(NOT DEFINED ${required} OR "${${required}}" STREQUAL "")
        message(FATAL_ERROR "${required} is required")
    endif()
endforeach()

cmake_path(ABSOLUTE_PATH RULE_ENGINE_SOURCE_DIR NORMALIZE OUTPUT_VARIABLE source_root)
cmake_path(ABSOLUTE_PATH RULE_ENGINE_BINARY_ROOT NORMALIZE OUTPUT_VARIABLE binary_root)
if(binary_root STREQUAL source_root)
    message(FATAL_ERROR "Install smoke binary root cannot be the source root")
endif()

set(tool_dirs_to_remove "")
foreach(tool IN ITEMS cargo rustc)
    unset(found_tool)
    find_program(found_tool NAMES "${tool}" NO_CACHE)
    if(found_tool)
        cmake_path(GET found_tool PARENT_PATH tool_dir)
        cmake_path(NORMAL_PATH tool_dir OUTPUT_VARIABLE tool_dir)
        if(WIN32)
            string(TOLOWER "${tool_dir}" tool_dir)
        endif()
        list(APPEND tool_dirs_to_remove "${tool_dir}")
    endif()
endforeach()
if(WIN32)
    cmake_path(CONVERT "$ENV{PATH}" TO_CMAKE_PATH_LIST path_entries NORMALIZE)
    set(path_separator ";")
else()
    string(REPLACE ":" ";" path_entries "$ENV{PATH}")
    set(path_separator ":")
endif()
set(sanitized_path_entries "")
foreach(path_entry IN LISTS path_entries)
    if(path_entry STREQUAL "")
        continue()
    endif()
    cmake_path(NORMAL_PATH path_entry OUTPUT_VARIABLE normalized_path_entry)
    if(WIN32)
        string(TOLOWER "${normalized_path_entry}" normalized_path_entry)
    endif()
    if(NOT normalized_path_entry IN_LIST tool_dirs_to_remove)
        list(APPEND sanitized_path_entries "${path_entry}")
    endif()
endforeach()
list(JOIN sanitized_path_entries "${path_separator}" sanitized_path)
set(ENV{PATH} "${sanitized_path}")
foreach(tool IN ITEMS cargo rustc)
    unset(found_tool)
    find_program(found_tool NAMES "${tool}" NO_CACHE)
    if(found_tool)
        message(FATAL_ERROR "Install smoke must run without Cargo/Rust on PATH, but found ${found_tool}")
    endif()
endforeach()

set(producer_source "${source_root}/tests/install/producer")
set(downstream_source "${source_root}/tests/install/downstream")
foreach(required_path IN ITEMS "${producer_source}" "${downstream_source}")
    if(NOT IS_DIRECTORY "${required_path}")
        message(FATAL_ERROR "Install smoke fixture is missing: ${required_path}")
    endif()
endforeach()

set(producer_build "${binary_root}/producer-build")
set(downstream_build "${binary_root}/downstream-build")
set(missing_runtime_build "${binary_root}/missing-runtime-build")
set(configured_prefix "${binary_root}/configured-prefix")
set(prefix "${binary_root}/relocated-prefix")
file(
    REMOVE_RECURSE
    "${producer_build}"
    "${downstream_build}"
    "${missing_runtime_build}"
    "${configured_prefix}"
    "${prefix}"
)
file(MAKE_DIRECTORY "${binary_root}")

set(generator_args "")
if(DEFINED RULE_ENGINE_CMAKE_GENERATOR AND NOT RULE_ENGINE_CMAKE_GENERATOR STREQUAL "")
    list(APPEND generator_args -G "${RULE_ENGINE_CMAKE_GENERATOR}")
endif()
set(toolchain_args "")
if(DEFINED RULE_ENGINE_C_COMPILER AND NOT RULE_ENGINE_C_COMPILER STREQUAL "")
    list(APPEND toolchain_args "-DCMAKE_C_COMPILER=${RULE_ENGINE_C_COMPILER}")
endif()
if(DEFINED RULE_ENGINE_CXX_COMPILER AND NOT RULE_ENGINE_CXX_COMPILER STREQUAL "")
    list(APPEND toolchain_args "-DCMAKE_CXX_COMPILER=${RULE_ENGINE_CXX_COMPILER}")
endif()
if(DEFINED RULE_ENGINE_MAKE_PROGRAM AND NOT RULE_ENGINE_MAKE_PROGRAM STREQUAL "")
    list(APPEND toolchain_args "-DCMAKE_MAKE_PROGRAM=${RULE_ENGINE_MAKE_PROGRAM}")
endif()

function(run_checked label)
    execute_process(
        COMMAND ${ARGN}
        RESULT_VARIABLE result
        OUTPUT_VARIABLE output
        ERROR_VARIABLE error
    )
    if(NOT result EQUAL 0)
        message(FATAL_ERROR "${label} failed (${result}):\n${output}${error}")
    endif()
endfunction()

run_checked(
    "producer configure"
    "${CMAKE_COMMAND}"
    -S "${producer_source}"
    -B "${producer_build}"
    ${generator_args}
    ${toolchain_args}
    "-DRULE_ENGINE_SOURCE_ROOT=${source_root}"
    "-DCMAKE_INSTALL_PREFIX=${configured_prefix}"
    -DCMAKE_BUILD_TYPE=Release
)
run_checked("producer build" "${CMAKE_COMMAND}" --build "${producer_build}" --config Release)
run_checked("producer install" "${CMAKE_COMMAND}" --install "${producer_build}" --config Release)
file(RENAME "${configured_prefix}" "${prefix}")

execute_process(
    COMMAND
        "${CMAKE_COMMAND}"
        -S "${producer_source}"
        -B "${missing_runtime_build}"
        ${generator_args}
        ${toolchain_args}
        "-DRULE_ENGINE_SOURCE_ROOT=${source_root}"
        -DRULE_ENGINE_INSTALL_PRIVATE_PYTHON=ON
        "-DRULE_ENGINE_PRIVATE_PYTHON_RUNTIME_ROOT=${binary_root}/does-not-exist"
        -DCMAKE_BUILD_TYPE=Release
    RESULT_VARIABLE missing_runtime_result
    OUTPUT_VARIABLE missing_runtime_output
    ERROR_VARIABLE missing_runtime_error
)
if(missing_runtime_result EQUAL 0)
    message(FATAL_ERROR "Private-runtime install unexpectedly accepted an absent runtime root")
endif()
string(CONCAT missing_runtime_log "${missing_runtime_output}" "${missing_runtime_error}")
if(NOT missing_runtime_log MATCHES "system Python fallback is forbidden|runtime root does not exist")
    message(FATAL_ERROR "Missing-runtime rejection did not report the fail-closed reason")
endif()

set(required_files
    "include/rule_engine/python/contract/core.hpp"
    "lib/cmake/rule_engine/rule_engineConfig.cmake"
    "lib/cmake/rule_engine/rule_engineConfigVersion.cmake"
    "lib/cmake/rule_engine/rule_engineTargets.cmake"
    "share/rule_engine/python-sdk/1.0.0/manifest.json"
    "share/rule_engine/python-sdk/1.0.0/rule_engine/__init__.pyi"
    "share/rule_engine/python-sdk/1.0.0/rule_engine/py.typed"
    "share/rule_engine/python-sdk/1.0.0/rule_engine_generator/__init__.pyi"
    "share/rule_engine/python-sdk/1.0.0/rule_engine_generator/py.typed"
    "libexec/rule_engine/python/rule_engine_python_worker.py"
    "share/rule_engine/docs/python-engine/README.md"
    "share/rule_engine/examples/python/unsigned_process/rulepack.toml"
    "share/rule_engine/examples/python/authoring_tour/rulepack.toml"
    "share/rule_engine/examples/python/authoring_tour/src/authoring_tour/rules.py"
    "share/rule_engine/examples/python/authoring_tour/contract/08_combined_cheat_detection.py"
    "share/rule_engine/package/INSTALL_PACKAGE.md"
)
if(WIN32)
    set(executable_suffix ".exe")
else()
    set(executable_suffix "")
endif()
foreach(tool IN ITEMS pack check admin)
    list(APPEND required_files "bin/rule_engine_${tool}${executable_suffix}")
endforeach()
if(WIN32)
    list(APPEND required_files "bin/rule_engine_install_fixture_runtime.dll")
elseif(APPLE)
    list(APPEND required_files "lib/librule_engine_install_fixture_runtime.dylib")
else()
    list(APPEND required_files "lib/librule_engine_install_fixture_runtime.so")
endif()
foreach(relative IN LISTS required_files)
    if(NOT EXISTS "${prefix}/${relative}")
        message(FATAL_ERROR "Installed package is missing ${relative}")
    endif()
endforeach()

foreach(tool IN ITEMS pack check admin)
    set(executable "${prefix}/bin/rule_engine_${tool}${executable_suffix}")
    execute_process(
        COMMAND "${executable}" --version
        WORKING_DIRECTORY "${prefix}/bin"
        RESULT_VARIABLE version_result
        OUTPUT_VARIABLE version_output
        ERROR_VARIABLE version_error
    )
    if(NOT version_result EQUAL 0 OR
       NOT version_output MATCHES "^rule_engine_${tool} 1\\.0\\.0")
        message(FATAL_ERROR
            "Relocated rule_engine_${tool} --version failed (${version_result}):\n"
            "${version_output}${version_error}"
        )
    endif()
endforeach()

set(installed_sdk_root "${prefix}/share/rule_engine/python-sdk/1.0.0")
file(READ "${installed_sdk_root}/manifest.json" sdk_manifest)
string(JSON sdk_file_count LENGTH "${sdk_manifest}" files)
if(sdk_file_count LESS 1)
    message(FATAL_ERROR "Installed SDK manifest has no files")
endif()
math(EXPR sdk_last_index "${sdk_file_count} - 1")
foreach(index RANGE 0 ${sdk_last_index})
    string(JSON relative GET "${sdk_manifest}" files ${index} path)
    string(JSON expected_size GET "${sdk_manifest}" files ${index} size)
    string(JSON expected_sha256 GET "${sdk_manifest}" files ${index} sha256)
    set(path "${installed_sdk_root}/${relative}")
    if(NOT EXISTS "${path}" OR IS_DIRECTORY "${path}")
        message(FATAL_ERROR "Installed SDK manifest entry is missing: ${relative}")
    endif()
    file(SIZE "${path}" actual_size)
    file(SHA256 "${path}" actual_sha256)
    if(NOT actual_size EQUAL expected_size OR NOT actual_sha256 STREQUAL expected_sha256)
        message(FATAL_ERROR "Installed SDK manifest entry is not exact: ${relative}")
    endif()
endforeach()

file(GLOB_RECURSE installed_files LIST_DIRECTORIES FALSE RELATIVE "${prefix}" "${prefix}/*")
foreach(relative IN LISTS installed_files)
    string(TOLOWER "${relative}" lower_relative)
    if(lower_relative MATCHES "(^|/)(cargo\\.toml|cargo\\.lock|target|__pycache__|cmakecache\\.txt|\\.git)(/|$)" OR
       lower_relative MATCHES "\\.(rs|yar|yara|pyc|pyo|pem|key)$")
        message(FATAL_ERROR "Forbidden source, cache, legacy, or key material was installed: ${relative}")
    endif()
    if(lower_relative MATCHES "python(3|w)?\\.exe$")
        message(FATAL_ERROR "Private/system Python was bundled without explicit opt-in: ${relative}")
    endif()
endforeach()

file(GLOB package_metadata "${prefix}/lib/cmake/rule_engine/*.cmake")
foreach(metadata IN LISTS package_metadata)
    file(READ "${metadata}" metadata_text)
    string(TOLOWER "${metadata_text}" metadata_lower)
    if(metadata_lower MATCHES "cargo|yara_bridge|rust/yara|python_runtime_root=[a-z]:")
        message(FATAL_ERROR "Installed CMake metadata leaks a legacy or machine-local dependency: ${metadata}")
    endif()
endforeach()

run_checked(
    "downstream configure"
    "${CMAKE_COMMAND}"
    -S "${downstream_source}"
    -B "${downstream_build}"
    ${generator_args}
    ${toolchain_args}
    "-DCMAKE_PREFIX_PATH=${prefix}"
    -DCMAKE_BUILD_TYPE=Release
)
run_checked("downstream build" "${CMAKE_COMMAND}" --build "${downstream_build}" --config Release)

message(STATUS "Rule Engine clean-install smoke passed: ${prefix}")
