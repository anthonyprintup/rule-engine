cmake_minimum_required(VERSION 3.31)

foreach(required IN ITEMS RULE_ENGINE_SOURCE_DIR RULE_ENGINE_BINARY_ROOT)
    if(NOT DEFINED ${required} OR "${${required}}" STREQUAL "")
        message(FATAL_ERROR "${required} is required")
    endif()
endforeach()

cmake_path(ABSOLUTE_PATH RULE_ENGINE_SOURCE_DIR NORMALIZE OUTPUT_VARIABLE source_root)
cmake_path(ABSOLUTE_PATH RULE_ENGINE_BINARY_ROOT NORMALIZE OUTPUT_VARIABLE binary_root)
if(binary_root STREQUAL source_root)
    message(FATAL_ERROR "Real install smoke binary root cannot be the source root")
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
        message(FATAL_ERROR "Real install smoke must run without Cargo/Rust: ${found_tool}")
    endif()
endforeach()

if(NOT RULE_ENGINE_INSTALL_HOOK)
    set(RULE_ENGINE_INSTALL_HOOK "${source_root}/tests/install/real-project/InstallHook.cmake")
endif()
if(NOT RULE_ENGINE_INSTALL_MODULE)
    set(RULE_ENGINE_INSTALL_MODULE "${source_root}/cmake/RuleEngineInstall.cmake")
endif()
if(NOT RULE_ENGINE_DOWNSTREAM_SOURCE)
    set(RULE_ENGINE_DOWNSTREAM_SOURCE "${source_root}/tests/install/downstream")
endif()
cmake_path(ABSOLUTE_PATH RULE_ENGINE_INSTALL_HOOK NORMALIZE OUTPUT_VARIABLE install_hook)
cmake_path(ABSOLUTE_PATH RULE_ENGINE_INSTALL_MODULE NORMALIZE OUTPUT_VARIABLE install_module)
cmake_path(ABSOLUTE_PATH RULE_ENGINE_DOWNSTREAM_SOURCE NORMALIZE OUTPUT_VARIABLE downstream_source)
foreach(required_path IN ITEMS "${install_hook}" "${install_module}" "${downstream_source}")
    if(NOT EXISTS "${required_path}")
        message(FATAL_ERROR "Real install smoke input is missing: ${required_path}")
    endif()
endforeach()

set(producer_build "${binary_root}/producer-build")
set(downstream_build "${binary_root}/downstream-build")
set(configured_prefix "${binary_root}/configured-prefix")
set(prefix "${binary_root}/relocated-prefix")
file(REMOVE_RECURSE "${producer_build}" "${downstream_build}" "${configured_prefix}" "${prefix}")
file(MAKE_DIRECTORY "${binary_root}")

set(generator_args "")
if(DEFINED RULE_ENGINE_CMAKE_GENERATOR AND NOT RULE_ENGINE_CMAKE_GENERATOR STREQUAL "")
    list(APPEND generator_args -G "${RULE_ENGINE_CMAKE_GENERATOR}")
endif()
set(toolchain_args "")
foreach(pair IN ITEMS
    "CMAKE_C_COMPILER;RULE_ENGINE_C_COMPILER"
    "CMAKE_CXX_COMPILER;RULE_ENGINE_CXX_COMPILER"
    "CMAKE_MAKE_PROGRAM;RULE_ENGINE_MAKE_PROGRAM"
    "CMAKE_AR;RULE_ENGINE_CMAKE_AR"
    "CMAKE_LINKER;RULE_ENGINE_CMAKE_LINKER"
)
    list(GET pair 0 cmake_name)
    list(GET pair 1 input_name)
    if(DEFINED ${input_name} AND NOT "${${input_name}}" STREQUAL "")
        list(APPEND toolchain_args "-D${cmake_name}=${${input_name}}")
    endif()
endforeach()
set(fetchcontent_args -DFETCHCONTENT_FULLY_DISCONNECTED=ON)
foreach(pair IN ITEMS
    "ASIO;RULE_ENGINE_ASIO_SOURCE_DIR"
    "CATCH2;RULE_ENGINE_CATCH2_SOURCE_DIR"
    "RULE_ENGINE_ABSEIL;RULE_ENGINE_ABSEIL_SOURCE_DIR"
    "RULE_ENGINE_RE2;RULE_ENGINE_RE2_SOURCE_DIR"
)
    list(GET pair 0 dependency_name)
    list(GET pair 1 input_name)
    if(DEFINED ${input_name} AND NOT "${${input_name}}" STREQUAL "")
        list(APPEND
            fetchcontent_args
            "-DFETCHCONTENT_SOURCE_DIR_${dependency_name}=${${input_name}}"
        )
    endif()
endforeach()
if(NOT DEFINED RULE_ENGINE_REAL_SMOKE_BUILD_TESTING)
    set(RULE_ENGINE_REAL_SMOKE_BUILD_TESTING OFF)
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
    "real producer configure"
    "${CMAKE_COMMAND}"
    -S "${source_root}"
    -B "${producer_build}"
    ${generator_args}
    ${toolchain_args}
    ${fetchcontent_args}
    "-DBUILD_TESTING=${RULE_ENGINE_REAL_SMOKE_BUILD_TESTING}"
    -DRULE_ENGINE_ENABLE_INSTALL_SMOKE_TEST=OFF
    -DRULE_ENGINE_ENABLE_REAL_INSTALL_SMOKE_TEST=OFF
    -DRULE_ENGINE_INSTALL_PRIVATE_PYTHON=OFF
    "-DCMAKE_PROJECT_INCLUDE=${install_hook}"
    "-DRULE_ENGINE_INSTALL_MODULE=${install_module}"
    "-DCMAKE_INSTALL_PREFIX=${configured_prefix}"
    -DCMAKE_BUILD_TYPE=Release
)
run_checked(
    "real package build and install"
    "${CMAKE_COMMAND}" --build "${producer_build}" --target rule_engine_install_package --config Release
)
file(RENAME "${configured_prefix}" "${prefix}")

set(required_files
    "include/rule_engine/python/contract/core.hpp"
    "lib/cmake/rule_engine/rule_engineConfig.cmake"
    "lib/cmake/rule_engine/rule_engineTargets.cmake"
    "share/rule_engine/python-sdk/1.0.0/manifest.json"
    "libexec/rule_engine/python/rule_engine_python_worker.py"
    "share/rule_engine/docs/python-engine/README.md"
)
foreach(relative IN LISTS required_files)
    if(NOT EXISTS "${prefix}/${relative}")
        message(FATAL_ERROR "Real installed package is missing ${relative}")
    endif()
endforeach()

set(installed_sdk_root "${prefix}/share/rule_engine/python-sdk/1.0.0")
file(READ "${installed_sdk_root}/manifest.json" sdk_manifest)
string(JSON sdk_file_count LENGTH "${sdk_manifest}" files)
math(EXPR sdk_last_index "${sdk_file_count} - 1")
foreach(index RANGE 0 ${sdk_last_index})
    string(JSON relative GET "${sdk_manifest}" files ${index} path)
    string(JSON expected_size GET "${sdk_manifest}" files ${index} size)
    string(JSON expected_sha256 GET "${sdk_manifest}" files ${index} sha256)
    set(path "${installed_sdk_root}/${relative}")
    if(NOT EXISTS "${path}" OR IS_DIRECTORY "${path}" OR IS_SYMLINK "${path}")
        message(FATAL_ERROR "Real installed SDK entry is missing or irregular: ${relative}")
    endif()
    file(SIZE "${path}" actual_size)
    file(SHA256 "${path}" actual_sha256)
    if(NOT actual_size EQUAL expected_size OR NOT actual_sha256 STREQUAL expected_sha256)
        message(FATAL_ERROR "Real installed SDK entry is not exact: ${relative}")
    endif()
endforeach()

file(GLOB_RECURSE installed_files LIST_DIRECTORIES FALSE RELATIVE "${prefix}" "${prefix}/*")
foreach(relative IN LISTS installed_files)
    string(TOLOWER "${relative}" lower_relative)
    if(lower_relative MATCHES "(^|/)(cargo\\.toml|cargo\\.lock|target|__pycache__|cmakecache\\.txt|\\.git)(/|$)" OR
       lower_relative MATCHES "\\.(rs|yar|yara|pyc|pyo|pem|key)$")
        message(FATAL_ERROR "Forbidden material was installed by the real graph: ${relative}")
    endif()
    if(lower_relative MATCHES "python(3|w)?\\.exe$")
        message(FATAL_ERROR "Private/system Python was bundled without opt-in: ${relative}")
    endif()
endforeach()

set(config_file "${prefix}/lib/cmake/rule_engine/rule_engineConfig.cmake")
file(READ "${config_file}" config_text)
file(GLOB metadata_files "${prefix}/lib/cmake/rule_engine/*.cmake")
set(metadata_text "")
foreach(metadata_file IN LISTS metadata_files)
    file(READ "${metadata_file}" metadata_fragment)
    string(APPEND metadata_text "${metadata_fragment}")
endforeach()
string(TOLOWER "${metadata_text}" metadata_lower)
string(TOLOWER "${source_root}" source_root_lower)
string(TOLOWER "${binary_root}" binary_root_lower)
foreach(forbidden IN ITEMS
    "${source_root_lower}"
    "${binary_root_lower}"
    "cargo"
    "rust/yara"
    "yara_bridge"
    "asio::asio"
)
    string(FIND "${metadata_lower}" "${forbidden}" forbidden_index)
    if(NOT forbidden STREQUAL "" AND NOT forbidden_index EQUAL -1)
        message(FATAL_ERROR "Real installed CMake metadata contains forbidden text: ${forbidden}")
    endif()
endforeach()
if(WIN32 AND config_text MATCHES "if\\(ON\\)[\r\n ]+find_dependency\\(re2")
    message(FATAL_ERROR "Windows shared RE2 bridge incorrectly exports a system re2 dependency")
endif()

if(WIN32)
    set(executable_suffix ".exe")
else()
    set(executable_suffix "")
endif()
if(DEFINED RULE_ENGINE_EXPECTED_TOOL_NAMES AND NOT RULE_ENGINE_EXPECTED_TOOL_NAMES STREQUAL "")
    string(REPLACE "," ";" expected_tool_names "${RULE_ENGINE_EXPECTED_TOOL_NAMES}")
    foreach(tool IN LISTS expected_tool_names)
        set(executable "${prefix}/bin/${tool}${executable_suffix}")
        if(NOT EXISTS "${executable}")
            message(FATAL_ERROR "Real installed package is missing public tool ${tool}")
        endif()
        run_checked(
            "relocated ${tool} --version"
            "${executable}" --version
        )
    endforeach()
endif()

run_checked(
    "real downstream configure"
    "${CMAKE_COMMAND}"
    -S "${downstream_source}"
    -B "${downstream_build}"
    ${generator_args}
    ${toolchain_args}
    "-DCMAKE_PREFIX_PATH=${prefix}"
    -DRULE_ENGINE_DOWNSTREAM_COMPONENT=python_protocol
    -DCMAKE_BUILD_TYPE=Release
)
run_checked(
    "real downstream build"
    "${CMAKE_COMMAND}" --build "${downstream_build}" --config Release
)
set(downstream_executable "${downstream_build}/rule_engine_downstream_smoke${executable_suffix}")
if(WIN32)
    set(ENV{PATH} "${prefix}/bin;$ENV{PATH}")
elseif(APPLE)
    set(ENV{DYLD_LIBRARY_PATH} "${prefix}/lib:$ENV{DYLD_LIBRARY_PATH}")
else()
    set(ENV{LD_LIBRARY_PATH} "${prefix}/lib:$ENV{LD_LIBRARY_PATH}")
endif()
run_checked(
    "real downstream execution"
    "${downstream_executable}"
)

message(STATUS "Rule Engine real-graph install smoke passed: ${prefix}")
