cmake_minimum_required(VERSION 3.31)

foreach(_required IN ITEMS RULE_ENGINE_TEST_CASE RULE_ENGINE_STAGE_SCRIPT RULE_ENGINE_TEST_ROOT)
    if(NOT DEFINED ${_required} OR "${${_required}}" STREQUAL "")
        message(FATAL_ERROR "${_required} is required")
    endif()
endforeach()

cmake_path(ABSOLUTE_PATH RULE_ENGINE_TEST_ROOT NORMALIZE OUTPUT_VARIABLE _test_root)
cmake_path(GET _test_root PARENT_PATH _test_parent)
cmake_path(IS_PREFIX _test_parent "${_test_root}" NORMALIZE _test_root_is_scoped)
if(NOT _test_root_is_scoped OR "${_test_root}" STREQUAL "${_test_parent}")
    message(FATAL_ERROR "test root must be a scoped child directory")
endif()
file(REMOVE_RECURSE "${_test_root}")
file(MAKE_DIRECTORY "${_test_root}")

set(_archive "${_test_root}/cache/python-3.14.6-embed-amd64.zip")
set(_extract "${_test_root}/work/extracted")
set(_stage "${_test_root}/work/staged")

function(_run_stage _result_out _output_out)
    execute_process(
        COMMAND
            "${CMAKE_COMMAND}"
            "-DRULE_ENGINE_CPYTHON_ARCHIVE:FILEPATH=${_archive}"
            "-DRULE_ENGINE_CPYTHON_EXTRACT_DIR:PATH=${_extract}"
            "-DRULE_ENGINE_CPYTHON_WORK_ROOT:PATH=${_test_root}/work"
            -DRULE_ENGINE_CPYTHON_ALLOW_DOWNLOAD:BOOL=OFF
            -P "${RULE_ENGINE_STAGE_SCRIPT}"
        RESULT_VARIABLE _result
        OUTPUT_VARIABLE _stdout
        ERROR_VARIABLE _stderr
    )
    set(${_result_out} "${_result}" PARENT_SCOPE)
    set(${_output_out} "${_stdout}\n${_stderr}" PARENT_SCOPE)
endfunction()

if(RULE_ENGINE_TEST_CASE STREQUAL "missing-cache")
    _run_stage(_result _output)
    if(_result EQUAL 0 OR NOT _output MATCHES "offline mode requires the pinned CPython 3.14.6 archive")
        message(FATAL_ERROR "missing offline cache was not rejected as expected:\n${_output}")
    endif()
    if(EXISTS "${_extract}")
        message(FATAL_ERROR "missing-cache failure published an extraction directory")
    endif()
    return()
endif()

if(RULE_ENGINE_TEST_CASE STREQUAL "tampered-cache")
    file(MAKE_DIRECTORY "${_test_root}/cache")
    file(WRITE "${_archive}" "tampered-cache")
    _run_stage(_result _output)
    if(_result EQUAL 0 OR NOT _output MATCHES "cached CPython archive digest mismatch in offline mode")
        message(FATAL_ERROR "tampered offline cache was not rejected as expected:\n${_output}")
    endif()
    file(READ "${_archive}" _preserved_cache)
    if(NOT _preserved_cache STREQUAL "tampered-cache")
        message(FATAL_ERROR "offline failure unexpectedly replaced the tampered cache")
    endif()
    if(EXISTS "${_extract}")
        message(FATAL_ERROR "tampered-cache failure published an extraction directory")
    endif()
    return()
endif()

if(RULE_ENGINE_TEST_CASE STREQUAL "path-escape")
    set(_escaped_extract "${_test_parent}/escaped-runtime")
    execute_process(
        COMMAND
            "${CMAKE_COMMAND}"
            "-DRULE_ENGINE_CPYTHON_ARCHIVE:FILEPATH=${_archive}"
            "-DRULE_ENGINE_CPYTHON_EXTRACT_DIR:PATH=${_escaped_extract}"
            "-DRULE_ENGINE_CPYTHON_WORK_ROOT:PATH=${_test_root}/work"
            -DRULE_ENGINE_CPYTHON_ALLOW_DOWNLOAD:BOOL=OFF
            -P "${RULE_ENGINE_STAGE_SCRIPT}"
        RESULT_VARIABLE _result
        OUTPUT_VARIABLE _stdout
        ERROR_VARIABLE _stderr
    )
    if(_result EQUAL 0 OR NOT "${_stdout}\n${_stderr}" MATCHES "must be a scoped child")
        message(FATAL_ERROR "extraction path escape was not rejected:\n${_stdout}\n${_stderr}")
    endif()
    if(EXISTS "${_escaped_extract}")
        message(FATAL_ERROR "path-escape failure modified the out-of-scope extraction path")
    endif()
    return()
endif()

if(RULE_ENGINE_TEST_CASE STREQUAL "valid-cache")
    foreach(_valid_required IN ITEMS RULE_ENGINE_VALID_ARCHIVE RULE_ENGINE_RUNTIME_STAGER RULE_ENGINE_WORKER_SCRIPT)
        if(NOT DEFINED ${_valid_required} OR "${${_valid_required}}" STREQUAL "" OR
           NOT EXISTS "${${_valid_required}}")
            message(STATUS "SKIPPED: exact CPython 3.14.6 artifact or staging input is unavailable")
            return()
        endif()
    endforeach()

    file(MAKE_DIRECTORY "${_test_root}/cache")
    file(COPY_FILE "${RULE_ENGINE_VALID_ARCHIVE}" "${_archive}" ONLY_IF_DIFFERENT)
    _run_stage(_result _output)
    if(NOT _result EQUAL 0)
        message(FATAL_ERROR "valid offline cache could not be extracted:\n${_output}")
    endif()
    if(NOT EXISTS "${_extract}/python.exe")
        message(FATAL_ERROR "valid offline cache did not produce python.exe")
    endif()

    execute_process(
        COMMAND
            "${RULE_ENGINE_RUNTIME_STAGER}"
            "${_archive}"
            "${_extract}"
            "${_stage}"
            "${RULE_ENGINE_WORKER_SCRIPT}"
        RESULT_VARIABLE _stager_result
        OUTPUT_VARIABLE _stager_stdout
        ERROR_VARIABLE _stager_stderr
    )
    if(NOT _stager_result EQUAL 0 OR NOT EXISTS "${_stage}/rule-engine-python-runtime.manifest")
        message(FATAL_ERROR
            "exact per-file runtime staging validation failed:\n${_stager_stdout}\n${_stager_stderr}")
    endif()

    file(APPEND "${_stage}/python.exe" "tamper")
    execute_process(
        COMMAND
            "${RULE_ENGINE_RUNTIME_STAGER}"
            "${_archive}"
            "${_extract}"
            "${_stage}"
            "${RULE_ENGINE_WORKER_SCRIPT}"
        RESULT_VARIABLE _tampered_result
        OUTPUT_VARIABLE _tampered_stdout
        ERROR_VARIABLE _tampered_stderr
    )
    if(_tampered_result EQUAL 0 OR NOT _tampered_stderr MATCHES "digest|size")
        message(FATAL_ERROR
            "tampered staged runtime passed manifest validation:\n${_tampered_stdout}\n${_tampered_stderr}")
    endif()
    return()
endif()

message(FATAL_ERROR "unknown runtime staging test case: ${RULE_ENGINE_TEST_CASE}")
