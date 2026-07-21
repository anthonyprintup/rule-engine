cmake_minimum_required(VERSION 3.31)

set(_cpython_url "https://www.python.org/ftp/python/3.14.6/python-3.14.6-embed-amd64.zip")
set(_cpython_sha256 "df901e84a896ff1ee720ad03377e0c8d8c2244fda79808aeeaff6316df1cb75c")

foreach(_required IN ITEMS
        RULE_ENGINE_CPYTHON_ARCHIVE
        RULE_ENGINE_CPYTHON_EXTRACT_DIR
        RULE_ENGINE_CPYTHON_WORK_ROOT)
    if(NOT DEFINED ${_required} OR "${${_required}}" STREQUAL "")
        message(FATAL_ERROR "${_required} is required")
    endif()
endforeach()

if(NOT DEFINED RULE_ENGINE_CPYTHON_ALLOW_DOWNLOAD)
    set(RULE_ENGINE_CPYTHON_ALLOW_DOWNLOAD OFF)
endif()

cmake_path(ABSOLUTE_PATH RULE_ENGINE_CPYTHON_ARCHIVE NORMALIZE OUTPUT_VARIABLE _archive)
cmake_path(ABSOLUTE_PATH RULE_ENGINE_CPYTHON_EXTRACT_DIR NORMALIZE OUTPUT_VARIABLE _extract_dir)
cmake_path(ABSOLUTE_PATH RULE_ENGINE_CPYTHON_WORK_ROOT NORMALIZE OUTPUT_VARIABLE _work_root)
cmake_path(IS_PREFIX _work_root "${_extract_dir}" NORMALIZE _extract_is_scoped)
if(NOT _extract_is_scoped OR "${_extract_dir}" STREQUAL "${_work_root}")
    message(FATAL_ERROR "CPython extraction directory must be a scoped child of the runtime work root")
endif()

cmake_path(GET _archive PARENT_PATH _archive_parent)
file(MAKE_DIRECTORY "${_archive_parent}" "${_work_root}")

set(_cache_valid OFF)
if(EXISTS "${_archive}")
    if(IS_DIRECTORY "${_archive}" OR IS_SYMLINK "${_archive}")
        message(FATAL_ERROR "cached CPython archive must be a regular file: ${_archive}")
    endif()
    file(SHA256 "${_archive}" _cached_sha256)
    if(_cached_sha256 STREQUAL _cpython_sha256)
        set(_cache_valid ON)
    elseif(NOT RULE_ENGINE_CPYTHON_ALLOW_DOWNLOAD)
        message(FATAL_ERROR
            "cached CPython archive digest mismatch in offline mode: expected ${_cpython_sha256}, got ${_cached_sha256}")
    endif()
endif()

if(NOT _cache_valid)
    if(NOT RULE_ENGINE_CPYTHON_ALLOW_DOWNLOAD)
        message(FATAL_ERROR
            "offline mode requires the pinned CPython 3.14.6 archive at ${_archive}; no system Python fallback is permitted")
    endif()

    set(_download "${_archive}.download")
    file(REMOVE "${_download}")
    file(
        DOWNLOAD "${_cpython_url}" "${_download}"
        EXPECTED_HASH "SHA256=${_cpython_sha256}"
        TLS_VERIFY ON
        TIMEOUT 120
        INACTIVITY_TIMEOUT 30
        STATUS _download_status
    )
    list(GET _download_status 0 _download_code)
    list(GET _download_status 1 _download_message)
    if(NOT _download_code EQUAL 0)
        file(REMOVE "${_download}")
        message(FATAL_ERROR "failed to download pinned CPython runtime: ${_download_message}")
    endif()

    if(EXISTS "${_archive}")
        file(REMOVE "${_archive}")
    endif()
    file(RENAME "${_download}" "${_archive}" RESULT _rename_result)
    if(NOT _rename_result STREQUAL "0")
        file(REMOVE "${_download}")
        message(FATAL_ERROR "cannot publish validated CPython archive cache: ${_rename_result}")
    endif()
endif()

# Re-hash even a successful download before extraction. This makes cache reuse
# and the online path converge on the same trusted artifact decision.
file(SHA256 "${_archive}" _archive_sha256)
if(NOT _archive_sha256 STREQUAL _cpython_sha256)
    message(FATAL_ERROR "CPython archive changed after validation; refusing extraction")
endif()

set(_extract_staging "${_extract_dir}.staging")
cmake_path(IS_PREFIX _work_root "${_extract_staging}" NORMALIZE _staging_is_scoped)
if(NOT _staging_is_scoped OR "${_extract_staging}" STREQUAL "${_work_root}")
    message(FATAL_ERROR "CPython extraction staging directory escaped the runtime work root")
endif()

file(REMOVE_RECURSE "${_extract_staging}")
file(MAKE_DIRECTORY "${_extract_staging}")
file(ARCHIVE_EXTRACT INPUT "${_archive}" DESTINATION "${_extract_staging}")

if(EXISTS "${_extract_dir}")
    file(REMOVE_RECURSE "${_extract_dir}")
endif()
file(RENAME "${_extract_staging}" "${_extract_dir}" RESULT _extract_rename_result)
if(NOT _extract_rename_result STREQUAL "0")
    file(REMOVE_RECURSE "${_extract_staging}")
    message(FATAL_ERROR "cannot publish extracted CPython distribution: ${_extract_rename_result}")
endif()

message(STATUS "Validated and extracted pinned CPython 3.14.6 runtime from ${_archive}")
