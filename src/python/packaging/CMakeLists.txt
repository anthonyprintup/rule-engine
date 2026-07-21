add_library(
    rule_engine_python_packaging
    archive.cpp
    crypto.cpp
    generator.cpp
    runtime.cpp
    source_pack.cpp
    worker.cpp
    windows_worker_launcher.cpp
)
add_library(rule_engine::python_packaging ALIAS rule_engine_python_packaging)
target_include_directories(rule_engine_python_packaging PUBLIC "${PROJECT_SOURCE_DIR}/include")
target_link_libraries(
    rule_engine_python_packaging
    PUBLIC
        rule_engine::python_contract
        rule_engine::project_options
)

add_executable(rule_engine_python_runtime_stager runtime_stager_main.cpp)
target_link_libraries(rule_engine_python_runtime_stager PRIVATE rule_engine::python_packaging)

set(python_worker_script "${CMAKE_CURRENT_SOURCE_DIR}/rule_engine_python_worker.py")
set(staged_python_worker_script "${CMAKE_CURRENT_BINARY_DIR}/rule_engine_python_worker.py")
configure_file("${python_worker_script}" "${staged_python_worker_script}" COPYONLY)
file(TO_CMAKE_PATH "${staged_python_worker_script}" staged_python_worker_script_for_cxx)

set(
    RULE_ENGINE_PYTHON_RUNTIME_WORK_ROOT
    "${CMAKE_BINARY_DIR}/python-runtime"
    CACHE PATH
    "Build-tree root for the exact private CPython runtime"
)
set(
    RULE_ENGINE_PYTHON_RUNTIME_ARCHIVE
    "${RULE_ENGINE_PYTHON_RUNTIME_WORK_ROOT}/cache/python-3.14.6-embed-amd64.zip"
    CACHE FILEPATH
    "Validated cache path for the official CPython 3.14.6 Windows x64 embeddable ZIP"
)
set(
    RULE_ENGINE_PYTHON_RUNTIME_EXTRACTED_DIR
    "${RULE_ENGINE_PYTHON_RUNTIME_WORK_ROOT}/extracted-python-3.14.6"
    CACHE PATH
    "Validated extraction root for the official CPython 3.14.6 distribution"
)
set(
    RULE_ENGINE_PYTHON_RUNTIME_STAGE_DIR
    "${RULE_ENGINE_PYTHON_RUNTIME_WORK_ROOT}/python-3.14.6"
    CACHE PATH
    "Install/package-ready exact private CPython 3.14.6 runtime root"
)
option(
    RULE_ENGINE_PYTHON_RUNTIME_ALLOW_DOWNLOAD
    "Allow the explicit runtime staging target to download the pinned CPython artifact"
    OFF
)
option(
    RULE_ENGINE_PYTHON_RUNTIME_STAGE_FOR_TESTS
    "Stage the exact private CPython runtime whenever the packaging test target is built"
    OFF
)

set(python_runtime_stage_manifest "${RULE_ENGINE_PYTHON_RUNTIME_STAGE_DIR}/rule-engine-python-runtime.manifest")
add_custom_target(
    rule_engine_stage_python_runtime
    COMMAND
        "${CMAKE_COMMAND}"
        "-DRULE_ENGINE_CPYTHON_ARCHIVE:FILEPATH=${RULE_ENGINE_PYTHON_RUNTIME_ARCHIVE}"
        "-DRULE_ENGINE_CPYTHON_EXTRACT_DIR:PATH=${RULE_ENGINE_PYTHON_RUNTIME_EXTRACTED_DIR}"
        "-DRULE_ENGINE_CPYTHON_WORK_ROOT:PATH=${RULE_ENGINE_PYTHON_RUNTIME_WORK_ROOT}"
        "-DRULE_ENGINE_CPYTHON_ALLOW_DOWNLOAD:BOOL=${RULE_ENGINE_PYTHON_RUNTIME_ALLOW_DOWNLOAD}"
        -P "${CMAKE_CURRENT_SOURCE_DIR}/stage_cpython_runtime.cmake"
    COMMAND
        $<TARGET_FILE:rule_engine_python_runtime_stager>
        "${RULE_ENGINE_PYTHON_RUNTIME_ARCHIVE}"
        "${RULE_ENGINE_PYTHON_RUNTIME_EXTRACTED_DIR}"
        "${RULE_ENGINE_PYTHON_RUNTIME_STAGE_DIR}"
        "${python_worker_script}"
    BYPRODUCTS "${python_runtime_stage_manifest}"
    DEPENDS
        rule_engine_python_runtime_stager
        "${python_worker_script}"
        "${CMAKE_CURRENT_SOURCE_DIR}/stage_cpython_runtime.cmake"
    COMMENT "Staging exact private CPython 3.14.6 runtime"
    VERBATIM
)
set_property(
    TARGET rule_engine_stage_python_runtime
    PROPERTY RULE_ENGINE_PRIVATE_PYTHON_RUNTIME_ROOT "${RULE_ENGINE_PYTHON_RUNTIME_STAGE_DIR}"
)

add_executable(
    rule_engine_python_packaging_tests
    "${PROJECT_SOURCE_DIR}/tests/python_packaging_tests.cpp"
)
target_link_libraries(
    rule_engine_python_packaging_tests
    PRIVATE
        rule_engine::python_packaging
        Catch2::Catch2WithMain
)
target_compile_options(
    rule_engine_python_packaging_tests
    PRIVATE
        $<$<AND:$<COMPILE_LANG_AND_ID:CXX,Clang>,$<CXX_COMPILER_FRONTEND_VARIANT:MSVC>>:/clang:-Wno-c2y-extensions>
        $<$<AND:$<COMPILE_LANG_AND_ID:CXX,Clang>,$<CXX_COMPILER_FRONTEND_VARIANT:MSVC>>:/clang:-Wno-exit-time-destructors>
        $<$<AND:$<COMPILE_LANG_AND_ID:CXX,Clang>,$<CXX_COMPILER_FRONTEND_VARIANT:GNU>>:-Wno-c2y-extensions>
        $<$<AND:$<COMPILE_LANG_AND_ID:CXX,Clang>,$<CXX_COMPILER_FRONTEND_VARIANT:GNU>>:-Wno-exit-time-destructors>
)
target_compile_definitions(
    rule_engine_python_packaging_tests
    PRIVATE RULE_ENGINE_PACKAGING_WORKER_SCRIPT="${staged_python_worker_script_for_cxx}"
)

set(
    RULE_ENGINE_TEST_PYTHON_RUNTIME_ROOT
    "${RULE_ENGINE_PYTHON_RUNTIME_EXTRACTED_DIR}"
    CACHE PATH
    "Extracted official CPython 3.14.6 embeddable runtime used by tests"
)
set(
    RULE_ENGINE_TEST_PYTHON_RUNTIME_ARCHIVE
    "${RULE_ENGINE_PYTHON_RUNTIME_ARCHIVE}"
    CACHE FILEPATH
    "Official CPython 3.14.6 embeddable ZIP used by tests"
)
if(RULE_ENGINE_PYTHON_RUNTIME_STAGE_FOR_TESTS)
    add_dependencies(rule_engine_python_packaging_tests rule_engine_stage_python_runtime)
endif()
enable_testing()
add_test(NAME rule_engine_python_packaging_tests COMMAND $<TARGET_FILE:rule_engine_python_packaging_tests>)
if(RULE_ENGINE_TEST_PYTHON_RUNTIME_ROOT AND RULE_ENGINE_TEST_PYTHON_RUNTIME_ARCHIVE)
    set_tests_properties(
        rule_engine_python_packaging_tests
        PROPERTIES
            ENVIRONMENT
                "RULE_ENGINE_TEST_PYTHON_RUNTIME_ROOT=${RULE_ENGINE_TEST_PYTHON_RUNTIME_ROOT};RULE_ENGINE_TEST_PYTHON_RUNTIME_ARCHIVE=${RULE_ENGINE_TEST_PYTHON_RUNTIME_ARCHIVE}"
    )
endif()

foreach(runtime_stage_test_case IN ITEMS missing-cache tampered-cache path-escape)
    add_test(
        NAME "rule_engine_python_runtime_stage_${runtime_stage_test_case}"
        COMMAND
            "${CMAKE_COMMAND}"
            "-DRULE_ENGINE_TEST_CASE=${runtime_stage_test_case}"
            "-DRULE_ENGINE_STAGE_SCRIPT=${CMAKE_CURRENT_SOURCE_DIR}/stage_cpython_runtime.cmake"
            "-DRULE_ENGINE_TEST_ROOT=${CMAKE_CURRENT_BINARY_DIR}/runtime-stage-tests/${runtime_stage_test_case}"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/stage_cpython_runtime_tests.cmake"
    )
endforeach()
add_test(
    NAME rule_engine_python_runtime_stage_valid-cache
    COMMAND
        "${CMAKE_COMMAND}"
        -DRULE_ENGINE_TEST_CASE=valid-cache
        "-DRULE_ENGINE_STAGE_SCRIPT=${CMAKE_CURRENT_SOURCE_DIR}/stage_cpython_runtime.cmake"
        "-DRULE_ENGINE_TEST_ROOT=${CMAKE_CURRENT_BINARY_DIR}/runtime-stage-tests/valid-cache"
        "-DRULE_ENGINE_VALID_ARCHIVE=${RULE_ENGINE_TEST_PYTHON_RUNTIME_ARCHIVE}"
        "-DRULE_ENGINE_RUNTIME_STAGER=$<TARGET_FILE:rule_engine_python_runtime_stager>"
        "-DRULE_ENGINE_WORKER_SCRIPT=${python_worker_script}"
        -P "${CMAKE_CURRENT_SOURCE_DIR}/stage_cpython_runtime_tests.cmake"
)
