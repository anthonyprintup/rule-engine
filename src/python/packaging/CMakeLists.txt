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

set(python_worker_script "${CMAKE_CURRENT_SOURCE_DIR}/rule_engine_python_worker.py")
set(staged_python_worker_script "${CMAKE_CURRENT_BINARY_DIR}/rule_engine_python_worker.py")
configure_file("${python_worker_script}" "${staged_python_worker_script}" COPYONLY)
file(TO_CMAKE_PATH "${staged_python_worker_script}" staged_python_worker_script_for_cxx)

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

set(RULE_ENGINE_TEST_PYTHON_RUNTIME_ROOT "" CACHE PATH "Extracted official CPython 3.14.6 embeddable runtime")
set(RULE_ENGINE_TEST_PYTHON_RUNTIME_ARCHIVE "" CACHE FILEPATH "Official CPython 3.14.6 embeddable ZIP")
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
