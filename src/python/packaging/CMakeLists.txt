add_library(
    rule_engine_python_packaging
    generator.cpp
    runtime.cpp
    source_pack.cpp
    worker.cpp
)
add_library(rule_engine::python_packaging ALIAS rule_engine_python_packaging)
target_include_directories(rule_engine_python_packaging PUBLIC "${PROJECT_SOURCE_DIR}/include")
target_link_libraries(
    rule_engine_python_packaging
    PUBLIC
        rule_engine::python_contract
        rule_engine::project_options
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
        $<$<AND:$<COMPILE_LANG_AND_ID:CXX,Clang>,$<CXX_COMPILER_FRONTEND_VARIANT:GNU>>:-Wno-c2y-extensions>
)
enable_testing()
add_test(NAME rule_engine_python_packaging_tests COMMAND $<TARGET_FILE:rule_engine_python_packaging_tests>)
