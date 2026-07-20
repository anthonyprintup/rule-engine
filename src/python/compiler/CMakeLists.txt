add_library(
    rule_engine_python_compiler
    ast.cpp
    frontend.cpp
    operands.cpp
    worker_adapter.cpp
)
add_library(rule_engine::python_compiler ALIAS rule_engine_python_compiler)
target_link_libraries(
    rule_engine_python_compiler
    PUBLIC
        rule_engine::python_contract
        rule_engine::python_packaging
)

add_executable(rule_engine_python_compiler_tests "../../../tests/python_compiler_tests.cpp")
target_link_libraries(
    rule_engine_python_compiler_tests
    PRIVATE
        rule_engine::python_compiler
        rule_engine::python_vm
        Catch2::Catch2WithMain
)
set_source_files_properties(
    "../../../tests/python_compiler_tests.cpp"
    PROPERTIES COMPILE_OPTIONS $<$<COMPILE_LANG_AND_ID:CXX,Clang>:-Wno-c2y-extensions>
)
enable_testing()
add_test(NAME rule_engine_python_compiler_tests COMMAND $<TARGET_FILE:rule_engine_python_compiler_tests>)
