add_library(
    rule_engine_python_vm
    register_vm.cpp
    structured_tasks.cpp
    value.cpp
)
add_library(rule_engine::python_vm ALIAS rule_engine_python_vm)
target_include_directories(rule_engine_python_vm PUBLIC "${CMAKE_SOURCE_DIR}/include")
target_link_libraries(
    rule_engine_python_vm
    PUBLIC rule_engine::python_contract
    PRIVATE rule_engine::project_options
)

if(BUILD_TESTING)
    add_executable(rule_engine_python_vm_tests "${CMAKE_SOURCE_DIR}/tests/python_vm_tests.cpp")
    target_link_libraries(
        rule_engine_python_vm_tests
        PRIVATE rule_engine::python_vm rule_engine_test_options Catch2::Catch2WithMain
    )
    target_compile_options(
        rule_engine_python_vm_tests
        PRIVATE
            $<$<AND:$<COMPILE_LANG_AND_ID:CXX,Clang>,$<CXX_COMPILER_FRONTEND_VARIANT:MSVC>>:/clang:-Wno-c2y-extensions>
            $<$<AND:$<COMPILE_LANG_AND_ID:CXX,Clang>,$<CXX_COMPILER_FRONTEND_VARIANT:GNU>>:-Wno-c2y-extensions>
    )
    enable_testing()
    add_test(NAME rule_engine_python_vm_tests COMMAND $<TARGET_FILE:rule_engine_python_vm_tests>)
endif()
