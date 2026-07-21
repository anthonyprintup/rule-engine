add_library(rule_engine_python_events reference_runtime.cpp runtime_adapter.cpp)
add_library(rule_engine::python_events ALIAS rule_engine_python_events)
target_include_directories(rule_engine_python_events PUBLIC "${PROJECT_SOURCE_DIR}/include")
target_link_libraries(
    rule_engine_python_events
    PUBLIC
        rule_engine::python_contract
        rule_engine::python_effects
    PRIVATE
        rule_engine::project_options
)

if(BUILD_TESTING)
    add_executable(
        rule_engine_python_events_tests
        "${PROJECT_SOURCE_DIR}/tests/python_events_adapter_tests.cpp"
        "${PROJECT_SOURCE_DIR}/tests/python_events_tests.cpp"
    )
    target_link_libraries(
        rule_engine_python_events_tests
        PRIVATE
            rule_engine::python_events
            rule_engine_test_options
            Catch2::Catch2WithMain
    )
    target_compile_options(
        rule_engine_python_events_tests
        PRIVATE
            $<$<AND:$<COMPILE_LANG_AND_ID:CXX,Clang>,$<CXX_COMPILER_FRONTEND_VARIANT:MSVC>>:/clang:-Wno-c2y-extensions>
            $<$<AND:$<COMPILE_LANG_AND_ID:CXX,Clang>,$<CXX_COMPILER_FRONTEND_VARIANT:GNU>>:-Wno-c2y-extensions>
    )
    add_test(NAME rule_engine_python_events_tests COMMAND $<TARGET_FILE:rule_engine_python_events_tests>)
endif()
