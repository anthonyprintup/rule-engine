add_library(
    rule_engine_python_effects
    common.cpp
    execution.cpp
    journal.cpp
    labels.cpp
    outbox.cpp
    recorder.cpp
    replay.cpp
    service.cpp
    service_coordinator.cpp
)
add_library(rule_engine::python_effects ALIAS rule_engine_python_effects)
target_include_directories(rule_engine_python_effects PUBLIC "${CMAKE_SOURCE_DIR}/include")
target_link_libraries(
    rule_engine_python_effects
    PUBLIC
        rule_engine::project_options
        rule_engine::python_contract
)

add_executable(rule_engine_python_effects_tests "${CMAKE_SOURCE_DIR}/tests/python_effects_tests.cpp")
target_link_libraries(
    rule_engine_python_effects_tests
    PRIVATE
        rule_engine::python_effects
        Catch2::Catch2WithMain
)
target_compile_options(
    rule_engine_python_effects_tests
    PRIVATE
        $<$<AND:$<COMPILE_LANG_AND_ID:CXX,Clang>,$<CXX_COMPILER_FRONTEND_VARIANT:MSVC>>:/clang:-Wno-c2y-extensions>
        $<$<AND:$<COMPILE_LANG_AND_ID:CXX,Clang>,$<CXX_COMPILER_FRONTEND_VARIANT:GNU>>:-Wno-c2y-extensions>
)
enable_testing()
add_test(NAME rule_engine_python_effects_tests COMMAND $<TARGET_FILE:rule_engine_python_effects_tests>)
