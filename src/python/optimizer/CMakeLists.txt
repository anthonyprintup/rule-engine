add_library(
    rule_engine_python_optimizer
    optimizer.cpp
    scanner.cpp
)
add_library(rule_engine::python_optimizer ALIAS rule_engine_python_optimizer)
target_include_directories(rule_engine_python_optimizer PUBLIC "${PROJECT_SOURCE_DIR}/include")
target_link_libraries(
    rule_engine_python_optimizer
    PUBLIC
        rule_engine::python_contract
        rule_engine::project_options
)

# The scanner has a strict RE2 integration seam and rejects every regex when
# RE2 is absent. Do not substitute std::regex. The current root dependency
# graph supplies Abseil with a static CRT, which cannot safely link a fetched
# current RE2 into the dynamic-CRT application on Windows. Integration can
# enable the real engine by supplying a compatible re2::re2 target.
if(TARGET re2::re2)
    target_compile_definitions(rule_engine_python_optimizer PRIVATE RULE_ENGINE_PYTHON_OPTIMIZER_HAS_RE2=1)
    target_link_libraries(rule_engine_python_optimizer PRIVATE re2::re2)
endif()

enable_testing()
add_executable(rule_engine_python_optimizer_tests "${PROJECT_SOURCE_DIR}/tests/python_optimizer_tests.cpp")
target_link_libraries(
    rule_engine_python_optimizer_tests
    PRIVATE
        rule_engine::python_optimizer
        Catch2::Catch2WithMain
)
target_compile_options(
    rule_engine_python_optimizer_tests
    PRIVATE
        $<$<AND:$<COMPILE_LANG_AND_ID:CXX,Clang>,$<CXX_COMPILER_FRONTEND_VARIANT:MSVC>>:/clang:-Wno-c2y-extensions>
        $<$<AND:$<COMPILE_LANG_AND_ID:CXX,Clang>,$<CXX_COMPILER_FRONTEND_VARIANT:GNU>>:-Wno-c2y-extensions>
)
add_test(NAME rule_engine_python_optimizer_tests COMMAND $<TARGET_FILE:rule_engine_python_optimizer_tests>)
