add_library(
    rule_engine_python_protocol
    types.cpp
    codec.cpp
    provider_router.cpp
    session.cpp
    snapshot.cpp
)
add_library(rule_engine::python_protocol ALIAS rule_engine_python_protocol)
target_include_directories(rule_engine_python_protocol PUBLIC "${PROJECT_SOURCE_DIR}/include")
target_link_libraries(
    rule_engine_python_protocol
    PUBLIC
        rule_engine::python_contract
        rule_engine::project_options
)

add_executable(rule_engine_python_protocol_v2_tests "${PROJECT_SOURCE_DIR}/tests/python_protocol_v2_tests.cpp")
enable_testing()
target_link_libraries(
    rule_engine_python_protocol_v2_tests
    PRIVATE
        rule_engine::python_protocol
        Catch2::Catch2WithMain
)
target_compile_options(
    rule_engine_python_protocol_v2_tests
    PRIVATE
        $<$<AND:$<COMPILE_LANG_AND_ID:CXX,Clang>,$<CXX_COMPILER_FRONTEND_VARIANT:MSVC>>:/clang:-Wno-c2y-extensions>
        $<$<AND:$<COMPILE_LANG_AND_ID:CXX,Clang>,$<CXX_COMPILER_FRONTEND_VARIANT:GNU>>:-Wno-c2y-extensions>
)
add_test(NAME rule_engine_python_protocol_v2 COMMAND $<TARGET_FILE:rule_engine_python_protocol_v2_tests>)
