add_library(rule_engine_python_runtime orchestrator.cpp)
add_library(rule_engine::python_runtime ALIAS rule_engine_python_runtime)
target_include_directories(rule_engine_python_runtime PUBLIC "${CMAKE_SOURCE_DIR}/include")
target_link_libraries(
    rule_engine_python_runtime
    PUBLIC
        rule_engine::python_engine
        rule_engine::python_effects
        rule_engine::project_options
)

add_library(rule_engine_python_runtime_adapters adapters.cpp)
add_library(rule_engine::python_runtime_adapters ALIAS rule_engine_python_runtime_adapters)
target_include_directories(rule_engine_python_runtime_adapters PUBLIC "${CMAKE_SOURCE_DIR}/include")
target_link_libraries(
    rule_engine_python_runtime_adapters
    PUBLIC
        rule_engine::python_runtime
        rule_engine::python_cluster
        rule_engine::python_protocol
        rule_engine::project_options
)

if(BUILD_TESTING)
    add_executable(
        rule_engine_python_runtime_integration_tests
        "${CMAKE_SOURCE_DIR}/tests/python_runtime_integration_tests.cpp"
    )
    target_link_libraries(
        rule_engine_python_runtime_integration_tests
        PRIVATE
            rule_engine::python_runtime_adapters
            Catch2::Catch2WithMain
    )
    target_compile_options(
        rule_engine_python_runtime_integration_tests
        PRIVATE
            $<$<AND:$<COMPILE_LANG_AND_ID:CXX,Clang>,$<CXX_COMPILER_FRONTEND_VARIANT:MSVC>>:
                /clang:-Wno-c2y-extensions
                /clang:-Wno-missing-designated-field-initializers
            >
            $<$<AND:$<COMPILE_LANG_AND_ID:CXX,Clang>,$<CXX_COMPILER_FRONTEND_VARIANT:GNU>>:
                -Wno-c2y-extensions
                -Wno-missing-designated-field-initializers
            >
    )
    add_test(
        NAME rule_engine_python_runtime_integration_tests
        COMMAND $<TARGET_FILE:rule_engine_python_runtime_integration_tests>
    )
endif()
