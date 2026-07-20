add_library(
    rule_engine_python_cluster
    activation.cpp
    audit.cpp
    breaker.cpp
    configuration.cpp
    coordinator.cpp
    migrations.cpp
    postgres_store.cpp
    readiness.cpp
    serialization.cpp
    sqlite_store.cpp
    store.cpp
)
add_library(rule_engine::python_cluster ALIAS rule_engine_python_cluster)
target_include_directories(rule_engine_python_cluster PUBLIC ../../../include)
target_link_libraries(
    rule_engine_python_cluster
    PUBLIC
        rule_engine::python_contract
        rule_engine::project_options
)

find_package(SQLite3 QUIET)
if(TARGET SQLite::SQLite3)
    target_link_libraries(rule_engine_python_cluster PRIVATE SQLite::SQLite3)
    target_compile_definitions(rule_engine_python_cluster PUBLIC RULE_ENGINE_HAS_SQLITE=1)
elseif(WIN32)
    target_link_libraries(rule_engine_python_cluster PRIVATE winsqlite3)
    target_compile_definitions(
        rule_engine_python_cluster
        PUBLIC RULE_ENGINE_HAS_SQLITE=1
        PRIVATE RULE_ENGINE_USE_WINSQLITE3=1
    )
else()
    message(FATAL_ERROR "The Python cluster component requires SQLite3 for its single-process durable store")
endif()

find_package(PostgreSQL 17 QUIET)
if(PostgreSQL_FOUND)
    target_link_libraries(rule_engine_python_cluster PRIVATE PostgreSQL::PostgreSQL)
    target_compile_definitions(rule_engine_python_cluster PUBLIC RULE_ENGINE_HAS_POSTGRESQL=1)
endif()

add_executable(rule_engine_python_cluster_tests ../../../tests/python_cluster_tests.cpp)
target_link_libraries(
    rule_engine_python_cluster_tests
    PRIVATE
        rule_engine::python_cluster
        Catch2::Catch2WithMain
)
target_compile_options(
    rule_engine_python_cluster_tests
    PRIVATE
        $<$<AND:$<COMPILE_LANG_AND_ID:CXX,Clang>,$<CXX_COMPILER_FRONTEND_VARIANT:MSVC>>:/clang:-Wno-c2y-extensions>
        $<$<AND:$<COMPILE_LANG_AND_ID:CXX,Clang>,$<CXX_COMPILER_FRONTEND_VARIANT:GNU>>:-Wno-c2y-extensions>
)
enable_testing()
add_test(NAME python_cluster_tests COMMAND $<TARGET_FILE:rule_engine_python_cluster_tests>)
