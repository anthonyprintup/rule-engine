add_library(
    rule_engine_python_protocol
    types.cpp
    codec.cpp
    network.cpp
    provider_router.cpp
    session.cpp
    snapshot.cpp
    spool.cpp
    transport.cpp
)
add_library(rule_engine::python_protocol ALIAS rule_engine_python_protocol)
target_include_directories(rule_engine_python_protocol PUBLIC "${PROJECT_SOURCE_DIR}/include")
target_link_libraries(
    rule_engine_python_protocol
    PUBLIC
        rule_engine::python_contract
    PRIVATE
        rule_engine::project_options
        asio::asio
)

option(RULE_ENGINE_PROTOCOL_ENABLE_SECURE_RUNTIME "Build OpenSSL transport and SQLite agent spool backends" ON)
option(RULE_ENGINE_PROTOCOL_REQUIRE_SECURE_RUNTIME "Fail configure when a secure protocol backend is unavailable" OFF)

set(rule_engine_protocol_has_openssl OFF)
set(rule_engine_protocol_has_sqlite OFF)
set(rule_engine_protocol_use_winsqlite OFF)
if(RULE_ENGINE_PROTOCOL_ENABLE_SECURE_RUNTIME)
    if(WIN32 AND NOT OPENSSL_ROOT_DIR AND EXISTS "$ENV{ProgramFiles}/OpenSSL-Win64")
        set(OPENSSL_ROOT_DIR "$ENV{ProgramFiles}/OpenSSL-Win64" CACHE PATH "OpenSSL installation root")
    endif()
    find_package(OpenSSL 3 QUIET COMPONENTS SSL Crypto)
    if(OpenSSL_FOUND)
        set(rule_engine_protocol_has_openssl ON)
        target_link_libraries(rule_engine_python_protocol PRIVATE OpenSSL::SSL OpenSSL::Crypto)
        find_program(rule_engine_protocol_openssl_executable openssl HINTS "${OPENSSL_ROOT_DIR}/bin")
        message(STATUS "Protocol v2: secure transport enabled with OpenSSL ${OPENSSL_VERSION}")
    else()
        message(WARNING
            "Protocol v2: OpenSSL 3 or newer was not found. TLS transport APIs will fail explicitly at runtime. "
            "Set OPENSSL_ROOT_DIR or enable RULE_ENGINE_PROTOCOL_REQUIRE_SECURE_RUNTIME for a hard configure failure."
        )
    endif()

    if(WIN32)
        include(CheckIncludeFileCXX)
        check_include_file_cxx("winsqlite/winsqlite3.h" rule_engine_protocol_has_winsqlite_header)
        if(rule_engine_protocol_has_winsqlite_header)
            set(rule_engine_protocol_has_sqlite ON)
            set(rule_engine_protocol_use_winsqlite ON)
            target_link_libraries(rule_engine_python_protocol PRIVATE winsqlite3)
            message(STATUS "Protocol v2: durable spool enabled with Windows system SQLite")
        endif()
    else()
        find_package(SQLite3 QUIET)
        if(SQLite3_FOUND)
            set(rule_engine_protocol_has_sqlite ON)
            target_link_libraries(rule_engine_python_protocol PRIVATE SQLite::SQLite3)
            message(STATUS "Protocol v2: durable spool enabled with SQLite ${SQLite3_VERSION}")
        endif()
    endif()
    if(NOT rule_engine_protocol_has_sqlite)
        message(WARNING
            "Protocol v2: SQLite was not found. Durable spool APIs will fail explicitly at runtime. "
            "Install SQLite development files or enable RULE_ENGINE_PROTOCOL_REQUIRE_SECURE_RUNTIME for a hard configure failure."
        )
    endif()
else()
    message(WARNING
        "Protocol v2 secure runtime was explicitly disabled. TLS transport and durable spool APIs will fail "
        "with dependency_unavailable at runtime."
    )
endif()

if(RULE_ENGINE_PROTOCOL_REQUIRE_SECURE_RUNTIME AND
   (NOT rule_engine_protocol_has_openssl OR NOT rule_engine_protocol_has_sqlite))
    message(FATAL_ERROR "Protocol v2 secure runtime requires both OpenSSL 3+ and SQLite")
endif()

target_compile_definitions(
    rule_engine_python_protocol
    PRIVATE
        RULE_ENGINE_PROTOCOL_HAS_OPENSSL=$<BOOL:${rule_engine_protocol_has_openssl}>
        RULE_ENGINE_PROTOCOL_HAS_SQLITE=$<BOOL:${rule_engine_protocol_has_sqlite}>
        RULE_ENGINE_PROTOCOL_USE_WINSQLITE=$<BOOL:${rule_engine_protocol_use_winsqlite}>
)

if(BUILD_TESTING)
    add_executable(rule_engine_python_protocol_fixture "${PROJECT_SOURCE_DIR}/tests/python_protocol_fixture.cpp")
    target_link_libraries(
        rule_engine_python_protocol_fixture
        PRIVATE
            rule_engine::python_protocol
            rule_engine::project_options
    )

    add_executable(
        rule_engine_python_protocol_v2_tests
        "${PROJECT_SOURCE_DIR}/tests/python_protocol_v2_tests.cpp"
        "${PROJECT_SOURCE_DIR}/tests/python_protocol_runtime_tests.cpp"
    )
    add_dependencies(rule_engine_python_protocol_v2_tests rule_engine_python_protocol_fixture)
    target_link_libraries(
        rule_engine_python_protocol_v2_tests
        PRIVATE
            rule_engine::python_protocol
            rule_engine_test_options
            Catch2::Catch2WithMain
    )
    target_compile_definitions(
        rule_engine_python_protocol_v2_tests
        PRIVATE RULE_ENGINE_PROTOCOL_FIXTURE_PATH="$<TARGET_FILE:rule_engine_python_protocol_fixture>"
    )
    if(rule_engine_protocol_openssl_executable)
        target_compile_definitions(
            rule_engine_python_protocol_v2_tests
            PRIVATE RULE_ENGINE_PROTOCOL_OPENSSL_EXECUTABLE="${rule_engine_protocol_openssl_executable}"
        )
    endif()
    if(WIN32)
        target_link_libraries(rule_engine_python_protocol_v2_tests PRIVATE ws2_32)
    endif()
    target_compile_options(
        rule_engine_python_protocol_v2_tests
        PRIVATE
            $<$<AND:$<COMPILE_LANG_AND_ID:CXX,Clang>,$<CXX_COMPILER_FRONTEND_VARIANT:MSVC>>:/clang:-Wno-c2y-extensions>
            $<$<AND:$<COMPILE_LANG_AND_ID:CXX,Clang>,$<CXX_COMPILER_FRONTEND_VARIANT:GNU>>:-Wno-c2y-extensions>
    )
    add_test(NAME rule_engine_python_protocol_v2 COMMAND $<TARGET_FILE:rule_engine_python_protocol_v2_tests>)

    if(OpenSSL_FOUND AND OPENSSL_ROOT_DIR AND EXISTS "${OPENSSL_ROOT_DIR}/bin")
        set_tests_properties(
            rule_engine_python_protocol_v2
            PROPERTIES ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${OPENSSL_ROOT_DIR}/bin"
        )
    endif()
endif()
