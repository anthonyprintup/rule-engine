# CMAKE_PROJECT_INCLUDE evaluates this file after every project() call. Defer
# the install module only for the repository's top-level project so it observes
# the complete, real target graph without changing the root CMakeLists.txt.
if(PROJECT_NAME STREQUAL "rule_engine" AND PROJECT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    if(RULE_ENGINE_INSTALL_MODULE)
        set(rule_engine_install_module "${RULE_ENGINE_INSTALL_MODULE}")
    else()
        set(rule_engine_install_module "${CMAKE_SOURCE_DIR}/cmake/RuleEngineInstall.cmake")
    endif()
    cmake_path(ABSOLUTE_PATH rule_engine_install_module NORMALIZE)
    set(RULE_ENGINE_ENABLE_INSTALL_RULES ON CACHE BOOL "" FORCE)
    set(RULE_ENGINE_ENABLE_INSTALL_SMOKE_TEST OFF CACHE BOOL "" FORCE)
    set(RULE_ENGINE_ENABLE_REAL_INSTALL_SMOKE_TEST OFF CACHE BOOL "" FORCE)
    set(RULE_ENGINE_INSTALL_PRIVATE_PYTHON OFF CACHE BOOL "" FORCE)
    set(RULE_ENGINE_INSTALL_SOURCE_DIR "${CMAKE_SOURCE_DIR}" CACHE PATH "" FORCE)
    cmake_language(
        DEFER
        DIRECTORY "${CMAKE_SOURCE_DIR}"
        CALL include "${rule_engine_install_module}"
    )
endif()
