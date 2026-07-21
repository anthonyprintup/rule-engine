include_guard(GLOBAL)

cmake_policy(PUSH)
if(POLICY CMP0207)
    cmake_policy(SET CMP0207 NEW)
endif()

include(CMakePackageConfigHelpers)
include(GNUInstallDirs)

option(RULE_ENGINE_ENABLE_INSTALL_RULES "Configure the relocatable Rule Engine package" ON)
option(RULE_ENGINE_INSTALL_PRIVATE_PYTHON "Bundle the exact validated private CPython runtime" OFF)
option(RULE_ENGINE_ENABLE_INSTALL_SMOKE_TEST "Register the clean-install downstream smoke test" ON)
option(
    RULE_ENGINE_ENABLE_REAL_INSTALL_SMOKE_TEST
    "Register the offline real-target-graph install smoke test"
    ON
)

set(
    RULE_ENGINE_INSTALL_SOURCE_DIR
    "${PROJECT_SOURCE_DIR}"
    CACHE PATH
    "Rule Engine source root containing include/, sdk/, docs/, examples/, and src/"
)
if(PROJECT_VERSION)
    set(_rule_engine_default_package_version "${PROJECT_VERSION}")
else()
    set(_rule_engine_default_package_version "1.0.0")
endif()
set(
    RULE_ENGINE_PACKAGE_VERSION
    "${_rule_engine_default_package_version}"
    CACHE STRING
    "Version written to rule_engineConfigVersion.cmake"
)
set(
    RULE_ENGINE_PRIVATE_PYTHON_RUNTIME_ROOT
    ""
    CACHE PATH
    "Already-staged exact CPython 3.14.6 runtime root; never a system Python installation"
)
set(
    RULE_ENGINE_PRIVATE_PYTHON_STAGE_TARGET
    ""
    CACHE STRING
    "Optional packaging target that materializes RULE_ENGINE_PRIVATE_PYTHON_RUNTIME_ROOT"
)

set(
    _rule_engine_default_install_targets
    rule_engine_project_options
    rule_engine_python_contract
    rule_engine_python_engine
    rule_engine_python_packaging
    rule_engine_python_compiler
    rule_engine_python_vm
    rule_engine_python_effects
    rule_engine_python_events
    rule_engine_python_protocol
    rule_engine_python_cluster
    rule_engine_python_re2_bridge
    rule_engine_python_optimizer
    rule_engine_python_runtime
    rule_engine_python_runtime_adapters
    rule_engine_python_tools
    rule_engine_python_executable_support
    rule_engine_python_windows
    rule_engine_python_windows_runtime
)
set(
    RULE_ENGINE_INSTALL_LIBRARY_TARGETS
    "${_rule_engine_default_install_targets}"
    CACHE STRING
    "Candidate C++ targets exported when they exist"
)
set(
    _rule_engine_default_install_executables
    rule_engine_python_pack_cli
    rule_engine_python_check_cli
    rule_engine_python_admin_cli
    rule_engine_python_server
    rule_engine_python_agent
    rule_engine_python_benchmark
)
set(
    RULE_ENGINE_INSTALL_EXECUTABLE_TARGETS
    "${_rule_engine_default_install_executables}"
    CACHE STRING
    "Candidate Python-engine executables installed when they exist"
)

function(_rule_engine_prepare_export_target target source_root)
    get_target_property(target_is_imported "${target}" IMPORTED)
    if(target_is_imported)
        message(FATAL_ERROR "Cannot export imported target ${target}")
    endif()

    string(REGEX REPLACE "^rule_engine_" "" export_name "${target}")
    set_property(TARGET "${target}" PROPERTY EXPORT_NAME "${export_name}")

    get_target_property(target_type "${target}" TYPE)
    if(target_type STREQUAL "EXECUTABLE")
        return()
    endif()

    get_target_property(interface_includes "${target}" INTERFACE_INCLUDE_DIRECTORIES)
    if(interface_includes STREQUAL "interface_includes-NOTFOUND")
        set(interface_includes "")
    endif()
    get_target_property(target_source_dir "${target}" SOURCE_DIR)

    set(export_includes "")
    foreach(entry IN LISTS interface_includes)
        if(entry MATCHES "^\\$<")
            list(APPEND export_includes "${entry}")
            continue()
        endif()
        if(IS_ABSOLUTE "${entry}")
            cmake_path(NORMAL_PATH entry OUTPUT_VARIABLE absolute_entry)
        else()
            cmake_path(ABSOLUTE_PATH entry BASE_DIRECTORY "${target_source_dir}" NORMALIZE OUTPUT_VARIABLE absolute_entry)
        endif()
        list(APPEND export_includes "$<BUILD_INTERFACE:${absolute_entry}>")
    endforeach()
    list(APPEND export_includes "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>")
    list(REMOVE_DUPLICATES export_includes)
    set_property(TARGET "${target}" PROPERTY INTERFACE_INCLUDE_DIRECTORIES "${export_includes}")
endfunction()

function(_rule_engine_flatten_private_header_only_dependency target dependency)
    if(NOT TARGET "${target}")
        return()
    endif()

    get_target_property(links "${target}" INTERFACE_LINK_LIBRARIES)
    if(links STREQUAL "links-NOTFOUND")
        return()
    endif()
    set(link_only_dependency "$<LINK_ONLY:${dependency}>")
    if(NOT link_only_dependency IN_LIST links)
        return()
    endif()
    if(NOT TARGET "${dependency}")
        message(FATAL_ERROR
            "${target} exports ${link_only_dependency}, but ${dependency} is not a target"
        )
    endif()

    get_target_property(dependency_type "${dependency}" TYPE)
    if(NOT dependency_type STREQUAL "INTERFACE_LIBRARY")
        message(FATAL_ERROR
            "Refusing to flatten non-header-only private dependency ${dependency} from ${target}"
        )
    endif()
    foreach(property IN ITEMS
        INTERFACE_LINK_DEPENDS
        INTERFACE_LINK_DIRECTORIES
        INTERFACE_LINK_OPTIONS
        INTERFACE_SOURCES
    )
        get_target_property(dependency_property "${dependency}" "${property}")
        if(dependency_property AND NOT dependency_property MATCHES "-NOTFOUND$")
            message(FATAL_ERROR
                "Cannot safely flatten ${dependency}: ${property} is not empty"
            )
        endif()
    endforeach()

    get_target_property(dependency_links "${dependency}" INTERFACE_LINK_LIBRARIES)
    if(dependency_links STREQUAL "dependency_links-NOTFOUND")
        set(dependency_links "")
    endif()
    set(flattened_links "")
    foreach(link IN LISTS links)
        if(NOT "${link}" STREQUAL "${link_only_dependency}")
            list(APPEND flattened_links "${link}")
            continue()
        endif()
        foreach(dependency_link IN LISTS dependency_links)
            list(APPEND flattened_links "$<LINK_ONLY:${dependency_link}>")
        endforeach()
    endforeach()
    set_property(TARGET "${target}" PROPERTY INTERFACE_LINK_LIBRARIES "${flattened_links}")
endfunction()

function(_rule_engine_detect_package_dependencies targets)
    set(needs_openssl OFF)
    set(needs_postgresql OFF)
    set(needs_re2 OFF)
    set(needs_sqlite OFF)
    foreach(target IN LISTS targets)
        # Only dependencies that survive in the exported usage requirements
        # belong in the package config. CMake represents private dependencies
        # of static libraries here as LINK_ONLY generator expressions. Private
        # dependencies of shared libraries deliberately do not leak through.
        get_target_property(links "${target}" INTERFACE_LINK_LIBRARIES)
        if(links STREQUAL "links-NOTFOUND")
            continue()
        endif()
        string(JOIN ";" link_text ${links})
        if(link_text MATCHES "OpenSSL::")
            set(needs_openssl ON)
        endif()
        if(link_text MATCHES "PostgreSQL::")
            set(needs_postgresql ON)
        endif()
        if(link_text MATCHES "re2::")
            set(needs_re2 ON)
        endif()
        if(link_text MATCHES "SQLite::")
            set(needs_sqlite ON)
        endif()
        if(link_text MATCHES "asio::")
            message(FATAL_ERROR
                "An exported target still exposes private build-tree Asio: ${target}: ${link_text}"
            )
        endif()
    endforeach()
    set(RULE_ENGINE_CONFIG_NEEDS_OPENSSL "${needs_openssl}" PARENT_SCOPE)
    set(RULE_ENGINE_CONFIG_NEEDS_POSTGRESQL "${needs_postgresql}" PARENT_SCOPE)
    set(RULE_ENGINE_CONFIG_NEEDS_RE2 "${needs_re2}" PARENT_SCOPE)
    set(RULE_ENGINE_CONFIG_NEEDS_SQLITE "${needs_sqlite}" PARENT_SCOPE)
endfunction()

function(_rule_engine_validate_sdk_manifest source_root output_version)
    set(manifest_path "${source_root}/sdk/manifest.json")
    file(READ "${manifest_path}" manifest)
    string(JSON manifest_format ERROR_VARIABLE manifest_error GET "${manifest}" format)
    if(manifest_error OR NOT manifest_format EQUAL 1)
        message(FATAL_ERROR "Python SDK manifest format is invalid: ${manifest_error}")
    endif()
    string(JSON sdk_version ERROR_VARIABLE manifest_error GET "${manifest}" sdk_version)
    if(manifest_error OR NOT sdk_version MATCHES "^[0-9]+\\.[0-9]+\\.[0-9]+([.-][0-9A-Za-z.-]+)?$")
        message(FATAL_ERROR "Python SDK version is invalid: ${manifest_error}")
    endif()
    string(JSON python_version ERROR_VARIABLE manifest_error GET "${manifest}" python)
    if(manifest_error OR NOT python_version STREQUAL "3.14.6")
        message(FATAL_ERROR "Python SDK must target exact CPython 3.14.6")
    endif()
    string(JSON file_count ERROR_VARIABLE manifest_error LENGTH "${manifest}" files)
    if(manifest_error OR file_count LESS 1)
        message(FATAL_ERROR "Python SDK manifest file table is empty or invalid: ${manifest_error}")
    endif()

    set(seen_paths "")
    math(EXPR last_index "${file_count} - 1")
    foreach(index RANGE 0 ${last_index})
        string(JSON relative GET "${manifest}" files ${index} path)
        string(JSON expected_size GET "${manifest}" files ${index} size)
        string(JSON expected_sha256 GET "${manifest}" files ${index} sha256)
        if(relative STREQUAL "" OR IS_ABSOLUTE "${relative}" OR relative MATCHES "(^|/)\\.\\.(/|$)" OR
           relative MATCHES "\\\\" OR relative IN_LIST seen_paths)
            message(FATAL_ERROR "Python SDK manifest path is invalid or duplicate: ${relative}")
        endif()
        list(APPEND seen_paths "${relative}")
        set(path "${source_root}/sdk/${relative}")
        if(NOT EXISTS "${path}" OR IS_DIRECTORY "${path}" OR IS_SYMLINK "${path}")
            message(FATAL_ERROR "Python SDK manifest entry is absent or not regular: ${relative}")
        endif()
        file(SIZE "${path}" actual_size)
        file(SHA256 "${path}" actual_sha256)
        if(NOT actual_size EQUAL expected_size OR NOT actual_sha256 STREQUAL expected_sha256)
            message(FATAL_ERROR "Python SDK manifest entry is not exact: ${relative}")
        endif()
    endforeach()
    set("${output_version}" "${sdk_version}" PARENT_SCOPE)
endfunction()

function(_rule_engine_validate_runtime_at_configure source_root)
    if(NOT RULE_ENGINE_INSTALL_PRIVATE_PYTHON)
        return()
    endif()
    if(NOT WIN32 OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
        message(FATAL_ERROR
            "The currently pinned private CPython bundle is supported only for Windows x64"
        )
    endif()
    if(NOT RULE_ENGINE_PRIVATE_PYTHON_RUNTIME_ROOT)
        message(FATAL_ERROR
            "RULE_ENGINE_INSTALL_PRIVATE_PYTHON=ON requires an explicit "
            "RULE_ENGINE_PRIVATE_PYTHON_RUNTIME_ROOT; system Python fallback is forbidden"
        )
    endif()

    if(EXISTS "${RULE_ENGINE_PRIVATE_PYTHON_RUNTIME_ROOT}")
        execute_process(
            COMMAND
                "${CMAKE_COMMAND}"
                "-DRULE_ENGINE_RUNTIME_ROOT=${RULE_ENGINE_PRIVATE_PYTHON_RUNTIME_ROOT}"
                "-DRULE_ENGINE_EXPECTED_RUNTIME_MANIFEST=${CMAKE_CURRENT_FUNCTION_LIST_DIR}/private-python-3.14.6.manifest"
                -P "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/ValidatePrivatePythonRuntime.cmake"
            RESULT_VARIABLE validation_result
            OUTPUT_VARIABLE validation_output
            ERROR_VARIABLE validation_error
        )
        if(NOT validation_result EQUAL 0)
            message(FATAL_ERROR
                "Exact private CPython runtime validation failed:\n${validation_output}${validation_error}"
            )
        endif()
        return()
    endif()

    if(NOT RULE_ENGINE_PRIVATE_PYTHON_STAGE_TARGET OR
       NOT TARGET "${RULE_ENGINE_PRIVATE_PYTHON_STAGE_TARGET}")
        message(FATAL_ERROR
            "Private runtime root does not exist and no valid packaging staging target was supplied: "
            "${RULE_ENGINE_PRIVATE_PYTHON_RUNTIME_ROOT}"
        )
    endif()
endfunction()

function(rule_engine_configure_install)
    set(options "")
    set(one_value_args SOURCE_DIR PACKAGE_VERSION)
    set(multi_value_args TARGETS EXECUTABLE_TARGETS)
    cmake_parse_arguments(ARG "${options}" "${one_value_args}" "${multi_value_args}" ${ARGN})
    if(ARG_UNPARSED_ARGUMENTS)
        message(FATAL_ERROR "Unknown rule_engine_configure_install arguments: ${ARG_UNPARSED_ARGUMENTS}")
    endif()

    get_property(already_configured GLOBAL PROPERTY RULE_ENGINE_INSTALL_CONFIGURED)
    if(already_configured)
        message(FATAL_ERROR "Rule Engine install rules were configured more than once")
    endif()
    set_property(GLOBAL PROPERTY RULE_ENGINE_INSTALL_CONFIGURED TRUE)

    if(ARG_SOURCE_DIR)
        set(source_root "${ARG_SOURCE_DIR}")
    else()
        set(source_root "${RULE_ENGINE_INSTALL_SOURCE_DIR}")
    endif()
    cmake_path(ABSOLUTE_PATH source_root NORMALIZE OUTPUT_VARIABLE source_root)
    foreach(required_path IN ITEMS include/rule_engine/python sdk/rule_engine sdk/rule_engine_generator docs/python-engine examples/python)
        if(NOT EXISTS "${source_root}/${required_path}")
            message(FATAL_ERROR "Rule Engine package input is missing: ${source_root}/${required_path}")
        endif()
    endforeach()
    _rule_engine_validate_sdk_manifest("${source_root}" sdk_version)
    set(package_component rule_engine)

    if(ARG_PACKAGE_VERSION)
        set(package_version "${ARG_PACKAGE_VERSION}")
    else()
        set(package_version "${RULE_ENGINE_PACKAGE_VERSION}")
    endif()
    if(NOT package_version MATCHES "^[0-9]+\\.[0-9]+\\.[0-9]+([.-][0-9A-Za-z.-]+)?$")
        message(FATAL_ERROR "RULE_ENGINE_PACKAGE_VERSION is not a supported semantic version: ${package_version}")
    endif()

    if(ARG_TARGETS)
        set(candidate_libraries ${ARG_TARGETS})
    else()
        set(candidate_libraries ${RULE_ENGINE_INSTALL_LIBRARY_TARGETS})
    endif()
    if(ARG_EXECUTABLE_TARGETS)
        set(candidate_executables ${ARG_EXECUTABLE_TARGETS})
    else()
        set(candidate_executables ${RULE_ENGINE_INSTALL_EXECUTABLE_TARGETS})
    endif()

    set(install_libraries "")
    foreach(target IN LISTS candidate_libraries)
        if(TARGET "${target}")
            list(APPEND install_libraries "${target}")
        endif()
    endforeach()
    set(install_executables "")
    foreach(target IN LISTS candidate_executables)
        if(TARGET "${target}")
            list(APPEND install_executables "${target}")
        endif()
    endforeach()
    if(NOT install_libraries AND NOT install_executables)
        message(FATAL_ERROR "No Rule Engine package targets exist at the install-module include point")
    endif()

    set(all_install_targets ${install_libraries} ${install_executables})
    list(REMOVE_DUPLICATES all_install_targets)
    # Standalone Asio is a private, header-only compile dependency. Static
    # libraries otherwise export a LINK_ONLY reference to the build-tree alias.
    # Flatten only its link requirements (ws2_32 on Windows), so installed
    # consumers neither need Asio headers nor inherit a build-tree target.
    _rule_engine_flatten_private_header_only_dependency(
        rule_engine_python_protocol
        asio::asio
    )
    foreach(target IN LISTS all_install_targets)
        _rule_engine_prepare_export_target("${target}" "${source_root}")
    endforeach()

    _rule_engine_detect_package_dependencies("${all_install_targets}")

    set(runtime_targets ${install_executables})
    set(non_runtime_targets "")
    foreach(target IN LISTS install_libraries)
        get_target_property(target_type "${target}" TYPE)
        if(target_type STREQUAL "SHARED_LIBRARY" OR target_type STREQUAL "MODULE_LIBRARY")
            list(APPEND runtime_targets "${target}")
        else()
            list(APPEND non_runtime_targets "${target}")
        endif()
    endforeach()
    list(REMOVE_DUPLICATES runtime_targets)
    list(REMOVE_DUPLICATES non_runtime_targets)

    if(non_runtime_targets)
        install(
            TARGETS ${non_runtime_targets}
            EXPORT rule_engineTargets
            RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}" COMPONENT "${package_component}"
            LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}" COMPONENT "${package_component}"
            ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}" COMPONENT "${package_component}"
        )
    endif()
    if(runtime_targets)
        install(
            TARGETS ${runtime_targets}
            EXPORT rule_engineTargets
            RUNTIME_DEPENDENCY_SET rule_engineRuntimeDependencies
            RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}" COMPONENT "${package_component}"
            LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}" COMPONENT "${package_component}"
            ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}" COMPONENT "${package_component}"
        )
        install(
            RUNTIME_DEPENDENCY_SET rule_engineRuntimeDependencies
            PRE_EXCLUDE_REGEXES
                "api-ms-.*"
                "ext-ms-.*"
            POST_EXCLUDE_REGEXES
                ".*[Ww][Ii][Nn][Dd][Oo][Ww][Ss][/\\\\][Ss][Yy][Ss][Tt][Ee][Mm]32[/\\\\].*"
                "^/lib/.*"
                "^/usr/lib/.*"
            RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}" COMPONENT "${package_component}"
            LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}" COMPONENT "${package_component}"
        )
    endif()
    install(
        DIRECTORY "${source_root}/include/rule_engine/python"
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/rule_engine"
        COMPONENT "${package_component}"
        FILES_MATCHING PATTERN "*.hpp"
    )

    set(python_sdk_install_dir "${CMAKE_INSTALL_DATADIR}/rule_engine/python-sdk/${sdk_version}")
    install(
        DIRECTORY
            "${source_root}/sdk/rule_engine"
            "${source_root}/sdk/rule_engine_generator"
        DESTINATION "${python_sdk_install_dir}"
        COMPONENT "${package_component}"
        PATTERN "__pycache__" EXCLUDE
        PATTERN "*.pyc" EXCLUDE
    )
    install(
        FILES
            "${source_root}/sdk/manifest.json"
            "${source_root}/sdk/verify_manifest.py"
        DESTINATION "${python_sdk_install_dir}"
        COMPONENT "${package_component}"
    )

    set(worker_install_dir "${CMAKE_INSTALL_LIBEXECDIR}/rule_engine/python")
    set(worker_source "${source_root}/src/python/packaging/rule_engine_python_worker.py")
    if(NOT EXISTS "${worker_source}")
        message(FATAL_ERROR "Private Python worker source is missing: ${worker_source}")
    endif()
    install(
        FILES "${worker_source}"
        DESTINATION "${worker_install_dir}"
        COMPONENT "${package_component}"
    )

    install(
        DIRECTORY "${source_root}/docs/python-engine/"
        DESTINATION "${CMAKE_INSTALL_DATADIR}/rule_engine/docs/python-engine"
        COMPONENT "${package_component}"
        PATTERN "__pycache__" EXCLUDE
        PATTERN "*.pyc" EXCLUDE
    )
    install(
        DIRECTORY "${source_root}/examples/python/"
        DESTINATION "${CMAKE_INSTALL_DATADIR}/rule_engine/examples/python"
        COMPONENT "${package_component}"
        PATTERN "__pycache__" EXCLUDE
        PATTERN "*.pyc" EXCLUDE
    )

    set(private_python_bundled OFF)
    set(private_python_install_dir "${CMAKE_INSTALL_LIBEXECDIR}/rule_engine/python/runtime/3.14.6")
    if(RULE_ENGINE_INSTALL_PRIVATE_PYTHON)
        _rule_engine_validate_runtime_at_configure("${source_root}")
        set(private_python_bundled ON)

        add_custom_target(
            rule_engine_validate_private_python_runtime
            COMMAND
                "${CMAKE_COMMAND}"
                "-DRULE_ENGINE_RUNTIME_ROOT=${RULE_ENGINE_PRIVATE_PYTHON_RUNTIME_ROOT}"
                "-DRULE_ENGINE_EXPECTED_RUNTIME_MANIFEST=${CMAKE_CURRENT_FUNCTION_LIST_DIR}/private-python-3.14.6.manifest"
                -P "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/ValidatePrivatePythonRuntime.cmake"
            VERBATIM
        )
        if(RULE_ENGINE_PRIVATE_PYTHON_STAGE_TARGET AND TARGET "${RULE_ENGINE_PRIVATE_PYTHON_STAGE_TARGET}")
            add_dependencies(rule_engine_validate_private_python_runtime "${RULE_ENGINE_PRIVATE_PYTHON_STAGE_TARGET}")
        endif()

        install(CODE
            "execute_process(COMMAND \"${CMAKE_COMMAND}\" \"-DRULE_ENGINE_RUNTIME_ROOT=${RULE_ENGINE_PRIVATE_PYTHON_RUNTIME_ROOT}\" \"-DRULE_ENGINE_EXPECTED_RUNTIME_MANIFEST=${CMAKE_CURRENT_FUNCTION_LIST_DIR}/private-python-3.14.6.manifest\" -P \"${CMAKE_CURRENT_FUNCTION_LIST_DIR}/ValidatePrivatePythonRuntime.cmake\" RESULT_VARIABLE runtime_validation_result)\nif(NOT runtime_validation_result EQUAL 0)\n  message(FATAL_ERROR \"Exact private CPython runtime failed install-time validation\")\nendif()"
            COMPONENT "${package_component}"
        )
        install(
            DIRECTORY "${RULE_ENGINE_PRIVATE_PYTHON_RUNTIME_ROOT}/"
            DESTINATION "${private_python_install_dir}"
            COMPONENT "${package_component}"
        )
    endif()

    set(config_install_dir "${CMAKE_INSTALL_LIBDIR}/cmake/rule_engine")
    set(config_build_dir "${CMAKE_CURRENT_BINARY_DIR}/rule_engine-package")
    file(MAKE_DIRECTORY "${config_build_dir}")

    set(RULE_ENGINE_CONFIG_AVAILABLE_COMPONENTS "")
    foreach(target IN LISTS install_libraries)
        string(REGEX REPLACE "^rule_engine_" "" component "${target}")
        if(NOT component STREQUAL "project_options" AND NOT component STREQUAL "python_re2_bridge")
            list(APPEND RULE_ENGINE_CONFIG_AVAILABLE_COMPONENTS "${component}")
        endif()
    endforeach()
    list(REMOVE_DUPLICATES RULE_ENGINE_CONFIG_AVAILABLE_COMPONENTS)
    set(RULE_ENGINE_CONFIG_PRIVATE_PYTHON_BUNDLED "${private_python_bundled}")
    set(RULE_ENGINE_CONFIG_PYTHON_SDK_DIR "${python_sdk_install_dir}")
    set(RULE_ENGINE_CONFIG_WORKER_FILE "${worker_install_dir}/rule_engine_python_worker.py")
    set(RULE_ENGINE_CONFIG_DOC_DIR "${CMAKE_INSTALL_DATADIR}/rule_engine/docs/python-engine")
    set(RULE_ENGINE_CONFIG_EXAMPLE_DIR "${CMAKE_INSTALL_DATADIR}/rule_engine/examples/python")
    set(RULE_ENGINE_CONFIG_PRIVATE_PYTHON_DIR "${private_python_install_dir}")

    configure_package_config_file(
        "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/rule_engineConfig.cmake.in"
        "${config_build_dir}/rule_engineConfig.cmake"
        INSTALL_DESTINATION "${config_install_dir}"
        PATH_VARS
            CMAKE_INSTALL_INCLUDEDIR
            RULE_ENGINE_CONFIG_PYTHON_SDK_DIR
            RULE_ENGINE_CONFIG_WORKER_FILE
            RULE_ENGINE_CONFIG_DOC_DIR
            RULE_ENGINE_CONFIG_EXAMPLE_DIR
            RULE_ENGINE_CONFIG_PRIVATE_PYTHON_DIR
    )
    write_basic_package_version_file(
        "${config_build_dir}/rule_engineConfigVersion.cmake"
        VERSION "${package_version}"
        COMPATIBILITY SameMajorVersion
    )
    install(
        EXPORT rule_engineTargets
        FILE rule_engineTargets.cmake
        NAMESPACE rule_engine::
        DESTINATION "${config_install_dir}"
        COMPONENT "${package_component}"
    )
    install(
        FILES
            "${config_build_dir}/rule_engineConfig.cmake"
            "${config_build_dir}/rule_engineConfigVersion.cmake"
        DESTINATION "${config_install_dir}"
        COMPONENT "${package_component}"
    )
    install(
        FILES
            "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/INSTALL_PACKAGE.md"
            "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/private-python-3.14.6.manifest"
        DESTINATION "${CMAKE_INSTALL_DATADIR}/rule_engine/package"
        COMPONENT "${package_component}"
    )

    if(NOT TARGET rule_engine_install_package)
        get_property(is_multi_config GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
        set(package_install_command "${CMAKE_COMMAND}" --install "${CMAKE_BINARY_DIR}")
        if(is_multi_config)
            list(APPEND package_install_command --config "$<CONFIG>")
        endif()
        list(APPEND package_install_command --component "${package_component}")
        add_custom_target(
            rule_engine_install_package
            COMMAND ${package_install_command}
            DEPENDS ${all_install_targets}
            USES_TERMINAL
            VERBATIM
        )
        if(TARGET rule_engine_validate_private_python_runtime)
            add_dependencies(rule_engine_install_package rule_engine_validate_private_python_runtime)
        endif()
    endif()

    if(BUILD_TESTING AND RULE_ENGINE_ENABLE_INSTALL_SMOKE_TEST AND
       EXISTS "${source_root}/cmake/RuleEngineInstallSmoke.cmake")
        add_test(
            NAME rule_engine_install_fixture_smoke
            COMMAND
                "${CMAKE_COMMAND}"
                "-DRULE_ENGINE_SOURCE_DIR=${source_root}"
                "-DRULE_ENGINE_BINARY_ROOT=${CMAKE_CURRENT_BINARY_DIR}/rule-engine-install-smoke"
                "-DRULE_ENGINE_CMAKE_GENERATOR=${CMAKE_GENERATOR}"
                "-DRULE_ENGINE_C_COMPILER=${CMAKE_C_COMPILER}"
                "-DRULE_ENGINE_CXX_COMPILER=${CMAKE_CXX_COMPILER}"
                "-DRULE_ENGINE_MAKE_PROGRAM=${CMAKE_MAKE_PROGRAM}"
                -P "${source_root}/cmake/RuleEngineInstallSmoke.cmake"
        )
        set_tests_properties(
            rule_engine_install_fixture_smoke
            PROPERTIES LABELS "install;python-engine"
        )
    endif()

    if(BUILD_TESTING AND RULE_ENGINE_ENABLE_REAL_INSTALL_SMOKE_TEST AND
       EXISTS "${source_root}/cmake/RuleEngineRealInstallSmoke.cmake")
        set(expected_tool_names "")
        foreach(target IN LISTS install_executables)
            get_target_property(tool_name "${target}" OUTPUT_NAME)
            if(NOT tool_name OR tool_name MATCHES "-NOTFOUND$")
                set(tool_name "${target}")
            endif()
            list(APPEND expected_tool_names "${tool_name}")
        endforeach()
        string(REPLACE ";" "," expected_tool_names_argument "${expected_tool_names}")
        add_test(
            NAME rule_engine_install_smoke
            COMMAND
                "${CMAKE_COMMAND}"
                "-DRULE_ENGINE_SOURCE_DIR=${source_root}"
                "-DRULE_ENGINE_BINARY_ROOT=${CMAKE_CURRENT_BINARY_DIR}/rule-engine-real-install-smoke"
                "-DRULE_ENGINE_CMAKE_GENERATOR=${CMAKE_GENERATOR}"
                "-DRULE_ENGINE_C_COMPILER=${CMAKE_C_COMPILER}"
                "-DRULE_ENGINE_CXX_COMPILER=${CMAKE_CXX_COMPILER}"
                "-DRULE_ENGINE_MAKE_PROGRAM=${CMAKE_MAKE_PROGRAM}"
                "-DRULE_ENGINE_CMAKE_AR=${CMAKE_AR}"
                "-DRULE_ENGINE_CMAKE_LINKER=${CMAKE_LINKER}"
                "-DRULE_ENGINE_ASIO_SOURCE_DIR=${asio_SOURCE_DIR}"
                "-DRULE_ENGINE_CATCH2_SOURCE_DIR=${catch2_SOURCE_DIR}"
                "-DRULE_ENGINE_ABSEIL_SOURCE_DIR=${rule_engine_abseil_SOURCE_DIR}"
                "-DRULE_ENGINE_RE2_SOURCE_DIR=${rule_engine_re2_SOURCE_DIR}"
                "-DRULE_ENGINE_EXPECTED_TOOL_NAMES=${expected_tool_names_argument}"
                -P "${source_root}/cmake/RuleEngineRealInstallSmoke.cmake"
        )
        set_tests_properties(
            rule_engine_install_smoke
            PROPERTIES
                LABELS "install;python-engine;real-graph"
                RUN_SERIAL TRUE
                TIMEOUT 900
        )
    endif()

    message(STATUS "Rule Engine package targets: ${all_install_targets}")
    message(STATUS "Rule Engine private CPython bundled: ${private_python_bundled}")
endfunction()

if(RULE_ENGINE_INSTALL_PRIVATE_PYTHON)
    if(NOT RULE_ENGINE_PRIVATE_PYTHON_STAGE_TARGET)
        foreach(candidate IN ITEMS
            rule_engine_stage_python_runtime
            rule_engine_stage_private_python_runtime
            rule_engine_python_runtime_stage
            rule_engine_python_runtime_bundle
        )
            if(TARGET "${candidate}")
                set(RULE_ENGINE_PRIVATE_PYTHON_STAGE_TARGET "${candidate}")
                message(STATUS "Using private Python packaging staging target: ${candidate}")
                break()
            endif()
        endforeach()
    endif()
    if(RULE_ENGINE_PRIVATE_PYTHON_STAGE_TARGET AND
       TARGET "${RULE_ENGINE_PRIVATE_PYTHON_STAGE_TARGET}" AND
       NOT RULE_ENGINE_PRIVATE_PYTHON_RUNTIME_ROOT)
        foreach(property IN ITEMS RULE_ENGINE_PRIVATE_PYTHON_RUNTIME_ROOT RULE_ENGINE_STAGED_RUNTIME_ROOT)
            get_target_property(
                staged_runtime_root
                "${RULE_ENGINE_PRIVATE_PYTHON_STAGE_TARGET}"
                "${property}"
            )
            if(staged_runtime_root AND NOT staged_runtime_root MATCHES "-NOTFOUND$")
                set(RULE_ENGINE_PRIVATE_PYTHON_RUNTIME_ROOT "${staged_runtime_root}")
                break()
            endif()
        endforeach()
    endif()
    if(NOT RULE_ENGINE_PRIVATE_PYTHON_RUNTIME_ROOT AND RULE_ENGINE_PYTHON_RUNTIME_STAGE_DIR)
        set(RULE_ENGINE_PRIVATE_PYTHON_RUNTIME_ROOT "${RULE_ENGINE_PYTHON_RUNTIME_STAGE_DIR}")
        message(STATUS
            "Using packaging runtime stage directory: ${RULE_ENGINE_PRIVATE_PYTHON_RUNTIME_ROOT}"
        )
    endif()
    if(RULE_ENGINE_PRIVATE_PYTHON_RUNTIME_ROOT)
        cmake_path(
            ABSOLUTE_PATH RULE_ENGINE_PRIVATE_PYTHON_RUNTIME_ROOT
            BASE_DIRECTORY "${CMAKE_BINARY_DIR}"
            NORMALIZE
            OUTPUT_VARIABLE normalized_private_python_runtime_root
        )
        set(
            RULE_ENGINE_PRIVATE_PYTHON_RUNTIME_ROOT
            "${normalized_private_python_runtime_root}"
        )
    endif()
endif()

if(RULE_ENGINE_ENABLE_INSTALL_RULES)
    rule_engine_configure_install(
        SOURCE_DIR "${RULE_ENGINE_INSTALL_SOURCE_DIR}"
        PACKAGE_VERSION "${RULE_ENGINE_PACKAGE_VERSION}"
        TARGETS ${RULE_ENGINE_INSTALL_LIBRARY_TARGETS}
        EXECUTABLE_TARGETS ${RULE_ENGINE_INSTALL_EXECUTABLE_TARGETS}
    )
endif()

cmake_policy(POP)
