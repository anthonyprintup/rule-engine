if(NOT DEFINED RULE_ENGINE_SOURCE_DIR)
    message(FATAL_ERROR "RULE_ENGINE_SOURCE_DIR is required")
endif()

cmake_path(ABSOLUTE_PATH RULE_ENGINE_SOURCE_DIR NORMALIZE OUTPUT_VARIABLE source_root)

set(forbidden_paths
    "rust/yara_bridge"
    "Cargo.toml"
    "Cargo.lock"
    "cbindgen.toml"
)

foreach(relative_path IN LISTS forbidden_paths)
    if(EXISTS "${source_root}/${relative_path}")
        message(FATAL_ERROR "retired rule-engine artifact exists: ${relative_path}")
    endif()
endforeach()

file(
    GLOB_RECURSE live_files
    LIST_DIRECTORIES FALSE
    "${source_root}/include/*"
    "${source_root}/src/*"
    "${source_root}/tests/*"
    "${source_root}/examples/*"
    "${source_root}/sdk/*"
)
list(APPEND live_files "${source_root}/CMakeLists.txt")

set(forbidden_content
    "YARA"
    "yara-x"
    "yara_bridge"
    "cbindgen"
    "Cargo.toml"
    "rust/yara_bridge"
    "protocol v1"
)

foreach(path IN LISTS live_files)
    cmake_path(RELATIVE_PATH path BASE_DIRECTORY "${source_root}" OUTPUT_VARIABLE relative_path)
    if(relative_path MATCHES "\\.(yar|yara)$")
        message(FATAL_ERROR "retired rule-language fixture exists: ${relative_path}")
    endif()

    file(READ "${path}" contents LIMIT 8388608)
    foreach(needle IN LISTS forbidden_content)
        string(FIND "${contents}" "${needle}" position)
        if(NOT position EQUAL -1)
            message(FATAL_ERROR "retired live surface '${needle}' found in ${relative_path}")
        endif()
    endforeach()
endforeach()

message(STATUS "Python-only source gate passed (${source_root})")
