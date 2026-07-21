cmake_minimum_required(VERSION 3.31)

foreach(required IN ITEMS RULE_ENGINE_PACK_EXE RULE_ENGINE_CHECK_EXE RULE_ENGINE_RUNTIME_ROOT RULE_ENGINE_SMOKE_ROOT)
    if(NOT DEFINED ${required} OR "${${required}}" STREQUAL "")
        message(FATAL_ERROR "${required} is required")
    endif()
endforeach()

file(REMOVE_RECURSE "${RULE_ENGINE_SMOKE_ROOT}")
set(source_root "${RULE_ENGINE_SMOKE_ROOT}/source")
set(worker_root "${RULE_ENGINE_SMOKE_ROOT}/workers")
set(archive_path "${RULE_ENGINE_SMOKE_ROOT}/tooling.rpack")
file(MAKE_DIRECTORY "${source_root}/src/tooling" "${worker_root}")
set(manifest [=[format = 1

[pack]
id = "com.example.tooling-executable-smoke"
version = "1.0.0"
kind = "rules"
engine_api = 1
python = "3.14.6"
entry_modules = ["tooling.rules"]
budget_profile = "balanced.v1"
policy_profile = "development.v1"

[capabilities]
required = []
optional = []
]=])
set(rule_source [=[@rule("com.example.tooling.executable-constant")
def constant() -> bool:
    return True
]=])
file(CONFIGURE OUTPUT "${source_root}/rulepack.toml" CONTENT "${manifest}" @ONLY NEWLINE_STYLE LF)
file(CONFIGURE OUTPUT "${source_root}/src/tooling/rules.py" CONTENT "${rule_source}" @ONLY NEWLINE_STYLE LF)

execute_process(
    COMMAND
        "${RULE_ENGINE_PACK_EXE}"
        build
        --source "${source_root}"
        --output "${archive_path}"
        --trust-mode development
        --format=json
    RESULT_VARIABLE pack_result
    OUTPUT_VARIABLE pack_output
    ERROR_VARIABLE pack_error
)
if(NOT pack_result EQUAL 0)
    message(FATAL_ERROR "rule_engine_pack build failed (${pack_result}):\n${pack_output}\n${pack_error}")
endif()
if(NOT EXISTS "${archive_path}" OR NOT pack_output MATCHES [["success":true]])
    message(FATAL_ERROR "rule_engine_pack did not emit its canonical success artifact:\n${pack_output}")
endif()

execute_process(
    COMMAND
        "${RULE_ENGINE_CHECK_EXE}"
        --pack "${archive_path}"
        --runtime-root "${RULE_ENGINE_RUNTIME_ROOT}"
        --temporary-root "${worker_root}"
        --trust-mode development
        --format=json
        --explain-plan
    RESULT_VARIABLE check_result
    OUTPUT_VARIABLE check_output
    ERROR_VARIABLE check_error
)
if(NOT check_result EQUAL 0)
    message(FATAL_ERROR "rule_engine_check failed (${check_result}):\n${check_output}\n${check_error}")
endif()
if(NOT check_output MATCHES [["success":true]] OR
   NOT check_output MATCHES [["semantic_hash":]] OR
   NOT check_output MATCHES [[com.example.tooling.executable-constant]])
    message(FATAL_ERROR "rule_engine_check did not emit the expected compiled result:\n${check_output}")
endif()
