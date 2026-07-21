cmake_minimum_required(VERSION 3.31)
project(rule_engine_downstream_smoke LANGUAGES CXX)

set(
    RULE_ENGINE_DOWNSTREAM_COMPONENT
    python_contract
    CACHE STRING
    "Installed Rule Engine component exercised by the downstream smoke"
)
find_package(rule_engine 1 CONFIG REQUIRED COMPONENTS "${RULE_ENGINE_DOWNSTREAM_COMPONENT}")

add_executable(rule_engine_downstream_smoke main.cpp)
target_link_libraries(
    rule_engine_downstream_smoke
    PRIVATE "rule_engine::${RULE_ENGINE_DOWNSTREAM_COMPONENT}"
)
target_compile_features(rule_engine_downstream_smoke PRIVATE cxx_std_23)
