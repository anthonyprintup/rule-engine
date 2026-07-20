#pragma once

#include "rule_engine/python/tools/admin.hpp"
#include "rule_engine/python/tools/authoring.hpp"

#include <span>
#include <string_view>

namespace rule_engine::python::tools {

    [[nodiscard]] std::string_view check_help() noexcept;
    [[nodiscard]] std::string_view pack_help() noexcept;
    [[nodiscard]] std::string_view admin_help() noexcept;

    [[nodiscard]] CommandOutput run_rule_engine_check(std::span<const std::string_view> arguments,
                                                      CompilerToolBackend &backend,
                                                      CheckWatchCoordinator *watch = nullptr);
    [[nodiscard]] CommandOutput run_rule_engine_pack(std::span<const std::string_view> arguments,
                                                     PackagingToolBackend &backend);
    [[nodiscard]] CommandOutput run_rule_engine_admin(std::span<const std::string_view> arguments,
                                                      AdminToolBackend &backend);

} // namespace rule_engine::python::tools
