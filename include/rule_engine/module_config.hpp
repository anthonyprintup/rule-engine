#pragma once

#include <rule_engine/diagnostic.hpp>
#include <rule_engine/modules.hpp>

#include <expected>
#include <filesystem>

namespace rule_engine {
    [[nodiscard]] std::expected<void, ErrorSet> load_module_config_file(const std::filesystem::path &path,
                                                                        ModuleRegistry &registry);
} // namespace rule_engine
