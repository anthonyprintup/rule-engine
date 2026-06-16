#pragma once

#include <rule_engine/diagnostic.hpp>
#include <rule_engine/evaluator.hpp>

#include <expected>
#include <filesystem>
#include <string>
#include <vector>

namespace rule_engine::windows {
    [[nodiscard]] std::expected<std::vector<Fact>, ErrorSet> read_pe_image_facts(std::string subject_id,
                                                                                 const std::filesystem::path &image_path);
} // namespace rule_engine::windows
