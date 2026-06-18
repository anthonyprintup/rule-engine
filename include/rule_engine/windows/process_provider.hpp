#pragma once

#include <rule_engine/diagnostic.hpp>
#include <rule_engine/evaluator.hpp>
#include <rule_engine/pattern_fixture_provider.hpp>

#include <expected>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace rule_engine::windows {
    struct ProcessFactKey {
        std::string subject_id;
        std::string key;
    };

    [[nodiscard]] std::expected<std::vector<Subject>, ErrorSet> enumerate_process_subjects();
    [[nodiscard]] std::expected<std::vector<Fact>, ErrorSet>
    read_process_snapshot_facts(std::span<const ProcessFactKey> keys);
    [[nodiscard]] std::expected<std::vector<Fact>, ErrorSet>
    read_process_handle_facts(std::span<const ProcessFactKey> keys);
    [[nodiscard]] std::expected<std::vector<Fact>, ErrorSet>
    read_process_signer_facts(std::span<const ProcessFactKey> keys,
                              std::chrono::milliseconds timeout = std::chrono::milliseconds {5000});
    [[nodiscard]] std::expected<std::vector<Fact>, ErrorSet>
    read_process_signer_image_facts(std::string_view subject_id,
                                    const std::filesystem::path &image_path,
                                    std::span<const ProcessFactKey> keys,
                                    std::chrono::milliseconds timeout = std::chrono::milliseconds {5000});
    [[nodiscard]] std::expected<std::filesystem::path, ErrorSet> resolve_process_image_path(std::string_view subject_id);
    [[nodiscard]] std::expected<std::vector<patterns::PatternScanSpace>, ErrorSet>
    read_process_readable_memory_scan_spaces(std::string subject_id,
                                             std::span<const PatternScanPlan> scan_plans,
                                             std::span<const patterns::ReadableMemoryScanScope> scopes = {});
} // namespace rule_engine::windows
