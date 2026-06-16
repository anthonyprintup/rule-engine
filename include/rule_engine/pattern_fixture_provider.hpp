#pragma once

#include <rule_engine/protocol.hpp>

#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

namespace rule_engine::patterns {
    struct PatternFixture {
        std::string pattern_key;
        PatternValue value;
    };

    struct PatternScanSpace {
        std::string subject_id;
        std::string scan_space;
        std::string permissions;
        std::vector<std::byte> bytes;
    };

    struct ReadableMemoryScanScope {
        std::uintptr_t base {};
        std::size_t size {};
    };

    struct PatternFixtureSet {
        std::vector<PatternFixture> patterns;
        std::vector<PatternScanSpace> scan_spaces;
        bool scan_process_image_sections {};
        bool scan_readable_memory_regions {};
        std::vector<ReadableMemoryScanScope> readable_memory_scopes;
    };

    [[nodiscard]] PatternFixtureSet default_pattern_fixtures();
    [[nodiscard]] std::expected<PatternFixtureSet, ErrorSet>
    load_pattern_fixture_file(const std::filesystem::path &path);
    [[nodiscard]] std::vector<Fact>
    read_fixture_pattern_facts(std::span<const protocol::FactKey> keys,
                               const PatternFixtureSet &fixtures,
                               std::span<const PatternScanPlan> scan_plans = {});
} // namespace rule_engine::patterns
