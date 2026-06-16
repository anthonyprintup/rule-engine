#pragma once

#include <rule_engine/protocol.hpp>

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

    struct PatternFixtureSet {
        std::vector<PatternFixture> patterns;
    };

    [[nodiscard]] PatternFixtureSet default_pattern_fixtures();
    [[nodiscard]] std::expected<PatternFixtureSet, ErrorSet>
    load_pattern_fixture_file(const std::filesystem::path &path);
    [[nodiscard]] std::vector<Fact> read_fixture_pattern_facts(std::span<const protocol::FactKey> keys,
                                                               const PatternFixtureSet &fixtures);
} // namespace rule_engine::patterns
