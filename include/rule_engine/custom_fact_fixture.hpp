#pragma once

#include <rule_engine/diagnostic.hpp>
#include <rule_engine/protocol.hpp>

#include <chrono>
#include <expected>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace rule_engine::custom_facts {
    struct CustomFactFixture {
        std::string route;
        std::string key;
        Value value;
        std::chrono::seconds ttl {};
    };

    struct CustomFactFixtureSet {
        std::vector<protocol::Capability> capabilities;
        std::vector<CustomFactFixture> facts;
    };

    [[nodiscard]] std::expected<CustomFactFixtureSet, ErrorSet>
    load_custom_fact_fixture_file(const std::filesystem::path &path);
    [[nodiscard]] std::optional<protocol::FactBatchResponseMessage>
    read_custom_fact_fixture_response(const protocol::FactBatchRequestMessage &request,
                                      const CustomFactFixtureSet &fixtures);
} // namespace rule_engine::custom_facts
