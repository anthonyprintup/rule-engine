#pragma once

#include <rule_engine/value.hpp>

#include <span>
#include <string>
#include <string_view>

namespace rule_engine {
    [[nodiscard]] std::string provider_argument_key(const Value &value);
    [[nodiscard]] std::string provider_function_key(std::string_view key_prefix, std::span<const Value> arguments);
} // namespace rule_engine
