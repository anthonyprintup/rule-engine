#pragma once

#include "rule_engine/python/tools/common.hpp"

#include <span>
#include <string>
#include <string_view>

namespace rule_engine::python::tools {

    inline constexpr auto redacted_value = "[REDACTED]";

    [[nodiscard]] bool field_name_is_sensitive(std::string_view name) noexcept;
    [[nodiscard]] std::string redact_text(std::string_view text);
    [[nodiscard]] std::string display_value(const DisplayField &field);
    [[nodiscard]] std::string render_fields_text(std::span<const DisplayField> fields);
    [[nodiscard]] std::string render_fields_json(std::span<const DisplayField> fields);

} // namespace rule_engine::python::tools
