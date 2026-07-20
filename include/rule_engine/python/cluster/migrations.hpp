#pragma once

#include <cstdint>
#include <span>
#include <string_view>

namespace rule_engine::python::cluster {

    inline constexpr std::uint32_t runtime_store_schema_version = 1;

    struct SchemaMigration {
        std::uint32_t version {};
        std::string_view name;
        std::string_view sqlite_sql;
        std::string_view postgresql_sql;
    };

    [[nodiscard]] std::span<const SchemaMigration> runtime_store_migrations();

} // namespace rule_engine::python::cluster
