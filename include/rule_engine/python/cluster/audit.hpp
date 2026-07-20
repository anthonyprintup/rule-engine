#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace rule_engine::python::cluster {

    struct AuditRecord {
        std::uint64_t sequence {};
        std::uint64_t at_unix_ms {};
        std::string actor;
        std::string action;
        std::string resource;
        std::string outcome;
        std::string detail;

        auto operator<=>(const AuditRecord &) const = default;
    };

    struct AuditTrail {
        [[nodiscard]] std::uint64_t append(std::uint64_t at_unix_ms, std::string_view actor, std::string_view action,
                                           std::string_view resource, std::string_view outcome,
                                           std::string_view detail);
        [[nodiscard]] std::vector<AuditRecord> snapshot() const;

    private:
        mutable std::mutex mutex_;
        std::uint64_t next_sequence_ {1};
        std::vector<AuditRecord> records_;
    };

} // namespace rule_engine::python::cluster
