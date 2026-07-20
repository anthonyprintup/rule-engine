#include "rule_engine/python/cluster/audit.hpp"

#include <utility>

namespace rule_engine::python::cluster {

    std::uint64_t AuditTrail::append(const std::uint64_t at_unix_ms, const std::string_view actor,
                                     const std::string_view action, const std::string_view resource,
                                     const std::string_view outcome, const std::string_view detail) {
        const std::scoped_lock lock {mutex_};
        const auto sequence = next_sequence_++;
        records_.push_back(AuditRecord {
            .sequence = sequence,
            .at_unix_ms = at_unix_ms,
            .actor = std::string {actor},
            .action = std::string {action},
            .resource = std::string {resource},
            .outcome = std::string {outcome},
            .detail = std::string {detail},
        });
        return sequence;
    }

    std::vector<AuditRecord> AuditTrail::snapshot() const {
        const std::scoped_lock lock {mutex_};
        return records_;
    }

} // namespace rule_engine::python::cluster
