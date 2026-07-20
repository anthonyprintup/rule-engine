#pragma once

#include "rule_engine/python/cluster/configuration.hpp"

#include <string>
#include <vector>

namespace rule_engine::python::cluster {

    struct ReadinessInput {
        bool process_responsive {true};
        bool database_reachable {};
        bool backend_driver_ready {};
        bool migrations_compatible {};
        bool node_lease_current {};
        bool trust_policy_loaded {};
        bool retention_profiles_loaded {};
        bool active_generation_compiled {};
        bool schemas_compatible {};
        bool required_capabilities_available {};
        StoreBackendCapabilities backend;
    };

    struct ReadinessSnapshot {
        bool live {};
        bool ready {};
        std::vector<std::string> blockers;
    };

    [[nodiscard]] ReadinessSnapshot evaluate_readiness(const ReadinessInput &input);

} // namespace rule_engine::python::cluster
