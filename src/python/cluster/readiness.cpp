#include "rule_engine/python/cluster/readiness.hpp"

namespace rule_engine::python::cluster {

    ReadinessSnapshot evaluate_readiness(const ReadinessInput &input) {
        ReadinessSnapshot result {.live = input.process_responsive, .ready = false, .blockers = {}};
        const auto require = [&result](const bool condition, std::string blocker) {
            if (!condition) {
                result.blockers.push_back(std::move(blocker));
            }
        };

        require(input.process_responsive, "process watchdog is not responsive");
        require(input.database_reachable, "runtime store is unreachable");
        require(input.backend_driver_ready && input.backend.implementation_available,
                "selected runtime-store driver is not ready");
        require(input.migrations_compatible, "store migrations are incompatible");
        require(input.node_lease_current, "node lease is not current");
        require(input.trust_policy_loaded, "trust policy is not loaded");
        require(input.retention_profiles_loaded, "required retention profiles are not loaded");
        require(input.active_generation_compiled, "active pack generation is not compiled locally");
        require(input.schemas_compatible, "schema catalog is incompatible");
        require(input.required_capabilities_available, "required capabilities are unavailable");

        result.ready = result.blockers.empty();
        return result;
    }

    ReadinessSnapshot evaluate_readiness(const ReadinessInput &input, const RuntimeStoreHealth &store_health) {
        auto selected = input;
        selected.database_reachable = store_health.connected;
        selected.backend_driver_ready = store_health.driver_available;
        selected.migrations_compatible = store_health.migrations_compatible;
        auto result = evaluate_readiness(selected);
        if (store_health.backend != input.backend.kind) {
            result.blockers.push_back("runtime-store health does not match the selected backend");
            result.ready = false;
        }
        return result;
    }

} // namespace rule_engine::python::cluster
