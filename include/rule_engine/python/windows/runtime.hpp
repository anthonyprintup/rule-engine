#pragma once

#include "rule_engine/python/protocol/types.hpp"
#include "rule_engine/python/windows/provider.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace rule_engine::python::windows {

    enum struct AgentRuntimeErrorCode : std::uint8_t {
        invalid_configuration,
        invalid_work,
        stale_session,
        stale_fence,
        stale_generation,
        work_conflict,
        canceled,
        limit_exceeded,
        provider_violation,
        invalid_inventory,
    };

    struct AgentRuntimeError {
        AgentRuntimeErrorCode code {AgentRuntimeErrorCode::invalid_work};
        std::string message;
    };

    struct WindowsAgentRuntimeIdentity {
        SessionId session;
        PeerId peer;
        std::uint64_t session_fence {};
        std::uint64_t generation {};
        std::string route {provider_name};
    };

    struct WindowsAgentRuntimeLimits {
        protocol_v2::ProtocolLimits protocol;
        std::size_t maximum_tracked_work {4'096};
        std::size_t maximum_inventory_scopes {4'096};
        std::size_t maximum_cached_result_bytes {64U * mebibyte};
        std::size_t maximum_last_good_inventory_bytes {128U * mebibyte};
    };

    struct InventoryProjectionRequest {
        std::string snapshot_id;
        std::optional<SubjectKey> parent;
        SchemaId subject_schema;
        std::size_t chunk_items {1'024};
    };

    struct ProjectedObservation {
        SubjectObservation observation;
        std::uint64_t generation {};
        std::string canonical_digest;
    };

    struct ProjectedRemoval {
        SubjectKey subject;
        std::uint64_t generation {};
        std::string canonical_digest;
    };

    struct InventoryProjection {
        std::uint64_t generation {};
        std::string inventory_digest;
        std::string protocol_digest;
        std::vector<protocol_v2::DurableAgentBody> durable_messages;
        std::vector<ProjectedObservation> observations;
        std::vector<ProjectedRemoval> removals;
        bool duplicate {};
    };

    // This adapter is deliberately below protocol transport/persistence and
    // above the Win32 collectors. It validates authenticated work identity,
    // calls only the data-only fact/scan entry points, and returns values that
    // the protocol spool may persist. It never receives a predicate, bytecode,
    // rule identity, or verdict.
    struct WindowsAgentProviderRuntime {
        explicit WindowsAgentProviderRuntime(WindowsAgentRuntimeIdentity identity,
                                             WindowsAgentRuntimeLimits limits = {});

        [[nodiscard]] std::expected<protocol_v2::WorkResultMessage, AgentRuntimeError>
        dispatch(const protocol_v2::WorkLeaseMessage &work);

        [[nodiscard]] std::expected<void, AgentRuntimeError> cancel(const protocol_v2::CancelWorkMessage &message);

        [[nodiscard]] std::expected<InventoryProjection, AgentRuntimeError>
        project_inventory(const InventoryProjectionRequest &request, const InventorySnapshot &inventory);

        [[nodiscard]] std::optional<std::uint64_t> last_good_generation(const SchemaId &schema,
                                                                        const std::optional<SubjectKey> &parent) const;
        [[nodiscard]] std::size_t tracked_work() const noexcept { return work_.size(); }
        [[nodiscard]] std::size_t last_good_scopes() const noexcept { return inventories_.size(); }

    private:
        struct WorkState {
            std::string work_id;
            std::string attempt_id;
            std::uint64_t work_fence {};
            std::uint64_t generation {};
            std::string fingerprint;
            std::vector<RequestId> request_ids;
            std::set<std::string, std::less<>> canceled_requests;
            bool cancel_all {};
            std::size_t cached_result_bytes {};
            std::optional<protocol_v2::WorkResultMessage> result;
        };

        struct InventoryState {
            std::string scope_key;
            SchemaId subject_schema;
            std::optional<SubjectKey> parent;
            std::uint64_t generation {};
            std::string inventory_digest;
            std::string protocol_digest;
            std::size_t storage_bytes {};
            std::vector<SubjectObservation> items;
        };

        [[nodiscard]] WorkState *find_work(std::string_view work_id) noexcept;
        [[nodiscard]] const InventoryState *find_inventory(std::string_view scope_key) const noexcept;

        WindowsAgentRuntimeIdentity identity_;
        WindowsAgentRuntimeLimits limits_;
        std::vector<WorkState> work_;
        std::vector<InventoryState> inventories_;
        std::size_t cached_result_bytes_ {};
        std::size_t last_good_inventory_bytes_ {};
    };

} // namespace rule_engine::python::windows
