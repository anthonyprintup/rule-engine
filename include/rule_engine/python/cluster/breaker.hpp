#pragma once

#include "rule_engine/python/cluster/audit.hpp"
#include "rule_engine/python/contract/budget.hpp"
#include "rule_engine/python/contract/distributed.hpp"

#include <cstdint>
#include <expected>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace rule_engine::python::cluster {

    enum struct BreakerAdmissionKind : std::uint8_t {
        allowed,
        half_open_probe,
        peer_quarantined,
        global_quarantined,
        source_not_active,
    };

    struct BreakerAdmission {
        BreakerAdmissionKind kind {BreakerAdmissionKind::allowed};
        bool allowed {};
        std::optional<std::uint64_t> retry_at_unix_ms;
    };

    struct PeerBreakerSnapshot {
        BindingId binding;
        PeerId peer;
        SourceDigest signed_source_hash;
        std::uint32_t faults_in_window {};
        std::optional<std::uint64_t> quarantine_until_unix_ms;
        bool half_open_probe_in_flight {};
    };

    struct GlobalBreakerSnapshot {
        BindingId binding;
        SourceDigest active_signed_source_hash;
        std::uint32_t faults_in_window {};
        std::uint32_t distinct_peers_in_window {};
        bool quarantined {};
    };

    struct TripleFaultBreaker {
        explicit TripleFaultBreaker(AuditTrail &audit, BreakerProfile profile = breaker_v1):
            audit_ {audit}, profile_ {profile} {}

        // This is the only automatic reset path: an audited activation of a
        // different signed source hash. Merely asking admission for another
        // hash does not reset a breaker.
        void activate_signed_source(const BindingId &binding, const SourceDigest &signed_source_hash,
                                    std::uint64_t now_unix_ms, std::string_view actor);

        [[nodiscard]] std::expected<BreakerAdmission, StoreError>
        record_triple_fault(const BindingId &binding, const PeerId &peer, const SourceDigest &signed_source_hash,
                            std::uint64_t now_unix_ms);
        [[nodiscard]] std::expected<BreakerAdmission, StoreError> admit(const BindingId &binding, const PeerId &peer,
                                                                        const SourceDigest &signed_source_hash,
                                                                        std::uint64_t now_unix_ms);
        [[nodiscard]] std::expected<void, StoreError> complete_half_open(const BindingId &binding, const PeerId &peer,
                                                                         const SourceDigest &signed_source_hash,
                                                                         bool healthy, std::uint64_t now_unix_ms);
        [[nodiscard]] std::expected<void, StoreError> clear_global(const BindingId &binding, std::uint64_t now_unix_ms,
                                                                   std::string_view actor);

        [[nodiscard]] std::vector<PeerBreakerSnapshot> peer_snapshot(std::uint64_t now_unix_ms) const;
        [[nodiscard]] std::vector<GlobalBreakerSnapshot> global_snapshot(std::uint64_t now_unix_ms) const;

    private:
        struct PeerKey {
            BindingId binding;
            PeerId peer;
            SourceDigest source;

            auto operator<=>(const PeerKey &) const = default;
        };

        struct PeerState {
            std::vector<std::uint64_t> faults;
            std::optional<std::uint64_t> quarantine_until_unix_ms;
            bool half_open_probe_in_flight {};
        };

        struct GlobalFault {
            std::uint64_t at_unix_ms {};
            PeerId peer;
        };

        struct GlobalState {
            SourceDigest active_source;
            std::vector<GlobalFault> faults;
            bool quarantined {};
        };

        [[nodiscard]] static StoreError source_error();
        [[nodiscard]] BreakerAdmission admission_locked(const BindingId &binding, const PeerId &peer,
                                                        const SourceDigest &source, std::uint64_t now_unix_ms,
                                                        bool consume_half_open);
        void record_triple_fault_locked(const BindingId &binding, const PeerId &peer, const SourceDigest &source,
                                        std::uint64_t now_unix_ms);

        AuditTrail &audit_;
        BreakerProfile profile_;
        mutable std::mutex mutex_;
        std::map<PeerKey, PeerState> peers_;
        std::map<BindingId, GlobalState> globals_;
    };

} // namespace rule_engine::python::cluster
