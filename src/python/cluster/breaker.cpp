#include "rule_engine/python/cluster/breaker.hpp"

#include <algorithm>
#include <chrono>
#include <limits>
#include <set>
#include <utility>

namespace rule_engine::python::cluster {
    namespace {

        std::uint64_t milliseconds(const std::chrono::minutes value) {
            return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(value).count());
        }

        std::uint64_t lower_bound(const std::uint64_t now_unix_ms, const std::uint64_t window_ms) {
            return now_unix_ms > window_ms ? now_unix_ms - window_ms : 0U;
        }

        std::uint64_t saturating_add(const std::uint64_t left, const std::uint64_t right) {
            if (right > std::numeric_limits<std::uint64_t>::max() - left) {
                return std::numeric_limits<std::uint64_t>::max();
            }
            return left + right;
        }

        template<typename Collection, typename Timestamp>
        void trim_window(Collection &items, const std::uint64_t cutoff, Timestamp timestamp) {
            items.erase(std::remove_if(items.begin(), items.end(),
                                       [cutoff, timestamp](const auto &item) { return timestamp(item) < cutoff; }),
                        items.end());
        }

    } // namespace

    StoreError TripleFaultBreaker::source_error() {
        return StoreError {
            .code = StoreErrorCode::constraint_violation,
            .message = "breaker request does not use the active signed source hash",
            .retryable = false,
        };
    }

    void TripleFaultBreaker::activate_signed_source(const BindingId &binding, const SourceDigest &signed_source_hash,
                                                    const std::uint64_t now_unix_ms, const std::string_view actor) {
        if (binding.empty() || signed_source_hash.empty()) {
            return;
        }
        std::unique_lock lock {mutex_};
        auto &global = globals_[binding];
        if (global.active_source == signed_source_hash) {
            return;
        }
        global = GlobalState {
            .active_source = signed_source_hash,
            .faults = {},
            .quarantined = false,
        };
        for (auto current = peers_.begin(); current != peers_.end();) {
            if (current->first.binding == binding) {
                current = peers_.erase(current);
            } else {
                ++current;
            }
        }
        lock.unlock();
        static_cast<void>(audit_.append(now_unix_ms, actor, "breaker.activate_source", binding.value, "reset",
                                        signed_source_hash.value));
    }

    void TripleFaultBreaker::record_triple_fault_locked(const BindingId &binding, const PeerId &peer,
                                                        const SourceDigest &source, const std::uint64_t now_unix_ms) {
        auto &peer_state = peers_[PeerKey {.binding = binding, .peer = peer, .source = source}];
        trim_window(peer_state.faults, lower_bound(now_unix_ms, milliseconds(profile_.peer_window)),
                    [](const auto timestamp) { return timestamp; });
        peer_state.faults.push_back(now_unix_ms);
        if (peer_state.faults.size() >= profile_.peer_threshold) {
            peer_state.quarantine_until_unix_ms = saturating_add(now_unix_ms, milliseconds(profile_.peer_quarantine));
            peer_state.half_open_probe_in_flight = false;
        }

        auto &global = globals_.at(binding);
        trim_window(global.faults, lower_bound(now_unix_ms, milliseconds(profile_.global_window)),
                    [](const GlobalFault &fault) { return fault.at_unix_ms; });
        global.faults.push_back(GlobalFault {.at_unix_ms = now_unix_ms, .peer = peer});
        std::set<PeerId> distinct_peers;
        for (const auto &fault : global.faults) { distinct_peers.insert(fault.peer); }
        if (global.faults.size() >= profile_.global_threshold &&
            distinct_peers.size() >= profile_.global_distinct_peers) {
            global.quarantined = true;
        }
    }

    BreakerAdmission TripleFaultBreaker::admission_locked(const BindingId &binding, const PeerId &peer,
                                                          const SourceDigest &source, const std::uint64_t now_unix_ms,
                                                          const bool consume_half_open) {
        const auto global = globals_.find(binding);
        if (global == globals_.end() || global->second.active_source != source) {
            return BreakerAdmission {
                .kind = BreakerAdmissionKind::source_not_active,
                .allowed = false,
                .retry_at_unix_ms = std::nullopt,
            };
        }
        if (global->second.quarantined) {
            return BreakerAdmission {
                .kind = BreakerAdmissionKind::global_quarantined,
                .allowed = false,
                .retry_at_unix_ms = std::nullopt,
            };
        }

        const auto key = PeerKey {.binding = binding, .peer = peer, .source = source};
        const auto found = peers_.find(key);
        if (found == peers_.end() || !found->second.quarantine_until_unix_ms) {
            return BreakerAdmission {
                .kind = BreakerAdmissionKind::allowed,
                .allowed = true,
                .retry_at_unix_ms = std::nullopt,
            };
        }
        auto &state = found->second;
        if (now_unix_ms < *state.quarantine_until_unix_ms) {
            return BreakerAdmission {
                .kind = BreakerAdmissionKind::peer_quarantined,
                .allowed = false,
                .retry_at_unix_ms = state.quarantine_until_unix_ms,
            };
        }
        if (state.half_open_probe_in_flight) {
            return BreakerAdmission {
                .kind = BreakerAdmissionKind::peer_quarantined,
                .allowed = false,
                .retry_at_unix_ms = std::nullopt,
            };
        }
        if (consume_half_open) {
            state.half_open_probe_in_flight = true;
        }
        return BreakerAdmission {
            .kind = BreakerAdmissionKind::half_open_probe,
            .allowed = true,
            .retry_at_unix_ms = std::nullopt,
        };
    }

    std::expected<BreakerAdmission, StoreError>
    TripleFaultBreaker::record_triple_fault(const BindingId &binding, const PeerId &peer,
                                            const SourceDigest &signed_source_hash, const std::uint64_t now_unix_ms) {
        if (binding.empty() || peer.empty() || signed_source_hash.empty()) {
            return std::unexpected(StoreError {.code = StoreErrorCode::constraint_violation,
                                               .message = "triple-fault identity is incomplete",
                                               .retryable = false});
        }
        std::unique_lock lock {mutex_};
        const auto global = globals_.find(binding);
        if (global == globals_.end() || global->second.active_source != signed_source_hash) {
            return std::unexpected(source_error());
        }
        record_triple_fault_locked(binding, peer, signed_source_hash, now_unix_ms);
        const auto admission = admission_locked(binding, peer, signed_source_hash, now_unix_ms, false);
        lock.unlock();
        static_cast<void>(audit_.append(now_unix_ms, peer.value, "breaker.triple_fault", binding.value,
                                        admission.kind == BreakerAdmissionKind::global_quarantined ?
                                            "global_quarantine" :
                                        admission.kind == BreakerAdmissionKind::peer_quarantined ? "peer_quarantine" :
                                                                                                   "recorded",
                                        signed_source_hash.value));
        return admission;
    }

    std::expected<BreakerAdmission, StoreError> TripleFaultBreaker::admit(const BindingId &binding, const PeerId &peer,
                                                                          const SourceDigest &signed_source_hash,
                                                                          const std::uint64_t now_unix_ms) {
        const std::scoped_lock lock {mutex_};
        return admission_locked(binding, peer, signed_source_hash, now_unix_ms, true);
    }

    std::expected<void, StoreError> TripleFaultBreaker::complete_half_open(const BindingId &binding, const PeerId &peer,
                                                                           const SourceDigest &signed_source_hash,
                                                                           const bool healthy,
                                                                           const std::uint64_t now_unix_ms) {
        std::unique_lock lock {mutex_};
        const auto global = globals_.find(binding);
        if (global == globals_.end() || global->second.active_source != signed_source_hash) {
            return std::unexpected(source_error());
        }
        const PeerKey key {.binding = binding, .peer = peer, .source = signed_source_hash};
        const auto state = peers_.find(key);
        if (state == peers_.end() || !state->second.half_open_probe_in_flight) {
            return std::unexpected(StoreError {.code = StoreErrorCode::constraint_violation,
                                               .message = "no half-open probe is in flight",
                                               .retryable = false});
        }

        if (healthy) {
            peers_.erase(state);
        } else {
            state->second.half_open_probe_in_flight = false;
            state->second.quarantine_until_unix_ms =
                saturating_add(now_unix_ms, milliseconds(profile_.peer_quarantine));
            record_triple_fault_locked(binding, peer, signed_source_hash, now_unix_ms);
        }
        lock.unlock();
        static_cast<void>(audit_.append(now_unix_ms, peer.value, "breaker.half_open", binding.value,
                                        healthy ? "closed" : "requarantined", signed_source_hash.value));
        return {};
    }

    std::expected<void, StoreError> TripleFaultBreaker::clear_global(const BindingId &binding,
                                                                     const std::uint64_t now_unix_ms,
                                                                     const std::string_view actor) {
        std::unique_lock lock {mutex_};
        const auto state = globals_.find(binding);
        if (state == globals_.end()) {
            return {};
        }
        state->second.quarantined = false;
        state->second.faults.clear();
        lock.unlock();
        static_cast<void>(
            audit_.append(now_unix_ms, actor, "breaker.clear_global", binding.value, "cleared", "operator"));
        return {};
    }

    std::vector<PeerBreakerSnapshot> TripleFaultBreaker::peer_snapshot(const std::uint64_t now_unix_ms) const {
        const std::scoped_lock lock {mutex_};
        std::vector<PeerBreakerSnapshot> result;
        result.reserve(peers_.size());
        const auto cutoff = lower_bound(now_unix_ms, milliseconds(profile_.peer_window));
        for (const auto &[key, state] : peers_) {
            const auto count =
                std::ranges::count_if(state.faults, [cutoff](const auto time) { return time >= cutoff; });
            result.push_back(PeerBreakerSnapshot {
                .binding = key.binding,
                .peer = key.peer,
                .signed_source_hash = key.source,
                .faults_in_window = static_cast<std::uint32_t>(count),
                .quarantine_until_unix_ms = state.quarantine_until_unix_ms,
                .half_open_probe_in_flight = state.half_open_probe_in_flight,
            });
        }
        return result;
    }

    std::vector<GlobalBreakerSnapshot> TripleFaultBreaker::global_snapshot(const std::uint64_t now_unix_ms) const {
        const std::scoped_lock lock {mutex_};
        std::vector<GlobalBreakerSnapshot> result;
        result.reserve(globals_.size());
        const auto cutoff = lower_bound(now_unix_ms, milliseconds(profile_.global_window));
        for (const auto &[binding, state] : globals_) {
            std::set<PeerId> peers;
            std::uint32_t count {};
            for (const auto &fault : state.faults) {
                if (fault.at_unix_ms >= cutoff) {
                    ++count;
                    peers.insert(fault.peer);
                }
            }
            result.push_back(GlobalBreakerSnapshot {
                .binding = binding,
                .active_signed_source_hash = state.active_source,
                .faults_in_window = count,
                .distinct_peers_in_window = static_cast<std::uint32_t>(peers.size()),
                .quarantined = state.quarantined,
            });
        }
        return result;
    }

} // namespace rule_engine::python::cluster
