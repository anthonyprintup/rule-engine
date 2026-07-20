#include "rule_engine/python/cluster/coordinator.hpp"

#include <algorithm>
#include <limits>
#include <set>
#include <tuple>
#include <utility>

namespace rule_engine::python::cluster {
    namespace {

        StoreError coordinator_error(const StoreErrorCode code, std::string message, const bool retryable = false) {
            return StoreError {.code = code, .message = std::move(message), .retryable = retryable};
        }

        std::uint64_t saturating_add(const std::uint64_t left, const std::uint64_t right) {
            if (right > std::numeric_limits<std::uint64_t>::max() - left) {
                return std::numeric_limits<std::uint64_t>::max();
            }
            return left + right;
        }

    } // namespace

    std::expected<FencedLease, StoreError> FencedLeaseManager::claim(const LeaseResource &resource,
                                                                     const std::string_view owner,
                                                                     const std::uint64_t now_unix_ms,
                                                                     const std::uint64_t lease_duration_ms) {
        if (resource.scope.empty() || resource.key.empty() || owner.empty() || lease_duration_ms == 0) {
            return std::unexpected(
                coordinator_error(StoreErrorCode::constraint_violation, "lease claim arguments are invalid"));
        }

        std::unique_lock lock {mutex_};
        auto &record = leases_[resource];
        if (record.held && record.lease_until_unix_ms >= now_unix_ms) {
            if (record.owner == owner) {
                return FencedLease {
                    .resource = resource,
                    .owner = record.owner,
                    .fence = record.fence,
                    .lease_until_unix_ms = record.lease_until_unix_ms,
                };
            }
            return std::unexpected(coordinator_error(StoreErrorCode::conflict, "lease is held by another owner", true));
        }

        ++record.fence;
        record.owner = std::string {owner};
        record.held = true;
        record.lease_until_unix_ms = saturating_add(now_unix_ms, lease_duration_ms);
        const FencedLease lease {
            .resource = resource,
            .owner = record.owner,
            .fence = record.fence,
            .lease_until_unix_ms = record.lease_until_unix_ms,
        };
        lock.unlock();
        static_cast<void>(audit_.append(now_unix_ms, owner, "lease.claim", resource.scope + ":" + resource.key,
                                        "leased", std::to_string(lease.fence)));
        return lease;
    }

    std::expected<FencedLease, StoreError> FencedLeaseManager::renew(const FencedLease &lease,
                                                                     const std::uint64_t now_unix_ms,
                                                                     const std::uint64_t lease_duration_ms) {
        if (lease_duration_ms == 0) {
            return std::unexpected(
                coordinator_error(StoreErrorCode::constraint_violation, "lease renewal duration must be positive"));
        }
        std::unique_lock lock {mutex_};
        const auto current = leases_.find(lease.resource);
        if (current == leases_.end() || !current->second.held || current->second.owner != lease.owner ||
            current->second.fence != lease.fence || current->second.lease_until_unix_ms < now_unix_ms) {
            return std::unexpected(coordinator_error(StoreErrorCode::stale_fence, "lease renewal is stale"));
        }
        current->second.lease_until_unix_ms = saturating_add(now_unix_ms, lease_duration_ms);
        const FencedLease renewed {
            .resource = lease.resource,
            .owner = current->second.owner,
            .fence = current->second.fence,
            .lease_until_unix_ms = current->second.lease_until_unix_ms,
        };
        lock.unlock();
        static_cast<void>(audit_.append(now_unix_ms, lease.owner, "lease.renew",
                                        lease.resource.scope + ":" + lease.resource.key, "renewed",
                                        std::to_string(renewed.fence)));
        return renewed;
    }

    std::expected<void, StoreError> FencedLeaseManager::release(const FencedLease &lease,
                                                                const std::uint64_t now_unix_ms) {
        std::unique_lock lock {mutex_};
        const auto current = leases_.find(lease.resource);
        if (current == leases_.end() || !current->second.held || current->second.owner != lease.owner ||
            current->second.fence != lease.fence || current->second.lease_until_unix_ms < now_unix_ms) {
            return std::unexpected(coordinator_error(StoreErrorCode::stale_fence, "lease release is stale"));
        }
        current->second.held = false;
        current->second.owner.clear();
        current->second.lease_until_unix_ms = now_unix_ms;
        ++current->second.fence;
        const auto fence = current->second.fence;
        lock.unlock();
        static_cast<void>(audit_.append(now_unix_ms, lease.owner, "lease.release",
                                        lease.resource.scope + ":" + lease.resource.key, "released",
                                        std::to_string(fence)));
        return {};
    }

    bool FencedLeaseManager::is_current(const FencedLease &lease, const std::uint64_t now_unix_ms) const {
        const std::scoped_lock lock {mutex_};
        const auto current = leases_.find(lease.resource);
        return current != leases_.end() && current->second.held && current->second.owner == lease.owner &&
               current->second.fence == lease.fence && current->second.lease_until_unix_ms >= now_unix_ms;
    }

    std::vector<LeaseSnapshot> FencedLeaseManager::snapshot(const std::uint64_t now_unix_ms) const {
        const std::scoped_lock lock {mutex_};
        std::vector<LeaseSnapshot> result;
        result.reserve(leases_.size());
        for (const auto &[resource, lease] : leases_) {
            result.push_back(LeaseSnapshot {
                .resource = resource,
                .owner = lease.owner,
                .fence = lease.fence,
                .lease_until_unix_ms = lease.lease_until_unix_ms,
                .held = lease.held && lease.lease_until_unix_ms >= now_unix_ms,
            });
        }
        return result;
    }

    bool DeterministicWorkCoordinator::definition_matches(const WorkDefinition &left, const WorkDefinition &right) {
        return left.work_id == right.work_id && left.pack == right.pack && left.generation == right.generation &&
               left.serial_domain == right.serial_domain && left.event == right.event &&
               left.priority == right.priority && left.ingest_position == right.ingest_position;
    }

    std::expected<bool, StoreError> DeterministicWorkCoordinator::enqueue(const WorkDefinition &work) {
        if (work.work_id.empty() || work.pack.empty() || work.generation == 0 || work.serial_domain.empty() ||
            work.event.empty()) {
            return std::unexpected(
                coordinator_error(StoreErrorCode::constraint_violation, "work definition is incomplete"));
        }
        std::unique_lock lock {mutex_};
        if (const auto existing = work_.find(work.work_id); existing != work_.end()) {
            if (!definition_matches(existing->second.work, work)) {
                return std::unexpected(
                    coordinator_error(StoreErrorCode::constraint_violation, "duplicate work ID has different content"));
            }
            return false;
        }
        work_.emplace(work.work_id, WorkSnapshot {
                                        .work = work,
                                        .phase = WorkPhase::ready,
                                        .node_id = {},
                                        .attempt = 0,
                                        .fence = 0,
                                        .lease_until_unix_ms = 0,
                                    });
        lock.unlock();
        static_cast<void>(audit_.append(work.ingest_position, "coordinator", "work.enqueue", work.work_id, "queued",
                                        work.serial_domain));
        return true;
    }

    std::expected<std::vector<WorkLease>, StoreError>
    DeterministicWorkCoordinator::claim(const std::string_view node_id, const std::uint64_t now_unix_ms,
                                        const std::uint64_t lease_duration_ms, const std::size_t limit) {
        if (node_id.empty() || lease_duration_ms == 0 || limit == 0) {
            return std::unexpected(
                coordinator_error(StoreErrorCode::constraint_violation, "work claim arguments are invalid"));
        }

        std::unique_lock lock {mutex_};
        std::map<std::string, WorkSnapshot *, std::less<>> domain_heads;
        for (auto &[_, item] : work_) {
            if (item.phase == WorkPhase::completed) {
                continue;
            }
            const auto current = domain_heads.find(item.work.serial_domain);
            if (current == domain_heads.end() ||
                std::tie(item.work.ingest_position, item.work.work_id) <
                    std::tie(current->second->work.ingest_position, current->second->work.work_id)) {
                domain_heads.insert_or_assign(item.work.serial_domain, &item);
            }
        }
        std::vector<WorkSnapshot *> candidates;
        candidates.reserve(domain_heads.size());
        for (const auto &[_, item] : domain_heads) { candidates.push_back(item); }
        std::ranges::sort(candidates, [](const WorkSnapshot *left, const WorkSnapshot *right) {
            if (left->work.priority != right->work.priority) {
                return left->work.priority > right->work.priority;
            }
            return std::tie(left->work.ingest_position, left->work.work_id) <
                   std::tie(right->work.ingest_position, right->work.work_id);
        });

        std::vector<WorkLease> claimed;
        claimed.reserve(std::min(limit, candidates.size()));
        for (auto *item : candidates) {
            if (claimed.size() == limit) {
                break;
            }
            if (item->phase == WorkPhase::leased && item->lease_until_unix_ms >= now_unix_ms) {
                continue;
            }

            const auto lease = leases_.claim(LeaseResource {.scope = "work", .key = item->work.serial_domain}, node_id,
                                             now_unix_ms, lease_duration_ms);
            if (!lease) {
                if (lease.error().code == StoreErrorCode::conflict) {
                    continue;
                }
                return std::unexpected(lease.error());
            }
            if (auto installed = store_.install_consumer_fence(item->work.serial_domain, lease->fence); !installed) {
                static_cast<void>(leases_.release(*lease, now_unix_ms));
                return std::unexpected(installed.error());
            }

            item->phase = WorkPhase::leased;
            item->node_id = std::string {node_id};
            ++item->attempt;
            item->fence = lease->fence;
            item->lease_until_unix_ms = lease->lease_until_unix_ms;
            claimed.push_back(WorkLease {
                .work = item->work,
                .node_id = item->node_id,
                .attempt = item->attempt,
                .fence = item->fence,
                .lease_until_unix_ms = item->lease_until_unix_ms,
            });
        }
        return claimed;
    }

    std::expected<TransactionReceipt, StoreError>
    DeterministicWorkCoordinator::commit(const WorkLease &lease, RuntimeTransaction transaction,
                                         const std::uint64_t now_unix_ms) {
        std::unique_lock lock {mutex_};
        const auto current = work_.find(lease.work.work_id);
        if (current == work_.end() || current->second.phase != WorkPhase::leased ||
            !definition_matches(current->second.work, lease.work) || current->second.node_id != lease.node_id ||
            current->second.attempt != lease.attempt || current->second.fence != lease.fence ||
            current->second.lease_until_unix_ms < now_unix_ms ||
            !leases_.is_current(
                FencedLease {
                    .resource = {.scope = "work", .key = lease.work.serial_domain},
                    .owner = lease.node_id,
                    .fence = lease.fence,
                    .lease_until_unix_ms = lease.lease_until_unix_ms,
                },
                now_unix_ms)) {
            return std::unexpected(coordinator_error(StoreErrorCode::stale_fence, "work completion is stale"));
        }
        if (transaction.input.id != lease.work.event) {
            return std::unexpected(coordinator_error(StoreErrorCode::constraint_violation,
                                                     "work event and transaction input do not match"));
        }

        transaction.cursor.consumer = lease.work.serial_domain;
        transaction.fence_token = lease.fence;
        auto committed = store_.transact_event(transaction);
        if (!committed) {
            return std::unexpected(committed.error());
        }

        current->second.phase = WorkPhase::completed;
        const FencedLease domain_lease {
            .resource = {.scope = "work", .key = lease.work.serial_domain},
            .owner = lease.node_id,
            .fence = lease.fence,
            .lease_until_unix_ms = lease.lease_until_unix_ms,
        };
        static_cast<void>(leases_.release(domain_lease, now_unix_ms));
        lock.unlock();
        static_cast<void>(audit_.append(now_unix_ms, lease.node_id, "work.commit", lease.work.work_id, "committed",
                                        lease.work.serial_domain));
        return committed;
    }

    std::expected<void, StoreError> DeterministicWorkCoordinator::abandon(const WorkLease &lease,
                                                                          const std::uint64_t now_unix_ms) {
        std::unique_lock lock {mutex_};
        const auto current = work_.find(lease.work.work_id);
        if (current == work_.end() || current->second.phase != WorkPhase::leased ||
            current->second.node_id != lease.node_id || current->second.attempt != lease.attempt ||
            current->second.fence != lease.fence) {
            return std::unexpected(coordinator_error(StoreErrorCode::stale_fence, "work abandonment is stale"));
        }
        const FencedLease domain_lease {
            .resource = {.scope = "work", .key = lease.work.serial_domain},
            .owner = lease.node_id,
            .fence = lease.fence,
            .lease_until_unix_ms = lease.lease_until_unix_ms,
        };
        if (auto released = leases_.release(domain_lease, now_unix_ms); !released) {
            return std::unexpected(released.error());
        }
        current->second.phase = WorkPhase::ready;
        current->second.node_id.clear();
        current->second.lease_until_unix_ms = 0;
        lock.unlock();
        static_cast<void>(audit_.append(now_unix_ms, lease.node_id, "work.abandon", lease.work.work_id, "ready",
                                        lease.work.serial_domain));
        return {};
    }

    std::optional<TransactionReceipt> DeterministicWorkCoordinator::recover_receipt(const EventId &input) const {
        return store_.lookup_receipt(input);
    }

    std::vector<WorkSnapshot> DeterministicWorkCoordinator::snapshot() const {
        const std::scoped_lock lock {mutex_};
        std::vector<WorkSnapshot> result;
        result.reserve(work_.size());
        for (const auto &[_, item] : work_) { result.push_back(item); }
        return result;
    }

} // namespace rule_engine::python::cluster
