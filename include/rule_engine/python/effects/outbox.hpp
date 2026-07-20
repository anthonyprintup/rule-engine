#pragma once

#include "rule_engine/python/effects/journal.hpp"

#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace rule_engine::python::effects {

    enum struct OutboxState : std::uint8_t { pending, leased, retry_wait, delivered, dead_letter, expired };

    struct OutboxEntry {
        OutboxRecord record;
        OutboxState state {OutboxState::pending};
        std::uint64_t committed_unix_ms {};
        std::uint64_t expires_unix_ms {};
        std::uint64_t next_attempt_unix_ms {};
        std::uint32_t attempts {};
        std::uint64_t lease_token {};
        std::string lease_owner;
        std::uint64_t lease_expires_unix_ms {};
        std::string last_error;
        std::optional<FrozenValue> acknowledgment;
    };

    struct OutboxLease {
        IntentId intent;
        std::string worker;
        std::uint64_t token {};
        std::uint32_t attempt {};
        OutboxRecord record;
        std::uint64_t expires_unix_ms {};
    };

    enum struct DeliveryFailureKind : std::uint8_t { transport, http_status };

    struct DeliveryFailure {
        DeliveryFailureKind kind {DeliveryFailureKind::transport};
        std::uint16_t status_code {};
        std::optional<std::uint64_t> retry_after_ms;
        std::string summary;
    };

    struct ActionDeliveryRecord {
        IntentId intent;
        OutboxState state {OutboxState::pending};
        std::uint32_t attempts {};
        std::optional<FrozenValue> acknowledgment;
        std::string summary;
    };

    enum struct OutboxErrorCode : std::uint8_t {
        invalid_record,
        replay_forbidden,
        intent_not_committed,
        duplicate_idempotency_mismatch,
        duplicate_intent_mismatch,
        unknown_intent,
        no_claimable_record,
        stale_lease,
        invalid_state,
        invalid_snapshot,
    };

    struct OutboxError {
        OutboxErrorCode code {};
        std::string message;
    };

    struct EnqueueResult {
        IntentId intent;
        bool inserted {};
    };

    struct IOutboxDeliveryStore {
        IOutboxDeliveryStore() = default;
        IOutboxDeliveryStore(IOutboxDeliveryStore &&) noexcept = default;
        IOutboxDeliveryStore &operator=(IOutboxDeliveryStore &&) noexcept = default;
        IOutboxDeliveryStore(const IOutboxDeliveryStore &) = delete;
        IOutboxDeliveryStore &operator=(const IOutboxDeliveryStore &) = delete;
        virtual ~IOutboxDeliveryStore() = default;
        [[nodiscard]] virtual std::expected<OutboxLease, OutboxError>
        claim(std::string worker, std::uint64_t now_unix_ms, std::uint64_t lease_duration_ms) = 0;
        [[nodiscard]] virtual std::expected<ActionDeliveryRecord, OutboxError>
        acknowledge(const OutboxLease &lease, std::uint64_t now_unix_ms,
                    std::optional<FrozenValue> acknowledgment = std::nullopt) = 0;
        [[nodiscard]] virtual std::expected<ActionDeliveryRecord, OutboxError>
        fail(const OutboxLease &lease, const DeliveryFailure &failure, std::uint64_t now_unix_ms) = 0;
    };

    struct ActionDispatchSuccess {
        std::uint64_t completed_unix_ms {};
        std::optional<FrozenValue> acknowledgment;
    };

    struct ActionDispatchFailure {
        std::uint64_t completed_unix_ms {};
        DeliveryFailure failure;
    };

    struct IActionTransport {
        IActionTransport() = default;
        IActionTransport(const IActionTransport &) = delete;
        IActionTransport &operator=(const IActionTransport &) = delete;
        virtual ~IActionTransport() = default;
        [[nodiscard]] virtual std::expected<ActionDispatchSuccess, ActionDispatchFailure>
        dispatch(const OutboxLease &lease) = 0;
    };

    struct OutboxDispatcherConfig {
        ExecutionMode mode {ExecutionMode::live};
        std::string worker;
        std::uint64_t lease_duration_ms {};
    };

    struct OutboxDispatcher {
        [[nodiscard]] static std::expected<ActionDeliveryRecord, OutboxError>
        dispatch_one(IOutboxDeliveryStore &store, IActionTransport &transport, const OutboxDispatcherConfig &config,
                     std::uint64_t now_unix_ms);
    };

    struct OutboxQueue final: IOutboxDeliveryStore {
        struct Implementation;

        [[nodiscard]] static std::expected<OutboxQueue, OutboxError> create();
        [[nodiscard]] static std::expected<OutboxQueue, OutboxError> restore(std::vector<OutboxEntry> entries);

        OutboxQueue(OutboxQueue &&other) noexcept;
        OutboxQueue &operator=(OutboxQueue &&other) noexcept;
        OutboxQueue(const OutboxQueue &) = delete;
        OutboxQueue &operator=(const OutboxQueue &) = delete;
        ~OutboxQueue() override;

        [[nodiscard]] std::expected<EnqueueResult, OutboxError> enqueue(const FinalizedJournal &journal,
                                                                        const IntentId &intent, std::string destination,
                                                                        std::uint64_t committed_unix_ms,
                                                                        std::uint64_t lifetime_ms = 86'400'000);
        [[nodiscard]] std::expected<OutboxLease, OutboxError> claim(std::string worker, std::uint64_t now_unix_ms,
                                                                    std::uint64_t lease_duration_ms) override;
        [[nodiscard]] std::expected<ActionDeliveryRecord, OutboxError>
        acknowledge(const OutboxLease &lease, std::uint64_t now_unix_ms,
                    std::optional<FrozenValue> acknowledgment = std::nullopt) override;
        [[nodiscard]] std::expected<ActionDeliveryRecord, OutboxError>
        fail(const OutboxLease &lease, const DeliveryFailure &failure, std::uint64_t now_unix_ms) override;

        void release_expired_leases(std::uint64_t now_unix_ms);
        void expire_due(std::uint64_t now_unix_ms);
        [[nodiscard]] std::vector<OutboxEntry> snapshot() const;
        [[nodiscard]] std::optional<OutboxEntry> find(const IntentId &intent) const;
        [[nodiscard]] std::size_t size() const noexcept;

    private:
        explicit OutboxQueue(std::unique_ptr<Implementation> implementation) noexcept;

        std::unique_ptr<Implementation> implementation_;
    };

} // namespace rule_engine::python::effects
