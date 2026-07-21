#pragma once

#include "rule_engine/python/protocol/codec.hpp"
#include "rule_engine/python/protocol/session.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace rule_engine::python::protocol_v2 {

    struct SpoolBackendStatus {
        bool available {};
        std::string implementation;
        std::string diagnostic;
    };

    [[nodiscard]] SpoolBackendStatus spool_backend_status() noexcept;

    struct StoredSpoolRecord {
        std::uint64_t sequence {};
        DurableAgentBody body;
        std::vector<std::byte> canonical_body;
        std::size_t encoded_bytes {};
        std::uint32_t transmit_attempts {};
    };

    struct SqliteAgentSpool {
        SqliteAgentSpool(SqliteAgentSpool &&) noexcept;
        SqliteAgentSpool &operator=(SqliteAgentSpool &&) noexcept;
        SqliteAgentSpool(const SqliteAgentSpool &) = delete;
        SqliteAgentSpool &operator=(const SqliteAgentSpool &) = delete;
        ~SqliteAgentSpool();

        [[nodiscard]] static std::expected<SqliteAgentSpool, ProtocolError>
        open(std::string database_path, AgentSpoolLimits limits = {}, ProtocolLimits protocol_limits = {}) noexcept;

        [[nodiscard]] const std::string &agent_epoch() const noexcept;
        [[nodiscard]] std::uint64_t next_sequence() const noexcept;
        [[nodiscard]] std::uint64_t acknowledged_through() const noexcept;
        [[nodiscard]] std::size_t pending_records() const noexcept;
        [[nodiscard]] std::size_t pending_bytes() const noexcept;
        [[nodiscard]] bool backpressured() const noexcept;

        [[nodiscard]] std::expected<std::uint64_t, ProtocolError> enqueue(const DurableAgentBody &body) noexcept;
        [[nodiscard]] std::expected<std::vector<std::uint64_t>, ProtocolError>
        enqueue_batch(std::span<const DurableAgentBody> bodies) noexcept;
        [[nodiscard]] std::expected<std::vector<StoredSpoolRecord>, ProtocolError>
        pending(std::size_t maximum_records, std::size_t maximum_bytes) const noexcept;
        [[nodiscard]] std::expected<void, ProtocolError> mark_transmitted(std::uint64_t sequence) noexcept;
        [[nodiscard]] std::expected<void, ProtocolError> acknowledge(std::string_view agent_epoch,
                                                                     std::uint64_t through) noexcept;
        [[nodiscard]] std::expected<void, ProtocolError> reject(const NackMessage &nack) noexcept;
        [[nodiscard]] std::expected<void, ProtocolError> reset_epoch() noexcept;

    private:
        struct Impl;
        explicit SqliteAgentSpool(std::unique_ptr<Impl> impl) noexcept;
        std::unique_ptr<Impl> impl_;
    };

    // Couples session fences/credits to the durable database. In-flight state
    // is intentionally volatile: reconnect clears it and retransmits canonical
    // rows after the server's cumulative durable ACK.
    struct PersistentAgentSession {
        PersistentAgentSession(PeerId peer, SqliteAgentSpool &spool);

        [[nodiscard]] std::expected<void, ProtocolError> establish(const ServerHelloMessage &hello) noexcept;
        [[nodiscard]] std::expected<WorkAcceptance, ProtocolError> accept_work(const WorkLeaseMessage &work);
        [[nodiscard]] std::expected<std::vector<RequestId>, ProtocolError>
        accept_cancel(const CancelWorkMessage &cancel);
        [[nodiscard]] std::expected<std::uint64_t, ProtocolError> enqueue(const DurableAgentBody &body) noexcept;
        [[nodiscard]] std::expected<std::vector<PeerEnvelope>, ProtocolError>
        take_transmit_batch(std::size_t maximum_records = 256) noexcept;
        [[nodiscard]] std::expected<void, ProtocolError> acknowledge(const AckMessage &ack) noexcept;
        [[nodiscard]] std::expected<void, ProtocolError> reject(const NackMessage &nack) noexcept;
        void update_credit(CreditWindow credit) noexcept;
        void disconnect() noexcept;

        [[nodiscard]] bool established() const noexcept { return session_.has_value(); }
        [[nodiscard]] bool backpressured() const noexcept { return spool_->backpressured(); }
        [[nodiscard]] const std::string &agent_epoch() const noexcept { return spool_->agent_epoch(); }
        [[nodiscard]] std::uint64_t next_sequence() const noexcept { return spool_->next_sequence(); }

    private:
        struct InFlight {
            std::uint64_t sequence {};
            std::size_t bytes {};
            bool work {};
            bool snapshot_chunk {};
        };

        void clear_in_flight() noexcept;
        void release(std::uint64_t sequence) noexcept;

        PeerId peer_;
        SqliteAgentSpool *spool_ {};
        AgentSessionState control_;
        std::optional<SessionId> session_;
        CreditWindow credit_;
        std::vector<InFlight> in_flight_;
    };

} // namespace rule_engine::python::protocol_v2
