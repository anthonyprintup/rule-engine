#include "rule_engine/python/protocol/session.hpp"

#include <algorithm>
#include <limits>
#include <string_view>
#include <type_traits>
#include <unordered_set>
#include <utility>

namespace rule_engine::python::protocol_v2 {
    namespace {

        [[nodiscard]] ProtocolError session_error(const ProtocolErrorCode code, std::string message) {
            return ProtocolError {.code = code, .message = std::move(message), .byte_offset = 0};
        }

        [[nodiscard]] bool request_ids_are_unique(const std::span<const FactRequest> facts,
                                                  const std::span<const ScanRequest> scans) {
            std::unordered_set<std::string> ids;
            ids.reserve(facts.size() + scans.size());
            for (const auto &fact : facts) {
                if (fact.request_id.empty() || !ids.insert(fact.request_id.value).second) {
                    return false;
                }
            }
            for (const auto &scan : scans) {
                if (scan.request_id.empty() || !ids.insert(scan.request_id.value).second) {
                    return false;
                }
            }
            return true;
        }

        [[nodiscard]] bool is_snapshot_chunk(const DurableAgentBody &body) noexcept {
            return std::holds_alternative<AuthoritativeSnapshotChunk>(body);
        }

        [[nodiscard]] bool is_work_result(const DurableAgentBody &body) noexcept {
            return std::holds_alternative<WorkResultMessage>(body);
        }

    } // namespace

    std::expected<AuthenticatedPeer, ProtocolError> authenticate_transport(const TlsPeerIdentity &identity,
                                                                           const ITrustPolicy &policy) noexcept {
        // The fields use human protocol notation: TLS 1.3 is {1, 3}.
        if (identity.tls_major != 1 || identity.tls_minor != 3) {
            return std::unexpected(session_error(ProtocolErrorCode::unauthenticated, "TLS 1.3 is required"));
        }
        if (!identity.mutual_authentication || !identity.certificate_chain_verified || !identity.client_auth_eku) {
            return std::unexpected(
                session_error(ProtocolErrorCode::unauthenticated, "a verified mutual-TLS client identity is required"));
        }
        if (identity.revoked) {
            return std::unexpected(
                session_error(ProtocolErrorCode::unauthenticated, "the peer certificate is revoked"));
        }
        if (identity.canonical_uri_san.empty() || identity.certificate_sha256.empty()) {
            return std::unexpected(
                session_error(ProtocolErrorCode::unauthenticated, "the peer certificate identity is incomplete"));
        }

        auto peer = policy.authenticate(identity);
        if (!peer) {
            return std::unexpected(std::move(peer.error()));
        }
        if (peer->tenant.empty() || peer->peer.empty()) {
            return std::unexpected(
                session_error(ProtocolErrorCode::unauthenticated, "the trust policy returned an empty peer"));
        }
        return peer;
    }

    std::expected<SequenceDisposition, ProtocolError> ServerReceiveState::observe(const PeerEnvelope &envelope) {
        if (!envelope.session.has_value() || *envelope.session != session) {
            return std::unexpected(session_error(ProtocolErrorCode::stale_session, "message session is not current"));
        }
        if (envelope.agent_epoch != agent_epoch || envelope.agent_sequence == 0) {
            return std::unexpected(session_error(ProtocolErrorCode::malformed, "durable sequence identity is invalid"));
        }
        if (envelope.agent_sequence <= acknowledged_through || observed_.contains(envelope.agent_sequence)) {
            return SequenceDisposition::duplicate;
        }
        if (envelope.agent_sequence - acknowledged_through > maximum_gap) {
            return std::unexpected(
                session_error(ProtocolErrorCode::sequence_gap, "durable sequence exceeds the receive window"));
        }

        observed_.insert(envelope.agent_sequence);
        if (envelope.agent_sequence == acknowledged_through + 1) {
            return SequenceDisposition::accepted;
        }
        return SequenceDisposition::accepted_out_of_order;
    }

    std::expected<std::uint64_t, ProtocolError> ServerReceiveState::mark_durable(const std::uint64_t sequence) {
        if (sequence <= acknowledged_through) {
            return acknowledged_through;
        }
        if (!observed_.contains(sequence)) {
            return std::unexpected(
                session_error(ProtocolErrorCode::sequence_gap, "cannot settle an unobserved durable sequence"));
        }

        durable_.insert(sequence);
        while (durable_.contains(acknowledged_through + 1)) {
            const auto next = acknowledged_through + 1;
            durable_.erase(next);
            observed_.erase(next);
            acknowledged_through = next;
        }
        return acknowledged_through;
    }

    AgentSessionState::AgentSessionState(PeerId peer, std::string agent_epoch, AgentSpoolLimits limits):
        peer_ {std::move(peer)}, agent_epoch_ {std::move(agent_epoch)}, limits_ {limits} {
        refresh_backpressure();
    }

    std::expected<void, ProtocolError> AgentSessionState::establish(const ServerHelloMessage &hello) {
        if (peer_.empty() || agent_epoch_.empty()) {
            return std::unexpected(
                session_error(ProtocolErrorCode::malformed, "agent peer and epoch must be configured"));
        }
        if (hello.peer != peer_ || hello.session.empty() || hello.session_fence == 0) {
            return std::unexpected(
                session_error(ProtocolErrorCode::stale_session, "server hello does not bind the configured peer"));
        }
        if (hello.selected_minor != initial_minor_version) {
            return std::unexpected(
                session_error(ProtocolErrorCode::unsupported_version, "server selected an unsupported minor version"));
        }
        if (hello.acknowledged_sequence >= next_sequence_) {
            return std::unexpected(
                session_error(ProtocolErrorCode::sequence_gap, "server acknowledgement exceeds the local spool"));
        }

        for (auto &record : pending_) {
            release_in_flight(record);
            record.in_flight = false;
        }
        session_ = hello.session;
        session_fence_ = hello.session_fence;
        last_server_sequence_ = 0;
        credit_ = hello.credit;

        return acknowledge(AckMessage {
            .agent_epoch = agent_epoch_,
            .acknowledged_through = hello.acknowledged_sequence,
            .credit = hello.credit,
        });
    }

    std::expected<void, ProtocolError> AgentSessionState::validate_server_message(const SessionId &session,
                                                                                  const PeerId &peer,
                                                                                  const std::uint64_t fence,
                                                                                  const std::uint64_t sequence) {
        if (!session_.has_value() || session != *session_ || peer != peer_) {
            return std::unexpected(session_error(ProtocolErrorCode::stale_session, "server message session is stale"));
        }
        if (fence != session_fence_) {
            return std::unexpected(session_error(ProtocolErrorCode::stale_fence, "server message fence is stale"));
        }
        if (sequence == 0) {
            return std::unexpected(session_error(ProtocolErrorCode::malformed, "server sequence must be nonzero"));
        }
        if (sequence > last_server_sequence_ + 1) {
            return std::unexpected(session_error(ProtocolErrorCode::sequence_gap, "server sequence contains a gap"));
        }
        return {};
    }

    std::expected<WorkAcceptance, ProtocolError> AgentSessionState::accept_work(const WorkLeaseMessage &work) {
        if (auto valid = validate_server_message(work.session, work.peer, work.session_fence, work.server_sequence);
            !valid) {
            return std::unexpected(std::move(valid.error()));
        }
        if (work.work_id.empty() || work.attempt_id.empty() || work.work_fence == 0 || work.generation == 0 ||
            work.route.empty()) {
            return std::unexpected(session_error(ProtocolErrorCode::malformed, "work identity is incomplete"));
        }
        if (work.facts.size() > 512 || work.scans.size() > 128 || (work.facts.empty() && work.scans.empty()) ||
            !request_ids_are_unique(work.facts, work.scans)) {
            return std::unexpected(
                session_error(ProtocolErrorCode::limit_exceeded, "work request count or request identity is invalid"));
        }
        for (const auto &fact : work.facts) {
            if (!fact.subject.valid() || fact.subject.peer != peer_ || fact.route.provider != work.route ||
                fact.route.fact.empty() || fact.expected_schema.empty()) {
                return std::unexpected(session_error(ProtocolErrorCode::malformed,
                                                     "fact work is not bound to its route, subject, and schema"));
            }
        }
        for (const auto &scan : work.scans) {
            if (!scan.subject.valid() || scan.subject.peer != peer_ || scan.plan.plan_id.empty() ||
                scan.space.kind.empty()) {
                return std::unexpected(session_error(ProtocolErrorCode::malformed, "scan work identity is incomplete"));
            }
        }

        const auto found = std::ranges::find_if(
            accepted_work_, [&work](const AcceptedWork &accepted) { return accepted.work_id == work.work_id; });
        if (found != accepted_work_.end()) {
            if (found->work_fence > work.work_fence) {
                return std::unexpected(session_error(ProtocolErrorCode::stale_fence, "work fence is stale"));
            }
            if (found->work_fence == work.work_fence) {
                if (found->attempt_id != work.attempt_id) {
                    return std::unexpected(
                        session_error(ProtocolErrorCode::stale_fence, "work attempt conflicts at the same fence"));
                }
                return WorkAcceptance {.disposition = WorkAcceptance::Disposition::duplicate, .requests = {}};
            }
            *found = AcceptedWork {
                .work_id = work.work_id,
                .attempt_id = work.attempt_id,
                .work_fence = work.work_fence,
                .canceled = false,
            };
            last_server_sequence_ = work.server_sequence;
            std::vector<RequestId> requests;
            requests.reserve(work.facts.size() + work.scans.size());
            for (const auto &fact : work.facts) { requests.push_back(fact.request_id); }
            for (const auto &scan : work.scans) { requests.push_back(scan.request_id); }
            return WorkAcceptance {.disposition = WorkAcceptance::Disposition::superseded,
                                   .requests = std::move(requests)};
        }

        if (work.server_sequence <= last_server_sequence_) {
            return std::unexpected(
                session_error(ProtocolErrorCode::sequence_gap, "unknown work reused an old server sequence"));
        }
        accepted_work_.push_back(AcceptedWork {
            .work_id = work.work_id,
            .attempt_id = work.attempt_id,
            .work_fence = work.work_fence,
            .canceled = false,
        });
        last_server_sequence_ = work.server_sequence;

        std::vector<RequestId> requests;
        requests.reserve(work.facts.size() + work.scans.size());
        for (const auto &fact : work.facts) { requests.push_back(fact.request_id); }
        for (const auto &scan : work.scans) { requests.push_back(scan.request_id); }
        return WorkAcceptance {.disposition = WorkAcceptance::Disposition::accepted, .requests = std::move(requests)};
    }

    std::expected<std::vector<RequestId>, ProtocolError>
    AgentSessionState::accept_cancel(const CancelWorkMessage &cancel) {
        if (auto valid =
                validate_server_message(cancel.session, cancel.peer, cancel.session_fence, cancel.server_sequence);
            !valid) {
            return std::unexpected(std::move(valid.error()));
        }
        if (cancel.work_id.empty() || cancel.attempt_id.empty() || cancel.work_fence == 0 || cancel.route.empty()) {
            return std::unexpected(session_error(ProtocolErrorCode::malformed, "cancel identity is incomplete"));
        }
        const auto found = std::ranges::find_if(
            accepted_work_, [&cancel](const AcceptedWork &accepted) { return accepted.work_id == cancel.work_id; });
        if (found == accepted_work_.end() || found->attempt_id != cancel.attempt_id) {
            return std::unexpected(session_error(ProtocolErrorCode::stale_fence, "cancel targets unknown work"));
        }
        if (found->work_fence != cancel.work_fence) {
            return std::unexpected(session_error(ProtocolErrorCode::stale_fence, "cancel work fence is stale"));
        }
        if (cancel.server_sequence < last_server_sequence_ ||
            (cancel.server_sequence == last_server_sequence_ && !found->canceled)) {
            return std::unexpected(session_error(ProtocolErrorCode::sequence_gap, "cancel reused an old sequence"));
        }
        found->canceled = true;
        last_server_sequence_ = std::max(last_server_sequence_, cancel.server_sequence);
        return cancel.requests;
    }

    std::expected<std::uint64_t, ProtocolError> AgentSessionState::enqueue(DurableAgentBody body,
                                                                           const std::size_t encoded_bytes) {
        if (encoded_bytes == 0 || encoded_bytes > limits_.maximum_bytes || pending_.size() >= limits_.maximum_records ||
            encoded_bytes > limits_.maximum_bytes - pending_bytes_) {
            backpressured_ = true;
            return std::unexpected(
                session_error(ProtocolErrorCode::backpressured, "outbound spool hard limit is reached"));
        }
        const auto sequence = next_sequence_++;
        pending_.push_back(OutboundRecord {
            .sequence = sequence,
            .body = std::move(body),
            .encoded_bytes = encoded_bytes,
            .in_flight = false,
            .transmit_attempts = 0,
        });
        pending_bytes_ += encoded_bytes;
        refresh_backpressure();
        return sequence;
    }

    std::vector<OutboundRecord> AgentSessionState::take_transmit_batch() {
        std::vector<OutboundRecord> batch;
        if (!session_.has_value()) {
            return batch;
        }

        for (auto &record : pending_) {
            if (record.in_flight) {
                continue;
            }
            const auto message_credit_exhausted = in_flight_messages_ >= credit_.messages;
            const auto byte_credit_exhausted = record.encoded_bytes > credit_.bytes - in_flight_bytes_;
            const auto work_credit_exhausted =
                is_work_result(record.body) && std::ranges::count_if(pending_, [](const OutboundRecord &candidate) {
                                                   return candidate.in_flight && is_work_result(candidate.body);
                                               }) >= credit_.work_attempts;
            const auto snapshot_credit_exhausted =
                is_snapshot_chunk(record.body) && in_flight_snapshot_chunks_ >= credit_.snapshot_chunks;
            if (message_credit_exhausted || byte_credit_exhausted || work_credit_exhausted ||
                snapshot_credit_exhausted) {
                break;
            }

            record.in_flight = true;
            ++record.transmit_attempts;
            ++in_flight_messages_;
            in_flight_bytes_ += record.encoded_bytes;
            if (is_snapshot_chunk(record.body)) {
                ++in_flight_snapshot_chunks_;
            }
            batch.push_back(record);
        }
        return batch;
    }

    void AgentSessionState::release_in_flight(const OutboundRecord &record) noexcept {
        if (!record.in_flight) {
            return;
        }
        if (in_flight_messages_ > 0) {
            --in_flight_messages_;
        }
        if (in_flight_bytes_ >= record.encoded_bytes) {
            in_flight_bytes_ -= record.encoded_bytes;
        } else {
            in_flight_bytes_ = 0;
        }
        if (is_snapshot_chunk(record.body) && in_flight_snapshot_chunks_ > 0) {
            --in_flight_snapshot_chunks_;
        }
    }

    std::expected<void, ProtocolError> AgentSessionState::acknowledge(const AckMessage &ack) {
        if (ack.agent_epoch != agent_epoch_) {
            return std::unexpected(session_error(ProtocolErrorCode::stale_session, "acknowledgement epoch is stale"));
        }
        if (ack.acknowledged_through >= next_sequence_) {
            return std::unexpected(
                session_error(ProtocolErrorCode::sequence_gap, "acknowledgement exceeds the local spool"));
        }
        if (ack.acknowledged_through < acknowledged_through_) {
            credit_ = ack.credit;
            return {};
        }

        while (!pending_.empty() && pending_.front().sequence <= ack.acknowledged_through) {
            release_in_flight(pending_.front());
            pending_bytes_ -= pending_.front().encoded_bytes;
            pending_.pop_front();
        }
        acknowledged_through_ = ack.acknowledged_through;
        credit_ = ack.credit;
        refresh_backpressure();
        return {};
    }

    std::expected<void, ProtocolError> AgentSessionState::reject(const NackMessage &nack) {
        if (nack.agent_epoch != agent_epoch_ || nack.sequence == 0 || nack.sequence >= next_sequence_) {
            return std::unexpected(session_error(ProtocolErrorCode::sequence_gap, "NACK sequence is not local"));
        }
        const auto found = std::ranges::find_if(
            pending_, [&nack](const OutboundRecord &record) { return record.sequence == nack.sequence; });
        if (found == pending_.end()) {
            const auto already_quarantined =
                std::ranges::any_of(quarantined_, [&nack](const QuarantinedRecord &record) {
                    return record.record.sequence == nack.sequence;
                });
            if (nack.sequence <= acknowledged_through_ || already_quarantined) {
                return {};
            }
            return std::unexpected(session_error(ProtocolErrorCode::sequence_gap, "NACK targets an unknown record"));
        }

        if (!nack.permanent) {
            release_in_flight(*found);
            found->in_flight = false;
            return {};
        }

        release_in_flight(*found);
        pending_bytes_ -= found->encoded_bytes;
        quarantined_.push_back(QuarantinedRecord {
            .record = std::move(*found),
            .reason = nack.reason,
            .diagnostic = nack.diagnostic,
        });
        pending_.erase(found);
        refresh_backpressure();
        return {};
    }

    void AgentSessionState::update_credit(const CreditWindow credit) noexcept { credit_ = credit; }

    bool AgentSessionState::work_canceled(const std::string_view work_id) const {
        const auto found = std::ranges::find_if(
            accepted_work_, [work_id](const AcceptedWork &work) { return work.work_id == work_id; });
        return found != accepted_work_.end() && found->canceled;
    }

    void AgentSessionState::refresh_backpressure() noexcept {
        if (limits_.high_water_bytes > limits_.maximum_bytes) {
            limits_.high_water_bytes = limits_.maximum_bytes;
        }
        if (limits_.low_water_bytes > limits_.high_water_bytes) {
            limits_.low_water_bytes = limits_.high_water_bytes;
        }
        if (backpressured_) {
            backpressured_ = pending_bytes_ > limits_.low_water_bytes;
            return;
        }
        backpressured_ = pending_bytes_ >= limits_.high_water_bytes || pending_.size() >= limits_.maximum_records;
    }

} // namespace rule_engine::python::protocol_v2
