#include "rule_engine/python/runtime/adapters.hpp"

#include "rule_engine/python/contract/subject.hpp"
#include "rule_engine/python/protocol/codec.hpp"

#include <algorithm>
#include <limits>
#include <ranges>
#include <string_view>
#include <type_traits>
#include <unordered_set>
#include <utility>

namespace rule_engine::python::runtime {
    namespace {

        [[nodiscard]] protocol_v2::ProtocolError protocol_error(const protocol_v2::ProtocolErrorCode code,
                                                                std::string message) {
            return {.code = code, .message = std::move(message)};
        }

        [[nodiscard]] PortError port_error(const PortErrorCode code, std::string message) {
            return {.code = code, .message = std::move(message)};
        }

        [[nodiscard]] StoreError store_error(const StoreErrorCode code, std::string message) {
            return {.code = code, .message = std::move(message), .retryable = false};
        }

        [[nodiscard]] std::expected<protocol_v2::DurableAgentBody, protocol_v2::ProtocolError>
        durable_body(const protocol_v2::MessageBody &body) {
            if (const auto *result = std::get_if<protocol_v2::WorkResultMessage>(&body)) {
                return protocol_v2::DurableAgentBody {*result};
            }
            if (const auto *begin = std::get_if<protocol_v2::AuthoritativeSnapshotBegin>(&body)) {
                return protocol_v2::DurableAgentBody {*begin};
            }
            if (const auto *chunk = std::get_if<protocol_v2::AuthoritativeSnapshotChunk>(&body)) {
                return protocol_v2::DurableAgentBody {*chunk};
            }
            if (const auto *commit = std::get_if<protocol_v2::AuthoritativeSnapshotCommit>(&body)) {
                return protocol_v2::DurableAgentBody {*commit};
            }
            return std::unexpected(protocol_error(protocol_v2::ProtocolErrorCode::unexpected_message,
                                                  "only durable agent messages may enter the durable sequence gate"));
        }

        [[nodiscard]] bool inner_identity_matches(const protocol_v2::DurableAgentBody &body,
                                                  const protocol_v2::ServerReceiveState &receive) {
            return std::visit(
                [&](const auto &message) {
                    using Message = std::remove_cvref_t<decltype(message)>;
                    if constexpr (std::same_as<Message, protocol_v2::WorkResultMessage>) {
                        return message.originating_session == receive.session && message.peer == receive.peer &&
                               message.originating_session_fence == receive.session_fence;
                    } else {
                        return message.session == receive.session && message.peer == receive.peer &&
                               message.session_fence == receive.session_fence;
                    }
                },
                body);
        }

        [[nodiscard]] bool same_subject(const SubjectKey &left, const SubjectKey &right) {
            const auto left_key = canonical_subject_key(left);
            return !left_key.empty() && left_key == canonical_subject_key(right);
        }

        [[nodiscard]] bool fact_request_matches(const FactRequest &left, const FactRequest &right) {
            return left.request_id == right.request_id && same_subject(left.subject, right.subject) &&
                   left.route.provider == right.route.provider && left.route.fact == right.route.fact &&
                   left.expected_schema == right.expected_schema && left.deadline_unix_ms == right.deadline_unix_ms;
        }

        [[nodiscard]] bool scan_request_matches(const ScanRequest &left, const ScanRequest &right) {
            return left.request_id == right.request_id && same_subject(left.subject, right.subject) &&
                   left.space.kind == right.space.kind && left.space.begin == right.space.begin &&
                   left.space.size == right.space.size && left.space.permissions == right.space.permissions &&
                   left.space.identity == right.space.identity && left.space.label == right.space.label &&
                   left.space.subject_generation == right.space.subject_generation &&
                   left.plan.plan_id == right.plan.plan_id && left.plan.encoded_pattern == right.plan.encoded_pattern &&
                   left.plan.maximum_bytes == right.plan.maximum_bytes &&
                   left.plan.maximum_matches == right.plan.maximum_matches &&
                   left.plan.context_bytes_before == right.plan.context_bytes_before &&
                   left.plan.context_bytes_after == right.plan.context_bytes_after &&
                   left.plan.result_mode == right.plan.result_mode && left.plan.pattern_ids == right.plan.pattern_ids &&
                   left.deadline_unix_ms == right.deadline_unix_ms;
        }

        [[nodiscard]] bool fact_status_valid(const FactResponse &response) {
            return response.status == FactTerminalStatus::value ? response.value.has_value() :
                                                                  !response.value.has_value();
        }

        [[nodiscard]] bool scan_status_valid(const ScanResponse &response) {
            if (response.truncated ||
                (response.mode != ScanResultMode::exact_complete && response.mode != ScanResultMode::existential) ||
                (response.mode == ScanResultMode::existential && response.matches.size() > 1U)) {
                return false;
            }
            return response.status == FactTerminalStatus::value || response.matches.empty();
        }

        [[nodiscard]] bool scan_pattern_ids_valid(const ScanPlan &plan, const protocol_v2::ProtocolLimits &limits) {
            if (plan.pattern_ids.empty() || plan.pattern_ids.size() > limits.maximum_scan_patterns) {
                return false;
            }
            std::unordered_set<std::string_view> unique;
            unique.reserve(plan.pattern_ids.size());
            return std::ranges::all_of(plan.pattern_ids, [&](const std::string &id) {
                return !id.empty() && id.size() <= limits.maximum_string_bytes && unique.insert(id).second;
            });
        }

        [[nodiscard]] bool scan_request_valid(const ScanRequest &request, const protocol_v2::ProtocolLimits &limits) {
            return !request.request_id.empty() && request.subject.valid() && !request.space.kind.empty() &&
                   !request.space.identity.empty() && request.space.subject_generation != 0U &&
                   !request.plan.plan_id.empty() && !request.plan.encoded_pattern.empty() &&
                   request.plan.encoded_pattern.size() <= limits.maximum_string_bytes &&
                   scan_pattern_ids_valid(request.plan, limits) && request.plan.maximum_bytes != 0U &&
                   request.plan.maximum_bytes <= limits.maximum_blob_bytes && request.plan.maximum_matches != 0U &&
                   request.plan.maximum_matches <= limits.maximum_scan_matches &&
                   request.plan.context_bytes_before <= limits.maximum_blob_bytes &&
                   request.plan.context_bytes_after <= limits.maximum_blob_bytes &&
                   (request.plan.result_mode == ScanResultMode::exact_complete ||
                    request.plan.result_mode == ScanResultMode::existential) &&
                   request.space.size <= std::numeric_limits<std::uint64_t>::max() - request.space.begin &&
                   request.deadline_unix_ms != 0U;
        }

        [[nodiscard]] bool scan_match_valid(const ScanRequest &request, const ScanMatch &match,
                                            const protocol_v2::ProtocolLimits &limits) {
            if (std::ranges::find(request.plan.pattern_ids, match.pattern_id) == request.plan.pattern_ids.end() ||
                match.scan_space_id != request.space.identity ||
                match.permission_snapshot != request.space.permissions || match.label != request.space.label ||
                match.subject_generation != request.space.subject_generation || match.offset > request.space.size ||
                match.length > request.space.size - match.offset ||
                match.offset > std::numeric_limits<std::uint64_t>::max() - request.space.begin ||
                match.absolute_address != request.space.begin + match.offset ||
                match.matched_bytes.size() != match.length ||
                match.before_bytes.size() > request.plan.context_bytes_before ||
                match.after_bytes.size() > request.plan.context_bytes_after ||
                match.before_bytes.size() > match.offset ||
                match.after_bytes.size() > request.space.size - match.offset - match.length ||
                match.matched_bytes.size() > limits.maximum_blob_bytes) {
                return false;
            }
            const auto remaining_after_match = limits.maximum_blob_bytes - match.matched_bytes.size();
            if (match.before_bytes.size() > remaining_after_match) {
                return false;
            }
            return match.after_bytes.size() <= remaining_after_match - match.before_bytes.size();
        }

        [[nodiscard]] bool resident_identity_matches(const ResidentWorkIdentity &work,
                                                     const cluster::WorkLease &lease) {
            return work.work_id == lease.work.work_id && work.node_id == lease.node_id &&
                   work.serial_domain == lease.work.serial_domain && work.pack == lease.work.pack &&
                   work.generation == lease.work.generation && work.attempt == lease.attempt &&
                   work.fence == lease.fence && work.lease_until_unix_ms == lease.lease_until_unix_ms;
        }

    } // namespace

    ProtocolV2DurableSequenceGate::ProtocolV2DurableSequenceGate(protocol_v2::ServerReceiveState receive,
                                                                 const std::uint16_t selected_minor,
                                                                 protocol_v2::ProtocolLimits limits) noexcept:
        receive_ {std::move(receive)}, selected_minor_ {selected_minor}, limits_ {std::move(limits)} {}

    std::expected<ProtocolV2DurableSequenceGate, protocol_v2::ProtocolError>
    ProtocolV2DurableSequenceGate::create(PeerId peer, SessionId session, const std::uint64_t session_fence,
                                          std::string agent_epoch, const std::uint64_t acknowledged_through,
                                          const std::uint16_t selected_minor, protocol_v2::ProtocolLimits limits) {
        if (peer.empty() || session.empty() || session_fence == 0U || agent_epoch.empty() ||
            acknowledged_through == std::numeric_limits<std::uint64_t>::max() ||
            selected_minor != protocol_v2::initial_minor_version || limits.maximum_frame_bytes == 0U ||
            limits.maximum_sequence_gap == 0U) {
            return std::unexpected(protocol_error(protocol_v2::ProtocolErrorCode::malformed,
                                                  "durable receive identity is incomplete or unsupported"));
        }
        protocol_v2::ServerReceiveState receive;
        receive.peer = std::move(peer);
        receive.session = std::move(session);
        receive.session_fence = session_fence;
        receive.agent_epoch = std::move(agent_epoch);
        receive.acknowledged_through = acknowledged_through;
        receive.maximum_gap = limits.maximum_sequence_gap;
        return ProtocolV2DurableSequenceGate {std::move(receive), selected_minor, std::move(limits)};
    }

    std::expected<protocol_v2::SequenceDisposition, protocol_v2::ProtocolError>
    ProtocolV2DurableSequenceGate::admit(protocol_v2::PeerEnvelope envelope) {
        if (envelope.protocol_major != protocol_v2::major_version || envelope.protocol_minor != selected_minor_) {
            return std::unexpected(protocol_error(protocol_v2::ProtocolErrorCode::unsupported_version,
                                                  "durable message protocol version is not negotiated"));
        }
        if (auto encoded = protocol_v2::encode_payload(envelope, limits_); !encoded) {
            return std::unexpected(std::move(encoded.error()));
        }
        auto body = durable_body(envelope.body);
        if (!body) {
            return std::unexpected(std::move(body.error()));
        }
        if (!inner_identity_matches(*body, receive_)) {
            return std::unexpected(protocol_error(protocol_v2::ProtocolErrorCode::stale_fence,
                                                  "durable body identity is not bound to the current session fence"));
        }
        auto fingerprint = protocol_v2::encode_durable_body(*body, limits_);
        if (!fingerprint) {
            return std::unexpected(std::move(fingerprint.error()));
        }
        const auto sequence = envelope.agent_sequence;
        auto disposition = receive_.observe(envelope);
        if (!disposition) {
            return std::unexpected(std::move(disposition.error()));
        }
        if (*disposition == protocol_v2::SequenceDisposition::duplicate) {
            const auto prior = fingerprints_.find(sequence);
            if (prior != fingerprints_.end() && prior->second != *fingerprint) {
                return std::unexpected(protocol_error(protocol_v2::ProtocolErrorCode::duplicate_item,
                                                      "duplicate durable sequence has different content"));
            }
            return *disposition;
        }
        fingerprints_.emplace(sequence, std::move(*fingerprint));
        staged_.emplace(sequence, std::move(*body));
        return *disposition;
    }

    std::optional<SequencedDurableAgentMessage> ProtocolV2DurableSequenceGate::next_contiguous() const {
        const auto next = receive_.acknowledged_through + 1U;
        const auto found = staged_.find(next);
        if (found == staged_.end()) {
            return std::nullopt;
        }
        return SequencedDurableAgentMessage {.sequence = next, .body = found->second};
    }

    std::expected<std::uint64_t, protocol_v2::ProtocolError>
    ProtocolV2DurableSequenceGate::mark_durable(const std::uint64_t sequence) {
        if (sequence != receive_.acknowledged_through + 1U || !staged_.contains(sequence)) {
            return std::unexpected(protocol_error(protocol_v2::ProtocolErrorCode::sequence_gap,
                                                  "only the next routed durable message may be acknowledged"));
        }
        auto acknowledged = receive_.mark_durable(sequence);
        if (!acknowledged) {
            return std::unexpected(std::move(acknowledged.error()));
        }
        staged_.erase(sequence);
        fingerprints_.erase(sequence);
        return *acknowledged;
    }

    ProtocolV2ProviderResponsePort::ProtocolV2ProviderResponsePort(protocol_v2::WorkLeaseMessage work,
                                                                   IProtocolV2CancelSink &cancel_sink,
                                                                   protocol_v2::ProtocolLimits limits) noexcept:
        work_ {std::move(work)}, cancel_sink_ {cancel_sink}, limits_ {std::move(limits)} {
        for (const auto &request : work_.facts) { expected_facts_.emplace(request.request_id.value, request); }
        for (const auto &request : work_.scans) { expected_scans_.emplace(request.request_id.value, request); }
    }

    std::expected<ProtocolV2ProviderResponsePort, protocol_v2::ProtocolError>
    ProtocolV2ProviderResponsePort::create(protocol_v2::WorkLeaseMessage work, IProtocolV2CancelSink &cancel_sink,
                                           protocol_v2::ProtocolLimits limits) {
        const protocol_v2::PeerEnvelope validation_envelope {
            .protocol_major = protocol_v2::major_version,
            .protocol_minor = protocol_v2::initial_minor_version,
            .message_id = "v",
            .session = work.session,
            .agent_epoch = "v",
            .agent_sequence = 0U,
            .acknowledged_agent_sequence = 0U,
            .body = work,
        };
        if (auto encoded = protocol_v2::encode_payload(validation_envelope, limits); !encoded) {
            return std::unexpected(std::move(encoded.error()));
        }
        if (work.session.empty() || work.peer.empty() || work.session_fence == 0U || work.work_id.empty() ||
            work.attempt_id.empty() || work.work_fence == 0U || work.generation == 0U || work.server_sequence == 0U ||
            work.route.empty() || work.facts.size() > limits.maximum_fact_requests ||
            work.scans.size() > limits.maximum_scan_requests || (work.facts.empty() && work.scans.empty())) {
            return std::unexpected(
                protocol_error(protocol_v2::ProtocolErrorCode::malformed, "provider work lease is incomplete"));
        }

        std::unordered_set<std::string> request_ids;
        request_ids.reserve(work.facts.size() + work.scans.size());
        for (const auto &request : work.facts) {
            if (request.request_id.empty() || !request_ids.insert(request.request_id.value).second ||
                !request.subject.valid() || request.subject.peer != work.peer || request.route.provider != work.route ||
                request.route.fact.empty() || request.expected_schema.empty() || request.deadline_unix_ms == 0U) {
                return std::unexpected(protocol_error(protocol_v2::ProtocolErrorCode::malformed,
                                                      "fact request is not bound to its work lease"));
            }
        }
        for (const auto &request : work.scans) {
            if (!scan_request_valid(request, limits) || request.subject.peer != work.peer ||
                !request_ids.insert(request.request_id.value).second) {
                return std::unexpected(protocol_error(protocol_v2::ProtocolErrorCode::malformed,
                                                      "scan request is not bound to its work lease"));
            }
        }
        return ProtocolV2ProviderResponsePort {std::move(work), cancel_sink, std::move(limits)};
    }

    std::expected<void, protocol_v2::ProtocolError>
    ProtocolV2ProviderResponsePort::admit(const protocol_v2::WorkResultMessage &result) {
        if (admitted_) {
            return std::unexpected(protocol_error(protocol_v2::ProtocolErrorCode::duplicate_item,
                                                  "work already has a terminal provider result"));
        }
        if (result.originating_session != work_.session || result.peer != work_.peer ||
            result.originating_session_fence != work_.session_fence || result.work_id != work_.work_id ||
            result.attempt_id != work_.attempt_id || result.work_fence != work_.work_fence ||
            result.generation != work_.generation) {
            return std::unexpected(protocol_error(protocol_v2::ProtocolErrorCode::stale_fence,
                                                  "work result identity does not match the active lease"));
        }
        if (result.facts.size() != expected_facts_.size() || result.scans.size() != expected_scans_.size()) {
            return std::unexpected(protocol_error(protocol_v2::ProtocolErrorCode::provider_violation,
                                                  "work result must contain one terminal response per request"));
        }
        if (auto encoded = protocol_v2::encode_durable_body(protocol_v2::DurableAgentBody {result}, limits_);
            !encoded) {
            return std::unexpected(std::move(encoded.error()));
        }

        std::map<std::string, FactResponse, std::less<>> facts;
        for (const auto &response : result.facts) {
            const auto expected = expected_facts_.find(response.request_id.value);
            if (expected == expected_facts_.end() || !same_subject(response.subject, expected->second.subject) ||
                !fact_status_valid(response) || !facts.emplace(response.request_id.value, response).second) {
                return std::unexpected(protocol_error(protocol_v2::ProtocolErrorCode::provider_violation,
                                                      "fact response request, subject, or terminal value is invalid"));
            }
        }

        std::map<std::string, ScanResponse, std::less<>> scans;
        for (auto response : result.scans) {
            const auto expected = expected_scans_.find(response.request_id.value);
            if (expected == expected_scans_.end() || !same_subject(response.subject, expected->second.subject) ||
                !scan_status_valid(response) || response.mode != expected->second.plan.result_mode ||
                response.matches.size() > expected->second.plan.maximum_matches ||
                !std::ranges::all_of(
                    response.matches,
                    [&](const ScanMatch &match) { return scan_match_valid(expected->second, match, limits_); }) ||
                scans.contains(response.request_id.value)) {
                return std::unexpected(protocol_error(protocol_v2::ProtocolErrorCode::provider_violation,
                                                      "scan response is outside its authenticated request bounds"));
            }
            std::ranges::sort(response.matches, [](const ScanMatch &left, const ScanMatch &right) {
                if (left.offset != right.offset) {
                    return left.offset < right.offset;
                }
                if (left.pattern_id != right.pattern_id) {
                    return left.pattern_id < right.pattern_id;
                }
                return left.length < right.length;
            });
            scans.emplace(response.request_id.value, std::move(response));
        }

        facts_ = std::move(facts);
        scans_ = std::move(scans);
        admitted_ = true;
        return {};
    }

    std::expected<std::vector<FactResponse>, PortError>
    ProtocolV2ProviderResponsePort::resolve_facts(const std::span<const FactRequest> requests) noexcept {
        std::vector<FactResponse> responses;
        responses.reserve(requests.size());
        for (const auto &request : requests) {
            const auto expected = expected_facts_.find(request.request_id.value);
            if (expected == expected_facts_.end() || !fact_request_matches(request, expected->second)) {
                return std::unexpected(
                    port_error(PortErrorCode::invalid_request, "fact request does not match the admitted work lease"));
            }
            if (canceled_.contains(request.request_id.value)) {
                return std::unexpected(port_error(PortErrorCode::canceled, "fact request was canceled"));
            }
            const auto response = facts_.find(request.request_id.value);
            if (!admitted_ || response == facts_.end()) {
                return std::unexpected(
                    port_error(PortErrorCode::unavailable, "terminal fact response has not arrived"));
            }
            responses.push_back(response->second);
        }
        return responses;
    }

    std::expected<std::vector<ScanResponse>, PortError>
    ProtocolV2ProviderResponsePort::resolve_scans(const std::span<const ScanRequest> requests) noexcept {
        std::vector<ScanResponse> responses;
        responses.reserve(requests.size());
        for (const auto &request : requests) {
            const auto expected = expected_scans_.find(request.request_id.value);
            if (expected == expected_scans_.end() || !scan_request_matches(request, expected->second)) {
                return std::unexpected(
                    port_error(PortErrorCode::invalid_request, "scan request does not match the admitted work lease"));
            }
            if (canceled_.contains(request.request_id.value)) {
                return std::unexpected(port_error(PortErrorCode::canceled, "scan request was canceled"));
            }
            const auto response = scans_.find(request.request_id.value);
            if (!admitted_ || response == scans_.end()) {
                return std::unexpected(
                    port_error(PortErrorCode::unavailable, "terminal scan response has not arrived"));
            }
            responses.push_back(response->second);
        }
        return responses;
    }

    void ProtocolV2ProviderResponsePort::cancel(const std::span<const RequestId> requests) noexcept {
        std::vector<RequestId> newly_canceled;
        newly_canceled.reserve(requests.size());
        for (const auto &request : requests) {
            if ((!expected_facts_.contains(request.value) && !expected_scans_.contains(request.value)) ||
                !canceled_.insert(request.value).second) {
                continue;
            }
            newly_canceled.push_back(request);
        }
        if (!newly_canceled.empty()) {
            cancel_sink_.cancel(work_, newly_canceled);
        }
    }

    std::expected<TransactionReceipt, StoreError>
    ClusterWorkTransactionPort::commit(const ResidentWorkIdentity &work,
                                       const RuntimeTransaction &transaction) noexcept {
        if (!resident_identity_matches(work, lease_)) {
            return std::unexpected(
                store_error(StoreErrorCode::stale_fence, "resident work generation, attempt, or lease fence is stale"));
        }
        if (transaction.cursor.consumer != work.serial_domain || transaction.fence_token != work.fence) {
            return std::unexpected(store_error(StoreErrorCode::stale_fence,
                                               "runtime transaction does not match the claimed cluster fence"));
        }
        if (transaction.input.id != lease_.work.event) {
            return std::unexpected(store_error(StoreErrorCode::constraint_violation,
                                               "runtime transaction input does not match the claimed work event"));
        }
        return coordinator_.commit(lease_, transaction, clock_.now_unix_ms());
    }

} // namespace rule_engine::python::runtime
