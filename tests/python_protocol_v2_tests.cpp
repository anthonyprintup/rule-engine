#include "rule_engine/python/protocol.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {
    using namespace rule_engine::python;
    using namespace rule_engine::python::protocol_v2;

    template<typename Type>
    concept HasPredicate = requires(Type value) { value.predicate; };

    template<typename Type>
    concept HasVerdict = requires(Type value) { value.verdict; };

    static_assert(!HasPredicate<WorkLeaseMessage>);
    static_assert(!HasVerdict<WorkResultMessage>);
    static_assert(!HasPredicate<IWindowsAgentProvider>);

    SubjectKey process_subject(const std::string_view peer = "peer-1", const std::uint64_t pid = 420,
                               const std::uint64_t creation = 123'456) {
        return SubjectKey {
            .peer = PeerId {std::string {peer}},
            .descriptor = SchemaId {"process/v1"},
            .identity = {{.field_id = 1, .value = pid}, {.field_id = 2, .value = creation}},
            .parent = {},
        };
    }

    SubjectKey region_subject() {
        return SubjectKey {
            .peer = PeerId {"peer-1"},
            .descriptor = SchemaId {"memory-region/v1"},
            .identity = {{.field_id = 1, .value = std::uint64_t {0x1000}},
                         {.field_id = 2, .value = std::uint64_t {0x2000}}},
            .parent = std::make_shared<const SubjectKey>(process_subject()),
        };
    }

    FactRequest fact_request(const std::string_view id = "fact-1") {
        return FactRequest {
            .request_id = RequestId {std::string {id}},
            .subject = region_subject(),
            .route = FactRoute {.provider = "windows.memory", .fact = "region.protection"},
            .expected_schema = SchemaId {"protection/v1"},
            .expected_schema_hash = "sha256:protection-v1",
            .deadline_unix_ms = 5'000,
        };
    }

    ScanRequest scan_request(const std::string_view id = "scan-1") {
        return ScanRequest {
            .request_id = RequestId {std::string {id}},
            .subject = region_subject(),
            .space =
                ScanSpace {.kind = "memory",
                           .begin = 0x2000,
                           .size = 0x1000,
                           .permissions = 5,
                           .identity = "memory:allocation-2000",
                           .label = {.classification = Classification::sensitive, .categories = {"process-memory"}},
                           .subject_generation = 9},
            .plan = ScanPlan {.plan_id = "pattern-1",
                              .encoded_pattern = "48 8b ??",
                              .maximum_bytes = 0x1000,
                              .maximum_matches = 16,
                              .context_bytes_before = 2,
                              .context_bytes_after = 2,
                              .result_mode = ScanResultMode::exact_complete,
                              .pattern_ids = {"pattern-1", "pattern-2"}},
            .deadline_unix_ms = 5'000,
        };
    }

    WorkLeaseMessage work_lease(const std::uint64_t server_sequence = 1, const std::uint64_t session_fence = 7,
                                const std::uint64_t work_fence = 11) {
        return WorkLeaseMessage {
            .session = SessionId {"session-1"},
            .peer = PeerId {"peer-1"},
            .session_fence = session_fence,
            .work_id = "work-1",
            .attempt_id = "attempt-1",
            .work_fence = work_fence,
            .generation = 3,
            .server_sequence = server_sequence,
            .route = "windows.memory",
            .facts = {fact_request()},
            .scans = {scan_request()},
        };
    }

    FactValue nested_fact_value() {
        return make_fact(FactRecord {
            .schema = SchemaId {"protection/v1"},
            .fields =
                {
                    {.field_id = 1, .value = make_fact(IntegerValue {"42"})},
                    {.field_id = 2,
                     .value = make_fact(FactList {
                         .items = {make_fact(UnicodeValue {"read"}), make_fact(BytesValue {{std::byte {0xaa}}})},
                     })},
                },
        });
    }

    WorkResultMessage work_result() {
        return WorkResultMessage {
            .originating_session = SessionId {"session-1"},
            .peer = PeerId {"peer-1"},
            .originating_session_fence = 7,
            .work_id = "work-1",
            .attempt_id = "attempt-1",
            .work_fence = 11,
            .generation = 3,
            .facts = {FactResponse {
                .request_id = RequestId {"fact-1"},
                .subject = region_subject(),
                .status = FactTerminalStatus::value,
                .value = nested_fact_value(),
                .returned_schema =
                    SchemaIdentity {.id = SchemaId {"protection/v1"}, .canonical_hash = "sha256:protection-v1"},
                .diagnostic = std::nullopt,
            }},
            .scans = {ScanResponse {
                .request_id = RequestId {"scan-1"},
                .subject = region_subject(),
                .status = FactTerminalStatus::value,
                .matches = {{.offset = 8,
                             .length = 3,
                             .pattern_id = "pattern-1",
                             .scan_space_id = "memory:allocation-2000",
                             .absolute_address = 0x2008,
                             .permission_snapshot = 5,
                             .matched_bytes = {std::byte {0x48}, std::byte {0x8b}, std::byte {0x10}},
                             .before_bytes = {std::byte {0x90}, std::byte {0x90}},
                             .after_bytes = {std::byte {0x90}},
                             .label = {.classification = Classification::sensitive, .categories = {"process-memory"}},
                             .subject_generation = 9},
                            {.offset = 32,
                             .length = 3,
                             .pattern_id = "pattern-2",
                             .scan_space_id = "memory:allocation-2000",
                             .absolute_address = 0x2020,
                             .permission_snapshot = 5,
                             .matched_bytes = {std::byte {0x48}, std::byte {0x8b}, std::byte {0x20}},
                             .before_bytes = {std::byte {0x90}},
                             .after_bytes = {std::byte {0x90}, std::byte {0x90}},
                             .label = {.classification = Classification::sensitive, .categories = {"process-memory"}},
                             .subject_generation = 9}},
                .truncated = false,
                .diagnostic = std::nullopt,
                .mode = ScanResultMode::exact_complete,
            }},
        };
    }

    ServerHelloMessage server_hello(const std::uint64_t acknowledged = 0) {
        return ServerHelloMessage {
            .selected_minor = 0,
            .session = SessionId {"session-1"},
            .peer = PeerId {"peer-1"},
            .session_fence = 7,
            .acknowledged_sequence = acknowledged,
            .schemas = {{.schema = SchemaId {"protection/v1"}, .major = 1, .canonical_hash = "sha256:schema"}},
            .capabilities = {{.capability = CapabilityId {"windows.memory"},
                              .version = 1,
                              .request_schema = SchemaId {"request/v1"},
                              .response_schema = SchemaId {"response/v1"}}},
            .credit = CreditWindow {.bytes = 1'000'000, .messages = 16, .work_attempts = 8, .snapshot_chunks = 4},
            .heartbeat_interval_ms = 5'000,
        };
    }

    PeerEnvelope envelope(MessageBody body, const std::uint64_t agent_sequence = 0) {
        const auto kind = message_kind(body);
        const auto durable = kind == MessageKind::work_result || kind == MessageKind::snapshot_begin ||
                             kind == MessageKind::snapshot_chunk || kind == MessageKind::snapshot_commit;
        PeerEnvelope result {
            .protocol_major = 2,
            .protocol_minor = 0,
            .message_id = "message-1",
            .session = SessionId {"session-1"},
            .agent_epoch = "epoch-1",
            .agent_sequence = durable ? agent_sequence : 0,
            .acknowledged_agent_sequence = 0,
            .body = std::move(body),
        };
        return result;
    }

    TEST_CASE("protocol v2 round-trips hello work facts scans and recursive subjects") {
        AgentHelloMessage agent {
            .minimum_minor = 0,
            .maximum_minor = 0,
            .agent_version = "agent/1",
            .agent_epoch = "epoch-1",
            .next_sequence = 1,
            .schemas = {{.schema = SchemaId {"protection/v1"}, .major = 1, .canonical_hash = "sha256:schema"}},
            .capabilities = {{.capability = CapabilityId {"windows.memory"},
                              .version = 1,
                              .request_schema = SchemaId {"request/v1"},
                              .response_schema = SchemaId {"response/v1"}}},
            .receive_limit = {.bytes = 1024, .messages = 4, .work_attempts = 2, .snapshot_chunks = 2},
        };
        auto agent_envelope = envelope(agent);
        agent_envelope.session.reset();
        const auto agent_frame = encode_frame(agent_envelope);
        REQUIRE(agent_frame.has_value());
        const auto decoded_agent = decode_frame(*agent_frame);
        REQUIRE(decoded_agent.has_value());
        REQUIRE(std::get<AgentHelloMessage>(decoded_agent->envelope.body).agent_epoch == "epoch-1");

        const auto server_frame = encode_frame(envelope(server_hello()));
        REQUIRE(server_frame.has_value());
        REQUIRE(std::get<ServerHelloMessage>(decode_frame(*server_frame)->envelope.body).session.value == "session-1");

        const auto lease_frame = encode_frame(envelope(work_lease()));
        REQUIRE(lease_frame.has_value());
        const auto decoded_lease = decode_frame(*lease_frame);
        REQUIRE(decoded_lease.has_value());
        const auto &lease = std::get<WorkLeaseMessage>(decoded_lease->envelope.body);
        REQUIRE(lease.route == "windows.memory");
        REQUIRE(lease.facts.front().expected_schema_hash == "sha256:protection-v1");
        REQUIRE(canonical_subject_key(lease.facts.front().subject) == canonical_subject_key(region_subject()));
        REQUIRE(lease.scans.front().plan.encoded_pattern == "48 8b ??");
        REQUIRE(lease.scans.front().plan.pattern_ids ==
                std::vector {std::string {"pattern-1"}, std::string {"pattern-2"}});

        const auto result_frame = encode_frame(envelope(work_result(), 1));
        REQUIRE(result_frame.has_value());
        const auto decoded_result = decode_frame(*result_frame);
        REQUIRE(decoded_result.has_value());
        const auto &result = std::get<WorkResultMessage>(decoded_result->envelope.body);
        REQUIRE(result.facts.size() == 1);
        REQUIRE(result.facts.front().returned_schema ==
                std::optional<SchemaIdentity> {
                    SchemaIdentity {.id = SchemaId {"protection/v1"}, .canonical_hash = "sha256:protection-v1"}});
        REQUIRE(result.scans.front().matches.size() == 2);
        REQUIRE(result.scans.front().mode == ScanResultMode::exact_complete);
        REQUIRE(result.scans.front().matches.front().pattern_id == "pattern-1");
        REQUIRE(result.scans.front().matches.back().pattern_id == "pattern-2");
        REQUIRE(result.scans.front().matches.front().scan_space_id == "memory:allocation-2000");
        REQUIRE(result.scans.front().matches.front().absolute_address == 0x2008);
        REQUIRE(result.scans.front().matches.front().permission_snapshot == 5);
        REQUIRE(result.scans.front().matches.front().matched_bytes ==
                std::vector {std::byte {0x48}, std::byte {0x8b}, std::byte {0x10}});
        REQUIRE(result.scans.front().matches.front().before_bytes.size() == 2);
        REQUIRE(result.scans.front().matches.front().after_bytes.size() == 1);
        REQUIRE(result.scans.front().matches.front().label.classification == Classification::sensitive);
        REQUIRE(result.scans.front().matches.front().subject_generation == 9);
        REQUIRE(std::holds_alternative<FactRecord>(result.facts.front().value->node->data));
        REQUIRE(decoded_result->bytes_consumed == result_frame->size());
    }

    TEST_CASE("protocol v2 rejects malformed oversized duplicate and deep input before domain use") {
        const auto valid = encode_frame(envelope(work_lease()));
        REQUIRE(valid.has_value());

        auto truncated = *valid;
        truncated.pop_back();
        REQUIRE_FALSE(decode_frame(truncated).has_value());
        REQUIRE(decode_frame(truncated).error().code == ProtocolErrorCode::truncated);

        ProtocolLimits tiny;
        tiny.maximum_frame_bytes = 32;
        REQUIRE_FALSE(decode_frame(*valid, tiny).has_value());
        REQUIRE(decode_frame(*valid, tiny).error().code == ProtocolErrorCode::limit_exceeded);

        auto payload = encode_payload(envelope(work_lease()));
        REQUIRE(payload.has_value());
        payload->push_back(std::byte {0x08});
        payload->push_back(std::byte {0x02});
        const auto duplicate = decode_payload(*payload);
        REQUIRE_FALSE(duplicate.has_value());
        REQUIRE(duplicate.error().code == ProtocolErrorCode::duplicate_field);

        auto deep = process_subject();
        for (std::uint64_t index = 0; index < 5; ++index) {
            deep = SubjectKey {
                .peer = PeerId {"peer-1"},
                .descriptor = SchemaId {"nested/v1"},
                .identity = {{.field_id = 1, .value = index + 1}},
                .parent = std::make_shared<const SubjectKey>(std::move(deep)),
            };
        }
        auto request = work_lease();
        request.facts.front().subject = deep;
        ProtocolLimits shallow;
        shallow.maximum_subject_depth = 2;
        const auto deep_result = encode_frame(envelope(request), shallow);
        REQUIRE_FALSE(deep_result.has_value());
        REQUIRE(deep_result.error().code == ProtocolErrorCode::limit_exceeded);

        auto too_many = work_lease();
        too_many.facts.push_back(fact_request("fact-2"));
        ProtocolLimits one_fact;
        one_fact.maximum_fact_requests = 1;
        REQUIRE_FALSE(encode_frame(envelope(too_many), one_fact).has_value());

        auto truncated_exact = work_result();
        truncated_exact.scans.front().truncated = true;
        REQUIRE_FALSE(encode_frame(envelope(truncated_exact, 1)).has_value());

        auto missing_pattern_ids = work_lease();
        missing_pattern_ids.scans.front().plan.pattern_ids.clear();
        const auto missing_pattern_ids_result = encode_frame(envelope(missing_pattern_ids));
        REQUIRE_FALSE(missing_pattern_ids_result.has_value());
        REQUIRE(missing_pattern_ids_result.error().code == ProtocolErrorCode::malformed);

        auto empty_pattern_id = work_lease();
        empty_pattern_id.scans.front().plan.pattern_ids = {""};
        const auto empty_pattern_id_result = encode_frame(envelope(empty_pattern_id));
        REQUIRE_FALSE(empty_pattern_id_result.has_value());
        REQUIRE(empty_pattern_id_result.error().code == ProtocolErrorCode::malformed);

        auto duplicate_pattern_ids = work_lease();
        duplicate_pattern_ids.scans.front().plan.pattern_ids = {"pattern-1", "pattern-1"};
        const auto duplicate_pattern_ids_result = encode_frame(envelope(duplicate_pattern_ids));
        REQUIRE_FALSE(duplicate_pattern_ids_result.has_value());
        REQUIRE(duplicate_pattern_ids_result.error().code == ProtocolErrorCode::duplicate_item);

        ProtocolLimits one_pattern;
        one_pattern.maximum_scan_patterns = 1;
        const auto too_many_pattern_ids = encode_frame(envelope(work_lease()), one_pattern);
        REQUIRE_FALSE(too_many_pattern_ids.has_value());
        REQUIRE(too_many_pattern_ids.error().code == ProtocolErrorCode::limit_exceeded);

        auto zero_length = work_result();
        zero_length.scans.front().matches.front().length = 0;
        zero_length.scans.front().matches.front().matched_bytes.clear();
        const auto zero_length_frame = encode_frame(envelope(zero_length, 1));
        REQUIRE(zero_length_frame.has_value());
        const auto zero_length_round_trip = decode_frame(*zero_length_frame);
        REQUIRE(zero_length_round_trip.has_value());
        const auto &zero_length_result = std::get<WorkResultMessage>(zero_length_round_trip->envelope.body);
        REQUIRE(zero_length_result.scans.front().matches.front().length == 0);
        REQUIRE(zero_length_result.scans.front().matches.front().matched_bytes.empty());

        auto inconsistent_match_length = work_result();
        inconsistent_match_length.scans.front().matches.front().length = 2;
        REQUIRE_FALSE(encode_frame(envelope(inconsistent_match_length, 1)).has_value());

        auto missing_request_hash = work_lease();
        missing_request_hash.facts.front().expected_schema_hash.clear();
        REQUIRE_FALSE(encode_frame(envelope(missing_request_hash)).has_value());

        auto missing_returned_schema = work_result();
        missing_returned_schema.facts.front().returned_schema.reset();
        REQUIRE_FALSE(encode_frame(envelope(missing_returned_schema, 1)).has_value());

        auto value_with_diagnostic = work_result();
        value_with_diagnostic.facts.front().diagnostic = Diagnostic {.code = "test.invalid",
                                                                     .severity = DiagnosticSeverity::error,
                                                                     .message = "mixed terminal",
                                                                     .span = std::nullopt,
                                                                     .related = {}};
        REQUIRE_FALSE(encode_frame(envelope(value_with_diagnostic, 1)).has_value());

        auto non_value_with_schema = work_result();
        non_value_with_schema.facts.front().status = FactTerminalStatus::unavailable;
        non_value_with_schema.facts.front().value.reset();
        REQUIRE_FALSE(encode_frame(envelope(non_value_with_schema, 1)).has_value());
    }

    TEST_CASE("transport authentication requires TLS 1.3 mutual identity and operator mapping") {
        struct FakeTrust final: ITrustPolicy {
            mutable std::size_t calls {};
            [[nodiscard]] std::expected<AuthenticatedPeer, ProtocolError>
            authenticate(const TlsPeerIdentity &identity) const noexcept override {
                ++calls;
                if (identity.canonical_uri_san != "urn:rule-engine:peer-1") {
                    return std::unexpected(ProtocolError {
                        .code = ProtocolErrorCode::unauthenticated, .message = "not enrolled", .byte_offset = 0});
                }
                return AuthenticatedPeer {.tenant = TenantId {"tenant-1"}, .peer = PeerId {"peer-1"}};
            }
        } trust;

        TlsPeerIdentity identity {.tls_major = 1,
                                  .tls_minor = 2,
                                  .mutual_authentication = true,
                                  .certificate_chain_verified = true,
                                  .client_auth_eku = true,
                                  .revoked = false,
                                  .canonical_uri_san = "urn:rule-engine:peer-1",
                                  .certificate_sha256 = "sha256:certificate"};
        REQUIRE_FALSE(authenticate_transport(identity, trust).has_value());
        REQUIRE(trust.calls == 0);
        identity.tls_minor = 3;
        const auto authenticated = authenticate_transport(identity, trust);
        REQUIRE(authenticated.has_value());
        REQUIRE(authenticated->peer.value == "peer-1");
        REQUIRE(trust.calls == 1);
        identity.revoked = true;
        REQUIRE_FALSE(authenticate_transport(identity, trust).has_value());
        REQUIRE(trust.calls == 1);
    }

    TEST_CASE("session sequence fences cancellation retransmit and credits are explicit") {
        ServerReceiveState receive;
        receive.peer = PeerId {"peer-1"};
        receive.session = SessionId {"session-1"};
        receive.session_fence = 7;
        receive.agent_epoch = "epoch-1";
        receive.acknowledged_through = 0;
        receive.maximum_gap = 4;
        auto first = envelope(work_result(), 1);
        REQUIRE(receive.observe(first) == SequenceDisposition::accepted);
        REQUIRE(receive.observe(first) == SequenceDisposition::duplicate);
        auto third = envelope(work_result(), 3);
        REQUIRE(receive.observe(third) == SequenceDisposition::accepted_out_of_order);
        REQUIRE(receive.mark_durable(3) == 0);
        REQUIRE(receive.mark_durable(1) == 1);
        auto second = envelope(work_result(), 2);
        REQUIRE(receive.observe(second) == SequenceDisposition::accepted);
        REQUIRE(receive.mark_durable(2) == 3);

        AgentSessionState agent {
            PeerId {"peer-1"}, "epoch-1",
            AgentSpoolLimits {
                .maximum_records = 4, .maximum_bytes = 400, .high_water_bytes = 200, .low_water_bytes = 120}};
        auto hello = server_hello();
        hello.credit = {.bytes = 200, .messages = 1, .work_attempts = 1, .snapshot_chunks = 1};
        REQUIRE(agent.establish(hello).has_value());
        REQUIRE(agent.accept_work(work_lease()).has_value());
        REQUIRE(agent.accept_work(work_lease())->disposition == WorkAcceptance::Disposition::duplicate);

        auto stale = work_lease(2, 6, 12);
        REQUIRE_FALSE(agent.accept_work(stale).has_value());
        REQUIRE(agent.accept_work(stale).error().code == ProtocolErrorCode::stale_fence);

        CancelWorkMessage cancel {.session = SessionId {"session-1"},
                                  .peer = PeerId {"peer-1"},
                                  .session_fence = 7,
                                  .work_id = "work-1",
                                  .attempt_id = "attempt-1",
                                  .work_fence = 11,
                                  .server_sequence = 2,
                                  .route = "windows.memory",
                                  .requests = {RequestId {"fact-1"}}};
        REQUIRE(agent.accept_cancel(cancel).has_value());
        REQUIRE(agent.work_canceled("work-1"));

        REQUIRE(agent.enqueue(work_result(), 120) == 1);
        REQUIRE(agent.enqueue(work_result(), 120) == 2);
        REQUIRE(agent.backpressured());
        auto batch = agent.take_transmit_batch();
        REQUIRE(batch.size() == 1);
        REQUIRE(batch.front().sequence == 1);
        agent.disconnect();
        REQUIRE_FALSE(agent.established());
        const auto disconnected_work = agent.accept_work(work_lease());
        REQUIRE_FALSE(disconnected_work.has_value());
        REQUIRE(disconnected_work.error().code == ProtocolErrorCode::stale_session);
        REQUIRE(agent.establish(hello).has_value());
        batch = agent.take_transmit_batch();
        REQUIRE(batch.size() == 1);
        REQUIRE(batch.front().sequence == 1);
        REQUIRE(batch.front().transmit_attempts == 2);
        REQUIRE(
            agent.acknowledge(AckMessage {.agent_epoch = "epoch-1", .acknowledged_through = 1, .credit = hello.credit})
                .has_value());
        REQUIRE(agent.pending_records() == 1);
        REQUIRE_FALSE(agent.backpressured());
        REQUIRE(agent
                    .reject(NackMessage {.agent_epoch = "epoch-1",
                                         .sequence = 2,
                                         .reason = ProtocolErrorCode::schema_mismatch,
                                         .permanent = true,
                                         .diagnostic = "schema rejected"})
                    .has_value());
        REQUIRE(agent.pending_records() == 0);
        REQUIRE(agent.quarantined().size() == 1);
    }

    TEST_CASE("authoritative snapshots publish only complete current generations") {
        const auto first_subject = process_subject("peer-1", 10, 100);
        const auto second_subject = process_subject("peer-1", 20, 200);
        const std::vector first_inventory {first_subject, second_subject};
        const auto first_digest = authoritative_snapshot_digest(first_inventory);
        REQUIRE(first_digest.has_value());

        AuthoritativeSnapshotAssembler assembler {PeerId {"peer-1"}, SessionId {"session-1"}, 7,
                                                  SchemaId {"process/v1"}, std::nullopt};
        AuthoritativeSnapshotBegin begin {.session = SessionId {"session-1"},
                                          .peer = PeerId {"peer-1"},
                                          .session_fence = 7,
                                          .snapshot_id = "snapshot-1",
                                          .parent = std::nullopt,
                                          .subject_schema = SchemaId {"process/v1"},
                                          .generation = 1,
                                          .expected_count = 2,
                                          .expected_digest = *first_digest};
        REQUIRE(assembler.begin(begin).has_value());
        REQUIRE(assembler
                    .append(AuthoritativeSnapshotChunk {.session = SessionId {"session-1"},
                                                        .peer = PeerId {"peer-1"},
                                                        .session_fence = 7,
                                                        .snapshot_id = "snapshot-1",
                                                        .generation = 1,
                                                        .chunk_index = 0,
                                                        .subjects = {first_subject}})
                    .has_value());
        REQUIRE(assembler
                    .append(AuthoritativeSnapshotChunk {.session = SessionId {"session-1"},
                                                        .peer = PeerId {"peer-1"},
                                                        .session_fence = 7,
                                                        .snapshot_id = "snapshot-1",
                                                        .generation = 1,
                                                        .chunk_index = 1,
                                                        .subjects = {second_subject}})
                    .has_value());
        const auto first_commit = assembler.commit(AuthoritativeSnapshotCommit {.session = SessionId {"session-1"},
                                                                                .peer = PeerId {"peer-1"},
                                                                                .session_fence = 7,
                                                                                .snapshot_id = "snapshot-1",
                                                                                .generation = 1,
                                                                                .item_count = 2,
                                                                                .canonical_digest = *first_digest});
        REQUIRE(first_commit.has_value());
        REQUIRE(first_commit->added.size() == 2);
        REQUIRE(assembler.visible().size() == 2);

        begin.snapshot_id = "partial";
        begin.generation = 2;
        REQUIRE(assembler.begin(begin).has_value());
        REQUIRE(assembler
                    .append(AuthoritativeSnapshotChunk {.session = SessionId {"session-1"},
                                                        .peer = PeerId {"peer-1"},
                                                        .session_fence = 7,
                                                        .snapshot_id = "partial",
                                                        .generation = 2,
                                                        .chunk_index = 1,
                                                        .subjects = {first_subject}})
                    .error()
                    .code == ProtocolErrorCode::sequence_gap);
        REQUIRE_FALSE(assembler.staging());
        REQUIRE(assembler.visible().size() == 2);

        begin.snapshot_id = "bad-digest";
        begin.expected_count = 1;
        begin.expected_digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        REQUIRE(assembler.begin(begin).has_value());
        REQUIRE(assembler
                    .append(AuthoritativeSnapshotChunk {.session = SessionId {"session-1"},
                                                        .peer = PeerId {"peer-1"},
                                                        .session_fence = 7,
                                                        .snapshot_id = "bad-digest",
                                                        .generation = 2,
                                                        .chunk_index = 0,
                                                        .subjects = {first_subject}})
                    .has_value());
        const auto bad = assembler.commit(AuthoritativeSnapshotCommit {
            .session = SessionId {"session-1"},
            .peer = PeerId {"peer-1"},
            .session_fence = 7,
            .snapshot_id = "bad-digest",
            .generation = 2,
            .item_count = 1,
            .canonical_digest = begin.expected_digest,
        });
        REQUIRE_FALSE(bad.has_value());
        REQUIRE(bad.error().code == ProtocolErrorCode::digest_mismatch);
        REQUIRE(assembler.visible().size() == 2);

        const std::vector second_inventory {second_subject};
        const auto second_digest = authoritative_snapshot_digest(second_inventory);
        begin.snapshot_id = "snapshot-2";
        begin.expected_digest = *second_digest;
        REQUIRE(assembler.begin(begin).has_value());
        REQUIRE(assembler
                    .append(AuthoritativeSnapshotChunk {.session = SessionId {"session-1"},
                                                        .peer = PeerId {"peer-1"},
                                                        .session_fence = 7,
                                                        .snapshot_id = "snapshot-2",
                                                        .generation = 2,
                                                        .chunk_index = 0,
                                                        .subjects = second_inventory})
                    .has_value());
        const auto second_commit = assembler.commit(AuthoritativeSnapshotCommit {.session = SessionId {"session-1"},
                                                                                 .peer = PeerId {"peer-1"},
                                                                                 .session_fence = 7,
                                                                                 .snapshot_id = "snapshot-2",
                                                                                 .generation = 2,
                                                                                 .item_count = 1,
                                                                                 .canonical_digest = *second_digest});
        REQUIRE(second_commit.has_value());
        REQUIRE(second_commit->removed.size() == 1);
        REQUIRE(canonical_subject_key(second_commit->removed.front()) == canonical_subject_key(first_subject));

        const auto stale = assembler.begin(begin);
        REQUIRE_FALSE(stale.has_value());
        REQUIRE(stale.error().code == ProtocolErrorCode::stale_generation);
    }

    struct FakeProvider final: IWindowsAgentProvider {
        enum struct ScanBehavior : std::uint8_t { normal, unknown_pattern, zero_length, out_of_bounds };

        std::vector<FactRequest> facts;
        std::vector<ScanRequest> scans;
        std::vector<RequestId> canceled;
        ScanBehavior scan_behavior {ScanBehavior::normal};
        std::optional<SchemaIdentity> fact_schema_override;

        [[nodiscard]] std::expected<std::vector<FactResponse>, ProviderDispatchError>
        resolve_facts(const std::span<const FactRequest> requests) noexcept override {
            facts.assign(requests.begin(), requests.end());
            std::vector<FactResponse> result;
            for (const auto &request : requests) {
                result.push_back(
                    FactResponse {.request_id = request.request_id,
                                  .subject = request.subject,
                                  .status = FactTerminalStatus::value,
                                  .value = nested_fact_value(),
                                  .returned_schema = fact_schema_override.value_or(SchemaIdentity {
                                      .id = request.expected_schema, .canonical_hash = request.expected_schema_hash}),
                                  .diagnostic = std::nullopt});
            }
            return result;
        }

        [[nodiscard]] std::expected<std::vector<ScanResponse>, ProviderDispatchError>
        resolve_scans(const std::span<const ScanRequest> requests) noexcept override {
            scans.assign(requests.begin(), requests.end());
            std::vector<ScanResponse> result;
            for (const auto &request : requests) {
                std::vector<ScanMatch> matches;
                matches.reserve(request.plan.pattern_ids.size());
                for (std::size_t index = 0; index < request.plan.pattern_ids.size(); ++index) {
                    matches.push_back(ScanMatch {
                        .offset = 16 + index * 16,
                        .length = 3,
                        .pattern_id = request.plan.pattern_ids[index],
                        .scan_space_id = request.space.identity,
                        .absolute_address = request.space.begin + 16 + index * 16,
                        .permission_snapshot = request.space.permissions,
                        .matched_bytes = {std::byte {0x48}, std::byte {0x8b}, std::byte {0x30}},
                        .before_bytes = {std::byte {0x90}},
                        .after_bytes = {std::byte {0x90}},
                        .label = request.space.label,
                        .subject_generation = request.space.subject_generation,
                    });
                }
                if (scan_behavior == ScanBehavior::unknown_pattern) {
                    matches.front().pattern_id = "pattern-unknown";
                } else if (scan_behavior == ScanBehavior::zero_length) {
                    matches.front().offset = request.space.size;
                    matches.front().length = 0;
                    matches.front().absolute_address = request.space.begin + request.space.size;
                    matches.front().matched_bytes.clear();
                    matches.front().after_bytes.clear();
                } else if (scan_behavior == ScanBehavior::out_of_bounds) {
                    matches.front().offset = request.space.size;
                    matches.front().length = 1;
                    matches.front().absolute_address = request.space.begin + request.space.size;
                    matches.front().matched_bytes = {std::byte {0x48}};
                    matches.front().after_bytes.clear();
                }
                result.push_back(ScanResponse {
                    .request_id = request.request_id,
                    .subject = request.subject,
                    .status = FactTerminalStatus::value,
                    .matches = std::move(matches),
                    .truncated = false,
                    .diagnostic = std::nullopt,
                    .mode = request.plan.result_mode,
                });
            }
            return result;
        }

        void cancel(const std::span<const RequestId> requests) noexcept override {
            canceled.assign(requests.begin(), requests.end());
        }
    };

    TEST_CASE("Windows provider routing exposes typed facts and scans but no predicate or verdict") {
        FakeProvider provider;
        WindowsAgentProviderRouter router;
        REQUIRE(router.bind("windows.memory", provider).has_value());
        REQUIRE_FALSE(router.bind("windows.memory", provider).has_value());

        const auto result = router.dispatch(work_lease());
        REQUIRE(result.has_value());
        REQUIRE(provider.facts.size() == 1);
        REQUIRE(provider.scans.size() == 1);
        REQUIRE(result->facts.front().request_id.value == "fact-1");
        REQUIRE(result->scans.front().matches.size() == 2);
        REQUIRE(result->scans.front().matches.front().offset == 16);
        REQUIRE(result->scans.front().matches.front().pattern_id == "pattern-1");
        REQUIRE(result->scans.front().matches.back().pattern_id == "pattern-2");
        REQUIRE(result->work_id == "work-1");

        provider.fact_schema_override =
            SchemaIdentity {.id = SchemaId {"protection/v1"}, .canonical_hash = "sha256:wrong-revision"};
        const auto wrong_schema = router.dispatch(work_lease());
        REQUIRE_FALSE(wrong_schema.has_value());
        REQUIRE(wrong_schema.error().code == ProviderDispatchErrorCode::provider_violation);
        provider.fact_schema_override.reset();

        auto missing_pattern_ids = work_lease();
        missing_pattern_ids.scans.front().plan.pattern_ids.clear();
        const auto missing_pattern_ids_result = router.dispatch(missing_pattern_ids);
        REQUIRE_FALSE(missing_pattern_ids_result.has_value());
        REQUIRE(missing_pattern_ids_result.error().code == ProviderDispatchErrorCode::invalid_request);

        auto duplicate_pattern_ids = work_lease();
        duplicate_pattern_ids.scans.front().plan.pattern_ids = {"pattern-1", "pattern-1"};
        const auto duplicate_pattern_ids_result = router.dispatch(duplicate_pattern_ids);
        REQUIRE_FALSE(duplicate_pattern_ids_result.has_value());
        REQUIRE(duplicate_pattern_ids_result.error().code == ProviderDispatchErrorCode::invalid_request);

        provider.scan_behavior = FakeProvider::ScanBehavior::unknown_pattern;
        const auto unknown_pattern = router.dispatch(work_lease());
        REQUIRE_FALSE(unknown_pattern.has_value());
        REQUIRE(unknown_pattern.error().code == ProviderDispatchErrorCode::provider_violation);

        provider.scan_behavior = FakeProvider::ScanBehavior::zero_length;
        const auto zero_length = router.dispatch(work_lease());
        REQUIRE(zero_length.has_value());
        REQUIRE(zero_length->scans.front().matches.back().length == 0);
        REQUIRE(zero_length->scans.front().matches.back().matched_bytes.empty());

        provider.scan_behavior = FakeProvider::ScanBehavior::out_of_bounds;
        const auto out_of_bounds = router.dispatch(work_lease());
        REQUIRE_FALSE(out_of_bounds.has_value());
        REQUIRE(out_of_bounds.error().code == ProviderDispatchErrorCode::provider_violation);

        provider.scan_behavior = FakeProvider::ScanBehavior::normal;

        auto insufficient_context = work_lease();
        insufficient_context.scans.front().plan.context_bytes_before = 0;
        REQUIRE_FALSE(router.dispatch(insufficient_context).has_value());

        CancelWorkMessage cancel {.session = SessionId {"session-1"},
                                  .peer = PeerId {"peer-1"},
                                  .session_fence = 7,
                                  .work_id = "work-1",
                                  .attempt_id = "attempt-1",
                                  .work_fence = 11,
                                  .server_sequence = 2,
                                  .route = "windows.memory",
                                  .requests = {RequestId {"fact-1"}}};
        REQUIRE(router.cancel(cancel).has_value());
        REQUIRE(provider.canceled.size() == 1);

        auto unknown = work_lease();
        unknown.route = "rule.predicate";
        REQUIRE_FALSE(router.dispatch(unknown).has_value());
        REQUIRE(router.dispatch(unknown).error().code == ProviderDispatchErrorCode::unknown_route);
    }

} // namespace
