#include "rule_engine/python/tools/resident_evaluator.hpp"

#include "rule_engine/python/vm/register_vm.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace {

    using namespace rule_engine::python;
    namespace cluster = rule_engine::python::cluster;
    namespace compiler = rule_engine::python::compiler;
    namespace protocol = rule_engine::python::protocol_v2;
    namespace tools = rule_engine::python::tools;
    namespace vm = rule_engine::python::vm;

    [[nodiscard]] SourceSpan span(const std::uint32_t begin) {
        return {.source = SourceId {"rules/main.py"}, .begin_byte = begin, .end_byte = begin + 1U};
    }

    [[nodiscard]] Instruction instruction(const Opcode opcode, const std::uint32_t destination = 0U,
                                          const std::uint32_t operand_a = 0U, const std::uint32_t operand_b = 0U,
                                          const std::uint32_t immediate = 0U, const std::uint32_t offset = 0U) {
        return {.opcode = opcode,
                .destination = destination,
                .operand_a = operand_a,
                .operand_b = operand_b,
                .immediate = immediate,
                .span = span(offset)};
    }

    [[nodiscard]] tools::ResidentActivePack active_pack() {
        CompiledPack pack {
            .pack = PackId {"com.example.resident"},
            .version = PackVersion {"1.0.0"},
            .source_digest = SourceDigest {"sha256:source"},
            .compiler_abi = std::string {python_static_compiler_abi_v1},
            .semantic_hash = "fnv1a64:semantic",
            .schemas = {.descriptors = {{.id = SchemaId {"bool"},
                                         .kind = SchemaKind::fact,
                                         .qualified_name = "bool",
                                         .canonical_hash = "fnv1a64:bool",
                                         .fields = {}}},
                        .canonical_hash = "fnv1a64:schemas"},
            .constants = {vm::make_fact_operand(FactRoute {.provider = "windows", .fact = "process.is_signed"},
                                                SchemaId {"bool"})},
            .functions = {{.id = ExecutableId {"com.example.resident.unsigned"},
                           .qualified_name = "rules.main.unsigned",
                           .register_count = 2U,
                           .parameter_count = 1U,
                           .generator = false,
                           .async = false,
                           .instructions = {instruction(Opcode::await_fact, 1U, 0U, 0U, 0U, 0U),
                                            instruction(Opcode::return_value, 0U, 1U, 0U, 0U, 1U)},
                           .exception_regions = {}}},
            .bindings = {{.id = BindingId {"com.example.resident.unsigned"},
                          .executable = ExecutableId {"com.example.resident.unsigned"},
                          .capabilities = {},
                          .budget = balanced_v1}},
            .optimization_certificates = {},
        };
        return tools::ResidentActivePack {
            .generation = 7U,
            .state_namespace = "state-live",
            .compilation =
                compiler::CompilationArtifact {
                    .pack = std::move(pack),
                    .symbols = {{.module = "rules.main",
                                 .name = "unsigned",
                                 .qualified_name = "rules.main.unsigned",
                                 .executable = ExecutableId {"com.example.resident.unsigned"},
                                 .subject_schema = SchemaId {"windows.process.v1"},
                                 .kind = compiler::SymbolKind::rule,
                                 .type = {.kind = compiler::StaticTypeKind::callable,
                                          .qualified_name = "rules.main.unsigned"},
                                 .span = span(0U),
                                 .public_api = true,
                                 .async = false,
                                 .generator = false}},
                    .fact_requirements = {},
                    .canonical_form = "resident-test",
                },
        };
    }

    [[nodiscard]] tools::ResidentActivePack stateful_active_pack() {
        auto result = active_pack();
        result.compilation.pack.constants = {
            vm::make_state_operand("rule", "enabled", SchemaId {"bool"}),
            make_fact(true),
        };
        auto &function = result.compilation.pack.functions.front();
        function.register_count = 3U;
        function.instructions = {
            instruction(Opcode::read_state, 1U, 0U, 0U, 0U, 0U),
            instruction(Opcode::load_const, 2U, 0U, 0U, 1U, 1U),
            instruction(Opcode::write_state, 0U, 2U, 0U, 0U, 2U),
            instruction(Opcode::return_value, 0U, 2U, 0U, 0U, 3U),
        };
        return result;
    }

    [[nodiscard]] SubjectKey subject() {
        return {
            .peer = PeerId {"peer-a"},
            .descriptor = SchemaId {"windows.process.v1"},
            .identity = {{.field_id = 1U, .value = std::uint64_t {42U}}},
            .parent = {},
        };
    }

    [[nodiscard]] tools::ResidentAgentSession session() {
        return {
            .authenticated_peer = {.tenant = TenantId {"tenant-a"}, .peer = PeerId {"peer-a"}},
            .session = SessionId {"session-a"},
            .session_fence = 11U,
            .agent_epoch = "epoch-a",
            .acknowledged_through = 0U,
            .credit = {.bytes = 1U << 20U, .messages = 16U, .work_attempts = 4U, .snapshot_chunks = 4U},
            .schemas = {},
            .capabilities = {},
        };
    }

    TEST_CASE("durable authoritative snapshot drives a fenced VM provider round to a committed result") {
        cluster::AuditTrail audit;
        cluster::InMemoryRuntimeStore store {audit};
        auto scheduler = tools::ResidentEvaluationScheduler::create(store, audit, "node-a", std::chrono::seconds {30},
                                                                    {active_pack()});
        REQUIRE(scheduler.has_value());
        const auto agent = session();
        REQUIRE((*scheduler)->bind_session(agent).has_value());

        const std::vector subjects {subject()};
        const auto digest = protocol::authoritative_snapshot_digest(subjects);
        REQUIRE(digest.has_value());
        const protocol::AuthoritativeSnapshotBegin begin {
            .session = agent.session,
            .peer = agent.authenticated_peer.peer,
            .session_fence = agent.session_fence,
            .snapshot_id = "snapshot-a",
            .parent = {},
            .subject_schema = SchemaId {"windows.process.v1"},
            .generation = 1U,
            .expected_count = 1U,
            .expected_digest = *digest,
        };
        const protocol::AuthoritativeSnapshotChunk chunk {
            .session = agent.session,
            .peer = agent.authenticated_peer.peer,
            .session_fence = agent.session_fence,
            .snapshot_id = "snapshot-a",
            .generation = 1U,
            .chunk_index = 0U,
            .subjects = subjects,
        };
        const protocol::AuthoritativeSnapshotCommit commit {
            .session = agent.session,
            .peer = agent.authenticated_peer.peer,
            .session_fence = agent.session_fence,
            .snapshot_id = "snapshot-a",
            .generation = 1U,
            .item_count = 1U,
            .canonical_digest = *digest,
        };
        REQUIRE((*scheduler)->ingest(agent, 1U, begin, {}).has_value());
        REQUIRE((*scheduler)->ingest(agent, 2U, chunk, {}).has_value());
        REQUIRE((*scheduler)->ingest(agent, 3U, commit, {}).has_value());

        auto work = (*scheduler)->take_work(agent, 4U, {});
        REQUIRE(work.has_value());
        REQUIRE(work->size() == 1U);
        REQUIRE(work->front().generation == 7U);
        REQUIRE(work->front().route == "windows");
        REQUIRE(work->front().facts.size() == 1U);
        const auto &request = work->front().facts.front();
        REQUIRE(request.subject.descriptor == SchemaId {"windows.process.v1"});

        const protocol::WorkResultMessage result {
            .originating_session = agent.session,
            .peer = agent.authenticated_peer.peer,
            .originating_session_fence = agent.session_fence,
            .work_id = work->front().work_id,
            .attempt_id = work->front().attempt_id,
            .work_fence = work->front().work_fence,
            .generation = work->front().generation,
            .facts = {{.request_id = request.request_id,
                       .subject = request.subject,
                       .status = FactTerminalStatus::value,
                       .value = make_fact(true),
                       .returned_schema = SchemaIdentity {.id = request.expected_schema,
                                                          .canonical_hash = request.expected_schema_hash},
                       .diagnostic = std::nullopt}},
            .scans = {},
        };
        REQUIRE((*scheduler)->ingest(agent, 4U, result, {}).has_value());

        const auto snapshot = store.snapshot();
        REQUIRE(snapshot.receipts.size() == 1U);
        REQUIRE(snapshot.results.size() == 1U);
        CHECK(snapshot.results.front().evaluation.outcome == EvaluationOutcome::match);
        CHECK(snapshot.results.front().evaluation.verdict == true);
        CHECK((*scheduler)->take_work(agent, 4U, {})->empty());
    }

    TEST_CASE("resident state turns stay on the server and commit beneath a tenant-isolated activation namespace") {
        cluster::AuditTrail audit;
        cluster::InMemoryRuntimeStore store {audit};
        auto scheduler = tools::ResidentEvaluationScheduler::create(store, audit, "node-a", std::chrono::seconds {30},
                                                                    {stateful_active_pack()});
        REQUIRE(scheduler.has_value());

        const auto run_tenant = [&](tools::ResidentAgentSession agent, const std::string &snapshot_id) {
            REQUIRE((*scheduler)->bind_session(agent).has_value());
            auto selected_subject = subject();
            selected_subject.peer = agent.authenticated_peer.peer;
            const std::vector subjects {selected_subject};
            const auto digest = protocol::authoritative_snapshot_digest(subjects);
            REQUIRE(digest.has_value());
            REQUIRE((*scheduler)
                        ->ingest(agent, 1U,
                                 protocol::AuthoritativeSnapshotBegin {
                                     .session = agent.session,
                                     .peer = agent.authenticated_peer.peer,
                                     .session_fence = agent.session_fence,
                                     .snapshot_id = snapshot_id,
                                     .parent = {},
                                     .subject_schema = SchemaId {"windows.process.v1"},
                                     .generation = 1U,
                                     .expected_count = 1U,
                                     .expected_digest = *digest,
                                 },
                                 {})
                        .has_value());
            REQUIRE((*scheduler)
                        ->ingest(agent, 2U,
                                 protocol::AuthoritativeSnapshotChunk {
                                     .session = agent.session,
                                     .peer = agent.authenticated_peer.peer,
                                     .session_fence = agent.session_fence,
                                     .snapshot_id = snapshot_id,
                                     .generation = 1U,
                                     .chunk_index = 0U,
                                     .subjects = subjects,
                                 },
                                 {})
                        .has_value());
            REQUIRE((*scheduler)
                        ->ingest(agent, 3U,
                                 protocol::AuthoritativeSnapshotCommit {
                                     .session = agent.session,
                                     .peer = agent.authenticated_peer.peer,
                                     .session_fence = agent.session_fence,
                                     .snapshot_id = snapshot_id,
                                     .generation = 1U,
                                     .item_count = 1U,
                                     .canonical_digest = *digest,
                                 },
                                 {})
                        .has_value());
            auto external_work = (*scheduler)->take_work(agent, 1U, {});
            REQUIRE(external_work.has_value());
            CHECK(external_work->empty());
        };

        auto tenant_a = session();
        run_tenant(tenant_a, "state-a");
        auto tenant_b = tenant_a;
        tenant_b.authenticated_peer.tenant = TenantId {"tenant-b"};
        tenant_b.authenticated_peer.peer = PeerId {"peer-b"};
        tenant_b.session = SessionId {"session-b"};
        tenant_b.session_fence = 12U;
        tenant_b.agent_epoch = "epoch-b";
        run_tenant(tenant_b, "state-b");

        const auto snapshot = store.snapshot();
        REQUIRE(snapshot.results.size() == 2U);
        REQUIRE(snapshot.state.size() == 2U);
        CHECK(snapshot.state[0].key.namespace_name != "rule");
        CHECK(snapshot.state[1].key.namespace_name != "rule");
        CHECK(snapshot.state[0].key.namespace_name != snapshot.state[1].key.namespace_name);
        for (const auto &cell : snapshot.state) {
            CHECK(cell.version == 1U);
            REQUIRE(cell.value.has_value());
            CHECK(std::get<bool>(cell.value->value.node->data));
        }
    }

    TEST_CASE("scheduler rebuilds snapshot work from the durable agent stream after restart") {
        cluster::AuditTrail audit;
        cluster::InMemoryRuntimeStore store {audit};
        const auto agent = session();
        const auto lease = store.claim_lease(
            {.scope = "agent-session",
             .key = agent.authenticated_peer.tenant.value + "/" + agent.authenticated_peer.peer.value},
            agent.session.value, 1U, 60'000U);
        REQUIRE(lease.has_value());

        const std::vector subjects {subject()};
        const auto digest = protocol::authoritative_snapshot_digest(subjects);
        REQUIRE(digest.has_value());
        const std::vector<protocol::DurableAgentBody> bodies {
            protocol::AuthoritativeSnapshotBegin {
                .session = agent.session,
                .peer = agent.authenticated_peer.peer,
                .session_fence = lease->fence,
                .snapshot_id = "snapshot-recovery",
                .parent = {},
                .subject_schema = SchemaId {"windows.process.v1"},
                .generation = 1U,
                .expected_count = 1U,
                .expected_digest = *digest,
            },
            protocol::AuthoritativeSnapshotChunk {
                .session = agent.session,
                .peer = agent.authenticated_peer.peer,
                .session_fence = lease->fence,
                .snapshot_id = "snapshot-recovery",
                .generation = 1U,
                .chunk_index = 0U,
                .subjects = subjects,
            },
            protocol::AuthoritativeSnapshotCommit {
                .session = agent.session,
                .peer = agent.authenticated_peer.peer,
                .session_fence = lease->fence,
                .snapshot_id = "snapshot-recovery",
                .generation = 1U,
                .item_count = 1U,
                .canonical_digest = *digest,
            },
        };
        for (std::size_t index = 0U; index < bodies.size(); ++index) {
            auto encoded = protocol::encode_durable_body(bodies[index]);
            REQUIRE(encoded.has_value());
            const auto committed = store.transact_agent_message(cluster::AgentMessageCommit {
                .stream = {.tenant = agent.authenticated_peer.tenant,
                           .peer = agent.authenticated_peer.peer,
                           .agent_epoch = agent.agent_epoch},
                .session = agent.session,
                .session_fence = lease->fence,
                .sequence = index + 1U,
                .received_at_unix_ms = index + 1U,
                .body_kind =
                    static_cast<std::uint8_t>(static_cast<std::uint8_t>(protocol::MessageKind::snapshot_begin) + index),
                .body = std::move(*encoded),
            });
            REQUIRE(committed.has_value());
        }

        auto recovered = tools::ResidentEvaluationScheduler::create(store, audit, "node-a", std::chrono::seconds {30},
                                                                    {active_pack()});
        REQUIRE(recovered.has_value());
        auto rebound = agent;
        rebound.session_fence = lease->fence;
        rebound.acknowledged_through = 3U;
        auto work = (*recovered)->take_work(rebound, 1U, {});
        REQUIRE(work.has_value());
        REQUIRE(work->size() == 1U);
        CHECK(work->front().facts.size() == 1U);
    }

    TEST_CASE("new session reclaims unfinished work and stale close cannot abandon it") {
        cluster::AuditTrail audit;
        cluster::InMemoryRuntimeStore store {audit};
        auto scheduler = tools::ResidentEvaluationScheduler::create(store, audit, "node-a", std::chrono::seconds {30},
                                                                    {active_pack()});
        REQUIRE(scheduler.has_value());
        const auto old_session = session();
        REQUIRE((*scheduler)->bind_session(old_session).has_value());

        const std::vector subjects {subject()};
        const auto digest = protocol::authoritative_snapshot_digest(subjects);
        REQUIRE(digest.has_value());
        REQUIRE((*scheduler)
                    ->ingest(old_session, 1U,
                             protocol::AuthoritativeSnapshotBegin {
                                 .session = old_session.session,
                                 .peer = old_session.authenticated_peer.peer,
                                 .session_fence = old_session.session_fence,
                                 .snapshot_id = "snapshot-reconnect",
                                 .parent = {},
                                 .subject_schema = SchemaId {"windows.process.v1"},
                                 .generation = 1U,
                                 .expected_count = 1U,
                                 .expected_digest = *digest,
                             },
                             {})
                    .has_value());
        REQUIRE((*scheduler)
                    ->ingest(old_session, 2U,
                             protocol::AuthoritativeSnapshotChunk {
                                 .session = old_session.session,
                                 .peer = old_session.authenticated_peer.peer,
                                 .session_fence = old_session.session_fence,
                                 .snapshot_id = "snapshot-reconnect",
                                 .generation = 1U,
                                 .chunk_index = 0U,
                                 .subjects = subjects,
                             },
                             {})
                    .has_value());
        REQUIRE((*scheduler)
                    ->ingest(old_session, 3U,
                             protocol::AuthoritativeSnapshotCommit {
                                 .session = old_session.session,
                                 .peer = old_session.authenticated_peer.peer,
                                 .session_fence = old_session.session_fence,
                                 .snapshot_id = "snapshot-reconnect",
                                 .generation = 1U,
                                 .item_count = 1U,
                                 .canonical_digest = *digest,
                             },
                             {})
                    .has_value());
        auto first_work = (*scheduler)->take_work(old_session, 1U, {});
        REQUIRE(first_work.has_value());
        REQUIRE(first_work->size() == 1U);

        auto new_session = old_session;
        new_session.session = SessionId {"session-b"};
        new_session.session_fence = 12U;
        new_session.acknowledged_through = 3U;
        REQUIRE((*scheduler)->bind_session(new_session).has_value());
        auto reclaimed = (*scheduler)->take_work(new_session, 1U, {});
        REQUIRE(reclaimed.has_value());
        REQUIRE(reclaimed->size() == 1U);
        CHECK(reclaimed->front().work_fence > first_work->front().work_fence);
        (*scheduler)->close(old_session);

        const auto &request = reclaimed->front().facts.front();
        REQUIRE((*scheduler)
                    ->ingest(new_session, 4U,
                             protocol::WorkResultMessage {
                                 .originating_session = new_session.session,
                                 .peer = new_session.authenticated_peer.peer,
                                 .originating_session_fence = new_session.session_fence,
                                 .work_id = reclaimed->front().work_id,
                                 .attempt_id = reclaimed->front().attempt_id,
                                 .work_fence = reclaimed->front().work_fence,
                                 .generation = reclaimed->front().generation,
                                 .facts = {{.request_id = request.request_id,
                                            .subject = request.subject,
                                            .status = FactTerminalStatus::value,
                                            .value = make_fact(true),
                                            .returned_schema =
                                                SchemaIdentity {.id = request.expected_schema,
                                                                .canonical_hash = request.expected_schema_hash},
                                            .diagnostic = std::nullopt}},
                                 .scans = {},
                             },
                             {})
                    .has_value());
        CHECK(store.snapshot().receipts.size() == 1U);
    }

    TEST_CASE("restart replays agent epochs in durable receive order") {
        cluster::AuditTrail audit;
        cluster::InMemoryRuntimeStore store {audit};
        const auto first = session();
        auto second = first;
        second.session = SessionId {"session-b"};
        second.session_fence = 2U;
        second.agent_epoch = "epoch-a";

        const auto persist_snapshot = [&](const tools::ResidentAgentSession &agent, const std::string &snapshot_id,
                                          const std::uint64_t generation, const std::uint64_t received_at) {
            auto lease = store.claim_lease(
                {.scope = "agent-session",
                 .key = agent.authenticated_peer.tenant.value + "/" + agent.authenticated_peer.peer.value},
                agent.session.value, received_at, 10U);
            REQUIRE(lease.has_value());
            const std::vector subjects {subject()};
            const auto digest = protocol::authoritative_snapshot_digest(subjects);
            REQUIRE(digest.has_value());
            const std::vector<protocol::DurableAgentBody> bodies {
                protocol::AuthoritativeSnapshotBegin {
                    .session = agent.session,
                    .peer = agent.authenticated_peer.peer,
                    .session_fence = lease->fence,
                    .snapshot_id = snapshot_id,
                    .parent = {},
                    .subject_schema = SchemaId {"windows.process.v1"},
                    .generation = generation,
                    .expected_count = 1U,
                    .expected_digest = *digest,
                },
                protocol::AuthoritativeSnapshotChunk {
                    .session = agent.session,
                    .peer = agent.authenticated_peer.peer,
                    .session_fence = lease->fence,
                    .snapshot_id = snapshot_id,
                    .generation = generation,
                    .chunk_index = 0U,
                    .subjects = subjects,
                },
                protocol::AuthoritativeSnapshotCommit {
                    .session = agent.session,
                    .peer = agent.authenticated_peer.peer,
                    .session_fence = lease->fence,
                    .snapshot_id = snapshot_id,
                    .generation = generation,
                    .item_count = 1U,
                    .canonical_digest = *digest,
                },
            };
            for (std::size_t index = 0U; index < bodies.size(); ++index) {
                auto encoded = protocol::encode_durable_body(bodies[index]);
                REQUIRE(encoded.has_value());
                REQUIRE(store
                            .transact_agent_message(cluster::AgentMessageCommit {
                                .stream = {.tenant = agent.authenticated_peer.tenant,
                                           .peer = agent.authenticated_peer.peer,
                                           .agent_epoch = agent.agent_epoch},
                                .session = agent.session,
                                .session_fence = lease->fence,
                                .sequence = index + 1U,
                                .received_at_unix_ms = received_at + index,
                                .body_kind = static_cast<std::uint8_t>(
                                    static_cast<std::uint8_t>(protocol::MessageKind::snapshot_begin) + index),
                                .body = std::move(*encoded),
                            })
                            .has_value());
            }
            REQUIRE(store.release_lease(*lease, received_at + bodies.size()).has_value());
        };

        auto lexically_late_first = first;
        lexically_late_first.agent_epoch = "epoch-z";
        persist_snapshot(lexically_late_first, "snapshot-old", 1U, 10U);
        persist_snapshot(second, "snapshot-new", 2U, 100U);

        auto recovered = tools::ResidentEvaluationScheduler::create(store, audit, "node-a", std::chrono::seconds {30},
                                                                    {active_pack()});
        REQUIRE(recovered.has_value());
        second.acknowledged_through = 3U;
        auto work = (*recovered)->take_work(second, 4U, {});
        REQUIRE(work.has_value());
        CHECK(work->size() == 1U);
    }

} // namespace
