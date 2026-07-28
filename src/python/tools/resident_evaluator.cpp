#include "rule_engine/python/tools/resident_evaluator.hpp"

#include "rule_engine/python/engine.hpp"
#include "rule_engine/python/packaging/source_pack.hpp"
#include "rule_engine/python/protocol/codec.hpp"
#include "rule_engine/python/runtime/orchestrator.hpp"
#include "rule_engine/python/vm/register_vm.hpp"

#include <algorithm>
#include <charconv>
#include <deque>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <ranges>
#include <string_view>
#include <tuple>
#include <utility>

namespace rule_engine::python::tools {
    namespace {

        [[nodiscard]] protocol_v2::ProtocolError protocol_error(const protocol_v2::ProtocolErrorCode code,
                                                                std::string message) {
            return {.code = code, .message = std::move(message), .byte_offset = 0U};
        }

        [[nodiscard]] std::uint64_t now_unix_ms() noexcept {
            return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                  std::chrono::system_clock::now().time_since_epoch())
                                                  .count());
        }

        [[nodiscard]] std::string digest_key(const std::string_view domain, const std::string_view material) {
            std::string canonical {domain};
            canonical.push_back('\0');
            canonical.append(material);
            return packaging::sha256_hex(std::as_bytes(std::span {canonical.data(), canonical.size()}));
        }

        [[nodiscard]] std::string peer_key(const TenantId &tenant, const PeerId &peer) {
            return tenant.value + '\0' + peer.value;
        }

        [[nodiscard]] std::string snapshot_scope_key(const SchemaId &schema, const std::optional<SubjectKey> &parent) {
            return schema.value + '\0' + (parent ? canonical_subject_key(*parent) : std::string {"-"});
        }

        [[nodiscard]] std::optional<std::string> physical_state_namespace(const EventEnvelope &input,
                                                                          const PackId &pack,
                                                                          const std::string_view activation_namespace,
                                                                          const std::string_view logical_namespace) {
            std::string material;
            material.reserve(input.tenant.value.size() + pack.value.size() + activation_namespace.size() +
                             logical_namespace.size() + 3U);
            material.append(input.tenant.value);
            material.push_back('\0');
            material.append(pack.value);
            material.push_back('\0');
            material.append(activation_namespace);
            material.push_back('\0');
            material.append(logical_namespace);
            if (logical_namespace.starts_with("state-key-v1/peer/")) {
                material.push_back('\0');
                material.append(input.peer.value);
            } else if (logical_namespace.starts_with("state-key-v1/subject/")) {
                if (!input.subject) {
                    return std::nullopt;
                }
                material.push_back('\0');
                material.append(canonical_subject_key(*input.subject));
            }
            return "state:" + digest_key("resident-state-namespace-v1", material);
        }

        [[nodiscard]] bool terminal(const VmStepState state) noexcept {
            return state == VmStepState::complete || state == VmStepState::faulted ||
                   state == VmStepState::quarantined || state == VmStepState::canceled;
        }

        constexpr std::size_t maximum_recovered_provider_bytes_per_work = 16U * mebibyte;
        constexpr std::size_t maximum_recovered_provider_bytes = 64U * mebibyte;

    } // namespace

    struct ResidentEvaluationScheduler::Impl {
        struct EvaluationDefinition {
            std::size_t pack_index {};
            BindingId binding;
            SubjectKey subject;
            EventEnvelope input;
            CursorAdvance cursor;
            std::string serial_domain;
        };

        struct RecoveredProviderRound {
            HostResponses responses;
            std::vector<std::byte> canonical_result;
            std::uint64_t protocol_attempt {};
            std::uint64_t work_fence {};
        };

        struct ActiveEvaluation {
            struct CapturedProviderRound {
                std::vector<std::string> fact_keys;
                std::vector<std::string> scan_keys;
                HostResponses responses;
            };

            cluster::WorkLease lease;
            std::unique_ptr<VmSession> vm;
            std::size_t round {};
            std::uint64_t protocol_attempt {};
            SessionId session;
            std::uint64_t session_fence {};
            std::vector<CapturedProviderRound> captured_provider_rounds;
            std::size_t replay_provider_round {};
            std::vector<HostResponses> recovered_provider_rounds;
            std::size_t recovered_provider_round {};
            std::uint32_t mvcc_attempt {1U};
            VmResourceUsage cumulative_usage;
            std::chrono::nanoseconds reported_elapsed {};
            std::chrono::steady_clock::time_point started {std::chrono::steady_clock::now()};
            BudgetProfile attempt_budget {balanced_v1};
            bool replaying {};
            std::vector<std::string> pending_fact_keys;
            std::vector<std::string> pending_scan_keys;
        };

        struct SnapshotScope {
            std::unique_ptr<protocol_v2::AuthoritativeSnapshotAssembler> assembler;
        };

        struct PeerState {
            std::unique_ptr<cluster::DeterministicWorkCoordinator> coordinator;
            std::map<std::string, SnapshotScope, std::less<>> snapshots;
            std::map<std::string, std::string, std::less<>> staging_snapshot_scopes;
            std::map<std::string, EvaluationDefinition, std::less<>> definitions;
            std::map<std::string, ActiveEvaluation, std::less<>> active_rounds;
            std::map<std::string, std::vector<RecoveredProviderRound>, std::less<>> recovered_provider_rounds;
            std::deque<protocol_v2::WorkLeaseMessage> pending;
            std::map<std::string, std::uint64_t, std::less<>> processed_epochs;
            SessionId current_session;
            std::uint64_t current_session_fence {};
        };

        cluster::IClusterRuntimeStore &store;
        cluster::AuditTrail &audit;
        std::string node_id;
        std::uint64_t work_lease_ms {};
        std::vector<ResidentActivePack> packs;
        protocol_v2::ProtocolLimits limits;
        std::map<std::string, std::uint64_t, std::less<>> reserved_cursors;
        std::map<std::string, PeerState, std::less<>> peers;
        std::size_t recovered_provider_bytes {};
        std::mutex mutex;

        Impl(cluster::IClusterRuntimeStore &store_value, cluster::AuditTrail &audit_value, std::string node_id_value,
             const std::uint64_t work_lease_ms_value, std::vector<ResidentActivePack> packs_value,
             const protocol_v2::ProtocolLimits limits_value):
            store {store_value},
            audit {audit_value},
            node_id {std::move(node_id_value)},
            work_lease_ms {work_lease_ms_value},
            packs {std::move(packs_value)},
            limits {limits_value} {}

        [[nodiscard]] PeerState &state_for(const ResidentAgentSession &session) {
            const auto key = peer_key(session.authenticated_peer.tenant, session.authenticated_peer.peer);
            auto [position, inserted] = peers.try_emplace(key);
            if (inserted) {
                position->second.coordinator = std::make_unique<cluster::DeterministicWorkCoordinator>(store, audit);
            }
            return position->second;
        }

        [[nodiscard]] std::expected<void, protocol_v2::ProtocolError> bind_locked(const ResidentAgentSession &session) {
            auto &state = state_for(session);
            if (state.current_session == session.session && state.current_session_fence == session.session_fence) {
                return {};
            }
            for (auto &[_, active] : state.active_rounds) {
                static_cast<void>(state.coordinator->abandon(active.lease, now_unix_ms()));
            }
            state.active_rounds.clear();
            state.pending.clear();
            for (auto &[_, scope] : state.snapshots) {
                scope.assembler->abort();
                auto rebound = scope.assembler->rebind_session(session.session, session.session_fence);
                if (!rebound) {
                    return std::unexpected(std::move(rebound.error()));
                }
            }
            state.staging_snapshot_scopes.clear();
            state.current_session = session.session;
            state.current_session_fence = session.session_fence;
            return {};
        }

        [[nodiscard]] const compiler::BoundSymbol *entry_symbol(const ResidentActivePack &pack,
                                                                const OperatorBinding &binding) const noexcept {
            const auto symbol =
                std::ranges::find(pack.compilation.symbols, binding.executable, &compiler::BoundSymbol::executable);
            return symbol == pack.compilation.symbols.end() ? nullptr : std::addressof(*symbol);
        }

        [[nodiscard]] bool owns_executable(const ResidentActivePack &pack,
                                           const ExecutableId &executable) const noexcept {
            return std::ranges::any_of(pack.compilation.pack.functions,
                                       [&executable](const auto &function) { return function.id == executable; });
        }

        [[nodiscard]] static VmInvocation invocation_for(const EvaluationDefinition &definition,
                                                         const std::string_view work_id,
                                                         BudgetProfile budget = balanced_v1) {
            return {
                .execution = ExecutionId {"execution:" + std::string {work_id}},
                .invocation = InvocationId {"invocation:" + std::string {work_id}},
                .root_event = definition.input.id,
                .binding = definition.binding,
                .subject = definition.subject,
                .budget = std::move(budget),
                .deterministic_hash_seed = 0U,
            };
        }

        struct WorkRoundIdentity {
            std::string root_work_id;
            std::size_t round {};
        };

        struct WorkAttemptIdentity {
            std::uint64_t attempt {};
            std::size_t round {};
        };

        [[nodiscard]] static std::optional<WorkRoundIdentity> work_round_identity(const std::string_view work_id) {
            constexpr std::string_view marker {":round:"};
            const auto suffix = work_id.rfind(marker);
            if (suffix == std::string_view::npos || suffix == 0U || suffix + marker.size() == work_id.size()) {
                return std::nullopt;
            }
            std::uint64_t round {};
            const auto digits = work_id.substr(suffix + marker.size());
            const auto parsed = std::from_chars(digits.data(), digits.data() + digits.size(), round);
            if (parsed.ec != std::errc {} || parsed.ptr != digits.data() + digits.size() || round == 0U ||
                round > balanced_v1.normal.provider_rounds) {
                return std::nullopt;
            }
            return WorkRoundIdentity {
                .root_work_id = std::string {work_id.substr(0U, suffix)},
                .round = static_cast<std::size_t>(round),
            };
        }

        [[nodiscard]] static std::optional<WorkAttemptIdentity>
        work_attempt_identity(const std::string_view attempt_id) {
            constexpr std::string_view prefix {"attempt:"};
            if (!attempt_id.starts_with(prefix)) {
                return std::nullopt;
            }
            const auto separator = attempt_id.find(':', prefix.size());
            if (separator == std::string_view::npos || separator == prefix.size() ||
                separator + 1U == attempt_id.size()) {
                return std::nullopt;
            }
            std::uint64_t attempt {};
            const auto attempt_digits = attempt_id.substr(prefix.size(), separator - prefix.size());
            const auto parsed_attempt =
                std::from_chars(attempt_digits.data(), attempt_digits.data() + attempt_digits.size(), attempt);
            std::uint64_t round {};
            const auto round_digits = attempt_id.substr(separator + 1U);
            const auto parsed_round =
                std::from_chars(round_digits.data(), round_digits.data() + round_digits.size(), round);
            if (parsed_attempt.ec != std::errc {} ||
                parsed_attempt.ptr != attempt_digits.data() + attempt_digits.size() || attempt == 0U ||
                parsed_round.ec != std::errc {} || parsed_round.ptr != round_digits.data() + round_digits.size() ||
                round == 0U || round > balanced_v1.normal.provider_rounds) {
                return std::nullopt;
            }
            return WorkAttemptIdentity {.attempt = attempt, .round = static_cast<std::size_t>(round)};
        }

        [[nodiscard]] static ActiveEvaluation::CapturedProviderRound
        capture_provider_round(const ActiveEvaluation &active, HostResponses responses) {
            ActiveEvaluation::CapturedProviderRound capture {.fact_keys = active.pending_fact_keys,
                                                             .scan_keys = active.pending_scan_keys,
                                                             .responses = std::move(responses)};
            return capture;
        }

        [[nodiscard]] static ActiveEvaluation::CapturedProviderRound capture_provider_round(const VmStep &step,
                                                                                            HostResponses responses) {
            ActiveEvaluation::CapturedProviderRound capture {
                .fact_keys = {}, .scan_keys = {}, .responses = std::move(responses)};
            capture.fact_keys.reserve(step.fact_requests.size());
            for (const auto &request : step.fact_requests) {
                capture.fact_keys.push_back(runtime::captured_fact_input_key(request));
            }
            capture.scan_keys.reserve(step.scan_requests.size());
            for (const auto &request : step.scan_requests) {
                capture.scan_keys.push_back(runtime::captured_scan_input_key(request));
            }
            return capture;
        }

        [[nodiscard]] static bool provider_round_matches(const VmStep &step,
                                                         const ActiveEvaluation::CapturedProviderRound &capture) {
            if (step.fact_requests.size() != capture.fact_keys.size() ||
                step.scan_requests.size() != capture.scan_keys.size()) {
                return false;
            }
            for (std::size_t index = 0U; index < step.fact_requests.size(); ++index) {
                if (runtime::captured_fact_input_key(step.fact_requests[index]) != capture.fact_keys[index]) {
                    return false;
                }
            }
            for (std::size_t index = 0U; index < step.scan_requests.size(); ++index) {
                if (runtime::captured_scan_input_key(step.scan_requests[index]) != capture.scan_keys[index]) {
                    return false;
                }
            }
            return true;
        }

        [[nodiscard]] std::expected<void, protocol_v2::ProtocolError>
        index_recovered_provider_round(PeerState &state, const ResidentAgentSession &session,
                                       const protocol_v2::WorkResultMessage &result) {
            if (result.originating_session != session.session ||
                result.originating_session_fence != session.session_fence ||
                result.peer != session.authenticated_peer.peer || result.attempt_id.empty() ||
                result.work_fence == 0U || (result.facts.empty() && result.scans.empty())) {
                return std::unexpected(protocol_error(protocol_v2::ProtocolErrorCode::stale_fence,
                                                      "durable provider result has inconsistent recovery identity"));
            }
            const auto identity = work_round_identity(result.work_id);
            if (!identity) {
                return std::unexpected(protocol_error(protocol_v2::ProtocolErrorCode::invalid_identity,
                                                      "durable provider result has an invalid work-round identity"));
            }
            const auto attempt = work_attempt_identity(result.attempt_id);
            if (!attempt || attempt->round != identity->round) {
                return std::unexpected(protocol_error(protocol_v2::ProtocolErrorCode::invalid_identity,
                                                      "durable provider result has an invalid attempt identity"));
            }
            const auto definition = state.definitions.find(identity->root_work_id);
            if (definition == state.definitions.end()) {
                if (!identity->root_work_id.starts_with("work:")) {
                    return std::unexpected(protocol_error(protocol_v2::ProtocolErrorCode::invalid_identity,
                                                          "durable provider result has no deterministic work root"));
                }
                auto receipt = store.load_receipt(EventId {"event:" + identity->root_work_id.substr(5U)});
                if (!receipt) {
                    return std::unexpected(protocol_error(protocol_v2::ProtocolErrorCode::persistence_error,
                                                          "durable provider recovery receipt lookup failed"));
                }
                if (*receipt) {
                    // A committed receipt suppresses its deterministic
                    // definition during snapshot reconstruction. Its old
                    // provider result is no longer recovery input.
                    return {};
                }
                return std::unexpected(protocol_error(protocol_v2::ProtocolErrorCode::stale_generation,
                                                      "durable provider result has no recoverable work definition"));
            }
            if (result.generation != packs[definition->second.pack_index].generation) {
                return std::unexpected(protocol_error(protocol_v2::ProtocolErrorCode::stale_generation,
                                                      "durable provider result targets a different generation"));
            }
            auto canonical = protocol_v2::encode_durable_body(protocol_v2::DurableAgentBody {result}, limits);
            if (!canonical) {
                return std::unexpected(std::move(canonical.error()));
            }
            auto &rounds = state.recovered_provider_rounds[identity->root_work_id];
            if (!rounds.empty() && rounds.front().protocol_attempt != attempt->attempt) {
                return std::unexpected(protocol_error(protocol_v2::ProtocolErrorCode::stale_fence,
                                                      "durable provider result changed attempt during recovery"));
            }
            if (identity->round <= rounds.size()) {
                if (rounds[identity->round - 1U].canonical_result == *canonical) {
                    return {};
                }
                return std::unexpected(protocol_error(protocol_v2::ProtocolErrorCode::provider_violation,
                                                      "durable provider result changed across recovery replay"));
            }
            if (identity->round != rounds.size() + 1U) {
                return std::unexpected(protocol_error(protocol_v2::ProtocolErrorCode::sequence_gap,
                                                      "durable provider result rounds are not contiguous"));
            }
            std::size_t work_bytes {};
            for (const auto &round : rounds) {
                if (round.canonical_result.size() > maximum_recovered_provider_bytes_per_work - work_bytes) {
                    return std::unexpected(
                        protocol_error(protocol_v2::ProtocolErrorCode::limit_exceeded,
                                       "durable provider recovery capture exceeds its per-work byte limit"));
                }
                work_bytes += round.canonical_result.size();
            }
            if (canonical->size() > maximum_recovered_provider_bytes_per_work - work_bytes ||
                canonical->size() > maximum_recovered_provider_bytes - recovered_provider_bytes) {
                return std::unexpected(protocol_error(protocol_v2::ProtocolErrorCode::limit_exceeded,
                                                      "durable provider recovery capture exceeds its byte limit"));
            }
            recovered_provider_bytes += canonical->size();
            rounds.push_back(RecoveredProviderRound {
                .responses =
                    HostResponses {
                        .facts = result.facts,
                        .scans = result.scans,
                        .capabilities = {},
                        .state = {},
                        .history = {},
                        .cancel = false,
                    },
                .canonical_result = std::move(*canonical),
                .protocol_attempt = attempt->attempt,
                .work_fence = result.work_fence,
            });
            return {};
        }

        [[nodiscard]] std::expected<HostResponses, protocol_v2::ProtocolError>
        resolve_local_state(const EvaluationDefinition &definition, const ResidentActivePack &pack,
                            const std::span<const StateReadRequest> requests) const {
            HostResponses responses;
            responses.state.reserve(requests.size());
            for (const auto &request : requests) {
                if (request.request_id.empty() || request.owner.empty() || request.namespace_name.empty() ||
                    request.key.empty() || request.schema.empty() || !owns_executable(pack, request.owner)) {
                    return std::unexpected(protocol_error(protocol_v2::ProtocolErrorCode::provider_violation,
                                                          "VM state request is invalid or crosses pack ownership"));
                }
                auto state_namespace = physical_state_namespace(definition.input, pack.compilation.pack.pack,
                                                                pack.state_namespace, request.namespace_name);
                if (!state_namespace) {
                    return std::unexpected(protocol_error(protocol_v2::ProtocolErrorCode::invalid_identity,
                                                          "state scope requires an unavailable subject identity"));
                }
                const cluster::StoredStateKey key {
                    .owner = request.owner,
                    .namespace_name = std::move(*state_namespace),
                    .key = request.key,
                };
                auto stored = store.load_state(key);
                if (!stored) {
                    return std::unexpected(
                        protocol_error(protocol_v2::ProtocolErrorCode::persistence_error, "durable state read failed"));
                }
                responses.state.push_back(StateReadResponse {
                    .request_id = request.request_id,
                    .value = *stored ? (*stored)->value : std::optional<FrozenValue> {},
                    .version = *stored ? (*stored)->version : 0U,
                    .diagnostic = std::nullopt,
                });
            }
            return responses;
        }

        [[nodiscard]] std::expected<EvaluationResult, protocol_v2::ProtocolError>
        physicalize_state(const EvaluationDefinition &definition, const ResidentActivePack &pack,
                          const EvaluationResult &evaluation) const {
            auto result = evaluation;
            for (auto &mutation : result.state_mutations) {
                if (mutation.owner.empty() || mutation.namespace_name.empty() || mutation.key.empty() ||
                    !owns_executable(pack, mutation.owner)) {
                    return std::unexpected(protocol_error(protocol_v2::ProtocolErrorCode::provider_violation,
                                                          "VM state mutation is invalid or crosses pack ownership"));
                }
                auto state_namespace = physical_state_namespace(definition.input, pack.compilation.pack.pack,
                                                                pack.state_namespace, mutation.namespace_name);
                if (!state_namespace) {
                    return std::unexpected(protocol_error(protocol_v2::ProtocolErrorCode::invalid_identity,
                                                          "state scope requires an unavailable subject identity"));
                }
                mutation.namespace_name = std::move(*state_namespace);
            }
            return result;
        }

        [[nodiscard]] std::expected<void, protocol_v2::ProtocolError>
        schedule_snapshot(PeerState &state, const ResidentAgentSession &session, const std::string_view snapshot_id,
                          const protocol_v2::SnapshotDelta &delta) {
            for (const auto &subject : delta.current) {
                for (std::size_t pack_index = 0U; pack_index < packs.size(); ++pack_index) {
                    auto &active_pack = packs[pack_index];
                    for (const auto &binding : active_pack.compilation.pack.bindings) {
                        const auto *symbol = entry_symbol(active_pack, binding);
                        if (symbol == nullptr || symbol->subject_schema.empty() ||
                            symbol->subject_schema != subject.descriptor) {
                            continue;
                        }

                        const auto subject_key = canonical_subject_key(subject);
                        const auto identity =
                            session.authenticated_peer.tenant.value + '\0' + session.authenticated_peer.peer.value +
                            '\0' + active_pack.compilation.pack.pack.value + '\0' +
                            std::to_string(active_pack.generation) + '\0' + binding.id.value + '\0' +
                            std::string {snapshot_id} + '\0' + std::to_string(delta.generation) + '\0' + subject_key;
                        const auto digest = digest_key("resident-snapshot-work-v1", identity);
                        const auto work_id = "work:" + digest;
                        const auto event = EventId {"event:" + digest};
                        auto receipt = store.load_receipt(event);
                        if (!receipt) {
                            return std::unexpected(protocol_error(protocol_v2::ProtocolErrorCode::persistence_error,
                                                                  "work receipt lookup failed"));
                        }
                        if (*receipt) {
                            continue;
                        }
                        const auto serial_domain =
                            "serial:" +
                            digest_key("resident-serial-domain-v1", session.authenticated_peer.tenant.value + '\0' +
                                                                        session.authenticated_peer.peer.value + '\0' +
                                                                        active_pack.compilation.pack.pack.value + '\0' +
                                                                        binding.id.value + '\0' + subject_key);
                        const auto expected = reserved_cursors[serial_domain];
                        if (expected == (std::numeric_limits<std::uint64_t>::max)()) {
                            return std::unexpected(protocol_error(protocol_v2::ProtocolErrorCode::limit_exceeded,
                                                                  "serial-domain cursor is exhausted"));
                        }
                        const auto next = expected + 1U;
                        cluster::WorkDefinition work {
                            .work_id = work_id,
                            .pack = active_pack.compilation.pack.pack,
                            .generation = active_pack.generation,
                            .serial_domain = serial_domain,
                            .event = event,
                            .priority = 0,
                            .ingest_position = next,
                        };
                        auto queued = state.coordinator->enqueue(work);
                        if (!queued) {
                            return std::unexpected(protocol_error(protocol_v2::ProtocolErrorCode::persistence_error,
                                                                  "deterministic work enqueue failed"));
                        }
                        if (!*queued) {
                            continue;
                        }
                        reserved_cursors[serial_domain] = next;
                        state.definitions.emplace(work_id,
                                                  EvaluationDefinition {
                                                      .pack_index = pack_index,
                                                      .binding = binding.id,
                                                      .subject = subject,
                                                      .input =
                                                          EventEnvelope {
                                                              .id = event,
                                                              .schema = SchemaId {"rule-engine.snapshot-subject.v1"},
                                                              .tenant = session.authenticated_peer.tenant,
                                                              .peer = session.authenticated_peer.peer,
                                                              .subject = subject,
                                                              .producer_unix_ms = 0U,
                                                              .ingest_unix_ms = now_unix_ms(),
                                                              .label = {},
                                                              .causation = std::nullopt,
                                                              .payload =
                                                                  FrozenValue {
                                                                      .value = make_fact(std::monostate {}),
                                                                      .label = {},
                                                                      .canonical_digest = "sha256:" + digest,
                                                                  },
                                                          },
                                                      .cursor =
                                                          CursorAdvance {
                                                              .consumer = serial_domain,
                                                              .expected_position = expected,
                                                              .new_position = next,
                                                          },
                                                      .serial_domain = serial_domain,
                                                  });
                    }
                }
            }
            return {};
        }

        [[nodiscard]] std::expected<bool, protocol_v2::ProtocolError>
        commit_terminal(PeerState &state, const std::string &work_id, ActiveEvaluation &active,
                        const EvaluationResult &evaluation) {
            const auto definition = state.definitions.find(work_id);
            if (definition == state.definitions.end()) {
                return std::unexpected(protocol_error(protocol_v2::ProtocolErrorCode::stale_generation,
                                                      "evaluation definition is absent"));
            }
            const auto &pack = packs[definition->second.pack_index];
            auto durable_evaluation = physicalize_state(definition->second, pack, evaluation);
            if (!durable_evaluation) {
                return std::unexpected(std::move(durable_evaluation.error()));
            }
            const VmInvocation invocation {
                .execution = ExecutionId {"execution:" + work_id},
                .invocation = InvocationId {"invocation:" + work_id},
                .root_event = definition->second.input.id,
                .binding = definition->second.binding,
                .subject = definition->second.subject,
                .budget = balanced_v1,
                .deterministic_hash_seed = 0U,
            };
            auto transaction =
                project_runtime_transaction(definition->second.input, definition->second.cursor, invocation,
                                            pack.compilation.pack, *durable_evaluation, active.lease.fence);
            if (!transaction) {
                return std::unexpected(protocol_error(protocol_v2::ProtocolErrorCode::persistence_error,
                                                      "terminal evaluation projection failed"));
            }
            auto committed = state.coordinator->commit(active.lease, std::move(*transaction), now_unix_ms());
            if (!committed) {
                if (committed.error().code == StoreErrorCode::conflict) {
                    return false;
                }
                return std::unexpected(protocol_error(committed.error().code == StoreErrorCode::stale_fence ?
                                                          protocol_v2::ProtocolErrorCode::stale_fence :
                                                          protocol_v2::ProtocolErrorCode::persistence_error,
                                                      "terminal evaluation transaction failed"));
            }
            return true;
        }

        [[nodiscard]] std::expected<void, protocol_v2::ProtocolError>
        drive(PeerState &state, const ResidentAgentSession &session, const std::string &work_id,
              ActiveEvaluation active, HostResponses responses) {
            constexpr std::size_t maximum_local_yields = 4'096U;
            for (std::size_t turn = 0U; turn < maximum_local_yields; ++turn) {
                auto step = active.vm->step(std::move(responses));
                responses = {};
                if (terminal(step.state)) {
                    if (!step.result) {
                        static_cast<void>(state.coordinator->abandon(active.lease, now_unix_ms()));
                        return std::unexpected(protocol_error(protocol_v2::ProtocolErrorCode::provider_violation,
                                                              "terminal VM step has no result"));
                    }
                    if (active.recovered_provider_round != active.recovered_provider_rounds.size()) {
                        static_cast<void>(state.coordinator->abandon(active.lease, now_unix_ms()));
                        return std::unexpected(protocol_error(
                            protocol_v2::ProtocolErrorCode::provider_violation,
                            "resident recovery terminated before consuming every durable provider round"));
                    }
                    if (active.replaying && active.replay_provider_round != active.captured_provider_rounds.size()) {
                        static_cast<void>(state.coordinator->abandon(active.lease, now_unix_ms()));
                        return std::unexpected(protocol_error(
                            protocol_v2::ProtocolErrorCode::provider_violation,
                            "resident MVCC replay terminated before consuming every captured provider round"));
                    }
                    auto committed = commit_terminal(state, work_id, active, *step.result);
                    if (!committed) {
                        return std::unexpected(std::move(committed.error()));
                    }
                    if (*committed) {
                        return {};
                    }
                    if (active.mvcc_attempt == runtime::maximum_mvcc_attempts) {
                        return std::unexpected(protocol_error(protocol_v2::ProtocolErrorCode::persistence_error,
                                                              "resident MVCC retry attempts are exhausted"));
                    }
                    const auto attempt_usage = active.vm->resource_usage();
                    if (auto accounted = runtime::accumulate_vm_retry_usage(
                            active.cumulative_usage, active.reported_elapsed, attempt_usage, active.attempt_budget);
                        !accounted) {
                        static_cast<void>(state.coordinator->abandon(active.lease, now_unix_ms()));
                        return std::unexpected(protocol_error(protocol_v2::ProtocolErrorCode::limit_exceeded,
                                                              "resident MVCC retry resource accounting failed"));
                    }
                    active.cumulative_usage.elapsed =
                        std::max(active.reported_elapsed, std::chrono::duration_cast<std::chrono::nanoseconds>(
                                                              std::chrono::steady_clock::now() - active.started));
                    ++active.mvcc_attempt;
                    active.attempt_budget = runtime::remaining_vm_retry_budget(balanced_v1, active.cumulative_usage);
                    const auto definition = state.definitions.find(work_id);
                    if (definition == state.definitions.end()) {
                        return std::unexpected(protocol_error(protocol_v2::ProtocolErrorCode::stale_generation,
                                                              "evaluation definition is absent during MVCC retry"));
                    }
                    const auto &pack = packs[definition->second.pack_index];
                    auto vm = vm::RegisterVmSession::create(
                        pack.compilation.pack, invocation_for(definition->second, work_id, active.attempt_budget));
                    if (!vm) {
                        static_cast<void>(state.coordinator->abandon(active.lease, now_unix_ms()));
                        return std::unexpected(protocol_error(protocol_v2::ProtocolErrorCode::limit_exceeded,
                                                              "resident MVCC retry VM could not start"));
                    }
                    active.vm = std::move(*vm);
                    active.replaying = true;
                    active.replay_provider_round = 0U;
                    active.pending_fact_keys.clear();
                    active.pending_scan_keys.clear();
                    continue;
                }
                if (step.state == VmStepState::yielded && step.fact_requests.empty() && step.scan_requests.empty() &&
                    step.capability_requests.empty() && step.state_requests.empty() && step.history_requests.empty()) {
                    continue;
                }
                if (!step.capability_requests.empty() || !step.history_requests.empty()) {
                    static_cast<void>(state.coordinator->abandon(active.lease, now_unix_ms()));
                    return std::unexpected(protocol_error(
                        protocol_v2::ProtocolErrorCode::dependency_unavailable,
                        "resident host turn requires a capability or history service that is not configured"));
                }
                if (!step.state_requests.empty()) {
                    const auto definition = state.definitions.find(work_id);
                    if (definition == state.definitions.end()) {
                        static_cast<void>(state.coordinator->abandon(active.lease, now_unix_ms()));
                        return std::unexpected(protocol_error(protocol_v2::ProtocolErrorCode::stale_generation,
                                                              "evaluation definition is absent"));
                    }
                    const auto &pack = packs[definition->second.pack_index];
                    auto resolved = resolve_local_state(definition->second, pack, step.state_requests);
                    if (!resolved) {
                        static_cast<void>(state.coordinator->abandon(active.lease, now_unix_ms()));
                        return std::unexpected(std::move(resolved.error()));
                    }
                    responses = std::move(*resolved);
                    continue;
                }
                if (step.fact_requests.empty() && step.scan_requests.empty()) {
                    static_cast<void>(state.coordinator->abandon(active.lease, now_unix_ms()));
                    return std::unexpected(protocol_error(protocol_v2::ProtocolErrorCode::provider_violation,
                                                          "nonterminal VM step produced no provider request"));
                }
                if (active.replaying) {
                    if (active.replay_provider_round >= active.captured_provider_rounds.size()) {
                        static_cast<void>(state.coordinator->abandon(active.lease, now_unix_ms()));
                        return std::unexpected(
                            protocol_error(protocol_v2::ProtocolErrorCode::provider_violation,
                                           "resident MVCC replay requested an uncaptured provider round"));
                    }
                    const auto &capture = active.captured_provider_rounds[active.replay_provider_round++];
                    if (!provider_round_matches(step, capture)) {
                        static_cast<void>(state.coordinator->abandon(active.lease, now_unix_ms()));
                        return std::unexpected(
                            protocol_error(protocol_v2::ProtocolErrorCode::provider_violation,
                                           "resident MVCC replay provider request differs from its captured input"));
                    }
                    responses = capture.responses;
                    continue;
                }
                if (active.recovered_provider_round < active.recovered_provider_rounds.size()) {
                    auto recovered = active.recovered_provider_rounds[active.recovered_provider_round++];
                    ++active.round;
                    active.captured_provider_rounds.push_back(capture_provider_round(step, recovered));
                    responses = std::move(recovered);
                    continue;
                }
                std::string route {"windows"};
                if (!step.fact_requests.empty()) {
                    route = step.fact_requests.front().route.provider;
                    if (std::ranges::any_of(step.fact_requests, [&route](const FactRequest &request) {
                            return request.route.provider != route;
                        })) {
                        static_cast<void>(state.coordinator->abandon(active.lease, now_unix_ms()));
                        return std::unexpected(protocol_error(protocol_v2::ProtocolErrorCode::unknown_route,
                                                              "one VM provider turn spans multiple agent routes"));
                    }
                }
                ++active.round;
                const auto protocol_work_id = work_id + ":round:" + std::to_string(active.round);
                active.pending_fact_keys.clear();
                active.pending_fact_keys.reserve(step.fact_requests.size());
                for (const auto &request : step.fact_requests) {
                    active.pending_fact_keys.push_back(runtime::captured_fact_input_key(request));
                }
                active.pending_scan_keys.clear();
                active.pending_scan_keys.reserve(step.scan_requests.size());
                for (const auto &request : step.scan_requests) {
                    active.pending_scan_keys.push_back(runtime::captured_scan_input_key(request));
                }
                protocol_v2::WorkLeaseMessage message {
                    .session = session.session,
                    .peer = session.authenticated_peer.peer,
                    .session_fence = session.session_fence,
                    .work_id = protocol_work_id,
                    .attempt_id =
                        "attempt:" + std::to_string(active.protocol_attempt) + ':' + std::to_string(active.round),
                    .work_fence = active.lease.fence,
                    .generation = active.lease.work.generation,
                    .server_sequence = 0U,
                    .route = std::move(route),
                    .facts = std::move(step.fact_requests),
                    .scans = std::move(step.scan_requests),
                };
                active.session = session.session;
                active.session_fence = session.session_fence;
                state.active_rounds.emplace(protocol_work_id, std::move(active));
                state.pending.push_back(std::move(message));
                return {};
            }
            static_cast<void>(state.coordinator->abandon(active.lease, now_unix_ms()));
            return std::unexpected(protocol_error(protocol_v2::ProtocolErrorCode::limit_exceeded,
                                                  "VM exceeded the resident local-yield guard"));
        }

        [[nodiscard]] std::expected<void, protocol_v2::ProtocolError>
        ingest_locked(const ResidentAgentSession &session, const std::uint64_t sequence,
                      const protocol_v2::DurableAgentBody &body, const bool recovering) {
            auto &state = state_for(session);
            const auto processed = state.processed_epochs[session.agent_epoch];
            if (sequence <= processed) {
                return {};
            }
            if (sequence != processed + 1U) {
                return std::unexpected(protocol_error(protocol_v2::ProtocolErrorCode::sequence_gap,
                                                      "scheduler durable sequence is not contiguous"));
            }
            if (auto bound = bind_locked(session); !bound) {
                return bound;
            }

            std::expected<void, protocol_v2::ProtocolError> applied;
            if (const auto *begin = std::get_if<protocol_v2::AuthoritativeSnapshotBegin>(&body)) {
                const auto scope_key = snapshot_scope_key(begin->subject_schema, begin->parent);
                auto [scope, inserted] = state.snapshots.try_emplace(scope_key);
                if (inserted) {
                    scope->second.assembler = std::make_unique<protocol_v2::AuthoritativeSnapshotAssembler>(
                        session.authenticated_peer.peer, session.session, session.session_fence, begin->subject_schema,
                        begin->parent, limits);
                }
                applied = scope->second.assembler->begin(*begin);
                if (applied) {
                    state.staging_snapshot_scopes.emplace(begin->snapshot_id, scope_key);
                }
            } else if (const auto *chunk = std::get_if<protocol_v2::AuthoritativeSnapshotChunk>(&body)) {
                const auto scope_key = state.staging_snapshot_scopes.find(chunk->snapshot_id);
                if (scope_key == state.staging_snapshot_scopes.end()) {
                    applied = std::unexpected(protocol_error(protocol_v2::ProtocolErrorCode::stale_generation,
                                                             "snapshot chunk has no active scope"));
                } else {
                    applied = state.snapshots.at(scope_key->second).assembler->append(*chunk);
                }
            } else if (const auto *commit = std::get_if<protocol_v2::AuthoritativeSnapshotCommit>(&body)) {
                const auto scope_key = state.staging_snapshot_scopes.find(commit->snapshot_id);
                if (scope_key == state.staging_snapshot_scopes.end()) {
                    applied = std::unexpected(protocol_error(protocol_v2::ProtocolErrorCode::stale_generation,
                                                             "snapshot commit has no active scope"));
                } else {
                    auto delta = state.snapshots.at(scope_key->second).assembler->commit(*commit);
                    state.staging_snapshot_scopes.erase(scope_key);
                    if (!delta) {
                        applied = std::unexpected(std::move(delta.error()));
                    } else {
                        applied = schedule_snapshot(state, session, commit->snapshot_id, *delta);
                    }
                }
            } else if (const auto *result = std::get_if<protocol_v2::WorkResultMessage>(&body)) {
                if (recovering) {
                    applied = index_recovered_provider_round(state, session, *result);
                } else {
                    auto active = state.active_rounds.find(result->work_id);
                    if (active == state.active_rounds.end() || active->second.session != session.session ||
                        active->second.session_fence != session.session_fence ||
                        result->originating_session != session.session ||
                        result->originating_session_fence != session.session_fence ||
                        result->work_fence != active->second.lease.fence ||
                        result->generation != active->second.lease.work.generation ||
                        result->attempt_id != "attempt:" + std::to_string(active->second.protocol_attempt) + ':' +
                                                  std::to_string(active->second.round)) {
                        applied = std::unexpected(protocol_error(protocol_v2::ProtocolErrorCode::stale_fence,
                                                                 "work result does not match an active VM round"));
                    } else {
                        auto evaluation = std::move(active->second);
                        state.active_rounds.erase(active);
                        const auto suffix = result->work_id.rfind(":round:");
                        const auto root =
                            suffix == std::string::npos ? std::string {} : result->work_id.substr(0U, suffix);
                        HostResponses responses {
                            .facts = result->facts,
                            .scans = result->scans,
                            .capabilities = {},
                            .state = {},
                            .history = {},
                            .cancel = false,
                        };
                        evaluation.captured_provider_rounds.push_back(capture_provider_round(evaluation, responses));
                        evaluation.pending_fact_keys.clear();
                        evaluation.pending_scan_keys.clear();
                        applied = drive(state, session, root, std::move(evaluation), std::move(responses));
                    }
                }
            }
            if (!applied) {
                return applied;
            }
            state.processed_epochs[session.agent_epoch] = sequence;
            return {};
        }

        [[nodiscard]] std::expected<void, protocol_v2::ProtocolError> recover() {
            auto snapshot = store.inspect();
            if (!snapshot) {
                return std::unexpected(protocol_error(protocol_v2::ProtocolErrorCode::persistence_error,
                                                      "runtime store inspection failed during scheduler recovery"));
            }
            for (const auto &[consumer, position] : snapshot->cursors) {
                reserved_cursors.insert_or_assign(consumer, position);
            }
            std::ranges::sort(snapshot->agent_messages, [](const auto &left, const auto &right) {
                return std::tie(left.commit.stream.tenant.value, left.commit.stream.peer.value,
                                left.commit.received_at_unix_ms, left.commit.stream.agent_epoch, left.commit.sequence) <
                       std::tie(right.commit.stream.tenant.value, right.commit.stream.peer.value,
                                right.commit.received_at_unix_ms, right.commit.stream.agent_epoch,
                                right.commit.sequence);
            });
            for (const auto &stored : snapshot->agent_messages) {
                auto body = protocol_v2::decode_durable_body(stored.commit.body, limits);
                if (!body) {
                    return std::unexpected(protocol_error(protocol_v2::ProtocolErrorCode::persistence_error,
                                                          "durable agent body failed recovery decoding"));
                }
                const ResidentAgentSession session {
                    .authenticated_peer = {.tenant = stored.commit.stream.tenant, .peer = stored.commit.stream.peer},
                    .session = stored.commit.session,
                    .session_fence = stored.commit.session_fence,
                    .agent_epoch = stored.commit.stream.agent_epoch,
                    .acknowledged_through = stored.commit.sequence,
                    .credit = {},
                    .schemas = {},
                    .capabilities = {},
                };
                auto replayed = ingest_locked(session, stored.commit.sequence, *body, true);
                if (!replayed) {
                    return replayed;
                }
            }
            return {};
        }

        [[nodiscard]] std::expected<void, protocol_v2::ProtocolError> catch_up(const ResidentAgentSession &session) {
            auto snapshot = store.inspect();
            if (!snapshot) {
                return std::unexpected(protocol_error(protocol_v2::ProtocolErrorCode::persistence_error,
                                                      "runtime store inspection failed during session catch-up"));
            }
            std::vector<const cluster::StoredAgentMessage *> messages;
            for (const auto &stored : snapshot->agent_messages) {
                if (stored.commit.stream.tenant == session.authenticated_peer.tenant &&
                    stored.commit.stream.peer == session.authenticated_peer.peer &&
                    stored.commit.stream.agent_epoch == session.agent_epoch) {
                    messages.push_back(std::addressof(stored));
                }
            }
            std::ranges::sort(messages, [](const auto *left, const auto *right) {
                return left->commit.sequence < right->commit.sequence;
            });
            for (const auto *stored : messages) {
                auto body = protocol_v2::decode_durable_body(stored->commit.body, limits);
                if (!body) {
                    return std::unexpected(protocol_error(protocol_v2::ProtocolErrorCode::persistence_error,
                                                          "durable agent body failed session catch-up decoding"));
                }
                const ResidentAgentSession stored_session {
                    .authenticated_peer = session.authenticated_peer,
                    .session = stored->commit.session,
                    .session_fence = stored->commit.session_fence,
                    .agent_epoch = session.agent_epoch,
                    .acknowledged_through = stored->commit.sequence,
                    .credit = session.credit,
                    .schemas = session.schemas,
                    .capabilities = session.capabilities,
                };
                auto applied = ingest_locked(stored_session, stored->commit.sequence, *body, true);
                if (!applied) {
                    return applied;
                }
            }
            return bind_locked(session);
        }
    };

    std::expected<std::unique_ptr<ResidentEvaluationScheduler>, protocol_v2::ProtocolError>
    ResidentEvaluationScheduler::create(cluster::IClusterRuntimeStore &store, cluster::AuditTrail &audit,
                                        std::string node_id, const std::chrono::milliseconds work_lease_duration,
                                        std::vector<ResidentActivePack> active_packs,
                                        const protocol_v2::ProtocolLimits limits) {
        if (node_id.empty() || work_lease_duration.count() <= 0 ||
            std::ranges::any_of(active_packs, [](const ResidentActivePack &pack) {
                return pack.generation == 0U || pack.state_namespace.empty() || pack.compilation.pack.pack.empty() ||
                       pack.compilation.pack.bindings.empty();
            })) {
            return std::unexpected(protocol_error(protocol_v2::ProtocolErrorCode::invalid_value,
                                                  "resident evaluation scheduler configuration is invalid"));
        }
        auto impl = std::make_unique<Impl>(store, audit, std::move(node_id),
                                           static_cast<std::uint64_t>(work_lease_duration.count()),
                                           std::move(active_packs), limits);
        auto recovered = impl->recover();
        if (!recovered) {
            return std::unexpected(std::move(recovered.error()));
        }
        return std::unique_ptr<ResidentEvaluationScheduler> {new ResidentEvaluationScheduler {std::move(impl)}};
    }

    ResidentEvaluationScheduler::ResidentEvaluationScheduler(std::unique_ptr<Impl> impl) noexcept:
        impl_ {std::move(impl)} {}
    ResidentEvaluationScheduler::~ResidentEvaluationScheduler() = default;

    std::expected<void, protocol_v2::ProtocolError>
    ResidentEvaluationScheduler::bind_session(const ResidentAgentSession &session) noexcept {
        std::scoped_lock lock {impl_->mutex};
        if (auto bound = impl_->bind_locked(session); !bound) {
            return bound;
        }
        return impl_->catch_up(session);
    }

    std::expected<void, protocol_v2::ProtocolError>
    ResidentEvaluationScheduler::ingest(const ResidentAgentSession &session, const std::uint64_t sequence,
                                        const protocol_v2::DurableAgentBody &body,
                                        const std::stop_token cancellation) noexcept {
        if (cancellation.stop_requested()) {
            return std::unexpected(
                protocol_error(protocol_v2::ProtocolErrorCode::canceled, "scheduler ingest was canceled"));
        }
        std::scoped_lock lock {impl_->mutex};
        return impl_->ingest_locked(session, sequence, body, false);
    }

    std::expected<std::vector<protocol_v2::WorkLeaseMessage>, protocol_v2::ProtocolError>
    ResidentEvaluationScheduler::take_work(const ResidentAgentSession &session, const std::size_t limit,
                                           const std::stop_token cancellation) noexcept {
        if (cancellation.stop_requested()) {
            return std::unexpected(
                protocol_error(protocol_v2::ProtocolErrorCode::canceled, "scheduler work poll was canceled"));
        }
        if (limit == 0U) {
            return std::vector<protocol_v2::WorkLeaseMessage> {};
        }
        std::scoped_lock lock {impl_->mutex};
        auto &state = impl_->state_for(session);
        if (auto bound = impl_->bind_locked(session); !bound) {
            return std::unexpected(std::move(bound.error()));
        }

        auto fill = [&]() {
            std::vector<protocol_v2::WorkLeaseMessage> result;
            while (!state.pending.empty() && result.size() < limit) {
                result.push_back(std::move(state.pending.front()));
                state.pending.pop_front();
            }
            return result;
        };
        auto result = fill();
        if (result.size() == limit) {
            return result;
        }

        auto claimed =
            state.coordinator->claim(impl_->node_id, now_unix_ms(), impl_->work_lease_ms, limit - result.size());
        if (!claimed) {
            return std::unexpected(
                protocol_error(protocol_v2::ProtocolErrorCode::persistence_error, "deterministic work claim failed"));
        }
        for (auto &lease : *claimed) {
            const auto definition = state.definitions.find(lease.work.work_id);
            if (definition == state.definitions.end()) {
                static_cast<void>(state.coordinator->abandon(lease, now_unix_ms()));
                continue;
            }
            const auto &pack = impl_->packs[definition->second.pack_index];
            const VmInvocation invocation {
                .execution = ExecutionId {"execution:" + lease.work.work_id},
                .invocation = InvocationId {"invocation:" + lease.work.work_id},
                .root_event = definition->second.input.id,
                .binding = definition->second.binding,
                .subject = definition->second.subject,
                .budget = balanced_v1,
                .deterministic_hash_seed = 0U,
            };
            auto vm = vm::RegisterVmSession::create(pack.compilation.pack, invocation);
            if (!vm) {
                static_cast<void>(state.coordinator->abandon(lease, now_unix_ms()));
                continue;
            }
            std::vector<HostResponses> recovered_provider_rounds;
            auto protocol_attempt = lease.attempt;
            if (const auto recovered = state.recovered_provider_rounds.find(lease.work.work_id);
                recovered != state.recovered_provider_rounds.end()) {
                recovered_provider_rounds.reserve(recovered->second.size());
                protocol_attempt = recovered->second.front().protocol_attempt;
                for (auto &round : recovered->second) {
                    if (round.work_fence != lease.fence) {
                        static_cast<void>(state.coordinator->abandon(lease, now_unix_ms()));
                        return std::unexpected(
                            protocol_error(protocol_v2::ProtocolErrorCode::stale_fence,
                                           "durable provider result fence does not match the reacquired work lease"));
                    }
                    recovered_provider_rounds.push_back(std::move(round.responses));
                }
                state.recovered_provider_rounds.erase(recovered);
            }
            auto driven =
                impl_->drive(state, session, lease.work.work_id,
                             Impl::ActiveEvaluation {.lease = lease,
                                                     .vm = std::move(*vm),
                                                     .round = 0U,
                                                     .protocol_attempt = protocol_attempt,
                                                     .session = session.session,
                                                     .session_fence = session.session_fence,
                                                     .captured_provider_rounds = {},
                                                     .replay_provider_round = 0U,
                                                     .recovered_provider_rounds = std::move(recovered_provider_rounds),
                                                     .recovered_provider_round = 0U,
                                                     .mvcc_attempt = 1U,
                                                     .cumulative_usage = {},
                                                     .reported_elapsed = {},
                                                     .started = std::chrono::steady_clock::now(),
                                                     .attempt_budget = balanced_v1,
                                                     .replaying = false,
                                                     .pending_fact_keys = {},
                                                     .pending_scan_keys = {}},
                             {});
            if (!driven) {
                return std::unexpected(std::move(driven.error()));
            }
        }
        auto newly_pending = fill();
        result.insert(result.end(), std::make_move_iterator(newly_pending.begin()),
                      std::make_move_iterator(newly_pending.end()));
        return result;
    }

    void ResidentEvaluationScheduler::close(const ResidentAgentSession &session) noexcept {
        std::scoped_lock lock {impl_->mutex};
        auto &state = impl_->state_for(session);
        if (state.current_session != session.session || state.current_session_fence != session.session_fence) {
            return;
        }
        for (auto &[_, active] : state.active_rounds) {
            static_cast<void>(state.coordinator->abandon(active.lease, now_unix_ms()));
        }
        state.active_rounds.clear();
        state.pending.clear();
        state.staging_snapshot_scopes.clear();
        for (auto &[_, scope] : state.snapshots) { scope.assembler->abort(); }
        state.current_session = {};
        state.current_session_fence = 0U;
    }

} // namespace rule_engine::python::tools
