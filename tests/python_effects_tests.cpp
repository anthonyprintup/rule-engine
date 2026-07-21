#include "rule_engine/python/effects.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace {

    using namespace rule_engine::python;
    using namespace rule_engine::python::effects;

    SourceSpan span(const std::uint32_t begin = 1) {
        return SourceSpan {.source = SourceId {"rules/main.py"}, .begin_byte = begin, .end_byte = begin + 4U};
    }

    DataLabel label(const Classification classification = Classification::public_data,
                    std::vector<std::string> categories = {}) {
        return DataLabel {.classification = classification, .categories = std::move(categories)};
    }

    FrozenValue frozen(std::string text, const Classification classification = Classification::public_data,
                       std::vector<std::string> categories = {}) {
        auto digest = "digest:" + text;
        return FrozenValue {
            .value = make_fact(UnicodeValue {.utf8 = std::move(text)}),
            .label = label(classification, std::move(categories)),
            .canonical_digest = std::move(digest),
        };
    }

    InvocationOwner owner(std::string invocation = "root", std::string executable = "example.rule",
                          std::string binding = "example.binding") {
        return InvocationOwner {
            .execution = ExecutionId {"execution-1"},
            .invocation = InvocationId {std::move(invocation)},
            .executable = ExecutableId {std::move(executable)},
            .binding = BindingId {std::move(binding)},
        };
    }

    EffectCallPolicy policy(const ReceiptEligibility eligibility = ReceiptEligibility::queued,
                            const Classification ceiling = Classification::secret,
                            std::vector<std::string> categories = {"identity", "telemetry"}) {
        return EffectCallPolicy {
            .snapshot = {.policy_id = "operator.effects.v1",
                         .policy_digest = "sha256:operator-effects-v1",
                         .sink_ceiling = label(ceiling, std::move(categories)),
                         .dry_run = eligibility == ReceiptEligibility::dry_run},
            .eligibility = eligibility,
        };
    }

    EffectDraft draft(std::string reach, std::string text,
                      const ReceiptEligibility eligibility = ReceiptEligibility::queued,
                      const std::uint32_t source_begin = 1) {
        return EffectDraft {
            .reach_key = std::move(reach),
            .kind = "post",
            .payload = frozen(std::move(text)),
            .span = span(source_begin),
            .policy = policy(eligibility),
            .control_label = label(),
        };
    }

    ServiceCallSpec service_call(std::string canonical_key = "fingerprint.resolve",
                                 std::string request_id = "service-request-1") {
        return ServiceCallSpec {
            .canonical_key = std::move(canonical_key),
            .request = {.request_id = RequestId {std::move(request_id)},
                        .capability = CapabilityId {"machine-fingerprint/v1"},
                        .request_schema = SchemaId {"machine-fingerprint/request/v1"},
                        .arguments = frozen("machine-1", Classification::internal),
                        .deadline_unix_ms = 10'000},
            .retry = {.maximum_attempts = 2, .base_delay_ms = 100, .maximum_delay_ms = 1'000},
            .cache = ServiceCachePolicy {.scope_key = "tenant-1/peer-1", .ttl_ms = 1'000},
            .request_ceiling = label(Classification::internal),
            .response_ceiling = label(Classification::sensitive, {"identity"}),
        };
    }

    RecorderEvent recorder_event(const std::uint64_t sequence) {
        return RecorderEvent {
            .sequence = sequence,
            .kind = "branch",
            .span = span(static_cast<std::uint32_t>(sequence)),
            .label = label(),
            .summary = "event-" + std::to_string(sequence),
        };
    }

    EffectIntent vm_intent(const std::uint64_t sequence, const InvocationOwner &intent_owner, std::string text,
                           const bool dry_run = false) {
        const auto id = "vm:" + intent_owner.invocation.value + ":effect:" + std::to_string(sequence);
        return EffectIntent {
            .id = IntentId {id},
            .invocation = intent_owner.invocation,
            .owner = intent_owner.executable,
            .binding = intent_owner.binding,
            .sequence = sequence,
            .kind = "post",
            .payload = frozen(std::move(text)),
            .span = span(static_cast<std::uint32_t>(sequence * 10U)),
            .policy = {.policy_id = "vm.policy",
                       .policy_digest = "vm.policy.v1",
                       .sink_ceiling = label(Classification::secret, {"identity", "telemetry"}),
                       .dry_run = dry_run},
            .disposition = EffectDisposition::pending,
            .idempotency_key = "execution-1:" + id,
        };
    }

    VmStep vm_step(const VmStepState state, std::vector<EffectIntent> effects = {},
                   std::vector<RecorderEvent> recorder = {}, std::optional<EvaluationResult> result = std::nullopt) {
        return VmStep {
            .state = state,
            .fact_requests = {},
            .scan_requests = {},
            .capability_requests = {},
            .state_requests = {},
            .history_requests = {},
            .journal_delta = std::move(effects),
            .recorder_delta = std::move(recorder),
            .yielded_value = std::nullopt,
            .result = std::move(result),
        };
    }

    EvaluationResult clean_result(const bool verdict, std::vector<EffectIntent> effects) {
        for (auto &effect : effects) {
            if (effect.disposition == EffectDisposition::pending) {
                effect.disposition = EffectDisposition::committed;
            }
        }
        return EvaluationResult {
            .outcome = verdict ? EvaluationOutcome::match : EvaluationOutcome::no_match,
            .verdict = verdict,
            .committed_effects = std::move(effects),
            .committed_events = {},
            .state_mutations = {},
            .fault = std::nullopt,
        };
    }

    ServiceBindingPolicy service_binding() {
        return ServiceBindingPolicy {
            .binding_key = "operator/fingerprint/v1",
            .capability = CapabilityId {"machine-fingerprint/v1"},
            .request_schema = SchemaId {"machine-fingerprint/request/v1"},
            .retry = {.maximum_attempts = 2, .base_delay_ms = 100, .maximum_delay_ms = 1'000},
            .cache = ServiceCachePolicy {.scope_key = "tenant-1/peer-1", .ttl_ms = 1'000},
            .request_ceiling = label(Classification::internal),
            .response_ceiling = label(Classification::sensitive, {"identity"}),
        };
    }

    struct RecordingServiceTransport final: IServiceTransport {
        std::vector<ServiceAttempt> attempts;
        std::vector<ServiceAttempt> cancellations;
        std::optional<ServiceResult> reject_next;

        std::expected<void, ServiceResult> dispatch(const ServiceAttempt &attempt) override {
            attempts.push_back(attempt);
            if (reject_next.has_value()) {
                auto result = std::move(*reject_next);
                reject_next.reset();
                return std::unexpected(std::move(result));
            }
            return {};
        }

        void cancel(const ServiceAttempt &attempt) noexcept override { cancellations.push_back(attempt); }
    };

    struct CountingOutboxStore final: IOutboxDeliveryStore {
        explicit CountingOutboxStore(OutboxQueue &selected): queue {selected} {}

        OutboxQueue &queue;
        std::uint64_t claims {};
        std::uint64_t settlements {};

        std::expected<OutboxLease, OutboxError> claim(std::string worker, const std::uint64_t now_unix_ms,
                                                      const std::uint64_t lease_duration_ms) override {
            ++claims;
            return queue.claim(std::move(worker), now_unix_ms, lease_duration_ms);
        }

        std::expected<ActionDeliveryRecord, OutboxError>
        acknowledge(const OutboxLease &lease, const std::uint64_t now_unix_ms,
                    std::optional<FrozenValue> acknowledgment) override {
            ++settlements;
            return queue.acknowledge(lease, now_unix_ms, std::move(acknowledgment));
        }

        std::expected<ActionDeliveryRecord, OutboxError> fail(const OutboxLease &lease, const DeliveryFailure &failure,
                                                              const std::uint64_t now_unix_ms) override {
            ++settlements;
            return queue.fail(lease, failure, now_unix_ms);
        }
    };

    struct RecordingActionTransport final: IActionTransport {
        std::uint64_t dispatches {};
        std::expected<ActionDispatchSuccess, ActionDispatchFailure> next = ActionDispatchSuccess {};

        std::expected<ActionDispatchSuccess, ActionDispatchFailure> dispatch(const OutboxLease &lease) override {
            (void) lease;
            ++dispatches;
            return next;
        }
    };

    TEST_CASE("effect journal preserves order and deduplicates one resumed reach") {
        auto created = EffectJournal::create(owner());
        REQUIRE(created.has_value());
        auto journal = std::move(*created);

        const auto first = journal.append(journal.root_scope(), draft("pc:10/frame:1/iteration:0", "first", {}, 10));
        REQUIRE(first.has_value());

        // A suspension resumes at the same VM reach token. The journal returns the
        // existing receipt instead of allocating a second intent.
        const auto resumed = journal.append(journal.root_scope(), draft("pc:10/frame:1/iteration:0", "first", {}, 10));
        REQUIRE(resumed.has_value());
        REQUIRE(resumed->intent == first->intent);
        REQUIRE(journal.intents().size() == 1);

        const auto second = journal.append(journal.root_scope(), draft("pc:20/frame:1/iteration:0", "second", {}, 20));
        REQUIRE(second.has_value());
        REQUIRE(journal.intents().size() == 2);
        REQUIRE(journal.intents()[0].sequence == 1);
        REQUIRE(journal.intents()[1].sequence == 2);

        const auto finalized = journal.finish_root(EvaluationOutcome::no_match);
        REQUIRE(finalized.has_value());
        REQUIRE(finalized->clean);
        REQUIRE(finalized->durable_commit_allowed());
        REQUIRE(finalized->dispatchable_intents().size() == 2);
        REQUIRE(finalized->intents[0].disposition == EffectDisposition::committed);
        REQUIRE(finalized->intents[1].disposition == EffectDisposition::committed);

        auto replayed_create = EffectJournal::create(owner());
        REQUIRE(replayed_create.has_value());
        auto replayed = std::move(*replayed_create);
        REQUIRE(
            replayed.append(replayed.root_scope(), draft("pc:10/frame:1/iteration:0", "first", {}, 10)).has_value());
        REQUIRE(
            replayed.append(replayed.root_scope(), draft("pc:20/frame:1/iteration:0", "second", {}, 20)).has_value());
        const auto replayed_final = replayed.finish_root(EvaluationOutcome::no_match);
        REQUIRE(replayed_final.has_value());
        REQUIRE(compare_effect_journals(finalized->intents, replayed_final->intents).empty());
    }

    TEST_CASE("nested transactions default to rollback and committed children retain ownership") {
        auto created = EffectJournal::create(owner());
        REQUIRE(created.has_value());
        auto journal = std::move(*created);

        const auto abandoned = journal.open_scope(journal.root_scope(), JournalScopeKind::explicit_transaction,
                                                  owner("transaction-abandoned"));
        REQUIRE(abandoned.has_value());
        const auto abandoned_effect = journal.append(*abandoned, draft("tx-a/0", "abandoned"));
        REQUIRE(abandoned_effect.has_value());
        REQUIRE(journal.close_scope(*abandoned, JournalExit::normal).has_value());
        REQUIRE(journal.receipt(abandoned_effect->intent)->final_disposition == EffectDisposition::rolled_back);

        const auto committed = journal.open_scope(journal.root_scope(), JournalScopeKind::explicit_transaction,
                                                  owner("transaction-committed"));
        REQUIRE(committed.has_value());
        const auto committed_effect = journal.append(*committed, draft("tx-b/0", "committed"));
        REQUIRE(committed_effect.has_value());
        REQUIRE(journal.request_commit(*committed).has_value());
        REQUIRE(journal.close_scope(*committed, JournalExit::normal).has_value());

        const auto exceptional = journal.open_scope(journal.root_scope(), JournalScopeKind::explicit_transaction,
                                                    owner("transaction-exceptional"));
        REQUIRE(exceptional.has_value());
        const auto exceptional_effect = journal.append(*exceptional, draft("tx-c/0", "exceptional"));
        REQUIRE(exceptional_effect.has_value());
        REQUIRE(journal.request_commit(*exceptional).has_value());
        REQUIRE(journal.close_scope(*exceptional, JournalExit::exceptional).has_value());

        const auto child = journal.open_scope(journal.root_scope(), JournalScopeKind::child_invocation,
                                              owner("child-1", "example.child", "example.child.binding"));
        REQUIRE(child.has_value());
        const auto child_effect = journal.append(*child, draft("child/0", "child"));
        REQUIRE(child_effect.has_value());
        REQUIRE(journal.close_scope(*child, JournalExit::normal).has_value());

        const auto finalized = journal.finish_root(EvaluationOutcome::match);
        REQUIRE(finalized.has_value());
        const auto durable = finalized->durable_intents();
        REQUIRE(durable.size() == 2);
        REQUIRE(durable[0].id == committed_effect->intent);
        REQUIRE(durable[1].id == child_effect->intent);
        REQUIRE(durable[1].invocation == InvocationId {"child-1"});
        REQUIRE(durable[1].owner == ExecutableId {"example.child"});
        REQUIRE(journal.receipt(exceptional_effect->intent)->final_disposition == EffectDisposition::rolled_back);
    }

    TEST_CASE("faulted roots roll back queued dry-run and suppressed intents") {
        auto created = EffectJournal::create(owner());
        REQUIRE(created.has_value());
        auto journal = std::move(*created);

        const auto queued = journal.append(journal.root_scope(), draft("root/queued", "queued"));
        const auto dry_run =
            journal.append(journal.root_scope(), draft("root/dry", "dry", ReceiptEligibility::dry_run));
        const auto suppressed = journal.append(
            journal.root_scope(), draft("root/suppressed", "secret-not-retained", ReceiptEligibility::suppressed));
        REQUIRE(queued.has_value());
        REQUIRE(dry_run.has_value());
        REQUIRE(suppressed.has_value());
        REQUIRE(std::holds_alternative<std::monostate>(journal.intents()[2].payload.value.node->data));
        REQUIRE(suppressed->call_site_eligibility == ReceiptEligibility::suppressed);

        const auto finalized = journal.finish_root(EvaluationOutcome::faulted);
        REQUIRE(finalized.has_value());
        REQUIRE_FALSE(finalized->clean);
        REQUIRE_FALSE(finalized->durable_commit_allowed());
        REQUIRE(finalized->durable_intents().empty());
        REQUIRE(std::ranges::all_of(finalized->intents, [](const EffectIntent &intent) {
            return intent.disposition == EffectDisposition::rolled_back;
        }));
        REQUIRE(journal.receipt(dry_run->intent)->call_site_eligibility == ReceiptEligibility::dry_run);
        REQUIRE(journal.receipt(dry_run->intent)->final_disposition == EffectDisposition::rolled_back);
    }

    TEST_CASE("clean roots retain dry-run and suppressed audit dispositions without dispatch") {
        auto created = EffectJournal::create(owner());
        REQUIRE(created.has_value());
        auto journal = std::move(*created);
        REQUIRE(
            journal.append(journal.root_scope(), draft("root/dry", "dry", ReceiptEligibility::dry_run)).has_value());
        REQUIRE(
            journal.append(journal.root_scope(), draft("root/suppressed", "suppressed", ReceiptEligibility::suppressed))
                .has_value());

        const auto finalized = journal.finish_root(EvaluationOutcome::no_match);
        REQUIRE(finalized.has_value());
        REQUIRE(finalized->durable_intents().size() == 2);
        REQUIRE(finalized->dispatchable_intents().empty());
        REQUIRE(finalized->intents[0].disposition == EffectDisposition::dry_run);
        REQUIRE(finalized->intents[1].disposition == EffectDisposition::suppressed);
    }

    TEST_CASE("control labels join monotonically and sinks reject implicit flows") {
        ControlLabelStack labels;
        REQUIRE(labels.current() == label());
        const auto secret_region = labels.push(label(Classification::secret, {"identity"}));
        REQUIRE(labels.current() == label(Classification::secret, {"identity"}));

        const auto tainted = apply_control_label(frozen("constant"), labels.current());
        REQUIRE(tainted.label == label(Classification::secret, {"identity"}));

        auto created = EffectJournal::create(owner());
        REQUIRE(created.has_value());
        auto journal = std::move(*created);
        auto implicit_flow = draft("secret-branch/post", "constant");
        implicit_flow.control_label = labels.current();
        implicit_flow.policy = policy(ReceiptEligibility::queued, Classification::internal, {"identity"});
        const auto rejected = journal.append(journal.root_scope(), implicit_flow);
        REQUIRE_FALSE(rejected.has_value());
        REQUIRE(rejected.error().code == EffectErrorCode::label_rejected);
        REQUIRE(journal.intents().empty());

        REQUIRE(labels.pop(secret_region).has_value());
        REQUIRE(labels.current() == label());
        REQUIRE_FALSE(labels.pop(secret_region).has_value());
    }

    TEST_CASE("only an authorized named transform can declassify") {
        const auto source = frozen("raw-identity", Classification::secret, {"identity"});
        const auto transformed = frozen("redacted-identity", Classification::secret, {"identity"});
        const DeclassifierPermit permit {
            .transform_id = "redact.identity",
            .transform_version = "1",
            .authorized_binding = BindingId {"example.binding"},
            .accepted_input = label(Classification::secret, {"identity"}),
            .output_label = label(Classification::internal),
        };

        const auto rejected = apply_declassification(source, transformed, BindingId {"other.binding"}, permit, span());
        REQUIRE_FALSE(rejected.has_value());
        REQUIRE(rejected.error().code == LabelErrorCode::caller_not_authorized);

        const auto accepted =
            apply_declassification(source, transformed, BindingId {"example.binding"}, permit, span());
        REQUIRE(accepted.has_value());
        REQUIRE(accepted->value.label == label(Classification::internal));
        REQUIRE(accepted->audit.input_label == label(Classification::secret, {"identity"}));
        REQUIRE(accepted->audit.output_digest == transformed.canonical_digest);
    }

    TEST_CASE("flight recorder keeps bounded head and tail with an explicit dropped marker") {
        auto created = FlightRecorder::create(FlightRecorderConfig {
            .armed = true,
            .publish_initially = false,
            .maximum_entries = 5,
            .maximum_bytes = 10'000,
            .retention_ceiling = label(Classification::secret),
        });
        REQUIRE(created.has_value());
        auto recorder = std::move(*created);

        for (std::uint64_t sequence = 1; sequence <= 8; ++sequence) {
            REQUIRE(recorder.record(recorder_event(sequence)).has_value());
        }

        const auto snapshot = recorder.snapshot();
        REQUIRE(snapshot.armed);
        REQUIRE(snapshot.truncated);
        REQUIRE_FALSE(snapshot.publication_requested);
        REQUIRE(snapshot.entries.size() == 5);
        REQUIRE(std::get<RecorderEvent>(snapshot.entries[0]).sequence == 1);
        REQUIRE(std::get<RecorderEvent>(snapshot.entries[1]).sequence == 2);
        const auto &dropped = std::get<DroppedRecorderEvents>(snapshot.entries[2]);
        REQUIRE(dropped.first_sequence == 3);
        REQUIRE(dropped.last_sequence == 6);
        REQUIRE(dropped.event_count == 4);
        REQUIRE(std::get<RecorderEvent>(snapshot.entries[3]).sequence == 7);
        REQUIRE(std::get<RecorderEvent>(snapshot.entries[4]).sequence == 8);
        REQUIRE(snapshot.estimated_bytes <= 10'000);
        REQUIRE(recorder.published_snapshot().entries.empty());

        REQUIRE(recorder.request_publication());
        REQUIRE(recorder.published_snapshot().entries.size() == 5);
        recorder.disable_publication();
        REQUIRE(recorder.published_snapshot().entries.empty());

        const auto non_monotonic = recorder.record(recorder_event(8));
        REQUIRE_FALSE(non_monotonic.has_value());
        REQUIRE(non_monotonic.error().code == RecorderErrorCode::non_monotonic_sequence);
    }

    TEST_CASE("an unarmed recorder cannot be armed retroactively") {
        auto created = FlightRecorder::create(FlightRecorderConfig {
            .armed = false,
            .publish_initially = true,
            .maximum_entries = 5,
            .maximum_bytes = 1'024,
            .retention_ceiling = label(Classification::secret),
        });
        REQUIRE(created.has_value());
        auto recorder = std::move(*created);
        REQUIRE(recorder.record(recorder_event(1)).has_value());
        REQUIRE_FALSE(recorder.request_publication());
        REQUIRE(recorder.snapshot().entries.empty());
    }

    TEST_CASE("flight recorder redacts summaries above its retention ceiling") {
        auto created = FlightRecorder::create(FlightRecorderConfig {
            .armed = true,
            .publish_initially = true,
            .maximum_entries = 5,
            .maximum_bytes = 1'024,
            .retention_ceiling = label(Classification::internal),
        });
        REQUIRE(created.has_value());
        auto recorder = std::move(*created);
        auto event = recorder_event(1);
        event.label = label(Classification::secret, {"identity"});
        event.summary = "must-not-leave-the-recorder";
        REQUIRE(recorder.record(std::move(event)).has_value());

        const auto snapshot = recorder.published_snapshot();
        REQUIRE(snapshot.redacted_events == 1);
        REQUIRE(std::get<RecorderEvent>(snapshot.entries[0]).summary == "<redacted>");
    }

    TEST_CASE("captured replay resolves inputs but blocks commit and dispatch") {
        auto host_created = CapturedInputReplayHost::create({CapturedInput {
            .key = "service:fingerprint.resolve/request-1",
            .kind = CapturedInputKind::service,
            .value = frozen("fingerprint-result", Classification::sensitive, {"identity"}),
            .terminal_code = {},
        }});
        REQUIRE(host_created.has_value());
        auto host = std::move(*host_created);
        REQUIRE(host.resolve("service:fingerprint.resolve/request-1").has_value());
        REQUIRE_FALSE(host.resolve("service:missing").has_value());

        auto journal_created = EffectJournal::create(owner(), ExecutionMode::replay);
        REQUIRE(journal_created.has_value());
        auto journal = std::move(*journal_created);
        REQUIRE(journal.append(journal.root_scope(), draft("replay/post", "would-post")).has_value());
        const auto finalized = journal.finish_root(EvaluationOutcome::match);
        REQUIRE(finalized.has_value());
        REQUIRE_FALSE(finalized->durable_commit_allowed());
        REQUIRE(finalized->durable_intents().empty());
        REQUIRE(finalized->dispatchable_intents().empty());
        REQUIRE(finalized->intents[0].disposition == EffectDisposition::committed);

        REQUIRE_FALSE(host.dispatch(finalized->intents[0]).has_value());
        REQUIRE_FALSE(host.commit(*finalized).has_value());
        REQUIRE(host.blocked_dispatches() == 1);
        REQUIRE(host.blocked_commits() == 1);
        REQUIRE(host.live_dispatches() == 0);
    }

    TEST_CASE("service task group preserves deadline retry identity and explicit cache policy") {
        ServiceCache cache;
        auto group_created = ServiceTaskGroup::create(7, TaskGroupExitPolicy::cancel_pending, 0x1234, 2);
        REQUIRE(group_created.has_value());
        auto group = std::move(*group_created);
        const auto task = group.add_call(service_call());
        REQUIRE(task.has_value());
        REQUIRE(group.state(*task) == ServiceTaskState::cold);
        REQUIRE(group.active_count() == 0);

        const auto started = group.start(*task, 1'000, &cache);
        REQUIRE(started.has_value());
        REQUIRE(started->attempt.has_value());
        REQUIRE(started->attempt->attempt == 1);
        REQUIRE(group.active_count() == 1);
        const auto first_idempotency = started->attempt->idempotency_key;

        const auto transient = group.accept(*task, 1,
                                            ServiceResult {.status = ServiceStatus::rate_limited,
                                                           .value = std::nullopt,
                                                           .retry_after_ms = 50,
                                                           .diagnostic_code = "HTTP_429"},
                                            1'100, &cache);
        REQUIRE(transient.has_value());
        REQUIRE(transient->state == ServiceTaskState::retry_wait);
        REQUIRE(transient->retry_at_unix_ms == 1'150);
        REQUIRE(group.active_count() == 0);
        REQUIRE_FALSE(group.resume_retry(*task, 1'149).has_value());

        const auto retried = group.resume_retry(*task, 1'150);
        REQUIRE(retried.has_value());
        REQUIRE(retried->attempt == 2);
        REQUIRE(retried->idempotency_key == first_idempotency);
        const auto completed =
            group.accept(*task, 2,
                         ServiceResult {.status = ServiceStatus::ok,
                                        .value = frozen("fingerprint", Classification::sensitive, {"identity"}),
                                        .retry_after_ms = std::nullopt,
                                        .diagnostic_code = {}},
                         1'200, &cache);
        REQUIRE(completed.has_value());
        REQUIRE(completed->state == ServiceTaskState::completed);
        REQUIRE(group.result(*task)->status == ServiceStatus::ok);
        REQUIRE(cache.size() == 1);

        const auto cached_task = group.add_call(service_call("fingerprint.resolve", "service-request-2"));
        REQUIRE(cached_task.has_value());
        const auto cached = group.start(*cached_task, 1'300, &cache);
        REQUIRE(cached.has_value());
        REQUIRE(cached->cache_hit);
        REQUIRE_FALSE(cached->attempt.has_value());
        REQUIRE(cached->state == ServiceTaskState::completed);
        REQUIRE(group.active_count() == 0);
    }

    TEST_CASE("service response labels are checked before a result enters the task") {
        auto group_created = ServiceTaskGroup::create(8, TaskGroupExitPolicy::cancel_pending, 9);
        REQUIRE(group_created.has_value());
        auto group = std::move(*group_created);
        auto spec = service_call();
        spec.response_ceiling = label(Classification::internal);
        spec.cache = std::nullopt;
        const auto task = group.add_call(std::move(spec));
        REQUIRE(task.has_value());
        REQUIRE(group.start(*task, 1'000).has_value());
        const auto rejected = group.accept(*task, 1,
                                           ServiceResult {.status = ServiceStatus::ok,
                                                          .value = frozen("secret", Classification::secret),
                                                          .retry_after_ms = std::nullopt,
                                                          .diagnostic_code = {}},
                                           1'100);
        REQUIRE_FALSE(rejected.has_value());
        REQUIRE(rejected.error().code == ServiceErrorCode::response_label_rejected);
        REQUIRE(group.state(*task) == ServiceTaskState::failed);
    }

    TEST_CASE("service request labels are checked before a cold task exists") {
        auto group_created = ServiceTaskGroup::create(81, TaskGroupExitPolicy::cancel_pending, 9);
        REQUIRE(group_created.has_value());
        auto group = std::move(*group_created);
        auto spec = service_call();
        spec.request.arguments = frozen("secret-request", Classification::secret, {"identity"});
        spec.request_ceiling = label(Classification::internal, {"identity"});
        const auto rejected = group.add_call(std::move(spec));
        REQUIRE_FALSE(rejected.has_value());
        REQUIRE(rejected.error().code == ServiceErrorCode::request_label_rejected);
    }

    TEST_CASE("task groups cancel by default and wait only when requested") {
        auto cancel_created = ServiceTaskGroup::create(9, TaskGroupExitPolicy::cancel_pending, 1);
        REQUIRE(cancel_created.has_value());
        auto cancel_group = std::move(*cancel_created);
        const auto running = cancel_group.add_call(service_call("service.a", "request-a"));
        const auto cold = cancel_group.add_call(service_call("service.b", "request-b"));
        REQUIRE(running.has_value());
        REQUIRE(cold.has_value());
        REQUIRE(cancel_group.start(*running, 1'000).has_value());
        const auto canceled = cancel_group.close(1'100, false);
        REQUIRE(canceled.has_value());
        REQUIRE(canceled->closed);
        REQUIRE(canceled->canceled.size() == 2);
        REQUIRE(cancel_group.state(*running) == ServiceTaskState::canceled);
        REQUIRE(cancel_group.state(*cold) == ServiceTaskState::canceled);
        REQUIRE(cancel_group.active_count() == 0);

        auto wait_created = ServiceTaskGroup::create(10, TaskGroupExitPolicy::wait_pending, 2);
        REQUIRE(wait_created.has_value());
        auto wait_group = std::move(*wait_created);
        auto wait_spec = service_call("service.wait", "request-wait");
        wait_spec.cache = std::nullopt;
        const auto waiting_task = wait_group.add_call(std::move(wait_spec));
        REQUIRE(waiting_task.has_value());
        REQUIRE(wait_group.start(*waiting_task, 1'000).has_value());
        const auto closing = wait_group.close(1'010, false);
        REQUIRE(closing.has_value());
        REQUIRE_FALSE(closing->closed);
        REQUIRE(closing->waiting == std::vector<TaskHandle> {*waiting_task});
        REQUIRE(wait_group
                    .accept(*waiting_task, 1,
                            ServiceResult {.status = ServiceStatus::ok,
                                           .value = frozen("done", Classification::internal),
                                           .retry_after_ms = std::nullopt,
                                           .diagnostic_code = {}},
                            1'020)
                    .has_value());
        REQUIRE(wait_group.closed());
    }

    TEST_CASE("outbox enqueue is idempotent and a restarted queue fences stale leases") {
        auto journal_created = EffectJournal::create(owner());
        REQUIRE(journal_created.has_value());
        auto journal = std::move(*journal_created);
        REQUIRE(journal.append(journal.root_scope(), draft("post/outbox", "payload")).has_value());
        const auto finalized = journal.finish_root(EvaluationOutcome::match);
        REQUIRE(finalized.has_value());
        REQUIRE(finalized->dispatchable_intents().size() == 1);
        const auto &intent = finalized->intents[0];

        auto queue_created = OutboxQueue::create();
        REQUIRE(queue_created.has_value());
        auto queue = std::move(*queue_created);
        const auto inserted = queue.enqueue(*finalized, intent.id, "https://sink.example/v1", 1'000);
        REQUIRE(inserted.has_value());
        REQUIRE(inserted->inserted);
        const auto duplicate = queue.enqueue(*finalized, intent.id, "https://sink.example/v1", 1'000);
        REQUIRE(duplicate.has_value());
        REQUIRE_FALSE(duplicate->inserted);
        REQUIRE(queue.size() == 1);

        const auto first_lease = queue.claim("worker-a", 1'000, 100);
        REQUIRE(first_lease.has_value());
        REQUIRE(first_lease->attempt == 1);
        const auto persisted = queue.snapshot();

        auto restarted_create = OutboxQueue::restore(persisted);
        REQUIRE(restarted_create.has_value());
        auto restarted = std::move(*restarted_create);
        const auto second_lease = restarted.claim("worker-b", 1'100, 100);
        REQUIRE(second_lease.has_value());
        REQUIRE(second_lease->token > first_lease->token);
        REQUIRE(second_lease->attempt == 2);
        const auto stale_ack = restarted.acknowledge(*first_lease, 1'101);
        REQUIRE_FALSE(stale_ack.has_value());
        REQUIRE(stale_ack.error().code == OutboxErrorCode::stale_lease);

        const auto delivered = restarted.acknowledge(*second_lease, 1'101, frozen("ack"));
        REQUIRE(delivered.has_value());
        REQUIRE(delivered->state == OutboxState::delivered);
        REQUIRE(restarted.find(intent.id)->state == OutboxState::delivered);
    }

    TEST_CASE("outbox retries transient failures and dead-letters terminal responses") {
        auto journal_created = EffectJournal::create(owner());
        REQUIRE(journal_created.has_value());
        auto journal = std::move(*journal_created);
        REQUIRE(journal.append(journal.root_scope(), draft("post/retry", "payload")).has_value());
        const auto finalized = journal.finish_root(EvaluationOutcome::match);
        REQUIRE(finalized.has_value());

        auto queue_created = OutboxQueue::create();
        REQUIRE(queue_created.has_value());
        auto queue = std::move(*queue_created);
        REQUIRE(queue.enqueue(*finalized, finalized->intents[0].id, "sink", 1'000, 5'000).has_value());
        const auto first = queue.claim("worker", 1'000, 100);
        REQUIRE(first.has_value());
        const auto retry = queue.fail(*first,
                                      DeliveryFailure {.kind = DeliveryFailureKind::http_status,
                                                       .status_code = 503,
                                                       .retry_after_ms = 10,
                                                       .summary = "unavailable"},
                                      1'001);
        REQUIRE(retry.has_value());
        REQUIRE(retry->state == OutboxState::retry_wait);
        REQUIRE_FALSE(queue.claim("worker", 1'010, 100).has_value());

        const auto second = queue.claim("worker", 1'011, 100);
        REQUIRE(second.has_value());
        const auto dead_letter = queue.fail(*second,
                                            DeliveryFailure {.kind = DeliveryFailureKind::http_status,
                                                             .status_code = 400,
                                                             .retry_after_ms = std::nullopt,
                                                             .summary = "bad request"},
                                            1'012);
        REQUIRE(dead_letter.has_value());
        REQUIRE(dead_letter->state == OutboxState::dead_letter);
        REQUIRE_FALSE(queue.claim("worker", 1'013, 100).has_value());
    }

    TEST_CASE("outbox expires pending work and replay can never enqueue it") {
        auto journal_created = EffectJournal::create(owner(), ExecutionMode::replay);
        REQUIRE(journal_created.has_value());
        auto journal = std::move(*journal_created);
        REQUIRE(journal.append(journal.root_scope(), draft("post/replay", "payload")).has_value());
        const auto finalized = journal.finish_root(EvaluationOutcome::match);
        REQUIRE(finalized.has_value());

        auto queue_created = OutboxQueue::create();
        REQUIRE(queue_created.has_value());
        auto queue = std::move(*queue_created);
        const auto blocked = queue.enqueue(*finalized, finalized->intents[0].id, "sink", 1'000);
        REQUIRE_FALSE(blocked.has_value());
        REQUIRE(blocked.error().code == OutboxErrorCode::replay_forbidden);
        REQUIRE(queue.size() == 0);

        auto live_journal_created = EffectJournal::create(owner());
        REQUIRE(live_journal_created.has_value());
        auto live_journal = std::move(*live_journal_created);
        REQUIRE(live_journal.append(live_journal.root_scope(), draft("post/live-expiry", "payload")).has_value());
        const auto live_finalized = live_journal.finish_root(EvaluationOutcome::match);
        REQUIRE(live_finalized.has_value());
        REQUIRE(queue.enqueue(*live_finalized, live_finalized->intents[0].id, "sink", 1'000, 100).has_value());
        queue.expire_due(1'100);
        REQUIRE(queue.find(live_finalized->intents[0].id)->state == OutboxState::expired);
        REQUIRE_FALSE(queue.claim("worker", 1'100, 100).has_value());
    }

    TEST_CASE("VM step adapter preserves suspended nested reach ownership and replay parity") {
        const auto root_owner = owner();
        const auto child_owner = owner("child-1", "example.child", "example.child.binding");
        const auto root_effect = vm_intent(1, root_owner, "root-effect");
        const auto child_effect = vm_intent(2, child_owner, "child-effect");
        const auto transaction_effect = vm_intent(3, root_owner, "rolled-back-effect");
        const FlightRecorderConfig recorder_config {
            .armed = true,
            .publish_initially = true,
            .maximum_entries = 16,
            .maximum_bytes = 8'192,
            .retention_ceiling = label(Classification::secret, {"identity"}),
        };

        auto live_created = ExecutionJournalAdapter::create(ExecutionJournalConfig {
            .root_owner = root_owner,
            .mode = ExecutionMode::live,
            .journal_limits = {},
            .recorder = recorder_config,
            .parity_expectation = std::nullopt,
        });
        REQUIRE(live_created.has_value());
        auto live = std::move(*live_created);

        const auto suspended = vm_step(VmStepState::waiting_for_capabilities, {root_effect}, {recorder_event(1)});
        REQUIRE(live.observe_step(suspended, live.root_scope()).has_value());
        // A host may re-observe an unchanged suspension snapshot. Both contract
        // deltas are idempotent and retain their original IDs/sequences.
        REQUIRE(live.observe_step(suspended, live.root_scope()).has_value());

        const auto child = live.open_scope(live.root_scope(), JournalScopeKind::child_invocation, child_owner);
        REQUIRE(child.has_value());
        const auto secret_branch = live.push_control(label(Classification::sensitive, {"identity"}));
        REQUIRE(live.observe_step(vm_step(VmStepState::yielded, {child_effect}), *child).has_value());
        REQUIRE(live.pop_control(secret_branch).has_value());
        REQUIRE(live.close_scope(*child, JournalExit::normal).has_value());

        const auto transaction = live.open_scope(live.root_scope(), JournalScopeKind::explicit_transaction, root_owner);
        REQUIRE(transaction.has_value());
        REQUIRE(live.observe_step(vm_step(VmStepState::yielded, {transaction_effect}), *transaction).has_value());
        REQUIRE(live.close_scope(*transaction, JournalExit::normal).has_value());

        const auto terminal = vm_step(VmStepState::complete, {}, {recorder_event(2)},
                                      clean_result(true, {root_effect, child_effect, transaction_effect}));
        REQUIRE(live.observe_step(terminal, live.root_scope()).has_value());
        const auto *live_completion = live.completion();
        REQUIRE(live_completion != nullptr);
        REQUIRE(live_completion->result.outcome == EvaluationOutcome::match);
        REQUIRE(live_completion->result.committed_effects.size() == 2);
        REQUIRE(live_completion->journal.intents.size() == 3);
        REQUIRE(live_completion->journal.intents[1].invocation == child_owner.invocation);
        REQUIRE(live_completion->journal.intents[1].payload.label == label(Classification::sensitive, {"identity"}));
        REQUIRE(live_completion->journal.intents[2].disposition == EffectDisposition::rolled_back);
        REQUIRE(live_completion->recorder.entries.size() == 2);

        const ExecutionReplayExpectation expectation {
            .result = live_completion->result,
            .journal = live_completion->journal.intents,
            .recorder = live_completion->recorder,
        };
        auto replay_created = ExecutionJournalAdapter::create(ExecutionJournalConfig {
            .root_owner = root_owner,
            .mode = ExecutionMode::replay,
            .journal_limits = {},
            .recorder = recorder_config,
            .parity_expectation = expectation,
        });
        REQUIRE(replay_created.has_value());
        auto replay = std::move(*replay_created);
        REQUIRE(replay.observe_step(suspended, replay.root_scope()).has_value());
        REQUIRE(replay.observe_step(suspended, replay.root_scope()).has_value());
        const auto replay_child =
            replay.open_scope(replay.root_scope(), JournalScopeKind::child_invocation, child_owner);
        REQUIRE(replay_child.has_value());
        const auto replay_secret = replay.push_control(label(Classification::sensitive, {"identity"}));
        REQUIRE(replay.observe_step(vm_step(VmStepState::yielded, {child_effect}), *replay_child).has_value());
        REQUIRE(replay.pop_control(replay_secret).has_value());
        REQUIRE(replay.close_scope(*replay_child, JournalExit::normal).has_value());
        const auto replay_transaction =
            replay.open_scope(replay.root_scope(), JournalScopeKind::explicit_transaction, root_owner);
        REQUIRE(replay_transaction.has_value());
        REQUIRE(
            replay.observe_step(vm_step(VmStepState::yielded, {transaction_effect}), *replay_transaction).has_value());
        REQUIRE(replay.close_scope(*replay_transaction, JournalExit::normal).has_value());
        REQUIRE(replay.observe_step(terminal, replay.root_scope()).has_value());
        const auto *replay_completion = replay.completion();
        REQUIRE(replay_completion != nullptr);
        REQUIRE(replay_completion->parity_differences.empty());
        REQUIRE_FALSE(replay_completion->journal.durable_commit_allowed());
        REQUIRE(replay_completion->result.committed_effects.size() == 2);
    }

    TEST_CASE("VM journal imports reject foreign ownership reordered sequences and identity reuse") {
        auto created = EffectJournal::create(owner());
        REQUIRE(created.has_value());
        auto journal = std::move(*created);

        const auto foreign = vm_intent(1, owner("foreign", "foreign.rule", "foreign.binding"), "foreign");
        const auto foreign_result = journal.append_vm_intent(journal.root_scope(), foreign);
        REQUIRE_FALSE(foreign_result.has_value());
        REQUIRE(foreign_result.error().code == EffectErrorCode::ownership_mismatch);

        const auto reordered = vm_intent(2, owner(), "second-before-first");
        const auto reordered_result = journal.append_vm_intent(journal.root_scope(), reordered);
        REQUIRE_FALSE(reordered_result.has_value());
        REQUIRE(reordered_result.error().code == EffectErrorCode::sequence_mismatch);

        const auto first = vm_intent(1, owner(), "first");
        REQUIRE(journal.append_vm_intent(journal.root_scope(), first).has_value());
        auto changed = first;
        changed.payload = frozen("changed");
        const auto reused = journal.append_vm_intent(journal.root_scope(), changed);
        REQUIRE_FALSE(reused.has_value());
        REQUIRE(reused.error().code == EffectErrorCode::duplicate_reach_mismatch);
        REQUIRE(journal.intents().size() == 1);
    }

    TEST_CASE("VM terminal faults and cancellation roll back effects and candidate state") {
        const auto root_owner = owner();
        const auto effect = vm_intent(1, root_owner, "candidate-effect");

        const auto verify_terminal = [&](const VmStepState state, const EvaluationOutcome outcome) {
            auto created = ExecutionJournalAdapter::create(ExecutionJournalConfig {
                .root_owner = root_owner,
                .mode = ExecutionMode::live,
                .journal_limits = {},
                .recorder = FlightRecorderConfig {},
                .parity_expectation = std::nullopt,
            });
            REQUIRE(created.has_value());
            auto adapter = std::move(*created);
            REQUIRE(adapter.observe_step(vm_step(VmStepState::yielded, {effect}), adapter.root_scope()).has_value());
            EvaluationResult result {
                .outcome = outcome,
                .verdict = std::nullopt,
                .committed_effects = {},
                .committed_events = {},
                .state_mutations = {StateMutation {.owner = root_owner.executable,
                                                   .namespace_name = "candidate",
                                                   .key = "discard-me",
                                                   .expected_version = 1,
                                                   .value = frozen("state")}},
                .fault = FaultChain {.frames = {FaultFrame {.code = "PYVM4002",
                                                            .message = "terminal unwind",
                                                            .executable = root_owner.executable,
                                                            .span = span()}},
                                     .double_fault = false,
                                     .triple_fault = false},
            };
            REQUIRE(adapter.observe_step(vm_step(state, {}, {}, std::move(result)), adapter.root_scope()).has_value());
            const auto *completion = adapter.completion();
            REQUIRE(completion != nullptr);
            REQUIRE(completion->result.outcome == outcome);
            REQUIRE(completion->result.committed_effects.empty());
            REQUIRE(completion->result.state_mutations.empty());
            REQUIRE(completion->journal.intents[0].disposition == EffectDisposition::rolled_back);
            REQUIRE_FALSE(completion->journal.durable_commit_allowed());
        };

        verify_terminal(VmStepState::faulted, EvaluationOutcome::faulted);
        verify_terminal(VmStepState::canceled, EvaluationOutcome::canceled);
    }

    TEST_CASE("service coordinator retries captures caches replays and cancels typed VM requests") {
        auto resolver_created = StaticServiceBindingResolver::create({service_binding()});
        REQUIRE(resolver_created.has_value());
        auto resolver = std::move(*resolver_created);
        RecordingServiceTransport transport;
        auto coordinator_created =
            ServiceCoordinator::create(ServiceCoordinatorConfig {.group_id = 100,
                                                                 .exit_policy = TaskGroupExitPolicy::cancel_pending,
                                                                 .deterministic_seed = 0x1234,
                                                                 .maximum_active = 2,
                                                                 .mode = ExecutionMode::live,
                                                                 .replay_captures = {}},
                                       resolver, &transport);
        REQUIRE(coordinator_created.has_value());
        auto coordinator = std::move(*coordinator_created);

        const auto request = service_call().request;
        const std::vector<CapabilityRequest> requests {request};
        const auto scheduled = coordinator.schedule(requests, 1'000);
        REQUIRE(scheduled.has_value());
        REQUIRE(scheduled->attempts.size() == 1);
        const auto first_attempt = scheduled->attempts[0];
        REQUIRE(coordinator
                    .complete(first_attempt,
                              ServiceResult {.status = ServiceStatus::rate_limited,
                                             .value = std::nullopt,
                                             .retry_after_ms = 50,
                                             .diagnostic_code = "HTTP_429"},
                              1'100)
                    .has_value());
        REQUIRE(coordinator.take_responses().empty());
        REQUIRE(coordinator.poll(1'149)->empty());
        const auto retried = coordinator.poll(1'150);
        REQUIRE(retried.has_value());
        REQUIRE(retried->size() == 1);
        REQUIRE((*retried)[0].attempt == 2);
        REQUIRE((*retried)[0].idempotency_key == first_attempt.idempotency_key);
        REQUIRE(coordinator
                    .complete((*retried)[0],
                              ServiceResult {.status = ServiceStatus::ok,
                                             .value = frozen("fingerprint", Classification::sensitive, {"identity"}),
                                             .retry_after_ms = std::nullopt,
                                             .diagnostic_code = {}},
                              1'200)
                    .has_value());
        const auto responses = coordinator.take_responses();
        REQUIRE(responses.size() == 1);
        REQUIRE(responses[0].request_id == request.request_id);
        REQUIRE(responses[0].status == FactTerminalStatus::value);
        REQUIRE(coordinator.captures().size() == 1);
        REQUIRE(coordinator.captures()[0].attempts.size() == 2);

        auto cached_request = service_call("fingerprint.resolve", "service-request-cached").request;
        const std::vector<CapabilityRequest> cached_requests {cached_request};
        const auto cached = coordinator.schedule(cached_requests, 1'300);
        REQUIRE(cached.has_value());
        REQUIRE(cached->cache_hits == 1);
        REQUIRE(cached->attempts.empty());
        REQUIRE(transport.attempts.size() == 2);
        REQUIRE(coordinator.take_responses().size() == 1);
        REQUIRE(coordinator.captures().size() == 2);
        REQUIRE(coordinator.captures()[1].cache_hit);

        const std::vector<ServiceCapture> replay_captures {coordinator.captures()[0]};
        auto replay_created =
            ServiceCoordinator::create(ServiceCoordinatorConfig {.group_id = 101,
                                                                 .exit_policy = TaskGroupExitPolicy::cancel_pending,
                                                                 .deterministic_seed = 0x1234,
                                                                 .maximum_active = 2,
                                                                 .mode = ExecutionMode::replay,
                                                                 .replay_captures = replay_captures},
                                       resolver);
        REQUIRE(replay_created.has_value());
        auto replay = std::move(*replay_created);
        const auto replayed = replay.schedule(requests, 1'000);
        REQUIRE(replayed.has_value());
        REQUIRE(replay.live_dispatches() == 0);
        REQUIRE(replay.blocked_replay_dispatches() == 2);
        const auto replay_responses = replay.take_responses();
        REQUIRE(replay_responses.size() == 1);
        REQUIRE(replay_responses[0].value->canonical_digest == responses[0].value->canonical_digest);

        RecordingServiceTransport cancel_transport;
        auto cancel_created =
            ServiceCoordinator::create(ServiceCoordinatorConfig {.group_id = 102,
                                                                 .exit_policy = TaskGroupExitPolicy::wait_pending,
                                                                 .deterministic_seed = 7,
                                                                 .maximum_active = 1,
                                                                 .mode = ExecutionMode::live,
                                                                 .replay_captures = {}},
                                       resolver, &cancel_transport);
        REQUIRE(cancel_created.has_value());
        auto cancel_coordinator = std::move(*cancel_created);
        auto cancel_request = service_call("fingerprint.resolve", "service-request-cancel").request;
        const std::vector<CapabilityRequest> cancel_requests {cancel_request};
        const auto cancel_scheduled = cancel_coordinator.schedule(cancel_requests, 2'000);
        REQUIRE(cancel_scheduled.has_value());
        REQUIRE(cancel_scheduled->attempts.size() == 1);
        const auto canceled = cancel_coordinator.close(2'010, true);
        REQUIRE(canceled.has_value());
        REQUIRE(canceled->closed);
        REQUIRE(cancel_transport.cancellations.size() == 1);
        REQUIRE(cancel_coordinator.take_responses()[0].status == FactTerminalStatus::canceled);
        const auto late =
            cancel_coordinator.complete(cancel_scheduled->attempts[0],
                                        ServiceResult {.status = ServiceStatus::ok,
                                                       .value = frozen("late", Classification::sensitive, {"identity"}),
                                                       .retry_after_ms = std::nullopt,
                                                       .diagnostic_code = {}},
                                        2'020);
        REQUIRE_FALSE(late.has_value());
        REQUIRE(late.error().code == ServiceErrorCode::stale_attempt);

        const std::vector<ServiceCapture> cancel_capture {cancel_coordinator.captures()[0]};
        auto cancel_replay_created =
            ServiceCoordinator::create(ServiceCoordinatorConfig {.group_id = 103,
                                                                 .exit_policy = TaskGroupExitPolicy::wait_pending,
                                                                 .deterministic_seed = 7,
                                                                 .maximum_active = 1,
                                                                 .mode = ExecutionMode::replay,
                                                                 .replay_captures = cancel_capture},
                                       resolver);
        REQUIRE(cancel_replay_created.has_value());
        auto cancel_replay = std::move(*cancel_replay_created);
        REQUIRE(cancel_replay.schedule(cancel_requests, 2'000).has_value());
        REQUIRE(cancel_replay.take_responses().empty());
        REQUIRE(cancel_replay.close(2'010, true).has_value());
        REQUIRE(cancel_replay.take_responses()[0].status == FactTerminalStatus::canceled);
        REQUIRE(cancel_replay.live_dispatches() == 0);
    }

    TEST_CASE("store-neutral outbox dispatcher fences replay and terminal lease recovery") {
        auto journal_created = EffectJournal::create(owner());
        REQUIRE(journal_created.has_value());
        auto journal = std::move(*journal_created);
        REQUIRE(journal.append(journal.root_scope(), draft("dispatcher/post", "payload")).has_value());
        const auto finalized = journal.finish_root(EvaluationOutcome::match);
        REQUIRE(finalized.has_value());
        const auto intent = finalized->intents[0].id;

        auto queue_created = OutboxQueue::create();
        REQUIRE(queue_created.has_value());
        auto queue = std::move(*queue_created);
        REQUIRE(queue.enqueue(*finalized, intent, "https://sink.example", 1'000).has_value());
        CountingOutboxStore store {queue};
        RecordingActionTransport transport;
        transport.next = ActionDispatchSuccess {.completed_unix_ms = 1'001, .acknowledgment = frozen("accepted")};
        const auto delivered = OutboxDispatcher::dispatch_one(
            store, transport,
            OutboxDispatcherConfig {.mode = ExecutionMode::live, .worker = "worker-a", .lease_duration_ms = 100},
            1'000);
        REQUIRE(delivered.has_value());
        REQUIRE(delivered->state == OutboxState::delivered);
        REQUIRE(store.claims == 1);
        REQUIRE(store.settlements == 1);
        REQUIRE(transport.dispatches == 1);

        auto replay_queue_created = OutboxQueue::create();
        REQUIRE(replay_queue_created.has_value());
        auto replay_queue = std::move(*replay_queue_created);
        REQUIRE(replay_queue.enqueue(*finalized, intent, "https://sink.example", 1'000).has_value());
        CountingOutboxStore replay_store {replay_queue};
        RecordingActionTransport replay_transport;
        const auto replay_blocked = OutboxDispatcher::dispatch_one(
            replay_store, replay_transport,
            OutboxDispatcherConfig {.mode = ExecutionMode::replay, .worker = "replay", .lease_duration_ms = 100},
            1'000);
        REQUIRE_FALSE(replay_blocked.has_value());
        REQUIRE(replay_blocked.error().code == OutboxErrorCode::replay_forbidden);
        REQUIRE(replay_store.claims == 0);
        REQUIRE(replay_transport.dispatches == 0);

        auto dead_queue_created = OutboxQueue::create();
        REQUIRE(dead_queue_created.has_value());
        auto dead_queue = std::move(*dead_queue_created);
        REQUIRE(dead_queue.enqueue(*finalized, intent, "https://sink.example", 1'000).has_value());
        CountingOutboxStore dead_store {dead_queue};
        RecordingActionTransport dead_transport;
        dead_transport.next = std::unexpected(ActionDispatchFailure {
            .completed_unix_ms = 1'001,
            .failure = DeliveryFailure {.kind = DeliveryFailureKind::http_status,
                                        .status_code = 400,
                                        .retry_after_ms = std::nullopt,
                                        .summary = "bad request"},
        });
        const auto dead = OutboxDispatcher::dispatch_one(
            dead_store, dead_transport,
            OutboxDispatcherConfig {.mode = ExecutionMode::live, .worker = "worker-b", .lease_duration_ms = 100},
            1'000);
        REQUIRE(dead.has_value());
        REQUIRE(dead->state == OutboxState::dead_letter);

        auto final_attempt_create = OutboxQueue::create();
        REQUIRE(final_attempt_create.has_value());
        auto final_attempt = std::move(*final_attempt_create);
        REQUIRE(final_attempt.enqueue(*finalized, intent, "https://sink.example", 1'000).has_value());
        auto before_final_claim = final_attempt.snapshot();
        before_final_claim[0].attempts = 9;
        auto restored_create = OutboxQueue::restore(std::move(before_final_claim));
        REQUIRE(restored_create.has_value());
        auto restored = std::move(*restored_create);
        const auto tenth = restored.claim("worker-final", 1'000, 100);
        REQUIRE(tenth.has_value());
        REQUIRE(tenth->attempt == 10);
        restored.release_expired_leases(1'100);
        REQUIRE(restored.find(intent)->state == OutboxState::dead_letter);
        REQUIRE_FALSE(restored.claim("worker-final", 1'100, 100).has_value());

        auto expiring_create = OutboxQueue::create();
        REQUIRE(expiring_create.has_value());
        auto expiring = std::move(*expiring_create);
        REQUIRE(expiring.enqueue(*finalized, intent, "https://sink.example", 1'000, 100).has_value());
        const auto bounded_lease = expiring.claim("worker-expiry", 1'050, 10'000);
        REQUIRE(bounded_lease.has_value());
        REQUIRE(bounded_lease->expires_unix_ms == 1'100);
        REQUIRE_FALSE(expiring.acknowledge(*bounded_lease, 1'100).has_value());
        expiring.release_expired_leases(1'100);
        REQUIRE(expiring.find(intent)->state == OutboxState::expired);

        auto mismatch_create = OutboxQueue::create();
        REQUIRE(mismatch_create.has_value());
        auto mismatch = std::move(*mismatch_create);
        REQUIRE(mismatch.enqueue(*finalized, intent, "https://sink.example", 1'000, 100).has_value());
        const auto changed_lifetime = mismatch.enqueue(*finalized, intent, "https://sink.example", 1'000, 200);
        REQUIRE_FALSE(changed_lifetime.has_value());
        REQUIRE(changed_lifetime.error().code == OutboxErrorCode::duplicate_idempotency_mismatch);
    }

} // namespace
