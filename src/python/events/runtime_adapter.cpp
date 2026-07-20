#include "rule_engine/python/events/runtime_adapter.hpp"

#include <algorithm>
#include <compare>
#include <limits>
#include <ranges>
#include <set>
#include <utility>

namespace rule_engine::python::events {
    namespace {

        Error error(const ErrorCode code, std::string message) {
            return Error {.code = code, .message = std::move(message)};
        }

        Error store_error(const StoreError &source, std::string_view operation) {
            auto message = std::string {operation};
            message += ": ";
            message += source.message;
            return error(ErrorCode::store_failure, std::move(message));
        }

        bool canonical_label(const DataLabel &label) {
            return std::ranges::is_sorted(label.categories) &&
                   std::ranges::adjacent_find(label.categories) == label.categories.end() &&
                   std::ranges::none_of(label.categories, [](const std::string &category) { return category.empty(); });
        }

        bool valid_namespace(const StateNamespace &state_namespace) {
            return !state_namespace.tenant.empty() && !state_namespace.owner.empty() &&
                   !state_namespace.namespace_id.empty() && !state_namespace.schema.empty() &&
                   canonical_label(state_namespace.label_ceiling);
        }

        bool frozen_matches_schema(const FrozenValue &value, const SchemaId &schema) {
            if (!value.value.valid() || value.canonical_digest.empty()) {
                return false;
            }
            const auto *record = std::get_if<FactRecord>(&value.value.node->data);
            return record != nullptr && record->schema == schema;
        }

        bool valid_captured_input(const effects::CapturedInput &capture) {
            if (capture.key.empty() || (!capture.value && capture.terminal_code.empty())) {
                return false;
            }
            return !capture.value || (capture.value->value.valid() && !capture.value->canonical_digest.empty());
        }

        template<typename Value>
        bool compare_value(const Value &left, const Value &right, const HistoryPredicateOperator operation) {
            switch (operation) {
                case HistoryPredicateOperator::equal: return left == right;
                case HistoryPredicateOperator::not_equal: return left != right;
                case HistoryPredicateOperator::less: return left < right;
                case HistoryPredicateOperator::less_or_equal: return left <= right;
                case HistoryPredicateOperator::greater: return left > right;
                case HistoryPredicateOperator::greater_or_equal: return left >= right;
                default: return false;
            }
        }

        std::expected<void, Error> validate_predicate(const HistoryPredicate &predicate) {
            const auto string_field = predicate.field == HistoryPredicateField::event_id ||
                                      predicate.field == HistoryPredicateField::schema ||
                                      predicate.field == HistoryPredicateField::peer ||
                                      predicate.field == HistoryPredicateField::payload_digest;
            if (string_field && !std::holds_alternative<std::string>(predicate.value)) {
                return std::unexpected(error(ErrorCode::invalid_schema, "history predicate requires a string value"));
            }
            const auto time_field = predicate.field == HistoryPredicateField::producer_timestamp ||
                                    predicate.field == HistoryPredicateField::ingest_timestamp;
            if (time_field && !std::holds_alternative<std::uint64_t>(predicate.value)) {
                return std::unexpected(
                    error(ErrorCode::invalid_schema, "history timestamp predicate requires an integer value"));
            }
            if (predicate.field == HistoryPredicateField::label_classification &&
                !std::holds_alternative<Classification>(predicate.value)) {
                return std::unexpected(
                    error(ErrorCode::invalid_schema, "history label predicate requires a classification value"));
            }
            return {};
        }

        bool pushdown_safe(const HistoryPredicate &predicate) {
            switch (predicate.field) {
                case HistoryPredicateField::event_id:
                case HistoryPredicateField::schema:
                case HistoryPredicateField::peer:
                case HistoryPredicateField::producer_timestamp:
                case HistoryPredicateField::ingest_timestamp: return true;
                case HistoryPredicateField::payload_digest:
                case HistoryPredicateField::label_classification: return false;
                default: return false;
            }
        }

        std::uint64_t selected_timestamp(const EventEnvelope &event, const HistoryTimeBasis basis) {
            return basis == HistoryTimeBasis::ingest ? event.ingest_unix_ms : event.producer_unix_ms;
        }

        std::expected<void, Error> validate_history_candidate(const HistoryPlan &plan, const EventEnvelope &event) {
            const auto timestamp = selected_timestamp(event, plan.time_basis);
            if (event.tenant != plan.tenant || (plan.peer && event.peer != *plan.peer) ||
                !std::ranges::contains(plan.schemas, event.schema) || timestamp < plan.begin_unix_ms ||
                timestamp >= plan.end_unix_ms) {
                return std::unexpected(
                    error(ErrorCode::invalid_bounds, "history store returned a candidate outside the typed plan"));
            }
            if (!may_flow_to(event.label, plan.result_ceiling)) {
                return std::unexpected(
                    error(ErrorCode::invalid_label, "history store returned a candidate above the label ceiling"));
            }
            return {};
        }

        bool same_state_identity(const StateNamespace &left, const StateNamespace &right) {
            return left.tenant == right.tenant && left.owner == right.owner;
        }

        bool address_targets_namespace(const StateAddress &address, const StateNamespace &state_namespace) {
            return address.tenant == state_namespace.tenant && address.owner == state_namespace.owner &&
                   address.namespace_id == state_namespace.namespace_id && address.schema == state_namespace.schema &&
                   !address.scope.empty() && !address.key.empty();
        }

        std::expected<void, Error> validate_state_read(const StateRead &read, const StateNamespace &state_namespace) {
            if (read.value && read.version == 0) {
                return std::unexpected(error(ErrorCode::store_failure, "state store returned an unversioned value"));
            }
            if (!read.value) {
                return {};
            }
            if (!frozen_matches_schema(*read.value, state_namespace.schema)) {
                return std::unexpected(error(ErrorCode::schema_mismatch, "state store returned the wrong schema"));
            }
            if (!may_flow_to(read.value->label, state_namespace.label_ceiling)) {
                return std::unexpected(error(ErrorCode::invalid_label, "state store returned an excessive label"));
            }
            return {};
        }

        StateAddress source_address(const StateAddress &target, const StateNamespace &source) {
            auto result = target;
            result.tenant = source.tenant;
            result.owner = source.owner;
            result.namespace_id = source.namespace_id;
            result.schema = source.schema;
            return result;
        }

        bool completion_advances(const CorrelationCompletion completion) {
            return completion == CorrelationCompletion::committed ||
                   completion == CorrelationCompletion::defined_fault ||
                   completion == CorrelationCompletion::quarantined;
        }

        bool completion_matches_outcome(const CorrelationCompletion completion, const EvaluationOutcome outcome) {
            switch (completion) {
                case CorrelationCompletion::committed:
                    return outcome == EvaluationOutcome::match || outcome == EvaluationOutcome::no_match;
                case CorrelationCompletion::defined_fault: return outcome == EvaluationOutcome::faulted;
                case CorrelationCompletion::quarantined: return outcome == EvaluationOutcome::quarantined;
                case CorrelationCompletion::retryable_fault:
                case CorrelationCompletion::rolled_back: return false;
                default: return false;
            }
        }

        bool same_input_identity(const EventEnvelope &left, const EventEnvelope &right) {
            return left.id == right.id && left.schema == right.schema && left.tenant == right.tenant &&
                   left.peer == right.peer && left.payload.canonical_digest == right.payload.canonical_digest;
        }

    } // namespace

    std::expected<void, Error> validate_history_plan(const HistoryPlan &plan, const EventRuntimeLimits &limits) {
        if (plan.tenant.empty() || plan.schemas.empty() ||
            std::ranges::any_of(plan.schemas, [](const SchemaId &schema) { return schema.empty(); })) {
            return std::unexpected(error(ErrorCode::invalid_schema, "history tenant and event schemas are required"));
        }
        if (!std::ranges::is_sorted(plan.schemas) || std::ranges::adjacent_find(plan.schemas) != plan.schemas.end()) {
            return std::unexpected(error(ErrorCode::invalid_schema, "history event schemas must be sorted and unique"));
        }
        if (plan.peer.has_value() == plan.fleet_history || (plan.peer && plan.peer->empty()) ||
            plan.begin_unix_ms >= plan.end_unix_ms || plan.limit == 0 || plan.page_rows == 0 ||
            plan.page_rows > plan.limit || plan.limit > limits.maximum_history_rows ||
            plan.page_rows > limits.maximum_history_page_rows ||
            plan.end_unix_ms - plan.begin_unix_ms > limits.maximum_history_span_ms ||
            !canonical_label(plan.result_ceiling)) {
            return std::unexpected(error(ErrorCode::invalid_bounds, "history plan is not fully bounded"));
        }
        if (plan.after && (plan.after->plan_fingerprint.empty() || plan.after->snapshot_ingest_position == 0 ||
                           plan.after->event.empty() || plan.after->returned_rows >= plan.limit)) {
            return std::unexpected(error(ErrorCode::invalid_cursor, "history cursor is incomplete or exhausted"));
        }
        return {};
    }

    HistoryPlanBuilder HistoryPlanBuilder::peer_local(TenantId tenant, PeerId peer) {
        HistoryPlan plan;
        plan.tenant = std::move(tenant);
        plan.peer = std::move(peer);
        plan.fleet_history = false;
        return HistoryPlanBuilder {std::move(plan)};
    }

    HistoryPlanBuilder HistoryPlanBuilder::fleet(TenantId tenant) {
        HistoryPlan plan;
        plan.tenant = std::move(tenant);
        plan.peer = std::nullopt;
        plan.fleet_history = true;
        return HistoryPlanBuilder {std::move(plan)};
    }

    HistoryPlanBuilder &HistoryPlanBuilder::event_schemas(std::vector<SchemaId> schemas) {
        std::ranges::sort(schemas);
        schemas.erase(std::ranges::unique(schemas).begin(), schemas.end());
        plan_.schemas = std::move(schemas);
        return *this;
    }

    HistoryPlanBuilder &HistoryPlanBuilder::between(const std::uint64_t begin_unix_ms,
                                                    const std::uint64_t end_unix_ms) {
        plan_.begin_unix_ms = begin_unix_ms;
        plan_.end_unix_ms = end_unix_ms;
        return *this;
    }

    HistoryPlanBuilder &HistoryPlanBuilder::ordered_by(const HistoryTimeBasis time_basis) noexcept {
        plan_.time_basis = time_basis;
        return *this;
    }

    HistoryPlanBuilder &HistoryPlanBuilder::bounded_to(const std::uint32_t limit,
                                                       const std::uint32_t page_rows) noexcept {
        plan_.limit = limit;
        plan_.page_rows = page_rows;
        return *this;
    }

    HistoryPlanBuilder &HistoryPlanBuilder::label_ceiling(DataLabel ceiling) {
        plan_.result_ceiling = std::move(ceiling);
        return *this;
    }

    HistoryPlanBuilder &HistoryPlanBuilder::after(HistoryCursor cursor) {
        plan_.after = std::move(cursor);
        return *this;
    }

    std::expected<HistoryPlan, Error> HistoryPlanBuilder::build(const EventRuntimeLimits &limits) const {
        if (auto validated = validate_history_plan(plan_, limits); !validated) {
            return std::unexpected(validated.error());
        }
        return plan_;
    }

    std::expected<HistoryPredicatePartition, Error>
    split_history_predicates(const std::span<const HistoryPredicate> predicates) {
        HistoryPredicatePartition result;
        for (const auto &predicate : predicates) {
            if (auto validated = validate_predicate(predicate); !validated) {
                return std::unexpected(validated.error());
            }
            (pushdown_safe(predicate) ? result.pushdown : result.residual).push_back(predicate);
        }
        return result;
    }

    std::expected<bool, Error> event_matches_history_predicates(const EventEnvelope &event,
                                                                const std::span<const HistoryPredicate> predicates) {
        for (const auto &predicate : predicates) {
            if (auto validated = validate_predicate(predicate); !validated) {
                return std::unexpected(validated.error());
            }

            bool matches {};
            switch (predicate.field) {
                case HistoryPredicateField::event_id:
                    matches =
                        compare_value(event.id.value, std::get<std::string>(predicate.value), predicate.operation);
                    break;
                case HistoryPredicateField::schema:
                    matches =
                        compare_value(event.schema.value, std::get<std::string>(predicate.value), predicate.operation);
                    break;
                case HistoryPredicateField::peer:
                    matches =
                        compare_value(event.peer.value, std::get<std::string>(predicate.value), predicate.operation);
                    break;
                case HistoryPredicateField::producer_timestamp:
                    matches = compare_value(event.producer_unix_ms, std::get<std::uint64_t>(predicate.value),
                                            predicate.operation);
                    break;
                case HistoryPredicateField::ingest_timestamp:
                    matches = compare_value(event.ingest_unix_ms, std::get<std::uint64_t>(predicate.value),
                                            predicate.operation);
                    break;
                case HistoryPredicateField::payload_digest:
                    matches = compare_value(event.payload.canonical_digest, std::get<std::string>(predicate.value),
                                            predicate.operation);
                    break;
                case HistoryPredicateField::label_classification:
                    matches = compare_value(event.label.classification, std::get<Classification>(predicate.value),
                                            predicate.operation);
                    break;
                default: return std::unexpected(error(ErrorCode::invalid_schema, "history predicate field is unknown"));
            }
            if (!matches) {
                return false;
            }
        }
        return true;
    }

    std::expected<HistoryPage, Error>
    ReferenceHistoryCandidateStore::query_candidates(const HistoryPlan &plan,
                                                     const std::span<const HistoryPredicate> pushdown) const {
        const auto partition = split_history_predicates(pushdown);
        if (!partition) {
            return std::unexpected(partition.error());
        }
        if (!partition->residual.empty()) {
            return std::unexpected(
                error(ErrorCode::invalid_schema, "history candidate store accepts pushdown-safe predicates only"));
        }
        auto page = runtime_.query_history(plan);
        if (!page) {
            return std::unexpected(page.error());
        }
        std::erase_if(page->events, [&pushdown](const EventEnvelope &event) {
            const auto matches = event_matches_history_predicates(event, pushdown);
            return !matches || !*matches;
        });
        return page;
    }

    std::expected<HistoryPage, Error>
    HistoryQueryAdapter::query_page(const HistoryPlan &plan, const std::span<const HistoryPredicate> predicates) const {
        if (auto validated = validate_history_plan(plan, limits_); !validated) {
            return std::unexpected(validated.error());
        }
        const auto partition = split_history_predicates(predicates);
        if (!partition) {
            return std::unexpected(partition.error());
        }
        auto candidates = store_.query_candidates(plan, partition->pushdown);
        if (!candidates) {
            return std::unexpected(candidates.error());
        }
        if (candidates->events.size() > plan.page_rows) {
            return std::unexpected(error(ErrorCode::invalid_bounds, "history store exceeded the requested page bound"));
        }

        HistoryPage result {.events = {}, .next = candidates->next};
        result.events.reserve(candidates->events.size());
        std::optional<std::pair<std::uint64_t, EventId>> previous;
        for (const auto &candidate : candidates->events) {
            if (auto validated = validate_history_candidate(plan, candidate); !validated) {
                return std::unexpected(validated.error());
            }
            const auto ordering = std::pair {selected_timestamp(candidate, plan.time_basis), candidate.id};
            if (previous && ordering <= *previous) {
                return std::unexpected(
                    error(ErrorCode::invalid_bounds, "history store returned candidates out of stable order"));
            }
            previous = ordering;
            const auto matches = event_matches_history_predicates(candidate, predicates);
            if (!matches) {
                return std::unexpected(matches.error());
            }
            if (*matches) {
                result.events.push_back(candidate);
            }
        }
        return result;
    }

    std::expected<StateReadResponse, Error> MvccEvaluationContext::read_state(const StateReadRequest &request) const {
        if (request.request_id.empty() || request.owner.empty() || request.namespace_name.empty() ||
            request.key.empty() || request.schema.empty()) {
            return std::unexpected(error(ErrorCode::invalid_identity, "state read request is incomplete"));
        }
        auto response = state_.read_state(request);
        if (!response) {
            return std::unexpected(store_error(response.error(), "state read"));
        }
        if (response->request_id != request.request_id) {
            return std::unexpected(error(ErrorCode::store_failure, "state store returned a mismatched request ID"));
        }
        return *response;
    }

    std::expected<effects::CapturedInput, Error>
    MvccEvaluationContext::resolve_input(const std::string_view key, const effects::CapturedInputKind kind) {
        if (key.empty()) {
            return std::unexpected(error(ErrorCode::invalid_identity, "external input key is empty"));
        }
        if (attempt_ != 1U) {
            if (replay_inputs_ == nullptr) {
                return std::unexpected(error(ErrorCode::replay_diverged, "retry has no sealed input bundle"));
            }
            const auto replayed = replay_inputs_->resolve(key);
            if (!replayed || replayed->kind != kind) {
                return std::unexpected(
                    error(ErrorCode::replay_diverged, "retry reached an uncaptured or differently typed input"));
            }
            return *replayed;
        }

        const auto existing = std::ranges::find(captures_, key, &effects::CapturedInput::key);
        if (existing != captures_.end()) {
            if (existing->kind != kind) {
                return std::unexpected(
                    error(ErrorCode::replay_diverged, "one input key was used with two input kinds"));
            }
            return *existing;
        }
        if (live_inputs_ == nullptr) {
            return std::unexpected(error(ErrorCode::replay_diverged, "original attempt has no live input source"));
        }
        auto capture = live_inputs_->resolve(key, kind);
        if (!capture) {
            return std::unexpected(capture.error());
        }
        if (capture->key != key || capture->kind != kind || !valid_captured_input(*capture)) {
            return std::unexpected(
                error(ErrorCode::invalid_schema, "external input source returned an invalid capture"));
        }
        captures_.push_back(*capture);
        return *capture;
    }

    std::expected<void, Error> MvccEvaluationContext::charge(const std::uint64_t units) {
        return budget_.charge(units);
    }

    std::expected<MvccRunReceipt, Error> TransactionalMvccRunner::run(IMvccEvaluationFactory &factory) {
        if (shared_budget_limit_ == 0) {
            return std::unexpected(error(ErrorCode::budget_exhausted, "shared retry budget is empty"));
        }

        SharedRetryBudget budget {.limit = shared_budget_limit_, .consumed = 0};
        std::vector<effects::CapturedInput> captures;
        std::optional<EventEnvelope> original_input;
        std::optional<CursorAdvance> original_cursor;
        std::uint64_t original_fence {};
        for (std::uint32_t attempt = 1; attempt <= MvccRetryController::maximum_attempts; ++attempt) {
            auto evaluation = factory.start(attempt);
            if (!evaluation || !*evaluation) {
                return std::unexpected(evaluation ?
                                           error(ErrorCode::invalid_identity, "attempt factory returned null") :
                                           evaluation.error());
            }

            std::optional<effects::CapturedInputReplayHost> replay;
            if (attempt != 1U) {
                auto created = effects::CapturedInputReplayHost::create(captures);
                if (!created) {
                    return std::unexpected(error(ErrorCode::replay_diverged, created.error().message));
                }
                replay = std::move(*created);
            }
            MvccEvaluationContext context {
                attempt,  state_, attempt == 1U ? &external_inputs_ : nullptr, replay ? &*replay : nullptr,
                captures, budget};
            auto proposal = (*evaluation)->evaluate(context);
            if (!proposal) {
                return std::unexpected(proposal.error());
            }
            if (!original_input) {
                original_input = proposal->transaction.input;
                original_cursor = proposal->transaction.cursor;
                original_fence = proposal->transaction.fence_token;
            } else if (!same_input_identity(*original_input, proposal->transaction.input) ||
                       original_cursor->consumer != proposal->transaction.cursor.consumer ||
                       original_cursor->expected_position != proposal->transaction.cursor.expected_position ||
                       original_cursor->new_position != proposal->transaction.cursor.new_position ||
                       original_fence != proposal->transaction.fence_token) {
                return std::unexpected(
                    error(ErrorCode::replay_diverged,
                          "retry changed the input event, serial cursor, or fence of the original transaction"));
            }
            if (!proposal->commit) {
                return MvccRunReceipt {
                    .attempts = attempt,
                    .committed = false,
                    .budget_consumed = budget.consumed,
                    .captured_inputs = std::move(captures),
                    .transaction = std::nullopt,
                };
            }

            auto committed = transactions_.transact_event(proposal->transaction);
            if (committed) {
                return MvccRunReceipt {
                    .attempts = attempt,
                    .committed = true,
                    .budget_consumed = budget.consumed,
                    .captured_inputs = std::move(captures),
                    .transaction = std::move(*committed),
                };
            }
            if (committed.error().code != StoreErrorCode::conflict) {
                return std::unexpected(store_error(committed.error(), "transaction commit"));
            }
            if (attempt == MvccRetryController::maximum_attempts) {
                return std::unexpected(
                    error(ErrorCode::replay_exhausted, "state conflict persisted through original plus two retries"));
            }
        }
        return std::unexpected(error(ErrorCode::replay_exhausted, "MVCC retry loop terminated unexpectedly"));
    }

    std::expected<LazyStateNamespace, Error> LazyStateNamespace::create(IStateNamespaceStore &store,
                                                                        StateNamespaceTransition transition,
                                                                        const IPureStateMigration *migration) {
        if (!valid_namespace(transition.source) || !valid_namespace(transition.target) ||
            !same_state_identity(transition.source, transition.target)) {
            return std::unexpected(
                error(ErrorCode::invalid_transition, "state transition namespaces are incomplete or change ownership"));
        }
        if (!transition.retain_source_for_rollback) {
            return std::unexpected(
                error(ErrorCode::invalid_transition, "state transition must retain its source namespace"));
        }

        switch (transition.mode) {
            case StateNamespaceTransitionMode::carry:
                if (transition.source.schema != transition.target.schema || migration != nullptr ||
                    !transition.migration_id.empty()) {
                    return std::unexpected(error(ErrorCode::invalid_transition,
                                                 "carry requires an exact schema and no migration program"));
                }
                break;
            case StateNamespaceTransitionMode::migrate: {
                if (transition.source.namespace_id == transition.target.namespace_id || migration == nullptr ||
                    transition.migration_id.empty()) {
                    return std::unexpected(error(ErrorCode::invalid_transition,
                                                 "migration requires distinct namespaces and a named pure program"));
                }
                const auto &descriptor = migration->descriptor();
                if (descriptor.id != transition.migration_id || descriptor.source_schema != transition.source.schema ||
                    descriptor.target_schema != transition.target.schema || !descriptor.deterministic ||
                    descriptor.performs_external_reads || descriptor.emits_effects) {
                    return std::unexpected(error(ErrorCode::invalid_transition,
                                                 "migration descriptor is incompatible or not observationally pure"));
                }
                break;
            }
            case StateNamespaceTransitionMode::reset:
                if (!transition.reset_authorized || transition.source.namespace_id == transition.target.namespace_id ||
                    migration != nullptr || !transition.migration_id.empty()) {
                    return std::unexpected(error(ErrorCode::invalid_transition,
                                                 "reset requires explicit authorization and a fresh namespace"));
                }
                break;
            default: return std::unexpected(error(ErrorCode::invalid_transition, "state transition mode is unknown"));
        }
        return LazyStateNamespace {store, std::move(transition), migration};
    }

    std::expected<StateRead, Error> LazyStateNamespace::read(const StateAddress &target_address) const {
        if (!address_targets_namespace(target_address, transition_.target)) {
            return std::unexpected(error(ErrorCode::invalid_identity, "state address does not target this namespace"));
        }
        auto target = store_.read(target_address);
        if (!target) {
            return std::unexpected(store_error(target.error(), "target state read"));
        }
        if (auto valid_target = validate_state_read(*target, transition_.target); !valid_target) {
            return std::unexpected(valid_target.error());
        }
        if (target->value || target->version != 0 || transition_.mode == StateNamespaceTransitionMode::reset) {
            return *target;
        }

        const auto source_key = source_address(target_address, transition_.source);
        auto source = store_.read(source_key);
        if (!source) {
            return std::unexpected(store_error(source.error(), "source state read"));
        }
        if (auto valid_source = validate_state_read(*source, transition_.source); !valid_source) {
            return std::unexpected(valid_source.error());
        }
        if (!source->value) {
            return *target;
        }

        auto value = *source->value;
        if (transition_.mode == StateNamespaceTransitionMode::migrate) {
            if (migration_ == nullptr) {
                return std::unexpected(error(ErrorCode::invalid_transition, "migration program is unavailable"));
            }
            auto migrated = migration_->migrate(*source->value);
            if (!migrated) {
                return std::unexpected(migrated.error());
            }
            value = std::move(*migrated);
        }
        if (!frozen_matches_schema(value, transition_.target.schema)) {
            return std::unexpected(error(ErrorCode::schema_mismatch, "migrated state has the wrong target schema"));
        }
        if (!may_flow_to(value.label, transition_.target.label_ceiling)) {
            return std::unexpected(error(ErrorCode::invalid_label, "migrated state exceeds the target label ceiling"));
        }

        const LazyStateMigrationWrite write {
            .source = source_key,
            .source_version = source->version,
            .target = target_address,
            .target_expected_version = target->version,
            .value = std::move(value),
            .migration_id = transition_.migration_id,
        };
        auto installed = store_.install_migrated(write);
        if (installed) {
            if (auto valid_installed = validate_state_read(*installed, transition_.target); !valid_installed) {
                return std::unexpected(valid_installed.error());
            }
            return *installed;
        }
        if (installed.error().code != StoreErrorCode::conflict) {
            return std::unexpected(store_error(installed.error(), "lazy state migration"));
        }

        auto raced = store_.read(target_address);
        if (!raced) {
            return std::unexpected(store_error(raced.error(), "target state race read"));
        }
        if (auto valid_raced = validate_state_read(*raced, transition_.target); !valid_raced) {
            return std::unexpected(valid_raced.error());
        }
        if (raced->value || raced->version != 0) {
            return *raced;
        }
        return std::unexpected(
            error(ErrorCode::state_conflict, "lazy migration conflicted without installing a target value"));
    }

    std::expected<CorrelationLease, Error> ReferenceCorrelationStateStore::claim(const CorrelationGroupId &group) {
        return runtime_.claim_group(group);
    }

    std::expected<WindowAdmission, Error>
    ReferenceCorrelationStateStore::admit(const CorrelationLease &lease, const EventEnvelope &event,
                                          const CorrelationTimePolicy &policy, const std::uint64_t server_now_unix_ms) {
        return runtime_.admit_group_event(lease, event, policy, server_now_unix_ms);
    }

    std::expected<std::uint64_t, Error>
    ReferenceCorrelationStateStore::complete(const CorrelationLease &lease, const CorrelationCompletion completion) {
        return runtime_.complete_group(lease, completion);
    }

    std::expected<void, Error> ReferenceCorrelationStateStore::clear_quarantine(const CorrelationGroupId &group) {
        return runtime_.clear_group_quarantine(group);
    }

    std::string correlation_consumer_key(const CorrelationGroupId &group) {
        return effects::stable_domain_key("correlation-consumer-v1", {group.tenant.value, group.executable.value,
                                                                      group.binding.value, group.canonical_key});
    }

    std::expected<CorrelationRunReceipt, Error>
    SerializedCorrelationRunner::run(const CorrelationGroupId &group, const EventEnvelope &event,
                                     const CorrelationTimePolicy &time_policy, const std::uint64_t server_now_unix_ms,
                                     const std::span<const CorrelationEdge> causation_edges,
                                     ICorrelationEvaluator &evaluator) {
        const std::vector<CorrelationEdge> edges {causation_edges.begin(), causation_edges.end()};
        if (auto valid_dag = validate_correlation_dag(edges); !valid_dag) {
            return std::unexpected(valid_dag.error());
        }

        auto lease = groups_.claim(group);
        if (!lease) {
            return std::unexpected(lease.error());
        }
        auto release = [this, &lease](const CorrelationCompletion completion) {
            return groups_.complete(*lease, completion);
        };

        auto window = groups_.admit(*lease, event, time_policy, server_now_unix_ms);
        if (!window) {
            static_cast<void>(release(CorrelationCompletion::rolled_back));
            return std::unexpected(window.error());
        }
        auto proposal = evaluator.evaluate(event, *window);
        if (!proposal) {
            static_cast<void>(release(CorrelationCompletion::retryable_fault));
            return std::unexpected(proposal.error());
        }

        if (!completion_advances(proposal->completion)) {
            if (proposal->transaction) {
                static_cast<void>(release(CorrelationCompletion::rolled_back));
                return std::unexpected(error(ErrorCode::invalid_bounds,
                                             "non-advancing correlation completion cannot publish a transaction"));
            }
            auto cursor = release(proposal->completion);
            if (!cursor) {
                return std::unexpected(cursor.error());
            }
            return CorrelationRunReceipt {
                .completion = proposal->completion,
                .window = *window,
                .group_cursor = *cursor,
                .transaction = std::nullopt,
            };
        }

        if (!proposal->transaction ||
            !completion_matches_outcome(proposal->completion, proposal->transaction->evaluation.outcome) ||
            !same_input_identity(proposal->transaction->input, event)) {
            static_cast<void>(release(CorrelationCompletion::rolled_back));
            return std::unexpected(error(ErrorCode::invalid_bounds,
                                         "advancing correlation completion requires a matching durable transaction"));
        }
        if (std::ranges::any_of(proposal->transaction->emitted_events, [&event](const EventEnvelope &emitted) {
                return emitted.tenant != event.tenant || !emitted.causation || *emitted.causation != event.id;
            })) {
            static_cast<void>(release(CorrelationCompletion::rolled_back));
            return std::unexpected(
                error(ErrorCode::causation_cycle, "correlation output must name its input as same-tenant causation"));
        }

        proposal->transaction->cursor = CursorAdvance {
            .consumer = correlation_consumer_key(group),
            .expected_position = lease->expected_cursor,
            .new_position = lease->expected_cursor + 1U,
        };
        proposal->transaction->fence_token = lease->token;
        auto committed = transactions_.transact_event(*proposal->transaction);
        if (!committed) {
            static_cast<void>(release(CorrelationCompletion::retryable_fault));
            return std::unexpected(store_error(committed.error(), "correlation transaction commit"));
        }

        auto cursor = release(proposal->completion);
        if (!cursor) {
            return std::unexpected(cursor.error());
        }
        return CorrelationRunReceipt {
            .completion = proposal->completion,
            .window = *window,
            .group_cursor = *cursor,
            .transaction = std::move(*committed),
        };
    }

} // namespace rule_engine::python::events
