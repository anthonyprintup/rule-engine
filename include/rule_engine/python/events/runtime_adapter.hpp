#pragma once

#include "rule_engine/python/effects/replay.hpp"
#include "rule_engine/python/events/reference_runtime.hpp"

#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace rule_engine::python::events {

    [[nodiscard]] std::expected<void, Error> validate_history_plan(const HistoryPlan &plan,
                                                                   const EventRuntimeLimits &limits = {});

    struct HistoryPlanBuilder {
        [[nodiscard]] static HistoryPlanBuilder peer_local(TenantId tenant, PeerId peer);
        [[nodiscard]] static HistoryPlanBuilder fleet(TenantId tenant);

        HistoryPlanBuilder &event_schemas(std::vector<SchemaId> schemas);
        HistoryPlanBuilder &between(std::uint64_t begin_unix_ms, std::uint64_t end_unix_ms);
        HistoryPlanBuilder &ordered_by(HistoryTimeBasis time_basis) noexcept;
        HistoryPlanBuilder &bounded_to(std::uint32_t limit, std::uint32_t page_rows) noexcept;
        HistoryPlanBuilder &label_ceiling(DataLabel ceiling);
        HistoryPlanBuilder &after(HistoryCursor cursor);

        [[nodiscard]] std::expected<HistoryPlan, Error> build(const EventRuntimeLimits &limits = {}) const;

    private:
        explicit HistoryPlanBuilder(HistoryPlan plan): plan_ {std::move(plan)} {}

        HistoryPlan plan_;
    };

    enum struct HistoryPredicateField : std::uint8_t {
        event_id,
        schema,
        peer,
        producer_timestamp,
        ingest_timestamp,
        payload_digest,
        label_classification,
    };

    enum struct HistoryPredicateOperator : std::uint8_t {
        equal,
        not_equal,
        less,
        less_or_equal,
        greater,
        greater_or_equal,
    };

    using HistoryPredicateValue = std::variant<std::string, std::uint64_t, Classification>;

    struct HistoryPredicate {
        HistoryPredicateField field {HistoryPredicateField::event_id};
        HistoryPredicateOperator operation {HistoryPredicateOperator::equal};
        HistoryPredicateValue value;
    };

    struct HistoryPredicatePartition {
        std::vector<HistoryPredicate> pushdown;
        std::vector<HistoryPredicate> residual;
    };

    [[nodiscard]] std::expected<HistoryPredicatePartition, Error>
    split_history_predicates(std::span<const HistoryPredicate> predicates);
    [[nodiscard]] std::expected<bool, Error>
    event_matches_history_predicates(const EventEnvelope &event, std::span<const HistoryPredicate> predicates);

    // Implementations may translate only this typed predicate form to their
    // native query language. SQL, storage handles, and backend expressions do
    // not cross this interface.
    struct IHistoryCandidateStore {
        virtual ~IHistoryCandidateStore() = default;
        [[nodiscard]] virtual std::expected<HistoryPage, Error>
        query_candidates(const HistoryPlan &plan, std::span<const HistoryPredicate> pushdown) const = 0;
    };

    struct ReferenceHistoryCandidateStore final: IHistoryCandidateStore {
        explicit ReferenceHistoryCandidateStore(const InMemoryReferenceRuntime &runtime): runtime_ {runtime} {}

        [[nodiscard]] std::expected<HistoryPage, Error>
        query_candidates(const HistoryPlan &plan, std::span<const HistoryPredicate> pushdown) const override;

    private:
        const InMemoryReferenceRuntime &runtime_;
    };

    struct HistoryQueryAdapter {
        explicit HistoryQueryAdapter(const IHistoryCandidateStore &store, EventRuntimeLimits limits = {}):
            store_ {store}, limits_ {limits} {}

        [[nodiscard]] std::expected<HistoryPage, Error> query_page(const HistoryPlan &plan,
                                                                   std::span<const HistoryPredicate> predicates) const;

    private:
        const IHistoryCandidateStore &store_;
        EventRuntimeLimits limits_;
    };

    struct IStateSnapshotStore {
        virtual ~IStateSnapshotStore() = default;
        [[nodiscard]] virtual std::expected<StateReadResponse, StoreError>
        read_state(const StateReadRequest &request) const = 0;
    };

    struct IExternalInputSource {
        virtual ~IExternalInputSource() = default;
        [[nodiscard]] virtual std::expected<effects::CapturedInput, Error> resolve(std::string_view key,
                                                                                   effects::CapturedInputKind kind) = 0;
    };

    struct MvccEvaluationContext {
        [[nodiscard]] std::uint32_t attempt() const noexcept { return attempt_; }
        [[nodiscard]] std::expected<StateReadResponse, Error> read_state(const StateReadRequest &request) const;
        [[nodiscard]] std::expected<effects::CapturedInput, Error> resolve_input(std::string_view key,
                                                                                 effects::CapturedInputKind kind);
        [[nodiscard]] std::expected<void, Error> charge(std::uint64_t units);
        [[nodiscard]] std::uint64_t budget_remaining() const noexcept { return budget_.remaining(); }

    private:
        friend struct TransactionalMvccRunner;

        MvccEvaluationContext(std::uint32_t attempt, const IStateSnapshotStore &state,
                              IExternalInputSource *live_inputs, effects::CapturedInputReplayHost *replay_inputs,
                              std::vector<effects::CapturedInput> &captures, SharedRetryBudget &budget):
            attempt_ {attempt},
            state_ {state},
            live_inputs_ {live_inputs},
            replay_inputs_ {replay_inputs},
            captures_ {captures},
            budget_ {budget} {}

        std::uint32_t attempt_ {};
        const IStateSnapshotStore &state_;
        IExternalInputSource *live_inputs_ {};
        effects::CapturedInputReplayHost *replay_inputs_ {};
        std::vector<effects::CapturedInput> &captures_;
        SharedRetryBudget &budget_;
    };

    struct MvccEvaluationProposal {
        RuntimeTransaction transaction;
        bool commit {true};
    };

    struct IMvccEvaluationAttempt {
        virtual ~IMvccEvaluationAttempt() = default;
        [[nodiscard]] virtual std::expected<MvccEvaluationProposal, Error> evaluate(MvccEvaluationContext &context) = 0;
    };

    struct IMvccEvaluationFactory {
        virtual ~IMvccEvaluationFactory() = default;
        [[nodiscard]] virtual std::expected<std::unique_ptr<IMvccEvaluationAttempt>, Error>
        start(std::uint32_t attempt) = 0;
    };

    struct MvccRunReceipt {
        std::uint32_t attempts {};
        bool committed {};
        std::uint64_t budget_consumed {};
        std::vector<effects::CapturedInput> captured_inputs;
        std::optional<TransactionReceipt> transaction;
    };

    struct TransactionalMvccRunner {
        TransactionalMvccRunner(IRuntimeStore &transactions, const IStateSnapshotStore &state,
                                IExternalInputSource &external_inputs, std::uint64_t shared_budget_limit):
            transactions_ {transactions},
            state_ {state},
            external_inputs_ {external_inputs},
            shared_budget_limit_ {shared_budget_limit} {}

        [[nodiscard]] std::expected<MvccRunReceipt, Error> run(IMvccEvaluationFactory &factory);

    private:
        IRuntimeStore &transactions_;
        const IStateSnapshotStore &state_;
        IExternalInputSource &external_inputs_;
        std::uint64_t shared_budget_limit_ {};
    };

    enum struct StateNamespaceTransitionMode : std::uint8_t { carry, migrate, reset };

    struct StateMigrationDescriptor {
        std::string id;
        SchemaId source_schema;
        SchemaId target_schema;
        bool deterministic {true};
        bool performs_external_reads {};
        bool emits_effects {};
    };

    struct IPureStateMigration {
        virtual ~IPureStateMigration() = default;
        [[nodiscard]] virtual const StateMigrationDescriptor &descriptor() const noexcept = 0;
        [[nodiscard]] virtual std::expected<FrozenValue, Error> migrate(const FrozenValue &source) const = 0;
    };

    struct StateNamespaceTransition {
        StateNamespaceTransitionMode mode {StateNamespaceTransitionMode::carry};
        StateNamespace source;
        StateNamespace target;
        std::string migration_id;
        bool reset_authorized {};
        bool retain_source_for_rollback {true};
    };

    struct LazyStateMigrationWrite {
        StateAddress source;
        std::uint64_t source_version {};
        StateAddress target;
        std::uint64_t target_expected_version {};
        std::optional<FrozenValue> value;
        std::string migration_id;
    };

    struct IStateNamespaceStore {
        virtual ~IStateNamespaceStore() = default;
        [[nodiscard]] virtual std::expected<StateRead, StoreError> read(const StateAddress &address) const = 0;
        // The implementation validates source_version and target_expected_version
        // and installs the target in one durable transaction. The source is not
        // erased, which preserves the rollback namespace.
        [[nodiscard]] virtual std::expected<StateRead, StoreError>
        install_migrated(const LazyStateMigrationWrite &write) = 0;
    };

    struct LazyStateNamespace {
        [[nodiscard]] static std::expected<LazyStateNamespace, Error>
        create(IStateNamespaceStore &store, StateNamespaceTransition transition,
               const IPureStateMigration *migration = nullptr);

        [[nodiscard]] std::expected<StateRead, Error> read(const StateAddress &target_address) const;
        [[nodiscard]] const StateNamespaceTransition &transition() const noexcept { return transition_; }

    private:
        LazyStateNamespace(IStateNamespaceStore &store, StateNamespaceTransition transition,
                           const IPureStateMigration *migration):
            store_ {store}, transition_ {std::move(transition)}, migration_ {migration} {}

        IStateNamespaceStore &store_;
        StateNamespaceTransition transition_;
        const IPureStateMigration *migration_ {};
    };

    struct ICorrelationStateStore {
        virtual ~ICorrelationStateStore() = default;
        // The returned token is also the fence token for the matching
        // IRuntimeStore serial domain. Durable implementations allocate both
        // from one fenced lease record.
        [[nodiscard]] virtual std::expected<CorrelationLease, Error> claim(const CorrelationGroupId &group) = 0;
        [[nodiscard]] virtual std::expected<WindowAdmission, Error> admit(const CorrelationLease &lease,
                                                                          const EventEnvelope &event,
                                                                          const CorrelationTimePolicy &policy,
                                                                          std::uint64_t server_now_unix_ms) = 0;
        [[nodiscard]] virtual std::expected<std::uint64_t, Error> complete(const CorrelationLease &lease,
                                                                           CorrelationCompletion completion) = 0;
        [[nodiscard]] virtual std::expected<void, Error> clear_quarantine(const CorrelationGroupId &group) = 0;
    };

    struct ReferenceCorrelationStateStore final: ICorrelationStateStore {
        explicit ReferenceCorrelationStateStore(InMemoryReferenceRuntime &runtime): runtime_ {runtime} {}

        [[nodiscard]] std::expected<CorrelationLease, Error> claim(const CorrelationGroupId &group) override;
        [[nodiscard]] std::expected<WindowAdmission, Error> admit(const CorrelationLease &lease,
                                                                  const EventEnvelope &event,
                                                                  const CorrelationTimePolicy &policy,
                                                                  std::uint64_t server_now_unix_ms) override;
        [[nodiscard]] std::expected<std::uint64_t, Error> complete(const CorrelationLease &lease,
                                                                   CorrelationCompletion completion) override;
        [[nodiscard]] std::expected<void, Error> clear_quarantine(const CorrelationGroupId &group) override;

    private:
        InMemoryReferenceRuntime &runtime_;
    };

    struct CorrelationEvaluationProposal {
        CorrelationCompletion completion {CorrelationCompletion::rolled_back};
        std::optional<RuntimeTransaction> transaction;
    };

    struct ICorrelationEvaluator {
        virtual ~ICorrelationEvaluator() = default;
        [[nodiscard]] virtual std::expected<CorrelationEvaluationProposal, Error>
        evaluate(const EventEnvelope &event, const WindowAdmission &window) = 0;
    };

    struct CorrelationRunReceipt {
        CorrelationCompletion completion {CorrelationCompletion::rolled_back};
        WindowAdmission window;
        std::uint64_t group_cursor {};
        std::optional<TransactionReceipt> transaction;
    };

    [[nodiscard]] std::string correlation_consumer_key(const CorrelationGroupId &group);

    struct SerializedCorrelationRunner {
        SerializedCorrelationRunner(ICorrelationStateStore &groups, IRuntimeStore &transactions):
            groups_ {groups}, transactions_ {transactions} {}

        [[nodiscard]] std::expected<CorrelationRunReceipt, Error>
        run(const CorrelationGroupId &group, const EventEnvelope &event, const CorrelationTimePolicy &time_policy,
            std::uint64_t server_now_unix_ms, std::span<const CorrelationEdge> causation_edges,
            ICorrelationEvaluator &evaluator);

    private:
        ICorrelationStateStore &groups_;
        IRuntimeStore &transactions_;
    };

} // namespace rule_engine::python::events
