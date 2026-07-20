# ADR-008: Transactional Reach-Based Effects

Status: accepted for `design-v1`  
Date: 2026-07-20  
Tasks: `E1`, `E2`, `E3`, `R2`, `S2`, `I1`, `Q1`

## Context

Rules need to trace, post, retain data, emit custom events, request later peer captures, call child rules, and update typed state. Python authors naturally expect a call in a reached branch to occur in left-to-right program order. The final rule boolean is not an adequate effect trigger: useful reporting can accompany either `True` or `False`, and changing a final predicate should not silently remove earlier reached behavior.

The engine also suspends for facts/services, may retry on MVCC conflicts, permits parent/child composition, runs fault/finalizer code, and supports diagnostic replay. Directly performing effects at call time would produce partial external state and duplicates. Gating all effects on MATCH would avoid some partial behavior but create unintuitive semantics and still would not atomically coordinate state, emitted events, and external delivery.

## Decision

Use imperative **reach-based creation** and **transactional disposition**:

1. Reaching an effect call validates and freezes its arguments, snapshots policy/labels, allocates a deterministic `IntentId` and monotonic sequence, and appends an immutable intent to the current in-memory journal scope.
2. The call does not perform physical external I/O.
3. Root and child rules create a journal tree. Explicit `transaction()` scopes checkpoint both state and effects, default to rollback, and merge only after an explicit `commit()` followed by normal scope exit.
4. Child-rule journals retain child invocation/binding ownership when merged. A failed child discards user intents and raises `FaultedRule`; engine-owned fault audit remains.
5. Returning `True` or `False` leaves reached eligible intents intact. Uncaught fault, cancellation, rollback, finalizer abort, or failed recovery discards the applicable user journal.
6. The optional finalizer may keep/replace the verdict or abort and may append bounded intents. Fault handlers use separate journals; the original faulting journal is discarded before handler execution.
7. One `IRuntimeStore` transaction commits the event cursor, verdict, state CAS, events, retention, trace publication, audits, and outbox rows.
8. Only the outbox dispatcher performs posts, after commit, with deterministic idempotency keys and at-least-once delivery.
9. Intent policy is snapshotted at its call site. Later policy can suppress an eligible action for safety, but can never upgrade dry-run/suppressed intent to dispatch.
10. Replay constructs candidate journals for comparison but cannot commit state, retention, events, or outbox rows.

## Primary reasons

- It matches ordinary imperative reasoning: a reached call matters regardless of the final boolean.
- It provides one atomic boundary for verdict, state, events, retention, trace, and actions.
- It makes suspension and VM restart behavior testable: the sequence ledger reveals duplicates or reordering.
- It permits safe parent/child composition and local rollback without compensating external operations.
- It separates destination delivery guarantees from rule execution correctness.
- It supports deterministic replay and exact/optimized parity comparisons.

## Alternatives considered

### Match-gated effects

Rejected. Effects would disappear when a rule returns `False`, even if the call was reached intentionally. Refactoring the final predicate would alter unrelated behavior. Negative-result telemetry and explicit always-on reporting become awkward.

### Immediate dispatch at call time

Rejected. An exception, state conflict, process crash, parent rollback, or replay could expose partial or duplicate side effects. Arbitrary destinations cannot join the engine database transaction.

### One durable transaction per effect

Rejected. It would expose partial evaluations, materially increase database contention, and separate effects from the verdict and state version that justified them.

### Compensating actions

Rejected as the primary mechanism. Compensation is endpoint-specific, may itself fail, and cannot reliably undo notifications, captures, or third-party processing.

### Pure functional return of an effect list

Rejected. It would make normal Python control flow and nested helpers unnatural and would not eliminate the need for ownership, policy, labels, state atomicity, or bounded journals.

### Exactly-once external delivery

Rejected as a general guarantee. The engine cannot atomically commit with an arbitrary remote service. Deterministic idempotency plus at-least-once delivery is the honest boundary.

## Consequences

### Positive

- State, verdict, events, retention, and action eligibility are consistent.
- Effects from failed/rolled-back subtrees are never physically visible.
- Authors can write direct imperative code with predictable left-to-right behavior.
- Child ownership and causation survive composition.
- State conflict retries and diagnostic replay do not dispatch duplicate actions.
- Operator dry-run and safety revocation are explicit and auditable.

### Negative

- Effects consume memory until finalization and must be tightly bounded.
- A `queued` receipt indicates eligibility, not successful delivery.
- External endpoints must implement idempotency.
- A long evaluation delays physical action delivery until database commit.
- Journal/tree/finalizer semantics add implementation and testing complexity.
- Engine-owned fault/audit events need a distinct path from rollback-prone user effects.

## Operational and security implications

- Outbox lag, retry age, dead letters, per-kind journal size, and disposition require metrics and operator tooling.
- Payloads must be frozen and classification-checked before intent creation; physical dispatch rechecks current revocation/ceiling and may only downgrade.
- Crash recovery uses transaction identity and deterministic idempotency keys; a crash after commit but before acknowledgement cannot create a second visible evaluation.
- Emergency diagnostics after triple fault are engine-owned and operator-authorized; failed pack code cannot smuggle an ordinary post through that path.
- No user action may bypass `IRuntimeStore` and the outbox dispatcher.

## Known limitations

- External delivery is at-least-once (L-008).
- Replay cannot undo or redeliver external actions (L-009).
- Bounded effect memory can reject otherwise valid long-running logic.
- Operator safety revocation may suppress delivery after an immutable receipt reported `queued`; the receipt is not a delivery promise.
- Effects and full recorder observability can limit optimizer shortcuts (L-010).
- Cyclic VM values cannot be frozen as effect payloads (L-017).

## Evidence and validation

- Journal tests cover reached/unreached calls, MATCH/NO_MATCH, nested commit/rollback, exceptions after commit request, child success/fault/recovery, suspension, and recursion.
- Crash-injection tests cover before database commit, after commit before acknowledgement, and during delivery.
- State-conflict tests prove discarded attempts create no durable events/outbox rows and stable logical calls retain idempotency identity.
- Replay tests prove zero live transports/storage mutation and compare ordered journal ownership/payload digests/dispositions.
- Multi-node tests prove fenced workers cannot commit stale results.

## Revisit conditions

Revisit only if:

- a concrete external system exposes a transactional exactly-once protocol worth a dedicated adapter;
- production evidence shows the bounded in-memory journal is untenable and an encrypted durable pre-commit journal can preserve the same atomic semantics;
- a product requirement demands match-gated behavior as an explicit, separately named construct rather than changing default reach semantics; or
- formal parity evidence supports additional optimizer elision without changing recorder/effect observability.

Any revisit requires updates to the effect/store contracts, failure matrix, replay model, limitations registry, and cross-platform crash tests.

