# ADR-013: Atomic Pack Activation

- Status: Accepted
- Decision owner: Integration architecture
- Applies to: S2, S3, R2, R3, I1, Q1
- Related limitations: L-007, L-009, L-012, L-013, L-015

## Context

A rule-pack generation defines more than executable code. It fixes bindings,
schemas, capability availability, state layout/migrations, correlation
subscriptions, effect policy inputs, optimizer certificates, and the meaning of
each verdict. Servers are active-active and may schedule the same pack on
different Windows or Linux nodes. Observations continue to arrive while code is
being deployed, evaluations can be suspended on remote facts/services, and
state/effects commit transactionally.

Activating one node at a time would allow the same PackId and event population
to be interpreted by different semantics. That creates ambiguous state
ownership, duplicate or missing effects, incompatible correlation cursors,
unreproducible incident evidence, and breaker identities that do not correspond
to one executable.

The system therefore needs a crash-recoverable fleet boundary that detects
compile/configuration drift before any new work can use the generation.

## Decision

Activation is an explicit, all-healthy-node, database-coordinated state
transition. It is separate from upload and staging.

### Identity and local compilation

- The signed source archive and its canonical SourceDigest are the provenance
  root.
- Every healthy serving node compiles that source locally with its exact
  compiler, private CPython runtime, schemas, operator bindings, and platform
  ABI.
- Each node reports a platform-independent BindingSetHash and SemanticIrHash and
  a platform-specific ExecutableHash under its current node lease fence.
- The frozen stage target contains every healthy serving node at stage start.
  Every target must succeed and all platform-independent hashes must match.
- Required capabilities/schema hashes must exist on every target. An optional
  capability is resolved consistently cluster-wide to its typed binding or None.
- A node joining after target freeze is not added mid-operation and cannot
  become ready until it compiles the database-active generation.

### Drain and cutover

- Activation obtains a fenced PackId lease.
- A drain transaction stops new old-generation claims, advances its assignment
  fence, and reserves the next pack activation cursor as DrainBoundary. The
  durable database ingest cursor partitions generation eligibility but does not
  promise a global processing order. Ingestion continues; later events remain
  queued.
- Already-leased old work may commit until the bounded drain deadline.
- At deadline, unfinished work is canceled and fenced. Its durable event/work
  keys enter a successor-requeue set. Late commits are rejected.
- After no committable old lease remains, one PostgreSQL transaction:
  - activates the staged generation;
  - retires the prior generation;
  - writes the activation cursor and new assignment fence;
  - makes post-boundary and successor-requeued work claimable;
  - initializes new correlation subscriptions at the activation cursor; and
  - selects state namespaces/migration descriptors and appends the audit event.
- There is never simultaneous old/new assignment. A canceled pre-boundary event
  may be re-evaluated by the successor, but completed old work is not.
- Notifications are hints; all nodes reconcile authoritative database state.

~~~mermaid
flowchart LR
    U["Verified source"] --> S["Compile on frozen healthy node set"]
    S --> H{"All semantic/binding hashes and capabilities agree?"}
    H -->|No| F["Stage failed; active generation unchanged"]
    H -->|Yes| D["Fence old assignments and reserve drain boundary"]
    D --> W["Finish or cancel/fence old in-flight work"]
    W --> A["One DB transaction flips generation and cursor"]
    A --> N["New generation claims queued and requeued work"]
~~~

### Crash recovery and idempotency

- Operation phase, target reports, boundary, fences, requeues, and result are
  persisted.
- Control-plane leadership is a short fenced lease. A replacement resumes the
  same operation.
- Every mutation uses RequestId/IdempotencyKey and optimistic resource version.
- Before the final transaction, no new generation is active. After it commits,
  the new generation remains authoritative even when the caller loses the
  response.

### Rollback and state

- Rollback is a forward activation of previously verified source; it repeats
  current-node compilation and the same drain/flip protocol.
- It does not rewind events or compensate external effects.
- Identical state schema ID/hash continues in the current namespace.
- Changed schemas require pure forward/reverse migration, explicit reset, or an
  explicitly authorized retained-namespace state gap. Otherwise activation or
  rollback fails.
- Migrations are lazy transactional per key, with the old namespace retained
  read-only for a bounded rollback window.
- New correlations start at the activation cursor. Historical backfill is a
  separate bounded operation, isolated/no-dispatch by default.

## Primary reasons

1. **One semantic owner:** a PackId has exactly one generation able to receive
   work, so state, effects, traces, and breaker accounting are explainable.
2. **Fail before exposure:** compilation, schema, capability, or platform drift
   prevents activation rather than becoming a placement-dependent runtime fault.
3. **No ingest loss:** assignment can drain while provider observations remain
   durable.
4. **Database atomicity:** generation, cursor, state namespace, and work
   eligibility change together.
5. **Crash recovery:** durable phases and fences make coordinator/process
   failure restartable.
6. **Auditable identity:** source, semantic, binding, and executable hashes show
   what was approved and what every platform runs.

## Rejected alternatives

### Rolling per-node activation

Rejected because it deliberately permits mixed semantics and makes scheduling
placement affect results.

### Blue/green concurrent active generations

Rejected for production assignment. Shadow evaluation may compare a staged
generation only with isolated state, no-dispatch effects, and non-authoritative
results.

### Quorum of healthy nodes

Rejected initially. Any serving node can receive work, so all must agree.
Operators may explicitly drain an unhealthy node before staging it out of the
serving set.

### Pause ingestion

Rejected because provider inventories and telemetry would be lost or apply
backpressure to agents for the full compile/drain duration. Ingest and
evaluation assignment are separate.

### Activate precompiled IR from the archive

Rejected because it creates a second trusted execution format, weakens local ABI
verification, and hides schema/operator drift.

### Automatically roll back on fault thresholds

Rejected because actions already delivered cannot be undone, a rollback may
need a state strategy, and automatic broad changes can amplify incidents.
Breakers quarantine narrowly; rollback requires explicit authority.

### Best-effort old-work cancellation without fences

Rejected because a late transaction could commit after the new generation
activates. Cancellation is advisory; fencing is the correctness mechanism.

## Positive consequences

- No mixed-generation runtime behavior for a pack.
- Active code cannot depend on which healthy node receives work.
- Existing generation remains untouched when staging fails.
- Continuous observation ingestion is preserved.
- Late old results and stale coordinators cannot commit.
- Rollout/rollback operations are idempotent and explainable.
- New nodes have a clear readiness gate.

## Negative consequences

- One unhealthy serving node blocks activation until recovery or explicit node
  drain.
- Activation latency includes all-node local compile and bounded drain.
- PostgreSQL availability is required for production activation.
- Staged/rollback executable caches and old state namespaces consume storage.
- A canceled old evaluation can run under successor semantics.
- Rollback cannot be instant or side-effect-reversing.
- State-changing rollback and backfill require explicit operator choices.

## Operational and security implications

- pack.activate and pack.rollback are separate mTLS/RBAC capabilities.
- Every stage/activation/rollback includes actor, reason, request, source digest,
  target nodes, hashes, state strategy, boundary, cancellations, and result in
  durable audit.
- Production readiness requires compiled active generations and matching
  schemas/capabilities.
- Metrics alert on hash disagreement, stuck drain, cancellation/requeue growth,
  late fence rejection, migration failures, and nodes unable to compile active
  code.
- Pack signer identity does not grant activation authority.
- Sensitive pack contents and state values are excluded from logs, metrics, and
  operation summaries.

## Known limitations introduced

- All-healthy-node staging favors consistency over deployment availability.
- There is no cross-region/global event order.
- SQLite cannot provide this multi-node production protocol.
- Already delivered external actions survive rollback.
- Retained-state rollback can be stale and therefore requires explicit
  acceptance or migration.
- New correlations have no implicit historical context.
- Backfill is isolated and no-dispatch by default; it does not affect live state
  unless separately authorized.

## Validation evidence

- Generation state-machine and illegal-transition tests.
- All-node compile/hash/schema/capability mismatch tests.
- Continuous-ingest drain with successful, canceled, and crashed old work.
- Late commit rejection using generation and work fence tokens.
- Coordinator termination in every persisted phase and takeover by another
  node.
- Database disconnect immediately before/after the final transaction.
- Joining-node readiness and lost-notification reconciliation.
- Unchanged/migrated/reset/reverse/retained-gap rollback tests.
- Isolated, live-state, and effect-authorized backfill tests.
- Two-node Windows/Linux semantic agreement with PostgreSQL 17+.

## Conditions for revisiting

Revisit the all-node rule only if the scheduler gains explicit compatibility
domains that can prove a pack will never be assigned outside a successfully
staged domain. Revisit generation overlap only with a complete new design for
state ownership, effects, correlations, replay, and breaker identities.

Revisit rollback behavior if external sinks expose a transactional compensation
protocol or state can be transformed bidirectionally with a verified migration
contract. None of these changes may weaken fencing or make local node state the
activation authority.
