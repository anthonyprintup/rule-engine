# ADR-012: PostgreSQL-Backed Active-Active Servers

Status: accepted for implementation\
Date: 2026-07-20\
Owners: python-cluster lane and integration owner\
Tasks: S1, S2, S3, R2, R3, E3, I1, Q1\
Architecture: [08-protocol-storage-and-cluster.md](../architecture/08-protocol-storage-and-cluster.md)

## Context

The rewritten engine must coordinate remote Windows peers, resumable evaluations, correlations, MVCC state, transactional effects, durable outbox delivery, retention, audit, and cluster-atomic pack generations. Multiple server nodes must make progress concurrently and survive process/node failure without allowing a stale execution to commit.

The central correctness requirement is stronger than a simple work queue: one event transaction must atomically validate ownership and state versions, persist the result, update state and cursors, emit events, retain selected data, commit effect dispositions, and enqueue external actions. The system also needs deterministic idempotency after unknown commit outcomes and strong serial ordering per peer/correlation group, but it does not require a global order.

Production therefore needs a transactional shared authority. Local development still needs a lightweight backend with the same engine-facing semantic contract.

## Decision

Use PostgreSQL 17+ as the production transactional authority for active-active server nodes. Implement SQLite behind the same `IRuntimeStore` semantic interface for explicitly configured single-node development and tests only.

### PostgreSQL production model

- All ready server nodes may accept agent sessions, claim peer/correlation work, compile/stage packs, and lease outbox rows.
- PostgreSQL owns node, peer-session, work, correlation-group, and outbox leases plus monotonically increasing fences.
- Work claims use short `READ COMMITTED` transactions, deterministic ordering, `FOR UPDATE SKIP LOCKED`, a new attempt/fence, and a database-time expiry. Processing happens outside the transaction.
- Final event commit occurs in one transaction and requires current node/work/session/generation fences, expected cursor, and state MVCC versions.
- That transaction writes the input event/cursor, state, result, emitted events, retention, committed effect intents, outbox, trace metadata, and audits atomically.
- Deterministic transaction, event, intent, and idempotency IDs resolve duplicate delivery and unknown commit outcomes.
- PostgreSQL `NOTIFY` is a latency hint only; jittered polling remains authoritative.
- Normal event/state work uses explicit row locks, unique constraints, and CAS predicates under `READ COMMITTED`. Activation/migration operations use locked singleton rows and `SERIALIZABLE` when necessary for multi-row invariants.
- Node loss or database partition causes leases to expire. Another node claims a higher fence; every late mutation from the old node affects zero rows.
- During PostgreSQL unavailability, server nodes become unready, stop new work/commits, reduce peer credits, and rely on agent spooling. They never create divergent local production writes.
- Production PostgreSQL primary/standby replication, backup, disaster recovery, and failover are operator responsibilities. The rule engine assumes one current write authority.

### SQLite development model

- SQLite uses WAL, foreign keys, explicit transactions, busy timeout, and one process-level writer mutex.
- It implements the same idempotency, cursor, MVCC, fence, snapshot, outbox, and transaction outcomes and runs the shared store conformance suite.
- Startup rejects SQLite outside `single_node_dev`, with multiple server processes, or with production/HA configuration.
- SQLite is never promoted as a PostgreSQL replica and has no merge/failover path.

## Primary reasons

1. **Atomic semantic commit.** PostgreSQL can commit state, cursor, result, effects, emitted events, retention, outbox, and audit under one ownership check.
2. **Explicit stale-owner rejection.** Row-backed monotonically increasing fences make safety independent of socket state, graceful shutdown, or perfectly synchronized clocks.
3. **Active-active compute.** `SKIP LOCKED` and per-domain rows let nodes process unrelated peers/groups concurrently while preserving required serial domains.
4. **Idempotent failure recovery.** Unique deterministic IDs and transaction lookup handle ACK loss and unknown commit outcomes without duplicating visible engine state.
5. **Operational economy.** One mature transactional system serves queue, state, event history, coordination, outbox, activation, and audit needs. It avoids adding a message broker and distributed KV store before their value is proven.
6. **Correct backpressure.** Database capacity can propagate through server credits to the durable agent spool instead of accepting unbounded in-memory work.
7. **Representative local development.** A semantic interface and conformance suite let SQLite provide fast single-node workflows without pretending to reproduce cluster behavior.

## Rejected alternatives

### One permanent leader server

Rejected because it serializes unrelated work, creates a hot data-plane bottleneck, and adds leader failover delay. Fenced per-peer and per-correlation-group ownership provides only the serialization semantics actually needed.

### Active-passive application servers

Rejected because standby compute cannot help with normal load. PostgreSQL already provides the shared ownership primitive needed for concurrent application nodes.

### Kafka as primary event/coordination authority

Rejected initially. Kafka provides durable ordered streams but not the required atomic state CAS, cursor, result, effect, outbox, and activation update without another transactional database and cross-system consistency protocol. A future ingest broker may precede PostgreSQL without replacing it as commit authority.

### Redis leases plus a separate SQL database

Rejected because lease correctness and event commit would span systems. A Redis lease could expire independently of the SQL transaction that it is meant to authorize. PostgreSQL row fences keep authority and mutation atomic.

### PostgreSQL advisory locks

Rejected as the primary ownership mechanism because locks are connection-scoped, less visible as durable state, and do not themselves provide monotonically increasing fences for late writers. Row leases/fences survive observation and audit cleanly.

### Hold database transactions open while evaluating

Rejected because VM/provider/service/history waits would retain locks and connections for seconds, amplify failures, and make cluster capacity depend on evaluation duration. Short claims plus fenced completion separate ownership from open transactions.

### Run all event transactions at `SERIALIZABLE`

Rejected as the default because explicit row locks and MVCC predicates define the relevant conflicts and allow state conflicts to enter the engine's bounded captured-replay policy. Blanket serializable retries would add contention and hide conflict classification. It remains appropriate for rare control-plane transitions where a locked singleton row is insufficient.

### PostgreSQL multi-primary or a distributed SQL database

Rejected for the initial release because conflict resolution, latency, and operational topology would become part of rule semantics. One HA write authority gives a clear transaction model; application servers remain active-active.

### SQLite in production or as outage fallback

Rejected because multi-process lease behavior, HA, write throughput, and failover differ materially. Falling back locally during a PostgreSQL outage would create histories, state, and effects that cannot be merged safely.

### Exactly-once external delivery

Rejected as an end-to-end claim. A worker can crash after a sink accepts a request but before the acknowledgement commits. The engine guarantees durable at-least-once delivery with a deterministic idempotency key; the sink must deduplicate when required.

## Positive consequences

- One durable transaction defines visibility for every evaluation attempt.
- A node, socket, or worker may fail at any point; a higher fence safely takes over.
- Unrelated peers and correlation groups scale across nodes without weakening serial semantics inside a domain.
- Input admission, state, effects, and outbox share deterministic idempotency and auditability.
- Database outages produce explicit backpressure instead of split-brain local writes.
- The same engine code exercises PostgreSQL and SQLite through a semantic contract rather than scattered SQL conditionals.
- Pack generation can be fenced atomically against old work.

## Negative consequences and tradeoffs

- PostgreSQL becomes a critical production dependency and must be operated, monitored, backed up, and capacity-planned accordingly.
- Active-active application availability still pauses writes during PostgreSQL primary failover.
- Row/queue/index design, vacuum behavior, retention, and pool sizing materially affect throughput.
- Duplicate computation is possible after lease expiry even though duplicate visible commits are prevented.
- At-least-once outbox delivery requires idempotent downstream services.
- SQLite cannot validate production concurrency, query plans, failover, or pool behavior; PostgreSQL integration tests remain mandatory.
- `SKIP LOCKED` optimizes throughput rather than strict fairness; starvation needs aging policy and monitoring.

## Security and operational implications

- Database credentials are per service role with least privilege; migration/admin, runtime, and read-only observability roles are separate.
- Connections require TLS according to deployment policy, server identity verification, bounded pools, statement timeouts, and parameterized queries.
- Tenant predicates and/or PostgreSQL row-level security are defense in depth; application authorization still explicitly scopes every query.
- Backups must protect encrypted sensitive/secret payloads and retention/purge semantics. Restore procedures must preserve idempotency, fences, activation generation, and audit continuity.
- Operators monitor lease age, stale-fence rejections, queue/cursor lag, transaction latency, pool saturation, deadlocks, MVCC conflicts, table/index bloat, outbox age, replication lag, and backup/restore evidence.
- Nodes with lost database connectivity become unready before their leases can be treated as current. They must not continue accepting work optimistically.
- Schema migrations are checksummed, forward-only in production, and coordinated before nodes running incompatible code become ready.

## Known limitations

1. Active-active applies to rule-engine compute, not PostgreSQL writes; one PostgreSQL primary/HA authority remains required.
2. Production progress stops during complete database unavailability rather than diverging to local stores.
3. Cross-region latency directly affects claim, event-commit, and history performance; the initial design assumes nodes are near the primary.
4. There is no global event order, only per-peer and per-correlation-group serial order.
5. Duplicate execution may occur after timeout/failover; only visible database commit and deterministic effects are once-per-event.
6. External action delivery remains at-least-once.
7. `SKIP LOCKED` can starve low-priority work without aging/priority controls.
8. PostgreSQL retention and high event volumes require partitioning, vacuum, index, and purge tuning that cannot be made workload-independent.
9. SQLite does not reproduce PostgreSQL concurrency, planner, failover, replication, or operational failure modes.
10. The first release has no automatic SQLite-to-PostgreSQL production promotion or cross-database migration workflow beyond explicit export/import tooling if later designed.
11. Unknown commit resolution depends on retaining deterministic transaction receipts for at least the maximum retry/replay horizon.
12. Database-time leases protect correctness but a severely overloaded database can cause lease churn and duplicate computation; adaptive capacity/backpressure mitigates rather than eliminates it.

## Validation evidence required

- One parameterized `IRuntimeStore` conformance suite must pass against PostgreSQL 17+ and SQLite for transactions, idempotency, cursors, MVCC, effects/outbox, snapshots, history, purge, fences, and unknown outcomes.
- Two-node PostgreSQL fault injection must kill, pause, partition, and restart nodes after claim, during evaluation, before commit, after commit before ACK, and after outbox send.
- Tests must prove a higher peer/work/generation fence makes every stale mutation affect zero rows.
- Concurrent tests must prove serial processing for one peer/group and parallel progress for unrelated peers/groups.
- Primary restart/failover, connection loss, pool exhaustion, statement timeout, deadlock/serialization result, and `NOTIFY` loss must recover through polling/idempotency without duplicate visible results.
- State conflict tests must produce bounded captured replays and a typed fault after the third total attempt.
- Outbox tests must prove lease takeover, retry/dead-letter limits, deterministic idempotency, and explicitly demonstrate the possible duplicate physical send boundary.
- Pack activation tests must fail atomically on node hash mismatch and prevent old-generation commits after the activation cursor flips.
- SQLite must refuse production/cluster configuration and must never be selected implicitly when PostgreSQL is unavailable.
- Backup/restore qualification must verify events, state, receipts, outbox, fences, activation identity, and audit continuity.
- A 10,000-peer simulation must stay within configured database pool, queue-lag, lease, and memory bounds under reconnect and failover load.

## Revisit conditions

Revisit through a new ADR when evidence supports one of these changes:

- measured ingest scale justifies adding Kafka or another broker ahead of PostgreSQL while preserving the atomic commit authority;
- a supported multi-region availability objective cannot tolerate primary-region write unavailability and has a defined deterministic conflict/order model;
- workload evidence shows a distributed SQL backend can meet fence, transaction, latency, and operational requirements with lower total risk;
- strict fairness requirements outweigh `SKIP LOCKED` throughput and call for a different queue scheduler;
- PostgreSQL history volume requires a separate analytical/archive store, with PostgreSQL retaining authoritative cursors and transaction references;
- an end-to-end sink protocol can provide a stronger exactly-once contract than idempotent at-least-once delivery;
- SQLite development behavior diverges enough that an ephemeral local PostgreSQL distribution is preferable.
