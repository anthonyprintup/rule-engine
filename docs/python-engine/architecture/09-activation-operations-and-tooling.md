# Activation, Operations, and Tooling

## 1. Purpose and goals

This chapter defines how a compiled rule-pack generation moves from an uploaded
source archive to the only generation allowed to receive new work, how that
generation is rolled back or migrated, and how operators observe and control the
system. It also fixes the public command-line tools and the distinction between
authoring, control-plane, and runtime responsibilities.

The goals are:

- make a pack activation atomic across every healthy serving node;
- prevent old and new semantics from running concurrently for one pack;
- continue accepting observations while evaluations are drained;
- reject a generation before activation when compilation, bindings, schemas,
  capabilities, or semantic hashes disagree;
- make node, coordinator, and database failures restartable and idempotent;
- retain a bounded, explicit rollback path without pretending that external
  actions can be undone;
- migrate state transactionally without exposing half-migrated keys;
- keep historical backfill separate from the live cursor unless an operator
  explicitly authorizes live-state application;
- expose all privileged changes through an authenticated, audited control plane;
- give authors precise local tools without executing static rule modules; and
- make health, readiness, metrics, logs, traces, and audit evidence sufficient
  to explain every activation decision.

## 2. Non-goals

- There is no rolling mixed-version execution for one pack.
- Activation does not pause or discard observation ingestion.
- Rollback does not undo delivered actions, external service reads, captures, or
  already-published observations.
- The cluster does not trust precompiled IR received from a pack or another
  cluster.
- A quorum of serving nodes is not enough for activation. Every node in the
  frozen healthy target set must stage successfully.
- Development directory watch is not a production activation mechanism.
- The admin API is not a general database interface and does not expose SQL.
- The authoring tools are not a Python interpreter, package manager, or custom
  language server in the first release.
- Backfill is not an implicit part of activation and never silently changes the
  live correlation cursor.

## 3. Actors and trust boundaries

### 3.1 Actors

- **Pack publisher:** builds and signs a deterministic source-only rpack.
- **Pack registry:** content-addressed storage for verified source packs and
  immutable compile inputs. It is data storage, not a semantic authority.
- **Admin principal:** a human or automation identity authenticated by mTLS and
  authorized for named control-plane capabilities.
- **Control-plane leader:** the holder of a short fenced PostgreSQL lease for one
  activation operation. Leadership may move without changing operation
  semantics.
- **Serving node:** a Windows or Linux server eligible to schedule evaluations.
  It compiles a pack locally and reports hashes under a node lease/fence.
- **Windows agent:** provides facts and scans through protocol v2. It never
  participates in semantic compilation or activation decisions.
- **Runtime store:** PostgreSQL in production. It is the source of truth for
  operations, node leases, pack generations, activation boundaries, work
  fences, state namespaces, event cursors, audits, and outbox records.
- **Author:** uses pack, check, stub, and benchmark tools locally. An author has
  no production authority merely because a pack compiles.
- **External sink/service:** an operator-bound endpoint reached only through the
  effect/service contracts.

### 3.2 Boundaries

- Signature verification establishes pack provenance, not semantic correctness.
- Local compilation establishes semantics for the exact compiler/runtime ABI on
  each node.
- PostgreSQL transactions and monotonically increasing fence tokens establish
  activation and work ownership.
- The admin certificate identity is never accepted as a pack signer identity
  implicitly; signer trust and operator authorization are separate policies.
- Agent certificates identify peers, not administrators.
- A development unsigned pack can never be promoted through the production
  activation API without first becoming a canonical signed pack.

## 4. Public interfaces and owned data

### 4.1 Generation identity

A PackGeneration record contains:

- PackId and source SemVer;
- canonical SourceDigest;
- monotonically increasing generation number scoped to PackId;
- compiler API, Python runtime, Unicode table, VM bytecode, optimizer
  certificate, modeled-library, schema, and platform ABI versions;
- platform-independent SemanticIrHash and BindingSetHash;
- one platform-specific ExecutableHash per supported platform ABI;
- verified signer/key ID and trust-policy version;
- required and optional capability/schema hashes;
- state schema and migration descriptors;
- selected budget, retention, recorder, and effect policy versions;
- lifecycle state, timestamps, initiating principal, operation ID, and audit IDs.

SemanticIrHash excludes platform object layout and machine code but includes all
typed HIR/bytecode semantics, constants, model descriptors, bindings, effect
summaries, migrations, and policy selections that can change execution.
ExecutableHash includes SemanticIrHash and the complete compiler/runtime/platform
ABI. A breaker reset requires a new source-derived ExecutableHash; editing only
an operator policy does not reset it.

### 4.2 Lifecycle states

The persistent generation state machine is:

~~~mermaid
stateDiagram-v2
    [*] --> Uploaded
    Uploaded --> Verified: canonical index and signature pass
    Uploaded --> Rejected: verification fails
    Verified --> Compiling: stage operation freezes target nodes
    Compiling --> Staged: every target reports matching hashes
    Compiling --> StageFailed: any target fails or disagrees
    Staged --> Draining: activation lease and drain boundary acquired
    Draining --> Active: old work settled or fenced; atomic flip commits
    Draining --> StageFailed: pre-flip abort
    Active --> Retired: successor or rollback generation activates
    Retired --> Compiling: requested rollback restages generation
    Active --> Quarantined: breaker or operator action
    Quarantined --> Active: audited operator clear or valid half-open recovery
    Retired --> Expired: rollback retention expires
~~~

No transition is inferred from local files. Every transition is a fenced,
idempotent database operation with an audit record.

### 4.3 Control-plane API

The production control plane is a versioned protobuf-wire API over TLS 1.3 mTLS.
Every mutation carries:

- RequestId and IdempotencyKey;
- authenticated ActorId and certificate identity;
- required RBAC capability;
- expected resource version for optimistic concurrency;
- optional operator reason/ticket;
- requested dry-run state;
- deadline; and
- typed request payload.

Mutations return an OperationId. Long-running operations are observed rather
than held open. Reading an operation returns its current phase, target-node
reports, blockers, progress, warnings, terminal result, and audit IDs.

Named capabilities are intentionally narrow:

- pack.read, pack.upload, pack.stage, pack.activate, pack.rollback;
- registry.read (global aggregate maintenance observation only);
- policy.read, policy.write;
- quarantine.read, quarantine.clear, quarantine.force;
- trace.read, trace.arm, capture.authorize;
- backfill.preview, backfill.run, backfill.apply_state,
  backfill.authorize_effects;
- outbox.read, outbox.redrive, deadletter.manage;
- purge.preview, purge.execute;
- node.read, node.drain; and
- audit.read.

Production forbids an all-powerful implicit administrator. Deployment may map a
certificate to several named capabilities, but every authorization decision is
recorded.

### 4.4 Runtime configuration

rule_engine_server accepts one explicit configuration file. The file selects:

- PostgreSQL connection and TLS material references;
- node identity, advertised platform ABI, and lease timings;
- pack registry and trusted signer/revocation policy;
- admin and agent listener endpoints and certificate policies;
- operator capability bindings and schema hashes;
- named budget, retention, trace, capture, service, and sink profiles;
- Prometheus, JSON log, audit, and optional OTLP destinations; and
- explicit development-only switches.

Secrets are references to OS/deployment secret stores, not inline values emitted
by inspect commands. Production startup fails when required retention profiles,
trust roots, schema bindings, or database migrations are absent.

### 4.5 Command-line tools

The installed surface is:

- rule_engine_server --config PATH
- rule_engine_agent --config PATH on Windows
- rule_engine_check --pack PATH [--watch] [--format text|json|sarif]
  [--explain-facts] [--explain-plan]
- rule_engine_pack build|verify|inspect|stubs
- rule_engine_admin upload|stage|activate|rollback|operation|packs|nodes|
  policy|quarantine|trace|capture|backfill|outbox|deadletters|purge|audit
- rule_engine_benchmark for engineering qualification, using compiled Python
  packs rather than generated YARA source.

All tools support --help and --version. Machine formats are versioned and write
diagnostics to standard output; human progress goes to standard error. Exit
codes are stable:

- 0 success;
- 1 validation, compile, or requested-operation failure;
- 2 command-line/configuration error;
- 3 unavailable dependency or transport;
- 4 authentication/authorization failure; and
- 5 internal invariant failure.

rule_engine_check and rule_engine_pack never execute static rule modules.
Generator execution occurs only for a manifest-enabled build/check operation and
is visibly reported.

## 5. Activation control and data flow

### 5.1 Compile and stage

1. **Upload:** stream the archive to a bounded temporary object, verify its
   canonical index while reading, calculate SourceDigest, and atomically publish
   it by digest. Repeating the same upload is idempotent.
2. **Verify:** validate Ed25519 signature, signer trust/revocation, manifest,
   dependency closure, archive restrictions, source/runtime limits, and declared
   schemas. A rejected source cannot enter Compiling.
3. **Create stage operation:** under a fenced control lease, snapshot the target
   set of all healthy serving nodes with unexpired leases. Persist each NodeId,
   PlatformAbi, NodeLeaseFence, and required generation report. Nodes joining
   afterward do not enter this operation; they must compile the active
   generation before becoming ready.
4. **Compile locally:** each target fetches the verified source by digest, checks
   it again, invokes its private parse/generate workers, compiles in C++, verifies
   bytecode, checks operator capabilities/schema hashes, and stores its local
   executable cache by complete ExecutableHash.
5. **Report:** a node transactionally reports BindingSetHash, SemanticIrHash,
   ExecutableHash, requirements, warnings, and artifact-cache proof under its
   frozen lease fence. A stale or replaced node lease cannot report.
6. **Compare:** stage succeeds only when every frozen target succeeds, every
   platform-independent hash matches, every node reports a valid
   platform-specific executable, and required capabilities are available
   cluster-wide. An optional capability has one cluster-wide outcome: all
   executions receive the binding or all receive None.

Compilation warnings are immutable stage evidence. A stage operation never
silently recompiles after a compiler/runtime/policy ABI change; such a change
requires a new operation and generation identity.

~~~mermaid
sequenceDiagram
    actor Publisher
    participant Admin as Admin API
    participant DB as PostgreSQL
    participant N1 as Serving node A
    participant N2 as Serving node B
    Publisher->>Admin: upload signed source-only rpack
    Admin->>DB: store verified digest and audit
    Admin->>DB: create stage; freeze healthy target set
    par Compile locally
        N1->>N1: verify, parse, generate twice, compile
        N1->>DB: fenced hash/capability report
    and
        N2->>N2: verify, parse, generate twice, compile
        N2->>DB: fenced hash/capability report
    end
    Admin->>DB: compare all target reports
    alt hashes and capabilities agree
        DB-->>Admin: generation Staged
    else any failure or disagreement
        DB-->>Admin: generation StageFailed
    end
~~~

### 5.2 Drain and atomic cursor flip

Activation is a separate explicit operation; successful staging never activates
automatically.

1. Acquire the PackId activation lease and verify the staged report set is still
   valid. If a frozen target has lost its serving lease, either wait for it to
   return under the same fence or abort and restage against a fresh target set.
2. In one transaction, mark the current generation Draining, increment its
   assignment fence, stop new claims for that generation, and reserve the next
   pack activation cursor as DrainBoundary. The cursor is allocated from durable
   database ingest order only to partition generation eligibility; it is not a
   public global processing-order guarantee. Observation ingestion continues.
   Events at or after the boundary remain pending for the successor.
3. Allow pre-boundary work already leased to finish within the configured drain
   deadline. Successful commits must carry the prior generation and current
   work fence.
4. At deadline, cancel remaining sessions and advance their work fences.
   Uncommitted evaluations are rolled back. The store records their event/work
   keys in a successor-requeue set; a late old-generation commit is rejected.
5. Verify that no committable old-generation lease remains and that each current
   healthy node still has the staged executable.
6. Commit one activation transaction that:
   - marks the new generation Active and the old generation Retired;
   - writes DrainBoundary as the activation cursor;
   - changes PackId assignment to the new generation/fence;
   - makes post-boundary pending events and the explicit successor-requeue set
     claimable by the new generation;
   - initializes new correlation subscriptions at DrainBoundary;
   - selects state namespaces/migration descriptors;
   - publishes the active-generation audit event.
7. Notify nodes as a latency optimization. Nodes always reconcile from the
   database; losing a notification cannot change correctness.

Completed old-generation work is never requeued. Canceled or crashed work is
requeued exactly once through its durable work key. Thus the cutover can include
some pre-boundary retries under the new generation, but it never runs two
generations concurrently and never silently loses a queued observation.

~~~mermaid
sequenceDiagram
    participant Ingest
    participant Leader as Activation leader
    participant DB as PostgreSQL
    participant Old as Old generation workers
    participant New as New generation workers
    Leader->>DB: fence old assignments; reserve DrainBoundary
    Ingest->>DB: continue appending observations
    DB-->>Old: no new old-generation claims
    Old->>DB: commit already-leased work before deadline
    Leader->>Old: cancel remaining work
    Leader->>DB: advance work fences and record requeues
    Old--xDB: stale late commit rejected
    Leader->>DB: atomic generation and cursor flip
    DB-->>New: claim post-boundary and requeued work
~~~

### 5.3 Coordinator failure recovery

The database operation row, not the process, owns progress. A replacement
control-plane leader takes the next operation lease and resumes from persisted
phase:

- before Draining, it may safely repeat verification and report comparison;
- during Draining, it preserves the recorded boundary and fences, then continues
  waiting/canceling;
- before the activation transaction commits, the old generation remains active
  for already-leased work but cannot gain new work;
- after commit, the new generation is authoritative even if the response to the
  caller was lost;
- an operation idempotency key returns the original OperationId/result rather
  than creating a second activation.

Database failure aborts the current transaction. There is no externally visible
half-flip.

## 6. Rollback, migration, and backfill

### 6.1 Rollback

Rollback is a new forward activation of a previously verified source generation.
It repeats compile/stage/hash/capability validation on all currently healthy
nodes, drains the current generation, and creates a new activation boundary. It
does not rewind database time.

Rollback eligibility is bounded by operator policy and retained source/state
namespaces. The admin preview reports:

- whether the old source and compiler/runtime inputs remain available;
- node compile/hash results;
- state compatibility;
- events and actions produced since the original cutover;
- dead-letter/outbox exposure;
- required explicit state strategy; and
- whether breaker policy permits activation.

State strategy is deterministic:

1. If old and current state schema IDs/hashes are identical, continue the current
   namespace.
2. If the rollback target declares a pure reverse migration from the current
   schema, use a new namespace and migrate lazily.
3. If the manifest permits reset, --state reset creates an empty namespace.
4. --state restore-retained uses the retained pre-activation namespace only with
   the separate backfill.apply_state capability and an explicit
   --accept-state-gap reason. The resulting gap is audited.
5. Otherwise rollback is rejected.

Already delivered actions are not compensated. Compensation, when required, is
a separately authored and authorized action workflow.

### 6.2 State migration

An unchanged stable SchemaId and canonical schema hash carries automatically.
Any other change requires a manifest-declared pure migration or reset.

For a pure migration:

- activation creates a new state namespace referencing its immutable source
  namespace and MigrationId;
- the first transaction reading a key runs migration in a restricted VM with no
  facts, history, services, state outside that key, effects, time, or randomness;
- the transaction verifies the source value/version, validates the result
  against the target schema/labels/size, writes target value and provenance, and
  continues the evaluation atomically;
- concurrent migrations use normal CAS; losers read the committed target;
- a background warmer uses the same code path and lower-priority leases;
- failure leaves the source untouched, writes a typed migration fault, and
  faults only work that requires the key;
- no fallback reads from the old schema after a target value exists; and
- the source namespace is retained read-only for the configured rollback window,
  then deleted through an audited retention operation.

Reset is explicit in the manifest and activation request; it cannot be inferred
from a missing migration.

### 6.3 Correlation start and backfill

New correlations begin at the generation activation cursor. They do not inspect
older history implicitly.

Backfill is a bounded asynchronous admin operation requiring event types,
tenant, peer scope, start/end ingest or event time, maximum event count/bytes,
target generation, and reason. Preview computes the exact query bounds,
estimated rows, required retention, classifications, state mode, and effect
policy.

Default behavior:

- deterministic event order;
- a separate BackfillRunId and isolated state/result namespace;
- no movement of the live correlation cursor;
- posts and captures forced to dry-run;
- no physical action dispatch or replay of external service calls;
- results labeled as backfill and excluded from normal breaker counts.

Applying backfill state to live groups requires backfill.apply_state, a manifest
declaration that the correlation is replay-safe, and serialization through the
same group leases as live work. Authorizing posts/captures additionally requires
backfill.authorize_effects with named sinks/profiles and a bounded approval
token. These are independent flags; --apply-state never implies effect dispatch.

## 7. Operational tooling behavior

### 7.1 Author flow

rule_engine_pack build canonicalizes and validates a source tree, executes an
enabled generator twice, emits the source-only archive, and optionally signs it
through an external key provider. It never embeds local compiled IR.

rule_engine_pack verify checks archive structure, source digest, dependency
closure, signature/trust policy, runtime pins, and limits. inspect emits a
redacted canonical manifest/index/schema/capability summary. stubs emits PEP 561
authoring stubs and generated typed binding APIs.

rule_engine_check uses the same worker, compiler, type system, schemas, optimizer
certificates, and diagnostics as the server. Watch mode cancels a stale compile
and publishes output only after a complete successful generation; it never
partially updates runtime state. SARIF locations use UTF-8 byte spans and stable
diagnostic codes. --explain-facts separates logical read routes from physical
prefetch. --explain-plan labels exact versus optimized paths and the certificate
reason for every elimination or refusal.

### 7.2 Operator flow

A normal production rollout is:

1. rule_engine_admin upload PACK --reason TEXT
2. rule_engine_admin stage DIGEST --wait
3. rule_engine_admin operation OPERATION_ID --format json
4. rule_engine_admin activate GENERATION --drain-timeout DURATION --wait
5. rule_engine_admin packs active

All mutating commands support --request-id and --reason. Commands default to
preview when destructive or externally visible, including rollback with changed
state, effect-authorized backfill, dead-letter redrive, and purge.

Admin output never prints private keys, connection strings, bearer material, raw
Secret fields, or unredacted Sensitive/Secret payloads. JSON output returns
stable IDs operators can use in later calls.

## 8. Invariants and guarantees

- At most one Active generation exists per PackId.
- No new old-generation assignment is created after drain fencing.
- No new-generation assignment is claimable before the activation transaction.
- A late result cannot commit without the exact generation, session/work lease,
  and fence tokens.
- Observation ingestion remains available throughout stage and drain.
- Activation is all-target-node or no activation.
- Nodes joining after target freeze cannot serve until they compile and verify
  the database-active generation.
- Platform-independent semantic and binding hashes agree across operating
  systems; platform executable hashes may differ but are recorded.
- Required capabilities are present on every serving node. Optional typed
  capabilities resolve consistently to either the binding or None cluster-wide.
- Activation, rollback, policy, quarantine, trace, capture, backfill, outbox,
  purge, and node-drain mutations are authenticated, authorized, idempotent, and
  audited.
- Rollback changes future execution only; it never claims to undo prior external
  effects.
- Lazy migration is atomic per key and never exposes partially validated state.
- Backfill never changes live state or dispatches effects without separate,
  explicit authority.

## 9. Failure modes and recovery

| Failure | Required behavior |
|---|---|
| Signature, manifest, dependency, or archive failure | Reject before compiling; retain auditable diagnostic, no generation |
| Worker crash, timeout, or limit | Node reports typed compile failure; stage cannot pass |
| One node compiler/schema/capability failure | Entire stage fails; active generation unchanged |
| Cross-node semantic/binding hash mismatch | Fail closed, quarantine staged artifacts for inspection, emit high-severity audit/metric |
| Node lease loss during stage | Stale report rejected; operation waits or aborts and must restage |
| Node joins during stage | Not added to frozen set; must compile active generation before readiness |
| Coordinator crash | New fenced leader resumes the persisted operation |
| Database disconnect before flip | Transaction aborts; no partial activation |
| Database disconnect after flip response is lost | Operation read shows committed new generation; repeat request returns same result |
| Hung old evaluation | Cancel, advance fence, roll back journal/state, and add durable successor requeue |
| Late old result | Reject by generation/work fence; record diagnostic counter |
| Node loses staged artifact before flip | Abort activation and restage; never fetch/compile after the flip |
| Migration contention | CAS loser reads winner's validated target |
| Migration fault | Source remains intact; typed fault and per-key/work failure |
| Rollback state incompatibility | Reject unless reverse migration, explicit reset, or authorized retained-state gap is selected |
| Backfill exceeds bound | Stop with durable partial progress; never expand bounds implicitly |
| Admin retry | Idempotency key returns the original operation |
| Notification loss | Node/database reconciliation repairs state |

## 10. Alternatives considered

### Rolling per-node activation

Rejected because two semantic generations would make state ownership,
correlation ordering, effect identity, and incident explanation ambiguous.

### Blue/green generations processing the same events

Useful as a shadow qualification tool, but rejected as activation behavior.
Shadow runs must use isolated state and no-dispatch journals and cannot publish
normal results.

### Quorum activation

Rejected initially because work may land on any healthy serving node and
optional capabilities must resolve consistently. Operators can explicitly drain
a broken node before staging, which removes it from the healthy serving set.

### Stop observation ingestion during drain

Rejected because provider inventory and telemetry loss is worse than bounded
queue growth. Ingestion and evaluation assignment are deliberately separate.

### Ship precompiled cross-platform IR

Rejected because the source/signature plus local compiler/runtime pins are the
auditable semantic root. Locally compiling catches platform/schema/capability
drift and avoids treating serialized IR as a second public execution format.

### Automatic rollback on post-activation runtime faults

Rejected because external actions cannot be undone and automated rollback may
compound an incident. Breakers quarantine narrowly; a rollback remains an
explicit audited operation.

### Implicit historical correlation replay

Rejected because it would change state and potentially create actions without
an operator-selected bound or effect policy.

### Local files or process memory as activation truth

Rejected because they cannot provide cross-node fencing, crash recovery, or an
atomic cursor transition.

## 11. Decision reasoning

Atomic activation follows directly from the engine's transactional semantics:
state, effects, correlation cursors, and executable meaning form one generation
boundary. Requiring all healthy serving nodes is conservative, but it makes
placement independent of semantics and turns configuration drift into a stage
failure rather than a runtime surprise.

Separating ingest from assignment keeps the telemetry boundary available while
still preventing generation overlap. A durable drain boundary plus explicit
requeue ledger handles stragglers without pretending all old work can always
finish.

Local source compilation and cross-node semantic hashes provide two independent
checks: provenance says what source was approved, and semantic agreement says
what each node believes that source means. The platform executable hash then
pins the concrete runtime identity used for breakers and replay.

Rollback is modeled as forward activation because database time, delivered
actions, and external systems cannot move backward atomically. Explicit state
strategies prevent a convenient rollback command from silently corrupting or
discarding state.

The admin API is asynchronous and idempotent because stage, drain, migration,
backfill, and purge outlive individual client connections. Narrow capabilities,
previews, and immutable audits are required because these controls can change
fleet behavior or release protected data.

## 12. Consequences and tradeoffs

Positive consequences:

- deterministic fleet-wide generation ownership;
- failures before the flip leave the current generation untouched;
- node drift is found during staging;
- control-plane retries are safe;
- ingress availability is independent of evaluation drain;
- rollback and backfill expose their irreversible consequences;
- local tooling shares production semantics.

Negative consequences:

- one unhealthy serving node blocks activation until it recovers or is
  explicitly drained;
- activation latency includes compile time and bounded evaluation drain;
- PostgreSQL is part of the production control-plane availability boundary;
- executable caches must retain staged and rollback artifacts;
- migration/backfill/state policy makes operations more explicit and verbose;
- a canceled old evaluation can be re-evaluated under new semantics;
- there is no instant, side-effect-reversing rollback.

## 13. Known limitations

- L-007: production active-active nodes still depend on one PostgreSQL primary/HA
  service and provide no global event order.
- L-009: replay and rollback cannot undo external effects.
- L-012: changed state needs migration/reset, generations never overlap, and
  retained-state rollback can contain an explicit state gap.
- L-013: event-time backfill remains bounded by retention and lateness policy.
- L-015: SQLite cannot implement production multi-node activation.
- L-016: author tooling initially relies on stubs, Pyright, source lookup, and
  compiler diagnostics rather than a custom LSP.
- L-018: activation performance is reported, but semantic/budget/stability gates
  take precedence over a new numeric throughput target.
- Activation availability is intentionally reduced by the all-healthy-node
  requirement.
- New correlations see only post-activation events unless bounded backfill is
  requested.
- Default isolated backfill results do not influence live correlation state.
- Development watch mode proves local atomicity only; it does not qualify
  distributed production activation.

## 14. Observability and diagnostics

### Health

- Liveness reports only whether the process event loop and watchdog are
  responsive.
- Readiness requires database connectivity/migrations, valid certificates and
  trust policy, required retention profiles, node lease ownership, compiled
  active generations, matching schemas/capabilities, and available mandatory
  sinks/services.
- A joining node stays unready while compiling the active generation.

### Metrics

At minimum expose bounded-label Prometheus series for:

- pack upload/verify/stage/activation/rollback totals and durations by outcome;
- current generation number/digest prefix as info, not a high-cardinality label;
- target node count, outstanding reports, hash mismatches, and compile failures;
- drain in-flight count, cancellations, requeues, late-fence rejections, and
  queued-ingest age;
- state migration attempts/success/fault/contention and remaining keys;
- backfill scanned/processed/faulted rows and dry-run effect counts;
- admin authentication/authorization failures;
- outbox retries/dead letters/redrives;
- node lease/fence changes and readiness; and
- structured diagnostic codes.

### Logs, audit, and traces

- JSON logs include timestamp, severity, node, operation, pack/generation,
  execution/event IDs, phase, diagnostic code, and redacted context.
- Sensitive and Secret values are never logged; labels and schema/field IDs may
  be logged.
- Durable audit records include actor, certificate, capability, request and
  idempotency IDs, before/after resource versions, reason, target, preview,
  decision, and linked operation.
- Optional OTLP spans cover upload verification, node compile, drain, flip,
  migration, and backfill, while keeping source/payload content out of span
  attributes.
- rule_engine_admin operation explains blockers in machine and human formats;
  no operator must infer stage state from server logs.

## 15. Required tests and acceptance criteria

- Unit-test every generation transition and reject illegal transitions.
- Property-test idempotent control mutations and monotonic fences.
- Run stage with one compile failure, one hash mismatch, missing capability,
  schema mismatch, worker crash, stale node lease, and joining node.
- Kill the coordinator in every persisted phase and prove another node resumes.
- Disconnect PostgreSQL immediately before and after the activation transaction
  and prove exactly one active generation.
- Ingest continuously during drain; prove no observation is lost and no new old
  assignment appears.
- Force a hung old evaluation; prove cancellation, rollback, durable requeue,
  late-commit rejection, and new-generation completion.
- Prove joining nodes cannot become ready without the active executable.
- Exercise unchanged state, forward migration, reverse migration, reset,
  migration contention/failure, background warming, retention expiry, and each
  rollback rejection.
- Exercise default isolated backfill, live-state-authorized backfill,
  effect-authorized backfill, bounds, cancellation/resume, and classification
  enforcement.
- Test mTLS/RBAC/idempotency/audit for every admin mutation and redaction for
  every machine output format.
- Golden-test CLI help, exit codes, JSON schema, SARIF spans, explain-facts, and
  explain-plan.
- Production acceptance requires two active server nodes, PostgreSQL 17+, one
  Windows agent, mixed Windows/Linux semantic hash agreement, a successful
  signed-pack activation, a fenced straggler, and a successful audited rollback.

## 16. Related decisions, contracts, and tasks

- ADR-002: trusted signed pack boundary.
- ADR-005: source-only signed rule packs.
- ADR-010: MVCC and captured replay.
- ADR-011: protocol v2 clean break.
- ADR-012: PostgreSQL active-active.
- ADR-013: atomic pack activation.
- ADR-018: big-bang YARA removal.
- Foundation contracts: Generation identity, CompiledPack, IRuntimeStore,
  activation cursor, schema/capability hashes, and fences.
- Tasks: PK1-PK3, R2-R3, P2, S1-S3, I1-I2, X1, and Q1.
- Verification detail: architecture/10-verification-and-cutover.md.
