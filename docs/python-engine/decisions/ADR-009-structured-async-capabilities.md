# ADR-009: Structured Async Capabilities

Status: accepted for `design-v1`\
Date: 2026-07-20\
Tasks: `V3`, `E3`, `V4`, `S2`, `I1`, `Q1`

## Context

Rules may need several independent read-only service results. Executing them strictly serially wastes the bounded elapsed deadline and reduces throughput. General Python async facilities, however, expose an ambient event loop, detached task creation, scheduler-dependent lifetime, arbitrary I/O, and objects that can outlive the transaction that owns their result. Those properties conflict with deterministic budgets, replay capture, cancellation, and the requirement that C++ own all capabilities.

Service reads are also semantically different from posts. A service response influences the current verdict and must be captured as an external input. A post is a future action and must wait for durable commit.

## Decision

Expose only typed operator-bound read-only/idempotent service capabilities and structured lexical concurrency:

1. A service method call validates/freezes its request and returns a **cold awaitable**. It sends nothing until directly awaited or passed to `TaskGroup.start`.
2. Every hot task belongs to exactly one implicit direct-await scope or explicit lexical `TaskGroup`.
3. Helpers may return cold awaitables and manipulate task handles only when the owning group is passed explicitly. Hot tasks cannot escape the group or evaluation through return, yield, state, effects, closures, or longer-lived generators.
4. Normal task-group exit defaults to `CANCEL_PENDING`; `WAIT_PENDING` is an explicit opt-in. Exceptional exit always cancels pending work.
5. Cancellation is locally final. Remote work may continue, but a late result cannot resume a closed group or affect the evaluation.
6. The evaluation deadline includes queueing, waits, retry delay, and cleanup. Each call uses the minimum of its configured deadline, profile maximum, and remaining evaluation time.
7. Permit one transient retry inside the original deadline for transport failure or typed 408/425/429/5xx equivalents. Use the same call/idempotency identity and a new attempt identity.
8. No implicit cross-evaluation cache exists. An explicit operator cache must be bounded by TTL/scope/labels and is captured like a response.
9. Responses, terminal errors, cache decisions, retry decisions, and completion order where observable are captured for replay.
10. Rule modules have no `asyncio`, event-loop, thread, subprocess, raw socket, or detached-task API.
11. Required capabilities must bind consistently across all active nodes; optional `Service | None` parameters receive `None` cluster-wide.

## Primary reasons

- It enables useful overlap of independent latency without losing lexical lifetime ownership.
- Cold calls preserve left-to-right semantics: constructing an awaitable has no hidden transport effect.
- C++ retains control over scheduling, deadlines, quotas, cancellation, schema validation, and replay.
- The structured boundary guarantees all hot work is closed before verdict/finalization.
- Captured typed responses let transparent retry and diagnostic replay avoid live service calls.
- Separating reads from actions keeps action delivery behind the durable transaction.

## Alternatives considered

### Synchronous service calls only

Rejected. It is simple but forces independent requests to consume latency serially and makes the 10-second elapsed profile unnecessarily restrictive.

### Full `asyncio`

Rejected. It would introduce an ambient scheduler and broad API surface, permit task escape and unsupported I/O, complicate deterministic teardown, and duplicate the C++ coordinator.

### Hot-by-default futures

Rejected. Merely constructing a call would start I/O, making expression refactoring change observable requests and complicating short-circuiting, budgets, and replay.

### Detached background tasks

Rejected. Work could outlive the rule, its capability lease, its journal, pack activation generation, or server session. Late completion would have no safe transaction owner.

### Implicit global deduplication/cache

Rejected. It would blur tenant/peer/label/policy boundaries and make freshness and replay semantics invisible. Caching must be explicit operator policy.

### Treat posts as awaitable service calls

Rejected. Awaiting an external write before durable commit would expose partial side effects and create duplicates on state retry/replay.

## Consequences

### Positive

- All started work has deterministic ownership and teardown.
- Concurrency, response bytes, call count, retries, and deadlines are centrally bounded.
- Service requests remain typed, labeled, and auditable.
- Helpers can compose async work without gaining an event loop.
- Replay can return the exact recorded service outcome and observable completion order.
- Pack activation can reject inconsistent capability availability before work begins.

### Negative

- Existing `asyncio` libraries and idioms cannot be reused.
- Authors must explicitly pass task groups through helpers that start work.
- `CANCEL_PENDING` may waste already-started remote work.
- Remote cancellation is not guaranteed; only local non-resumption is guaranteed.
- Operators must accurately assert that a service method is read-only/idempotent and configure schema/labels/deadlines.
- An explicit TTL cache adds operational invalidation and classification responsibilities.

## Operational and security implications

- Transport envelopes require execution/call/attempt/idempotency/causation IDs, schema/method version, deadline, tenant/peer scope, and labels.
- Metrics must expose scheduled/active counts, queue time, retries, cache hits, cancellation, cleanup timeout, late results, malformed responses, and status classes.
- A malformed or mismatched response never becomes `PyValue`; it is rejected at the host boundary and contributes to endpoint protocol health.
- Handler/finalizer tiers receive only explicitly marked handler-safe methods and their smaller limits.
- Service responses above the operator classification ceiling are rejected before entering the VM; logs retain only safe metadata.
- Evaluation teardown closes every task group before releasing the session or activation generation.

## Known limitations

- Cancellation cannot force a remote service to stop; remote resource use can continue until its own deadline.
- Only explicitly modeled structured-concurrency constructs are supported; general Python async libraries are unavailable (L-003).
- One retry may be insufficient for an unstable service, by design.
- Captured response retention and classification policy may make old diagnostic replay partial (L-009).
- Cache correctness and method idempotency are operator/service-owner obligations.
- The aggregate evaluation deadline can expire while waiting even when active VM CPU remains.

## Evidence and validation

- VM tests cover cold construction, direct await, start, repeated await, nested groups, normal/exceptional exit, `CANCEL_PENDING`, `WAIT_PENDING`, handle escape, generators, and helper composition.
- Transport tests cover request identity, schema validation, one retry, preserved deadline, deterministic jitter, `Retry-After`, cancellation, late replies, and stale attempt IDs.
- Budget tests cover scheduled/active/response-byte limits and cleanup under cancellation storms.
- Replay tests prove no live transport call and exact captured result/error/completion order.
- Multi-node activation tests prove required/optional capabilities resolve identically across healthy nodes.

## Revisit conditions

Revisit if representative packs demonstrate that the structured API cannot express a needed bounded pattern, or if transport data proves a different retry/deadline default is necessary. Adding a construct requires explicit ownership, escape analysis, cancellation, budget charges, capture/replay semantics, and cross-platform tests. General ambient `asyncio` or detached work remains outside this ADR unless the entire scheduler and transaction model is replaced.
