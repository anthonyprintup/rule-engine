# Known Limitations

Every entry records impact, rationale, mitigation, observability, and revisit condition. A newly discovered limitation must be added before its task can be marked complete.

## L-001 — Trusted generator boundary

- **Impact:** A deliberately malicious signed generator is outside the worker's security guarantee.
- **Rationale:** Pack provenance is an operational trust boundary; process controls protect server availability, not hostile Python execution.
- **Mitigation:** Signature trust policy, declared inputs, cleared environment, private runtime, import restrictions, process-tree/resource limits, and isolated deployment controls.
- **Observability:** Audit signer, digest, worker mode, limits, exit reason, and generated binding hash.
- **Revisit:** If untrusted third parties may submit packs, require an OS/container sandbox as a separate security project.

## L-002 — Static Python subset

- **Impact:** Complete Python 3.14 grammar is parsed, but unsupported dynamic constructs fail compilation.
- **Rationale:** C++ must own deterministic semantics, capabilities, budgets, and replay.
- **Mitigation:** Stable diagnostics, generated stubs, Pyright, modeled libraries, and source lookup.
- **Observability:** Compiler diagnostic-code counts by construct.
- **Revisit:** Add constructs only with typed HIR, VM, budget, replay, and differential-test designs.

## L-003 — Modeled standard library only

- **Impact:** Native extensions, ambient packages, Python `re`, OS/process/network/filesystem/time/random APIs, and unmodeled stdlib calls are unavailable to rules.
- **Rationale:** Ambient behavior violates deterministic capability ownership.
- **Mitigation:** Pure modeled APIs, explicit RE2, deterministic datetime, and operator capabilities.
- **Revisit:** Add a module only after specifying exact semantics and resource costs in C++.

## L-004 — Worker limits reject some valid source

- **Impact:** Very large or deeply nested valid Python can be rejected.
- **Rationale:** CPython AST processing can exhaust stack or memory.
- **Mitigation:** Clear limit diagnostics and named versioned profiles.
- **Revisit:** Only after parser/worker hardening demonstrates safe larger bounds.

## L-005 — Generator double-run is not proof

- **Impact:** Two equal runs do not mathematically prove determinism.
- **Rationale:** It catches operational nondeterminism while retaining normal trusted Python tooling.
- **Mitigation:** Different hash seeds, clean processes, canonical C++ validation, content-addressed inputs, and replayable audits.
- **Revisit:** If stronger assurance is required, replace executed generators with a declarative generator language.

## L-006 — Platform scope

- **Impact:** No Linux provider agent initially; Windows provider behavior depends on process privileges, protected-process policy, and live-memory races.
- **Rationale:** Existing provider investment and requirements are Windows-specific.
- **Mitigation:** Typed errors, authoritative reconciliation, bounded retries, and Linux server portability.
- **Revisit:** Add Linux agents only with an equivalent provider/schema/security specification.

## L-007 — PostgreSQL topology and ordering

- **Impact:** Active-active servers share one PostgreSQL primary/HA service; there is no database multi-primary or global total event order.
- **Rationale:** Fenced row leases and per-peer/group serial order provide needed correctness with tractable operations.
- **Mitigation:** Durable ingest cursors, idempotency, explicit ordering keys, and HA PostgreSQL deployment.
- **Revisit:** Only if a concrete cross-region ordering/availability requirement justifies a different store architecture.

## L-008 — At-least-once actions

- **Impact:** External endpoints may receive a request more than once.
- **Rationale:** Durable outbox recovery cannot atomically commit with arbitrary external systems.
- **Mitigation:** Deterministic idempotency keys, typed acknowledgements, retry bounds, and dead letters.
- **Revisit:** Add endpoint-specific exactly-once integration only when the external system offers a transactional protocol.

## L-009 — Replay boundary

- **Impact:** Replay reproduces captured engine inputs but cannot undo or re-perform external side effects.
- **Rationale:** Replays are diagnostic/consistency executions.
- **Mitigation:** Disable dispatch, capture service responses/time/hash seed/facts, and compare intended journals.
- **Revisit:** Never allow ordinary replay to dispatch; provide a separately authorized redrive workflow if needed.

## L-010 — Conservative optimization

- **Impact:** Full recording, effects, state, services, history, or uncertain faults may force exact VM execution.
- **Rationale:** Optimization cannot alter observable behavior or provider privacy.
- **Mitigation:** Compiler certificates, shadow parity, and targeted pure-prefix planning.
- **Revisit:** Expand only with equivalence proofs and parity coverage.

## L-011 — RE2 rather than Python regex

- **Impact:** Backreferences, lookbehind, and other Python `re` constructs are rejected.
- **Rationale:** RE2 provides bounded-time matching suitable for agents.
- **Mitigation:** Dialect-specific diagnostics and authoring documentation.
- **Revisit:** Add another engine only with equivalent resource guarantees.

## L-012 — State and activation

- **Impact:** State schema changes require explicit pure migration or reset; old/new generations never execute concurrently.
- **Rationale:** This prevents ambiguous ownership and mixed-semantics state.
- **Mitigation:** Lazy transactional migration, background warming, retained rollback namespace, bounded drain/cancel.
- **Revisit:** Cross-generation coexistence would require a new state/effect consistency model.

## L-013 — Event time

- **Impact:** Ingest order is default; event-time mode accepts only operator-bounded lateness.
- **Rationale:** Unbounded lateness prevents bounded history and deterministic progress.
- **Mitigation:** Preserve both timestamps and make lateness explicit.
- **Revisit:** Only with a new watermark/retention design.

## L-014 — Conservative data labels

- **Impact:** Control-flow taint can overclassify derived data.
- **Rationale:** False-positive restriction is safer than covert leakage.
- **Mitigation:** Named audited declassification transforms and diagnostic provenance.
- **Revisit:** Improve precision only without weakening noninterference guarantees.

## L-015 — SQLite development scope

- **Impact:** SQLite supports one server process only and is not production cluster storage.
- **Rationale:** It provides low-friction local development behind the same interface.
- **Mitigation:** Production startup requires PostgreSQL unless explicit dev mode is selected.
- **Revisit:** None without redefining the production store contract.

## L-016 — Tooling and migration

- **Impact:** No custom LSP and no automatic YARA-to-Python translator are delivered initially.
- **Rationale:** Generated PEP 561 stubs, Pyright, source lookup, and precise compiler diagnostics cover authoring without preserving YARA semantics.
- **Mitigation:** Author guide, examples, check/watch/SARIF tools, and explicit clean break.
- **Revisit:** Add an LSP if real authoring workflows outgrow the generated tooling; do not reintroduce YARA compatibility.

## L-017 — Boundary values

- **Impact:** Cyclic VM objects cannot cross service/event/effect/state/persistence boundaries.
- **Rationale:** Canonical deterministic wire and storage representations are acyclic.
- **Mitigation:** Typed immutable records and a precise boundary validation error.
- **Revisit:** Only with a versioned graph serialization model.

## L-018 — Performance gate

- **Impact:** There is no independent numeric throughput threshold for the first rewrite.
- **Rationale:** Semantics, safety, budget compliance, and stability are the release gates while the workload model changes fundamentally.
- **Mitigation:** Preserve checkpoint benchmarks, report exact/optimized deltas, and run a 10,000-peer stability simulation.
- **Revisit:** Set service-level performance targets after representative production measurements exist.

## L-019 — State-conflict replay can diverge

- **Impact:** Refreshed state can make a retry reach an external read that the original attempt never captured.
- **Rationale:** Mixing a newly observed external value into an otherwise sealed retry would combine observation epochs and invalidate deterministic replay.
- **Mitigation:** Fail the retry as `StateConflictReplayDiverged`, preserve the original capture for diagnosis, and require a later ordinary event to evaluate with fresh inputs.
- **Observability:** Record the newly reached operation, source span, capture membership, attempt number, and state versions without performing the read.
- **Revisit:** Only if the engine adopts an explicit multi-epoch replay model with separately specified semantics.

## L-020 — Rollback does not reverse-migrate state

- **Impact:** If a new generation changed the state schema and wrote its new namespace, rolling activation back does not synthesize reverse migrations.
- **Rationale:** Automatically reversing arbitrary pure forward migrations is generally impossible and could corrupt state.
- **Mitigation:** Retain the old namespace for the rollback window, fence new-generation writes during rollback, and require an explicit forward repair before reactivation.
- **Observability:** Activation audits report namespace selection, migrated/warmed keys, rollback eligibility, and discarded new-generation work.
- **Revisit:** A pack may supply a separately reviewed reverse migration, but it is never inferred.

## L-021 — Socket orchestration is not a complete network service runtime

- **Impact:** The default system DNS resolver cannot guarantee a hard wall-clock deadline once the operating system's `getaddrinfo` call is in flight. The current connection facade permits one synchronous operation at a time, listener binds are numeric, the listener does not own a multi-worker scheduler, and TLS `close_notify` is best-effort.
- **Rationale:** Standalone Asio delegates name resolution to the platform resolver, whose cancellation behavior is platform-dependent. This slice owns bounded socket/TLS/session primitives rather than server thread-pool policy, service lifecycle, or a cross-platform asynchronous DNS implementation.
- **Mitigation:** Production configuration can set `require_hard_resolver_bounds` and inject an `IEndpointResolver` that advertises and implements hard deadline and cancellation bounds; the dialer fails closed before resolution otherwise. Callers serialize connection operations, resolve listener names before binding, supply bounded accept workers externally, and always close the socket after bounded best-effort TLS shutdown.
- **Observability:** Record resolver implementation/capability, configured and elapsed resolve/connect/handshake/read/write deadlines, endpoint/address attempts, cancellations, accept-worker saturation, and TLS shutdown outcome.
- **Revisit:** Replace the system resolver with a proven cross-platform cancelable DNS backend and add an owned bounded session scheduler when production service composition is implemented; strengthen TLS shutdown only if a separately bounded bidirectional close is operationally required.

## L-022 — The production Windows agent accepts numeric server endpoints only

- **Impact:** `rule_engine_agent` cannot resolve DNS names in `server_endpoint`; operators configure one to eight IPv4/IPv6 addresses plus a separate certificate `server_name`.
- **Rationale:** The platform `getaddrinfo` path cannot prove a hard deadline after resolution enters the OS. Claiming a hard resolver bound would weaken the production abuse boundary.
- **Mitigation:** Configuration rejects nonnumeric endpoints, the injected numeric resolver is immediate and cancellation-aware, reconnects fail over the bounded address list, and TLS still verifies the configured DNS name, chain, exact URI SAN, and exact SHA-256 fingerprint.
- **Observability:** Configuration validation reports endpoint syntax without printing credential contents; connection diagnostics identify only the attempted numeric endpoint and failure class.
- **Revisit:** Permit DNS only after integrating a resolver backend with tested hard cancellation and deadline guarantees.

## L-023 — Provider dispatch cannot consume a later cancel frame concurrently

- **Impact:** Once a fact/scan provider call begins, a cancel message arriving on the same synchronous TLS connection is handled only after that call returns.
- **Rationale:** The current agent loop deliberately serializes one socket operation and one data-provider dispatch; introducing an unbounded worker/thread model would create a larger resource-exhaustion surface.
- **Mitigation:** Every accepted request has an absolute provider deadline, the agent rejects deadlines more than 60 seconds in the future, queued cancellation is applied before subsequent dispatch, console shutdown cancels bounded transport operations, and providers return only typed terminal statuses.
- **Observability:** Agent counters distinguish accepted work, canceled work, deadline/provider failures, reconnects, and durable replay.
- **Revisit:** Add a bounded owned dispatch scheduler and an independent control-frame reader only with explicit queue, worker, memory, and shutdown limits.

## L-024 — Initial process inventory is once per agent process

- **Impact:** The agent publishes one authoritative process snapshot after its first successful session; it does not yet own a periodic inventory scheduler. Partial/failed enumeration publishes nothing, preserving the coordinator's last-good view.
- **Rationale:** Inventory cadence and fleet-wide jitter are coordinator/operations policy, while this slice establishes the durable snapshot and provider trust boundaries.
- **Mitigation:** A successful begin/chunk/commit projection is validated and inserted into SQLite atomically before any frame is sent. Pending rows replay after reconnect, and the snapshot is not regenerated during that process lifetime.
- **Observability:** Snapshot rows, replay counts, provider inventory attempts, and absence of a new authoritative commit expose the current state without treating partial enumeration as deletion.
- **Revisit:** Add a bounded, jittered reconciliation schedule with explicit cadence, overlap, and backpressure policy.

## L-025 — Agent certificate revocation is not checked online

- **Impact:** The production agent validates the TLS chain, DNS name, exact URI SAN, and pinned SHA-256 certificate fingerprint, but this slice does not configure CRL files or OCSP fetching.
- **Rationale:** Online revocation checks can add unbounded network dependencies, while a required local CRL needs a separately specified refresh and fail-closed expiry lifecycle.
- **Mitigation:** Operators rotate the exact configured fingerprint and trust bundle through deployment configuration; startup fails closed when either does not match or credentials cannot be loaded.
- **Observability:** Authentication failures expose only the failure class and never certificate, private-key, or trust-bundle contents.
- **Revisit:** Add an operator-managed, expiry-checked local CRL or a separately bounded stapled-status design before claiming revocation coverage.
