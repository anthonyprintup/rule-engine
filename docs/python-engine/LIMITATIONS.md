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

- **Impact:** The default system DNS resolver cannot guarantee a hard wall-clock deadline once the operating system's `getaddrinfo` call is in flight. The connection facade permits one synchronous operation at a time, listener binds are numeric, and TLS `close_notify` is best-effort.
- **Rationale:** Standalone Asio delegates name resolution to the platform resolver, whose cancellation behavior is platform-dependent. A separately bounded service scheduler does not make the operating-system resolver cancelable or make a bidirectional TLS close deterministic.
- **Mitigation:** Production configuration requires hard resolver bounds and numeric listener addresses. The resident server owns fixed workers, a bounded queue and application-memory reservation, per-session limits/deadlines, stop-token cancellation, and joined shutdown; sockets are closed after bounded best-effort TLS shutdown.
- **Observability:** Record resolver implementation/capability, configured and elapsed resolve/connect/handshake/read/write deadlines, endpoint/address attempts, cancellations, accept-worker saturation, and TLS shutdown outcome.
- **Revisit:** Replace the system resolver with a proven cross-platform cancelable DNS backend; strengthen TLS shutdown only if a separately bounded bidirectional close is operationally required.

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

## L-024 — Process inventory refresh uses a fixed per-agent cadence

- **Impact:** The agent publishes an immediate authoritative process snapshot and refreshes it every configured interval, but agents with identical start times and settings are not fleet-jittered. A very short fleet-wide cadence can therefore create synchronized enumeration and ingress load.
- **Rationale:** One synchronous deadline-driven session owner preserves socket ordering, cancellation, and the single-writer spool boundary. The scheduler waits for either readable input or the next inventory deadline and never starts overlapping enumerations.
- **Mitigation:** `inventory_refresh_interval_ms` is mandatory and accepts only 1,000 through 86,400,000 milliseconds. Each successful enumeration becomes a complete begin/chunk/commit batch, is validated, and is inserted into SQLite atomically before first transmission. Its checked monotonic inventory generation combines the active runtime generation with the durable spool sequence, starting above the legacy generation-only scheme so reconnect, upgrade, and process restart cannot reuse an acknowledged generation. Failed or partial enumeration publishes no batch, preserving the coordinator's last-good authority; pending rows replay normally after reconnect.
- **Observability:** Agent run statistics distinguish refresh attempts, authoritative generations spooled, refreshes without authority, snapshot records, connections, and replay. The absence of a new authoritative commit is never interpreted as an empty inventory.
- **Revisit:** Add bounded deterministic fleet jitter and exported cadence/lag metrics after production fleet-load measurements define an acceptable distribution policy.

## L-025 — Agent certificate revocation is not checked online

- **Impact:** The production agent can enforce an operator-provisioned local CRL, but it does not fetch OCSP/CRL data or reload a replaced CRL while running. An agent without explicit local-CRL enablement still relies on its exact certificate fingerprint and trust bundle.
- **Rationale:** Ambient online revocation introduces an independently failure-prone and potentially unbounded network dependency. Local files keep acquisition and refresh under deployment control while OpenSSL performs deterministic verification during the bounded TLS handshake.
- **Mitigation:** Configure `crl_path` and `require_crl = true` together. Startup rejects a missing or malformed CRL, and full-chain CRL verification rejects missing issuer coverage, a stale CRL, a wrong issuer, or a revoked server certificate. Publish refreshed CRLs atomically and restart agents before `nextUpdate`; continue rotating the exact fingerprint and trust bundle through controlled deployment.
- **Observability:** Configuration and authentication failures expose only the failure class and never certificate, private-key, CRL, or trust-bundle contents.
- **Revisit:** Add a bounded atomic local-file reload lifecycle or separately bounded stapled-status design before claiming live refresh or online revocation coverage.

## L-026 — Container and iteration frontend is intentionally partial

- **Impact:** The current compiler lowers fresh list/tuple/dictionary displays, subscription reads, one-target list/dictionary item assignment, and synchronous local-target `for`/`else`/`break`/`continue`. It also lowers module-level scalar `StateKey` declarations with `PEER` or `SUBJECT` scope and `state.get`, `state.set`, or `state.delete` used directly in a reportable entrypoint. Starred and `**` expansion, sets, slices, comprehensions/generator expressions, item deletion, destructuring targets, `range`, `async for`, arbitrary iterator protocols, state records, non-`None` defaults, wider scopes or classifications, explicit state identities, compare-and-set/require, helper ownership, shared state, and migrations still fail compilation.
- **Rationale:** The available fixed-display and iterator opcodes can express the delivered slice with exact ordering and hard charges. The deferred constructs need additional builder, scope, unwind, async, capability, identity, or replay contracts; approximating them would change Python behavior or weaken the trust boundary.
- **Mitigation:** Stable source-spanned diagnostics reject every deferred form. The exact private-CPython-worker-to-C++-VM tests cover delivered ordering, control flow, verifier dataflow, budgets, scalar state declaration typing, injected-capability erasure, state bytecode, and mutation journals. The resident evaluator independently derives tenant/pack/activation/executable plus peer or canonical-subject physical ownership; rule source cannot choose the durable physical namespace.
- **Observability:** Count `PY-NYI-COLLECTION-UNPACKING`, `PY-NYI-SLICE-LOWERING`, `PY-NYI-COMPREHENSION-LOWERING`, `PY-NYI-ITERATION-TARGET`, `PY-NYI-DELETE-LOWERING`, `PY-NYI-STATE-DEFAULT`, `PY-NYI-STATE-CLASSIFICATION`, `PY-NYI-STATE-IDENTITY`, `PY-NYI-STATE-HELPER`, `PY-NYI-SHARED-STATE`, and `PY-NYI-STATE-LOWERING` diagnostics by pack and source span.
- **Revisit:** Add one construct at a time only after its typed HIR, exact VM opcode semantics, verifier rules, precharge behavior, CPython differential vectors, and persistence/replay effects are specified and tested.

## L-027 — Provider container schemas and catalog generation are partial

- **Impact:** Fact schema identity protects scalar built-ins and exact top-level record descriptors, but the current built-in `list`/`map` identities do not describe recursive element/key/value types. The Windows route and composite-value descriptors are also maintained as a versioned C++ catalog rather than generated from the author/compiler schema source, so catalog drift can reject otherwise valid work until both sides are updated.
- **Rationale:** The frozen fact-value and `SchemaDescriptor` contracts do not yet express recursive generic container arguments or all optional/union shapes. Inventing an unversioned nested descriptor would create ambiguous semantics at the trust boundary.
- **Mitigation:** Every request and value response carries an exact independently sourced top-level ID/hash; mismatches, unknown routes, malformed terminal unions, and top-level value-kind/record-schema mismatches fail closed before VM exposure. Only cataloged routes are dispatchable, and composite descriptor strings are versioned and deterministically hashed.
- **Observability:** Provider/protocol faults identify the route and schema mismatch class without logging fact contents; catalog mismatch tests cover wrong hashes and missing/mixed schema identities.
- **Revisit:** Generate provider route artifacts from the authoritative compiler schema catalog after the contract supports recursive containers and optional/union fields, then add cross-artifact hash fixtures and nested structural validation.

## L-028 — The exception frontend is intentionally closed

- **Impact:** Source may raise only `ValueError`, `TypeError`, and `ArithmeticError`, and may catch those types or `Exception`. Handler binding, tuple/computed filters, user-defined exception classes, exception causes, exception groups/`except*`, and bare re-raise from a `finally` body fail compilation.
- **Rationale:** The verified bytecode ABI currently models a closed exception kind and message, not arbitrary exception instances, cause/context/traceback graphs, handler-bound object lifetimes, or Python's missing-active-exception `RuntimeError`. Approximating those features would change observable Python behavior and could confuse catchable author failures with uncatchable engine hard faults.
- **Mitigation:** Stable source-spanned diagnostics reject the unsupported surface. Exact CPython-worker-to-compiler-to-VM tests cover ordered typed matching, catch-all behavior, nested handlers, `else`, `finally`, re-raise, loop/return cleanup, and implicit value/type/arithmetic faults. Instruction-budget exhaustion, deployment cancellation, and VM integrity faults bypass source handlers and are tested separately from forced cleanup.
- **Observability:** Count `PY-NYI-EXCEPTION-FILTER`, `PY-NYI-EXCEPTION-BINDING`, `PY-NYI-EXCEPTION-GROUP`, `PY-NYI-RAISE-EXPRESSION`, `PY-NYI-RAISE-CAUSE`, and `PY-NYI-BARE-RAISE` by pack and source span. Verifier failures retain the existing `PYC0112` handler-filter-cycle and `PYC0114` cleanup-bypass diagnostics.
- **Revisit:** Expand only after versioning typed exception descriptors, cause/context/traceback representation, handler-scope unwind metadata, a catchable missing-active-exception value, exception-group splitting/merge semantics, and their verifier and budget rules.

## L-029 — Logical allocation has no distinct `balanced.v1` ceiling

- **Impact:** State-conflict retries cannot exceed the 16 MiB live heap in any attempt and cannot multiply the cumulative instruction or other semantic budgets, but allocation churn is not independently bounded by one cross-attempt byte total.
- **Rationale:** The immutable `balanced.v1` contract defines `heap_bytes` as a live-heap peak and does not assign a separate numeric ceiling to cumulative logical allocation work. Reusing that field would silently change the profile and reduce a retry's allowed live heap.
- **Mitigation:** `RegisterVmSession` reports logical allocation work; the resident aggregates it with overflow-safe arithmetic and exposes it in the evaluation receipt. The three-attempt bound, cumulative instructions/CPU/time, and per-attempt live-heap peak still bound abuse.
- **Observability:** Record per-attempt and cumulative logical allocation bytes alongside peak live heap and the remaining normal profile.
- **Revisit:** Add an independently named logical-allocation limit only in a new budget-profile version with boundary, retry, and representative-workload evidence.

## L-030 — Custom-event envelope metadata and author conveniences are partial

- **Impact:** Authors can declare `@schema`-pinned `EventRecord` classes, assign explicit positive `wire_field` IDs, omit fields with type-correct canonical `bool`, `int`, `float`, `str`, or `bytes` defaults, and call `telemetry.emit(record)` as a standalone statement. Dynamic and aggregate defaults, positional construction, and use of the returned `EventReceipt` inside rule bytecode are rejected. Projected envelopes retain root causation only and reuse the root ingest timestamp because the durable contract has no immediate-parent/depth or commit-clock fields. Evaluation records written before the event-journal codec marker require an explicit migration or development-store rebuild.
- **Rationale:** Keyword-only construction preserves explicit expression evaluation order while canonical scalar defaults are parsed as AST data, type-checked, included in schema and semantic hashes, and lowered to ordinary constants without CPython execution. Dynamic or aggregate defaults remain closed until their allocation, mutability, and evaluation-order semantics are explicit. A receipt cannot be exposed until its exact immutable record representation and field access semantics exist. Assigning parent/depth/timestamps without durable fields or a transactional database clock would create misleading metadata.
- **Mitigation:** The compiler derives `SchemaKind::event` only from the recognized `EventRecord` base plus one literal stable `@schema` decorator, validates unique field IDs, field types, and scalar defaults, materializes every omitted default before a verifier-pinned `build_record`, then emits `emit_event`. The VM reconstructs fields from the active descriptor, validates and freezes the record, and every durable store cross-checks deterministic intent identity, order, inherited context, causation, timestamps, label, and exact payload before commit. Missing required fields and unsupported constructor or receipt usage fail compilation. Operators must migrate or recreate pre-marker development result rows before upgrading.
- **Observability:** Count `PY-EVENT-SCHEMA`, `PY-EVENT-FIELD`, `PY-EVENT-CONSTRUCTOR`, `PY-EVENT-EMIT`, and `PY-EVENT-RECEIPT` diagnostics; `PYC0116` verifier failures; `EventProjectionErrorCode` failures; store intent/envelope mismatch rejections; event budget faults; and unsupported evaluation-codec versions.
- **Revisit:** Add dynamic or aggregate defaults and a typed receipt record only with explicit bytecode, allocation, and schema semantics. Extend envelopes with immediate-parent/depth and commit timestamps only through a versioned store migration and transactionally assigned metadata/clock semantics.

## L-031 — Resident host services and retry are partial

- **Impact:** An activated signed pack can evaluate subjects from committed authoritative snapshots and complete fact or scan suspensions through the agent protocol. The resident runtime performs durable state reads/writes entirely on the server for verified bytecode, and the Python frontend emits that bytecode for the scalar peer/subject subset in L-026. A state MVCC conflict transparently starts a fresh VM at most twice, rereads current state, and reuses exact captured fact/scan responses without another agent dispatch. If a process stops after a work result is durable but before its VM transaction commits, a same-node restart can reconstruct bounded contiguous fact/scan rounds and consume them through a fresh VM without redispatch; a different node still waits for lease expiry. Capability/service and history host turns are not yet connected, so they are not part of resident conflict or restart replay. Migration programs are not yet composed into resident state reads. One suspended VM turn must remain on a single agent route. An activation flip forces connected agents to reconnect before more old-generation work can be accepted; it is a bounded disruption rather than a process restart. VM frames, heap, journals, and cumulative usage are not checkpointed, so a process restart resets normal-budget accounting and cannot resume an arbitrary mid-instruction continuation.
- **Rationale:** C++ must retain exact rule semantics, budgets, ordering, and commit authority. Adding another host port or route handoff requires an explicit typed request/response contract and durable continuation rules; silently approximating one would make replay or failover produce a different decision.
- **Mitigation:** Startup and live refresh load the content-addressed archive named by durable activation state, verify its signature and signer policy, compile it with the pinned worker, and compare source, compiler ABI, semantic, binding, and executable identities before serving it. The activation fence backpressures new sessions and returns `stale_generation` to old sessions; the scheduler swaps only after they drain. Durable snapshot replay reconstructs deterministic work IDs, coordinator leases fence each attempt, returned observations resume the verified C++ VM, and the terminal transaction commits atomically. State requests never cross the agent boundary: the scheduler verifies pack ownership, derives an opaque physical namespace from tenant, pack, the activation-selected namespace, and the bytecode's logical namespace, reads the durable cell, and rewrites committed mutations to that same physical identity. On conflict, the scheduler discards candidate journals, checked-adds the VM's normal resource usage, derives the remaining immutable `balanced.v1` profile, and starts a fresh session. It requires every replayed fact/scan request to match its sealed canonical identity, fails on extra or missing rounds, and stops after three total attempts. Restart recovery accepts only durable results whose session/peer/fence/generation/work-round identities were prevalidated, requires contiguous canonical rounds, caps retained recovery input at 16 MiB per work and 64 MiB per scheduler construction, and lets the new VM validate every response against its reproduced request. Stable node identity may reacquire the same lease, but its fence must match every recovered round; attempt identities must be well formed, round-correlated, and consistent across the recovered work. Another node cannot steal the lease. A result durably committed at the same instant as an activation fence is not ingested by the old scheduler and is replayed idempotently after reconnect. Unsupported host turns and other store failures fail closed.
- **Observability:** Readiness identifies archive, trust, compilation, or activation-evidence failures. Runtime-store inspection exposes committed agent messages, work leases, fences, receipts, physical state cells, and final evaluation transactions; durable audit records ingress and evaluation commits. Stable protocol errors identify unsupported host turns, invalid state ownership, durable state failures, replay divergence or exhaustion, resource-accounting failure, route mismatch, stale work, schema mismatch, and capability mismatch. Retry-attempt and captured-byte production metrics are not yet exported.
- **Revisit:** Compose typed capability/service and history ports and extend their inputs to the sealed resident capture; route state reads through the reviewed lazy migration program; partition or join multi-route work without exposing semantics to agents; add a versioned durable usage/checkpoint contract if crash-based budget continuity or arbitrary continuation recovery becomes a requirement; shorten safe cross-node takeover through an explicit lease handoff rather than fence theft; and export retry, divergence, contention, and captured-byte metrics. The configured memory bound covers owned application reservations; OS socket buffers, TLS-library allocations, allocator overhead, and backend-internal memory require separate process/container limits and measurement.

## L-032 — The built-in signing adapter is Windows raw-seed only

- **Impact:** The shipped signer reads one raw 32-byte Ed25519 seed from a protected local Windows file. It does not implement PEM/PKCS#8, HSM, KMS, PKCS#11, remote signing, key generation, backup, rotation, or ceremony. The seed lifetime remains caller/process managed; it is cleansed after use but is not held in guaranteed page-locked memory. The selected OpenSSL DLL is absolute and version-checked but is not independently hash-pinned by the signer. Strict DACL rules can reject legitimate enterprise ACL variants.
- **Rationale:** A small fail-closed offline adapter establishes interoperable signing without embedding a key-management product or silently accepting ambiguous key encodings and permissions.
- **Mitigation:** Keep signing offline, protect and monitor the seed outside the repository, validate the derived public-key ID against policy, use an explicit crypto-library path, and supply a separately reviewed `ISigningKeyProvider` for production HSM/KMS ownership.
- **Observability:** Signing diagnostics expose only the failure class and public key ID; they never log the seed, its contents, or a secret-bearing path.
- **Revisit:** Add a provider only with explicit key identity, authorization, audit, cancellation, zeroization, rotation, and deterministic-signature contracts plus integration tests for the real device/service.

## L-033 — Filesystem and administration adapters are intentionally narrow

- **Impact:** Atomic no-clobber archive publication depends on a same-directory hard link and fails on filesystems without hard-link support. Schema-v3 registry lifecycle is filesystem-backed: it has bounded tenant/global accounting, partial expiry, reachability GC, and bounded aggregate maintenance observation, but no remote/object-store adapter, per-pack quota, admin-triggered maintenance command, or Prometheus maintenance series. Completion metadata is capped at 4,096 global and 1,024 per tenant; reaching a cap rejects new uploads until retention cleanup or operator investigation. Manually provisioned objects count against global bytes but have no upload-completion age and are intentionally not garbage-collected. Upload metadata v1 is not migrated automatically. `--watch` has no platform filesystem-event source, and cancellation is observed between compiler phases rather than forcibly terminating an in-flight parser worker. Stage and rollback currently expose only carry-forward state identity even though carry-mode resident reads/writes are durable; migration, reset, and retained-gap administration remains closed. Online policy mutation is deliberately not connected. Policy and resident-capability snapshots hash the raw bytes of deployment-owned files, so non-semantic edits are intentionally distinct. Durable generation payloads from codec versions 1 and 2 contain no activation-policy snapshot, while versions 1 through 3 contain no direct per-node state-schema attestation; they require restaging before the current resident can serve them. Rollback under a changed policy must be expressed as an ordinary new stage.
- **Rationale:** Cross-volume replacement, remote-object publication, forced worker interruption, and every privileged lifecycle need separately bounded, server-owned durability semantics. Accepting client-supplied compilation evidence, deleting retained rollback source, or claiming unbounded filesystem storage is production-safe would violate that boundary.
- **Mitigation:** Uploads are authorized before every phase, tenant-scoped, limited to the `balanced.v1` 16 MiB source-closure bound, globally serialized across local server processes, capped at 64 partial sessions and 256 MiB of reservations, charged conservatively against explicit global/tenant byte quotas, exact-byte replay checked, durably appended, signer/pack identity verified, and published without replacement. Startup and minute-cadence maintenance preserve every digest referenced by any durable generation, expire abandoned partials, and remove only uploaded objects older than explicit unreferenced retention. Stage authorization runs before the source registry is touched. Resident records are tied to fenced runtime leases and a sorted versioned capability inventory; stage and rollback freeze exact node/platform/fence/expiry/capability evidence, select only nodes satisfying every pack requirement, each target independently reopens and verifies the digest, and the generation cannot become ready until every still-current target reports matching C++ compilation identities. Stage preview first compiles the trusted source with the exact private runtime and persists the SHA-256 identity of every typed state declaration; the optional CLI state-schema value is only a mismatch guard. Resident reports bind that identity through semantic/executable hashes, and startup directly compares the freshly compiled state identity with durable generation evidence. The durable request and idempotency fingerprint bind one `activation-policy.v1` SHA-256 identity covering all configured trust, authorization, capability, schema, budget, retention, trace, capture, service, and sink inputs; compile, report, restart readiness, rollback, and the resident state namespace fail closed on a different bundle. Rollback source identity is reconstructed from durable retained evidence and semantic/binding/state drift fails the operation. Operation waits reconnect by durable operation ID under explicit interval and deadline bounds. Use a local hard-link-capable ACL-protected registry with external capacity monitoring. Unconnected admin commands fail closed with `ADMIN-NOT-IMPLEMENTED`.
- **Observability:** Upload responses expose only bounded progress and the final source digest; operation polling exposes the durable phase and returns typed terminal failure or timeout. Startup fails readiness if maintenance cannot safely inventory, clean, or durably record the registry pass. The protected registry retains one aggregate and the latest 32 successful pass records; an authorized pack snapshot exposes only counts and the last-success timestamp, never source content, digests, tenant identities, or filesystem paths. Later upload requests expose quota or registry unavailability. Typed failures distinguish malformed/replayed bytes, exhausted capacity, trust rejection, unavailable storage, cancellation generation, worker timeout, and transport failure without partially activating a pack. Failed passes cannot promise an additional registry audit write when that same storage is unavailable, and maintenance counters are not yet exported to Prometheus.
- **Revisit:** Add authenticated migration/reset/retained-gap state strategies only after their runtime state transitions are composed; add an object-store adapter and external maintenance time-series exporter, platform event adapters, phase-aware worker cancellation, an alternative atomic publication protocol, and—only if operationally required—an atomic cluster policy-deployment service with semantic canonicalization and migration tooling.

## L-034 — Portable and PostgreSQL release qualification is incomplete

- **Impact:** The implementation host qualified Windows only. Linux compilation/packaging/private-runtime behavior, live PostgreSQL 17 linking and migrations, mixed-OS semantic hashes, multi-node failover, and real network/database scale are not proven. The guarded PostgreSQL adapter currently owns one mutexed connection rather than a production pool.
- **Rationale:** WSL was absent, the available Docker daemon supported Windows containers only, and PostgreSQL client/development tools were unavailable. Required architecture cells cannot be inferred from Windows builds or fakes.
- **Mitigation:** Keep production-cluster readiness fail-closed, publish the exact qualified/unqualified matrix, and treat SQLite plus the 10,000-peer in-memory model as development/component evidence only.
- **Observability:** [QUALIFICATION.md](QUALIFICATION.md) records toolchain versions, commands, artifact hashes, benchmark mode flags, and every unrun required cell.
- **Revisit:** Run the complete architecture matrix on Linux with a separately pinned private runtime, real PostgreSQL 17 HA/TLS, mixed Windows agents, multi-process faults, and live scale; remove this limitation only when those cells pass.

## L-035 — Resident listener composition has bounded but narrow concurrency

- **Impact:** Development configuration can request loopback plaintext, but the resident service currently refuses startup unless both application listeners have authenticated TLS contexts. TCP accept plus TLS handshake is serial in the node loop before a session enters the bounded worker queue. An authenticated agent session polls ready work initially, after each durable inbound message, and after each bounded non-consuming input-readiness timeout. This closes unbounded idle delivery delay, but empty backend reads scale with connected sessions and the configured interval; there is no database push/notification fanout. The configured memory reservation covers application-owned frame/queue estimates, not total process RSS; OS/OpenSSL/allocator/backend allocations remain outside it. With project exceptions disabled, an unrecoverable thread/allocation failure terminates the process.
- **Rationale:** One synchronous, deadline-bounded session owner preserves deterministic channel ordering and avoids concurrent TLS writes. The readiness wait checks OpenSSL-buffered input and socket availability without consuming frame bytes, so its short timeout cannot discard a fragmented message. The explicit work-poll interval bounds delivery latency and load without creating another thread or weakening existing session, byte, or outstanding-work ceilings.
- **Mitigation:** Use mTLS even for development, keep accept/handshake deadlines below the validated lease window, set `service.work_poll_interval_ms` between 10 ms and the session lifetime according to measured latency/store-load needs, bound the queue/workers/session lifetime, and apply an external process/container memory limit.
- **Observability:** Stable startup errors identify unavailable plaintext/TLS paths; scheduler counters expose queued/active/rejected sessions and listener failures. `ResidentApplicationService::work_poll_snapshot()` adds concurrency-safe saturating totals for successful empty/nonempty backend polls and delivered leases, plus sample count, cumulative microseconds, and maximum microseconds for observed idle-to-send delay. The values contain no payload, rule, subject, or outcome dimensions. They are inspectable process-local receipts that reset on restart; the standalone server does not yet export them, and no durable histogram or percentile series exists. Process supervision records termination and RSS.
- **Revisit:** Add an explicitly bounded plaintext development listener if still required, independent accept/handshake workers, database-backed work notification with bounded polling fallback, a bounded Prometheus/OTLP poll-metric exporter and histogram, and measured allocator/process limits without weakening lease or shutdown guarantees.

## L-036 — Authenticated agents remain the source of fact truth

- **Impact:** A server that intentionally does not possess the scanned file or process memory cannot independently recompute returned fact values, regex match contents, or context bytes. An enrolled but compromised endpoint can therefore lie within a structurally valid, authenticated response.
- **Rationale:** The trust boundary keeps predicates, bytecode, and verdicts on the server while agents observe endpoint-local data. Shipping the source to the server would change privacy, performance, and ownership assumptions.
- **Mitigation:** Enforce mTLS enrollment, exact peer/session/request/fence/generation identities, schema ID/hash attestation, route authorization, byte/count/deadline bounds, canonical framing, and durable audit. Treat provider output as an authenticated observation, never as a server-derived proof.
- **Observability:** Record provider route, schema identity, endpoint/subject incarnation, request and session identities, terminal status, and validation failure class without logging protected contents.
- **Revisit:** Add independently specified remote attestation, content commitments, or corroborating providers only when the threat model requires stronger evidence than authenticated endpoint observation.
