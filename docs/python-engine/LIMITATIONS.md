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

## L-026 — Container and iteration frontend is intentionally partial

- **Impact:** The current compiler lowers fresh list/tuple/dictionary displays, subscription reads, one-target list/dictionary item assignment, and synchronous local-target `for`/`else`/`break`/`continue`. Starred and `**` expansion, sets, slices, comprehensions/generator expressions, item deletion, destructuring targets, `range`, `async for`, arbitrary iterator protocols, and source-level state operations still fail compilation.
- **Rationale:** The available fixed-display and iterator opcodes can express the delivered slice with exact ordering and hard charges. The deferred constructs need additional builder, scope, unwind, async, capability, identity, or replay contracts; approximating them would change Python behavior or weaken the trust boundary.
- **Mitigation:** Stable source-spanned diagnostics reject every deferred form. The exact CPython worker-to-C++-VM tests cover delivered ordering, control flow, verifier dataflow, and budget failures. Persistent deletion remains `state.delete(StateKey, identity=...)` and cannot reach `delete_state` until typed key and injected-capability lowering exists.
- **Observability:** Count `PY-NYI-COLLECTION-UNPACKING`, `PY-NYI-SLICE-LOWERING`, `PY-NYI-COMPREHENSION-LOWERING`, `PY-NYI-ITERATION-TARGET`, `PY-NYI-DELETE-LOWERING`, and `PY-NYI-STATE-LOWERING` diagnostics by pack and source span.
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

- **Impact:** Authors can declare `@schema`-pinned `EventRecord` classes, assign explicit positive `wire_field` IDs, construct them with complete keyword arguments, and call `telemetry.emit(record)` as a standalone statement. Constructor defaults, positional construction, and use of the returned `EventReceipt` inside rule bytecode are rejected. Projected envelopes retain root causation only and reuse the root ingest timestamp because the durable contract has no immediate-parent/depth or commit-clock fields. Evaluation records written before the event-journal codec marker require an explicit migration or development-store rebuild.
- **Rationale:** Keyword-only complete construction makes evaluation order independent of field-ID order and prevents omitted/default values from crossing the persistence boundary without a canonical default contract. A receipt cannot be exposed until its exact immutable record representation and field access semantics exist. Assigning parent/depth/timestamps without durable fields or a transactional database clock would create misleading metadata.
- **Mitigation:** The compiler derives `SchemaKind::event` only from the recognized `EventRecord` base plus one literal stable `@schema` decorator, validates unique field IDs and value types, and emits a verifier-pinned `build_record` followed by `emit_event`. The VM reconstructs fields from the active descriptor, validates and freezes the record, and every durable store cross-checks deterministic intent identity, order, inherited context, causation, timestamps, label, and exact payload before commit. Unsupported constructor or receipt usage fails compilation. Operators must migrate or recreate pre-marker development result rows before upgrading.
- **Observability:** Count `PY-EVENT-SCHEMA`, `PY-EVENT-FIELD`, `PY-EVENT-CONSTRUCTOR`, `PY-EVENT-EMIT`, and `PY-EVENT-RECEIPT` diagnostics; `PYC0116` verifier failures; `EventProjectionErrorCode` failures; store intent/envelope mismatch rejections; event budget faults; and unsupported evaluation-codec versions.
- **Revisit:** Add canonical defaults and a typed receipt record only with explicit bytecode and schema semantics. Extend envelopes with immediate-parent/depth and commit timestamps only through a versioned store migration and transactionally assigned metadata/clock semantics.

## L-031 — Resident evaluation supports agent fact and scan turns only

- **Impact:** An activated signed pack can now evaluate subjects from committed authoritative snapshots and complete fact or scan suspensions through the agent protocol. Capability, service, state, and history host turns are not yet connected to the resident evaluator. One suspended VM turn must remain on a single agent route, and activation changes require a server restart. If a process stops after a work result is durable but before its VM transaction commits, the old result is ignored and the work is retried after its lease expires instead of resuming from a durable VM checkpoint.
- **Rationale:** C++ must retain exact rule semantics, budgets, ordering, and commit authority. Adding another host port or route handoff requires an explicit typed request/response contract and durable continuation rules; silently approximating one would make replay or failover produce a different decision.
- **Mitigation:** Startup loads the content-addressed archive named by durable activation state, verifies its signature and signer policy, compiles it with the pinned worker, and compares source, compiler ABI, semantic, binding, and executable identities before readiness. Durable snapshot replay reconstructs deterministic work IDs, coordinator leases fence each attempt, returned observations resume the verified C++ VM, and the terminal transaction commits atomically. Unsupported host turns fail closed. Retrying an uncommitted result is safe because no effect, event, state, history, or outcome was committed.
- **Observability:** Readiness identifies archive, trust, compilation, or activation-evidence failures. Runtime-store inspection exposes committed agent messages, work leases, fences, receipts, and final evaluation transactions; durable audit records ingress and evaluation commits. Stable protocol errors identify unsupported host turns, route mismatch, stale work, schema mismatch, and capability mismatch.
- **Revisit:** Compose typed capability/service, state, and history ports; partition or join multi-route work without exposing semantics to agents; persist enough continuation/result state to avoid waiting for lease expiry after a server crash; and add a fenced live-activation watcher. The configured memory bound covers owned application reservations; OS socket buffers, TLS-library allocations, allocator overhead, and backend-internal memory require separate process/container limits and measurement.

## L-032 — The built-in signing adapter is Windows raw-seed only

- **Impact:** The shipped signer reads one raw 32-byte Ed25519 seed from a protected local Windows file. It does not implement PEM/PKCS#8, HSM, KMS, PKCS#11, remote signing, key generation, backup, rotation, or ceremony. The seed lifetime remains caller/process managed; it is cleansed after use but is not held in guaranteed page-locked memory. The selected OpenSSL DLL is absolute and version-checked but is not independently hash-pinned by the signer. Strict DACL rules can reject legitimate enterprise ACL variants.
- **Rationale:** A small fail-closed offline adapter establishes interoperable signing without embedding a key-management product or silently accepting ambiguous key encodings and permissions.
- **Mitigation:** Keep signing offline, protect and monitor the seed outside the repository, validate the derived public-key ID against policy, use an explicit crypto-library path, and supply a separately reviewed `ISigningKeyProvider` for production HSM/KMS ownership.
- **Observability:** Signing diagnostics expose only the failure class and public key ID; they never log the seed, its contents, or a secret-bearing path.
- **Revisit:** Add a provider only with explicit key identity, authorization, audit, cancellation, zeroization, rotation, and deterministic-signature contracts plus integration tests for the real device/service.

## L-033 — Filesystem and administration adapters are intentionally narrow

- **Impact:** Atomic no-clobber archive publication depends on a same-directory hard link and fails on filesystems without hard-link support. `--watch` owns cancellation/publication generations but has no platform filesystem-event source, and cancellation is observed between compiler phases rather than forcibly terminating an in-flight parser worker. The standalone admin CLI now connects with mTLS and supports reads plus activation preview/drain/fence/flip, but upload, distributed stage compilation, rollback restaging, policy mutation, and bounded operation polling are not connected.
- **Rationale:** Portable polling, cross-volume replacement, forced worker interruption, and every privileged lifecycle need separately bounded, server-owned durability semantics; pretending they are atomic or accepting client-supplied semantic evidence would be unsafe.
- **Mitigation:** Use a local hard-link-capable staging filesystem, invoke checks explicitly from an external watcher, rely on the worker's hard process deadline, and use the authenticated v2 activation sequence only for generations already staged by the durable backend. Unconnected admin commands fail closed with `ADMIN-NOT-IMPLEMENTED`.
- **Observability:** Tool results distinguish unsupported publication, cancellation generation, worker timeout, and unavailable transport without partially publishing output.
- **Revisit:** Add platform event adapters, phase-aware worker cancellation, alternative atomic publication protocols, server-owned upload/stage/rollback orchestration, policy versioning, and bounded reconnect polling with failure-injection tests.

## L-034 — Portable and PostgreSQL release qualification is incomplete

- **Impact:** The implementation host qualified Windows only. Linux compilation/packaging/private-runtime behavior, live PostgreSQL 17 linking and migrations, mixed-OS semantic hashes, multi-node failover, and real network/database scale are not proven. The guarded PostgreSQL adapter currently owns one mutexed connection rather than a production pool.
- **Rationale:** WSL was absent, the available Docker daemon supported Windows containers only, and PostgreSQL client/development tools were unavailable. Required architecture cells cannot be inferred from Windows builds or fakes.
- **Mitigation:** Keep production-cluster readiness fail-closed, publish the exact qualified/unqualified matrix, and treat SQLite plus the 10,000-peer in-memory model as development/component evidence only.
- **Observability:** [QUALIFICATION.md](QUALIFICATION.md) records toolchain versions, commands, artifact hashes, benchmark mode flags, and every unrun required cell.
- **Revisit:** Run the complete architecture matrix on Linux with a separately pinned private runtime, real PostgreSQL 17 HA/TLS, mixed Windows agents, multi-process faults, and live scale; remove this limitation only when those cells pass.

## L-035 — Resident listener composition has bounded but narrow concurrency

- **Impact:** Development configuration can request loopback plaintext, but the resident service currently refuses startup unless both application listeners have authenticated TLS contexts. TCP accept plus TLS handshake is serial in the node loop before a session enters the bounded worker queue. An injected agent backend is asked for one initial work batch per session rather than being continuously polled. The configured memory reservation covers application-owned frame/queue estimates, not total process RSS; OS/OpenSSL/allocator/backend allocations remain outside it. With project exceptions disabled, an unrecoverable thread/allocation failure terminates the process.
- **Rationale:** The delivered composition uses simple synchronous, deadline-bounded ownership and fails closed where plaintext, continuous scheduling, or whole-process memory guarantees are not implemented.
- **Mitigation:** Use mTLS even for development, keep accept/handshake deadlines below the validated lease window, bound the queue/workers/session lifetime, apply an external process/container memory limit, and reconnect to obtain later work batches.
- **Observability:** Stable startup errors identify unavailable plaintext/TLS paths; scheduler counters expose queued/active/rejected sessions and listener failures; process supervision records termination and RSS.
- **Revisit:** Add an explicitly bounded plaintext development listener if still required, independent accept/handshake workers, continuous durable work notification, and measured allocator/process limits without weakening lease or shutdown guarantees.

## L-036 — Authenticated agents remain the source of fact truth

- **Impact:** A server that intentionally does not possess the scanned file or process memory cannot independently recompute returned fact values, regex match contents, or context bytes. An enrolled but compromised endpoint can therefore lie within a structurally valid, authenticated response.
- **Rationale:** The trust boundary keeps predicates, bytecode, and verdicts on the server while agents observe endpoint-local data. Shipping the source to the server would change privacy, performance, and ownership assumptions.
- **Mitigation:** Enforce mTLS enrollment, exact peer/session/request/fence/generation identities, schema ID/hash attestation, route authorization, byte/count/deadline bounds, canonical framing, and durable audit. Treat provider output as an authenticated observation, never as a server-derived proof.
- **Observability:** Record provider route, schema identity, endpoint/subject incarnation, request and session identities, terminal status, and validation failure class without logging protected contents.
- **Revisit:** Add independently specified remote attestation, content commitments, or corroborating providers only when the threat model requires stronger evidence than authenticated endpoint observation.
