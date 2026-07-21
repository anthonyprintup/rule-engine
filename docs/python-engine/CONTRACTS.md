# Foundation Contracts

These contracts are frozen by the F0 commit. Lanes may depend on them but must not fork them. Fallible C++ APIs return `std::expected`; project code uses no exceptions or RTTI.

## Identity and source

- `PackId`, `PackVersion`, `SourceDigest`, `ExecutableId`, `BindingId`, `SchemaId`, `PeerId`, `SessionId`, `ExecutionId`, `InvocationId`, `EventId`, and `IntentId` are strong project types.
- Every diagnostic and executable instruction maps to a stable UTF-8 byte source span.
- `SubjectKey` is a recursive typed identity: peer plus a descriptor type and canonical identity tuple, optionally rooted in a parent. A digest is only an index, never semantic identity.
- Built-in canonical identity tuples are fixed: process `(peer_id, pid, creation_time)`; memory `(parent, allocation_base, base)`; PE section `(parent, virtual_address, raw_data_offset)`; import `(parent, normalized_dll, iat_rva)`; export `(parent, ordinal)`; debug entry `(parent, type, address_of_raw_data, pointer_to_raw_data)`; resource `(parent, tagged type/name/language path, rva)`; certificate `(parent, file_offset)`; TLS callback `(parent, rva)`. Custom nested subjects use all declared `Identity[T]` fields in descriptor order.

## Python worker and language runtime

- The worker uses only the bundled CPython `3.14.6` runtime and its matching Unicode data. Runtime patch, Unicode, worker-protocol, compiler, or semantic-ABI changes invalidate compiled and generator caches; the launcher never falls back to system Python, registry installations, `PYTHONPATH`, user site, or ambient packages.
- Each parse or generate request receives a fresh short-lived worker process. Windows Job Objects and Linux process/resource limits contain crashes and ordinary resource abuse for availability; they are explicitly not AppContainer/LPAC or a hostile-code sandbox. A valid production signer authorizes trusted generator execution under the worker account.
- Rule/model modules are parsed but never executed by CPython. Generator mode may execute only after verification and emits typed binding data, never executable VM IR.
- The statically accepted runtime includes generators, `yield`/`yield from`, async functions/generators, awaitables, async iteration/context managers, and lexical structured task groups. There is no ambient event loop, task spawning, or detached work.

## Schema and values

- `SchemaCatalog` owns model, fact, scope, service, action, event, state, capability, label, and numeric wire-field descriptors plus their canonical hashes.
- `FactValue` is an immutable, schema-validated provider value supporting null, bool, arbitrary integer, binary64 float, Unicode string, bytes, enums, lists, maps, and records.
- `PyValue` is VM-local and supports mutable/cyclic containers, functions, generators, classes, instances, slices, ranges, and exceptions.
- `FrozenValue` is immutable, labeled, canonical, and acyclic. Crossing a persistence/effect/service/event boundary deep-validates and freezes a `PyValue`; cycles fail with a typed boundary error.
- Data classification is `Public < Internal < Sensitive < Secret`; values also carry category tags. The VM joins value labels with the current control label.

## Pack and compiler

- `VerifiedRulePack` contains a verified canonical source index, manifest, source/dependency closure, declared generator inputs, trust result, and source digest.
- `PackCompiler::compile(VerifiedRulePack, SchemaCatalog, OperatorBindings) -> expected<CompiledPack, DiagnosticSet>` is the sole source-to-runtime entrypoint.
- `CompiledPack` contains source/type/constant tables, model descriptors, bindings, capability/fact requirements, verified bytecode, effect summaries, optimizer certificates, migrations, and semantic hashes.
- `OptimizationCertificate` is compiler-issued and includes transitive purity, logical reads, effects, state, service/history use, fault behavior, and recorder observability.

## VM and host

- `VmSession` owns frames, registers, heap, hash seed, logical-read ledger, task groups, state/effect/event journals, flight recorder, and captured replay inputs.
- `VmSession::step(HostResponses) -> VmStep` returns one of: yielded, waiting for facts, waiting for capabilities, complete, faulted, quarantined, or canceled.
- `VmSession::resource_usage() -> VmResourceUsage` is mandatory. The resident validates it before commit and uses checked cumulative normal-executor totals to derive every transparent retry's remaining profile; live heap, frames, and concurrent services remain per-attempt peaks.
- A suspended session resumes at its instruction; it never restarts the entrypoint.
- `EvaluationResult` distinguishes MATCH, NO_MATCH, FAULTED, QUARANTINED, and CANCELED.

## Facts and providers

- `IProviderDispatcher` receives only request ID, typed subject, route, exact expected schema ID and canonical hash, fact/scan request, deadline, and cancellation. It never receives a predicate or authority to decide a rule.
- `FactResponse` is a closed terminal union. A `value` response contains one valid value, the authoritative returned schema ID/hash, and no diagnostic. Every non-value terminal contains neither a value nor a returned schema identity and may contain one bounded diagnostic. Unknown statuses and every mixed/partial shape are malformed.
- The request schema identity comes from the active pack catalog. A provider derives the returned identity from its own route catalog rather than echoing the request. Codec, provider router, protocol runtime adapter, resident runtime, and VM reject any value whose returned ID/hash differs from the request before it can become a VM value; the VM then validates the value structure against the active descriptor.
- Provider batches contain typed values or typed terminal statuses. Schema, subject, request, size, and capability validation happens before a response reaches the VM.
- Authoritative enumeration uses begin/chunk/commit with generation, count, and digest; visibility changes only on a valid complete commit.

## Effects and services

- `EffectIntent` contains owner IDs, monotonic sequence, kind, frozen labeled payload, source span, call-site policy snapshot, disposition, and deterministic idempotency key.
- `EffectJournal` is append-only during execution. The root commits only after clean finalization; explicit child transactions default to rollback until committed.
- `IExternalTransport` is a pluggable typed service/action envelope transport. Service reads are captured for replay; action dispatch occurs only from a committed durable outbox.

## Events, state, and storage

- `EventIntent` is the VM-owned, ordered, frozen proposal produced by verified `emit_event`; its deterministic identity is derived from root event, invocation, and sequence. It is not durable or dispatchable by itself.
- `project_committed_events` revalidates the successful attempt's intents against the active event schema catalog and authenticated root, then materializes durable envelopes without I/O. Store adapters require exact intent/envelope correspondence.
- Event envelopes contain stable event/schema IDs, tenant, peer/subject, producer and ingest timestamps, labels, causation, and typed payload.
- `IRuntimeStore::transact_event` atomically commits input event/cursor, state CAS, result, emitted events, retention, journal, outbox, and audit records.
- Correlation state is keyed by executable, correlation binding, and canonical group key.
- Store work and agent sessions use monotonically increasing fence tokens; stale owners cannot commit.

## Protocol and activation

- Protocol v2 is framed Protocyte over TLS 1.3 mTLS. A certificate maps to a trusted `PeerId`; the server issues `SessionId` and negotiated schema/capability sets.
- Pack activation stages and compiles on all healthy leased nodes, compares binding and platform-independent semantic hashes, drains/fences the prior generation, and flips one database activation cursor.

## Resource profile

`balanced.v1` is immutable and fixes these normal-evaluation limits:

| Resource | Limit |
|---|---:|
| Elapsed time including waits and cleanup | 10 s |
| Active VM CPU | 100 ms |
| Semantic bytecode instructions | 1,000,000 |
| Frames | 128 |
| Live VM heap | 16 MiB |
| Loop iterations plus yields | 250,000 |
| Logical facts / provider rounds / fact bytes | 512 / 16 / 16 MiB |
| Service calls scheduled / active / response bytes / per-call deadline | 128 / 16 / 16 MiB / 5 s |
| History queries / rows / bytes | 16 / 10,000 / 16 MiB |
| State keys / combined read-write bytes | 256 / 1 MiB |
| Effect intents / frozen payload bytes | 256 / 2 MiB |
| Event intents / frozen payload bytes / depth | 256 / 2 MiB / 64 |
| Flight recorder | 25,000 events / 4 MiB, head-and-tail |

Compile and ingest limits are 16 MiB source closure, 1,000,000 AST nodes, 100,000 concrete generated bindings, 64 MiB generator arguments/inputs, a 512 MiB/15 s Python worker, and 100,000 items/16 MiB per authoritative nested snapshot. Finalizer/`on_fault` receives 100,000 instructions, 50 ms active, 2 s elapsed, 2 MiB heap, 8 handler-safe service calls, and 64 intents; `on_double_fault` receives 25,000 instructions, 1 s elapsed, 512 KiB heap, and diagnostic/quarantine capabilities only; forced cleanup receives 25,000 instructions and 500 ms elapsed. Hard exhaustion is an unsuppressible VM control fault. Any change creates a new named profile version rather than redefining `balanced.v1`.

## Fault and breaker contract

- Normal Python handling runs first, followed by the optional finalizer/nearest `on_fault`, then one `on_double_fault`; failure of that last tier is a triple fault and executes no more pack code.
- Three triple faults for the same binding and peer within 10 minutes open that peer breaker for 30 minutes, followed by one fenced half-open probe.
- Five triple faults for the same binding across at least three distinct peers within 15 minutes open the global binding breaker until audited operator clearance or activation of a different signed-source-derived `ExecutableId`. Policy-only changes do not reset it, and unrelated bindings/peers continue.
