# Verification and Big-Bang Cutover

## 1. Purpose and goals

This chapter defines the evidence required for the completed source cutover
from the former YARA/Rust engine to the Python authoring frontend and C++ runtime. It turns
implementation completion into explicit, reproducible gates and defines the
only acceptable legacy deletion sequence.

The normative gate remains this chapter. Evidence gathered on the current
implementation host, including the required cells that could not be run, is in
[`../QUALIFICATION.md`](../QUALIFICATION.md); an unavailable required cell is
not a pass.

The goals are:

- prove the supported Python semantics against the pinned CPython reference;
- prove resource, trust, capability, transaction, replay, and data-label
  boundaries under failure;
- prove exact and optimized execution are observationally equivalent;
- prove Windows agents and Windows/Linux servers agree on schemas and semantics;
- prove active-active PostgreSQL operation, fencing, activation, migration, and
  outbox recovery;
- preserve traceable coverage while replacing legacy tests rather than merely
  deleting them;
- remove every live YARA, YARA-X, Rust bridge, Cargo, cbindgen, protocol-v1,
  and .yar surface in one final cutover;
- prove a clean build/install/package on machines without Rust/Cargo or a system
  Python; and
- leave one documented engine and one production protocol.

## 2. Non-goals

- A passing unit suite alone is not sufficient release evidence.
- Legacy YARA result compatibility is not an acceptance requirement.
- A YARA-to-Python translator, runtime compatibility mode, or feature flag is
  not part of qualification.
- Benchmarks do not permit semantic, security, replay, or resource regressions.
- Sanitizer and fuzz tests do not replace deterministic negative tests.
- SQLite success does not qualify production active-active behavior.
- Manual smoke testing cannot waive a failed automated gate.
- The cutover does not preserve the old CLI, protocol, parser API, fixtures, or
  Rust build graph.

## 3. Verification actors and evidence ownership

- **Lane owner:** writes focused component tests and records commands/results for
  the lane's task done criteria.
- **Integration owner:** owns cross-component tests, the qualification manifest,
  tracked documentation, deletion inventory, final scans, and merge gates.
- **CI/release runner:** executes clean matrix jobs from source with declared
  toolchain/runtime pins. It may not reuse an unverified developer cache.
- **Security test runner:** executes archive, protocol, worker, schema, label,
  authorization, resource, and fuzz suites with sensitive diagnostic checks.
- **Operations test runner:** exercises PostgreSQL multi-node failover,
  activation, outbox, backfill, migration, purge, and observability.
- **Human reviewer:** approves ADR/architecture deviations, interprets accepted
  benchmark changes, and signs the final qualification record. A human cannot
  override correctness failures without changing the design and rerunning gates.

Every result is tied to source commit, compiler/runtime/dependency lock digests,
platform ABI, configuration profile, database version, test binary hash, and
timestamp. Logs containing protected data are invalid evidence.

## 4. Qualification artifacts and interfaces

The integration branch produces:

- a machine-readable qualification manifest containing all gates and evidence;
- CTest/JUnit results and component coverage summaries;
- sanitizer and fuzz corpus/crash summaries;
- CPython differential-test vectors and runtime identity;
- exact-versus-optimized parity reports;
- deterministic pack reproducibility/signature reports;
- protocol schema/hash and mixed-platform reports;
- PostgreSQL failure-injection and activation-operation reports;
- benchmark and 10,000-peer stability reports;
- install/package manifests and software-bill-of-materials output;
- the legacy tracked-file inventory before deletion;
- the post-cutover forbidden-reference scan with a narrow historical-note
  allowlist; and
- final Git status, diff-check, ignored-file, and generated-artifact evidence.

Machine evidence is stored as build/release output, not committed generated
source. Stable human-facing conclusions and operating limitations are promoted
to tracked project documentation.

## 5. Verification strategy

### 5.1 Test layers

1. **Contract tests:** strong IDs, canonical encodings, schemas, diagnostics,
   source spans, bytecode, host steps, store transactions, protocol envelopes,
   effects, and activation transitions.
2. **Component tests:** worker, pack, compiler, VM, optimizer, scanner, effects,
   state/history/correlation, protocol/provider, storage/coordinator, and tools.
3. **Reference differential tests:** supported Python behavior compared with the
   exact bundled CPython 3.14.6 runtime and Unicode data.
4. **Property and metamorphic tests:** canonicalization, round trips,
   order-independence where promised, deterministic hash seeds, replay, and
   exact/optimized equivalence.
5. **Fuzz tests:** archive/index, AST framing/decoder, source compiler, bytecode
   verifier, canonical values, RE2 pattern compiler, protocol frames, schema
   negotiation, and event/service/action envelopes.
6. **Integration tests:** complete pack-to-result flow with fake and live
   providers, durable state/effects, services, correlations, and activation.
7. **Distributed failure tests:** real PostgreSQL and at least two server
   processes with process, network, and database fault injection.
8. **Packaging tests:** clean configure/build/install/package and private
   runtime discovery in isolated environments.
9. **Stability/performance tests:** budget enforcement, bounded memory/queues,
   benchmark comparison, and 10,000-peer simulation.
10. **Cutover tests:** forbidden dependency/API/reference scan, target inventory,
    no-Rust/no-system-Python build, replacement documentation, and clean tree.

### 5.2 No silent coverage deletion

Before changing a legacy test or fixture, map its behavioral intent in
TRACEABILITY.md:

- retain it unchanged only if it is frontend-independent;
- port it to an equivalent Python pack/model/fact/scan test when the behavior
  remains part of the new design;
- replace it with a stronger new test when semantics changed; or
- mark it RemovedByDesign with the ADR/limitation proving why no replacement is
  correct.

Deleting a YARA fixture because the parser was removed is not sufficient. For
example, tests of short-circuit fact avoidance, nested provider routes, process
identity, diagnostics, cancellation, scheduler pressure, optimizer parity, and
pattern offsets remain required even though their author syntax changes.

### 5.3 Determinism protocol

Determinism-sensitive tests run:

- in two distinct absolute source/build paths;
- with at least two process hash seeds;
- on Windows and Linux where the component is portable;
- with shuffled source/archive/discovery/input order;
- under clean locale/time-zone/environment settings; and
- after clearing generated caches.

The expected result is identical canonical pack bytes, binding hashes, semantic
IR hashes, schemas, diagnostics, state/effect journals, and replay outputs where
the contract promises platform independence. Platform executable hashes are
expected to differ and are checked against the declared ABI.

## 6. Detailed test matrix

### 6.1 Pack, trust, and worker

Test:

- byte-identical rpack output across paths, input enumeration order, newline
  styles, and operating systems;
- canonical index, digest, Ed25519 sign/verify, unknown/revoked signer,
  signature/content tampering, dependency digest mismatch, dependency cycles,
  diamond closure, signer-independent source identity, and dev unsigned policy;
- traversal, absolute/device/UNC paths, symlinks/reparse metadata, duplicate and
  Unicode/case-fold-colliding names, unsupported compression, ZIP bombs,
  oversized source/inputs, native wheels, scripts, .pth, and bytecode;
- exact private CPython selection with PATH, registry, PYTHONHOME, PYTHONPATH,
  user site, current directory, locale, and environment deliberately poisoned;
- AST worker success, syntax diagnostics, full node/field/span coverage, invalid
  framed messages, oversized output, timeout, memory/CPU/process limit, crash,
  deep-stack input, and server survival;
- generator declared inputs, locked pure-Python wheels, typed SDK object
  authenticity, stable binding IDs, duplicate IDs, bad arguments, type
  mismatch, undeclared access, output bounds, clean-process double-run, and
  nondeterministic rejection; and
- no static rule-module import or top-level execution by CPython.

### 6.2 Compiler and authoring language

Positive and negative golden tests cover every Python 3.14 AST node. For every
valid but unsupported construct, assert diagnostic code, message category,
source file, exact UTF-8 byte span, explanation, and stable machine format.

Cover:

- module/import/name binding, closure/nonlocal/global rejection rules, type-only
  constructs, cyclic imports, embedded source dependencies, and allowlisted
  modeled libraries;
- public annotations, inference, Any narrowing, overloads, Protocol, scalar
  generics, PEP 695 bounds/constraints, and rejected ParamSpec/TypeVarTuple;
- static models, eager/lazy fields, Identity fields, inheritance, C3 MRO,
  super, dataclasses, enums, properties, class/static methods, allowed dunders,
  and rejected metaclasses/descriptors/monkey-patching;
- stable schema/field IDs, additive optional compatibility, rejected removal/
  reuse/type change, canonical hashes, capability negotiation, and generated
  Markdown/stubs;
- label propagation and control dependencies;
- HIR types, CFG normal/exception/finally edges, loops, pattern matching,
  comprehensions, recursion, generators, async constructs, suspension, cleanup,
  transactions, and source maps;
- deterministic bytecode and optimizer certificates; and
- bytecode verifier rejection of invalid registers, types, targets, exception
  regions, suspension state, budget safepoints, capabilities, and effect/state
  operations.

### 6.3 VM and Python differential semantics

Compare the documented supported subset with the bundled CPython 3.14.6 for:

- bool and arbitrary-precision integer arithmetic/bit operations;
- binary64 operations, exceptional cases, comparisons, conversions, and
  formatting;
- full Unicode indexing/slicing/casing/classification/formatting, non-BMP
  characters, normalization behavior where modeled, and escaped surrogates;
- strings, bytes, tuples, lists, dict insertion order, sets/frozensets, ranges,
  slices, iterators, comprehensions, truthiness, hashing, and comparison;
- functions, defaults, arguments, closures, recursion, classes, methods, MRO,
  super, dataclasses, enums, and modeled dunders;
- exceptions, chaining, groups, try/except/finally, return/break/continue through
  finally, and context managers;
- generators, send/throw/close, yield from, async functions/generators,
  awaitables, async iteration, and async context managers; and
- every modeled standard-library function.

VM-specific tests cover stable-handle mark/sweep collection, cyclic local
objects, canonical boundary cycle rejection, allocation-before-use charging,
hash-seed recording, frame/heap/loop/instruction/CPU/elapsed limits, soft
sub-budgets, and fresh handler/cleanup caps.

### 6.4 Facts, subjects, providers, and scanning

Test:

- logical left-to-right/short-circuit reads and transparent suspend/resume at the
  exact READ_FACT instruction;
- terminal fact statuses, caught versus uncaught behavior, route rounds,
  validation, cancellation, deadlines, and malformed provider output;
- proof that optimizer prefetch cannot expose an unvisited read, fault, trace,
  retention entry, or logical budget charge;
- typed process and all built-in nested SubjectKey identities;
- custom model identities and rejection of missing/duplicate identities;
- authoritative begin/chunk/commit count/digest/generation validation;
- atomic rejection of partial/bad snapshots with last-good comparison retained;
- explicit removals after a later valid snapshot and root inventory
  reconciliation;
- server-scheduled jittered pulls, agent-pushed observations/removals,
  backpressure, reconnect, and cancellation;
- encoded literal, byte literal, masked byte, and RE2 patterns across file and
  readable-memory scan spaces;
- rejected unsupported regex constructs and statically unbounded/dynamic
  patterns;
- MatchSet bool/count/offset/length/space/permission/context bounds; and
- proof that an agent returns typed matches/facts but never a rule verdict.

### 6.5 Effects, services, state, faults, and replay

Test ordered reach-based intent creation in branches, loops, helpers, child
rules, suspension, exceptions, finalizers, and transactions. Verify MATCH and
NO_MATCH both commit after clean finalization; rollback/discard/fault/cancel do
not.

Cover:

- child invocation ownership and FaultedRule behavior;
- nested default rollback and explicit commit;
- call-site post policy snapshots and queued/dry-run/suppressed receipts;
- durable outbox idempotency, Retry-After/full-jitter categories, attempt/age
  bounds, acknowledgements, dead letters, redrive, and action-delivery events;
- cold service calls, direct await and group.start, active limit, helper-returned
  awaitables, WAIT_PENDING/CANCEL_PENDING, exceptional cancellation, escape
  rejection, one transient retry, cache TTL, and response capture;
- runtime value/control label joins, sink/persistence ceilings, declassification
  authority, and redacted diagnostics;
- flight recorder pre-arm, dynamic publication, no retroactive arming,
  event ordering, head/tail truncation, and protected-data behavior;
- state key ownership/scope, canonical values, MVCC conflict, original plus two
  captured-input retries, conflict exhaustion, and no external re-read drift;
- normal Python handlers, finalizer keep/replace/abort, nearest on_fault,
  retry_once/complete/abort/quarantine, double fault, triple fault, handler
  journals, fresh caps, and forced cleanup;
- local/global triple-fault breaker thresholds, half-open probe, different
  executable reset, and unrelated binding/peer continuity; and
- replay equality for captured facts, time, hash seed, services, history, and
  state inputs while proving no physical action or capture dispatch.

### 6.6 Events, history, correlation, retention, and capture

Cover typed observation, removal, match, fault, delivery, capture-result, and
custom events; stable schemas/field IDs; dual timestamps; causation IDs/depth;
and acyclic correlation chains.

Test:

- pure group key restrictions and canonical key types;
- per-group serialization, duplicate/late events, ingest-time windows,
  event-time bounded lateness, fault cursor advancement, and quarantine;
- history's mandatory event/tenant/time/limit bounds, predicate pushdown,
  residual VM filtering, collect/count/exists/async iteration, deterministic
  ordering, row/byte limits, and peer-local/FleetHistory authorization;
- static inferred retention, explicit retain, retain_reads logical-read
  behavior, classification ceilings, startup profile requirements, expiry, and
  purge cascades/tombstones;
- capture named profiles, typed parameters, anchors/reasons/dedupe, quotas,
  deferred execution, and future observation results;
- new correlation activation cursor behavior; and
- bounded isolated/live-state/effect-authorized backfill modes.

### 6.7 Protocol v2 and security

Test with real TLS where practical:

- TLS 1.3 only, mTLS chain/EKU/expiry/revocation/hostname/URI-SAN peer mapping,
  disabled early data, wrong admin/agent certificate class, session issuance,
  and explicit loopback-only plaintext rejection in production;
- protocol version/schema/capability negotiation and required/optional
  capability consistency;
- fragmentation/coalescing, maximum frame/field/collection/depth limits,
  unknown-field/version behavior, malformed/fuzzed input, and bounded
  diagnostics;
- session/agent epoch sequence, cumulative ACK, duplicates, gaps, reconnect,
  SQLite spool crash recovery, lost hints, queue pressure, and cancellation;
- work/provider lease fencing, stale sessions, timeout, retry, and late result
  rejection; and
- provider protocol faults without turning provider values into verdicts.

### 6.8 Storage, active-active, activation, and operations

Run one parameterized IRuntimeStore contract suite against SQLite and PostgreSQL.
It covers atomic event/cursor/state/result/effects/event/retention/outbox/audit
commit, rollback, CAS, canonical ordering, idempotency, leases/fences,
migrations, purging, and transaction fault injection.

The PostgreSQL-only suite uses at least two server processes and covers:

- SKIP LOCKED work claims with per-peer and per-correlation-group serial order;
- node/group/work lease takeover and stale-owner commit rejection;
- crash before work, during VM suspension, before commit, after commit but before
  ACK, and during outbox delivery;
- once-per-event visible result/effect intent under retry;
- outbox row leasing, duplicate transport response, retry, dead letter, and
  redrive;
- all-node stage, compile/hash/capability failures, target freeze, joining nodes,
  continuous ingest, drain, cancellation/requeue, late commit, atomic cursor
  flip, coordinator crash in each phase, rollback, and node readiness;
- unchanged and lazy migrated state, contention, failure, warming, reverse
  migration/reset, retained-state gap authorization, and expiry;
- admin mTLS/RBAC/idempotency, quarantine, trace/capture policy, backfill, purge,
  audit, and redaction;
- liveness/readiness/metrics/log/audit/optional OTLP behavior; and
- PostgreSQL primary failover behavior according to the deployment's supported
  HA contract.

### 6.9 Optimizer equivalence and performance

For every optimizer transform and combined plan, execute exact and optimized
paths with the same captured inputs and compare:

- MATCH/NO_MATCH/FAULTED/QUARANTINED/CANCELED result;
- exception/fault chain and breaker accounting;
- logical facts and statuses in order;
- child invocations;
- state reads/writes and MVCC behavior;
- ordered effects and dispositions;
- service/history scheduling and captured results;
- flight recorder events/truncation;
- active instruction/CPU and logical budget accounting promised by the
  certificate; and
- output metrics.

Full-recorded, effectful, stateful, service, history, or uncertain-fault paths
must remain exact unless identical observability is demonstrated. Shadow mode
uses isolated state and no-dispatch effects.

Benchmark reports retain comparable checkpoint scenarios where meaningful,
explain workload substitutions, and disclose regressions. The release has no
independent throughput threshold, but every evaluation must obey balanced.v1,
queues/memory must remain bounded, and the 10,000-peer simulation must complete
without unbounded growth, deadlock, result drift, or missed deadlines outside
the declared profile.

## 7. Build, platform, and packaging matrix

| Platform | Compiler/configuration | Required coverage |
|---|---|---|
| Windows x64 | clang-cl Debug | Full unit/component/integration suite, Windows providers |
| Windows x64 | clang-cl Release | Full suite, packaging, benchmarks, remote agent |
| Windows x64 | MSVC Debug | Compile and portable/Windows tests |
| Linux x86-64 glibc 2.35+ | Clang Debug/Release | Server/compiler/VM/store/tools, PostgreSQL |
| Linux x86-64 glibc 2.35+ | GCC Debug/Release | Server/compiler/VM/store/tools |
| Linux x86-64 | Clang ASan/UBSan | Unit/component/integration and fuzz smoke |

Additional combinations:

- Windows agent → Windows server;
- Windows agent → Linux server;
- Windows and Linux servers in one PostgreSQL-backed cluster with matching
  semantic/binding hashes;
- PostgreSQL 17+ production mode;
- SQLite explicit single-node development/test mode;
- clean environments with no cargo/rustc/cbindgen and no system python on PATH;
- private Windows and Linux CPython 3.14.6 hash verification; and
- Release installation from the packaged artifact into a clean directory.

Linux tests must prove no accidental link or compile dependency on Windows
provider sources/libraries. Windows tests must prove no registry/system Python
fallback.

## 8. Gate sequence

~~~mermaid
flowchart TD
    D0["D0: dossier and traceability complete"] --> B0["B0: current optimizer/protocol checkpoint verified"]
    B0 --> F0["F0: shared contracts compile"]
    F0 --> C0["C0: lane component gates"]
    C0 --> I0["I0: end-to-end Python engine integrated"]
    I0 --> P0["P0: cross-platform and private-runtime matrix"]
    P0 --> S0["S0: PostgreSQL active-active and operations"]
    S0 --> E0["E0: security, replay, optimizer parity, stability"]
    E0 --> X0["X0: legacy deletion cutover"]
    X0 --> Q1["Q1: clean final qualification"]
~~~

### D0 — Design gate

Pass when architecture, ADRs, limitations, contracts, tasks, and traceability are
complete and checksummed in the ignored dossier.

### B0/F0 — Baseline and contract gates

Pass when current dirty optimizer/protocol work is independently verified and
committed, then all shared contracts compile with fakes from one recorded SHA.

### C0 — Component gate

Pass when every lane's assigned unit/component/property/fuzz tests pass, its
documentation and limitations are current, and its status records evidence.

### I0 — Integrated runtime gate

Pass when a signed Python pack moves through verify/compile/optimize/evaluate,
remote facts/scans, state/effects/events/correlations, persistence, and admin
activation using only new APIs.

### P0 — Cross-platform gate

Pass the entire build/platform/package matrix, mixed-OS semantic hashes, Windows
agent paths, Linux server paths, private runtime isolation, and clean install.

### S0 — Distributed operations gate

Pass the two-node PostgreSQL failure/activation/migration/outbox/admin suite.

### E0 — Semantic and stability gate

Pass CPython differentials, trust/security negatives, label tests, replay,
exact/optimized parity, sanitizers/fuzzing, balanced.v1 enforcement, benchmark
reporting, and 10,000-peer simulation.

### X0 — Deletion gate

Only after I0 through E0 pass, perform the legacy removal inventory in one
integration wave. Do not release or label the intermediate additive tree.

### Q1 — Final gate

Re-run all gates from a clean source checkout after deletion. Pass only when the
new engine is the sole path, tracked docs describe it, forbidden scans are
clean, package dependencies contain no Rust/YARA artifacts, and Git hygiene is
clean.

## 9. Big-bang cutover inventory

The integration owner records the exact tracked inventory immediately before
X0. The current known removal/replacement surface includes:

### Build and dependency graph

- Remove Cargo discovery, Cargo profiles, rule_engine_yara_bridge_build,
  imported rule_engine_yara_bridge, generated bridge include paths,
  dependencies, Windows Rust bridge system libraries, and test dependencies
  from CMakeLists.txt.
- Remove the complete rust/yara_bridge tree: Cargo.toml, Cargo.lock, build.rs,
  cbindgen.toml, generated/header assumptions, and all Rust sources.
- Remove YARA/YARA-X/Rust/cbindgen requirements from developer and package
  documentation.
- Ensure the installed/runtime dependency manifest contains the private CPython
  worker/runtime and new C++ dependencies, but no Cargo/Rust/YARA component.

### Compiler/runtime public surface

- Delete or replace include/rule_engine/ast.hpp and the YARA-oriented
  include/rule_engine/compiler.hpp API.
- Remove parse_source, parse_sources, parse_file, ParsedRuleSet, ParseOptions,
  YARA expression/pattern/rule structures, includes/namespaces, bridge ABI, and
  undefined-propagation rules tied only to YARA.
- Replace the recursive legacy evaluator/value/compiler paths with the frozen
  pack compiler, schemas, HIR/CFG/bytecode, resumable VM, and Python values.
- Remove fixture-only module/pattern configuration APIs when their behavior has
  moved to static models, operator bindings, typed facts, and scan plans.
- Preserve general diagnostics, scheduler, provider, trace, and optimizer
  behavior only through explicitly mapped new contracts.

### Protocol and executable surface

- Replace src/proto/rule_engine/Protocol.proto with protocol v2; no v1 messages,
  handshake, opaque subject strings, or legacy framing remain.
- Replace rule_engine_client with the Windows rule_engine_agent.
- Remove server --rule, -r, YARA include directories, module-config,
  pattern-fixture, custom-fact-fixture, one-shot client, localhost-v1 session,
  and other legacy-only options.
- Make rule_engine_server config/resident operation the only server path.
- Make rule_engine_check --pack the only source validation path.
- Update rule_engine_benchmark to build/use Python packs and new VM metrics.

### Tests, fixtures, examples, and docs

- Remove tests/parser_bridge_tests.cpp after its worker/AST replacement coverage
  is traceably present.
- Port or replace YARA-heavy semantic_vm_tests.cpp, scheduler_tests.cpp,
  protocol_tests.cpp, optimizer_tests.cpp, benchmark tests, runtime harness, and
  server output tests by behavioral intent.
- Delete all .yar files under tests/fixtures and examples.
- Replace custom .module/.facts fixture examples with Python models, pack
  manifests, operator binding configuration, typed provider fixtures, and scan
  tests where those paths remain relevant.
- Delete docs/RUST_BRIDGE_UPDATE.md.
- Rewrite README.md, GOAL.md, TODO.md, optimization/transport/status docs, and
  examples for the sole Python engine.
- One historical release-note sentence may state that YARA support was removed;
  it is the only permitted textual legacy reference after cutover.

This list is a starting inventory, not an allowlist for leftover files. X0
regenerates the inventory from git ls-files and content scans immediately before
deletion.

## 10. Deletion procedure and invariants

1. Freeze merges except X0 integration work.
2. Tag the last qualified additive commit internally as the recovery point; do
   not release it as a supported dual frontend.
3. Generate a tracked-file and symbol/reference inventory.
4. For every legacy test, record Retained, ReplacedBy, or RemovedByDesign in
   TRACEABILITY.md.
5. Delete bridge/dependencies/fixtures and switch aggregate build/entrypoints to
   only new components in one reviewable cutover series.
6. Rewrite product-facing documentation and examples in the same wave.
7. Configure/build/test from an empty build directory with Cargo/Rust/system
   Python unavailable.
8. Install/package into an empty prefix and inspect binaries, imports,
   libraries, manifests, licenses, and archives.
9. Run forbidden tracked-file/content/symbol scans with only the historical
   release-note line allowlisted.
10. Re-run P0, S0, E0, and the entire CTest suite.
11. Run git diff --check, inspect git status, verify local ignored files, and
    confirm no generated build/runtime material is tracked.

Cutover invariants:

- There is no commit designated releasable in which both frontends are public.
- No YARA/Rust build tool is required or probed.
- No old parser API links, even if unused.
- No protocol-v1 client can negotiate a session.
- No .yar input is accepted by any CLI.
- No documentation instructs users to install Rust/Cargo or author YARA.
- Every retained behavior has new coverage.
- Local agent guidance and implementation-planning artifacts remain ignored and untracked.

## 11. Forbidden-reference and artifact checks

Run scans against tracked files, not only the working directory. Case-insensitive
forbidden terms/symbols include:

- yara, yara-x, yara_x, yara_bridge;
- cargo, rustc, cbindgen;
- .yar;
- re_yara_bridge_;
- parse_source, parse_sources, parse_file when referring to the legacy rule API;
- ParsedRuleSet and legacy YARA AST type names;
- --rule and -r in the server's source-authoring sense;
- protocol version 1, rule_engine_client, and legacy fixture options.

The scan script has a single explicit path/line allowlist for the historical
release note. It fails on any new allowlist entry. It also checks:

- git ls-files for rust/, Cargo.toml, Cargo.lock, cbindgen.toml, and *.yar;
- CMake target/link/dependency graphs;
- installed headers and CMake package exports;
- executable/import tables and dynamic libraries;
- packaged archives and software bill of materials;
- CLI help/strings and runtime error messages;
- generated protocol/schema artifacts; and
- licenses/notices for removed dependencies.

Generic uses of the words parse, source, rule, Rust as unrelated prose, or cargo
as ordinary freight are not detected by filename alone; the script records
context and uses exact legacy identifiers for enforcement.

## 12. Failure behavior during qualification

- A flaky test is a failure until its nondeterminism is explained and removed;
  automatic retry may gather evidence but cannot turn it green.
- Sanitizer findings, fuzz crashes, hangs, leaks beyond declared ownership, and
  data races block the gate.
- Cross-platform semantic/binding hash disagreement blocks release.
- A test log containing unredacted Sensitive/Secret values blocks release and is
  handled as a security incident.
- A benchmark regression is documented and reviewed; a budget breach,
  unbounded-growth result, correctness drift, or stability failure blocks.
- A failed cutover scan restores the missing removal task; it is not solved by a
  broad allowlist.
- A discovered behavior with no requirement/ADR mapping pauses deletion until
  it is either preserved or explicitly removed by design.
- A late architectural change updates its ADR, limitations, contracts, tasks,
  traceability, and test plan before implementation continues.

## 13. Alternatives considered

### Keep YARA tests as a permanent oracle

Rejected. Their behavior can inform coverage mapping before deletion, but the
final build cannot depend on YARA-X/Rust or claim YARA semantics as normative.

### Delete legacy code early to force migration

Rejected. The new engine must first prove end-to-end behavior and allow mapping
valuable provider/scheduler/optimizer coverage. Early deletion destroys the
recovery baseline and obscures regressions.

### Maintain a long-lived dual-frontend branch

Rejected. It invites accidental release, doubles security and build surfaces,
and weakens the clean-break guarantee. Temporary additive integration is local
to the rewrite branch and has no releasable status.

### Declare success after Windows tests

Rejected because Linux server portability, mixed-OS semantic hashes, private
runtime packaging, and PostgreSQL active-active are part of the initial product.

### Use mocks for all database and TLS behavior

Rejected. Fencing, isolation, SKIP LOCKED, mTLS identity, and crash behavior
require real PostgreSQL, processes, sockets, and certificates in qualification.
Mocks remain useful for deterministic component tests.

### Require byte-for-byte optimized traces for operations declared unobservable

Rejected as a blanket rule. The compiler certificate explicitly defines
observability. Full-flight-recorded or effectful paths require exact visible
parity; pure optimized paths compare the promised trace/metric contract rather
than internal implementation steps.

### Set an arbitrary throughput release number

Rejected for the first semantic rewrite. Budget adherence, bounded resource
growth, comparative reports, and 10,000-peer stability are required; realistic
service-level targets follow production workload measurement.

## 14. Decision reasoning

The rewrite changes author syntax, compiler, runtime, protocol, persistence, and
operations simultaneously. Qualification therefore follows architectural
invariants rather than file ownership: each trust boundary and transaction is
tested at component, integrated, and failure-injected levels.

CPython differential tests are necessary because the language claims familiar
Python semantics, while explicit negative tests are necessary because complete
Python grammar does not mean complete Python runtime support. Both are
first-class contracts.

Behavioral coverage mapping preserves the hard-won provider, optimizer,
scheduler, diagnostics, cancellation, and transport tests without preserving
YARA as an implementation dependency. The big-bang deletion happens late so
those behaviors can be compared, but the additive intermediate is never a
supported dual frontend.

Real multi-process PostgreSQL and TLS tests are mandatory because fencing,
transaction boundaries, certificate identity, and crash recovery cannot be
proved by unit fakes. Clean packaging without Rust or system Python proves the
actual removal and private-runtime assumptions rather than only scanning source.

## 15. Consequences and tradeoffs

Positive:

- release evidence maps directly to architecture and known limitations;
- valuable legacy behavioral coverage survives in new tests;
- clean environments prove dependency removal;
- cross-platform and distributed failures are found before release;
- exact/optimized parity protects semantics while the optimizer evolves;
- the final source and package contain one understandable engine.

Negative:

- the qualification matrix is expensive and requires Windows, Linux, real
  PostgreSQL, certificates, process fault injection, and long-running stability
  jobs;
- the final deletion waits until most of the rewrite is implemented;
- some old tests require substantial redesign rather than mechanical syntax
  conversion;
- no arbitrary throughput target means the first release needs careful
  benchmark interpretation;
- big-bang release requires coordinated agent/server/pack deployment because
  protocol v1 is gone.

## 16. Known limitations

- L-002/L-003: differential coverage applies only to the documented Python
  subset and modeled standard libraries.
- L-004: valid Python beyond worker limits remains intentionally rejected.
- L-005: generator double-run catches but cannot prove all nondeterminism.
- L-006: no Linux provider agent is qualified initially.
- L-007: PostgreSQL multi-node tests do not create database multi-primary or
  global ordering.
- L-008/L-009: action delivery remains at-least-once and replay/rollback cannot
  reverse external effects.
- L-010: conservative exact execution can reduce optimizer benefit.
- L-011: RE2 is intentionally not Python re.
- L-012/L-013: migration, activation, and event-time/backfill bounds remain.
- L-015: SQLite evidence is development-only.
- L-016: no translator means existing YARA packs require manual rewrite.
- L-018: the first release has comparative performance evidence rather than a
  newly invented throughput SLA.
- The 10,000-peer test is a controlled simulation, not proof of every production
  network/fact distribution.
- Sanitizers and fuzzing reduce risk but do not prove absence of memory-safety or
  parser/protocol defects.
- Windows process-provider tests cannot eliminate races or privilege restrictions
  inherent in live external processes.

## 17. Observability and qualification diagnostics

Every test failure reports a stable component/diagnostic code, source/evidence
location, seed, runtime/profile identity, and reproduction command. Distributed
tests also record operation, node, lease/fence, pack/generation, event/work, and
database transaction IDs.

Qualification dashboards summarize:

- pass/fail/skip by gate and required matrix cell;
- compiler construct and diagnostic coverage;
- differential vector count and mismatches;
- exact/optimized parity cases;
- sanitizer/fuzz runtime, corpus, coverage signal, and crashes;
- activation fault-injection phases;
- state migration/backfill/outbox recovery results;
- package dependency and forbidden-scan status;
- benchmark deltas and resource peaks; and
- 10,000-peer queue, memory, deadline, and result-drift metrics.

Skipped required cells fail the gate unless the architecture removes the
platform/feature and updates all dependent records. Secrets and protected event
content are excluded from evidence.

## 18. Related decisions, contracts, and tasks

- ADR-001: C++ owns semantics.
- ADR-003/ADR-004: static Python language and custom resumable VM.
- ADR-005/ADR-017: source-only packs and bounded private Python worker.
- ADR-011: protocol v2 clean break.
- ADR-012/ADR-013: PostgreSQL active-active and atomic activation.
- ADR-014/ADR-015/ADR-016: optimizer observability, data labels, and RE2.
- ADR-018: big-bang YARA removal.
- All F0 contracts, with special focus on semantic hashes, VM host steps,
  transactions, fences, schema hashes, and EvaluationResult.
- Tasks: all component tasks, I1, I2, X1, and Q1.
- Operational detail: architecture/09-activation-operations-and-tooling.md.
