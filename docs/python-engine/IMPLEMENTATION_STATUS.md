# Python Engine Implementation Status

This document separates implemented, verified behavior from the target architecture in this directory. The architecture remains normative design intent; a capability is available only when it appears below with code and test evidence.

## Implemented and locally verified

- Shared C++23 contracts for budgets, typed recursive subjects, facts, scans, bytecode, VM suspension, effects, events, state, protocol, storage, activation, and policy.
- Canonical source-only pack loading, bounded archive validation, SHA-256 identities, OpenSSL 3 Ed25519 verification, and production rejection of unsigned or policy-invalid packs.
- Exact CPython 3.14.6 worker staging/validation, isolated parse/generate framing, and Windows Job Object limits for wall time, CPU, memory, output, handles, and descendant processes. Static rule modules are parsed as data and are not imported or executed.
- A static Python compiler and verified register VM covering the implemented language subset, including real worker-AST to compiler to VM interoperability, deterministic fact/capability operands, fresh list/tuple/dictionary values, bounded synchronous iteration, closed typed exception handlers, `else`/`finally` cleanup, state transactions, generator controls, bounded recovery, and exact operator behavior.
- Transactional effect and typed event-intent journals, label propagation, recorder/replay support, typed services, durable outbox/event projection, typed events/history/state, MVCC retry, migrations, and fenced correlation primitives.
- Protocol-v2 bounded codecs, TLS 1.3 mutual authentication, durable SQLite WAL agent spooling, lossless typed scan messages, and snapshot/session validation.
- Real RE2-backed literal, masked-byte, UTF-8/UTF-16, and regex scans over explicit spaces with bounded context, multi-pattern attribution, exact/existential modes, and deterministic zero-length handling.
- Durable Windows SQLite runtime storage with atomic receipts, cursors, state, history, journals, outbox, leases, and fencing. A guarded PostgreSQL implementation is present and warning-clean at compile time.
- Backend-neutral resident orchestration with captured-input replay, original-plus-two MVCC attempts, mandatory fail-closed VM usage snapshots, cumulative remaining-budget profiles, stale-fence rejection, cancellation, and atomic event/state/effect/outbox proposals.
- Concrete runtime adapters bind protocol-v2 fact/scan responses to exact work leases, require exact requested/returned schema ID/hash equality for fact values, reject malformed terminal unions and stale or conflicting sequence/generation/fence data, advance durable sequence state only after persistence, commit through the fenced coordinator, and keep replay dispatch-free.
- Versioned PEP 561 authoring stubs and a fail-closed author runtime plus a deterministic trusted-generator SDK, validated under the exact private CPython runtime and qualified with strict Pyright 1.1.411 and Ruff 0.15.22 checks.
- Text, JSON, and SARIF command models for pack/check/admin workflows, source diagnostics, watch-generation cancellation, redaction, and conservative mutation previews.
- Typed Windows process, image, PE, signer, memory, and scan providers use recursive subject identities and return only facts or scan observations. An authoritative route catalog binds each fact to a value schema ID/hash; the provider rejects request/catalog drift and attests that identity only on a structurally matching value. The provider suite includes process-incarnation and generation validation, deadline/error mapping, PE parsing bounds, signer policy, and scan-space tests.
- The production Windows `rule_engine_agent` has deterministic `--help`/`--version`, exact `--config PATH` plus optional trailing `--validate-config`, and a strict bounded configuration for absolute spool/credential paths, numeric failover endpoints, TLS DNS name, exact URI SAN and SHA-256 fingerprint, peer identity, active generation, and mandatory hard resolver bounds.
- The agent composes TLS 1.3 mutual authentication with persistent SQLite epoch/sequence spooling, hello/lease/cancel/ACK/NACK/credit handling, bounded reconnect/replay, pending-result deduplication, and atomic authoritative snapshot batches. Results and complete snapshot batches are durable before their first send.
- Agent work is dispatched only through `WindowsAgentProviderRuntime` fact, scan, and process-inventory entry points. Its transport/provider seams contain no predicate, rule, bytecode, or verdict field; stale sessions/fences/generations, unknown messages/config keys, oversized future deadlines, missing backends, and invalid provider projections fail closed.
- Focused fake-session and provider tests cover strict config/CLI rejection, whole-snapshot durability, reconnect replay without duplicate dispatch, duplicate leases, cancellation, transient NACK retry, cumulative ACK, stale fences, the facts-only boundary, and `BUILD_TESTING=OFF`. `rule_engine_python_agent` installs/exports through the central package graph with the installed executable name `rule_engine_agent`.

## Security boundary

The worker controls protect service availability and prevent accidental ambient Python use; they are not a hostile-code sandbox. Static rule source is never executed by CPython. A generator executes only after pack signature and signer policy authorize it, and the generated proposal is validated and double-run for operational determinism. A malicious authorized generator remains inside the trusted signer boundary described by L-001.

Agents do not receive predicates, rule bytecode, or match decisions. They receive typed fact and scan requests and return authenticated observations. C++ remains responsible for validation, scheduling, optimization, replay, effects, persistence, and the final outcome.

## Known implementation and qualification gaps

- The compiler/VM do not yet implement every construct described by the target subset. Current gaps include complete iterator/container lowering, comprehensions and generator expressions, nested generator/coroutine object creation, `yield from`, general async task bytecode, keyword/default/variadic binding, full pattern matching rollback, arbitrary/user exception classes, handler binding, exception causes/groups, bare re-raise from finalizers, complete model/class semantics, and state deletion. The implemented closed exception subset and its rationale are recorded in [L-028](LIMITATIONS.md#l-028--the-exception-frontend-is-intentionally-closed).
- The VM currently materializes the entry subject through fact requests rather than a complete author-visible subject object. Some handler metadata and decisions remain convention-based because the frozen bytecode contract lacks structured fields for them.
- Typed custom-event payloads now cross the VM, server projection, durable result codec, retry/replay, and atomic store boundary. Event usage is evaluation-owned and carried across transparent retries with the other cumulative normal budgets. Source lowering, complete envelope metadata, and pre-marker result migration remain [L-030](LIMITATIONS.md#l-030--custom-event-source-lowering-and-envelope-metadata-are-partial). `balanced.v1` has no separate cumulative logical-allocation ceiling; cross-retry allocation usage is reported and overflow-safely aggregated under [L-029](LIMITATIONS.md#l-029--logical-allocation-has-no-distinct-balancedv1-ceiling).
- Production agent dialing, identity pinning, reconnect, and durable replay are implemented. The listener still lacks an owned bounded service scheduler, and CRL/SQLite tests do not cover every revocation state or crash boundary.
- PostgreSQL 17 was unavailable on the implementation host. The driver-enabled branch was warning-clean compiled against the API surface, but real libpq linking, migrations, TLS connections, concurrency, failover, cancellation, and pooling remain unqualified. The current adapter owns one mutexed connection.
- Activation/admin control-plane state is not yet stored in the durable runtime schema. The current administrative domain and command layer must fail closed unless a real authenticated backend is supplied.
- Concrete server/admin command backends, bundled-runtime installation, Linux builds, full package/install smoke tests, fuzzing, fault injection, and the 10,000-peer stability run remain final integration gates until recorded otherwise.
- Production-agent limitations remain numeric-only endpoints ([L-022](LIMITATIONS.md#l-022--the-production-windows-agent-accepts-numeric-server-endpoints-only)), serialized in-flight cancellation ([L-023](LIMITATIONS.md#l-023--provider-dispatch-cannot-consume-a-later-cancel-frame-concurrently)), once-per-process initial inventory ([L-024](LIMITATIONS.md#l-024--initial-process-inventory-is-once-per-agent-process)), and no online certificate revocation check ([L-025](LIMITATIONS.md#l-025--agent-certificate-revocation-is-not-checked-online)).
- Provider schema attestation is exact at the top-level descriptor, but recursive list/map element descriptors and generated provider-catalog integration remain partial ([L-027](LIMITATIONS.md#l-027--provider-container-schemas-and-catalog-generation-are-partial)).
- Regex match and context contents cannot be independently recomputed by a server that intentionally does not possess the scanned source. The server validates authenticated attribution, identities, permissions, bounds, lengths, pattern membership, and framing; the provider remains the source of fact truth.
- Complete Unicode NFC/case-fold path normalization, locked-wheel dependency materialization, and cryptographic authentication of internal deterministic VM digests remain future hardening work.

## Cutover status

The working cutover removes the former parser/compiler/runtime/protocol source,
Rust bridge, Cargo/cbindgen files, YARA fixtures, legacy tools, and obsolete
documentation from the active build. A fresh Ninja directory configured with
clang-cl using only the Python-engine CMake graph completed all 470 build steps
and passed all 22 registered Python-engine CTest executables serially. The real
packaging and compiler suites used the SHA-256-verified official CPython 3.14.6
Windows x64 embeddable archive with isolated-worker flags and no system-Python
fallback.

This proves the Windows source/build removal gate for the current integration
snapshot; it does not prove release qualification. Real worker JSON-to-compiler
interoperability, listener/server service composition, durable activation/admin
state, remaining executable backends, complete install packaging,
Linux/PostgreSQL builds, fuzzing, fault injection, and scale qualification remain
open and must be recorded above until their tests pass.
