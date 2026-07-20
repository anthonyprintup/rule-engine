# ADR-018: Big-Bang YARA Removal

- Status: Accepted
- Decision owner: Integration architecture
- Applies to: all implementation lanes, I1, I2, X1, Q1
- Related limitations: L-002, L-003, L-011, L-016, L-018

## Context

The current repository parses YARA with a Rust YARA-X bridge generated through
cbindgen, exposes YARA-shaped AST/compiler APIs, evaluates YARA semantics, uses
protocol v1 and a rule_engine_client demo provider, accepts .yar files and
--rule, and contains YARA fixtures/examples/documentation.

The replacement is not merely new syntax. It introduces static Python models and
types, source-only signed packs, a private CPython AST/generator worker, typed
HIR/CFG/bytecode, a resumable C++ VM, explicit scan spaces, transactional
effects/state/correlation, protocol v2, and active-active coordination.

Maintaining both frontends would preserve two semantic languages, two packaging
and dependency chains, two sets of diagnostics/fixtures, and multiple public
ways to reach the engine. A translator would also imply compatibility that the
new model, async, exception, effect, and state semantics do not provide.

## Decision

Deliver one coordinated clean break. The final supported repository, binaries,
packages, docs, examples, tests, and protocol contain only the Python
rule-engine design.

The implementation may temporarily build additive components on the private
integration branch so behavior can be verified and valuable tests can be
mapped. That state is never designated releasable and exposes no supported
dual-frontend contract.

The X1 cutover occurs only after the new engine passes component, end-to-end,
cross-platform, distributed PostgreSQL, security/replay/optimizer, packaging,
and stability gates. X1 then removes in one integration wave:

- rust/yara_bridge, Cargo.toml/lock, build.rs, cbindgen configuration/generated
  assumptions, Cargo discovery/build targets, Rust bridge linking, and related
  system/build dependencies;
- YARA/YARA-X AST, bridge ABI, compiler/parser/evaluator semantics, public
  parse_source/parse_sources/parse_file APIs, ParsedRuleSet/ParseOptions, and
  old undefined/pattern behavior not present in the Python design;
- protocol v1 messages/framing/handshake and opaque subject identities;
- rule_engine_client, server --rule/-r and include/module/fixture options,
  check's .yar input path, and all other legacy-only CLI/configuration;
- every tracked .yar fixture/example and bridge-specific test;
- docs/RUST_BRIDGE_UPDATE.md and all instructions to install/update
  Rust/Cargo/YARA-X/cbindgen; and
- old examples/status/goal text that presents YARA or protocol v1 as current.

rule_engine_agent, protocol v2, rule_engine_check --pack, rule_engine_pack,
resident rule_engine_server --config, rule_engine_admin, and the Python-pack
benchmark path are the sole replacements.

Legacy behavioral tests are not blindly deleted. Each is classified:

- Retained when independent of the old frontend;
- ReplacedBy a Python/compiler/VM/protocol test when behavior remains required;
  or
- RemovedByDesign with an ADR/limitation link.

Short-circuit fact behavior, provider typing, nested identities, cancellation,
scheduler/backpressure, tracing, optimizer parity, diagnostics, and pattern
metadata must retain replacement coverage.

After deletion, tracked file/content/symbol, CMake graph, installed header,
binary/import, package/SBOM, CLI help/string, protocol artifact, and license
scans must find no live YARA/YARA-X/Rust-bridge/Cargo/cbindgen surface. One
explicit historical release-note sentence may state that YARA support was
removed; no other allowlist entry is permitted.

~~~mermaid
flowchart TD
    B["Verified optimizer/protocol recovery checkpoint"] --> N["New Python engine components"]
    N --> I["Integrated end-to-end new runtime"]
    I --> Q["Cross-platform, distributed, security and stability gates"]
    Q --> X["Single X1 deletion wave"]
    X --> C["Clean no-Rust/no-system-Python build and package"]
    C --> R["One supported Python engine release"]
~~~

## Primary reasons

1. **One semantic contract:** authors and operators need one language, verdict
   model, diagnostic system, state/effect model, and protocol.
2. **Smaller trust/build surface:** removing Rust/YARA-X/cbindgen eliminates the
   obsolete parser bridge and its update/ABI/dependency chain.
3. **No false compatibility claim:** Python models, explicit scans, exceptions,
   async capabilities, state, effects, and correlations cannot faithfully
   inherit generic YARA behavior through a syntactic translation.
4. **No permanent migration tax:** a dual frontend would force every compiler,
   optimizer, provider, protocol, CLI, document, and test change to consider two
   languages.
5. **Verifiable packaging:** a clean build without Rust/Cargo and a scan of
   installed artifacts prove the old engine is actually gone.

## Rejected alternatives

### Keep YARA as a feature flag

Rejected because feature flags do not remove the dependency, parser API,
security surface, tests, or maintenance obligation. Dormant paths also decay and
are difficult to qualify.

### Ship separate legacy and Python executables

Rejected because two binaries still share providers/storage/operations and
create two supported semantic generations. It also complicates protocol and
pack activation.

### Automatic YARA-to-Python translator

Rejected because it would need to define mappings for YARA undefined behavior,
patterns, quantifiers, modules, includes/namespaces, globals/private rules, and
provider-backed semantics. Producing superficially valid Python would overstate
semantic fidelity. Existing packs are manually rewritten and reviewed.

### Long deprecation period

Rejected by the explicit requirement to drop YARA completely and by the absence
of a backward-compatibility requirement. A coordinated agent/server/pack rollout
is accepted.

### Delete YARA before the new engine is integrated

Rejected because current tests and the dirty optimizer/protocol work provide a
valuable behavioral/recovery baseline. Deletion is late, but final delivery is
still one big-bang engine.

### Preserve YARA fixtures as permanent regression data

Rejected because that retains authoring artifacts and may preserve an implicit
compatibility promise. Behavioral intent is ported to Python fixtures or marked
removed by design before the .yar file is deleted.

## Positive consequences

- One frontend, compiler, VM, protocol, packaging system, CLI set, and
  documentation story.
- No Rust/Cargo/cbindgen/YARA-X dependency or generated bridge ABI.
- Smaller attack, supply-chain, build, and maintenance surface.
- Tests state new semantics directly.
- Operators cannot accidentally activate an obsolete rule format.
- Linux server builds are no longer blocked by the Windows-specific Rust .lib
  assumption in the current CMake graph.

## Negative consequences

- Existing YARA rules require manual redesign and validation.
- Protocol-v1 clients and server tooling stop interoperating at cutover.
- The release requires coordinated server, Windows-agent, and pack deployment.
- The cutover changes many files at once and demands a strong recovery
  checkpoint and qualification evidence.
- Some legacy tests cannot be mechanically translated because the semantics are
  intentionally different.
- The first release provides no YARA migration assistant.

## Operational and security implications

- Production must reject .yar input, old protocol handshakes, legacy CLI options,
  and old pack/config shapes with a clear unsupported-version diagnostic, not
  silent fallback.
- Deployment checks install protocol-v2 Windows agents before activating Python
  packs and verify servers no longer expose the v1 listener.
- Software bills of materials and license notices remove Rust/YARA-X/cbindgen
  entries and add the pinned private CPython and new C++ dependencies.
- Signer trust approves source packs only; there is no special legacy bypass.
- Incident/runbook documentation uses pack digest/generation/executable IDs, not
  YARA rule names or bridge versions.
- The recovery checkpoint is source-control history, not a runtime compatibility
  switch in the released product.

## Known limitations introduced

- Existing pack owners have no automatic conversion path.
- Python re is not a replacement for YARA patterns; authors must use explicit
  typed literal/masked/RE2 scan APIs.
- Some YARA constructs have no counterpart and are RemovedByDesign.
- Rollout cannot be piecemeal across protocol-v1 clients.
- Performance comparisons to YARA workloads require documented equivalent
  Python/scan workloads rather than identical source.
- One historical release-note reference remains permitted, but no executable or
  authoring compatibility does.

## Validation evidence

- TRACEABILITY.md maps every legacy test/fixture to Retained, ReplacedBy, or
  RemovedByDesign before deletion.
- Full new-engine qualification passes before X1.
- Fresh configure/build/test/install/package succeeds with cargo, rustc,
  cbindgen, and system Python unavailable.
- git ls-files contains no rust tree, Cargo manifests/lock, cbindgen config, or
  .yar file.
- Forbidden content/symbol scans cover source, docs, CMake exports, installed
  headers, executables/imports, package archives, SBOM, CLI help, and protocol
  artifacts.
- Only the explicit historical release-note line is allowlisted.
- Protocol-v1 connections and .yar/legacy CLI inputs receive explicit
  unsupported diagnostics and cannot execute.
- Windows agent to Windows/Linux server tests pass exclusively through protocol
  v2.
- Final Git status is clean; local agent guidance and planning artifacts
  remain ignored and untracked.

## Conditions for revisiting

The production runtime must not reintroduce YARA compatibility. If migration
demand later justifies assistance, it may be designed as a separate offline,
non-authoritative analysis tool that emits review-required suggestions and is
not linked into the engine, server, agent, pack compiler, or installed runtime.

Any proposal to support another authoring language requires its own complete
trust, typing, semantic, packaging, VM-lowering, tooling, protocol, operations,
and maintenance decision. It cannot weaken the one-active-semantic-generation
invariant or restore the deleted bridge through a feature flag.
