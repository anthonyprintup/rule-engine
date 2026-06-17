# TODO

This file tracks meaningful work beyond the currently implemented V1 scope in
`GOAL.md`. Keep the trust boundary intact for every item: C++ owns rule
semantics and match decisions; clients only return typed facts or structured
diagnostics.

## Provider And Module Binding Hardening

- [x] Advertise custom module/function provider routes in the client handshake instead
  of only advertising the built-in process, PE, and pattern routes.
- [x] Validate provider responses against C++ descriptors: returned field facts must
  match `FieldDescriptor::type`, and returned function facts must match
  `FunctionDescriptor::return_type`.
- [x] Reject evaluator fact requests for routes that are missing from the
  connected client's advertised capabilities.
- [x] Add a descriptor-level route registry so `rule_engine_server` can detect missing
  client capabilities before starting an evaluation session.
- [x] Add CLI/config support for registering custom module descriptors and client fact
  handlers without editing the core test harness.
- [x] Define stable provider key encoding rules for all `ValueType` values, including
  bytes, arrays, objects, and explicit undefined arguments.

## Windows Process Providers

- [x] Implement `process.command_line` with a Windows provider instead of returning a
  v1 diagnostic placeholder.
- [x] Implement `process.handles.count` on `endpoint.process.handles` with structured
  access-denied and partial-data diagnostics.
- [x] Implement `process.signer.status` on `endpoint.process.signer` using Windows
  Authenticode/WinTrust APIs.
- Add a first-class unsigned-process matching fact on `endpoint.process.signer`:
  - Expose a simple boolean process fact such as `process.signer.is_signed` so
    rules can match unsigned processes directly without string-comparing
    provider status values.
  - Treat both embedded PE signatures and Windows catalog signatures as valid
    signing sources; a process image should be considered unsigned only when
    neither path provides a usable signature.
  - Keep unavailable, inaccessible, timed-out, malformed-image, and verification
    diagnostic states distinct from a definitive unsigned result.
  - Add regression coverage for embedded-signed images, catalog-signed images,
    unsigned images, inaccessible/exited processes, and wrong-typed cached
    signer facts.
- [x] Add tests for process lifetime races where a process exits between subject
  enumeration and fact collection.
- [x] Add richer process facts once the route model is stable:
  - [x] Thread count via `process.thread_count` on `endpoint.process.snapshot`.
  - [x] Architecture via `process.architecture` on `endpoint.process.snapshot`.
  - [x] Integrity level via `process.integrity_level` on `endpoint.process.snapshot`.
  - [x] User/session basics via `process.session_id`, `process.user.sid`, and
    `process.user.name` on `endpoint.process.snapshot`.
  - [x] Loaded modules via `process.modules.count` and `process.modules.names`
    on `endpoint.process.snapshot`.
  - [x] Token metadata via `process.token.elevated` and `process.token.type` on
    `endpoint.process.snapshot`.
  - [x] Memory regions:
    - [x] Region counts via `process.memory.regions.count` and
      `process.memory.regions.readable_count` on `endpoint.process.snapshot`.
    - [x] Region arrays with base, size, state, protection, type, and scan-space
      metadata.

## PE And Image Facts

- [x] Expand the PE provider beyond the current minimal header facts:
  - [x] Sections via `pe.sections` array objects with name, virtual address/size,
    raw data offset/size, characteristics, and readable/writable/executable flags.
  - [x] Imports via `pe.imports` array objects with DLL, name/ordinal, hint,
    lookup RVA, and IAT RVA fields.
  - [x] Exports via `pe.exports` array objects with module, name/ordinal, RVA,
    forwarded flag, and forwarder string fields.
  - [x] Resources via `pe.resources` array objects with type/name/language,
    RVA, size, and code-page fields.
  - [x] Debug directory via `pe.debug_entries` array objects with type,
    timestamp, version, size, and raw-data location fields.
  - [x] TLS callbacks via `pe.tls_callbacks` array objects with index, VA,
    and RVA fields.
  - [x] Certificate table via `pe.certificates` array objects with file
    offset, size, revision, type, and payload size fields.
  - [x] Subsystem via `pe.subsystem`.
  - [x] Characteristics via `pe.characteristics` and `pe.dll_characteristics`.
  - [x] Timestamp fields for the COFF image header via `pe.timestamp`.
- [x] Add section-level array/object values so rules can iterate over PE sections with
  `for in`.
- [x] Add PE parser regression fixtures for malformed, truncated, non-PE, PE32,
  and PE32+ images.
- [x] Separate static image facts from volatile process facts in cache policy
  tests for richer PE routes.

## Pattern Scanning

- Replace fixture-backed pattern facts with a real scanner while preserving the
  final `PatternValue` fact schema.
  - [x] Configured literal byte scanner through `--pattern-fixture` `scan`
    directives, returning real offsets and match context metadata.
  - [x] Rule-derived scan plans so clients do not need pattern definitions
    duplicated in local fixture/config files.
- Support explicit scan spaces:
  - [x] File bytes through fixture `scan_file` directives.
  - [x] Process image bytes.
  - [x] Mapped image sections.
  - [x] Readable memory regions.
- [x] Preserve match context metadata: offset, length, bytes, before/after context,
  region permissions, and scan-space name.
- [x] Add scheduling controls for expensive scan routes so cheap process/PE filters
  can short-circuit before scanning.

## YARA Expression Coverage

- Implement currently rejected `of` shapes:
  - [x] Boolean tuple `of` expressions such as `any of (true, 1 == 1)`.
  - [x] Anchored pattern-set `of ... at/in` forms.
- Add descriptor-backed implementations for useful built-ins such as integer
  readers (`uint8`, `uint16`, `uint32`, etc.) once scan-space byte facts are
  available.
- Audit YARA-X AST variants after each `yara-x-parser` bump and add bridge tests
  for newly supported expression nodes.
- Expand semantic type inference for more expression forms while keeping dynamic
  fact-backed values symbolic.

## VM, Scheduler, And Caching

- [x] Add provider return-type enforcement at VM cache-fill boundaries so bad clients
  fail closed.
- [x] Prefetch deterministic function facts when all arguments are statically known
  and the descriptor marks the function as cheap.
- [x] Make provider timeout policy explicit per descriptor and per route batch.
- Define descriptor-level retry and cancellation semantics once runtime
  orchestration supports retries and cancellable in-flight provider requests.
- [x] Add replay tests for function-call fact requests and custom provider routes.
- Stabilize the debug IR and trace schemas once the module/provider surface stops
  changing.

## VM Optimization Roadmap

Design goal: optimize for thousands of rules evaluated against every process
subject reported by many connected clients. Clients should report minimal
inventory first, server-side C++ must still own rule semantics and match
decisions, and evaluation should aggressively early-reject rules that cannot
match without materializing broad per-process metadata.

Important workload assumptions:

- A connected client rearms its next evaluation after the current evaluation
  finishes, nominally on a five-minute cadence.
- Server scheduling must jitter and backpressure those client timers so many
  clients do not synchronize into one evaluation spike.
- A single client evaluation may contain many process subjects and thousands of
  rules.
- Most rules are expected to start with useful process, PE, signer, module,
  memory, or scan-space filters.
- Some intentionally broad rules will match many processes early, such as
  filters over common image names or broad PE validity checks, so the optimizer
  cannot rely on every first predicate being selective.
- Client-side coarse candidate providers are allowed when they expose generic
  inventory facts or subject sets, but they must not expose rule identity,
  hidden rule branches, exact YARA pattern intent, or client-owned match
  decisions.

Approved direction: evolve the current interpreter into a Phreak-inspired lazy,
goal-oriented optimizer backed by a canonical predicate DAG and adaptive
candidate sets. Keep the existing exact VM semantics as the final evaluator and
fallback path while adding shared predicate execution in front of it.

- Add a lightweight performance baseline before structural rewrites:
  - Measure per-client sweep time for synthetic and fixture-backed workloads
    with many subjects and thousands of rules.
  - Track number of provider rounds, facts requested, facts returned, VM
    expression evaluations, rules eliminated before exact VM evaluation, and
    rules that reach expensive providers.
  - Include adversarial cases with nonselective filters such as common process
    names, broad `pe.is_valid` checks, and rules whose cheap filters all pass.
  - Include selective cases where many rules share identical first filters, such
    as repeated `process.name == "powershell.exe"` or repeated PE/header
    predicates.
- Replace flat fact lookup on hot paths:
  - Change `FactCache` from linear subject/key scans to an indexed structure
    keyed by subject id and fact key.
  - Preserve TTL expiration semantics for volatile process facts and static PE
    facts.
  - Preserve trace replay behavior and deterministic fact snapshots.
  - Keep memory bounded per active client sweep; do not create an always-on
    cache of all process metadata for all clients.
- Add canonical predicate IDs:
  - Lower simple, side-effect-free condition fragments into canonical predicate
    forms, independent of source spelling where semantics are equivalent.
  - Canonicalize descriptor-backed comparisons such as field/global/function
    fact compared with a literal or small literal set.
  - Include predicate source spans and owning rule references so diagnostics and
    optimized traces can point back to original rule text.
  - Treat expressions with local bindings, loops, dynamic function arguments,
    pattern metadata, or unsupported shapes as exact-VM-only until explicitly
    lifted into the optimizer.
- Add cost and selectivity metadata:
  - Assign descriptor-level cost classes such as inventory, cheap process
    snapshot, static image header, broad image array, handle/signer, memory
    region, and pattern scan.
  - Allow boolean condition reordering for commutative `and` and `or`
    expressions when it is semantically safe.
  - Prefer low-cost, high-selectivity predicates before expensive or broad
    predicates.
  - Update selectivity estimates from observed sweep results without relying on
    clients to make semantic decisions.
  - Record the chosen predicate order in opt-in traces.
- Build a shared predicate DAG:
  - Deduplicate identical predicate nodes across all rules in a verified
    program.
  - Represent rule conditions as references into the DAG plus exact-VM fallback
    continuations for complex leaves.
  - Evaluate a predicate node at most once per subject or per candidate set in a
    sweep.
  - Store only compact node results needed for the active sweep, not full
    metadata snapshots for every process.
  - Preserve rule reference and global rule semantics while allowing shared
    predicate nodes below them.
- Add adaptive candidate sets:
  - Represent the current process universe for a client sweep as compact subject
    ids plus bitsets or compressed bitsets.
  - Evaluate shared predicates into candidate sets and combine them with fast
    set operations for `and`, `or`, and safe complements.
  - Use dense bitsets for small or dense subject sets and compressed/adaptive
    bitsets for large or sparse sets.
  - Drop rule branches immediately when their candidate set becomes empty.
  - Detect nonselective predicates and avoid spending memory retaining useless
    large intermediate sets unless they are needed for downstream branching.
- Add lazy provider expansion:
  - Start each sweep from minimal client inventory, such as process subject ids
    and cheap identity fields.
  - Request additional facts only for candidate subjects that survive earlier
    predicate nodes.
  - Batch requests by provider route across surviving subjects.
  - Avoid requesting expensive arrays, memory-region lists, PE imports/exports,
    signer data, handle counts, or pattern scans for eliminated subjects.
  - Keep provider request types generic; clients return typed facts or generic
    candidate sets, never rule decisions.
- Add generic client-side candidate providers where useful:
  - Support provider routes that return generic subject sets, such as processes
    with valid base image PE headers, processes grouped by image name, processes
    with readable image bytes, or processes with coarse architecture/session
    traits.
  - Ensure candidate providers are optional optimizations; the server must be
    able to fall back to per-subject facts and server-side candidate-set
    construction.
  - Do not expose exact rule names, full condition branches, private strings, or
    pattern literals through these routes unless that data is already part of a
    normal provider request by design.
  - Treat broad candidate provider output as a signal to continue narrowing on
    the server rather than as a failure.
- Add discovery gates for rule packs and expensive rule families:
  - Let the compiler derive cheap pack-level gates from predicates that are
    shared by many rules, such as required modules, process-kind constraints,
    architecture/session constraints, base-image PE validity, or known provider
    capability requirements.
  - Run discovery gates before building full per-process candidate sets for a
    rule pack; skip the pack when its gates prove that no rule in it can match
    the current client inventory.
  - Keep discovery gates server-owned and source-linked. They are optimizer
    predicates, not client-owned rule decisions.
  - Example: a pack whose rules all require `pe.is_valid` can first ask for a
    generic `valid_base_pe_subjects` candidate set. If the set is empty, the
    whole pack can be skipped with a trace entry.
  - Example: a pack whose rules only apply to 64-bit user processes can first
    intersect cheap inventory sets for `process.architecture == "x64"` and
    `process.integrity_level != "system"` before any signer, import, memory, or
    pattern routes are considered.
  - Example: a rule family that requires process image bytes can be gated by a
    generic provider capability and a cheap image-path/readability check before
    any scan plans are emitted.
- Add provider-scope filtering as a generic candidate provider pattern:
  - Allow the server to request coarse, reusable provider filters that are
    independent of exact rule identity, exact private strings, and full
    condition branches.
  - Keep the client limited to inventory and fact production; the server still
    combines provider-scope filter output with the rule predicate DAG and exact
    VM.
  - Example: request `process.inventory.by_image_name("chrome.exe")` to get a
    candidate subject set. If it returns many processes, the server continues
    narrowing with signer, parent, command-line, module, PE, memory, or pattern
    predicates.
  - Example: request `process.inventory.valid_base_pe_subjects` to get processes
    whose base image appears to be a readable, parseable PE, without revealing
    whether a specific rule is testing `pe.is_valid`.
  - Example: request `process.inventory.with_readable_image_bytes` before
    emitting literal scan requests, so subjects whose image cannot be read are
    eliminated or diagnosed before expensive pattern routes.
  - Model provider-scope filter output as typed facts or subject sets with
    diagnostics, TTLs, and traces, not as rule results.
  - Add a server-side fallback path that builds the same candidate sets from
    per-subject facts when a client does not advertise a candidate provider.
- Add demand-driven feature materialization:
  - Do not compute or request hashes, PE imports/exports/resources, debug
    entries, certificates, signer/catalog data, handle counts, memory-region
    arrays, loaded-module arrays, command lines, or pattern scans until a
    surviving predicate branch requires them.
  - Mark each descriptor with a materialization class and expected payload cost
    so the optimizer can keep cheap scalar inventory separate from expensive
    arrays, file reads, signature verification, and scans.
  - Keep expensive materialized values scoped to the active sweep unless their
    TTL and cache key make cross-subject or cross-sweep reuse safe.
  - Add tests that prove selective rules do not materialize expensive facts for
    eliminated subjects.
- Add route and predicate watchdogs:
  - Track per-route and per-predicate elapsed time, bytes returned, subjects
    touched, candidate-set reduction, and diagnostic rate during each sweep.
  - Put predicates or provider routes into a bounded cool-down when they exceed
    CPU, latency, payload-size, or low-selectivity budgets repeatedly.
  - During cool-down, either defer the expensive branch, request a cheaper
    substitute gate, or complete with a traceable budget diagnostic according to
    rule/policy settings.
  - Never silently skip a rule because of budget pressure; final no-match,
    timeout, unavailable, or deferred states must be explicit.
  - Add adversarial tests for rules that force broad signer, memory, import, or
    scan work across most process subjects.
- Add content-addressed fact caches where safe:
  - Cache static image facts by stable file identity rather than only process
    subject id when the provider can verify that the underlying file content has
    not changed.
  - Candidate cache keys include path or file id, size, timestamps, content hash
    when already available, signature/catalog identity, and scan-space version.
  - Reuse PE header, import/export/resource/debug/certificate, signer/catalog,
    and hash facts across multiple processes that map the same unchanged image.
  - Keep volatile process facts, command lines, handles, tokens, parent/child
    relationships, and live memory facts subject-scoped.
  - Add invalidation and trace entries whenever a reused static fact is accepted
    or rejected because its file identity changed.
- Defer event/delta streams until after snapshot optimization is stable:
  - Keep the current roadmap based on jittered five-minute snapshot sweeps.
  - Do not require process/file/image-load event streams for the predicate DAG,
    candidate providers, or exact VM fallback to work.
  - Reserve a future design for incremental inventory updates that invalidate
    affected predicate nodes and candidate sets between snapshot sweeps.
- Preserve exact VM semantics:
  - Use the optimized DAG only to prune impossible rules, reorder safe
    predicates, and reduce provider requests.
  - Run the existing exact VM or a semantically equivalent lowered VM for final
    rule results when a rule remains possible.
  - Keep undefined, unavailable, access-denied, timeout, global-rule gating,
    private-rule suppression, rule references, `with`, `for`, `of`, and pattern
    metadata behavior identical to the current VM.
  - Add differential tests that compare optimized and unoptimized evaluation
    results over the same verified program and fact responses.
- Add optimized diagnostics and traces:
  - Emit opt-in traces that show canonical predicate ids, source spans, chosen
    cost order, requested fact batches, candidate-set sizes, and prune reasons.
  - Explain when a rule was not run by the exact VM because an earlier shared
    predicate made it impossible.
  - Explain when a broad predicate was evaluated but retained too many subjects
    to be useful for pruning.
  - Keep trace output machine-readable and readable enough to debug rule
    authorship and optimizer decisions.
- Add server scheduling controls for the target deployment model:
  - Add jittered client evaluation timers so 10,000 clients do not wake at the
    same wall-clock boundary.
  - Add backpressure for provider rounds and VM work queues when the server is
    saturated.
  - Separate network I/O readiness from CPU-bound VM/provider orchestration with
    a bounded worker pool.
  - Track queue depth, active client sweeps, active provider requests, average
    sweep duration, and deadline misses.
  - Keep per-client state small enough that many connected idle clients do not
    imply many threads or large metadata snapshots.
- Add production-scale test fixtures:
  - Generate synthetic rule packs with shared first predicates, mixed predicate
    ordering, broad filters, expensive scan leaves, and complex exact-VM-only
    leaves.
  - Generate synthetic client inventories with many processes and controlled
    selectivity distributions.
  - Test that optimized evaluation requests fewer facts and performs fewer
    expression evaluations than the baseline on selective packs.
  - Test that broad-rule packs still complete correctly and do not retain
    unbounded candidate-set state.
  - Test that optimized and unoptimized modes produce identical final rule
    results and diagnostics for the same inputs.

## Client And Server Runtime

- [x] Support multi-session client service mode instead of only one-shot localhost
  smoke sessions.
- Add graceful shutdown and cancellation paths for long-running provider requests.
- [x] Make server output available as structured JSON in addition to human-readable
  text.
- [x] Add integration tests that evaluate rules against multiple live subjects
  with custom provider routes and capability negotiation.
- [x] Keep localhost/plain TCP as the V1 demo path, but document the production
  transport boundary before adding remote clients.

## Tooling And Documentation

- Keep `docs/V1_IMPLEMENTATION_STATUS.md` conservative: only mark items complete
  after tests or smoke checks cover them.
- [x] Add examples for custom module descriptors, function bindings, and client
  fact handlers.
- [x] Add a small rule corpus that documents supported and intentionally
  unsupported YARA constructs.
- [x] Add a developer guide for updating the Rust bridge and regenerated
  cbindgen C++ header.
