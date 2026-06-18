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
- [x] Add a first-class unsigned-process matching fact on `endpoint.process.signer`:
  - [x] Expose a simple boolean process fact such as `process.signer.is_signed` so
    rules can match unsigned processes directly without string-comparing
    provider status values.
  - [x] Treat both embedded PE signatures and Windows catalog signatures as valid
    signing sources; a process image should be considered unsigned only when
    neither path provides a usable signature.
  - [x] Keep unavailable and inaccessible process/signer provider results
    distinct from a definitive unsigned result for the live provider path.
  - [x] Keep malformed-image diagnostics distinct from a definitive unsigned
    result for path-backed signer evaluation.
  - [x] Keep richer verification diagnostics distinct from a definitive
    unsigned result, including malformed embedded signature data.
  - [x] Keep timed-out signer verification distinct from a definitive unsigned
    result for expired request deadlines.
  - [x] Add regression coverage for the VM binding, wrong-typed cached signer
    facts, live signer batches, localhost client routing, and exited processes.
  - [x] Add deterministic fixture coverage for unsigned and malformed image
    signer results.
  - [x] Add deterministic fixture coverage for embedded-signed images,
    catalog-signed images, and inaccessible live processes.
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
- [x] Add descriptor-backed implementations for useful built-ins such as integer
  readers (`uint8`, `uint16`, `uint32`, etc.) once scan-space byte facts are
  available.
- [x] Audit YARA-X AST variants after each `yara-x-parser` bump and add bridge tests
  for newly supported expression nodes.
- [x] Expand semantic type inference for more expression forms while keeping dynamic
  fact-backed values symbolic.

## VM, Scheduler, And Caching

- [x] Add provider return-type enforcement at VM cache-fill boundaries so bad clients
  fail closed.
- [x] Prefetch deterministic function facts when all arguments are statically known
  and the descriptor marks the function as cheap.
- [x] Make provider timeout policy explicit per descriptor and per route batch.
- [x] Define descriptor-level retry policy and descriptor-specific cancellation
  diagnostics now that runtime orchestration supports cooperative provider
  cancellation.
- [x] Add replay tests for function-call fact requests and custom provider routes.
- [x] Stabilize the debug IR and trace schemas once the module/provider surface stops
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

- Treat optimization work as validation-gated, POC-first development:
  - Do not land a production optimizer rewrite until a baseline report exists for
    the current unoptimized evaluator.
  - Keep each optimizer experiment behind an explicit opt-in path until
    optimized and unoptimized evaluation produce identical rule results,
    diagnostics, and trace-replay-compatible fact snapshots for the same
    verified program and fact responses.
  - Every POC should produce a machine-readable benchmark report plus a readable
    summary that compares baseline and candidate behavior.
  - Reports should include wall-clock sweep time, provider rounds, facts
    requested, facts returned, returned payload bytes, VM expression
    evaluations, exact-VM rule executions, rules pruned before exact VM,
    expensive-provider reaches, fact-cache lookups, cache hits/misses, and peak
    candidate-set state where applicable.
  - Treat any semantic mismatch, missing diagnostic, changed unavailable/timeout
    behavior, global/private/rule-reference mismatch, or trace replay regression
    as a failed optimization regardless of speedup.
  - Include broad/adversarial workloads and selective/shared-predicate workloads
    in every comparison so wins are not limited to ideal cases.
- Use a staged POC sequence before full implementation:
  - First add the benchmark/report harness and baseline measurements without
    changing evaluator behavior.
  - Add instrumentation counters to the current evaluator, cache, and client
    orchestration so optimization results can be explained rather than only
    timed.
    - [x] Add initial evaluator expression counters and `FactCache` lookup,
      hit, and miss counters to the synthetic baseline report path.
    - [x] Add initial client orchestration counters for provider rounds,
      provider request messages, requested fact keys, returned facts, and
      provider round-trip elapsed time.
  - Prototype the indexed `FactCache` independently before semantic optimizer
    work, because current lookup/store paths are linear and can be validated
    without changing rule behavior.
    - [x] Replace hot-path `FactCache` lookup/store scans with a subject/key
      index, preserving deterministic snapshots and TTL expiration behavior.
    - [x] Add lookup-probe counters to tests and benchmark reports so the POC
      has measurable validation evidence.
- Prototype canonical predicate extraction as an offline or opt-in compiler
  artifact that reports what can and cannot be safely lifted.
  - [x] Add an initial offline canonical predicate extractor for
    descriptor-backed field/global comparisons against scalar literals,
    including deduped owners and exact-VM-only notes for complex shapes.
  - [x] POC: `build_optimizer_plan` packages canonical predicate nodes, static
    predicate order, exact-VM fallback notes, provider requirements, and generic
    candidate-provider requests into an opt-in server-owned optimizer artifact.
  - Prototype a shared predicate DAG simulator that produces candidate sets and
    prune reasons while still letting the exact VM decide final results.
    - [x] Add an initial offline shared predicate DAG simulator that evaluates
      each lifted predicate once per subject, keeps unknown/diagnostic facts in
      the exact-VM candidate set, and only prunes rule-subject pairs for
      predicates lifted from required boolean contexts.
    - [x] Add opt-in benchmark report metrics for simulated shared-predicate
      pruning and peak candidate-set size without changing baseline exact-VM
      execution.
  - Prototype lazy provider expansion after the simulator proves it can prune
    subjects without semantic drift.
    - [x] Add an initial offline lazy provider expansion planner that groups
      non-cheap required facts by route/key and requests them only for
      shared-DAG candidate subjects, keeping unknown subjects in the request set.
    - [x] Add opt-in benchmark report metrics for lazy provider batches,
      requested facts, avoided facts, and avoided expensive facts on a synthetic
      shared process-name plus expensive PE-import workload.
  - Add generic client-side candidate providers only after the server-side
    fallback path and privacy boundaries are proven with reports.
- Add a lightweight performance baseline before structural rewrites:
  - [x] Add an initial synthetic baseline benchmark harness and
    `rule_engine_benchmark` CLI that emit JSON and Markdown reports for a shared
    process-name predicate workload.
  - Measure per-client sweep time for synthetic and fixture-backed workloads
    with many subjects and thousands of rules.
  - Track number of provider rounds, facts requested, facts returned, VM
    expression evaluations, rules eliminated before exact VM evaluation, and
    rules that reach expensive providers.
  - Include adversarial cases with nonselective filters such as common process
    names, broad `pe.is_valid` checks, and rules whose cheap filters all pass.
    - [x] POC: add a `broad_process_name` benchmark scenario where all subjects
      pass the shared process-name filter, so shared-DAG simulation reports zero
      pruning on a nonselective workload.
  - Include selective cases where many rules share identical first filters, such
    as repeated `process.name == "powershell.exe"` or repeated PE/header
    predicates.
  - Generate deterministic JSON and Markdown reports so benchmark changes can be
    compared across commits.
  - [x] Store enough benchmark metadata to reproduce the run: rule-pack generator
    seed, subject-count, rule-count, selectivity distribution, provider latency
    model, enabled optimizer flags, build type, and machine-readable version.
    - [x] POC benchmark reports include enabled optimizer flags in both JSON and
      Markdown metadata so baseline and opt-in optimizer runs can be compared
      across commits.
    - [x] POC benchmark reports include build type metadata before treating
      benchmark reports as production acceptance artifacts.
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
    - [x] POC: add descriptor-owned fact cost classes to built-in descriptors
      and carry them into verified required facts, canonical predicate reports,
      and shared-DAG simulations.
  - Define the first cost model as descriptor-owned static metadata, then let
    observed selectivity adjust ordering only within safe semantic boundaries.
    - [x] POC: sort offline shared-DAG predicate simulation by static descriptor
      cost, with deterministic id ordering for ties, without changing exact VM
      final evaluation.
    - [x] POC: build an observed selectivity profile from a prior shared-DAG
      sweep and use it only as a same-cost tie-breaker, so broad cheap
      inventory predicates move behind more selective cheap inventory predicates
      while higher-cost predicates cannot jump ahead of cheaper descriptor
      classes.
  - Record enough observed selectivity data to explain why an optimizer chose or
    rejected a predicate order.
    - [x] POC: emit predicate order, cost class, and observed selectivity ppm in
      optimizer JSON plus benchmark JSON/Markdown reports.
  - Allow boolean condition reordering for commutative `and` and `or`
    expressions when it is semantically safe.
  - Prefer low-cost, high-selectivity predicates before expensive or broad
    predicates.
  - Update selectivity estimates from observed sweep results without relying on
    clients to make semantic decisions.
    - [x] POC: `selectivity_feedback_inventory --simulate-selectivity-feedback`
      runs a static warm-up sweep, feeds the server-owned observed predicate
      profile into a second opt-in shared-DAG simulation, and reports reordered
      same-cost predicates in
      `build/codex-debug/reports/selectivity_feedback.{json,md}`.
  - Record the chosen predicate order in opt-in traces.
- Build a shared predicate DAG:
  - Deduplicate identical predicate nodes across all rules in a verified
    program.
    - [x] POC: reuse canonical predicate ids as shared nodes and evaluate each
      node once per subject for offline simulation.
  - Represent rule conditions as references into the DAG plus exact-VM fallback
    continuations for complex leaves.
    - [x] POC: add an optimizer-side prefiltered evaluation comparison that runs
      exact VM only for shared-DAG candidate rule/subject pairs, synthesizes
      pruned no-match results, and checks parity against baseline rule results.
    - [x] POC: add `evaluate_with_optimizer_plan` as an opt-in C++ sweep path
      that consumes `OptimizerPlan`, builds shared-DAG candidate state, runs the
      exact VM only for surviving reportable rule/subject pairs, and synthesizes
      no-match results for pruned pairs.
    - [x] POC: extend the plan-driven sweep path so it can consume generic
      candidate-provider subject sets, expose provider/fallback counters, and
      still run exact VM only for surviving rule/subject pairs.
    - [x] POC: add `--simulate-optimizer-plan-prefilter` benchmark coverage for
      the plan-driven sweep path; `production_scale_validation` reports 52
      plan-driven exact-VM executions, 108 avoided exact-VM executions, 108 skip
      trace events, zero result mismatches, and zero incomplete subjects in
      `build/codex-debug/reports/optimizer_plan_prefilter.{json,md}`.
    - [x] POC: do not mark predicates after earlier exact-VM-only diagnostic
      work as prune-safe, preserving expensive-first baseline diagnostics while
      still pruning cheap-first branches.
  - Evaluate a predicate node at most once per subject or per candidate set in a
    sweep.
    - [x] POC: report predicate evaluation count, per-node matched/pruned/unknown
      subject sets, per-rule exact-VM candidate sets, and prune reasons.
  - Store only compact node results needed for the active sweep, not full
    metadata snapshots for every process.
  - Preserve rule reference and global rule semantics while allowing shared
    predicate nodes below them.
    - [x] POC: keep diagnostic/unknown predicate subjects on the exact-VM path
      in the prefiltered comparison so unavailable facts preserve baseline
      diagnostics instead of becoming optimizer prunes.
    - [x] POC: the plan-driven opt-in sweep keeps unavailable predicate facts on
      the exact-VM path and preserves the provider diagnostic in final rule
      results.
    - [x] POC: `global_gate_prefilter --simulate-optimizer-plan-prefilter`
      preserves global rule gating while counting only reportable exact-VM rule
      work; the benchmark reports six optimized reportable exact-VM executions,
      two avoided executions, zero result mismatches, and zero incomplete
      subjects in `build/codex-debug/reports/global_gate_prefilter.{json,md}`.
- Add adaptive candidate sets:
  - Represent the current process universe for a client sweep as compact subject
    ids plus bitsets or compressed bitsets.
    - [x] POC: classify shared-DAG rule candidate sets as dense bitsets or
      sparse compact subject ids and report approximate active-state bytes.
  - Evaluate shared predicates into candidate sets and combine them with fast
    set operations for `and`, `or`, and safe complements.
    - [x] POC: safely union simple top-level `or` alternatives made only of
      lifted descriptor predicates, pruning only subjects that match none while
      retaining unknown/diagnostic subjects for exact-VM parity.
  - Use dense bitsets for small or dense subject sets and compressed/adaptive
    bitsets for large or sparse sets.
    - [x] POC: expose per-rule candidate-set representation plus peak
      candidate-set bytes in optimizer JSON and benchmark JSON/Markdown reports.
  - Drop rule branches immediately when their candidate set becomes empty.
    - [x] POC: mark empty shared-DAG rule candidate sets as dropped, report
      dropped branch counts, and skip lazy provider requests for those branches.
  - Detect nonselective predicates and avoid spending memory retaining useless
    large intermediate sets unless they are needed for downstream branching.
    - [x] POC: mark shared-DAG predicate nodes as nonselective when they match
      every subject with no pruned or unknown subjects, preserve matched-count
      and selectivity reporting, and elide retained matched-subject ids from
      optimizer JSON plus benchmark JSON/Markdown reports.
- Add lazy provider expansion:
  - Start each sweep from minimal client inventory, such as process subject ids
    and cheap identity fields.
  - Request additional facts only for candidate subjects that survive earlier
    predicate nodes.
    - [x] POC: derive post-DAG provider requests from per-rule candidate sets
      without changing exact-VM execution.
  - Batch requests by provider route across surviving subjects.
    - [x] POC: batch non-cheap required facts by route/key/type across all rules
      that still have surviving candidate subjects.
  - Avoid requesting expensive arrays, memory-region lists, PE imports/exports,
    signer data, handle counts, or pattern scans for eliminated subjects.
    - [x] POC: report avoided expensive fact requests for eliminated subjects in
      JSON/Markdown benchmark output.
    - [x] POC: add an `empty_process_name_expensive_pe` benchmark scenario that
      proves fully eliminated branches produce zero lazy expensive fact requests.
  - Keep provider request types generic; clients return typed facts or generic
    candidate sets, never rule decisions.
    - [x] POC: model provider-scope subject-set output as an offline
      candidate-provider result that the server combines with the predicate DAG,
      never as a rule result.
- Add generic client-side candidate providers where useful:
  - Support provider routes that return generic subject sets, such as processes
    with valid base image PE headers, processes grouped by image name, processes
    with readable image bytes, or processes with coarse architecture/session
    traits.
    - [x] POC: derive a generic `process.inventory.by_image_name` candidate
      provider request from shared `process.name == <literal>` predicates.
  - Ensure candidate providers are optional optimizations; the server must be
    able to fall back to per-subject facts and server-side candidate-set
    construction.
    - [x] POC: when a candidate provider result is unavailable, fall back to the
      server-side per-subject predicate simulation using cached facts.
  - Do not expose exact rule names, full condition branches, private strings, or
    pattern literals through these routes unless that data is already part of a
    normal provider request by design.
    - [x] POC: candidate-provider request reports expose only route, filter key,
      and argument, not owning rule identifiers.
  - Treat broad candidate provider output as a signal to continue narrowing on
    the server rather than as a failure.
    - [x] POC: feed candidate-provider subject sets into the same server-owned
      DAG and lazy provider expansion reports, preserving exact-VM final
      evaluation.
    - [x] POC: count available broad candidate-provider results that cover the
      whole evaluated subject set in optimizer sweeps, JSON/Markdown benchmark
      reports, and localhost optimizer-plan instrumentation while still running
      exact VM for every surviving rule/subject pair.
- Add discovery gates for rule packs and expensive rule families:
  - Let the compiler derive cheap pack-level gates from predicates that are
    shared by many rules, such as required modules, process-kind constraints,
    architecture/session constraints, base-image PE validity, or known provider
    capability requirements.
    - [x] POC: derive an offline discovery-gate plan for canonical predicates
      that are prune-safe and shared by every reportable rule in a pack.
  - Run discovery gates before building full per-process candidate sets for a
    rule pack; skip the pack when its gates prove that no rule in it can match
    the current client inventory.
    - [x] POC: add `discovery_gate_empty_pack` benchmark coverage where a
      shared cheap process-name gate rejects every subject, emits trace events,
      and reports a pack skip in JSON/Markdown without changing baseline exact
      VM execution.
  - Keep discovery gates server-owned and source-linked. They are optimizer
    predicates, not client-owned rule decisions.
    - [x] POC: discovery-gate simulation preserves unknown subjects by refusing
      to skip a pack when any gate input is missing or diagnostic.
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
    - [x] POC: add benchmark/report counters for candidate-provider requests,
      returned candidate subjects, broad results, and fallback predicate
      evaluations.
  - Keep the client limited to inventory and fact production; the server still
    combines provider-scope filter output with the rule predicate DAG and exact
    VM.
    - [x] POC: the plan-driven `OptimizerPlan` sweep consumes generic
      candidate-provider subject sets as predicate inputs, but exact VM still
      produces the final results for surviving rule/subject pairs.
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
    - [x] POC: add v1 protocol messages for generic candidate-provider
      route/filter/argument requests and status-bearing subject-set responses
      with diagnostics and TTLs, plus an optimizer bridge that consumes protocol
      subject-set responses without introducing rule identifiers into the wire
      shape.
    - [x] POC: localhost client sessions can now advertise a generic
      candidate-provider filter and round-trip status-bearing subject-set
      responses through `serve_client_once` / `run_client_session` using an
      optional candidate-provider handler.
    - [x] POC: an opt-in localhost optimizer-plan evaluator requests advertised
      candidate-provider filters before exact VM, converts status-bearing
      subject sets into optimizer inputs, and materializes provider facts only
      for surviving exact-VM rule/subject pairs; when a filter is not
      advertised, it skips the candidate-provider frame and rebuilds candidates
      from ordinary server-requested facts.
    - [x] POC: client evaluation instrumentation now records candidate-provider
      request messages, requested filter count, returned subject ids, broad
      results, and unadvertised plan filters for the opt-in localhost
      optimizer-plan path.
  - Add a server-side fallback path that builds the same candidate sets from
    per-subject facts when a client does not advertise a candidate provider.
    - [x] POC: add a `candidate_provider_unavailable` benchmark scenario where
      the provider-scope filter is unavailable, the server rebuilds candidates
      from per-subject facts, and JSON/Markdown reports expose fallback
      predicate evaluations plus lazy expensive-fact avoidance.
    - [x] POC: the plan-driven `OptimizerPlan` sweep has regression coverage for
      unavailable candidate-provider results falling back to per-subject
      predicate facts before exact-VM final evaluation.
    - [x] POC: candidate-provider fallback emits an optimizer trace event with
      the generic filter key and provider diagnostic before rebuilding the same
      candidate set from server-side predicate facts.
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
    - [x] POC: `shared_process_name_expensive_pe` with
      `--simulate-candidate-provider`, `--simulate-optimizer-plan-prefilter`,
      and `--simulate-lazy-provider-expansion` reports one generic
      candidate-provider request, two returned candidate subjects, six avoided
      exact-VM rule executions, two avoided expensive `pe.imports` facts, zero
      result mismatches, and zero incomplete subjects in
      `build/codex-debug/reports/optimizer_plan_candidate_provider.{json,md}`.
    - [x] POC: `localhost optimizer plan uses candidate provider transport
      before exact VM` proves a live client candidate-provider subject set
      avoids one exact-VM rule execution and one provider fact key request for
      the eliminated subject while preserving final server-owned rule results.
- Add route and predicate watchdogs:
  - Track per-route and per-predicate elapsed time, bytes returned, subjects
    touched, candidate-set reduction, and diagnostic rate during each sweep.
    - [x] POC: add trace-only watchdog budget classification for shared
      predicate selectivity and lazy provider route request volume, with
      benchmark JSON/Markdown counters for evaluations, budget events,
      predicate events, and route events.
  - Put predicates or provider routes into a bounded cool-down when they exceed
    CPU, latency, payload-size, or low-selectivity budgets repeatedly.
  - During cool-down, either defer the expensive branch, request a cheaper
    substitute gate, or complete with a traceable budget diagnostic according to
    rule/policy settings.
    - [x] POC: add opt-in watchdog enforcement policy actions for deferred
      broad-predicate branches and timed-out oversized route batches, producing
      explicit `optimizer.watchdog` diagnostics while leaving trace-only mode as
      the default.
  - Never silently skip a rule because of budget pressure; final no-match,
    timeout, unavailable, or deferred states must be explicit.
  - Add adversarial tests for rules that force broad signer, memory, import, or
    scan work across most process subjects.
    - [x] POC: `production_scale_validation --simulate-watchdogs` reports a broad
      nonselective predicate budget event, while
      `mixed_process_name_expensive_pe --simulate-watchdogs` reports an oversized
      PE-import route budget event, without changing exact-VM results.
    - [x] POC: `production_scale_validation --simulate-watchdog-enforcement`
      reports one explicit deferred-branch diagnostic for the broad predicate,
      and `mixed_process_name_expensive_pe --simulate-watchdog-enforcement`
      reports one explicit timeout diagnostic for the oversized `pe.imports`
      route batch in `build/codex-debug/reports/watchdog_enforcement_*.{json,md}`.
- Add content-addressed fact caches where safe:
  - Cache static image facts by stable file identity rather than only process
    subject id when the provider can verify that the underlying file content has
    not changed.
    - [x] POC: offline content-addressed static fact cache simulation reuses
      static image facts across subjects when path, file id, size, timestamp,
      hash, signature identity, and scan-space version match while keeping
      volatile process facts subject-scoped.
    - [x] Add a reusable server-owned `StaticFactCache` primitive that stores
      content-addressed static facts by route/key plus verified file identity,
      rewrites reused facts to the requesting subject id, rejects changed
      identities with invalidation trace events, and refuses volatile
      process-inventory facts.
    - [x] POC: opt-in localhost optimizer-plan evaluation can use caller-supplied
      static fact cache candidates to avoid repeated static provider fact
      requests across subjects with identical verified file identity, while
      replay captures the same static-cache trace events.
    - [x] POC: derive static fact cache candidates from server-owned identity
      facts in `FactCache`, emitting candidates only for static cacheable
      provider requirements and subjects with complete available file identity
      observations.
    - [x] POC: opt-in localhost optimizer-plan evaluation can derive runtime
      static cache candidates from a supplied server-owned identity fact
      snapshot, avoiding manual candidate construction while preserving replay
      parity.
    - [x] POC: opt-in localhost optimizer-plan evaluation can prefetch static
      identity facts from a configured provider route, derive static cache
      candidates from that typed response, and count the prefetch as ordinary
      provider work.
    - [x] Promote production PE image identity facts through the default
      descriptors and Windows PE provider: `pe.identity.path`,
      `pe.identity.file_id`, `pe.identity.file_size`,
      `pe.identity.last_write_time`, `pe.identity.scan_space_name`, and
      `pe.identity.scan_space_version` are typed `endpoint.process.image.pe`
      facts backed by Win32 file identity metadata, and optimizer-plan identity
      prefetch defaults to those keys without demo key mapping.
    - [x] POC: live localhost optimizer-plan evaluation can prefetch production
      PE identity facts from `endpoint.process.image.pe`, reuse a static PE
      header fact across two distinct processes mapping the same image, and
      report the avoided provider fact key through runtime instrumentation and
      server JSON/text output.
  - Candidate cache keys include path or file id, size, timestamps, content hash
    when already available, signature/catalog identity, and scan-space version.
  - Reuse PE header, import/export/resource/debug/certificate, signer/catalog,
    and hash facts across multiple processes that map the same unchanged image.
    - [x] Add bounded v1 fact value encoding for bytes, arrays, and objects so
      rich PE object-array facts can be transported by the localhost fact-batch
      codec; protocol regressions cover nested array/object values and
      oversized count rejection.
    - [x] POC: live localhost optimizer-plan evaluation can prefetch production
      PE identity facts from `endpoint.process.image.pe`, transport real
      `pe.imports` object-array facts, reuse them across two distinct processes
      mapping the same image, and report one avoided provider fact key with
      replay parity intact.
    - [x] Add separate live localhost reuse regressions for `pe.exports`,
      `pe.resources`, `pe.debug_entries`, `pe.certificates`, and
      `pe.tls_callbacks`; each regression prefetches production PE identity
      facts, transports the live array fact through the localhost protocol,
      reuses it for a second process mapping the same image, reports one avoided
      provider fact key, and preserves replay parity.
  - Keep volatile process facts, command lines, handles, tokens, parent/child
    relationships, and live memory facts subject-scoped.
  - Add invalidation and trace entries whenever a reused static fact is accepted
    or rejected because its file identity changed.
    - [x] POC: `production_scale_validation --simulate-static-fact-cache`
      reports 20 static lookups, 18 accepted reuses, 2 misses, 1 invalidation,
      20 subject-scoped volatile facts, and accepted/rejected reuse trace events.
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
    - [x] POC: shared-DAG simulation emits machine-readable optimizer trace
      events for static predicate ordering and rule-subject pruning, including
      canonical predicate ids, source spans, reasons, candidate subject counts,
      and candidate-set bytes; benchmark JSON/Markdown reports include an
      optimizer trace-event count.
    - [x] POC: benchmark JSON/Markdown reports now include bounded optimizer
      trace records with event, predicate id, rule, subject, reason, cost class,
      source span, and candidate-set counters for debugging opt-in optimizer
      runs without stabilizing the trace format as a public API.
  - Explain when a rule was not run by the exact VM because an earlier shared
    predicate made it impossible.
    - [x] POC: prefiltered evaluation emits exact-VM skip trace events for
      pruned rule/subject pairs, including rule id, subject id, predicate id,
      source span, prune reason, candidate count, and candidate-set bytes;
      benchmark JSON/Markdown reports count the emitted skip events.
  - Explain when a broad predicate was evaluated but retained too many subjects
    to be useful for pruning.
    - [x] POC: nonselective predicate trace events explain when a predicate
      matched every subject and retained matched-subject ids were elided.
  - Keep trace output machine-readable and readable enough to debug rule
    authorship and optimizer decisions.
    - [x] POC: localhost optimizer-plan instrumentation reports both
      provider-fact batches and candidate-provider frames, including skipped
      unadvertised candidate filters, so runtime optimizer runs can explain why
      candidate-provider fallback happened.
    - [x] POC: candidate-provider fallback trace records appear in optimizer
      JSON/Markdown reports, including the provider diagnostic, without exposing
      rule identifiers in the provider request shape.
    - [x] POC: opt-in localhost optimizer-plan sessions now expose the ordinary
      fact snapshot plus candidate-provider results needed to replay the same
      server-owned optimized sweep offline without live providers.
    - [x] POC: `replay_optimized_client_evaluation` reconstructs an optimized
      client sweep from the captured evaluated subjects, fact snapshot, and
      candidate-provider results, avoiding test-only replay wiring while keeping
      durable optimizer trace/schema stabilization future work.
    - [x] POC: `replay_optimized_client_evaluation_with_parity_report` compares
      captured and replayed optimized sweeps for subject, rule-result,
      optimizer-trace, and metric drift so localhost replay regressions are
      machine-checkable before trace artifacts are stabilized.
    - [x] POC: optimizer-plan benchmark JSON/Markdown reports now include replay
      parity counters for subject, rule-result, optimizer-trace, and metric
      drift, including runs shaped by generic candidate-provider results.
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
  - [x] POC: `production_scale_validation --simulate-scheduler-controls` adds a
    stress-tier scheduler report for 10,000 jittered clients over a five-minute
    window, peak wake batch, VM/provider queue peaks, backpressure events,
    deadline misses, and compact idle-state bytes without changing runtime
    scheduling behavior.
  - [x] POC: add a production-side evaluation scheduler primitive for
    deterministic per-client timer jitter, compact idle state, due-client
    admission, active-sweep limits, deferred-client counts, and deadline-miss
    metrics; the scheduler benchmark simulation now uses the same jittered idle
    state instead of a separate even-bucket approximation.
  - [x] POC: localhost client evaluation now records opt-in runtime VM subject
    queue peaks, provider request queue peaks, and threshold-crossing
    backpressure events for ordinary and optimizer-plan sessions without
    changing final rule results or provider request ordering.
  - [x] POC: `rule_engine_server --json` now emits runtime evaluation
    instrumentation for VM/provider queue peaks, provider request work, elapsed
    provider time, and backpressure events, with CLI thresholds for VM subject
    and provider request pressure.
  - [x] POC: localhost provider service now supports an explicit
    `max_session_workers` / `--session-workers` bound so multiple sessions can be
    served concurrently while listener admission remains capped.
- Add production-scale test fixtures:
  - Generate synthetic rule packs with shared first predicates, mixed predicate
    ordering, broad filters, expensive scan leaves, and complex exact-VM-only
    leaves.
    - [x] POC: add a `mixed_process_name_expensive_pe` benchmark scenario that
      alternates cheap-first, expensive-first, and `with` exact-VM-only branches
      while sharing the same process-name predicate and PE-import leaf.
  - Generate synthetic client inventories with many processes and controlled
    selectivity distributions.
    - [x] POC: add a scalable `production_scale_validation` benchmark scenario
      with unit-tier counts by default, acceptance target metadata for 1-16
      clients, 1,000 subjects/client, and 10,000 rules/pack, plus controlled 10%
      selectivity.
  - Test that optimized evaluation requests fewer facts and performs fewer
    expression evaluations than the baseline on selective packs.
    - [x] POC: `production_scale_validation --simulate-optimization-comparison`
      reports 108 avoided exact-VM rule executions, 18 avoided expensive
      provider fact opportunities, 560 avoided expression evaluations, and zero
      result mismatches or incomplete subjects.
  - Test that broad-rule packs still complete correctly and do not retain
    unbounded candidate-set state.
    - [x] POC: `production_scale_validation` mixes selective shared predicates,
      broad nonselective filters, expensive PE-import leaves, and exact-VM-only
      `with` leaves while reporting bounded peak candidate-set subjects/bytes.
    - [x] POC: the optimization comparison report records one broad nonselective
      predicate, peak candidate state bounded to 20 subjects / 3 bytes, and
      `comparisonBroadWorkloadBounded = 1`.
  - Test that optimized and unoptimized modes produce identical final rule
    results and diagnostics for the same inputs.
    - [x] POC: `production_scale_validation` report generation with
      `--simulate-prefiltered-evaluation` records zero result mismatches and zero
      incomplete subjects after preserving expensive-first diagnostic branches.
    - [x] POC: `--simulate-optimization-comparison` emits the same zero-mismatch
      and zero-incomplete parity counters alongside the reduction metrics in
      `build/codex-debug/reports/optimization_comparison.{json,md}`.
    - [x] POC: `--simulate-optimization-comparison` also includes the
      `OptimizerPlan` sweep and replay parity counters, so the production-scale
      comparison report covers subject, rule-result, optimizer-trace, and metric
      replay drift in the same artifact as the reduction metrics.
    - [x] POC: `--simulate-optimizer-plan-prefilter` emits the same
      zero-mismatch and zero-incomplete parity counters for the production
      `OptimizerPlan` sweep path in
      `build/codex-debug/reports/optimizer_plan_prefilter.{json,md}`.
    - [x] POC: the combined `OptimizerPlan` plus candidate-provider benchmark
      emits zero result mismatches and zero incomplete subjects while preserving
      exact-VM final evaluation for surviving candidate subjects.
- [x] Resolve open optimizer design questions before production work:
  - [x] Define the target benchmark scale for a first pass, including client count,
    subjects per client, rules per pack, provider-latency assumptions, and
    acceptable memory per active client sweep.
  - [x] Decide the primary success metric for each optimization phase: wall-clock
    time, provider round reduction, expensive fact reduction, VM expression
    reduction, memory stability, or scheduler smoothness.
  - [x] Define the stable benchmark/report artifact schema before using reports as
    acceptance evidence.
  - [x] Define candidate-provider protocol shapes and capability advertisement
    without exposing rule names, private strings, hidden branches, or exact
    pattern intent.
  - [x] Define watchdog policy outcomes for budget pressure: defer, substitute
    cheaper gates, timeout, unavailable, or explicit budget diagnostic.
  - [x] Define content-addressed cache invalidation requirements before reusing
    static PE, signer, hash, certificate, resource, scan-space, or image-byte
    facts across subjects or sweeps.
  - [x] Define which optimization traces are developer-only and which, if any, are
    suitable for user-facing reports before stabilizing trace artifacts.
  - [x] Decisions are captured in `docs/OPTIMIZATION_ARCHITECTURE.md`.

## Client And Server Runtime

- [x] Support multi-session client service mode instead of only one-shot localhost
  smoke sessions.
- [x] Add graceful shutdown and cancellation paths for long-running provider requests.
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
