# VM Optimization Architecture

This document closes the production design gates for the VM optimization
roadmap. It is intentionally conservative: optimized paths may prune impossible
work, reorder semantically safe predicates, and reduce provider requests, but the
exact VM remains the final rule evaluator for every surviving rule and subject.

## Trust Boundary

- C++ owns parsing, semantic validation, canonical predicate extraction,
  scheduling, optimization, diagnostics, traces, and final match decisions.
- Clients enumerate subjects and return typed facts, structured diagnostics, or
  generic provider-scope subject sets.
- Clients never receive rule identifiers, private rule state, hidden condition
  branches, or exact pattern intent unless that data is already part of a normal
  provider request by design.
- Candidate providers are optional accelerators. If a client does not advertise a
  candidate-provider route, the server builds the same candidate sets from
  per-subject facts.

## Target Benchmark Scale

Benchmarks use three tiers so CI stays fast while local runs still model the
target architecture.

| Tier | Purpose | Clients | Subjects per client | Rules per pack | CTest |
| --- | --- | ---: | ---: | ---: | --- |
| `unit` | deterministic regression coverage | 1 | 4-64 | 3-256 | yes |
| `acceptance` | local performance acceptance | 1-16 | 1,000 | 10,000 | opt-in |
| `stress` | scheduler and memory envelope checks | 10,000 simulated | 100-500 | 1,000-10,000 | no |

Every optimization phase must report at least one selective workload and one
broad/adversarial workload. Selective workloads include shared predicates such as
`process.name == "powershell.exe"` with configurable selectivity. Broad
workloads include common process names, broad `pe.is_valid` filters, and rules
whose cheap filters all pass.

## Success Metrics

Each phase chooses one primary metric and records secondary metrics for
explanation. Any semantic mismatch, diagnostic mismatch, trace replay regression,
or changed timeout/unavailable/access-denied behavior fails the phase regardless
of speed.

| Phase | Primary metric | Initial acceptance target |
| --- | --- | --- |
| Shared predicate DAG | exact-VM rule executions | reduce by at least 80% on 10% selective shared-predicate packs |
| Lazy provider expansion | expensive facts requested | reduce by at least 80% on selective cheap-filter plus expensive-leaf packs |
| Candidate providers | server predicate evaluations before exact VM | reduce fallback predicate work when provider results are available, with identical fallback output when unavailable |
| Adaptive candidate sets | peak candidate-state memory | stay bounded by active sweep subject and rule counts, with no persistent all-process metadata cache |
| Watchdogs | explicit budget outcomes | every enforced budget produces traceable timeout, unavailable, deferred, or substituted-gate diagnostics |
| Scheduler | client wake smoothing and queue stability | avoid synchronized evaluation spikes under the stress tier and report queue/deadline metrics |

Broad/adversarial workloads must not regress final results or diagnostics and
should not exceed baseline sweep time by more than 10% once an optimization phase
is no longer POC-only.

## Report And Trace Schemas

- Benchmark artifacts remain versioned with a machine-readable schema string.
- Schema changes are additive within a version. Breaking changes require a new
  schema name.
- Debug IR artifacts identify `rule-engine-debug-ir.v1`; schedule artifacts
  identify `rule-engine-schedule.v1`; evaluation trace artifacts identify
  `rule-engine-evaluation-trace.v1`.
- Reports must include seed, subject count, rule count, selectivity description,
  provider latency model, build type, enabled optimizer flags, and all counters
  needed to explain the optimization result.
- Optimizer traces are developer/operator artifacts, not stable public API.
- Optimizer traces include canonical predicate ids, source spans, prune-safe
  owners, cost class, selected predicate order, candidate-set sizes, requested
  fact batches, provider-scope filter requests, prune reasons, unknown/diagnostic
  reasons, and exact-VM fallback reasons.
- Trace replay snapshots the verified program inputs and fact responses needed to
  reproduce final VM decisions without live providers.
- Optimized replay also snapshots provider-scope candidate results when those
  results shaped candidate sets before exact VM.
- Localhost optimized client session replay is currently a helper-level POC:
  `replay_optimized_client_evaluation` consumes captured evaluated subjects,
  facts, and candidate-provider results. The parity-report helper reruns that
  snapshot and counts subject, rule-result, optimizer-trace, and metric drift,
  but does not make optimizer trace artifacts a stable public API.
- Optimizer-plan benchmark reports emit the same replay parity counters for
  synthetic fact snapshots and captured candidate-provider results, so report
  artifacts can fail closed on replay drift before trace schemas are stabilized.

## Candidate-Provider Protocol Shape

Candidate providers are advertised during the client handshake as generic
capabilities:

```text
route = endpoint.process.inventory
filter = process.inventory.by_image_name
argument_types = [string]
result = subject_set
ttl = descriptor-owned
diagnostics = structured per request
```

The server may request a provider-scope subject set when a canonical predicate
maps to an advertised generic filter. Requests contain route, filter key,
argument kind, and argument value. They do not contain owning rule identifiers,
full condition branches, private strings, or exact pattern literals.

Provider results contain the request id, subject ids, status, diagnostic text,
and TTL. `unavailable`, `timeout`, `access_denied`, or unsupported filters
trigger the server-side fallback path and emit a trace event with the generic
filter key plus provider diagnostic. Broad result sets are accepted as a signal
to continue narrowing on the server, not as a failure, and reports count broad
results that cover the whole evaluated subject set.

The opt-in localhost optimizer-plan path requests advertised provider-scope
filters before exact VM, feeds returned subject sets into the C++ optimizer, and
then requests ordinary provider facts only for exact-VM rule/subject pairs that
survive pruning. Final rule results still come from server-owned exact VM
evaluation or synthesized server-owned no-match results for pruned pairs.

## Watchdog Policy

The first watchdog implementation is trace-only. It records per-route and
per-predicate elapsed time, bytes returned, subjects touched, candidate-set
reduction, diagnostic rate, and budget classification.

Enforcement becomes opt-in after trace-only coverage is stable. Allowed outcomes
are:

- continue normally when the budget is healthy;
- request a cheaper generic gate when one is available;
- defer a branch with an explicit deferred diagnostic when policy allows delayed
  completion;
- complete the affected branch with timeout or unavailable diagnostics when a
  deadline or route budget is exceeded.

The optimizer must never silently skip a rule because of budget pressure.

## Content-Addressed Static Fact Caching

Content-addressed caching applies only to static image facts when the provider can
validate file identity. Candidate cache keys include path or file id, file size,
last-write timestamp, optional content hash when already available,
signature/catalog identity when relevant, scan-space name, and scan-space
version.

Reusable facts include PE header fields, imports, exports, resources, debug
entries, certificates, signer/catalog results, hashes, and file-backed scan-space
bytes. Volatile process facts remain subject-scoped: command lines, handles,
tokens, parent/child relationships, loaded modules, and live memory facts are not
shared across subjects unless a later design proves they are static.

Every cache reuse, rejection, and invalidation emits a trace entry.

The production cache primitive is server-owned and identity-first:
`StaticFactCache` accepts only content-addressable static fact candidates from
static image, broad image array, signer/catalog, or pattern scan cost classes.
It keys entries by route, fact key, path, scan space, and verified file identity,
returns reused facts with the requesting subject id, invalidates stale entries
when identity fields change, and leaves volatile process inventory facts
subject-scoped.

The optimizer can also derive static fact cache candidates from server-owned
identity facts already present in `FactCache`. Derivation requires available
path, file-id, file-size, and last-write facts, carries optional hash,
signature/catalog, and scan-space identity facts when present, and emits
candidates only for static cacheable optimizer-plan provider requirements.
Incomplete, unavailable, or wrong-typed identity observations leave the fact
subject-scoped until the provider refreshes identity.

The opt-in localhost optimizer-plan evaluator can consume explicit static fact
cache candidates, derive them from a supplied server-owned identity fact
snapshot, or prefetch identity facts from a configured provider route before
provider materialization. Identity prefetch uses the normal fact-batch protocol,
capability checks, typed response validation, and provider work counters. Cache
hits are stored in the per-subject fact cache before provider requests are sent,
misses and invalidations continue through the ordinary provider path, and
provider responses refresh the static cache. Runtime static-cache trace events
are captured with the optimized session so replay parity can include those
events without live providers.

The production Windows PE provider now exposes the default cache-identity facts
as typed `endpoint.process.image.pe` facts: `pe.identity.path`,
`pe.identity.file_id`, `pe.identity.file_size`, `pe.identity.last_write_time`,
`pe.identity.scan_space_name`, and `pe.identity.scan_space_version`. These are
backed by Win32 file metadata and the optimizer-plan evaluator defaults to those
keys when an identity route is configured. Content hashes and signer/catalog
identity remain optional cache-key inputs until a provider can verify and return
them directly.

Runtime instrumentation reports both static-cache reuse events and the concrete
number of provider fact keys avoided by accepted static-cache hits. The live
localhost validation currently proves this path for PE header facts plus
`pe.imports`, `pe.exports`, `pe.resources`, `pe.debug_entries`,
`pe.certificates`, and `pe.tls_callbacks` array facts transported over the v1
protocol. The fact-batch codec now carries bytes, bounded arrays, and bounded
objects, including nested values, so the transport no longer blocks rich PE fact
reuse. Provider fixture tests remain the non-empty object-payload coverage for PE
directories that are often empty on ordinary executable process images.

## Scheduler Controls

Scheduler controls start as observable runtime pressure signals before enforcing
work deferral. The localhost evaluator records peak pending VM subjects and peak
pending provider request batches, plus threshold-crossing backpressure events,
for ordinary and optimizer-plan sessions. These counters must remain diagnostic:
they cannot suppress provider requests, skip exact-VM execution, or change final
rule results without a later explicit policy gate and parity tests.

Evaluation timer admission uses deterministic server-owned jitter keyed by a
stable client id hash. The per-client idle state is fixed-size and stores only
the hash, next due time, deadline, and sequence counter. Admission reports count
tracked clients, due clients, admitted clients, deferred clients, active sweeps,
deadline misses, and idle-state bytes. These reports are scheduler diagnostics;
they do not allow clients to decide rule matches or predicate outcomes.

Runtime rule-evaluation reports include the same queue-pressure surface used by
the localhost evaluator: peak pending VM subjects, peak pending provider
requests, provider work counters, elapsed provider time, candidate-provider
counters, static fact cache counters, and threshold-crossing backpressure events.
Thresholds classify pressure for reports; they do not suppress work or alter
exact-VM final results.

Provider retry and cancellation policy is descriptor-owned. Descriptors can opt
into bounded retries for `timed_out` provider facts; the server retries those
facts by withholding the transient diagnostic from the fact cache until the retry
budget is spent. When evaluator shutdown is requested before provider dispatch,
the server synthesizes unavailable facts with descriptor cancellation
diagnostics and lets the exact VM produce the final no-match diagnostics.
Clients still only return typed facts or provider diagnostics.

Localhost provider serving keeps the serial one-session default, but can opt into
a bounded session worker limit. This separates accepted session handling from
listener admission without creating unbounded per-client threads: once the worker
limit is reached, the listener waits for a worker to finish before accepting more
sessions.

Graceful shutdown is opt-in through a listener stop token. The accept loop polls
that token while idle, active sessions return unavailable cancellation
diagnostics instead of dispatching new provider work after shutdown, and
context-aware custom provider handlers receive the same token for cooperative
in-flight cancellation. The command-line client wires console interrupts into
this path.

## Production Data Flow

1. The compiler verifies the rule pack and extracts canonical predicates.
2. The optimizer builds an opt-in `OptimizerPlan` with predicate nodes, owners,
   cost classes, safe ordering, exact-VM fallback continuations, and provider
   requirements.
3. A client sweep starts from the subject inventory and cheap identity facts.
4. Candidate-provider filters run when advertised and safe. Otherwise the server
   evaluates the equivalent predicate nodes from cached or requested facts.
5. Shared predicate nodes update adaptive candidate sets.
6. Lazy expansion requests additional facts only for surviving candidates and
   unknown subjects that must remain exact-VM candidates.
7. The exact VM evaluates every surviving rule and subject with the same fact
   responses used by the optimizer.
8. Reports and traces compare optimized prefilter work with baseline exact-VM
   behavior.

## Rollout Order

1. Add production-scale benchmark scenarios and differential fixture generation.
2. Add descriptor cost classes and selectivity observation to reports and traces.
3. Introduce `OptimizerPlan` as an opt-in compiler artifact.
4. Add adaptive candidate-set containers and shared-DAG execution behind an
   opt-in evaluator path.
5. Add lazy provider expansion to the opt-in path.
6. Add protocol-aware candidate providers and fallback equivalence tests.
7. Add optimizer trace artifacts and replay checks.
8. Add watchdog trace mode, then opt-in enforcement.
9. Add content-addressed static fact caching with invalidation traces.
10. Add scheduler jitter, backpressure, queue metrics, and stress-tier reports.

## Acceptance Gate

The architecture is fully working when optimized and unoptimized modes produce
identical final rule results, diagnostics, and replay-compatible fact snapshots
for the same verified programs and fact responses. Optimized paths must show
measured reductions in provider work, exact-VM executions, expression
evaluations, or bounded candidate-state memory on selective workloads, while
broad/adversarial workloads remain correct and bounded.
The production-scale comparison report is the default acceptance artifact for
this gate: it must include optimizer-plan parity, replay drift counters, and
work-reduction counters in both JSON and Markdown.
