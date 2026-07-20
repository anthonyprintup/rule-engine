# ADR-014: Optimize Only Under Compiler-Proven Observational Equivalence

- Status: Accepted
- Date: 2026-07-20
- Owners: Compiler, optimizer, VM, effects, and integration lanes
- Related tasks: C3, E1-E2, O1-O2, I1, Q1
- Related architecture: [Compiler, IR, and VM](../architecture/04-compiler-ir-and-vm.md)

## Context

The engine can often determine a rule result or fact plan without interpreting every source operation. Template specialization, constant propagation, pure predicate lifting, fact batching, and scan planning are valuable for fleet scale.

However, rule evaluation is observable beyond its boolean verdict. Observable behavior includes:

- Python exceptions and fault ownership;
- which facts are logically read and which failures become visible;
- provider privacy and scheduling;
- ordered traces and full-flight-recorder events;
- state reads/writes and MVCC retries;
- posts, custom events, retention, captures, and nested effect transactions;
- service/history requests and captured replay inputs;
- child-rule reporting;
- data/control labels;
- semantic instruction, loop, allocation-work, fact, service, history, state, and effect budgets.

A verdict-only optimizer could therefore return the same bool while changing externally important behavior. Full-flight recording also makes branches and pure operations observable when armed.

The existing optimizer work is valuable and must be adapted rather than discarded, but the Python rewrite adds more observable dimensions than the previous YARA condition evaluator.

## Decision

Optimization is conservative and effect-aware. The exact verified bytecode remains the semantic oracle. A transformation is enabled only from compiler-issued, transitive OptimizationCertificate evidence and only when it preserves every observation required by the active invocation policy.

The optimizer may never trust an author assertion of purity.

### Certificate requirements

Certificates describe:

- deterministic/pure status;
- possible Python exceptions and hard control faults;
- ordered and conditional logical fact reads;
- state, service, history, post, event, retention, capture, transaction, and child-rule behavior;
- allocation, mutation, hashing, object-identity, and iteration-order sensitivity;
- data/control-label effects;
- generator, async, suspension, and cancellation points;
- recorder observations by policy;
- semantic charges for operations that may be eliminated or fused.

Recursive or unknown analysis is conservative.

### Permitted transformations

When proven safe, the optimizer may specialize immutable template arguments and generics, propagate constants/types, fold pure operations through the VM's semantic implementations, simplify unreachable pure control flow, eliminate redundant pure checks, allocate registers, fuse pure iteration, hoist pure parent-only discovery predicates, and create tentative provider-safe fact plans.

Removed/fused semantic operations retain synthetic charge metadata so modeled instruction and resource ceilings cannot be bypassed.

### Required exact execution

Exact execution is the default for any path whose observable behavior cannot be reproduced exactly, including effects, state, services, history, fault/cleanup behavior, mutable identity, child ownership, generators/tasks, dynamic trace publication, or full flight recording.

The presence of one such operation does not forbid optimization of an independently proven pure prefix or leaf, but it forbids skipping or reordering the observable operation.

### Fact prefetch

Physical prefetch remains tentative. It never enters the logical-read ledger, raises a rule-visible exception, consumes logical fact/round/retention budget, or produces a trace/recorder read until control reaches READ_FACT. An unvisited prefetched denial, timeout, or malformed response is invisible to rule semantics, though protocol-level abuse may still be audited outside the invocation trace.

### Runtime policy

Optimization selection uses the policy snapshot fixed at invocation start. If the recorder policy requires an event that a transformation would remove, the transformation is disabled unless an exactly equivalent synthetic event is certified. Dynamic code cannot retroactively arm an unarmed recorder.

### Shadow and replay

Shadow comparison reuses captured facts, services, history, timestamps, hash seed, scheduler decisions, and state snapshot. It compares verdict/fault, logical reads, ordered journal/state, child ownership, labels, recorder output, and all semantic resource counters.

The exact result is the only committable result during shadow comparison. A mismatch disables the optimized executable and records a bounded redacted diff.

Actual CPU and elapsed duration are operational metrics rather than reproducible language observations. They are reported and bounded, but not required to be numerically equal between exact and optimized execution.

## Primary reasons

### Verdict parity is insufficient

Rules can intentionally trace, retain, write state, emit events, or enqueue posts on either MATCH or NO_MATCH paths. Those operations and their order are part of the product contract.

### Facts have privacy and fault semantics

Reading a fact can expose sensitive data, consume provider work, or raise a typed error. Short-circuit behavior must decide logical reads; an optimizer cannot make every statically possible read visible.

### Recording changes observability

An optimization harmless under minimal recording can be incorrect under full flight recording. Policy-aware selection avoids treating recorder behavior as an afterthought.

### Exact fallback supports safe rollout

Keeping exact bytecode allows conservative deployment, captured-input shadowing, quick fallback, and diagnosis without reinterpreting source or relying on a different engine.

### Compiler evidence is auditable

A stable certificate makes optimization legality reviewable and testable. Author hints alone cannot express transitive exceptions, effects, or task behavior safely.

## Rejected alternatives

### Optimize only for boolean equivalence

Rejected because it can suppress faults, facts, traces, state, effects, and budget exhaustion while returning the same bool.

### Eagerly fetch every possible fact

Rejected because it violates Python short-circuit semantics, provider privacy, logical budgets, retention policy, and visible failure ordering.

### Permit speculation and roll back effects

Rejected. A provider read, service call, history query, trace, timing change, or exception can be externally visible even if state/effect journal writes are rolled back.

### Treat full recording as best effort

Rejected. When armed by policy, recorder content is an operational contract used for diagnosis and audit. Silent branch/call removal would make exact and optimized incidents incomparable.

### Disable all optimization

Rejected. Static template binding, pure predicate lifting, register simplification, fact planning, and scan planning provide material scale and latency benefits while still admitting proof and fallback.

### Require human purity annotations

Rejected. An annotation cannot safely account for transitive helper/class/model behavior or future edits. The compiler may accept performance hints only as requests; it independently proves them.

### Make optimized bytecode the only artifact

Rejected. Removing the oracle would weaken shadow validation, replay diagnosis, and failure recovery.

## Consequences

### Positive

- Optimized execution cannot silently alter intended effects or logical facts.
- Provider privacy follows source control flow.
- Exact and optimized behavior is testable over captured inputs.
- Full recording and debugging remain trustworthy.
- The existing optimizer can be reused behind stronger certificates.
- Unknown semantics fail toward correctness rather than speed.
- Optimization mismatches do not contaminate committed state or actions.

### Negative

- Many effectful or heavily recorded rules execute mostly exact bytecode.
- Certificates and synthetic charge maps add compiler complexity and executable metadata.
- Shadow mode can approximately double compute for sampled evaluations.
- Conservative recursion/alias analysis may miss safe opportunities.
- Optimization selection depends on runtime policy, increasing cache variants.
- Actual CPU-time outcomes near the hard limit can differ because optimization changes real work.

## Operational and security implications

- Fact-plan audit distinguishes physical prefetch from logical reads.
- Prefetched values use a tentative cache with label/privacy controls and bounded lifetime.
- Optimizer mismatch telemetry is redacted through the same data-label policy as traces.
- A mismatch disables only the affected executable/optimizer variant; the exact engine remains available.
- Optimizer/compiler pass versions and certificate hashes are part of executable identity.
- Pack activation compares platform-independent semantic hashes, while nodes may record platform packaging identity separately.
- Production sampling rates for shadow execution are operator policy and cannot authorize effects from the shadow run.

## Known limitations introduced

- Full recording and effectful paths reduce attainable optimization.
- Static alias/purity analysis is intentionally conservative.
- Synthetic semantic charges preserve modeled budgets but cannot reproduce actual CPU nanoseconds or host scheduling.
- Near an actual CPU/elapsed deadline, exact and optimized executions can differ operationally even when semantic counters agree.
- Fact prefetch may still consume provider resources for a path that is not reached; it remains invisible to rule semantics but is visible in provider operational metrics.
- Cross-platform libm performance/results may restrict floating-point constant folding to certified operations.

## Evidence and validation

The decision is validated by:

- property-based exact-versus-optimized tests over verdict, exception, logical reads, journal/state, child ownership, labels, recorder, and semantic counters;
- explicit tests for left-to-right and short-circuit fact failures;
- tests proving an unvisited prefetched timeout/denial is not visible or logically charged;
- effect order and transaction tests on MATCH and NO_MATCH paths;
- recorder-policy matrices covering off, balanced, and full recording;
- injected certificate/verifier inconsistencies that must fail activation;
- injected shadow mismatches that must commit only the exact result and disable optimization;
- replay tests using captured services/history/time/hash seed/scheduler;
- provider metrics distinguishing tentative physical requests from logical reads;
- benchmark reports showing exact and optimized paths separately.

## Revisit conditions

Add a new optimization only when:

1. its proof obligation names every observation it can change;
2. compiler certificates can establish that obligation transitively;
3. verifier/runtime metadata prevents use outside the proven conditions;
4. exact-versus-optimized property and fault-injection tests cover it;
5. it retains exact fallback and redacted mismatch evidence.

Revisit the operational-time limitation only by introducing a separate deterministic virtual-work profile. Such a profile cannot replace real CPU and elapsed deployment safety limits.

Remove exact bytecode only if a replacement oracle provides at least the same semantic coverage, replay, mismatch safety, and diagnostic fidelity. No current design satisfies that condition.
