# ADR-006: Typed Lazy Facts with Transparent VM Suspension

- **Status:** Accepted
- **Decision owners:** Compiler, VM, protocol, and provider lanes
- **Related tasks:** C2, C3, V2, P1, P3, O1
- **Architecture:** [Facts, Subjects, and Scanning](../architecture/05-facts-subjects-and-scanning.md)

## Context

Rules need data that may be expensive, privileged, remote, unavailable, or unnecessary because an earlier Python expression short-circuits. Authors should see a typed domain model rather than a transport API, while C++ must retain semantics and agents must remain fact-only providers. Asynchronous resolution must not restart a rule, duplicate effects, change Python evaluation order, or let optimizer prefetch reveal data/failures from an unvisited branch.

## Decision

Model descriptors distinguish eager enumeration fields from lazy fields declared with `provider_fact(...)`. The compiler lowers lazy property access to typed `READ_FACT` bytecode. When reached, the C++ VM records one logical attempt and either uses a captured/validated cached result or suspends with an exact continuation and typed `FactRequest`. A validated response resumes the same instruction and produces a value or typed fact exception.

Logical access is distinct from physical collection. Compiler-certified prefetch uses separate operational quotas; its results remain unobservable until a matching `READ_FACT` is reached. Unreached prefetch does not affect logical budgets, traces, retention, replay capture, faults, effects, state, or verdicts.

Provider terminals are typed (`not_found`, `unsupported`, `access_denied`, `timed_out`, `unavailable`, `canceled`, `malformed`). Protocol/schema violations fail closed and are separately attributed to the provider. Required capability absence fails atomic activation; optional typed capabilities are consistently absent rather than changing field meaning.

## Primary reasons

1. Ordinary typed property access keeps rule code readable and statically analyzable.
2. Demand resolution implements least-data collection and preserves short-circuit privacy.
3. Exact VM continuation avoids restarts and duplicated effects.
4. Typed terminals allow local Python handling without inventing sentinel values.
5. Separating logical and physical reads permits latency optimization without changing semantics.
6. C++ continues to own scheduling, validation, exceptions, budgets, replay, and verdicts.

## Rejected alternatives

- **Require authors to `await fact(...)`:** rejected because it exposes transport mechanics, complicates models, and makes batching an author concern.
- **Eagerly collect every declared field:** rejected because it increases privileged reads, latency, bandwidth, and failure surface on unvisited paths.
- **Return `None` or status unions:** rejected because missing, denied, timeout, and malformed facts have different semantics and could be accidentally treated as valid absence.
- **Restart evaluation after data arrives:** rejected because arbitrary effects, state, generators, exception state, and recorder history would be duplicated or require fragile reconstruction.
- **Expose prefetched failures immediately:** rejected because it violates Python control flow and makes optimization observable.
- **Let providers evaluate predicates:** rejected because it violates the fundamental C++ semantic trust boundary.

## Positive consequences

- Natural authoring syntax with precise static types and exceptions.
- Provider access occurs only when semantically demanded, except for separately bounded invisible prefetch.
- Requests can be coalesced/batched while logical consumers retain independent source and accounting.
- Replay can capture the exact result at each reached logical read.
- Optimizer equivalence can be tested against a well-defined logical-read ledger.

## Negative consequences

- VM frames and exception/journal state must survive arbitrary suspension.
- Coordinator caches need strict schema, subject-generation, label, and lifetime keys.
- Prefetch accounting and quarantine are more complex than a shared eager cache.
- Authors must deliberately catch typed fact exceptions when partial availability is expected.
- Conservative certificates can reduce prefetch opportunities.

## Operational and security implications

- Every request binds execution, peer/session/fence, exact subject, fact ID, route, schema hash, deadline, and cancellation.
- Provider values are untrusted until server-side schema, size, label, and request validation completes.
- Logical and physical provider metrics are separate so speculative work cannot hide operational cost.
- Sensitive values are never logged by default; trace/retention capture is governed by labels and policy.
- Late or duplicate responses cannot mutate a canceled/completed session.

## Known limitations

- Demand access introduces suspension latency; safe prefetch is deliberately conservative.
- Provider caches cannot outlive their descriptor-declared subject generation or source validity.
- Valid provider failures can fault a rule unless the author handles their typed exceptions.
- Fact resolution is not an instantaneous snapshot of the operating system; replay guarantees captured engine inputs, not historical OS state.
- See L-006 and L-010 in [LIMITATIONS.md](../LIMITATIONS.md).

## Evidence and tests

- Left-to-right and short-circuit differential tests.
- Cache, coalescing, batching, cancellation, timeout, terminal-status, and protocol-fault tests.
- Exact-PC resume tests around loops, generators, try/finally, child rules, state, and effects.
- Proof tests that unreached prefetch is absent from all logical observables and adoption matches demand behavior.
- Exact-versus-optimized parity over verdict, facts, journal, state, trace, budgets, and faults.
- Codec fuzzing and schema/type/size mismatch tests before `FactValue` creation.

## Revisit conditions

Revisit only if production evidence shows fact latency cannot be met by certified prefetch/batching, or if a new provider consistency requirement demands multi-fact snapshot semantics. Any change must retain property syntax, C++ semantic ownership, least-data behavior, typed failures, replayability, and observational parity.

