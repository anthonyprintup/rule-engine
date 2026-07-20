# ADR-003: Use Python 3.14 Syntax as a Statically Compiled C++-Owned Language

- Status: accepted for `design-v1`
- Date: 2026-07-20
- Decision owners: integration and compiler lanes
- Implements: `C1`, `C2`, `C3`, `V1`–`V4`, `I2`
- Detailed design: [architecture/02-authoring-language-and-types.md](../architecture/02-authoring-language-and-types.md)
- Related limitations: [L-002, L-003, L-004, L-011, L-014, L-016, L-017](../LIMITATIONS.md)

## Context

The existing engine accepts YARA through a Rust/YARA-X parser bridge, then owns validation and execution in C++. The replacement needs a substantially richer, composable authoring language while retaining the repository's central trust boundary: the server determines rule semantics and clients return facts only.

The product requires Python-based syntax and accepts bundling Python when abuse and reliability are controlled. Full ordinary CPython execution, however, would make imports, platform behavior, memory, scheduling, exceptions, introspection, I/O, and side effects part of the semantic and security boundary. It would also prevent the C++ engine from proving provider requirements, suspending transparently on facts, applying deterministic replay, enforcing effect transactions, or safely optimizing observable behavior.

At the other extreme, a small Python-looking grammar or a new bespoke DSL would reduce implementation scope but create syntax/tooling drift, constrain future expressiveness, and require authors to learn which superficially Python expressions parse differently.

## Decision

Adopt the complete pinned CPython 3.14 grammar as the parse grammar and a closed, statically checked subset as the executable language.

- A private, short-lived CPython 3.14.6 worker performs only `ast.parse` for rule/model modules and serializes the complete AST.
- CPython never imports, compiles, or executes a rule/model module.
- The C++ compiler exclusively performs import resolution, binding, type checking, schema construction, semantic validation, HIR/CFG lowering, effect/fact analysis, optimization certification, and bytecode verification.
- The C++ resumable VM implements every accepted runtime semantic under engine budgets and explicit capabilities.
- Complete grammar coverage means valid Python either compiles under the documented subset or receives a source-precise `PY-UNSUPPORTED` diagnostic. It does not mean every Python construct executes.
- Public rules, templates, correlations, exported helpers, models, records, bindings, and distributed/persistent boundaries require explicit annotations. Private helpers and locals infer flow-sensitive types.
- Internal `Any` is permitted but must be narrowed and runtime-validated before crossing a trust/public boundary.
- Support the broad static features fixed in architecture 02: ordinary flow/mutation/closures/recursion, comprehensions, structural matching, exceptions/`finally`/exception groups, generators, structured async, static classes with C3 MRO, dataclasses, enums, selected dunders, scalar PEP 695 generics, Protocols, and overloads.
- Reject dynamic imports, ambient I/O/process/network/time/randomness, reflection, metaclasses, dynamic bases/classes, monkey-patching, arbitrary descriptors, mutable module globals, native extensions, and runtime code generation.
- Permit only pack-local modules, exact embedded dependency modules, `rule_engine`, and the versioned C++-modeled `stdlib.v1` catalog.
- Model Python `bool`, arbitrary-precision `int`, binary64 `float`, Unicode, containers, exceptions, and evaluation order in C++, with CPython differential tests. Reject complex, `Decimal`, and `Fraction` initially.
- Use explicit RE2 pattern APIs; do not emulate or alias Python `re`.
- Use static Python model classes and annotations as the source of provider and wire schemas. C++ canonical descriptors remain authoritative.

## Primary reasons

1. **C++ retains semantic ownership.** Every match, fault, provider read, capability, state mutation, effect, and optimization is visible to one verifier and VM.
2. **Transparent asynchronous facts become possible.** An ordinary property read can lower to `READ_FACT`, suspend the current continuation, and resume without rerunning Python code.
3. **Deterministic replay and transactional effects remain enforceable.** There is no ambient Python runtime state or unmodeled side effect outside the captured VM.
4. **Resource accounting is semantic rather than best effort.** Instructions, frames, heap, iteration, facts, services, history, state, effects, and cleanup are charged by the C++ runtime.
5. **Authors retain familiar syntax and tools.** Standard parsers, formatting, Pyright, PEP 561 stubs, and Python source lookup remain useful.
6. **Grammar diagnostics stay accurate.** Pinning CPython's parser avoids maintaining a divergent Python grammar, including new constructs and exact source spans.
7. **The accepted language can grow deliberately.** A valid-but-unsupported node is explicit technical debt with a stable diagnostic, not undefined behavior.
8. **Cross-platform compilation can be compared.** Static descriptors and semantic hashes exclude platform-local Python resolution and object behavior.

## Rejected alternatives

### Retain YARA or add Python beside YARA

Rejected because the requested result is a complete YARA removal. Dual frontends would preserve two type/pattern/diagnostic/optimization contracts, delay deletion of Rust/Cargo/cbindgen, and make rule behavior harder to reason about.

### Execute ordinary CPython modules in the server

Rejected because imports, native extensions, reflection, process-global state, the GIL, object lifetime, tracing, and ambient I/O would enter the production trust and semantic boundary. Hard budgets and deterministic suspension/replay would be unreliable.

### Evaluate rules in disposable Python subprocesses

Rejected as the primary runtime. Process isolation would protect the server better than in-process Python but would still delegate semantics and match decisions to Python, require RPC for every fact/effect, complicate nested suspension and transactional journals, and make fine-grained optimizer equivalence impractical.

### Translate accepted AST directly to CPython bytecode

Rejected because bytecode is a CPython implementation ABI, not a stable verified engine IR. It would retain Python frame/object semantics and prevent the engine from assigning explicit capability and budget operations.

### Implement a small Python-like parser

Rejected because it would drift from Python syntax, editor/parser behavior, error recovery, column accounting, and future grammar. Authors would encounter constructs accepted by tooling but parsed differently by the engine.

### Create a new non-Python declarative DSL

Rejected because the requested direction is Python and the required helpers, composition, exception handling, generators, correlations, and typed async workflows benefit from a general structured language.

### Make all Python syntax executable immediately

Rejected because metaprogramming, reflection, native libraries, and ambient APIs have no bounded deterministic C++ semantics. Parsing them and rejecting them precisely is safer than partial emulation.

### Infer every public type

Rejected because inferred distributed schemas and capabilities would change accidentally during refactors and would be harder to review. Explicit public annotations create stable contracts while local inference preserves ergonomics.

### Use Python `re`

Rejected because backtracking behavior conflicts with bounded scan execution. RE2 intentionally trades source compatibility for predictable resource use.

## Consequences

### Positive

- One typed semantic pipeline supports local execution, remote facts, effects, state, correlations, optimization, replay, and diagnostics.
- Rule source remains readable and benefits from ordinary Python editor tooling.
- Static models generate provider/service/event/state descriptors, documentation, and stubs from one source.
- Unsupported behavior fails during compilation/activation rather than at an arbitrary evaluation.
- The VM can preserve exact logical-read and effect order while allowing certified physical optimization.

### Negative

- Implementing Python-compatible values, classes, exceptions, generators, async behavior, Unicode, and a modeled library in C++ is a large engineering effort.
- Valid Python programs can fail with `PY-UNSUPPORTED` or resource-limit diagnostics.
- Authors must understand that the source is a static language, not an arbitrary Python environment.
- Pyright cannot express every engine label/effect/capability rule; the engine compiler remains a second required check.
- Pinned patch/Unicode changes require ABI and conformance updates.

## Operational and security implications

- Rule evaluation has no CPython interpreter, `sys.path`, site packages, native extension loader, filesystem, socket, subprocess, wall clock, or random source.
- All external behavior enters through typed injected capabilities and C++ runtime validation.
- Compiler and VM version, Python grammar/Unicode identity, stdlib descriptor, schema hashes, and semantic hashes are recorded at activation.
- A parser crash or limit violation is isolated by ADR-017 and fails pack staging rather than the resident server.
- Static analysis is not trusted as the only boundary check: provider, service, event, state, history, and effect values are validated and frozen at runtime.
- Data labels propagate through values and control dependencies; arbitrary Python casts cannot declassify.

## Known limitations introduced

- The complete grammar is parsed but only the documented subset executes.
- The modeled stdlib is deliberately incomplete and can lag CPython additions.
- No native Python extension, ambient package, metaclass, dynamic descriptor, or runtime reflection is available.
- `ParamSpec`, `TypeVarTuple`, t-strings, complex, `Decimal`, and `Fraction` are initially unsupported.
- RE2 differs intentionally from Python regular expressions.
- Compile and runtime limits reject some deep/large otherwise valid programs.
- Control-flow labeling may conservatively overclassify values.
- Cyclic VM values cannot cross canonical wire/persistence boundaries.
- Initial tooling uses generated stubs/Pyright/compiler diagnostics rather than a custom LSP.
- There is no automatic YARA translation path.

## Evidence and validation

The decision is validated by:

- a golden fixture for every CPython 3.14 AST node and every accepted/rejected construct;
- differential CPython 3.14 tests for all supported value and control-flow semantics;
- proof tests that parsing/import resolution never executes source or observes ambient packages;
- bytecode-verifier, value/heap, budget, exception, generator, async, label, and boundary fuzz/property tests;
- exact-versus-optimized observational parity;
- identical platform-independent semantic hashes on supported Windows and Linux builds;
- documentation/stub examples that pass Pyright and the C++ compiler.

Evidence is attached through `TRACEABILITY.md` to `C1`, `C2`, `C3`, `V1`–`V4`, `O1`, and `Q1`.

## Conditions for revisiting

Revisit an individual rejected construct only when it has:

1. an exact static type and runtime semantic specification;
2. a bounded VM representation and cost model;
3. defined fact/effect/state/service/history/label behavior;
4. deterministic replay and optimizer-observability rules;
5. cross-platform differential and negative tests;
6. no expansion of client authority.

Revisit CPython execution as a whole only if the product explicitly abandons C++ semantic ownership and accepts a new hostile-code/runtime isolation architecture. That would be a replacement architecture, not an incremental extension of this ADR.
