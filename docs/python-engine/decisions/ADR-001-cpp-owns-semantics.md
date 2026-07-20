# ADR-001: C++ Owns Rule Semantics and Match Decisions

- Status: Accepted
- Date: 2026-07-20
- Owners: Integration, compiler, VM, protocol, and provider lanes
- Related tasks: F0, C1-C3, V1-V4, P1-P3, I1
- Related architecture: [Compiler, IR, and VM](../architecture/04-compiler-ir-and-vm.md)

## Context

The engine accepts Python 3.14 syntax, resolves typed facts from remote Windows agents, calls bounded operator capabilities, and produces verdicts, state transitions, and effects. The design therefore needs one authority for:

- name binding and supported-language semantics;
- model and fact typing;
- evaluation order and short-circuit behavior;
- exception, generator, async, and class behavior;
- resource accounting and cancellation;
- data labels and boundary validation;
- rule verdicts and fault disposition;
- optimization legality and replay.

The current project goal already establishes that clients are fact providers rather than evaluators. Moving to Python syntax must not accidentally transfer authority to CPython, generators, agents, services, or storage adapters.

## Decision

C++ is the sole semantic authority after the short-lived CPython parser worker has returned syntax.

Specifically:

- CPython parse mode only converts source into a versioned AST envelope. It does not import, bind, type-check, compile, or execute rule modules.
- Generator mode may execute trusted Python to emit typed binding data, but C++ validates every emitted template ID, argument, type, schema, and stable binding ID. Generator code cannot define evaluation semantics.
- The C++ compiler owns module resolution, lexical binding, type checking, model/schema construction, HIR, CFG, bytecode, effect analysis, and diagnostics.
- The C++ VM owns values, classes, calls, exceptions, control flow, generators, async scheduling, facts, capabilities, state, effects, labels, budgets, fault behavior, and MATCH/NO_MATCH/FAULTED decisions.
- Agents receive typed enumeration/fact/scan requests and return typed values, terminal statuses, matches, removals, or diagnostics. They never receive a predicate, rule body, optimizer decision, or authority to determine a match.
- External services return typed data only. Storage commits validated engine decisions but does not reinterpret them.
- The optimizer may transform only compiler-owned IR under compiler-issued proof obligations; it cannot trust an author annotation or provider claim of purity.

This invariant applies to Windows and Linux server builds, exact and optimized execution, online execution and replay, development and production modes.

## Primary reasons

### One testable language

One C++ semantic implementation can be differentially tested against pinned CPython for the supported subset. Splitting semantics between CPython, C++, agents, and services would create ordering and edge-case disagreement that cannot be resolved by types alone.

### Safe suspension

The engine must stop at a fact or capability read and resume the exact continuation. C++ ownership makes the logical-read ledger, continuation, journal, budget, and replay capture one atomic state machine.

### Provider least authority

Agents inspect sensitive processes. Returning facts and scan matches rather than verdicts limits protocol authority, makes server-side audit possible, and prevents divergent agent versions from changing rule meaning.

### Deterministic replay and optimization

Captured replay and exact-versus-optimized comparison require the same implementation to own all observable decisions. Ambient CPython behavior or agent-side predicates would create hidden inputs.

### Cross-platform semantic identity

Windows and Linux servers must compile a source pack to the same platform-independent semantic hash. A versioned C++ model of Python behavior and Unicode makes this an explicit acceptance property.

## Rejected alternatives

### Execute static rules in embedded CPython

Rejected. Restricted builtins, import hooks, audit hooks, subinterpreters, and object proxies do not provide the required security/resource boundary. CPython would retain authority over object behavior, allocation, exceptions, hashing, scheduling, and dynamic lookup. It would also make effect analysis and exact fact planning incomplete.

### Compile to CPython bytecode and intercept fact access

Rejected. CPython bytecode is an unstable implementation detail and assumes the CPython frame/object runtime. Interception would not provide complete static knowledge of effects, labels, boundary types, or resource cost, and suspension/finally behavior would remain tied to CPython internals.

### Send rules or predicates to agents

Rejected. Agent-side evaluation would violate least authority, distribute semantic versions across the fleet, expose more rule intent, and allow client results to drift from the server's optimizer, policies, and fault model.

### Let generators emit executable IR

Rejected. Generators are convenient trusted build tools, not semantic plugins. Only compiler-known templates and typed immutable binding arguments may be emitted.

### Delegate expressions to external services

Rejected. Services are typed capability endpoints. Their response is input to evaluation, never an authoritative verdict or arbitrary expression execution.

## Consequences

### Positive

- A single source of truth for verdicts, effects, faults, and resource use.
- Agents and service endpoints have narrow, versioned contracts.
- Static analysis can enumerate capability use and reject unsupported Python before activation.
- Exact execution is a reliable semantic oracle for optimization.
- Cross-platform and replay discrepancies can be attributed to explicit inputs or engine defects.
- Security review can focus on a bounded C++ VM and boundary adapters rather than ambient Python execution.

### Negative

- The project must implement and maintain a substantial Python-compatible type system, object model, exception model, Unicode behavior, and async runtime.
- Supporting new Python or standard-library features requires C++ semantic work and differential tests.
- CPython bug compatibility is not automatic.
- The compiler and VM become critical trusted computing-base components.
- Some Python authors will encounter valid grammar that the static subset rejects.

## Operational and security implications

- Parser/generator workers are process-contained for reliability, but the signature policy is the security boundary for executed generator Python.
- A provider response is treated as untrusted typed input and validated before becoming a VM value.
- C++ engine invariant failures do not enter user exception handlers; they abort and quarantine because semantic state may be unsafe.
- No agent certificate or negotiated capability grants match-decision authority.
- Audit records include executable identity, compiler/runtime ABI, peer/session, fact routes, and final C++ verdict.
- A node with a different semantic hash cannot serve the activated generation.

## Known limitations introduced

- Full Python grammar is parsed, but only the explicitly modeled static subset runs.
- Native Python packages and dynamic language mechanisms are unavailable to rule code.
- C++ implementations may lag new Python releases or obscure library behavior.
- Cross-platform floating-point library edge cases require deterministic modeling or documented test tolerances.
- The trusted C++ compiler/VM is larger than a thin wrapper around CPython.

## Evidence and validation

The decision is validated by:

- AST tests proving rule modules are never imported or executed by CPython;
- negative protocol tests proving agents cannot submit verdicts or predicates;
- differential CPython tests for every supported pure semantic family;
- Windows/Linux semantic-hash equality tests;
- suspension tests proving continuation resumes without re-running source;
- captured replay tests;
- exact-versus-optimized parity tests;
- schema/label validation at every provider, service, state, event, and effect boundary;
- repository scans showing no alternative evaluator remains after cutover.

## Revisit conditions

Revisit only if all of the following are true:

1. a concrete feature cannot reasonably be modeled in the C++ semantics;
2. an alternative preserves server-owned verdicts, static capability knowledge, budgets, replay, labels, and provider least authority;
3. its security and operational isolation is specified rather than assumed;
4. it has an exact conformance and migration plan;
5. changing the core trust boundary is accepted as a new architecture version, not a local implementation shortcut.
