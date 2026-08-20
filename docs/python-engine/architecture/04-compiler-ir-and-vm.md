# Compiler, Intermediate Representations, and Resumable VM

## 1. Purpose

This document specifies how trusted Python 3.14 rule-pack source becomes an executable whose semantics are owned by C++, and how that executable runs safely while facts and capabilities arrive asynchronously.

The subsystem has five goals:

1. Preserve the documented Python language subset exactly, including evaluation order, exceptions, generators, async control flow, classes, arbitrary integers, Unicode, and mutable cyclic containers.
2. Make every provider read, capability call, state operation, effect, trace event, allocation, and budget charge explicit before execution.
3. Suspend and resume an invocation without restarting source code or duplicating observable work.
4. Reject malformed compiler output before it can execute.
5. Permit optimization only when compiler evidence proves that all language-visible and engine-visible observations are preserved.

Related decisions:

- [ADR-001: C++ owns semantics](../decisions/ADR-001-cpp-owns-semantics.md)
- [ADR-004: custom resumable VM](../decisions/ADR-004-custom-resumable-vm.md)
- [ADR-014: effect-aware optimization](../decisions/ADR-014-effect-aware-optimization.md)

Related contracts are in [CONTRACTS.md](../CONTRACTS.md). Fault journals, commits, and capability transports are expanded in architecture document 06.

## 2. Goals and non-goals

### Goals

- Deterministic compilation from a verified source closure, schema catalog, operator bindings, compiler/runtime ABI, and platform-independent semantic target.
- Precise diagnostics at UTF-8 byte source spans, including diagnostics for syntactically valid but unsupported Python.
- A typed HIR suitable for author-facing diagnostics and semantic checks.
- An explicit CFG/SSA-like representation suitable for control-flow validation and effect analysis.
- Locally generated, verified register bytecode suitable for compact interpretation and suspension.
- A session-owned heap that supports Python object graphs without native-language finalizers or unbounded recursive destruction.
- Exact resumption at the instruction that requested a fact or capability.
- Differential conformance tests against pinned CPython for every supported pure operation.
- A conservative optimizer whose output can be shadow-compared with exact execution.

### Non-goals

- Executing rule modules, CPython bytecode, or Python objects in the server.
- Accepting precompiled bytecode or IR from a rule pack.
- Reproducing undocumented CPython implementation accidents such as object addresses, reference-count timing, hash secrets, or garbage-collection callbacks.
- Providing a stable third-party bytecode ABI. Bytecode is a local cache artifact keyed by the complete compiler/runtime ABI.
- JIT compilation in the first rewrite.
- Making actual wall-clock or CPU timing bit-for-bit reproducible.
- Supporting Python weak references, object finalizers, metaclasses, arbitrary descriptors, native extensions, or reflection.

## 3. Ownership and trust boundaries

The compiler consumes only:

- a VerifiedRulePack with a verified canonical source index and dependency closure;
- a SchemaCatalog with canonical hashes;
- OperatorBindings naming capabilities, policies, retention profiles, and budget profiles;
- a pinned AST envelope produced by the short-lived CPython parser worker.

The AST envelope is untrusted input at the C++ boundary even though the signed source is operationally trusted. The decoder validates framing, version, node tags, field cardinality, scalar widths, source spans, nesting, and configured caps. Unknown or malformed fields fail compilation; they are never ignored.

The compiler is the sole authority for binding names, resolving imports, assigning types, declaring facts and capabilities, determining effects, and selecting language semantics. The worker does not bind or type-check. Providers do not see predicates or bytecode. The VM never imports modules or consults a Python runtime.

Compiled bytecode is produced locally and verified before activation. Cache corruption, compiler bugs, or incompatible cached output therefore fail closed rather than becoming unchecked interpreter state.

## 4. Compilation inputs and identity

PackCompiler::compile receives:

- VerifiedRulePack;
- SchemaCatalog;
- OperatorBindings;
- CompilerOptions containing the exact language, compiler, Unicode, bytecode, optimizer, and resource-profile versions.

The compilation key includes:

- canonical verified source digest and embedded dependency digests;
- binding-generator canonical output digest;
- schema and operator-binding hashes;
- Python grammar and modeled-library version;
- Unicode data version;
- HIR, CFG, bytecode, and verifier ABI versions;
- optimizer version and enabled optimization profile;
- target semantic ABI.

Platform-independent semantic hashes exclude filesystem paths, build timestamps, machine addresses, and host compiler details. Native packaging identity may additionally include OS, architecture, C++ ABI, and dependency versions.

Source files are valid UTF-8. Every AST node, HIR node, CFG instruction, bytecode instruction, diagnostic, effect summary, and recorder mapping references a SourceId plus a half-open UTF-8 byte range. Line and display-column data are derived at presentation edges, never used as identity.

## 5. Compiler pipeline

~~~mermaid
flowchart LR
    A["Verified .rpack source closure"] --> B["Short-lived CPython 3.14 parser"]
    B --> C["Versioned bounded AST envelope"]
    C --> D["C++ envelope validation"]
    D --> E["Module graph and name binding"]
    E --> F["Type, schema, class, and capability analysis"]
    F --> G["Typed HIR with ordered operations"]
    G --> H["CFG with block arguments and explicit exits"]
    H --> I["SSA-like analysis and effect summaries"]
    I --> J["Conservative optimization"]
    J --> K["Register allocation and bytecode emission"]
    K --> L["Independent bytecode verifier"]
    L --> M["CompiledPack plus semantic hashes"]
    L -->|failure| N["Internal compiler diagnostic; pack cannot activate"]
~~~

Every phase returns std::expected and accumulates deterministic DiagnosticSet values. Project code uses neither C++ exceptions nor RTTI.

### 5.1 AST envelope validation

The worker emits an envelope header containing grammar version, worker protocol version, source digest, node count, maximum observed depth, and source IDs. AST nodes are tagged unions with every field present in CPython field order. Constants use exact tagged encodings rather than lossy JSON numbers.

The decoder enforces:

- exact source digest and known protocol/grammar versions;
- no duplicate IDs, dangling references, cycles, or node sharing where the Python AST contract requires a tree;
- source ranges within the referenced file and child ranges contained where required;
- configured byte, node, string, integer, collection, and nesting limits;
- known node tags and exact required/optional fields;
- valid identifiers and operator/context enum tags.

A worker syntax error is converted to a stable source diagnostic. A malformed envelope, worker crash, timeout, or resource exit is a compiler infrastructure diagnostic and never partially compiles a pack.

### 5.2 Module graph and name binding

The binder builds one closed module graph from pack-local modules, embedded source dependencies, rule_engine, and the versioned modeled allowlist. Import resolution never consults sys.path, the host filesystem outside the verified closure, or ambient packages.

Binding follows the supported Python 3.14 lexical rules:

- module, class, function, lambda, comprehension, pattern, and exception-handler scopes;
- local, cell, free, global, and nonlocal resolution;
- comprehension isolation and left-to-right target binding;
- class-body name lookup and the implicit __class__ cell needed by zero-argument super;
- pattern-bound name consistency;
- decorator and default-expression evaluation order in the static declaration model.

The binder rejects dynamic/wildcard imports, import cycles, ambiguous dependency exports, mutable module globals, reflection, dynamic namespace access, and declarations that would require CPython execution. Allowed top-level operations are declarations, immutable constants, decorators modeled by the compiler, and bind calls whose arguments are statically evaluable.

Each reference is bound to a stable SymbolId. Names are not re-looked-up dynamically during evaluation.

### 5.3 Types, classes, schemas, and narrowing

The type checker represents:

- None, bool, arbitrary int, binary64 float, Unicode string, bytes, enum, literal, range, slice, tuple, list, set, frozenset, dict, iterator, generator, async iterator, awaitable, exception, callable, class, instance, record/model, union, Protocol, constrained/bounded scalar TypeVar, and internal Any;
- FactValue-backed model fields and their eager/lazy routes;
- labeled types and explicit declassification transforms;
- service, history, state, event, post, retention, capture, and task-group capabilities;
- Never for unreachable paths and control-flow narrowing.

Public declarations require complete annotations. Any may flow through private computations, but a boundary operation requires proof that its value has narrowed to the declared closed type. Runtime guards are inserted where static narrowing depends on a check whose result is only known during evaluation.

Class analysis computes a fixed C3 MRO, resolves super targets, lays out declared fields, validates properties and allowed descriptors, and creates immutable class descriptors. Dynamic base classes, metaclasses, monkey-patching, arbitrary descriptors, __del__, and weak references are rejected.

Schema analysis emits canonical descriptors and stable hashes. The compiler does not trust a provider, service, history row, generator result, or persisted state value merely because it has the expected C++ variant; boundary validation is explicit in bytecode or host adapters.

### 5.4 Typed HIR

HIR is structured and close enough to source to support diagnostics. It removes syntax sugar while retaining Python ordering and exception behavior.

Examples of HIR normalization:

- chained comparisons become ordered, single-evaluation comparisons with short-circuit edges;
- comprehensions become explicit iterator regions and scoped bindings;
- with and async with become enter/exit regions with explicit suppression checks;
- match becomes ordered pattern tests, bindings, guards, and rollback of failed tentative bindings;
- default arguments, decorators, and bind declarations become compiler-known declaration objects;
- property/method access becomes typed lookup operations, not a generic reflective lookup;
- provider-backed properties become FactRead nodes;
- await, yield, yield from, async iteration, and task-group operations remain explicit suspension nodes;
- try/except/except*/else/finally remain structured regions until CFG construction.

HIR nodes have:

- static input/output types;
- source span;
- possible Python exception set;
- possible unsuppressible VM control-fault set;
- effect and logical-read summary;
- data and control label behavior;
- allocation and semantic-cost category.

HIR preserves left-to-right evaluation. No phase may reorder expressions merely because C++ would permit it.

### 5.5 CFG and SSA-like form

Each function becomes a set of basic blocks with typed block arguments. Values defined once use SSA value IDs. Python locals that are captured, may be deleted, or require identity use explicit cells; mutable objects remain heap handles rather than being converted to immutable SSA values.

Every potentially faulting instruction has an explicit exceptional successor or an enclosing handler-table region. Every suspension has a resume block with typed success and error inputs. Return, raise, break, continue, yield, cancellation, and hard-control-fault exits are distinct.

Finally and context-manager semantics use explicit unwind records:

- pending reason: normal, return, break, continue, Python exception, cancellation, or hard control fault;
- associated value/target;
- cleanup stack;
- whether a Python handler may inspect or replace the reason.

Hard budget and deployment cancellation faults bypass Python except handlers but execute only the separately budgeted engine cleanup path. Ordinary Python exceptions run normal except/finally semantics.

The CFG builder validates:

- dominance and block-argument arity/type;
- initialization before use;
- legal loop, exception, cleanup, yield, and await structure;
- no value or task escaping its lifetime region;
- exact stack of data-label control contexts;
- transaction/task-group nesting;
- all public returns narrowed to bool for rules/correlations;
- all paths either terminate, suspend, yield, or transfer to a valid successor.

### 5.6 Whole-program summaries and certificates

Call-graph analysis computes a fixed point across helpers, templates, concrete rules, correlations, class methods, properties, and modeled library calls. Recursive strongly connected components are summarized conservatively.

An OptimizationCertificate records at least:

- deterministic/pure status;
- possible Python exceptions and engine control faults;
- ordered logical fact routes and whether each is conditional;
- service, history, state, event, post, retention, capture, and recorder interactions;
- allocation/mutation/identity sensitivity;
- data/control label effects;
- possible suspension/yield/cancellation points;
- child-rule ownership and transaction behavior;
- whether a result can be synthesized under each recorder policy;
- semantic charge map for eliminated or fused operations;
- proof inputs and compiler pass/version.

Certificates are compiler output, not author assertions. Unsupported or uncertain constructs receive the most conservative summary.

### 5.7 Register bytecode

CFG values are assigned typed virtual registers. A function chunk contains:

- stable FunctionId and source table;
- declared parameter/return types;
- register count and per-register verifier type;
- constants and referenced descriptor/capability IDs;
- instructions;
- normal/exception/cleanup/resume tables;
- generator/coroutine metadata;
- effect certificate and semantic charge table.

Instruction families include:

- constants, moves, tuples, unpacking, and type/narrowing guards;
- integer/float/string/bytes/container operations;
- object, class, field, property, method, cell, and closure operations;
- comparisons, truth conversion, branching, match tests, and iteration;
- direct/static dispatch, recursion, return, raise, exception-group split/merge;
- handler, finally, with, and unwind operations;
- generator create/resume/send/throw/close and yield;
- coroutine create/await and async iterator/context-manager operations;
- task-group create/start/join/cancel/exit;
- READ_FACT and scan request;
- service/history/state capability requests;
- append-effect, transaction, recorder, and label-control operations;
- semantic budget charge and explicit safepoint;
- cancellation and result completion.

There is no generic native-call opcode. Every modeled operation has a stable opcode or descriptor-selected intrinsic with declared type, effect, fault, label, and cost semantics.

Bytecode uses fixed-width opcode headers and bounded variable-length operands. All indices are checked before use. Its encoding is versioned but not public: a cache entry with any ABI mismatch is discarded and recompiled.

### 5.8 Implemented display, subscription, and synchronous-loop lowering

The current compiler backend uses the following exact mappings for its bounded
container/control-flow slice:

- list/tuple displays evaluate children left to right, copy their results into
  a contiguous register range, and emit `build_list`/`build_tuple`;
- dictionary displays emit an empty `build_dict`, then evaluate one key and one
  value and emit `store_subscript` before starting the next entry;
- subscription reads emit `load_subscript`; one-target list/dictionary writes
  emit `store_subscript` after evaluating the assignment RHS, container, and key
  in that order; and
- synchronous `for` evaluates its iterable once, emits `get_iter` once, and
  uses one `iter_next` header whose fallthrough enters the body and whose
  explicit exhaustion target enters `else`. Natural completion and `continue`
  jump to the header; `break` targets the point after `else`.

Dictionary construction is deliberately incremental even though `build_dict`
can consume a contiguous key/value range. Python hashes and compares each key
before evaluating the next entry. Deferring every insertion until all
expressions had run would expose later effects or faults after an earlier
unhashable key and would therefore be observably wrong.

The verifier treats the two `iter_next` successors asymmetrically: the
fallthrough initializes the loop-target register, while the exhaustion edge
retains the incoming initialization state. It checks every container range,
subscription operand, iterator register, and control-flow target. Consequently,
a new loop target cannot be read after a possibly empty loop unless another path
initializes it.

Container build work is instruction-precharged before allocation. Empty
dictionary allocation is charged before its first entry expression, each item
store is a checked instruction, and iterator advance consumes the loop budget
before changing iterator state. Budget failure therefore cannot partially
allocate the charged list/tuple or advance past the last accounted iteration.

This is an implementation slice, not a relaxation of the full typed-HIR design.
Starred/`**` expansion, sets, slices, comprehensions, generator expressions,
destructuring targets, item deletion, `range`, `async for`, arbitrary iterator
protocols, and the source-level state API remain fail-closed until their typed
scope, exception, replay, and charging contracts exist.

### 5.9 Implemented exception and cleanup lowering

The current frontend implements a closed exception slice whose semantics fit
the verified register ABI. CPython parses the syntax but never executes an
exception expression or chooses a handler. C++ resolves names, emits regions,
verifies their graph, classifies runtime faults, and owns every unwind.

#### Closed author-exception table

| Source name | ABI kind | Role |
|---|---|---|
| `ValueError` | `value_error` | Concrete raise kind and exact handler filter |
| `TypeError` | `type_error` | Concrete raise kind and exact handler filter |
| `ArithmeticError` | `arithmetic_error` | Concrete raise kind and exact handler filter |
| `Exception` | `exception` | Catch-all filter for the three concrete kinds |

A bare `except:` uses the same closed catch-all as `except Exception:`. It does
not catch cancellation, hard budgets, invalid bytecode, stale handles, host
protocol faults, or engine faults. `Exception` is filter-only and cannot be
raised. The compiler rejects a duplicate handler, a handler after a catch-all,
and a name shadowed anywhere in the function or current module. It never
reorders handlers to make a source program acceptable.

Explicit raises are limited to `raise ValueError`, `raise TypeError`, or
`raise ArithmeticError`, optionally called with zero or one positional `str`
message and no keywords. `raise ... from ...`, arbitrary expressions, multiple
arguments, user exception classes, and handler binding with `as` have no ABI
representation and fail with stable source-spanned diagnostics. A bare
`raise` emits `reraise` only in a handler body where an active exception is
guaranteed on every entry. A conditionally active bare raise in `finally` is
rejected: the VM guard for a missing current exception is an integrity failure,
not Python's catchable `RuntimeError`, so lowering it would be an approximation.

#### Handler and cleanup geometry

~~~mermaid
flowchart LR
    A["try body: protected handler interval"]
    A -->|"normal"| B["else suite"]
    A -->|"author fault"| C["ordered match_exception chain"]
    C -->|"match"| D["handler body"]
    C -->|"no match"| E["reraise"]
    B --> F["unwind_jump or normal join"]
    D --> G["leave_except"]
    G --> F
    A -->|"return / break / continue"| H["saved unwind reason"]
    E --> H
    F --> H
    H -->|"finally present"| I["cleanup entry"]
    I --> J["leave_try resumes saved reason"]
    H -->|"no finally"| K["continuation"]
    J --> K
    L["hard budget or cancellation"] -->|"bypass filters"| I
~~~

For `try/except/else`, only the `try` body belongs to the handler interval.
Normal completion executes `leave_try` and then `else`; a fault in `else` does
not select the preceding handlers. The exceptional entry is a source-ordered
linked list of `match_exception` instructions ending in `reraise`. Every
normally completing handler executes `leave_except` before joining ordinary
control flow.

`try/finally` adds an outer cleanup region. Combined
`try/except/else/finally` is the same outer region protecting the complete
inner handler construct, including filter and handler blocks. Cleanup entry and
its distinct exceptional-resume `reraise` are outside the protected half-open
interval. Every ordinary edge leaving that interval is `unwind_jump`; cleanup
ends with `leave_try`, which resumes the saved normal target, return value,
loop target, author exception, cancellation, or hard fault.

Regions are disjoint or strictly nested. The VM selects the smallest exited
cleanup first and records completed regions, so nested finalizers execute
inside-out exactly once. A normal finalizer can replace a pending normal,
return, loop, or author-exception unwind with its own return, jump, or exception.
Forced cleanup cannot replace cancellation or a hard fault; an attempted
replacement follows the bounded double/triple-fault policy.

Loop frames record handler and cleanup depth. A loop inside a handler retains
that handler on its own `break`; a handler opened inside a loop is left before
breaking or continuing the loop. Plain backedges remain plain jumps so
`iter_next` owns the single per-iteration charge. An edge that actually exits a
`finally` region uses `unwind_jump`, preserving cleanup and loop-budget order.

The independent verifier checks interval bounds and strict nesting, distinct
cleanup entries, exceptional-only entry, ordered filter ownership and terminal
`reraise`, current-exception reachability, initialized registers, and the
absence of ordinary edges that enter a region midway or bypass cleanup.
Malformed generated or mutated graphs fail activation with `PYC01xx`; rule
handlers never receive a verifier failure.

This remains a bounded implementation slice. Exception objects, `as` binding,
argument tuples, traceback/context/cause state, user subclasses, conditional
bare re-raise in finalizers, `BaseException`, and `except*`/exception groups are
not implemented. Returns and loop transfers leave active handler state before
an enclosing finalizer runs; accepted source cannot observe that state because
binding and finalizer bare re-raise are rejected. Full Python observability at
that boundary requires unwind records that carry handler-scope exits. These
limitations and revisit conditions are recorded as L-028.

### 5.10 Typed custom-event emission opcode

Custom event construction and emission are engine-owned operations. The
compiler evaluates supplied keyword expressions in Python order, materializes
permitted omitted canonical scalar defaults, and stages a complete field window
for `build_record` in canonical field-ID order. Its `immediate` pins the event
schema ID and canonical hash, `operand_a` begins that contiguous register
window, and `operand_b` is the exact active descriptor field count. The
verifier rejects an unknown schema, a non-event descriptor, a hash or
field-count mismatch, an invalid window, or any field register not initialized
on every path. The VM uses field IDs from the active descriptor; source never
supplies runtime field IDs or a nominal class-name shortcut.

The resulting record can enter the verified `emit_event` instruction:

| Field | Contract |
|---|---|
| `operand_a` | Initialized register containing the payload record. |
| `immediate` | Constant-pool index of a `rule-engine.vm.event-operand.v1` record containing the event schema ID and its exact canonical schema hash. |
| `destination` / `operand_b` | Reserved and required to be zero. |
| successor | The next instruction only; emission never suspends or dispatches. |

The verifier requires the operand to name an active `SchemaKind::event`
descriptor whose canonical hash exactly matches the operand. It rejects an
uninitialized payload register, malformed/reserved fields, an undeclared
schema, or an optimization certificate that claims the body does not emit
events.

At execution, the VM validates the record against that descriptor, derives its
label from the schema fields, and deep-freezes it before appending an
`EventIntent`. The intent identity is a collision-free, length-prefixed
encoding of `(root_event_id, invocation_id, monotonic_event_sequence)`. Nested
effect transactions share one ordering domain and one transaction mark with
the event journal. Rollback truncates both journals; count and byte charges are
cumulative and are never refunded. Python exceptions, failed finalization,
cancellation, and hard faults leave no committed event intent. Finalizer and
hard-cleanup code cannot use this opcode.

`balanced.v1` caps an invocation at 256 event intents, 2 MiB of cumulative
frozen event payload, and depth 64. Count, bytes, item traversal, cycle checks,
and schema checks occur before journal mutation. A limit failure is the typed
unsuppressible `event_budget_exhausted` VM fault.

The opcode creates no durable envelope and calls no event consumer. On clean
terminal completion, only `EvaluationResult::committed_events` is eligible for
server projection. Optimizer shadow comparison treats ordered event intents
and event resource counters as committable observations; an event-emitting
certificate conservatively selects the exact VM.

## 6. Independent bytecode verification

The verifier is a separate component that consumes serialized bytecode rather than compiler-internal objects. Activation requires successful verification.

It validates:

- header and ABI identity;
- bounded section sizes and canonical encoding;
- known opcode and operand forms;
- constant, descriptor, register, block, handler, and source-map indices;
- register initialization and verifier-type compatibility on every edge;
- legal control-flow targets and no branch into the middle of an instruction;
- dominance-like requirements for values and cells;
- handler/finally/task/transaction region nesting;
- suspension only at declared resume tables;
- generator/coroutine opcodes only in compatible functions;
- capability use only when declared and typed;
- no effect, fact, history, service, state, or trace operation omitted from the certificate;
- valid semantic-charge and resource metadata;
- bool return on reportable entrypoints;
- absence of unreachable malformed payloads hidden after an unconditional branch.

Verification failure produces an internal compiler diagnostic tied to the generating pass where possible. The pack cannot stage or activate. Repeated verifier failures mark the node unhealthy rather than invoking rule fault handlers.

## 7. Runtime value model

### 7.1 Immediate and heap values

PyValue is a tagged value. None, bool, sufficiently small integers, and selected sentinels may be immediate. All identity-bearing or variable-sized values use HeapHandle values containing a slot index plus generation. Handles remain stable across collection; generation checks prevent stale-handle reuse.

The heap supports:

- arbitrary integers, floats when not stored immediate, Unicode strings, bytes;
- tuples, lists, dictionaries, sets, frozensets;
- ranges, slices, iterators;
- cells, functions, bound methods, classes, instances;
- exceptions and traceback/source records;
- generators, coroutines, async generators, awaitables, and task-group objects.

Heap object layouts are engine-defined, never C++ RTTI-based. All casts inspect explicit type tags and return an EngineFault on invariant violation.

### 7.2 Arbitrary integers and floats

Integers use a small immediate representation with transparent promotion to a sign-plus-limb representation backed by Boost.Multiprecision-compatible algorithms. Arithmetic follows Python floor-division, modulo, bitwise, shift, comparison, and bool-conversion semantics.

Instruction and heap cost scales with operand/result limb counts. A shift or exponentiation validates its projected allocation and semantic work before allocating. Oversized results fail through the configured hard heap/instruction budget rather than native allocation failure.

Floats are IEEE-754 binary64 with Python-specified conversions and comparison behavior. Host floating-point mode is fixed at startup and verified by conformance tests. Frozen values preserve signed zero and canonicalize NaN payloads while retaining Python's NaN comparison behavior when thawed. APIs whose CPython results depend on a platform libm require cross-platform golden tolerances or a modeled deterministic implementation.

### 7.3 Unicode strings

PyString is an immutable sequence of code points from 0 through 0x10FFFF, including the surrogate range. This matches Python string indexing and preserves escaped surrogates without relying on native wchar_t width.

Generated tables come from the exact pinned CPython Unicode data and cover casing, classification, normalization exposed by the modeled API, identifier rules, and formatting. Indexing is by code point, not UTF-8 byte or grapheme.

Source identifiers and diagnostics remain valid UTF-8 and cannot contain raw surrogate encodings. String values cross canonical boundaries through the tagged FrozenValue Unicode representation; ordinary scalar strings use canonical UTF-8, while values containing surrogates use a tagged 32-bit code-point sequence. Human-readable logs escape control and surrogate code points.

### 7.4 Containers, equality, and hashing

Lists and dictionaries preserve Python mutation and insertion order. Sets/frozensets use a collision-resistant per-evaluation seed recorded in the replay capture. Hashes never leave the evaluation as semantic identities.

Equality and hashing are cycle-aware and budgeted. Recursive equality detects active object pairs; recursively self-containing structures follow the documented engine behavior and never recurse through the native C++ stack without a depth charge. Unhashable keys raise TypeError.

Dictionary/set resizing charges projected memory first. Iteration detects prohibited size changes with Python-compatible runtime errors. The VM never exposes native pointers or allocation addresses to rule code.

### 7.5 Boundary freezing

Before a value enters a fact cache, service request, event, state, effect, trace payload, or persistent store, the boundary adapter:

1. verifies the declared schema/type;
2. joins value and current control labels;
3. traverses with depth, byte, item, and cycle accounting;
4. rejects unsupported identities, functions, capabilities, generators, tasks, and cycles;
5. produces canonical immutable FrozenValue ordering/encoding.

Failure raises BoundaryValidationError at the source operation. Partial values or effects are never emitted.

## 8. Heap ownership and garbage collection

Each VmSession owns its heap. No object is shared mutably across evaluations or native threads. Immutable schema descriptors and constants are shared outside the session.

The heap uses non-moving mark/sweep:

- allocation slots contain explicit type, generation, mark state, size charge, and payload;
- roots include registers, frames, closures, pending exceptions, unwind records, generator/coroutine frames, task groups, host request records, state/effect journals, recorder buffers, and replay captures;
- collection runs only at deterministic allocation/safepoint thresholds derived from charged bytes, never from host memory pressure alone;
- traversal uses an explicit worklist, not native recursion;
- sweep increments slot generations before reuse;
- finalizers and weak references are unsupported, so collection has no user-visible callbacks.

All allocations are charged before mutation. Collection can recover storage but does not refund cumulative semantic allocation work. Live heap bytes enforce the 16 MiB cap; logical allocation charges defend against allocation churn.

Native allocation failure is converted to an EngineResourceFault at a guarded allocation boundary. If the process cannot allocate the pre-reserved emergency fault record, the session is canceled, the executable/node is quarantined according to infrastructure policy, and no user handler is invoked.

## 9. VM session and execution

VmSession owns:

- compiled executable and invocation identity;
- frame stack and typed registers;
- heap and hash seed;
- instruction pointer and unwind/exception state;
- generator/coroutine and deterministic task scheduler state;
- logical-read ledger and outstanding host requests;
- state snapshot/write set plus effect and event journals;
- label/control context;
- flight recorder;
- replay captures;
- all balanced-profile counters and deadlines.

VmSession::step(HostResponses) validates responses, applies them to matching outstanding requests, then executes until it:

- completes with MATCH or NO_MATCH;
- returns waiting-for-facts;
- returns waiting-for-capabilities;
- cooperatively yields for host fairness;
- becomes faulted, quarantined, or canceled.

The API is single-owner and non-reentrant. A session may move between worker threads only while stopped in VmStep; no thread retains interior pointers.

### Deterministic scheduling

Logical tasks receive monotonic TaskId values. Ready tasks run FIFO by TaskId at explicit safepoints. A HostResponses batch is canonicalized by request ID before making tasks ready. The author API exposes no ambient event loop, detached task, or race-on-first-completion primitive. Therefore host arrival order is not observable unless an explicit capability schema makes it data.

Replay supplies captured response batches and scheduler choices. Cancellation is checked at instruction, loop, allocation, call, backward-edge, and suspension safepoints.

## 10. Fact and capability suspension

~~~mermaid
sequenceDiagram
    participant VM as VmSession
    participant L as Logical-read ledger
    participant H as Coordinator/host
    participant P as Provider or capability

    VM->>L: Reach READ_FACT(subject, route, type)
    L-->>VM: Record logical read and source span
    alt Valid eager/cached value exists
        VM->>VM: Validate and continue next instruction
    else Request is already outstanding
        VM->>VM: Attach current continuation
        VM-->>H: VmStep waiting
    else Value is absent
        VM->>H: Typed request with request ID and deadline
        H->>P: Dispatch fact/capability request
        VM-->>H: VmStep waiting
        P-->>H: Typed value or terminal status
        H->>VM: HostResponses
        VM->>VM: Validate request, subject, schema, size, status
        alt Success
            VM->>VM: Store response and resume successor
        else Terminal provider status
            VM->>VM: Raise typed Python exception at READ_FACT
        else Protocol violation
            VM->>VM: Infrastructure/provider fault; do not expose malformed data
        end
    end
~~~

READ_FACT records the logical read only when execution reaches it. A pure physical prefetch may populate a separate tentative cache, but cannot:

- enter the logical-read ledger;
- raise a Python exception;
- consume logical fact count/round/retention budget;
- produce author trace or recorder read events;
- make an otherwise unvisited provider status visible.

When execution reaches a prefetched key, normal validation and charging occur and the tentative result becomes logical. Duplicate logical reads share a validated result but each language-level property operation still receives its semantic instruction charge.

Each outstanding request records execution, task, subject, route/method, schema, source span, deadline, capability, and expected response type. Unknown, duplicate-after-consumption, mismatched, oversized, or stale responses are ignored for evaluation and audited as provider/protocol faults.

## 11. Calls, generators, and async execution

### Calls and recursion

Calls use explicit frames with return register, caller instruction, locals/register file, cells, current exception, unwind stack, control label, and transaction/task-group region IDs. The 128-frame cap applies across helpers, methods, child rules, generator resumes, finalizer/handler calls within the normal executor, and recursive calls.

Static dispatch targets exact FunctionIds. Protocol/overload selection is resolved statically or through a bounded compiler-generated runtime type switch. No dictionary-based reflective method lookup exists.

### Generators

A generator owns a suspended frame and state: created, running, suspended, closed, or faulted. Resume operations implement next/send/throw/close explicitly. yield stores the resume instruction and returns the yielded PyValue to the owning iterator operation. yield from is lowered to a state machine that preserves send/throw/close delegation.

Generator cleanup occurs through bounded VM cleanup, never C++ destructors invoking user code. A generator that becomes unreachable is discarded without running arbitrary Python finalization; author code requiring cleanup must use a lexical context manager.

### Coroutines and task groups

Calling an async function creates a cold coroutine. It runs only when directly awaited or started in the current lexical TaskGroup. A group owns all child tasks transitively. Awaitables may pass through locals, containers, and helpers only while static escape analysis proves that their owning group is in scope.

Group exit behavior:

- normal exit defaults to CANCEL_PENDING;
- WAIT_PENDING is an explicit statically known policy;
- exceptional exit always cancels pending work;
- cancellation and cleanup use the group/evaluation deadline and cleanup cap;
- no task survives the group, invocation, retry, handler, or replay boundary.

Awaiting a fact/capability creates a suspension record rather than blocking a native thread. Async generators and context managers use the same frame/unwind machinery.

## 12. Exceptions, faults, and unwinding

Python exceptions are heap values with typed class, arguments, cause/context, suppression flag, and bounded source traceback. Raising transfers through verifier-approved handler tables. Bare raise uses the frame's active exception.

try, except, except*, else, finally, with, and async with preserve Python ordering and replacement rules. An exception or return passing through finally is represented by an unwind reason; a new return/raise may replace it according to Python semantics.

The VM distinguishes:

- author-visible Python exceptions, including typed fact/service/state/history and soft-budget exceptions;
- unsuppressible hard budget/deployment cancellation control faults;
- recoverable top-level rule faults routed to the separately budgeted finalizer/on_fault design;
- provider/protocol faults caused by invalid external responses;
- EngineFault caused by bytecode or native invariant failure.

EngineFault never enters Python handlers because continued execution may be unsafe. It aborts the journal, persists an infrastructure fault if possible, quarantines the executable or node as appropriate, and affects readiness if repeated.

Tracebacks use source maps and logical function/child-rule identity rather than raw bytecode offsets in user-facing output.

## 13. Resource accounting

### balanced.v1 normal executor

The exact locked limits are:

| Resource | Limit |
|---|---:|
| Elapsed time, including waits | 10 seconds |
| Active VM CPU | 100 milliseconds |
| Semantic bytecode instructions | 1,000,000 |
| Frames | 128 |
| Live VM heap | 16 MiB |
| Loop iterations/yields | 250,000 |
| Logical facts | 512 |
| Provider rounds | 16 |
| Fact data | 16 MiB |
| Service calls scheduled | 128 |
| Service calls active | 16 |
| Service response data | 16 MiB |
| Per-service-call deadline | 5 seconds, bounded by evaluation deadline |
| History queries | 16 |
| History rows | 10,000 |
| History data | 16 MiB |
| State keys | 256 |
| Combined state reads/writes | 1 MiB |
| Effect intents | 256 |
| Effect payloads | 2 MiB |
| Flight recorder | 25,000 events and 4 MiB, head-and-tail |

### Compile and ingest limits

| Resource | Limit |
|---|---:|
| Source closure | 16 MiB |
| AST nodes | 1,000,000 |
| Concrete generated bindings | 100,000 |
| Generator argument/input data | 64 MiB |
| Python worker | 512 MiB and 15 seconds |
| One authoritative nested snapshot | 100,000 items and 16 MiB |

### Recovery executors

| Executor | Limits |
|---|---|
| Finalizer / on_fault | 100,000 instructions; 50 ms active; 2 s elapsed; 2 MiB heap; 8 service calls; 64 intents |
| on_double_fault | 25,000 instructions; 1 s elapsed; 512 KiB heap; diagnostic/quarantine capabilities only |
| Forced cleanup | 25,000 instructions; 500 ms elapsed |

Hard exhaustion is an unsuppressible VM control fault. A named soft sub-budget may raise a catchable typed exception. A profile change creates a new profile version; balanced.v1 is never silently redefined.

### Charging rules

- Charge before performing an operation that could exceed a bound.
- Semantic instruction counts come from bytecode charge metadata, including synthetic charges retained for optimized-away work.
- Loops charge at each iteration/back edge; yields charge both instruction and loop/yield counters.
- Calls charge before allocating the frame.
- Heap charges projected live size before allocation or growth.
- Facts, services, history, state, and effects charge only when logically reached.
- Waiting time counts toward elapsed time but not active VM CPU.
- Active VM CPU uses a monotonic per-thread clock around interpreter work and excludes host waits.
- Recorder truncation is deterministic and does not disable the underlying recorder-observability restrictions.

Actual CPU time is operational rather than a reproducible language value. Optimization may reduce it, and OS scheduling makes exact equality impossible. Optimizers must preserve semantic instruction/resource counters and may not increase modeled worst-case work, but exact and optimized runs can differ in measured CPU duration. This limitation is visible in metrics and is not treated as semantic equivalence.

## 14. Effect-aware optimization

### Exact baseline

Unoptimized verified bytecode is the semantic oracle. Every optimized executable retains:

- the exact bytecode hash;
- optimizer pass/version;
- input certificate hashes;
- a mapping from optimized instructions to exact source/charge regions;
- the ability to run exact, optimized, shadow, or replay comparison modes.

### Permitted transformations

Subject to certificates, the optimizer may:

- specialize templates, generics, modeled calls, and immutable binding arguments;
- propagate constants and types;
- fold pure operations using the same C++ semantic implementation as the VM;
- remove unreachable pure blocks;
- eliminate redundant pure loads and bounds/type checks;
- simplify control flow and allocate registers;
- hoist pure parent-only nested-scope discovery predicates;
- build conditional fact plans and tentative prefetch groups;
- fuse pure container/iteration operations without changing ordered observations.

For eliminated/fused semantic operations, bytecode retains synthetic charge entries so instruction, loop, allocation-work, and logical boundary budgets cannot be bypassed.

### Forbidden without proof of identical observability

The optimizer must not skip, reorder, speculate, or synthesize across:

- effects or effect transactions;
- state reads/writes or MVCC boundaries;
- services, history, captures, or custom events;
- logical fact reads or potentially visible fact failures;
- Python exceptions, finally/with cleanup, cancellation, or fault handlers;
- mutable object identity or iteration-order dependencies;
- data/control-label changes;
- child-rule ownership/reporting;
- full-flight-recorder observations;
- dynamic trace publication;
- generator yield or async scheduling boundaries.

When a certificate is unknown or recursive analysis fails to prove a property, exact execution wins.

### Recorder policy

Optimization selection considers the invocation's pre-armed recorder policy. A transformation that removes an event required by that policy is disabled unless it emits an exactly equivalent synthetic recorder event with the same ownership, ordering, source span, values permitted by label policy, and disposition.

Full-flight-recorded or effect/state/service/history paths therefore normally use exact bytecode.

### Fact planning

The planner may issue tentative prefetch only for statically typed, provider-safe requests. It cannot convert a physical request into a logical read before READ_FACT. Provider scheduling costs and privacy policy may further prohibit prefetch even when semantically pure.

### Equivalence and rollout

Shadow execution reuses captured facts, service responses, history rows, timestamps, hash seed, scheduler decisions, and state snapshot. It compares:

- MATCH/NO_MATCH/FAULTED and exception identity;
- logical fact ledger and terminal statuses;
- ordered effect/state journal and dispositions;
- emitted events and retained fields;
- child-rule results and ownership;
- flight-recorder events after deterministic truncation;
- semantic instruction, loop, boundary, allocation-work, and budget outcomes.

Operational durations are compared as metrics, not for equality. A mismatch disables the optimized executable, preserves exact execution, records a bounded redacted diff, and increments a breaker metric. Optimizer mismatch never changes the committed result.

## 15. Failure modes and recovery

| Failure | Required behavior |
|---|---|
| Parser worker crash/timeout/limit | Fail compilation with infrastructure diagnostic; server remains alive. |
| Malformed/unknown AST envelope | Reject entire compilation; audit worker/compiler ABI details. |
| Binding/type/schema error | Emit deterministic source diagnostics; no CompiledPack. |
| Compiler internal CFG invariant failure | Return internal diagnostic, block activation, retain reproducer digest. |
| Bytecode verifier failure | Block staging/activation; mark repeated node failures unhealthy. |
| Corrupt/incompatible bytecode cache | Delete/ignore cache entry and recompile source; never execute it. |
| Python exception | Follow explicit Python handler/unwind tables, then top-level fault policy. |
| Hard budget/deadline exhaustion | Unsuppressible control fault; abort journal; run bounded cleanup/fault path. |
| Native allocation failure | Convert at guarded boundary; use pre-reserved fault storage or cancel/quarantine if impossible. |
| Invalid/stale host response | Do not expose data; audit provider/protocol fault; continue waiting or fail per deadline. |
| Duplicate response | Ignore after first accepted response and audit; never resume twice. |
| VM/heap invariant failure | EngineFault; abort, quarantine executable/node, never invoke user handlers. |
| Optimizer parity mismatch | Discard optimized outcome, commit exact outcome only, disable affected optimized executable. |
| Cancellation while suspended | Resume only into cancellation/unwind path; never process a late response into committed work. |
| Generator/task abandoned | Bounded lexical cancellation/cleanup; no user finalizer from GC. |

## 16. Invariants

1. C++ is the only semantic authority after the parser returns syntax.
2. No bytecode executes before independent verification.
3. A suspension resumes exactly once at its declared continuation.
4. A logical fact/capability/effect/state/history operation exists only if control reaches its instruction.
5. Host input is schema/identity/request/size validated before entering PyValue.
6. No native pointer, ambient handle, or capability is representable in rule data.
7. VM object mutation is session-local.
8. Boundary values are canonical, labeled, validated, and acyclic.
9. Hard budgets cannot be caught or converted into MATCH/NO_MATCH by Python code.
10. Exact bytecode remains available as the semantic oracle.
11. Unknown optimizer properties are treated conservatively.
12. Journal commit occurs outside the VM only after successful finalization and store transaction.

## 17. Reasoning and rejected alternatives

### Execute rules in CPython

Rejected because Python audit hooks, restricted builtins, and import filtering are not a security or determinism boundary. CPython would own name lookup, object behavior, exceptions, scheduling, allocation, and resource consumption, conflicting with the central trust boundary and captured replay.

### Reuse CPython bytecode

Rejected because it is version-specific, assumes CPython object/runtime machinery, is not typed for provider/capability validation, and cannot statically expose effects and logical facts with the required guarantees.

### Recursive AST evaluator

Rejected because recursion couples execution to the native stack and makes arbitrary suspension, generators, finally unwinding, task groups, verification, and optimization difficult. The current recursive evaluator is replaced rather than extended.

### Stack bytecode

Rejected in favor of typed registers because CFG values and block arguments map directly to registers, verifier dataflow is clearer, suspension frames are explicit, and optimizer output needs fewer stack-shape repair operations. A stack VM would be viable but offers no compensating benefit here.

### LLVM/native JIT

Deferred because executable memory, deoptimization, precise source traces, hard instruction charging, portable semantic parity, and safe suspension considerably enlarge the attack and correctness surface. Register interpretation is adequate for the first release and establishes a trustworthy oracle.

### WebAssembly runtime

Rejected because Python object, exception, generator, async, capability, label, and fact semantics would still require a large custom runtime. It would move rather than remove the hard design work and weaken direct C++ semantic ownership.

### Reference counting

Rejected as the sole memory strategy because cyclic Python containers require cycle collection, destruction timing would become observable pressure, and recursive releases can consume native stack. Session-local non-moving mark/sweep is simpler and supports stable handles.

### Aggressive speculative optimizer

Rejected because speculative facts and synthesized results can alter privacy, exceptions, traces, effects, budgets, and replay. Conservative compiler certificates plus exact fallback make correctness auditable.

## 18. Known limitations

### VM-L01 — Supported Python, not CPython internals

- Impact: code relying on object addresses, reference-count timing, garbage-collection callbacks, weak references, undocumented hashing, or dynamic internals is unsupported.
- Reason: these behaviors conflict with deterministic C++ ownership.
- Mitigation: precise diagnostics and conformance documentation.
- Revisit: only with a deterministic typed semantic design.

### VM-L02 — No hostile-code guarantee for the parser/generator worker

- Impact: a malicious trusted signed generator is outside this subsystem's security guarantee.
- Reason: process containment protects availability; provenance is the security boundary.
- Mitigation: signing, private runtime, cleared environment, declared inputs, and OS/deployment limits.
- Revisit: require a separately specified OS/container sandbox if third-party untrusted packs are accepted.

### VM-L03 — Modeled standard library and float variation

- Impact: only declared modeled APIs exist; some libm edge results may require platform tolerances.
- Reason: ambient CPython/native libraries are unavailable.
- Mitigation: deterministic implementations where practical and cross-platform differential vectors.
- Revisit: model new APIs only with exact effects, types, costs, and portability tests.

### VM-L04 — Cyclic boundary values

- Impact: cyclic objects are valid inside the VM but cannot enter state, services, events, effects, history, or persistence.
- Reason: canonical wire/storage formats are acyclic.
- Mitigation: immutable typed records and BoundaryValidationError with cycle path.
- Revisit: only with a versioned canonical graph format.

### VM-L05 — Conservative optimization

- Impact: effects, recording, uncertain faults, state, services, or history commonly force exact execution.
- Reason: observations and privacy matter more than speculative speed.
- Mitigation: certificates, pure-prefix planning, and parity telemetry.
- Revisit: add transformations only with proof obligations and shadow coverage.

### VM-L06 — Operational time is not deterministic

- Impact: optimized and exact runs can use different actual CPU time, and OS scheduling can cause a near-limit invocation to time out in one run but not another.
- Reason: the 100 ms active CPU and 10 s elapsed limits measure real resources.
- Mitigation: preserve every semantic counter, use monotonic clocks, record timings/profile/headroom, avoid relying on near-limit completion, and run parity with adequate operational headroom.
- Revisit: a deterministic virtual-time budget would be a new profile and would not replace deployment safety deadlines.

### VM-L07 — No JIT initially

- Impact: pure compute-heavy rules may run slower than native/JIT code.
- Reason: the interpreter is the simplest verifiable suspension and budget oracle.
- Mitigation: typed register bytecode, specialization, conservative fusion, and workload benchmarks.
- Revisit: only after stable semantics, profiles, and representative measurements justify a proof-carrying JIT.

### VM-L08 — Bounded tracebacks and diagnostics

- Impact: extremely deep/repetitive traceback and object representations are truncated.
- Reason: faults must remain reportable within recovery budgets and label caps.
- Mitigation: explicit truncation markers, source/function IDs, recorder head-and-tail data, and offline source lookup.
- Revisit: raise bounds only through a new profile.

## 19. Observability and diagnostics

Compiler diagnostics include stable code, severity, source span, phase, related spans, modeled-language version, and bounded help text. Internal errors additionally record source digest, pass ID, IR/verifier version, and a privacy-safe reproducer key.

Runtime metrics include:

- compile duration and nodes per phase;
- HIR/CFG/instruction/register/function sizes;
- verifier and cache outcomes;
- exact/optimized selection and fallback reasons;
- steps, instructions, frames, heap live/peak/collections;
- suspensions by fact/capability route and provider rounds;
- generator/task counts and cancellation cleanup;
- exceptions/control faults/engine faults;
- per-resource headroom and exhaustion;
- parity mismatch class.

User-facing traces contain source-level calls, branches, facts, effects, faults, and values only as allowed by label/redaction policy. Raw heap addresses, native stack data, secrets, and provider-prefetch-only reads are never logged.

## 20. Required tests and acceptance criteria

### Frontend and compiler

- Golden decode coverage for every Python 3.14 AST node/field and exact scalar kind.
- Negative tests for malformed node graphs, spans, counts, versions, unsupported constructs, imports, scopes, annotations, schemas, labels, classes, generics, and public Any escape.
- Control-flow tests for chained comparisons, match bindings, comprehensions, closures, recursion, with/finally, exception groups, generators, and async regions.
- Byte-identical semantic output across source paths, host OS, locale, hash seed, and compiler process.
- Verifier mutation/fuzz tests for every index, opcode, register type, handler, resume table, and region invariant.

### Value and VM conformance

- Differential tests against pinned CPython for supported integer, float, Unicode, string/bytes, formatting, equality/hash, list/dict/set, slicing, class/MRO/super, exception, generator, async iterator, and context-manager behavior.
- Property tests for arbitrary-integer identities and floor division/modulo.
- Full Unicode table/version tests including escaped surrogates.
- Heap tests for cycles, stale handles, deterministic collection, precharge, quota, allocation failure, and no finalizer execution.
- Pause/resume tests at every suspending opcode, including response error, cancellation, retry, and duplicate/stale response.
- Structured-task tests for cold coroutines, start, wait, cancel, exceptional exit, helper/container passage, and rejected escape.
- Hard/soft budget tests at one below, exactly at, and one above every balanced.v1 limit.
- Fault/unwind tests for return/raise/break/continue through nested finally/with and recovery executor limits.

### Optimization

- Exact-versus-optimized property tests comparing verdict, Python fault, logical facts, ordered journal/state, child ownership, labels, recorder, and every semantic resource counter.
- Tests proving unvisited prefetched failures are invisible and uncharged.
- Tests proving full recording/effects/state/services/history select exact execution unless equivalent synthetic observations are certified.
- Injected parity mismatches must commit only the exact result and disable the affected optimized executable.

### Completion criteria

This architecture slice is implemented only when:

1. locally compiled bytecode cannot execute without independent verification;
2. every supported pure semantic family has pinned CPython differential coverage;
3. every suspension resumes once without entrypoint restart or duplicated journal entries;
4. every balanced.v1 limit has boundary tests;
5. exact/optimized parity covers all language-visible and engine-visible semantic observations;
6. Windows and Linux semantic hashes and conformance results match;
7. sanitizers and VM/compiler/verifier fuzzers pass;
8. tracked product documentation reflects these contracts, reasoning, and limitations at integration.
