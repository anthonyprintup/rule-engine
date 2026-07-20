# ADR-004: Use a Verified Custom Resumable Register VM

- Status: Accepted
- Date: 2026-07-20
- Owners: Compiler and VM lanes
- Related tasks: F0, C3, V1-V4, E1-E3, O1, I1
- Related architecture: [Compiler, IR, and VM](../architecture/04-compiler-ir-and-vm.md)

## Context

Rule execution must combine Python-compatible control flow with distributed facts, service/history suspension, generators, async task groups, transactional state/effects, data labels, flight recording, deterministic replay, and hard resource ceilings.

A recursive AST evaluator can request missing facts, but scaling it to precise Python exception/finally behavior, generators, multiple suspended tasks, verification, heap cycles, and optimizer proofs would couple logical execution to native C++ calls and ad hoc continuation objects.

Executing CPython directly would give mature Python semantics but would transfer ownership of objects, frames, bytecode, scheduling, allocation, and many resource decisions to a runtime that is not designed for the engine's capability and replay contracts.

## Decision

Compile accepted Python through typed HIR and explicit CFG/SSA-like form into locally generated typed register bytecode. Verify the serialized bytecode independently before activation and execute it in a custom resumable C++ VM.

The VM has these defining properties:

- VmSession explicitly owns frames, typed registers, instruction pointers, heap handles, exceptions/unwind state, logical reads, tasks, journals, labels, recorder data, replay captures, and budget counters.
- VmSession::step accepts validated host responses and returns completion, fault, cancellation, cooperative yield, waiting-for-facts, or waiting-for-capabilities.
- Suspension records an exact typed resume continuation. Resumption never restarts the entrypoint.
- Bytecode represents Python exceptions, finally/with cleanup, generators, await, task groups, facts, capabilities, state, effects, labels, traces, and semantic charges explicitly.
- Values live in a session-local stable-handle heap with deterministic safepoints and non-moving mark/sweep. User finalizers and weak references are unavailable.
- No generic native-call opcode exists. Every intrinsic has declared types, effects, faults, labels, and costs.
- The exact unoptimized bytecode is retained as the semantic oracle.
- Bytecode is a private, versioned local artifact; source-only packs never contain it.

## Primary reasons

### Suspension is a normal state, not an exceptional retrofit

Facts and capabilities are expected to be absent during a step. Explicit instruction/resume tables let the coordinator release its native worker while preserving the exact rule continuation, unwind state, journal, and budgets.

### Verification before execution

A closed register instruction set allows dataflow verification of register initialization/types, handler regions, resume targets, capability declarations, and effect summaries. Even locally generated output is treated as fallible.

### Python control flow without the native stack

Explicit frames and unwind reasons model recursion, exceptions, return/break/continue through finally, generators, and async operations without depending on C++ call-stack shape or exceptions.

### Resource ownership

Every call, allocation, loop, instruction, fact, capability, history query, state operation, and effect can be charged at one well-defined VM boundary. Hard exhaustion bypasses Python catches while separately bounded cleanup can still run.

### Optimization and debugging

Typed registers and CFG provenance support specialization and source mapping while retaining an exact bytecode oracle. Suspension frames and recorder events reference stable source/function/instruction identities rather than native addresses.

## Why a register VM

SSA values and block arguments map directly to typed virtual registers. This reduces stack-shape joins, makes verifier state explicit, gives suspension records direct value locations, and simplifies specialization and register allocation.

A stack VM could satisfy the design, but it would require stack-map verification at every exceptional and suspension edge and additional shuffling after CFG optimization. The expected compactness benefit does not outweigh that complexity for this engine.

## Rejected alternatives

### Continue the recursive AST evaluator

Rejected. Native recursion and visitor state do not provide a robust representation for arbitrary suspension, multiple coroutines, generator throw/close, finally unwinding, verifier dataflow, or compiler optimization. Adding continuation cases to every AST visitor would duplicate a VM less explicitly.

### Embedded CPython evaluation

Rejected. It defeats C++ semantic ownership and exposes ambient dynamic behavior. Instruction, heap, fact, effect, label, and structured-concurrency limits could not be enforced comprehensively through hooks.

### CPython bytecode interpreter with custom objects

Rejected. The bytecode ABI and interpreter assumptions remain CPython-owned. Its opcodes do not carry the engine's static capability, label, effect, logical-read, or cost metadata.

### LLVM/native JIT

Deferred. Native code adds executable-memory policy, platform code generators, deoptimization, safepoints, precise charge preservation, native crash containment, and source/replay complexity before the semantics have stabilized.

### WebAssembly

Rejected for the first rewrite. Python objects, exceptions, generators, async tasks, fact suspension, labels, and boundary validation still require a custom runtime, while Wasm introduces another verifier/runtime and cross-platform semantic layer.

### One native thread per evaluation

Rejected. Blocking native threads on facts/services cannot scale to the intended peer population, complicates cancellation, and does not solve deterministic replay or transactional journal ownership.

### Reference counting only

Rejected. Python-compatible containers may form cycles, recursive release can consume native stack, and destruction timing would leak host scheduling/ownership details. A session-local tracing collector has no user callbacks.

## Consequences

### Positive

- Arbitrary facts and capabilities suspend without blocking a native thread.
- A session resumes once at an explicit continuation.
- Bytecode verification narrows the trusted execution surface.
- VM-local objects cannot carry ambient native capabilities.
- Cyclic Python object graphs are supported within a bounded heap.
- Hard resource accounting and cancellation are integrated into execution.
- Exact execution, replay, traces, and optimized execution use one frame/value model.
- Windows and Linux share a platform-independent semantic executable.

### Negative

- The VM is a substantial implementation and maintenance commitment.
- Python conformance requires broad differential testing.
- Initial throughput may be below a JIT or native specialization.
- The non-moving heap can fragment within a session.
- Stable handles add indirection.
- Generator, exception-group, async cleanup, and class semantics create many verifier/runtime edge cases.
- Bytecode format changes invalidate caches and require recompilation.

## Operational and security implications

- No unverified bytecode executes, even when read from a local cache.
- Source-only pack signing does not imply bytecode trust; local compiler and verifier versions are part of executable identity.
- VM invariant failures are infrastructure faults, not catchable Python exceptions. The invocation journal is aborted and the executable/node is quarantined as appropriate.
- Session heaps are isolated. Mutable objects cannot be shared across invocations or native threads.
- Hard VM limits are a safety backstop, while the worker's process limits protect parser/generator availability.
- Emergency fault reporting uses pre-reserved bounded memory so ordinary heap exhaustion can still be diagnosed.
- Cancellation and host responses use request/session/fence identities to prevent stale work from resuming or committing.

## Known limitations introduced

- There is no JIT initially.
- CPython-specific introspection, weak references, finalizers, and GC timing are unsupported.
- Cyclic objects cannot cross canonical storage/wire/effect boundaries.
- Non-moving collection may fragment, although the 16 MiB session cap bounds impact.
- Real CPU and elapsed time are operational measurements and cannot be replayed exactly.
- Large/deep valid programs may be rejected by compiler, frame, heap, or instruction limits.
- The VM bytecode is intentionally not a public author or plugin API.

## Evidence and validation

The decision is validated by:

- independent verifier mutation and fuzz tests;
- pause/resume tests at every suspending opcode;
- tests proving no source restart or duplicate state/effect intent;
- nested exception/finally/with, generator send/throw/close, and structured task-group suites;
- CPython differential tests for every supported pure operation;
- heap cycle, stale-handle, collection, quota, and allocation-failure tests;
- one-below/exactly-at/one-above tests for every balanced.v1 limit;
- ASan/UBSan and long-running randomized VM tests;
- Windows/Linux semantic-hash and behavior equality;
- exact/optimized captured-input parity.

## Revisit conditions

### Add a JIT

Only after the register VM is a stable oracle and profiling shows a material production bottleneck. A JIT design must preserve verifier proofs, safepoints, suspension, source maps, labels, journals, semantic charges, cancellation, replay, and exact fallback.

### Change the heap

Only if representative workloads show fragmentation or collection latency outside budgets. Any moving or generational design must retain stable external handles and deterministic, callback-free semantics.

### Publish bytecode

Only through a separate versioned compatibility and trust proposal. The current source-only signing and local compilation model intentionally excludes portable bytecode.

### Replace the VM

Only if the replacement demonstrably preserves C++ semantic authority, static capabilities, typed boundaries, all hard limits, suspension, replay, exact effect/state behavior, and cross-platform semantic identity.
