# Rule Engine

Rule Engine is a Windows-only C++23 rule engine for parsing, validating, lowering,
and evaluating YARA rules against live process subjects. YARA syntax is parsed by a
small Rust bridge over YARA-X, but rule semantics stay in C++.

The core trust boundary is simple: the server owns all rule meaning and match
decisions. Clients enumerate subjects and return typed facts or structured
diagnostics. A client never evaluates conditions, predicates, or whole rules.

## Current Scope

- Parse YARA through the Rust `yara-x-parser` bridge.
- Validate modules, fields, functions, globals, externals, rule references, and
  unsupported expression shapes in C++.
- Lower validated rules into deterministic debug-oriented IR and schedules.
- Evaluate rules through a synchronous VM step function that pauses for missing
  provider facts.
- Request process, PE image, and fixture pattern facts through provider routes.
- Exchange localhost v1 client/server messages with length-prefixed frames.
- Emit machine-readable artifacts, readable dumps, diagnostics, and opt-in traces.

See [GOAL.md](GOAL.md) for the project target and
[docs/V1_IMPLEMENTATION_STATUS.md](docs/V1_IMPLEMENTATION_STATUS.md) for the
current implementation checklist.

## Execution Model

The rule engine treats YARA rules as symbolic programs over facts. Parsing starts
in the Rust `yara-x-parser` bridge, but the bridge only returns syntax. C++ then
verifies imports, module fields, module functions, globals, rule references, and
unsupported expression forms against `ModuleRegistry` descriptors.

Descriptors are the contract between rule syntax and providers:

- `FieldDescriptor` maps a visible field such as `process.pid` to a typed fact
  key, provider route, TTL, and prefetch cost hint.
- `FunctionDescriptor` maps a visible function such as `demo.score(...)` to a
  return type, argument types, provider route, TTL, and a stable fact-key prefix.
- `GlobalDescriptor` maps bare external/global names to provider-backed facts.

Verification lowers descriptor-backed expressions into requirements, not values.
For example, `process.name` becomes a requirement for the `process.name` fact on
`endpoint.process.snapshot`. A module function call remains symbolic until its
arguments are evaluated; `demo.score(process.pid, "alpha")` first asks for
`process.pid`, then derives a typed function fact key such as
`demo.score(i:4242,s:alpha)`.

The VM is synchronous and resumable. `Evaluator::step(subject)` either returns a
complete set of rule results or returns `waiting_for_facts` with missing fact
batches grouped by provider route. The caller sends those batches to a client,
stores returned facts in the session `FactCache`, and calls `step` again. This
keeps async I/O out of the VM while still allowing facts to arrive later from
local or remote handlers.

Facts carry a subject id, key, typed `Value`, status, diagnostic text, and TTL.
Available facts participate in expression evaluation. Unavailable or
access-denied facts produce per-rule diagnostics and no-match results. Undefined
values propagate with YARA-like semantics: boolean `and`/`or` treat undefined
operands as false, while comparisons and string predicates return undefined when
their operands are undefined.

Clients are provider endpoints only. A localhost client advertises capabilities,
enumerates subjects, receives fact-batch requests, and returns typed facts or
structured diagnostics. It never evaluates predicates or decides rule matches.
Built-in routes serve process snapshot facts, PE image facts, and fixture-backed
pattern facts. Custom C++ handlers can be bound for descriptor-backed module
function routes while preserving the same trust boundary.

## Repository Layout

- `include/rule_engine/` - public C++ headers for the core engine and providers.
- `src/` - compiler, evaluator, protocol, trace, provider, and CLI code.
- `src/proto/` - v1 protocol schema.
- `rust/yara_bridge/` - Rust YARA-X parser bridge and generated C++ ABI inputs.
- `tests/` - Catch2 tests and YARA fixtures.
- `docs/` - implementation notes and status tracking.

## Requirements

- Windows
- CMake 3.31 or newer
- Ninja
- A C++23 compiler compatible with the MSVC frontend
- Visual Studio C++ build environment
- Rust and Cargo

The Rust bridge uses `cbindgen` as a Cargo build dependency to generate the C++
bridge header during the CMake build.

## Build

Run CMake from a Visual Studio developer environment:

```powershell
cmake -S . -B build/debug -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build/debug
```

For Clang on Windows, pass `clang-cl` as the C and C++ compiler during
configuration if it is not already selected by your environment.

## Test

```powershell
ctest --test-dir build/debug --output-on-failure
```

The test suite covers parser bridge conversion, semantic validation, VM behavior,
scheduling, protocol framing/codecs, runtime orchestration, traces, and unattended
abort behavior.

## CLI Tools

- `rule_engine_check` parses and validates rules.
- `rule_engine_server` evaluates rules against process subjects through the v1
  client protocol.
- `rule_engine_client` serves localhost provider facts for v1 smoke paths.

## Generated Files

Build outputs, Rust target artifacts, generated bridge headers, and IDE metadata
are ignored. Regenerate them through the normal CMake/Cargo build flow instead of
committing local build products.
