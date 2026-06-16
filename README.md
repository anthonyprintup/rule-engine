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
