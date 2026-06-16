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
- Evaluate pattern-set and boolean tuple `of` expressions, including numeric and
  percentage quantifiers plus `at`/`in` anchors for pattern sets.
- Request process, PE image, and fixture pattern facts through provider routes.
- Exchange localhost v1 client/server messages with length-prefixed frames.
- Emit machine-readable artifacts, readable dumps, diagnostics, and opt-in traces.

See [GOAL.md](GOAL.md) for the project target and
[docs/V1_IMPLEMENTATION_STATUS.md](docs/V1_IMPLEMENTATION_STATUS.md) for the
current implementation checklist. See
[docs/RUST_BRIDGE_UPDATE.md](docs/RUST_BRIDGE_UPDATE.md) for the YARA-X bridge
and cbindgen update workflow, and
[docs/TRANSPORT_BOUNDARY.md](docs/TRANSPORT_BOUNDARY.md) for the localhost V1
transport boundary.

## Execution Model

The rule engine treats YARA rules as symbolic programs over facts. Parsing starts
in the Rust `yara-x-parser` bridge, but the bridge only returns syntax. C++ then
verifies imports, module fields, module functions, globals, rule references, and
unsupported expression forms against `ModuleRegistry` descriptors.

Descriptors are the contract between rule syntax and providers:

- `FieldDescriptor` maps a visible field such as `process.pid` to a typed fact
  key, provider route, TTL, request timeout, and prefetch cost hint.
- `FunctionDescriptor` maps a visible function such as `demo.score(...)` to a
  return type, argument types, provider route, TTL, request timeout, and a stable
  fact-key prefix.
- `GlobalDescriptor` maps bare external/global names to provider-backed facts.

Verification lowers descriptor-backed expressions into requirements, not values.
For example, `process.name` becomes a requirement for the `process.name` fact on
`endpoint.process.snapshot`. A module function call remains symbolic until its
arguments are evaluated; `demo.score(process.pid, "alpha")` first asks for
`process.pid`, then derives a typed function fact key such as
`demo.score(i:4242,s:616c706861)`. Provider key v1 tokens are ASCII and
delimiter-safe: strings and bytes use lowercase hex payloads, floating-point
values use their IEEE-754 bit pattern, arrays/objects recurse into nested
argument tokens, and undefined is encoded explicitly as `u`.

The VM is synchronous and resumable. `Evaluator::step(subject)` either returns a
complete set of rule results or returns `waiting_for_facts` with missing fact
batches grouped by provider route. The caller sends those batches to a client,
stores returned facts in the session `FactCache`, and calls `step` again. This
keeps async I/O out of the VM while still allowing facts to arrive later from
local or remote handlers. The scheduler prefetches descriptor facts marked as
cheap, including deterministic module function facts whose arguments are
statically known, then evaluates symbolically and requests expensive facts only
when control flow reaches them. Pattern scan facts are treated as expensive so
process/PE filters can short-circuit before a scan route is requested.
Provider request timeouts are descriptor-owned: each field, function, and global
fact carries a timeout into the lowered requirement, and route batches use the
maximum timeout among the facts grouped into that request.

Facts carry a subject id, key, typed `Value`, status, diagnostic text, and TTL.
Available facts participate in expression evaluation. Unavailable or
access-denied facts produce per-rule diagnostics and no-match results. Undefined
values propagate with YARA-like semantics: boolean `and`/`or` treat undefined
operands as false, while comparisons and string predicates return undefined when
their operands are undefined.

Clients are provider endpoints only. A localhost client advertises capabilities,
enumerates subjects, receives fact-batch requests, and returns typed facts or
structured diagnostics. It never evaluates predicates or decides rule matches.
Built-in routes serve process snapshot facts, PE image header, section, import,
export, debug-directory, resource, certificate-table, and TLS callback facts, and
fixture-backed pattern facts. Custom C++ handlers can be bound for
descriptor-backed module function routes while preserving the same trust
boundary. After handshake, the server compares the verified program's required
provider-route registry against the client's advertised capabilities before
evaluation starts. Each emitted request is checked again before send; before
facts enter the cache, available values are checked against the
descriptor-derived expected type. The VM also rechecks descriptor-backed cached
field/global/pattern facts and function return facts before consuming them, so
manually populated or stale wrong-typed cache entries produce no-match
diagnostics.

## Custom Descriptor Configs

`rule_engine_server --module-config <file>` loads extra descriptors before rule
verification. The v1 text format is whitespace-delimited:

```text
module demo
function score integer integer,string endpoint.demo.functions demo.score 30 false 12
```

The function fields are: name, return type, comma-separated argument types or
`-`, provider route, key prefix, TTL seconds, cheap-prefetch boolean, and
optional timeout seconds. The same file format also accepts
`field <key> <type> <route> <ttl> <cheap> [timeout]` inside a module and
`global <name> <type> <key> <route> <ttl> <cheap> [timeout]`. If omitted, the
descriptor timeout defaults to 5 seconds.

`rule_engine_client --custom-fact-fixture <file>` advertises configured custom
routes and serves fixture facts for them:

```text
capability endpoint.demo.functions
fact endpoint.demo.functions demo.score(i:42,s:616c706861) integer 9 30
```

Fact fixture fields are: route, provider key, value type, value token, and TTL
seconds. String and bytes values are lowercase hex payloads. These fixture
handlers are for local v1 demos and tests; they still only return typed facts.

See `examples/custom_binding/` for a complete custom module example with a
descriptor config, YARA rule, and client fact fixture. In two terminals, run the
client first and then the server:

```powershell
build\debug\rule_engine_client.exe --custom-fact-fixture examples\custom_binding\demo.facts
build\debug\rule_engine_server.exe --module-config examples\custom_binding\demo.module --rule examples\custom_binding\demo_rule.yar
```

By default, `rule_engine_client` serves one localhost session and exits. Use
`--max-sessions <n>` to serve a bounded number of sequential sessions, or
`--serve` to keep the local provider service running until it is stopped.

## Pattern Scan Configs

`rule_engine_client --pattern-fixture <file>` accepts the original explicit
fixture lines:

```text
$needle true 4096 6 fixture.process.memory rx 6e6565646c65
```

It also accepts literal scan directives that scan configured bytes and return
real `PatternValue` match metadata:

```text
scan $needle configured.file r-- 41416e6565646c655a5a 6e6565646c65
```

The scan fields are: pattern key, scan-space name, region permissions, haystack
bytes as lowercase hex, and literal needle bytes as lowercase hex. File-backed
scan directives read bytes from a configured file path, resolving relative paths
against the fixture file:

```text
scan_file $needle file.bytes r-- sample.bin 6e6565646c65
```

The `scan_file` fields are: pattern key, scan-space name, region permissions,
file path, and literal needle bytes as lowercase hex. The client only returns
pattern facts such as `$needle.matches` and `$needle.pattern`; the server still
evaluates all rule conditions.

For rule-derived literal scan plans, configure only the scan space and let the
server send the YARA string literal bytes in the fact request:

```text
scan_file_space file.bytes r-- sample.bin
```

When evaluating a rule such as `$needle = "needle" ascii`, the server attaches a
scan plan for `$needle` to the `endpoint.scan.patterns` request. The client uses
that literal to scan the configured space and returns ordinary pattern facts.
When no explicit scan spaces are configured, the default Windows client adds a
subject-scoped `process.image.bytes` scan space by reading each requested
process subject's image file, so rules can match literals against process image
bytes without duplicating those literals in client config.
To scan mapped image sections instead of the whole image file, enable explicit
section scan spaces in the pattern fixture file:

```text
scan_process_image_sections
```

For each requested process subject, the client parses the image's PE section
table and returns matches from `process.image.section.<name>` scan spaces with
`rwx`-style permissions derived from section characteristics.
Readable process memory scan spaces are also explicit. Use the directive without
arguments to scan committed readable regions, or pass a decimal base address and
size to scope the scan:

```text
scan_readable_memory_regions
scan_readable_memory_regions 140737488355328 4096
```

Matching chunks are returned as subject-scoped `process.memory.region.<address>`
scan spaces with the Windows protection string as region permissions.

## Rule Corpus

`examples/rule_corpus/` contains a small checked corpus for the current YARA
subset. `supported_process_pe.yar` is expected to parse and verify with the
default descriptors. The `unsupported_*.yar` files are expected to parse but
fail semantic verification, documenting constructs that are intentionally
outside the current implementation.

## Repository Layout

- `include/rule_engine/` - public C++ headers for the core engine and providers.
- `src/` - compiler, evaluator, protocol, trace, provider, and CLI code.
- `src/proto/` - v1 protocol schema.
- `rust/yara_bridge/` - Rust YARA-X parser bridge and generated C++ ABI inputs.
- `tests/` - Catch2 tests and YARA fixtures.
- `examples/` - tested custom-binding and rule-corpus examples.
- `docs/` - implementation notes, bridge/transport guidance, and status
  tracking.

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
abort behavior. Trace replay artifacts snapshot cached subject facts, including
runtime-derived custom function facts, so replay does not need live providers.

## CLI Tools

- `rule_engine_check` parses and validates rules.
- `rule_engine_server` evaluates rules against process subjects through the v1
  client protocol. Pass `--json` to emit structured JSON for both rule
  evaluation and smoke fact round trips.
- `rule_engine_client` serves localhost provider facts for v1 smoke paths. Pass
  `--max-sessions <n>` for bounded multi-session service mode or `--serve` for
  an unbounded local service.

## Generated Files

Build outputs, Rust target artifacts, generated bridge headers, and IDE metadata
are ignored. Regenerate them through the normal CMake/Cargo build flow instead of
committing local build products.
