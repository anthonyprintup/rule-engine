# V1 Implementation Status

This file tracks current progress against `GOAL.md`. It is intentionally conservative: an item is marked complete only when implemented and covered by the current test suite or smoke checks.

## Implemented

- Cargo-built Rust `yara-x-parser` bridge exposed through a panic-safe C ABI.
- Versioned cbindgen-generated C++ ABI for parsed YARA rules (`re_yara_bridge_version() == 1`).
- C++ bridge conversion from Rust-owned parser arena views into the internal `ParsedRuleSet` and `Expression` model.
- Include resolver for root files, including-file directory lookup, explicit include directories, include cycle diagnostics, and CLI `-I`/`--include-dir` support.
- Source names and stable numeric source ids carried on parsed rule/expression spans so included-file semantic diagnostics and compact IR artifacts can point at the included source.
- C++ semantic validation for known module imports, module fields, and module functions, including function arity and statically known argument types.
- Semantic validation rejects unsupported YARA expression nodes and unknown module functions instead of letting them evaluate as false.
- Compiler-level source namespaces, same-namespace duplicate diagnostics, qualified cross-namespace rule references, dependency collection, fact propagation, and cycle diagnostics.
- Private rule suppression, global rule gating, and YARA-X-style validation that global rules depend only on global rules.
- Descriptor-backed global/external variables lowered from bare identifiers into async fact requirements.
- Descriptor-backed module function calls lowered into async fact requirements with typed argument-derived provider keys.
- Extended string operators `icontains`, `startswith`, `istartswith`, `endswith`, `iendswith`, and `iequals` bridged from YARA-X and evaluated by the VM.
- Integer arithmetic and bitwise expression nodes bridged from YARA-X and evaluated by the VM.
- Pattern count/offset/length constructs (`#`, `@`, `!`) bridged from YARA-X and evaluated from provider-supplied `PatternValue` metadata.
- Pattern-set `of` expressions for `all`, `any`, `none`, numeric, and percentage quantifiers over rule pattern facts.
- Numeric zero pattern quantifiers use YARA's clarified exactly-zero semantics for both `of` and `for..of` pattern sets.
- `with` expressions with local symbolic bindings for aliases over fact-backed expressions.
- `for in` expressions over integer ranges, expression tuples, arrays, and objects with value and key/index-value local bindings.
- `for of` pattern-set loops with current-pattern placeholder binding for `$`, `#`, `@`, and `!` body expressions plus `all`, `any`, `none`, numeric, and percentage quantifiers.
- YARA-X-style undefined propagation for boolean contexts: `and`/`or` treat undefined operands as false, while `not`, comparisons, and string predicate operators return undefined when an operand is undefined.
- Array and object `Value` storage plus lookup expressions for integer indexes and string keys.
- Synchronous VM step model that pauses on missing facts and resumes after `FactCache` fill.
- VM evaluation of rule references with per-step memoization.
- Descriptor-backed fact routing for process, PE, and fixture pattern facts.
- TTL-based session cache expiration for volatile facts.
- Versioned deterministic binary IR and schedule artifacts alongside readable dumps, including source tables and per-rule source ids.
- IR and schedule dumps/artifacts include rule namespace names and qualified rule identifiers.
- Versioned `RETR` evaluation trace artifacts capture subject, provider facts, final VM step, opt-in expression trace events, and replay deterministically without TCP or live providers.
- Length-prefixed protocol frame codec.
- Typed v1 protocol payload codecs for handshake capabilities, subject lists, batched fact requests, and fact responses, including pattern match metadata values.
- Windows process subject enumeration.
- Windows process snapshot fact provider for PID, parent PID, name, image path, and session id, with structured diagnostics for unsupported fields.
- Windows PE image fact provider for validity, machine, section count, entry point, and image size facts.
- Fixture-backed pattern fact provider for `$name.matches` and `$name.pattern` facts with scan-space and match-context metadata.
- Configurable pattern fixture text input through `rule_engine_client --pattern-fixture <file>`.
- One-shot localhost Asio client session for handshake capability advertisement, subject enumeration, batched fact requests, and fact responses.
- One-shot localhost clients can bind custom fact-batch handlers for descriptor-backed module function routes while keeping clients limited to typed fact responses.
- Client protocol sockets apply bounded read/write timeouts, and fact batch round-trips apply the request timeout advertised in the batch message.
- `rule_engine_client` serves a localhost v1 client session; `rule_engine_server` connects and performs a process/PE fact round-trip smoke path.
- `rule_engine_client` and `rule_engine_server` expose `--io-timeout-ms <ms>` for localhost protocol I/O deadlines.
- Client-backed VM orchestration can evaluate one subject or subject chunks over one connection, batching missing fact requests by provider route across subjects.
- `rule_engine_server --rule <rule.yar>` parses, verifies, evaluates the current process subject or `--all-subjects` with configurable `--subject-concurrency`, and prints per-subject rule results.
- Custom Catch2 test main disables Windows CRT abort/report dialogs so failing tests terminate in console/CTest output instead of blocking on modal UI; a child abort probe regression test verifies unattended aborts do not hang behind a modal dialog.
- CLI targets: `rule_engine_check`, `rule_engine_server`, and `rule_engine_client`.

## Remaining Full-V1 Work

- No currently tracked V1 gaps in this status file.
