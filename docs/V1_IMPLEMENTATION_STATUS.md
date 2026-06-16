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
- Pattern-set `of` expressions for `all`, `any`, `none`, numeric, and percentage quantifiers over rule pattern facts, including `at` and `in` anchor filters over provider-supplied match offsets.
- Boolean tuple `of` expressions for `all`, `any`, `none`, numeric, and percentage quantifiers over condition tuples.
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
- Cache policy tests cover volatile process facts with `0s` TTL separately from static PE image facts, including richer `pe.sections` and `pe.imports` array facts with `30s` TTL.
- Staged scheduler prefetches cheap descriptor facts first and defers expensive scan facts until symbolic evaluation reaches them, allowing cheap process/PE filters to short-circuit before scan requests.
- Cheap descriptor-backed module function calls with statically known arguments lower into deterministic provider fact keys and participate in staged prefetch before expensive facts.
- Versioned deterministic binary IR and schedule artifacts alongside readable dumps, including source tables and per-rule source ids.
- IR and schedule dumps/artifacts include rule namespace names and qualified rule identifiers.
- Versioned `RETR` evaluation trace artifacts capture subject, provider facts, final VM step, opt-in expression trace events, and replay deterministically without TCP or live providers.
- Trace capture snapshots all cached facts for the traced subject, including runtime-derived custom module function facts, so function-call decisions replay without provider access.
- Length-prefixed protocol frame codec.
- Typed v1 protocol payload codecs for handshake capabilities, subject lists, batched fact requests, and fact responses, including pattern match metadata values.
- Windows process subject enumeration.
- Windows process snapshot fact provider for PID, parent PID, thread count, architecture, integrity level, user SID, user name, token elevation, token type, loaded module count/names, memory region counts/region metadata arrays, process name, image path, session id, and command line, with structured diagnostics for unsupported or inaccessible fields.
- Windows process handle fact provider for `process.handles.count` on `endpoint.process.handles`, including access-denied and partial-data diagnostics.
- Windows Authenticode signer fact provider for `process.signer.status` on `endpoint.process.signer`, returning stable status strings from WinTrust results.
- Windows process providers have regression coverage for exited-process lifetime races returning unavailable facts with diagnostics.
- Windows PE image fact provider for validity, machine, section count, entry point, image size, subsystem, file and DLL characteristics, COFF timestamp, `pe.sections` section object arrays, `pe.imports` import object arrays, `pe.exports` export object arrays, `pe.debug_entries` debug directory object arrays, `pe.resources` resource data object arrays, `pe.certificates` certificate-table object arrays, and `pe.tls_callbacks` TLS callback object arrays.
- Windows PE parser regression coverage includes synthetic non-PE, malformed optional-header, truncated optional-header, PE32, and PE32+ fixture images.
- Fixture-backed pattern fact provider for `$name.matches` and `$name.pattern` facts with scan-space and match-context metadata.
- Configurable pattern fixture text input through `rule_engine_client --pattern-fixture <file>`.
- Configurable literal byte scanner in pattern fixture files through `scan` directives, returning real offsets, bytes, before/after context, scan-space names, and region permissions as `PatternValue` metadata.
- File-backed literal byte scanner in pattern fixture files through `scan_file` directives, resolving relative file paths from the fixture file and returning the same `PatternValue` match metadata.
- Rule-derived literal scan plans for text string patterns are attached to pattern fact requests and round-trip through the localhost protocol; `scan_file_space` fixture directives provide file-backed scan spaces without duplicating pattern definitions in client config.
- When no explicit pattern scan spaces are configured, the default Windows client adds subject-scoped `process.image.bytes` scan spaces for pattern requests by reading each requested process image file, with localhost integration coverage for matching the current process PE header.
- One-shot localhost Asio client session for handshake capability advertisement, subject enumeration, batched fact requests, and fact responses.
- Localhost clients can bind custom fact-batch handlers for descriptor-backed module function routes while keeping clients limited to typed fact responses.
- Localhost clients can advertise custom provider route capabilities; evaluator orchestration rejects requests for routes missing from the client handshake.
- Verified programs expose a deduplicated provider-route registry from concrete facts and descriptor-backed function calls; client-backed evaluation preflights that registry against handshake capabilities before subject evaluation starts.
- Client-backed evaluator orchestration validates available provider fact values against descriptor-derived expected types before storing them in the session cache.
- The VM revalidates descriptor-backed cached field/global/pattern facts and function return facts before evaluation consumes them, producing no-match diagnostics for wrong-typed available cache entries.
- Provider function fact keys use a stable v1 argument-token encoder for booleans, integers, floats, strings, bytes, arrays, objects, pattern values, and explicit undefined values.
- `rule_engine_server --module-config <file>` loads custom module field/function/global descriptors before verification; `rule_engine_client --custom-fact-fixture <file>` advertises custom routes and serves configured typed fixture facts.
- `examples/custom_binding/` provides a tested custom descriptor, rule, and client fact fixture covering a custom field, module function binding, provider-backed global, and custom route capabilities.
- `examples/rule_corpus/` provides tested supported and intentionally unsupported YARA examples for the current parser and semantic subset.
- `docs/RUST_BRIDGE_UPDATE.md` documents the Rust YARA-X bridge update workflow, cbindgen header regeneration path, ABI rules, and required Rust/C++ verification commands.
- Field, function, and global descriptors carry provider request timeouts into lowered fact requirements; request batches grouped by route use the maximum descriptor timeout in the batch.
- Client protocol sockets apply bounded read/write timeouts, and fact batch round-trips apply the request timeout advertised in the batch message.
- `rule_engine_client` serves localhost v1 client sessions with a default one-shot mode, bounded `--max-sessions <n>` mode, and unbounded `--serve` mode; `rule_engine_server` connects and performs process/PE fact round trips.
- `docs/TRANSPORT_BOUNDARY.md` documents that the plain TCP protocol is a localhost V1 demo path and lists the authentication, encryption, authorization, retry, cancellation, and payload-boundary work required before remote clients.
- `rule_engine_client` and `rule_engine_server` expose `--io-timeout-ms <ms>` for localhost protocol I/O deadlines.
- Client-backed VM orchestration can evaluate one subject or subject chunks over one connection, batching missing fact requests by provider route across subjects.
- Integration coverage evaluates multiple requested subjects over one localhost client connection with a custom provider route advertised during handshake and requested through the normal capability checks.
- `rule_engine_server --rule <rule.yar>` parses, verifies, evaluates the current process subject or `--all-subjects` with configurable `--subject-concurrency`, and prints per-subject rule results.
- `rule_engine_server --json` emits structured JSON for rule evaluation sessions and client smoke fact sessions, including handshake metadata, capabilities, evaluated subjects, rule results, diagnostics, fact statuses, typed fact values, and TTLs.
- Custom Catch2 test main disables Windows CRT abort/report dialogs so failing tests terminate in console/CTest output instead of blocking on modal UI; a child abort probe regression test verifies unattended aborts do not hang behind a modal dialog.
- CLI targets: `rule_engine_check`, `rule_engine_server`, and `rule_engine_client`.

## Remaining Full-V1 Work

- No currently tracked V1 gaps in this status file.
