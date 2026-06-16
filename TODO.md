# TODO

This file tracks meaningful work beyond the currently implemented V1 scope in
`GOAL.md`. Keep the trust boundary intact for every item: C++ owns rule
semantics and match decisions; clients only return typed facts or structured
diagnostics.

## Provider And Module Binding Hardening

- [x] Advertise custom module/function provider routes in the client handshake instead
  of only advertising the built-in process, PE, and pattern routes.
- [x] Validate provider responses against C++ descriptors: returned field facts must
  match `FieldDescriptor::type`, and returned function facts must match
  `FunctionDescriptor::return_type`.
- [x] Reject evaluator fact requests for routes that are missing from the
  connected client's advertised capabilities.
- [x] Add a descriptor-level route registry so `rule_engine_server` can detect missing
  client capabilities before starting an evaluation session.
- [x] Add CLI/config support for registering custom module descriptors and client fact
  handlers without editing the core test harness.
- [x] Define stable provider key encoding rules for all `ValueType` values, including
  bytes, arrays, objects, and explicit undefined arguments.

## Windows Process Providers

- [x] Implement `process.command_line` with a Windows provider instead of returning a
  v1 diagnostic placeholder.
- [x] Implement `process.handles.count` on `endpoint.process.handles` with structured
  access-denied and partial-data diagnostics.
- [x] Implement `process.signer.status` on `endpoint.process.signer` using Windows
  Authenticode/WinTrust APIs.
- [x] Add tests for process lifetime races where a process exits between subject
  enumeration and fact collection.
- [x] Add richer process facts once the route model is stable:
  - [x] Thread count via `process.thread_count` on `endpoint.process.snapshot`.
  - [x] Architecture via `process.architecture` on `endpoint.process.snapshot`.
  - [x] Integrity level via `process.integrity_level` on `endpoint.process.snapshot`.
  - [x] User/session basics via `process.session_id`, `process.user.sid`, and
    `process.user.name` on `endpoint.process.snapshot`.
  - [x] Loaded modules via `process.modules.count` and `process.modules.names`
    on `endpoint.process.snapshot`.
  - [x] Token metadata via `process.token.elevated` and `process.token.type` on
    `endpoint.process.snapshot`.
  - [x] Memory regions:
    - [x] Region counts via `process.memory.regions.count` and
      `process.memory.regions.readable_count` on `endpoint.process.snapshot`.
    - [x] Region arrays with base, size, state, protection, type, and scan-space
      metadata.

## PE And Image Facts

- [x] Expand the PE provider beyond the current minimal header facts:
  - [x] Sections via `pe.sections` array objects with name, virtual address/size,
    raw data offset/size, characteristics, and readable/writable/executable flags.
  - [x] Imports via `pe.imports` array objects with DLL, name/ordinal, hint,
    lookup RVA, and IAT RVA fields.
  - [x] Exports via `pe.exports` array objects with module, name/ordinal, RVA,
    forwarded flag, and forwarder string fields.
  - [x] Resources via `pe.resources` array objects with type/name/language,
    RVA, size, and code-page fields.
  - [x] Debug directory via `pe.debug_entries` array objects with type,
    timestamp, version, size, and raw-data location fields.
  - [x] TLS callbacks via `pe.tls_callbacks` array objects with index, VA,
    and RVA fields.
  - [x] Certificate table via `pe.certificates` array objects with file
    offset, size, revision, type, and payload size fields.
  - [x] Subsystem via `pe.subsystem`.
  - [x] Characteristics via `pe.characteristics` and `pe.dll_characteristics`.
  - [x] Timestamp fields for the COFF image header via `pe.timestamp`.
- [x] Add section-level array/object values so rules can iterate over PE sections with
  `for in`.
- [x] Add PE parser regression fixtures for malformed, truncated, non-PE, PE32,
  and PE32+ images.
- [x] Separate static image facts from volatile process facts in cache policy
  tests for richer PE routes.

## Pattern Scanning

- Replace fixture-backed pattern facts with a real scanner while preserving the
  final `PatternValue` fact schema.
  - [x] Configured literal byte scanner through `--pattern-fixture` `scan`
    directives, returning real offsets and match context metadata.
  - [ ] Rule-derived scan plans so clients do not need pattern definitions
    duplicated in local fixture/config files.
- Support explicit scan spaces:
  - [x] File bytes through fixture `scan_file` directives.
  - [ ] Process image bytes.
  - [ ] Mapped image sections.
  - [ ] Readable memory regions.
- [x] Preserve match context metadata: offset, length, bytes, before/after context,
  region permissions, and scan-space name.
- [x] Add scheduling controls for expensive scan routes so cheap process/PE filters
  can short-circuit before scanning.

## YARA Expression Coverage

- Implement currently rejected `of` shapes:
  - [x] Boolean tuple `of` expressions such as `any of (true, 1 == 1)`.
  - [x] Anchored pattern-set `of ... at/in` forms.
- Add descriptor-backed implementations for useful built-ins such as integer
  readers (`uint8`, `uint16`, `uint32`, etc.) once scan-space byte facts are
  available.
- Audit YARA-X AST variants after each `yara-x-parser` bump and add bridge tests
  for newly supported expression nodes.
- Expand semantic type inference for more expression forms while keeping dynamic
  fact-backed values symbolic.

## VM, Scheduler, And Caching

- [x] Add provider return-type enforcement at VM cache-fill boundaries so bad clients
  fail closed.
- [x] Prefetch deterministic function facts when all arguments are statically known
  and the descriptor marks the function as cheap.
- [x] Make provider timeout policy explicit per descriptor and per route batch.
- Define descriptor-level retry and cancellation semantics once runtime
  orchestration supports retries and cancellable in-flight provider requests.
- [x] Add replay tests for function-call fact requests and custom provider routes.
- Stabilize the debug IR and trace schemas once the module/provider surface stops
  changing.

## Client And Server Runtime

- [x] Support multi-session client service mode instead of only one-shot localhost
  smoke sessions.
- Add graceful shutdown and cancellation paths for long-running provider requests.
- [x] Make server output available as structured JSON in addition to human-readable
  text.
- [x] Add integration tests that evaluate rules against multiple live subjects
  with custom provider routes and capability negotiation.
- [x] Keep localhost/plain TCP as the V1 demo path, but document the production
  transport boundary before adding remote clients.

## Tooling And Documentation

- Keep `docs/V1_IMPLEMENTATION_STATUS.md` conservative: only mark items complete
  after tests or smoke checks cover them.
- [x] Add examples for custom module descriptors, function bindings, and client
  fact handlers.
- [x] Add a small rule corpus that documents supported and intentionally
  unsupported YARA constructs.
- [x] Add a developer guide for updating the Rust bridge and regenerated
  cbindgen C++ header.
