# TODO

This file tracks meaningful work beyond the currently implemented V1 scope in
`GOAL.md`. Keep the trust boundary intact for every item: C++ owns rule
semantics and match decisions; clients only return typed facts or structured
diagnostics.

## Provider And Module Binding Hardening

- Advertise custom module/function provider routes in the client handshake instead
  of only advertising the built-in process, PE, and pattern routes.
- Validate provider responses against C++ descriptors: returned field facts must
  match `FieldDescriptor::type`, and returned function facts must match
  `FunctionDescriptor::return_type`.
- Add a descriptor-level route registry so `rule_engine_server` can detect missing
  client capabilities before starting an evaluation session.
- Add CLI/config support for registering custom module descriptors and client fact
  handlers without editing the core test harness.
- Define stable provider key encoding rules for all `ValueType` values, including
  bytes, arrays, objects, and explicit undefined arguments.

## Windows Process Providers

- Implement `process.command_line` with a Windows provider instead of returning a
  v1 diagnostic placeholder.
- Implement `process.handles.count` on `endpoint.process.handles` with structured
  access-denied and partial-data diagnostics.
- Implement `process.signer.status` on `endpoint.process.signer` using Windows
  Authenticode/WinTrust APIs.
- Add tests for process lifetime races where a process exits between subject
  enumeration and fact collection.
- Add richer process facts once the route model is stable: architecture,
  integrity level, user/session details, loaded modules, token metadata, memory
  regions, and thread counts.

## PE And Image Facts

- Expand the PE provider beyond the current minimal header facts to sections,
  imports, exports, resources, debug directory, TLS callbacks, certificate table,
  subsystem, characteristics, and timestamp fields.
- Add section-level array/object values so rules can iterate over PE sections with
  `for in`.
- Add PE parser regression fixtures for malformed, truncated, non-PE, PE32, and
  PE32+ images.
- Separate static image facts from volatile process facts in cache policy tests
  for richer PE routes.

## Pattern Scanning

- Replace fixture-backed pattern facts with a real scanner while preserving the
  final `PatternValue` fact schema.
- Support explicit scan spaces such as process image bytes, mapped image sections,
  readable memory regions, and file bytes.
- Preserve match context metadata: offset, length, bytes, before/after context,
  region permissions, and scan-space name.
- Add scheduling controls for expensive scan routes so cheap process/PE filters
  can short-circuit before scanning.

## YARA Expression Coverage

- Implement currently rejected `of` shapes such as boolean tuple `of` and anchored
  `of ... at/in` forms.
- Add descriptor-backed implementations for useful built-ins such as integer
  readers (`uint8`, `uint16`, `uint32`, etc.) once scan-space byte facts are
  available.
- Audit YARA-X AST variants after each `yara-x-parser` bump and add bridge tests
  for newly supported expression nodes.
- Expand semantic type inference for more expression forms while keeping dynamic
  fact-backed values symbolic.

## VM, Scheduler, And Caching

- Add provider return-type enforcement at VM cache-fill boundaries so bad clients
  fail closed.
- Prefetch deterministic function facts when all arguments are statically known
  and the descriptor marks the function as cheap.
- Make provider timeout, retry, and cancellation policy explicit per descriptor.
- Add replay tests for function-call fact requests and custom provider routes.
- Stabilize the debug IR and trace schemas once the module/provider surface stops
  changing.

## Client And Server Runtime

- Support multi-session client service mode instead of only one-shot localhost
  smoke sessions.
- Add graceful shutdown and cancellation paths for long-running provider requests.
- Make server output available as structured JSON in addition to human-readable
  text.
- Add integration tests that evaluate rules against multiple live subjects with
  custom provider routes and capability negotiation.
- Keep localhost/plain TCP as the V1 demo path, but document the production
  transport boundary before adding remote clients.

## Tooling And Documentation

- Keep `docs/V1_IMPLEMENTATION_STATUS.md` conservative: only mark items complete
  after tests or smoke checks cover them.
- Add examples for custom module descriptors, function bindings, and client fact
  handlers.
- Add a small rule corpus that documents supported and intentionally unsupported
  YARA constructs.
- Add a developer guide for updating the Rust bridge and regenerated cbindgen C++
  header.
