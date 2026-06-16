# Rule Engine Goal

Build a Windows-only C++23 rule engine that can parse YARA rules through YARA-X, verify them against C++-owned module descriptors, lower them to a debug-stable symbolic IR, and evaluate them against live process subjects while facts arrive asynchronously from client-side handlers.

The server owns rule semantics. Clients are data providers only: they enumerate subjects and return typed facts or structured diagnostics. A client must never decide whether a rule matches.

## V1 Scope

- Parse YARA syntax with a Rust `yara-x-parser` bridge.
- Keep semantic validation, lowering, scheduling, caching, and execution in C++.
- Support provider-backed facts for process fields, PE image fields, and pattern matches.
- Use a synchronous VM step function that either completes or returns missing fact batches grouped by provider route.
- Use plain localhost TCP framing for v1 server/client demos.
- Record machine-readable and readable diagnostics, schedules, and opt-in traces.

## Non-Goals

- Do not implement a complete native pattern scanner in v1. Pattern facts are fixture/provider supplied.
- Do not let clients evaluate conditions or whole predicates.
- Do not make the debug IR or trace format a permanent public API yet.
- Do not support non-Windows live process providers in v1.
