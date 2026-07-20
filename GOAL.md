# Rule Engine Goal

Build a C++23 rule engine whose authoring language is a statically checked, resource-bounded Python 3.14 subset. C++ owns type checking, lowering, rule semantics, scheduling, optimization, effects, state, correlation, and match decisions. Windows agents only enumerate typed subjects and return requested facts, scans, observations, or diagnostics.

## Product invariants

- Python rule modules are parsed as data by a short-lived, exact CPython 3.14.6 worker; they are never imported or evaluated by CPython.
- Trusted signed generators may execute only in the short-lived worker with declared inputs and deterministic double-run validation. Process limits contain failures and resource abuse, but are not represented as a hostile-code sandbox.
- Rule evaluation runs only in the verified, resumable C++ VM under the immutable `balanced.v1` budget profile.
- Mutable VM values are deep-frozen, schema-checked, labeled, canonical, and acyclic before crossing provider, service, event, effect, or persistence boundaries.
- Reached effects remain ordered and transactional. External actions are dispatched only from a committed durable outbox.
- Protocol v2 uses typed recursive subject identities and never sends a predicate or delegates a rule decision to an agent.
- Production activation is atomic across healthy leased nodes and compares platform-independent semantic hashes before the active generation changes.

## Supported deployment

- Windows 10/Server 2019 or newer, x64: server and agent.
- glibc 2.35 or newer, x86-64: server only.
- PostgreSQL 17 or newer: production runtime store.
- SQLite: explicit single-node development and test store only.

## Non-goals

- Compatibility with YARA syntax, YARA artifacts, protocol v1, or the former Rust parser bridge.
- Treating signed pack authors as hostile. Signer authorization is the production source trust boundary.
- Executing arbitrary Python, dynamic imports, reflection, `eval`, `exec`, ambient filesystem/network/process APIs, or unbounded computation.
- Letting clients evaluate conditions, optimize predicates, or return match decisions.
