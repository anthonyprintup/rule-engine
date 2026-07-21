# Rule Engine

Rule Engine is a C++23 engine whose authoring language is a statically checked,
resource-bounded subset of Python 3.14. The repository contains one rule
language and one runtime path: there is no YARA compatibility frontend or
translation layer.

C++ owns every security-relevant semantic decision. A short-lived, exact
CPython 3.14.6 worker converts source into a bounded syntax envelope, but static
rule modules are never imported or evaluated by CPython. The C++ compiler binds,
type-checks, lowers, verifies, optimizes, and executes rules in a resumable VM.
Remote agents enumerate typed subjects and return requested facts, scans,
observations, or diagnostics; they never receive predicates or return verdicts.

The full design, rationale, rejected alternatives, and known limitations are in
[`docs/python-engine/`](docs/python-engine/README.md). The architecture documents
describe the product target. [`IMPLEMENTATION_STATUS.md`](docs/python-engine/IMPLEMENTATION_STATUS.md)
is the authoritative record of what the current tree has implemented and
verified.

## Core invariants

- Production rule packs are canonical, source-only archives authenticated by an
  operator trust policy and Ed25519 signatures.
- Static Python source is parsed as data in a private worker process and then
  compiled by C++; CPython never supplies rule semantics.
- Trusted generators may execute only after signature authorization, with
  declared inputs, a cleared environment, exact runtime validation, bounded
  framing, process-tree limits, and deterministic double-run validation.
- Rule execution occurs only in the verified C++ register VM under a named,
  immutable budget profile.
- Values are typed, labeled, canonical, acyclic, and deep-frozen before crossing
  provider, service, event, effect, or persistence boundaries.
- Reached effects remain ordered and transactional. External actions originate
  only from a committed durable outbox.
- Protocol v2 uses TLS 1.3 mutual authentication, typed recursive subject
  identities, leases, sequence fencing, and durable agent spooling.
- Pack activation is generation-fenced so old and new semantics cannot own the
  same work concurrently.

## Authoring model

Rules use ordinary typed Python syntax over engine-provided declarations. For
example:

```python
from rule_engine import Identity, Model, Sensitive, provider_fact, rule


class Process(Model):
    pid: Identity[int]
    creation_time: Identity[int]
    image_path: Sensitive[str]
    is_signed: bool = provider_fact(route="process.signer.is_signed")


@rule("com.example.process.unsigned")
def unsigned_process(process: Process) -> bool:
    return not process.is_signed
```

The decorator, annotations, model, identity fields, label, and provider route are
static declarations. Unsupported dynamic Python constructs fail compilation
with stable source diagnostics. The precise accepted subset is specified in
[`02-authoring-language-and-types.md`](docs/python-engine/architecture/02-authoring-language-and-types.md),
and the current compiler coverage and remaining gaps are listed in the
implementation status.

The complete source-only example is
[`examples/python/unsigned_process/`](examples/python/unsigned_process/README.md).
Versioned PEP 561 authoring and trusted-generator packages live under
[`sdk/`](sdk/README.md).

## Python worker safety boundary

The private worker is an availability boundary, not a hostile-code sandbox.
Static rule modules are never executed, which keeps ordinary rule authors
outside the Python execution boundary. A generator does execute Python, so its
signer must be explicitly trusted to authorize generation for that pack scope.
Worker isolation, resource limits, import restrictions, and double-run checks
reduce operational risk but do not make a malicious authorized generator safe.

If untrusted parties must be allowed to submit executable generators, run that
operation inside a separately administered OS or container sandbox. Do not
weaken the signer policy or treat the worker process controls as that sandbox.

## Repository layout

- `include/rule_engine/python/` — public Python-engine C++ contracts.
- `src/python/packaging/` — canonical packs, trust, exact runtime, and worker.
- `src/python/compiler/` — syntax-envelope decoding, binding, typing, lowering,
  and bytecode verification.
- `src/python/vm/` — bounded values, resumable execution, structured tasks, and
  faults.
- `src/python/effects/` and `src/python/events/` — journals, services, replay,
  labels, typed events, history, state, and correlation.
- `src/python/optimizer/` — effect-aware planning and bounded RE2 scanning.
- `src/python/protocol/` and `src/python/windows/` — protocol v2, secure
  transport/spool, and typed Windows providers.
- `src/python/cluster/` and `src/python/runtime/` — durable stores, fencing,
  activation, coordination, and resident orchestration.
- `src/python/tools/` — pack, check, admin, diagnostics, and redaction command
  surfaces.
- `sdk/`, `examples/python/`, and `docs/python-engine/` — authoring packages,
  examples, and the durable specification.
- `tests/python_*` — component and cross-component qualification.

## Supported deployment target

- Windows 10 or Windows Server 2019 and newer, x64: server and agent.
- glibc 2.35 or newer, x86-64: server only.
- PostgreSQL 17 or newer: production runtime store.
- SQLite: explicit single-process development and test store.

Windows is the locally qualified platform in the current tree. Linux and live
PostgreSQL qualification remain visible gates until their evidence is recorded
in the implementation status.

## Build requirements

- CMake 3.31 or newer
- Ninja 1.13.2 or newer (Ninja 1.12.1 is not supported for this graph on
  Windows because its dyndep handling can assert during concurrent builds)
- a C++23 compiler
- OpenSSL 3 or newer for TLS and Ed25519 operations
- SQLite development support (Windows system SQLite is supported)
- PostgreSQL 17 client development files for production-store builds
- network access during first configure for pinned C++ dependencies, or a
  pre-populated CMake dependency cache

Rust, Cargo, cbindgen, a YARA implementation, and a system Python installation
are not build dependencies.

Configure and build from a developer environment:

```powershell
cmake -S . -B build/debug -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build/debug
```

Tests that exercise the real worker require the official CPython 3.14.6 Windows
x64 embeddable archive and its extracted contents. Pass their explicit paths at
configure time; the engine never falls back to a system interpreter:

```powershell
cmake -S . -B build/debug -G Ninja `
  -DCMAKE_BUILD_TYPE=Debug `
  -DRULE_ENGINE_PYTHON_RUNTIME_ARCHIVE=C:/cache/python-3.14.6-embed-amd64.zip `
  -DRULE_ENGINE_TEST_PYTHON_RUNTIME_ARCHIVE=C:/cache/python-3.14.6-embed-amd64.zip `
  -DRULE_ENGINE_TEST_PYTHON_RUNTIME_ROOT=C:/cache/python-3.14.6
cmake --build build/debug
ctest --test-dir build/debug --output-on-failure
```

Production builds should require the secure protocol dependencies rather than
accepting dependency-unavailable stubs:

```powershell
cmake -S . -B build/release -G Ninja `
  -DCMAKE_BUILD_TYPE=Release `
  -DBUILD_TESTING=OFF `
  -DRULE_ENGINE_PROTOCOL_REQUIRE_SECURE_RUNTIME=ON `
  -DRULE_ENGINE_INSTALL_PRIVATE_PYTHON=ON `
  -DRULE_ENGINE_PRIVATE_PYTHON_RUNTIME_ROOT=C:/cache/python-3.14.6
cmake --build build/release
cmake --install build/release --prefix C:/rule-engine
```

The install contains `rule_engine_pack`, `rule_engine_check`,
`rule_engine_admin`, `rule_engine_server`, `rule_engine_agent`, and
`rule_engine_benchmark`. Each executable accepts `--help` and `--version`; no
legacy rule or protocol entrypoint is installed. Exact authoring, signing,
server, agent, and deployment commands are in
[`OPERATIONS.md`](docs/python-engine/OPERATIONS.md). Package layout and
relocation guarantees are in [`cmake/INSTALL_PACKAGE.md`](cmake/INSTALL_PACKAGE.md).

## Clean break from YARA

Existing YARA rules and protocol-v1 clients are intentionally incompatible.
There is no parser fallback, feature flag, compatibility artifact, or automatic
translator. Rewrite rules against the typed Python SDK and re-enroll agents for
protocol v2. Historical design discussion may mention the removed system only
to explain the clean-break decision; no live source, fixture, target, or runtime
path supports it.

## Design and operational references

- [`GOAL.md`](GOAL.md) — product invariants and deployment target.
- [`docs/python-engine/CONTRACTS.md`](docs/python-engine/CONTRACTS.md) — frozen
  cross-component contracts.
- [`docs/python-engine/LIMITATIONS.md`](docs/python-engine/LIMITATIONS.md) —
  impacts, mitigations, observability, and revisit criteria.
- [`docs/python-engine/decisions/`](docs/python-engine/decisions/) — accepted
  architecture decisions and rejected alternatives.
- [`docs/python-engine/architecture/10-verification-and-cutover.md`](docs/python-engine/architecture/10-verification-and-cutover.md)
  — release qualification and removal gates.
