# Python Engine Qualification Record

This record distinguishes evidence gathered on the implementation host from
the release matrix required by the architecture. A green local cell is not a
waiver for an unavailable platform, database, network, or failure-injection
cell.

## Qualified snapshot

- Date: 2026-07-21 (Europe/Warsaw)
- Branch: `codex/python-dsl-rewrite`
- Tested code/style head: `14e8bf7`
- Host: Windows 11 Pro 10.0.26200, x64
- CMake: 4.3.3
- Ninja: 1.13.2 from the configured CLion toolchain
- clang-cl: 22.1.4
- MSVC: 19.50.35729
- OpenSSL: 4.0.0
- Private parser runtime: CPython 3.14.6, isolated and site-disabled

The pinned runtime is the official [Python 3.14.6 Windows x64 embeddable
package](https://www.python.org/downloads/release/python-3146/). No system
Python fallback is permitted.

## Result matrix

| Cell | Evidence | Status |
|---|---|---|
| Windows Debug, clang-cl | Complete build; 37/37 CTest tests | Passed |
| Windows Debug, MSVC | Complete build; 37/37 CTest tests | Passed |
| Windows Release package | Fresh fully disconnected configure, `BUILD_TESTING=OFF`; 372 build steps; install completed | Passed |
| Installed executable surface | `--version` and `--help` for pack, check, admin, server, agent, and benchmark | Passed |
| Private runtime bundle | Configure-time and install-time manifest validation; exact isolated SDK execution | Passed |
| Author SDK | Pyright 1.1.411: 0 errors/warnings; Ruff 0.15.22: clean; exact-runtime unit suite: 12/12 | Passed |
| Source cutover | Python-only CMake gate; no tracked Rust/Cargo/YARA paths; no live compatibility target | Passed |
| Formatting and C++ policy | clang-format 22.1.4 clean; no project `class` declarations; no project exception/RTTI syntax | Passed |
| Deterministic fuzz regression | Included in optimizer CTest suite | Passed |
| Instrumented fuzzing | clang-cl ASan/libFuzzer, fixed seed, 20,000 runs, no crash or sanitizer finding | Passed |
| 10,000-peer model | Exact/optimized parity clean; all work committed; bounded in-memory queues/spool | Passed for the stated model |
| Linux server/build/package | WSL unavailable; Docker daemon is Windows-container mode only | Not run |
| Linux private runtime | No pinned Linux relocatable-runtime manifest is implemented on this host | Not run |
| PostgreSQL 17 | `psql` and `pg_config` unavailable; guarded adapter compiled only | Not run |
| Mixed Windows-agent/Linux-server | Requires the missing Linux cell | Not run |
| Real multi-process crash/failover | Component fakes and durable local stores are covered; no live multi-node environment | Not run |
| Live 10,000-connection/database scale | Benchmark explicitly reports network and PostgreSQL simulation disabled | Not run |

The architecture's Q1 release gate is therefore **incomplete**. The Windows
implementation and removal gate are locally qualified; Linux, live PostgreSQL,
mixed-OS, and real distributed failure/scale claims are not qualified.

### 2026-07-28 production-readiness continuation

The `codex/python-production-readiness` Debug graph built successfully with
clang-cl and Ninja after adding exact active-pack compilation, the resident
evaluator, and schema-typed custom-event author lowering.
`ctest --test-dir build/Debug --output-on-failure` passed 38/38 tests in
161.07 seconds after connecting the authenticated resident admin v2 lifecycle
and standalone mTLS client. The suite covers snapshot-to-fact-to-match commit, restart
reconstruction from durable snapshot ingress, reconnect work reclamation with
stale-session isolation, durable cross-epoch replay ordering, and the exact
private-worker-to-compiler-to-VM-to-transaction path for a typed custom event.
It also proves deterministic rejection of duplicate event wire IDs, incomplete
event construction, receipt use, and emission of non-event values. This is
Windows-local component, process-restart, admin-codec, and CLI-mapping evidence.
The admin tests prove canonical request/response bounds, every activation phase,
idempotent replay after lost preview/flip responses, and authorization denial
before store access; they do not constitute a live certificate deployment test.
After connecting authenticated resumable source-pack upload, the same complete
Debug graph passed 38/38 tests in 183.92 seconds. Focused upload evidence covers
client resume offsets and chunk identity, authorization before each backend
phase, exact-byte retry, restart resume, canonical archive and signer/pack
verification, cross-process spool serialization, immutable no-replace
content-addressed publication, and lost-finalize replay from durable evidence.
It does not qualify registry quota/retention policy or distributed stage
compilation.
The admin client also passed focused request-transport coverage for bounded
reconnect polling: it follows the authenticated durable operation identity,
uses fresh correlated request IDs, stops on staged/applied/failed phases, and
rejects invalid timeout or interval bounds. This is deterministic client and
codec evidence, not a live network-partition qualification.
The activation control schema then advanced to version 2 with durable resident
node evidence. Focused SQLite restart tests prove canonical node snapshots,
monotonic lease fences, immutable platform/capability identity within one
fence, renewal, successor leases, exact frozen stage targets, stale-report
rejection, restart recovery, all-target semantic/binding agreement, and
fail-closed disagreement without changing the active generation. The resident
couples registration and serving-state updates to its runtime lease claim,
renewal, and release paths. PostgreSQL implements the same transaction and
row-lock contract, but this remains compile evidence until the live PostgreSQL
17 qualification cell runs.
After this schema and staging-foundation slice, the complete Debug graph passed
38/38 tests in 270.82 seconds, including the clean-install/private-runtime
smoke.
The authenticated server-owned stage and live-refresh slice then passed a clean
incremental clang-cl/Ninja build and all 38 Debug tests in 178.84 seconds.
Focused executable-surface coverage proves v4 stage request round trips, CLI
preview/apply mapping, authorization before source resolution, exact durable
target freezing, and activation fencing. The resident background path reopens
the immutable digest, verifies signer and pack identity, compiles with the exact
private worker, appends only fenced server-generated evidence, and detects a
changed durable active identity. The session backend prevents a durable result
from crossing the activation epoch into the old scheduler; an exactly
concurrent committed message is replayed after reconnect. This remains
Windows-local component and process-restart evidence, not the required live
multi-node network, Linux, or PostgreSQL qualification.
The forward rollback slice then passed the complete 38-test Debug graph in
170.03 seconds. Cluster restart coverage proves that rollback preview selects a
retired source, apply reconstructs a new compiling generation on the server,
fresh leased targets are frozen, compilation resumes after restart, and the
existing drain/fence/flip lifecycle activates the new forward generation.
Negative coverage proves that a report whose semantic hash differs from the
retained generation fails the rollback without changing the active generation.
Executable-surface coverage proves v5 codec and CLI mappings plus the
authenticated backend transition; production operator bindings now authorize
stage and rollback only through separate `pack.stage` and `pack.rollback`
capabilities. Non-carry state transitions remain deliberately unavailable.
This evidence does not qualify live
PostgreSQL, multiple server processes, network partitions, Linux, or mixed-OS
operation.

The immutable activation-policy slice then passed the complete 38-test Debug
graph in 171.19 seconds. Focused control-plane coverage proves that the policy
snapshot is durable across restart and changes the stage idempotency
fingerprint. Executable-surface coverage proves deterministic
`activation-policy.v1` hashing across every configured trust, authorization,
schema, budget, retention, trace, capture, service, and sink input, and proves
that changing one input changes the bundle identity. Resident compilation,
report submission, restart readiness, rollback, and live-active identity all
require the exact snapshot. This is raw-byte immutable deployment-policy
evidence; it does not qualify an authenticated policy mutation API, semantic
policy canonicalization, registry lifecycle, or any open distributed platform
cell.

## Artifact identity

| Artifact | SHA-256 |
|---|---|
| `python-3.14.6-embed-amd64.zip` | `df901e84a896ff1ee720ad03377e0c8d8c2244fda79808aeeaff6316df1cb75c` |
| Installed `python314.dll` | `fde89cdb5c2d08ae65de7ef4abca1876c93ba3796002f5ac0bf7e4d4f5a94da0` |

The install manifest validates every bundled runtime entry, not only the DLL
shown above. The two hashes are recorded here as independent anchors for the
downloaded archive and installed runtime.

## Commands and evidence

The principal Windows test commands were:

```powershell
cmake --build build/codex-python-cutover --parallel 6
ctest --test-dir build/codex-python-cutover --output-on-failure

cmake --build build/qualification-msvc-debug --parallel 6
ctest --test-dir build/qualification-msvc-debug --output-on-failure
```

Both suites registered and passed 37 tests. They include the exact-runtime
stage/tamper/path-escape cases, real install and relocation smoke tests,
compiler/VM/effect/event/protocol/store/runtime tests, production CLI signing,
Windows providers, and the Windows agent.

The Release package used clang-cl, Ninja 1.13.2, `BUILD_TESTING=OFF`,
`FETCHCONTENT_FULLY_DISCONNECTED=ON`, and
`RULE_ENGINE_INSTALL_PRIVATE_PYTHON=ON`. All six installed executables returned
version `1.0.0` and accepted `--help`.

The SDK commands were:

```powershell
tests/sdk/run_sdk_tests.ps1 `
  -PrivatePython build/python-runtime/python-3.14.6/python.exe
uvx --from pyright==1.1.411 pyright sdk tests/sdk/authoring_surface.py
uvx --from ruff==0.15.22 ruff check sdk tests/sdk/authoring_surface.py
```

The instrumented fuzzer used the checked-in corpus copied into a build-local
writable directory:

```powershell
build/fuzz-clang/rule_engine_python_scan_fuzzer.exe `
  -seed=195936478 -runs=20000 -max_len=65536 `
  build/fuzz-clang/run-corpus
```

Final fuzzer counters were 402 coverage edges, 929 features, 101 retained
corpus units, and 182 MiB peak RSS. No crash or sanitizer diagnostic occurred.

The stability command was:

```powershell
rule_engine_benchmark --peers 10000 --format json
```

It reported exact/optimized parity with zero mismatches, 10,000 committed work
items, 100 retry attempts, 100 stale-fence rejections, zero ordering
violations, a peak claim/lease batch of 512, 10,000 backpressure transitions
and clears, one peak agent session, and a peak pending spool of two records / 160
bytes. It also reported `resident_network_simulated=false` and
`resident_postgresql_simulated=false`; those flags are why this run cannot be
used as live network or PostgreSQL evidence.

## Qualification interpretation

- Unit/fake coverage proves deterministic component contracts, not a live
  distributed deployment.
- Warning-clean guarded PostgreSQL compilation proves API compatibility, not
  linking, migrations, TLS, concurrency, failover, cancellation, or pooling.
- The Windows private runtime proves the exact parser/generator boundary on
  that platform only.
- The source gate proves the retired implementation is absent from live source
  and packaging; documentation may still name it when explaining the cutover.
- A required unrun cell remains open. It is never converted to a pass by a
  mock, a different platform, or an in-memory benchmark.
