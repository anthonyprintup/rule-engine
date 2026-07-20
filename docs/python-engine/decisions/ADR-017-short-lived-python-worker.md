# ADR-017: Use One Short-Lived Private CPython Worker per Parse or Generate Request

- **Status:** Accepted for design-v1
- **Date:** 2026-07-20
- **Owners:** Packaging/worker and compiler integration
- **Related:** ADR-002, ADR-003, ADR-005, `architecture/01-trust-and-threat-model.md`, limitations L-001/L-004/L-005

## Context

The engine needs exact Python 3.14 grammar and AST behavior, while C++ must own rule semantics. CPython's parser is the canonical grammar implementation, but embedding it into the long-lived server would share its stack, allocator, global interpreter/import state, environment discovery, and crash domain. Python's `ast` documentation warns that sufficiently large or complex input can crash the interpreter due to stack depth.

Optional generators must execute real Python after signature verification. A persistent process would allow imports, module globals, caches, monkey patches, file descriptors, allocator damage, and environment state from one pack/request to affect later requests. It would also make worker upgrade/restart and deterministic double-run isolation harder.

The worker has two materially different modes:

- `parse`: parse rule/model modules and serialize AST data; never import or execute them.
- `generate`: execute one verified generator against declared inputs and a typed binding SDK.

The design needs crash isolation, deterministic inputs, bounded resources, exact runtime selection, and a narrow validated IPC contract without implying that process limits securely sandbox hostile signed Python.

## Decision

Ship one small worker executable backed by an exact private CPython 3.14.6 runtime. The server launches a fresh process for exactly one `parse` or `generate` request and never embeds CPython in the long-lived server.

The worker:

- selects one explicit mode at process startup and cannot switch modes;
- reads one bounded length-prefixed UTF-8 JSON request and writes one bounded length-prefixed UTF-8 JSON response;
- runs with a cleared, explicitly constructed environment and private runtime paths;
- never falls back to system Python, registry installs, `PATH`, `PYTHONHOME`, `PYTHONPATH`, user site, ambient `site-packages`, or current-directory imports;
- terminates after the response or any failure;
- is killed as a complete process tree when a deadline, resource cap, cancellation, framing error, or parent-lifetime condition occurs;
- returns only a versioned data envelope that C++ validates completely before use.

Windows uses a kill-on-close Job Object and applicable process memory/CPU controls. Linux uses `setrlimit`/`prlimit`, parent-death handling, process-group termination, and deployment cgroups. These controls isolate failures and bound ordinary resource abuse; they are not AppContainer/LPAC or a hostile-code sandbox.

## Runtime identity and packaging

- Pin CPython `3.14.6` and the Unicode database it contains.
- Windows uses the official x64 embeddable package with SHA-256 `df901e84a896ff1ee720ad03377e0c8d8c2244fda79808aeeaff6316df1cb75c`.
- Linux uses a relocatable private build from source SHA-256 `143b1dddefaec3bd2e21e3b839b34a2b7fb9842272883c576420d605e9f30c63`, built by a pinned reproducible recipe for glibc 2.35+ x86-64.
- Package/runtime hash, worker protocol version, Python patch version, Unicode version, compiler ABI, and platform ABI participate in artifact/cache identity.
- A patch/runtime change forces local recompilation; the engine never silently accepts an AST or generator cache produced by a different identity.

## Mode contracts

### Parse mode

Input contains protocol/runtime version, module logical path, `source_utf8_b64`, source digest, parse flags, and limits. Pack canonicalization has already normalized line endings and required strict UTF-8. The worker strictly decodes base64, verifies the declared digest, decodes UTF-8 without normalization or replacement, and passes that exact text to `ast.parse`; C++ retains the canonical source bytes used to interpret CPython's UTF-8 byte offsets.

The worker calls the pinned parser equivalent of:

```python
ast.parse(
    source,
    filename=logical_path,
    mode="exec",
    type_comments=True,
    feature_version=(3, 14),
)
```

It serializes every AST node kind and declared field, `type_ignores`, exact constants, locations, and syntax diagnostics into the versioned response. Constants use tagged representations so booleans, arbitrary integers, binary64 floats, strings including escaped surrogates, bytes, `None`, and ellipsis cannot be confused by JSON number/string behavior.

Parse mode must not:

- call `compile` on the rule module;
- import the rule module or execute any top-level expression/decorator;
- resolve pack imports or names;
- decide supported semantics or types;
- generate Python bytecode;
- access source beyond the bytes provided in the request.

C++ owns UTF-8 source storage and verifies every node tag, field, scalar, nesting level, count, location, and byte-span boundary before binding.

### Generate mode

Input contains the verified pack/source/dependency identity, generator entrypoint, typed template/model descriptors, declared immutable input blobs, locked pure-Python wheel closure, selected hash seed, and limits.

Generate mode may import only:

- the generator's verified pack-local module closure;
- embedded digest-pinned source dependencies;
- the generated typed binding SDK;
- the bundled standard library allowlist;
- validated locked `py3-none-any` wheels.

It emits only typed binding records referencing already compiled templates. C++ rejects unknown templates, forged object types, duplicate/invalid stable IDs, type/schema mismatches, undeclared capabilities, and oversized output.

The pack compiler invokes generation twice in fresh processes with different hash seeds, canonicalizes results by binding ID, and accepts only byte-identical canonical binding content. A cached success is keyed by pack/source/input/dependency/runtime/compiler/platform identity.

## IPC and process lifecycle

```mermaid
sequenceDiagram
    participant S as Server / pack compiler
    participant L as Worker launcher
    participant W as Fresh CPython worker

    S->>S: Verify source/signature before generate mode
    S->>L: Mode, exact runtime, request, limits, cancellation
    L->>L: Create pipes + process containment before resume
    L->>W: Start with cleared explicit environment
    S->>W: One length-prefixed versioned request
    alt Parse
        W->>W: ast.parse only; serialize AST
    else Generate
        W->>W: Execute verified generator; serialize bindings
    end
    W-->>S: One bounded response
    S->>S: Validate frame, schema, identities, spans/types/limits
    W-->>L: Exit
    L->>L: Close containment and confirm process-tree exit
    alt Timeout, cancel, crash, protocol error, excess output
        L->>W: Terminate complete process tree
        S->>S: Discard all partial output and diagnose
    end
```

Lifecycle invariants:

1. Containment is configured before the child can execute worker code.
2. Generate mode cannot start until `VerifiedRulePack` exists.
3. One worker handles exactly one request.
4. One response is accepted only after clean framing, schema validation, allowed exit status, and EOF/process exit.
5. Partial output is never usable.
6. Parent cancellation or death cannot leave an unbounded orphan tree.
7. Worker stdout is protocol-only; bounded stderr/diagnostics are captured separately and sanitized before user/audit display.

## Limits and termination

Default compile-profile worker ceiling is 512 MiB memory and 15 seconds wall time. Source is capped at 16 MiB, returned AST at 1,000,000 nodes plus protocol byte limits, generated bindings at 100,000, and generator arguments at 64 MiB. The concrete protocol also caps frame length, nesting, scalar bytes, diagnostics, stderr, open files/handles where supported, and child process count/tree consumption.

The launcher maps outcomes to stable diagnostics:

- normal successful exit and valid envelope;
- Python syntax error;
- worker protocol/runtime mismatch;
- malformed/truncated/excess response;
- wall timeout or cancellation;
- CPU/memory/process/output limit;
- signal/exception/crash or abnormal exit;
- launcher/runtime missing or digest mismatch;
- internal C++ validation failure.

Every non-success discards the whole result. Retry is an explicit compiler/operation policy; the launcher does not silently retry generation and accidentally accept a different result.

## Primary reasons

1. **Server crash isolation:** Parser stack/allocator faults do not share the coordinator process.
2. **Request isolation:** Module/import/global/allocator state cannot leak between packs or double-run attempts.
3. **Exact runtime selection:** The launcher controls the private executable/runtime rather than ambient machine configuration.
4. **Determinism evidence:** Fresh processes with different seeds make generator comparison meaningful.
5. **Resource enforcement:** OS process boundaries provide enforceable wall/process-tree and memory controls unavailable to purely in-process accounting.
6. **Narrow semantic boundary:** The worker returns data; C++ remains authoritative for syntax support, binding, typing, lowering, and execution.
7. **Operational upgrades:** Worker/runtime ABI can be versioned, replaced, and health-tested independently of active VM sessions.

## Rejected alternatives

### Embed CPython in the server

Rejected because a parser/runtime crash or stack exhaustion would threaten the server, Python global state/environment would share the trust domain, and generator code would inherit the server process's authority.

### Maintain a persistent worker pool

Rejected initially because reuse introduces cross-request imports/globals/caches/descriptors, requires a trustworthy reset protocol, weakens double-run independence, and increases crash blast radius. Process startup cost is accepted at pack compilation time, which is not the per-fact hot path.

### Implement the entire Python parser in C++

Rejected because tracking the complete pinned 3.14 grammar, AST quirks, source locations, and future maintenance would be expensive and error-prone. The standard parser is used only as a data producer.

### Consume CPython bytecode instead of AST

Rejected because compiling executes more Python machinery, bytecode is not the intended stable semantic interchange, source typing/model rules would be harder to validate, and C++ must define its own verified instruction set.

### Use JSON lines or stdout scraping

Rejected because truncation, embedded newlines, mixed logging, unbounded allocation, and ambiguous scalars weaken framing/validation. The protocol is explicitly length-prefixed and stdout is reserved.

### Use AppContainer/LPAC on Windows and call the worker sandboxed

Rejected for design-v1. The source is operationally trusted, Linux requires a comparable independently specified boundary, and AppContainer integration would add broker/packaging policy not required for reliability containment. No security claim is made from Job Objects or `rlimit`.

### Run parse/generate in the Windows agent

Rejected because it would distribute compiler inputs/trust policy, expand the semantic surface to clients, and create cross-peer parser/runtime drift.

## Consequences

### Positive

- CPython crashes and ordinary resource exhaustion are contained to one compile operation.
- Generator attempts are isolated from one another and from later packs.
- The server can validate a small versioned data boundary rather than host the Python C API.
- Runtime provenance and cache invalidation are explicit.
- Rule evaluation remains independent of CPython availability once a pack is compiled.

### Negative

- Starting processes and transferring complete ASTs adds compile latency and IPC memory/serialization cost.
- Packaging exact private runtimes on Windows/Linux increases build, update, SBOM, signing, and vulnerability-management work.
- AST protocol evolution must track every pinned Python node/field and constant representation.
- Worker diagnostics can differ from final C++ semantic diagnostics and require careful source correlation.
- Process containment APIs differ across Windows and Linux and need platform-specific test harnesses.

## Failure modes and response

| Failure | Detection | Response |
|---|---|---|
| Private runtime absent or wrong hash/version | Launcher preflight/handshake | Do not spawn/accept output; emit deployment diagnostic and mark node not ready for that ABI. |
| Syntax error | Structured worker diagnostic | Map exact UTF-8 source span; fail compilation without retry. |
| Parser stack/memory crash | Exit/signal/exception/job notification | Kill tree, discard partial response, emit bounded crash/limit diagnostic; server remains healthy. |
| Generator hangs or forks | Deadline/job/cgroup/process-tree observation | Terminate complete tree and reject pack staging. |
| Output exceeds limit | Framing/read accounting | Stop reading, kill tree, discard response, report relevant cap. |
| Worker emits malformed/unknown AST field | C++ decoder/schema validation | Treat as worker protocol fault; never bind partial AST. |
| Parent canceled/dies | Cancellation/parent-death/job lifetime | Terminate or orphan-proof full tree; no activation result. |
| Generator runs differ | Canonical C++ comparison | Reject as nondeterministic; report first bounded difference by binding ID/field. |
| Cache identity mismatch | Full cache key/embedded identity | Ignore stale cache and rerun both workers. |
| Diagnostics contain sensitive/unbounded stderr | Separate bounded channel/sanitizer | Truncate/redact before logs/audits; protocol remains unaffected. |

## Operational and security implications

- The private Python distribution is a shipped production dependency with pinned provenance, SBOM entries, security patch ownership, and readiness checks.
- Worker binaries/runtime files require integrity verification and filesystem permissions; a modified runtime invalidates compiler readiness.
- Launch telemetry records mode, runtime hash/version, source/input digest, limits, duration, peak resources where available, exit reason, response size/count, and correlation ID—never unrestricted source or secrets by default.
- Nodes must compile the active generation before becoming ready; a worker/runtime failure prevents that node from serving the generation.
- Deployment may impose stronger containers/cgroups/service-account/network restrictions, but those remain defense in depth and cannot be advertised as a product hostile-code sandbox without a new ADR.

## Known limitations

- A malicious trusted generator can use authority available to the worker account; Job Objects/`rlimit` do not prevent this (`L-001`).
- Large/deep valid Python may hit stack, memory, node, output, or time caps (`L-004`).
- Fresh double-run equality is evidence, not proof, of determinism (`L-005`).
- Startup/serialization overhead makes this design appropriate for pack compile time, not per-evaluation dynamic code.
- Runtime patch/Unicode upgrades invalidate caches and require recompilation.
- OS containment metrics and exact failure classification can vary by platform.

## Validation evidence required

- Golden coverage for every Python 3.14 AST node/field, type ignore, constant tag, syntax diagnostic, and UTF-8 byte span.
- Test that a rule module with top-level side effects/decorators is parsed without executing those effects.
- Poison `PATH`, `PYTHONHOME`, `PYTHONPATH`, user site, registry, working directory, and ambient packages; prove output/runtime identity is unchanged.
- Force Windows access violation/job termination and Linux signal/limit termination; prove the server survives and the complete child tree exits.
- Force timeout, CPU/memory/output/input/node/depth/diagnostic limits and verify stable bounded errors with no partial acceptance.
- Fuzz request/response framing and AST decoding, including unknown fields, huge lengths, truncation, invalid UTF-8/locations, and scalar type confusion.
- Run concurrent parse/generate operations and verify no cross-request environment, import, source, input, hash seed, or output leakage.
- Verify generation cannot launch before signature/trust success and parse mode cannot import/execute the target module.
- Verify cache invalidation across worker protocol, Python patch, Unicode, compiler ABI, platform ABI, pack, dependency, and input changes.
- Package smoke on clean Windows/Linux hosts with system Python absent and Rust/Cargo absent.

## Traceability

- Architecture: `architecture/03-rulepacks-and-python-worker.md` and `architecture/01-trust-and-threat-model.md`.
- Contracts: worker request/response protocol, `VerifiedRulePack`, AST envelope, generator binding output, runtime/compiler ABI identity.
- Tasks: PK2, PK3, C1, C2, I1, Q1.
- Limitations: L-001, L-004, L-005.
- Acceptance: full AST golden suite, private-runtime/environment tests, worker crash/limit/process-tree tests, generator double-run tests, and clean packaging smoke.

## Revisit conditions

- Reconsider persistent workers only if measured pack-compilation startup cost is unacceptable and a proven hermetic reset/isolation protocol preserves all invariants.
- Reconsider the standard parser only if its compatibility/packaging cost exceeds implementing and maintaining exact grammar/source behavior independently.
- Add a hostile-code sandbox only if untrusted generators become a requirement; doing so requires a new cross-platform threat model and must not reuse Job Object/`rlimit` language as the security claim.
- Update runtime pins only through a versioned compiler/runtime ABI, differential conformance suite, cache invalidation, and cluster semantic-hash qualification.

## References

- [Python 3.14.6 release and source/runtime artifacts](https://www.python.org/downloads/release/python-3146/)
- [Python 3.14 AST documentation and parser resource warning](https://docs.python.org/3.14/library/ast.html#ast.parse)
- [Microsoft Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)
- [Linux `getrlimit` and `setrlimit`](https://man7.org/linux/man-pages/man2/getrlimit.2.html)
