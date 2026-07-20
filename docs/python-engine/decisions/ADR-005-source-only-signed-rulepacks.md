# ADR-005: Use Deterministic Source-Only, Ed25519-Signed Rule Packs

- Status: accepted for `design-v1`
- Date: 2026-07-20
- Decision owners: integration and packaging lanes
- Implements: `PK1`, `PK3`, `S3`, `I2`, `Q1`
- Detailed design: [architecture/03-rulepacks-and-python-worker.md](../architecture/03-rulepacks-and-python-worker.md)
- Related limitations: [L-001, L-005, L-012, L-016](../LIMITATIONS.md)

## Context

The rewritten engine needs a reviewable deployment unit containing rule/model source, an optional binding generator, declared immutable inputs, exact library dependencies, and generator-only packages. Production clusters must establish provenance, compile locally, compare semantic results across Windows/Linux nodes, activate one generation atomically, and reproduce exactly what was staged later.

A normal ZIP directory, mutable source checkout, dependency version range, or registry lookup cannot establish those properties. Shipping compiler IR would avoid local compilation work but would make a producer compiler and bytecode ABI part of the trust boundary, reduce inspectability, and make cross-platform compiler disagreement invisible.

Generators add a separate problem: they are convenient for large binding sets but actually execute Python. They must run only after source provenance is established, see only declared inputs/dependencies by contract, and produce output that C++ can type-check and compare. The pack signer is operationally trusted; worker resource controls are not an adversarial-code sandbox.

## Decision

Use one deterministic, inspectable, source-only `.rpack` format for production and development packaging.

- The archive is a strictly normalized ZIP-STORE stream with sorted NFC paths, fixed metadata, normalized text, no ambiguous/traversal/colliding entries, and bounded recursive validation.
- A canonical RFC 8785 JSON index records every payload path, media type, size, and SHA-256.
- `SourceDigest` is SHA-256 over a domain-separated canonical index and is independent of signer/key rotation.
- Production root packs are Ed25519-signed over a separate domain plus the canonical index. Operator trust policy binds key IDs to allowed pack-ID prefixes, validity, and revocation.
- Production dependencies are exact embedded `.rpack` source archives addressed by signer-independent digest. No version ranges, live downloads, or runtime pack calls exist.
- `.rpack` contains source, manifest, declared generator inputs, exact dependencies, pure-Python generator wheels, and licenses only. It never contains HIR, bytecode, native modules, or server-generated semantic artifacts.
- Every healthy server node verifies and compiles the source locally. Atomic activation requires equal canonical generator-binding and platform-independent semantic hashes.
- Unsigned packs are accepted only under an explicit local development mode and cannot be promoted through the production activation API.
- A `kind = "library"` pack exports models/helpers/templates only and compiles privately into its consumer. It cannot activate concrete entrypoints or run a generator.
- A `kind = "rules"` pack may contain static bindings and one optional trusted Python generator.
- Generation occurs after static template/model compilation. A generated, pack-specific typed SDK exposes only declared inputs and template factories. C++ deep-validates every proposed binding.
- The generator runs twice in fresh short-lived private CPython processes with different hash seeds. Canonical output sorted by binding ID must be byte-equal. Activation also compares it across nodes.
- Generator packages are exact root-signature-covered, hash-pinned `py3-none-any` wheels. Native wheels, bytecode, `.pth`, startup customization, and ambient packages are rejected.

The byte-level archive, manifest, signature message, worker/generator API, verification sequence, and limits are fixed in architecture 03.

## Primary reasons

1. **Authorized provenance:** Hashes detect change; Ed25519 trust policy identifies an operator-authorized source signer.
2. **Reproducibility:** Canonical archive bytes and signer-independent content identity support audit, cache, rollback, and independent rebuilding.
3. **Local semantic authority:** Each node uses its trusted local compiler and validates agreement instead of trusting foreign IR.
4. **Hermetic dependencies:** Exact embedded source prevents activation behavior from changing when a registry, branch, or package index changes.
5. **Inspectability:** Operators can review all executable rule/generator source and immutable inputs without reverse engineering bytecode.
6. **Cross-platform safety:** A platform-dependent generator/compiler result blocks cluster activation rather than creating mixed semantics.
7. **Clean consumer ownership:** Source libraries specialize and carry state inside each consumer unless an explicit shared capability says otherwise.
8. **Practical generation:** Typed Python generation handles data-driven binding sets while double-run comparison and C++ validation constrain its artifact.

## Rejected alternatives

### Ship only precompiled bytecode/IR

Rejected because it would trust the producer compiler, require a stable public executable ABI, hide source-to-IR disagreement, and complicate platform-independent validation. Local compilation is intentional even when cached.

### Ship source plus trusted precompiled IR and prefer the IR

Rejected because source and IR can disagree, creating two authorities. A local cache may store derived artifacts keyed by every compiler/runtime input, but the pack itself contains no authoritative IR.

### Use an ordinary ZIP without canonicalization

Rejected because filesystem enumeration, timestamps, permissions, separators, Unicode normalization, compression, and comments produce different bytes and path interpretations for identical logical source.

### Use SHA-256 digests without signatures

Rejected because integrity alone does not establish who was authorized to introduce the content. A malicious replacement can publish a new valid digest.

### Fetch dependencies from a registry at build/activation/runtime

Rejected because it adds mutable resolution, network availability, credential, substitution, and rollback risks. Digest-pinned embedded dependencies make the closure complete.

### Permit semantic-version ranges

Rejected because a range is not a reproducible program. Version is useful metadata; only exact content selects code.

### Share a live library-pack runtime

Rejected because it creates cross-consumer version, state, capability, fault, and activation coupling. Explicit shared state/history capabilities are clearer and operator-controlled.

### Allow native generator wheels

Rejected because native code evades the private-Python reproducibility/import boundary, creates per-platform ABI differences, and expands the trusted execution surface.

### Run the generator once

Rejected because ordinary Python iteration, environment, or accidental ambient inputs can produce unstable binding sets. Two fresh distinct hash seeds detect common nondeterminism before compilation/activation.

### Replace generators with arbitrary build scripts

Rejected because arbitrary scripts have no typed output, declared-input contract, standardized limits, cross-node comparison, or source provenance integration.

### Replace generators with a declarative-only format now

Rejected because real binding construction may need validated transformation and iteration. A declarative generator remains a future stronger-assurance option if double-run trusted Python proves inadequate.

### Require AppContainer/LPAC as the pack security boundary

Rejected for this design because production source comes from trusted signed operators. Job Objects/rlimits and import/audit guards protect reliability and cooperative determinism, not hostile execution. Untrusted third-party submission would require a separate sandbox/container threat model.

## Consequences

### Positive

- Every activated generation has a complete, inspectable, content-addressed source record.
- Signer rotation does not invalidate content identity, while the archive records exact provenance.
- Builds and signatures can be independently reproduced.
- Cluster nodes can detect generator, compiler, Unicode, modeled-library, or platform disagreement before cutover.
- Dependency and library state cannot change behind an active consumer.
- Production servers need no package registry or Python package installer.

### Negative

- Packs can be larger because source dependencies and pure-Python wheels are embedded.
- Every node performs local verification/compilation, and generators run at least twice per cache miss.
- Strict canonicalization rejects archives that ordinary ZIP tools consider valid.
- Key provisioning, scoping, rotation, and revocation become required operational responsibilities.
- Exact dependency upgrades require rebuilding and resigning the consumer pack.
- Generator inputs must be captured into the signed artifact rather than queried live.

## Operational and security implications

- Signing should occur in CI/offline key infrastructure. Servers store public trust policy only.
- Audit records include source digest, signer/trust outcome, dependency/wheel/input digests, generator hashes/seeds, compiler/runtime identities, and semantic/binding hashes.
- Revoked, expired, unknown, or out-of-scope signatures fail staging. Operators use the admin/quarantine path for already active content according to incident policy.
- Archive validation is streaming and bounded before extraction/allocation to address traversal, collision, malformed ZIP, recursion, and expansion attacks even though source is signed.
- Root signatures cover dependencies/wheels/inputs byte-for-byte, but C++ still validates every nested format and type.
- Unsigned development generations are permanently marked and barred from production promotion.
- Generator audit/import guards and process limits are defense in depth. They must not be advertised as protecting against a malicious trusted key holder.
- Cache entries are derived, never authoritative; cache keys include every semantic/runtime/platform input and cached bindings are revalidated.

## Known limitations introduced

- A signed malicious generator is outside the security guarantee.
- Double-run equality is not a proof of determinism.
- Staging latency and artifact size increase due to local compilation, duplicate generation, and embedded closure.
- Pure-Python wheels only; native extension ecosystems are unavailable.
- Dependency ranges, registry resolution, and live library services are unavailable.
- Key rotation changes archive bytes even though source identity stays stable.
- Cross-platform generator differences block activation rather than selecting per-platform bindings.
- Generator source cannot intentionally inspect live deployment state; operator capabilities are bound after static generation.
- No automatic YARA migration content is embedded or generated.

## Evidence and validation

The decision is validated by:

- byte-identical pack builds across Windows/Linux, roots, file enumeration order, and source line endings;
- golden ZIP/index/source-digest/Ed25519 vectors;
- exhaustive path, Unicode/case collision, malformed archive, tamper, recursion, dependency graph, signature, scope, validity, and revocation tests;
- offline builds/activation with registry/network unavailable;
- exact dependency diamond/two-version/isolation tests;
- wheel content/tag/hash/native/startup-code rejection tests;
- generator distinct-hash-seed nondeterminism, forged-output, type, input, limit, and cache-key tests;
- clean install tests with no system Python, ambient packages, Rust, or Cargo;
- equal canonical binding and semantic hashes from supported Windows and Linux nodes before atomic activation.

Evidence is linked from `TRACEABILITY.md` to `PK1`, `PK2`, `PK3`, `S3`, `I2`, and `Q1`.

## Conditions for revisiting

- Add an alternative pack container only if it retains canonical path semantics, signer-independent content identity, offline inspectability, exact dependency closure, and signature-policy equivalence.
- Add signed precompiled artifacts only after defining a stable verifier-enforced executable ABI, source-to-IR binding proof, producer compiler trust model, and cross-platform policy. Source remains authoritative.
- Add native generator packages only with a separately versioned, sandboxed, reproducible per-platform build/runtime model.
- Replace double-run Python generation with a declarative language if packs come from less-trusted authors or nondeterminism remains operationally common.
- Introduce online dependency resolution only if there is a concrete operational requirement and a new immutable transparency/pinning/availability design.
- Treat pack source as adversarial only after adopting an explicit OS/container sandbox and threat model; this ADR's trust assumption must then be superseded, not silently weakened.
