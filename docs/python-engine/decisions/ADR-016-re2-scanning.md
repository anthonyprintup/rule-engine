# ADR-016: Typed Scan Spaces with Literal, Masked-Byte, and RE2 Patterns

- **Status:** Accepted
- **Decision owners:** Compiler, optimizer, protocol, and Windows provider lanes
- **Related tasks:** C2, C3, P1, P3, O1, O2
- **Architecture:** [Facts, Subjects, and Scanning](../architecture/05-facts-subjects-and-scanning.md)

## Context

Dropping YARA removes its pattern declaration and scanning runtime. Rules still need to search executable files and readable process memory without transferring large sensitive regions to the server or allowing agents to evaluate predicates. Pattern work must be statically understood, budgeted, portable, diagnosable, and resistant to pathological regex execution.

## Decision

Provide explicit typed scan spaces on file/image and readable memory-region subjects. A pattern is either a compile-time constant or a typed template/binding argument. Version one supports:

- exact byte literals;
- text literals encoded by the compiler with an explicit encoding and case mode;
- masked-byte sequences using `HH`, `?H`, `H?`, and `??` nibble tokens; and
- regex patterns in an explicitly named RE2 dialect with an allowlisted flag set.

The compiler creates canonical pattern IDs and validates syntax/encoding. The optimizer creates a bounded scan plan containing only subject, scan space, bounds, patterns, required result mode, match/context limits, deadline, and source metadata. The agent executes that plan and returns typed matches or terminal scan status. It receives no predicate and returns no verdict.

The semantic `MatchSet` is immutable, complete, and deterministically ordered. If it cannot be completed within result limits, evaluation receives `ScanResultLimitExceeded`; a truncated result never masquerades as exact. An existential early-exit plan is legal only when compiler use analysis proves that truth is the sole observable result.

## Primary reasons

1. Literal and masked-byte patterns cover common executable and memory signatures without a general pattern language.
2. RE2 intentionally excludes backtracking constructs and supports bounded operational behavior.
3. Typed scan spaces prevent accidental scanning outside an authorized file/range.
4. Agent-side execution avoids transferring whole process memory while preserving C++ verdict ownership.
5. Static/bound patterns allow compile-time diagnostics, planning, hashing, and resource estimation.
6. Exact `MatchSet` semantics prevent undercount and unsafe decisions from silent truncation.

## Rejected alternatives

- **Retain YARA/YARA-X scanning only:** rejected because the rewrite makes a complete clean break and removes Rust/YARA dependencies and semantics.
- **Python `re`:** rejected because rule modules are not executed by CPython and its semantics/backtracking are outside the bounded C++ runtime contract.
- **`std::regex`:** rejected because dialect and worst-case behavior are unsuitable for a cross-platform security-sensitive contract.
- **PCRE/backreferences/lookaround:** rejected because advanced backtracking features undermine predictable bounds and portability.
- **Dynamic patterns from facts/state/services:** rejected because they weaken static planning, caching, privacy analysis, and compile-time validation.
- **Transfer all bytes to the server:** rejected because it increases sensitive-data movement and cannot reliably represent live remote memory.
- **Let the agent return match/no-match:** rejected because it would transfer rule semantics across the trust boundary.
- **Expose truncated `MatchSet` values:** rejected because counts and absence would be unsound.

## Positive consequences

- No YARA or Rust parser/scanner dependency remains.
- Plans and results are typed, bounded, schema-negotiated, and auditable.
- Regex behavior is consistent across Windows and Linux compilation.
- File and live-memory data remain local except for bounded match metadata/context.
- Optimizer existential specialization can reduce scanning while remaining provably equivalent.

## Negative consequences

- Authors lose YARA modifiers/modules and Python-regex features such as backreferences and lookbehind.
- Multiple encodings must be requested explicitly rather than inferred.
- Dynamic IOC construction must occur at pack-generation/binding time, not evaluation time.
- Complete high-cardinality result use can fault on match/result budgets.
- Agent-side scanning still observes a moving process and needs subject-generation checks.

## Operational and security implications

- Scan plans bind authenticated peer/session/fence, executable generation, exact subject/space, bounds, pattern IDs, limits, and deadline.
- Agents use checked address arithmetic and read only descriptor-authorized ranges.
- Returned offset, length, address, permission snapshot, context, count, pattern ID, and subject generation are validated server-side.
- Context bytes inherit the source label and are capped independently.
- Scan bytes/time/match count/result bytes/context and concurrency have provider and deployment ceilings.
- Pattern source and plans are audited by IDs and hashes; protected raw bytes are not logged by default.

## Known limitations

- RE2 does not support backreferences, lookbehind, and several Python/YARA regex constructs; see L-011 in [LIMITATIONS.md](../LIMITATIONS.md).
- The initial pattern set has no disassembly-aware, entropy, fuzzy-hash, archive, or structural PE query language.
- File/memory changes during scanning can produce a typed subject-changed/unavailable fault; scanning cannot freeze the OS.
- Protected processes and permissions can prevent reads; see L-006.
- High match cardinality produces a typed limit fault instead of a partial iterable.

## Evidence and tests

- Golden tests for byte/text encodings, case behavior, every masked-nibble form, canonical pattern IDs, RE2 flags, and precise invalid-syntax diagnostics.
- Cross-platform RE2 result parity and differential reference vectors.
- File, mapped-image/section, and memory-region scan integration tests.
- Boundary/overflow, permissions, context, classification, cancellation, subject-generation race, access failure, and resource-limit tests.
- Result-codec fuzzing that rejects unknown patterns, out-of-range/overlapping-invalid offsets, excessive context, wrong subject/space, and duplicate malformed results.
- Tests proving complete deterministic `MatchSet` ordering/count and no partial result on overflow.
- Compiler/optimizer tests proving existential mode is emitted only for certified truth-only use and is observationally equal to exact evaluation.
- Protocol assertions proving no predicate or verdict crosses the agent boundary.

## Revisit conditions

Add another pattern or scan-space kind only after defining canonical syntax, typing, platform semantics, worst-case resource behavior, classification, result validation, VM visibility, optimizer rules, and cross-platform tests. A different regex engine is acceptable only if it preserves or strengthens RE2's resource guarantees and is introduced as a separately versioned dialect rather than silently changing existing patterns.

