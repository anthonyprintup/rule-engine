# ADR-007: Hierarchical Typed Subject Identities and Atomic Inventories

- **Status:** Accepted
- **Decision owners:** Schema, protocol, provider, coordinator, and storage lanes
- **Related tasks:** C2, P1, P2, P3, S1, S2
- **Architecture:** [Facts, Subjects, and Scanning](../architecture/05-facts-subjects-and-scanning.md)

## Context

Processes and nested Windows structures are not reliably identified by an array position, display string, address alone, or PID. Arrays reorder, PE data can contain similarly named entries, addresses repeat beneath different parents, and PIDs are reused. The server must reconcile complete inventories, schedule child work independently, correlate events over time, and reject malformed provider data without inferring false removals.

## Decision

Every subject uses a recursive, schema-typed `SubjectKey` containing trusted `PeerId`, stable scope schema ID, a canonical identity tuple, and its optional full parent key. All `Identity[T]` fields are mandatory eager immutable values. Equality and uniqueness use the entire canonical key; a SHA-256 digest is an index only.

Built-in identities are fixed as follows:

- process: peer, PID, and creation time;
- memory region: allocation base and base under process;
- PE section: virtual address and raw-data offset under image;
- import: normalized DLL and IAT RVA under image;
- export: ordinal under image;
- debug entry: type, address of raw data, and pointer to raw data under image;
- resource: tagged type/name/language path and RVA under image;
- certificate: file offset under image;
- TLS callback: RVA under image;
- custom nested scope: every declared identity field in numeric field-ID order.

Each collection is independently scheduled and reconciled through begin/chunk/commit authoritative snapshots. The server stages and validates a complete inventory, then publishes additions, eager-field changes, and removals in one transaction. Any missing identity, duplicate key, gap, schema/count/digest/generation mismatch, cancellation, or disconnect rejects the entire stage and preserves visible last-good state. Sequenced push deltas accelerate observation/removal but never imply sibling completeness; periodic pull inventory remains authoritative.

## Primary reasons

1. Hierarchy disambiguates identities that are unique only within a parent.
2. Creation time prevents process PID reuse from corrupting facts, state, or history.
3. Schema-typed elements make identities validate, encode, compare, and document consistently.
4. Complete-key equality avoids depending on a digest collision assumption.
5. Atomic inventory publication prevents partial generations and false removals.
6. Independent nested scopes support scheduling, budgeting, discovery predicates, and precise lifecycle events.

## Rejected alternatives

- **Opaque subject strings:** rejected because their types, normalization, ancestry, and collision behavior cannot be enforced.
- **Digest-only IDs:** rejected because hash collisions must not become semantic equality and audits need explainable identity.
- **PID alone:** rejected because Windows reuses PIDs.
- **Addresses or array positions alone:** rejected because they are parent-relative, reused, and reorderable.
- **Natural display names/paths:** rejected because normalization and mutability make them unstable.
- **Incremental visibility per enumeration chunk:** rejected because interrupted/corrupt streams would expose mixed generations and infer false removals.
- **Push-only inventory:** rejected because loss, backpressure, reconnect, and agent restart require authoritative reconciliation.

## Positive consequences

- Stable joins across facts, scans, events, state, traces, and history.
- Deterministic additions/changes/removals independent of provider enumeration order.
- Precise nested scheduling and recursive cleanup when a parent disappears.
- Provider identity mistakes reject an inventory rather than silently aliasing objects.
- Custom object arrays use the same model/schema machinery as built-ins.

## Negative consequences

- Keys and indexes are larger than opaque integers or digests.
- Providers must obtain every identity field before emitting a subject.
- Snapshots require staging memory/storage and delay visibility until commit.
- Schema-owned normalization must remain stable across platform/runtime versions.
- Parent removal can create many deterministic descendant-removal events.

## Operational and security implications

- Subject keys are bound to authenticated peer identity; an agent cannot claim a different peer through payload fields.
- Schema negotiation fixes identity types and normalization before activation.
- Snapshot stages are bounded by item/byte/time limits and session/fence tokens.
- Canonical-key digests may accelerate indexes, but collisions are resolved by complete key comparison.
- Audits retain canonical identity metadata under classification policy, while UI display strings are derived only at edges.

## Known limitations

- If a required identity field cannot be read, the whole containing snapshot is rejected; no ordinal fallback exists.
- Inventories represent a source-sequence point, not an instantaneous OS-wide snapshot.
- Live memory/PE data can change during enumeration; generation and digest validation detect protocol consistency, not every OS race.
- Recursive keys consume more storage and bandwidth than flat numeric IDs.
- No Linux provider agent initially; see L-006 in [LIMITATIONS.md](../LIMITATIONS.md).

## Evidence and tests

- Cross-platform canonical-encoding and schema-hash golden tests.
- PID-reuse and identical-child-under-different-parent tests.
- Digest-collision simulation proving complete-key comparison.
- Valid empty/single/multichunk snapshot tests and deterministic diff ordering.
- Failure injection at every snapshot stage proving no partial visibility/removal.
- Duplicate/missing/invalid identity, normalization collision, wrong parent, stale session/fence/generation, count, and digest tests.
- Push retransmission/reordering/watermark tests followed by authoritative reconciliation.
- Parent removal tests proving deterministic descendant closure and no orphan visibility.

## Revisit conditions

Revisit a built-in identity tuple only when provider evidence proves it is not stable or unique. That is a schema-breaking change requiring a new scope schema ID and an explicit history/state migration policy. Revisit snapshot granularity only if measured staging cost is unacceptable and an alternative can prove the same atomic no-false-removal guarantee.
