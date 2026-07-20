# ADR-015: Runtime Data Labels with Control-Flow Propagation

Status: accepted for `design-v1`\
Date: 2026-07-20\
Tasks: `C2`, `V1`, `V2`, `E1`, `E2`, `E3`, `R1`, `R2`, `R3`, `S1`, `Q1`

## Context

Rules combine eager model fields, lazy provider facts, service responses, history rows, state, literals, and derived values. Some data may be safe in state but forbidden in a post, trace, retention profile, custom event, or lower-classified service. Static Python types alone cannot express dynamic envelope labels, tenant/operator categories, or data assembled at runtime.

Tracking only explicit value flow is also insufficient. A rule can leak a Secret bit by posting one of two Public constants, by varying collection length, by raising an exception, or by conditionally emitting an event. The runtime therefore needs to account for implicit control dependencies while remaining bounded and explainable.

## Decision

Implement mandatory runtime information-flow labels:

1. Confidentiality levels form the lattice `Public < Internal < Sensitive < Secret`; values may also carry operator-defined category tags and bounded provenance.
2. Schema aliases such as `Sensitive[T]` remain transparent to ordinary Python typing but become compiler/schema label metadata.
3. Provider, service, event, history, state, constant, and operator-transform sources create labeled values. Operations join operand labels.
4. Containers retain element/value labels plus a structural label for shape, length, ordering, and key set.
5. The VM maintains a program-counter label. Branches, match guards, loops, short-circuit choices, exceptions, iterator exhaustion, and context-manager suppression join the controlling label into their CFG region. Writes, returns, raises, yields, requests, state changes, and effect payloads join the current program-counter label.
6. CFG post-dominator metadata restores the prior control label after the controlled region. `finally` joins all incoming path labels.
7. Every wire, service, effect, event, state, history, retention, trace, and persistence boundary deep-freezes the value, joins its control label, and enforces both classification level and category policy.
8. Ordinary author boundary violations raise `DataPolicyViolation` before a request/intent exists. Mandatory engine fault/recorder metadata is retained with protected payload fields redacted.
9. Only a statically named, versioned, operator-bound declassification transform can lower a label. Its input/output schema/labels and caller set are fixed, and every use is audited.
10. Persisted values retain their labels and policy version. Current access/sink policy may further restrict them; it cannot reinterpret protected data as less sensitive.
11. Labels complement, but do not replace, TLS, database encryption/access control, tenant authorization, signature trust, and operator administration.

## Primary reasons

- It enforces sink and retention policy at the moment real dynamic data crosses a boundary.
- Program-counter propagation prevents common implicit-flow leaks.
- A small ordered lattice is understandable to authors and operators.
- Category tags support domain restrictions that a single confidentiality number cannot express.
- Explicit declassifiers make sensitive transformations reviewable, versioned, testable, and auditable.
- Compiler metadata plus VM propagation supports precise source diagnostics without trusting clients to enforce policy.

## Alternatives considered

### Documentation-only classifications

Rejected. They provide no technical enforcement and are easily lost through helpers, containers, or new sinks.

### Static-only label checking

Rejected as the complete solution. Provider/service/history envelopes and operator bindings supply runtime labels; dynamic control flow and `Any` narrowing also require runtime validation.

### Value-flow taint without a program-counter label

Rejected. It leaks through conditional constants, collection shape, exceptions, iteration count, effect presence, and other implicit flows.

### One label per whole object/container

Rejected as the sole representation. It is simpler but needlessly overclassifies unrelated fields/elements and prevents useful bounded retention. Structural labels are still required for shape leakage.

### Automatic declassification for hashing, truncation, or redaction-looking functions

Rejected. These operations may preserve identifying information or be reversible in a small domain. Only reviewed operator transforms may lower labels.

### Physically separate engine/runtime per classification

Rejected as the primary mechanism. Separate deployment can be an additional defense, but it does not solve mixed-label derivations, author diagnostics, or per-sink policy within an evaluation.

## Consequences

### Positive

- Provider facts cannot silently leak through posts, traces, state, custom events, or services.
- Implicit branch/exception/container-shape flows are conservatively protected.
- Stored and emitted data carries durable classification provenance.
- Declassification is explicit and auditable rather than inferred.
- Automatic diagnostics can retain safe structure while redacting payloads.
- Optimizer legality has an explicit label/control-observability requirement.

### Negative

- Conservative control joins can overclassify values and suppress otherwise intuitively safe effects.
- Every VM operation and boundary needs label-aware implementation and differential tests.
- Container element/shape labels increase memory and instruction cost.
- Provenance must be bounded to avoid itself becoming a memory or data-leak channel.
- Operator category and declassifier configuration becomes part of pack activation compatibility.
- Authors may need explicit reviewed transforms for common redaction/aggregation workflows.

## Operational and security implications

- Operator profiles must define storage, trace, retention, service, action, event, capture, audit, and log ceilings and allowed categories. Production startup fails without complete profiles.
- Metrics record policy/label/category and redaction counts, never protected payload values.
- Logs and recorder serialization apply redaction before bytes leave the VM boundary.
- Physical action dispatch rechecks current operator revocation/classification and may suppress previously queued work; it cannot upgrade earlier eligibility.
- Declassifier audits include transform/version/caller/source and input/output labels plus a protected digest where permitted.
- Database row access and tenant boundaries remain mandatory even when labels match.

## Known limitations

- Program-counter propagation deliberately overclassifies some data (L-014).
- Labels do not encrypt data or authenticate a caller.
- Covert channels through aggregate timing/resource exhaustion are reduced by budgets but not claimed to be eliminated.
- Provenance is bounded and may collapse to summarized source sets.
- A current stricter policy can prevent reading or delivering older persisted data that was valid when written.
- Cyclic VM values still cannot cross canonical boundaries regardless of their labels (L-017).
- Automatic recorder redaction can reduce the diagnostic detail available for protected-data faults.

## Evidence and validation

- Unit/property tests join every scalar/container/object operation and verify structural labels.
- CFG tests cover nested branches, short-circuiting, loops, `match`, exceptions, `finally`, context managers, generators, async suspension, and post-dominator restoration.
- End-to-end tests attempt explicit and implicit leaks through each state/service/event/effect/history/trace/retention boundary.
- Declassifier tests verify exact binding/schema/label constraints, audit creation, and rejection of dynamic or spoofed transforms.
- Serialization/log tests scan emitted bytes to prove protected fixtures never appear above the configured ceiling.
- Exact/optimized parity tests include label/provenance and control-region behavior.

## Revisit conditions

Revisit precision if production evidence shows material false-positive restriction. A change must preserve noninterference at every supported control construct, update optimizer certificates and VM costs, and add leak-regression tests. Adding new levels/categories or label lowering requires schema/policy versioning and an ADR amendment. The design must not weaken runtime enforcement merely to improve convenience or performance.
