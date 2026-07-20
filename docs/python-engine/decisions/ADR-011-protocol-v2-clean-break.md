# ADR-011: Protocol v2 Is a Clean Break

Status: accepted for implementation\
Date: 2026-07-20\
Owners: protocol-v2 lane and integration owner\
Tasks: P1, P2, P3, I1, X1, Q1\
Architecture: [08-protocol-storage-and-cluster.md](../architecture/08-protocol-storage-and-cluster.md)

## Context

The current protocol is a v1 localhost-oriented request/response demonstration. It uses a client listener, opaque subject strings, a simple handshake, one-shot/multi-session evaluation helpers, and no production authentication, durable reconnect, schema projection, authoritative snapshot transaction, database session fence, or cluster ownership model.

The Python rule-engine rewrite changes the boundary substantially:

- subjects are hierarchical typed identities rather than strings;
- providers return richer typed facts and scan results but still never evaluate rules;
- agents must push observations and receive server work over one outbound enterprise-friendly connection;
- server nodes are active-active and a stale node must not commit after failover;
- durable agent retransmission, sequence acknowledgement, explicit flow control, and schema/capability negotiation are required;
- every message must bind to a TLS-authenticated peer, server-issued session, executable generation, and where applicable a work fence;
- rule packs and external records require compatible stable schemas with numeric field IDs.

Trying to preserve the v1 wire shape would either hide these semantics behind ambiguous optional fields or require a long-lived dual implementation. Both conflict with the requested complete YARA/protocol break and increase the chance that an unauthenticated or unfenced path survives.

## Decision

Implement one protocol v2 and remove v1 completely at the final cutover.

- Production transport is framed Protocyte over outbound TCP from the Windows agent, protected by TLS 1.3 mutual authentication and ALPN `rule-engine-peer/2`.
- The operator trust configuration maps a validated canonical certificate URI SAN to exactly one tenant and `PeerId`. Message content cannot select or replace that identity.
- The server issues `SessionId` and monotonically increasing database-backed `SessionFence` after negotiating one protocol minor, schemas, capabilities, and limits.
- Durable agent-to-server records use persistent `(AgentEpoch, AgentSequence)` identity and a local SQLite spool. The server returns cumulative durable acknowledgements; retransmission is expected and idempotent.
- Server-to-agent provider work carries `WorkId`, `AttemptId`, `WorkFence`, `SessionFence`, pack generation, typed subject, route, deadline, and bounded request data. It carries no rule predicate or verdict logic.
- Application-level credits govern bytes, durable messages, work attempts, and snapshot chunks; a reserved control allowance keeps heartbeat/cancellation viable under overload.
- Authoritative enumeration is begin/chunk/commit and changes visible inventory only after canonical identity, schema, count, digest, and completeness checks pass atomically.
- Schema negotiation permits only structurally compatible optional additions. Identity, requiredness, type, numeric-field reuse, or classification changes require a new schema identity/major.
- Protocol major mismatch is fatal. There is no v1 negotiation, translation gateway, compatibility library, legacy CLI switch, or fallback listener.
- Explicit plaintext development mode is restricted to loopback at both ends.
- TLS early data, session tickets, and resumption are disabled initially so every connection establishes the current certificate identity and a fresh database session fence.

## Primary reasons

1. **One enforceable trust boundary.** Every provider response follows the same authentication, typed identity, schema, bounds, and fence checks before reaching the VM.
2. **Unambiguous failure semantics.** Session fencing and durable sequence IDs make reconnect, retry, ACK loss, and stale sockets explicit instead of inferred from TCP lifetime.
3. **Central semantic ownership.** Work messages are deliberately incapable of delegating rule predicates or verdicts to agents.
4. **Operational fit.** Outbound long-lived agent sessions work through ordinary endpoint firewall policy and carry work, results, observations, removals, and control together.
5. **Safe schema evolution.** Numeric fields and structural projection checks support additive optional fields without allowing semantic coercion.
6. **Reviewability.** A clean major removes dead v1 branches and prevents tests from accidentally proving only the weaker path.
7. **Big-bang product intent.** The requested delivered result has no YARA or legacy protocol support; maintaining migration machinery would add cost to a path that must disappear.

## Rejected alternatives

### Extend v1 in place

Rejected because its opaque identities and connection-oriented ownership cannot express the new invariants safely. Reusing the same version would also make old/new mismatch failures ambiguous.

### Run v1 and v2 indefinitely

Rejected because it doubles authentication, scheduling, provider, CLI, documentation, fuzzing, and incident-response surfaces. It also creates a route around schema/session fencing and blocks proof that clients remain fact-only.

### Provide a v1-to-v2 gateway

Rejected because a gateway cannot recover typed hierarchical identities, durable agent sequences, authoritative snapshots, or missing certificate identity from legacy messages without inventing semantics.

### Use gRPC

Rejected for the initial implementation. It introduces a general RPC/runtime/code-generation stack and HTTP/2 operational surface where the peer protocol needs a small fixed message catalog and already uses Protocyte-compatible generated types. External services may use the separate modeled HTTP/2 protobuf-wire transport; the peer channel remains purpose-built.

### Use JSON frames

Rejected because exact integers/bytes/enums, canonical typed identities, numeric schema fields, bounded decoding, and stable unknown-field behavior are central. JSON would require a second bespoke type/schema layer.

### Accept inbound connections on each agent

Rejected because endpoint exposure and firewall configuration become significantly harder. Outbound sessions also give the server one authenticated path for backpressure and observations.

### Authenticate `peer_id` from `AgentHello`

Rejected because it makes an untrusted message part of the security boundary. Certificate-to-registry mapping is established before protocol data is trusted.

### Rely only on TCP flow control

Rejected because TCP buffer availability is not database acceptance, provides no durable ACK, and cannot reserve control capacity or bound agent spool growth predictably.

### Require exact schema hashes

Rejected because harmless optional additions would force synchronized replacement of every server and agent. Structural compatibility is narrowly defined and recorded per session; arbitrary coercion remains forbidden.

## Positive consequences

- Protocol security, reconnect, inventory, schema, and flow-control invariants are testable in one implementation.
- Server and agent failures may duplicate transport/computation without duplicating durable visible results.
- Agent spooling gives a precise durable deletion boundary: cumulative ACK after database acceptance.
- A certificate and session fence establish one peer identity and one current owner across the cluster.
- Additive optional schema changes can roll out without lockstep replacement.
- Complete v1 deletion removes unauthenticated localhost assumptions from production binaries.

## Negative consequences and tradeoffs

- Existing v1 agents/servers cannot communicate with the rewrite; deployment must be coordinated.
- The protocol lane must implement TLS/PKI, reconnect, spooling, credits, schema negotiation, chunking, and fuzz-hardening before end-to-end behavior is available.
- Disabling TLS resumption increases reconnect cost.
- One active session per peer simplifies fencing but prevents connection-level load balancing across servers.
- A finite endpoint spool can halt provider work during a long outage.
- Protocol minor evolution must preserve all v2 invariants and golden encodings; otherwise another major is required.

## Security and operational implications

- Production needs certificate issuance, URI SAN registry mapping, trust/CRL distribution, rotation, expiry alerting, and emergency revocation procedures.
- Authentication failure details remain server-side; the peer gets a redacted reason code.
- Agent private keys require OS-protected storage and non-export policy where deployment supports it.
- A compromised enrolled agent can lie with schema-valid facts. The server limits and audits it but cannot independently attest arbitrary OS values.
- Operations must monitor sequence lag, spool age/bytes, repeated reconnect, schema ineligibility, certificate expiry, invalid snapshots, stale fences, and NACK quarantine.
- Upgrade runbooks replace server and agent cohorts around one explicit cutover; they never depend on automatic v1 fallback.

## Known limitations

1. No v1 compatibility or automated wire migration exists.
2. Offline agents cannot evaluate rules; they can only retain admitted observations/results in the bounded spool.
3. Loss of the local spool can lose unsent non-inventory history; complete inventory reconciliation restores current presence only.
4. CRL refresh makes revocation detection non-instantaneous; online OCSP is not required initially.
5. TLS resumption and early data are unavailable in the first release.
6. A peer has one active server session and reconnects to move between nodes.
7. Large logical messages must use explicit chunks and individual values above negotiated limits are rejected.
8. Schema compatibility is intentionally narrow and may require coordinated new schema IDs for substantive model changes.
9. The peer protocol is purpose-built; third-party agents require the same generated schema, PKI, session, spool, and conformance behavior.
10. Only Windows agents are supported initially.

## Validation evidence required

- Golden and cross-platform round-trip tests for every message and stable numeric field ID.
- Decoder fuzzing for arbitrary/truncated/oversized/nested data under fixed memory and time bounds.
- Full TLS negative matrix: trust, validity, EKU, SAN mapping, hostname, protocol version, ALPN, early data, and loopback plaintext checks.
- Peer-ID spoof tests proving message fields cannot override certificate identity.
- Crash-point tests across spool insert, send, server commit, ACK, local delete, restart, and endpoint failover.
- Schema projection tests for allowed optional evolution and every incompatible change.
- Simultaneous old/new socket tests proving only the current session fence can commit.
- Snapshot staging tests proving malformed/partial data never changes visible inventory or emits removals.
- Backpressure tests proving durable data is retained and control traffic remains available at zero bulk credit.
- Repository cutover scan proving no protocol-v1 decoder, listener, CLI option, fixture, or fallback remains.

## Revisit conditions

Revisit only through a new ADR and protocol-minor/major review if one of these becomes true:

- measured reconnect load justifies certificate-bound TLS resumption without weakening fresh session fencing;
- a supported deployment requires standardized SPIFFE/SPIRE enrollment or online revocation beyond the operator registry/CRL contract;
- a third-party ecosystem makes a standardized transport materially more valuable than the purpose-built peer protocol;
- Linux provider agents enter scope;
- schema evolution needs capabilities that cannot be expressed as compatible optional projections;
- product requirements mandate simultaneous multi-node sessions for one peer and define how provider work and authoritative inventories remain singular.
