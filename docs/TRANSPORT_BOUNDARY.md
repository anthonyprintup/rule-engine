# Transport Boundary

The V1 client/server transport is a localhost demo path. It uses length-prefixed
TCP frames and typed protocol payloads so the rule engine can exercise async fact
collection, batching, capability negotiation, and VM resume behavior.

Do not treat the current plain TCP transport as production-ready for remote
clients.

## Trust Boundary

- The server owns parsing, semantic validation, lowering, scheduling, cache
  policy, VM execution, and match decisions.
- Clients enumerate subjects and return typed facts, generic provider-scope
  subject sets, or structured diagnostics.
- Clients must never evaluate rule predicates or decide whether a rule matches.
- Candidate-provider requests carry generic route/filter/argument data without
  rule identifiers, and candidate-only capabilities do not satisfy ordinary
  fact-provider routes.
- Provider responses are untrusted input and must keep passing descriptor-backed
  type validation before they enter or leave the fact cache.

## Current V1 Assumptions

- Listener and connector default to `127.0.0.1`.
- There is no authentication, peer identity, authorization, or transport
  encryption.
- Capability negotiation is advisory plus enforced by the server before and
  during evaluation, but it is not a security identity.
- Candidate-provider dispatch requires a non-empty filter batch and an exact
  route/filter/`subject_set`/argument-type capability match. Mismatches use the
  ordinary fact path; clients do not resolve rule semantics.
- Request timeouts, retries, and cancellation diagnostics are descriptor-owned
  for localhost V1: timed-out provider facts can be retried within a bounded
  retry budget, shutdown before provider dispatch synthesizes descriptor
  cancellation facts locally, and context-aware localhost handlers can observe a
  cooperative stop token for in-flight cancellation.
- The protocol is suitable for local tests, demos, and fixture-backed provider
  development.

## Before Remote Clients

Remote clients require a separate production transport design. At minimum:

- Authenticate both sides and bind advertised capabilities to the authenticated
  peer identity.
- Encrypt transport traffic.
- Authorize which subjects, scan spaces, and provider routes each client may
  access.
- Preserve server-owned rule semantics; remote clients still return facts only.
- Add replay protection and stable request identifiers for any remote retry
  model.
- Define authenticated remote cancellation, retry, deadline, and backpressure
  behavior for in-flight provider requests.
- Bound payload sizes, fact counts, pattern-match counts, and diagnostic text at
  every decode boundary.
- Decide which facts may be cached, persisted, logged, or traced.
- Add integration tests with malicious or inconsistent client responses.

Until those items exist, keep the plain TCP implementation scoped to localhost
V1 demos and tests.
