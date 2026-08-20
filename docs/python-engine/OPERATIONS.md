# Python Engine Operations

This runbook covers the shipped Python-only command surfaces. It is subordinate
to the trust model, contracts, and limitations in this directory: a command
being present does not widen the supported Python subset or make a trusted
generator safe to run as hostile code.

## 1. Install and inventory

Production packages should bundle the already staged, manifest-validated
CPython 3.14.6 runtime. The staging root is not a system Python installation and
must contain `rule-engine-python-runtime.manifest` and the pinned worker.

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

Verify the six public executables from the installed prefix:

```powershell
$bin = 'C:/rule-engine/bin'
foreach ($name in @(
  'rule_engine_pack', 'rule_engine_check', 'rule_engine_admin',
  'rule_engine_server', 'rule_engine_agent', 'rule_engine_benchmark'
)) {
  & "$bin/$name.exe" --version
}
```

The package deliberately contains no Cargo, Rust, YARA, protocol-v1, private
key, cache, bytecode, or build-tree artifact. See
[`../../cmake/INSTALL_PACKAGE.md`](../../cmake/INSTALL_PACKAGE.md) for the full
layout and relocation contract.

## 2. Author, check, and build a pack

Static rule modules are parsed as data and are never imported or evaluated by
CPython. `rule_engine_check` uses the private worker only to obtain a bounded
syntax envelope; C++ performs binding, type checking, lowering, verification,
optimization, and execution semantics.

```powershell
$runtime = 'C:/rule-engine/libexec/rule_engine/python/runtime/3.14.6'
$sdk = 'C:/rule-engine/share/rule_engine/python-sdk/1.0.0'

rule_engine_pack stubs C:/rules/example `
  --output C:/rules/.typing `
  --sdk-root $sdk

rule_engine_pack build C:/rules/example `
  --output C:/packs/example.unsigned.rpack `
  --trust-mode development

rule_engine_check --pack C:/packs/example.unsigned.rpack `
  --runtime-root $runtime `
  --trust-mode development `
  --format sarif `
  --explain-facts `
  --explain-plan
```

Development trust is explicit. It does not authorize a generator unless the
pack trust decision independently grants generator execution. Unsupported
Python constructs fail with stable, source-spanned diagnostics.

## 3. Sign and verify offline

The built-in signer accepts an absolute `file:` reference to exactly one raw
32-byte Ed25519 seed. On Windows the file must be local, non-reparse, owned by
the caller, have no alternate streams, and have an allow-only protected ACL for
the caller, SYSTEM, and Administrators. The tool refuses to overwrite output
and never prints or embeds the seed or its path.

```powershell
rule_engine_pack sign C:/packs/example.unsigned.rpack `
  --output C:/packs/example.rpack `
  --signer file:C:/offline-keys/example.seed `
  --runtime-root C:/rule-engine/libexec/rule_engine/python/runtime/3.14.6

rule_engine_pack verify C:/packs/example.rpack `
  --trust-mode production `
  --trust-config C:/rule-engine/config/pack-trust.conf `
  --format json
```

The canonical trust configuration is:

```text
format=1
mode=production
crypto_library=C:/rule-engine/bin/libcrypto-4-x64.dll
signer=sha256:PUBLIC_KEY_DIGEST|64_HEX_PUBLIC_KEY|sorted.pack.prefixes|active
```

The local-file key provider is an offline operational adapter, not a substitute
for an HSM/KMS/PKCS#11 integration. Keep key generation, backup, rotation, and
operator ceremony outside the online server.

## 4. Configure the resident server

The server accepts only one explicit configuration path. Validate syntax,
cross-field policy, path types, runtime pins, trust snapshots, and required
backends before starting listeners:

```powershell
rule_engine_server --config C:/rule-engine/config/server.conf --validate-config
rule_engine_server --config C:/rule-engine/config/server.conf
```

A single-node development configuration uses `deployment.mode =
"single_node_dev"`, `store.backend = "sqlite_dev"`, exactly one server process,
numeric loopback listener endpoints, and explicit development authorization.
Production uses `deployment.mode = "production_cluster"`, PostgreSQL 17,
mutual TLS, CRL policy, signer/revocation/peer-enrollment snapshots, and every
named policy profile. Inline database secrets are rejected; the supported
reference form is `env:VARIABLE_NAME`, resolved once and then wiped from the
server-owned buffer.

Server configuration schema version 3 adds a versioned resident-capability
inventory on top of the explicit registry lifecycle bounds introduced in
version 2.
The pack registry is content addressed. Authenticated upload publishes each
canonical signed archive as
`PACK_REGISTRY/sha256/SOURCE_CLOSURE_SHA256.rpack`, using exactly 64 lowercase
hexadecimal characters for the digest and an absolute registry root. Startup
does not scan for a convenient version: it resolves the digest recorded by the
active generation, verifies that exact archive and signer, compiles it with the
pinned private runtime, and compares all finalized compilation identities.
Missing files, traversal-shaped digests, trust failures, and identity drift
fail readiness.

Both modes require these common keys:

```text
schema.version
deployment.mode
node.id
node.platform_abi
node.capability_inventory_path
node.lease_duration_ms
node.lease_renew_interval_ms
store.backend
store.server_processes
listener.agent_endpoint
listener.admin_endpoint
listener.accept_timeout_ms
listener.handshake_timeout_ms
listener.read_timeout_ms
listener.write_timeout_ms
listener.backlog
listener.maximum_consecutive_failures
service.worker_threads
service.maximum_queued_sessions
service.maximum_memory_bytes
service.maximum_frame_bytes
service.maximum_messages_per_session
service.maximum_inflight_work_per_session
service.maximum_session_duration_ms
service.work_poll_interval_ms
service.inbound_credit_bytes
service.inbound_credit_messages
service.inbound_credit_work_attempts
service.inbound_credit_snapshot_chunks
network.require_hard_resolver_bounds
runtime.root
pack.registry_path
pack.maximum_published_bytes
pack.maximum_tenant_bytes
pack.partial_session_ttl_ms
pack.unreferenced_retention_ms
bindings.operator_path
schemas.catalog_path
profiles.budget_path
profiles.retention_path
observability.prometheus_endpoint
observability.json_log_path
observability.audit_path
```

`pack.maximum_published_bytes` bounds canonical object bytes across the
registry; `pack.maximum_tenant_bytes` bounds each tenant's published identities
and in-progress reservations. Both must allow at least one 16 MiB source pack,
the tenant bound cannot exceed the global bound, and the global bound cannot
exceed 1 PiB. Partial-session TTL must be between one minute and 30 days.
Unreferenced retention must be between one hour and 365 days. A conservative
example is:

```text
schema.version = 3
node.capability_inventory_path = C:\ProgramData\RuleEngine\resident-capabilities.policy
pack.maximum_published_bytes = 1073741824
pack.maximum_tenant_bytes = 268435456
pack.partial_session_ttl_ms = 3600000
pack.unreferenced_retention_ms = 604800000
```

Registry maintenance runs before readiness and once per minute. Every durable
generation—compiling, ready, active, retired, or failed—keeps its source
reachable. An uploaded object is collected only after no generation references
it and its newest successful publication is older than the retention window.
Abandoned reservations expire from their creation time. Upload metadata format
v1 is not accepted by current servers; finish uploads before upgrade or clear
only the ACL-protected `.uploads` spool after confirming no upload is in
progress. Never delete `sha256` objects manually to recover quota.

Each successful maintenance pass atomically updates an aggregate-only audit and
retains the latest 32 pass records. The record contains only its timestamp and
expiry/removal/reclaimed-byte counts; it never contains source bytes, digests,
tenant or pack identities, or filesystem paths. The
`rule_engine_admin packs PACK_ID --tenant TENANT_ID` command returns the
cumulative counts and last-success timestamp only after both the normal
pack-scoped `pack.read` authorization and a separate global `registry.read`
authorization succeed. An ordinary pack reader still receives the pack
snapshot, but the registry fields remain absent and the registry is not read.
Before deleting anything, maintenance durably writes a bounded pending plan
containing only canonical hashed filenames, expected object sizes, and the
aggregate receipt. Startup and every upload operation replay that plan under
the cross-process registry lock, finish idempotent deletion, commit the audit
exactly once, and clear the plan. Observation remains unavailable while a plan
is pending. An authorized audit read or update failure fails closed. These fields are
operational counters, not a Prometheus time series; alert on a stale
last-success timestamp and corroborate non-zero reclamation with capacity
monitoring.

The capability inventory is a bounded UTF-8 file whose exact first line is
`rule-engine.resident-capabilities.v1`. Every following non-comment line is one
canonical capability ID, for example:

```text
rule-engine.resident-capabilities.v1
com.example.fact.process
com.example.scan.regex
```

Entries must be unique reverse-DNS atoms. The resident sorts and records the
inventory under its current node-lease fence, and the file is part of the
immutable activation-policy bundle. Stage freezes only serving nodes whose
inventory contains every capability required by the signed pack; if none
qualify, apply fails without creating a generation. Change the inventory only
through the same controlled restart-and-restage procedure as other policy
inputs.

Run `rule_engine_server --help` from the same installed version for the
production-only keys. Unknown and duplicate keys fail closed. Listener hosts
are numeric literals so startup does not introduce an unbounded resolver path.
The service owns a fixed joined worker pool and a bounded admission queue;
overload closes the newly authenticated connection. Its configured application
memory reservation covers owned frame/session reservations, not OS socket
buffers, TLS-library allocations, allocator overhead, or backend-internal
caches, so deployments still need a measured process/container memory limit.
The lease renewal interval plus the complete blocking listener window (TCP
accept timeout and TLS handshake timeout) must be strictly shorter than the
node lease duration; configuration validation computes this without overflowing
the duration representation.

`development.allow_loopback_plaintext` is parsed so the configuration schema
does not need another incompatible revision, but the current resident listener
does not implement a plaintext application channel and fails startup with
`SRV-PLAINTEXT-LISTENER-UNAVAILABLE`. Use mTLS for development sessions as well;
do not treat successful `--validate-config` as proof that plaintext serving is
available. Listener accept and TLS handshake are serial before admission to the
bounded worker queue, so their configured deadlines also bound head-of-line
delay.

The default store composition grants only the configured durable-message
credit. Every accepted body and cumulative receipt commit atomically under the
current session lease before ACK; a gap, changed replay, stale lease, or failed
commit is NACKed without advancing the receipt. A committed authoritative
snapshot is projected into deterministic subject/binding evaluations. The
resident evaluator leases generation-fenced fact or scan work, resumes the C++
VM from the authenticated result, and commits the terminal transaction through
the same durable coordinator. Restart reconstructs pending work from committed
snapshot messages.

An authenticated agent session checks for newly ready work at establishment,
after each durable inbound message, and whenever an otherwise idle,
non-consuming TLS/socket input-readiness wait reaches
`service.work_poll_interval_ms`. The interval must be at least 10 ms and no
longer than `service.maximum_session_duration_ms`. Polling stays on the
session's single channel-owning worker; it does not add concurrent TLS writes
or apply the short poll deadline to a partially received frame. Every poll is
still bounded by the negotiated peer work/message/byte limits and the
configured outstanding-work ceiling. Choose the interval as an explicit
delivery-latency versus backend-load tradeoff: shorter intervals reduce idle
delivery delay but multiply empty durable-store checks across connected peers.

`ResidentApplicationService::work_poll_snapshot()` exposes process-local,
payload-free tuning evidence: successful empty and nonempty backend polls,
successfully sent work leases, delivery-delay sample count, cumulative delay,
and maximum delay. Counters and the cumulative delay saturate at `uint64_t`
maximum rather than wrapping, and snapshots may be read while sessions run.
Each snapshot is coherent: delivered-work and its delay count, total, and
maximum publish together, including sub-microsecond samples rounded up to one
microsecond.
Delay begins at the first observed empty poll in an idle period and ends after
the last successfully sent lease in the later nonempty poll. If the initial
poll is already nonempty, it begins when that poll starts. It is therefore an
observed idle-to-send service delay, not durable queue age or agent execution
latency. Compare empty-poll rate and delay while tuning
`service.work_poll_interval_ms`; do not infer source contents, rule outcomes,
or endpoint performance from these aggregate values.

This receipt is currently an inspectable in-process surface. The standalone
server does not yet export it to Prometheus or OTLP, and the counters reset on
process restart. Operators must use an embedding/export adapter if they need
long-term rates, percentiles, or cross-node aggregation; snapshot merging is
saturating and preserves the maximum observed delay.

Current operations must account for three evaluator limits: one VM provider
turn stays on one agent route, capability/service/history host turns fail
closed, and no VM heap/frame checkpoint survives a server process crash. A
same-node restart can nevertheless recover an authenticated fact/scan result
that was durable before the crash: it reconstructs deterministic work,
reacquires its still-current fenced lease, rereads state, and validates bounded
contiguous provider rounds through a fresh VM without endpoint redispatch. A
different node waits for lease expiry. Canonically encoded recovery input is
capped at 16 MiB per work and 64 MiB per scheduler construction, and normal
resource counters restart with the fresh process. A durable state conflict is
replayed transparently at most twice: the scheduler creates a
fresh VM, rereads state, supplies exact captured fact/scan responses without
agent redispatch, and applies one cumulative `balanced.v1` normal budget across
all attempts. A changed or newly reached provider request, invalid resource
accounting, exhausted budget, or third conflict fails closed. Scalar
module-level `StateKey` declarations with peer or subject scope and direct
entrypoint `get`/`set`/`delete` are executable now. Reads and writes stay on the
server and are partitioned under tenant, pack,
activation-selected namespace, executable owner, and the peer or canonical
subject; no state request is sent to an agent. Records, custom defaults,
explicit identities, wider scopes/classifications, compare-and-set, shared
state, helpers, and migrations remain closed. Stage preview compiles the trusted
pack with the pinned private runtime and derives a SHA-256 identity from every
declared state key, including unused keys. The optional `--state-schema` value
is only an expected-value guard; it cannot choose the durable identity.
Activation does not require a process restart: an
atomic flip fences old sessions, residents verify and compile the new durable
active identity, and new sessions are admitted only after the local scheduler
has swapped. See
[L-026](LIMITATIONS.md#l-026--container-and-iteration-frontend-is-intentionally-partial),
[L-031](LIMITATIONS.md#l-031--resident-host-services-and-retry-are-partial),
and [L-033](LIMITATIONS.md#l-033--filesystem-and-administration-adapters-are-intentionally-narrow).

## 5. Configure the Windows agent

The agent is outbound-only and accepts numeric failover endpoints. It never
receives a predicate, bytecode, or verdict; it enumerates typed subjects and
returns requested facts, scans, inventory observations, or diagnostics.

```text
schema_version = 2
spool_path = C:\ProgramData\RuleEngine\agent\spool.sqlite3
certificate_path = C:\ProgramData\RuleEngine\agent\client.pem
private_key_path = C:\ProgramData\RuleEngine\agent\client-key.pem
ca_path = C:\ProgramData\RuleEngine\agent\ca.pem
crl_path = C:\ProgramData\RuleEngine\agent\server.crl.pem
require_crl = true
server_endpoint = 192.0.2.10:7443
server_endpoint = [2001:db8::10]:7443
server_name = coordinator.example
server_uri = urn:rule-engine:server
server_fingerprint_sha256 = 64_LOWERCASE_HEX_DIGITS
peer_id = peer:example-host
active_generation = 1
inventory_refresh_interval_ms = 300000
```

All filesystem paths are absolute. Production agents require both `crl_path`
and `require_crl = true`; there is no production switch that disables local
revocation checking. `--validate-config` rejects missing, malformed,
not-yet-valid, or expired CRLs before dialing. During connection, OpenSSL checks
the full certificate chain and additionally rejects missing issuer coverage, a
wrong CRL issuer, and revoked server certificates. The TLS chain, DNS name,
exact URI SAN, and SHA-256 leaf fingerprint must still agree.

Schema v2 makes the inventory interval explicit; schema-v1 agent files are
rejected and must add the bounded interval during upgrade.

CRL acquisition remains an operator responsibility: publish a refreshed file
atomically and restart the agent before its `nextUpdate`. The agent performs no
OCSP or online CRL fetch and does not reload the file in place. Validate before
running:

```powershell
rule_engine_agent --config C:/ProgramData/RuleEngine/agent/agent.conf --validate-config
rule_engine_agent --config C:/ProgramData/RuleEngine/agent/agent.conf
```

Accepted results and complete authoritative inventory snapshots are written to
the SQLite spool before first transmission. Reconnect replays unacknowledged
records; cumulative ACK is the deletion boundary. Sequence, generation,
session, request, and fence mismatches are rejected rather than guessed.

The agent enumerates process identities immediately after its first successful
session and then at `inventory_refresh_interval_ms`. The value is mandatory and
must be between 1,000 ms and 86,400,000 ms (24 hours). Each refresh is a complete
authoritative begin/chunk/commit generation; the agent never overlaps two
enumerations and never publishes a partial result. The checked generation
combines the active runtime generation with the durable spool sequence, starts
above the legacy generation-only scheme, and therefore lets unacknowledged
batches replay with their exact identity after reconnect while a restarted or
upgraded agent continues above its prior sequence. An enumeration failure emits
no replacement snapshot, leaving the
coordinator's last-good process view authoritative until a later refresh
succeeds.

Cadence is currently fixed per agent and has no fleet jitter. Stagger agent
service starts when rolling out a short interval, monitor snapshot ingress and
spool growth, and lengthen the interval before increasing spool limits. Never
delete the spool to resolve refresh lag: doing so discards the durable epoch and
sequence authority needed for safe replay.

## 6. Administration and observability

`rule_engine_admin` requires an authenticated configuration and an injected
transport backend. There is no implicit local administrator or unauthenticated
fallback:

```text
format=2
endpoint=https://control.example:9443/v1
server_uri=urn:rule-engine:control:production
client_certificate=client.pem
client_key=client.key
trust_bundle=trust.pem
```

Mutating commands require an idempotent request identity and audited reason;
destructive operations default to preview unless `--apply` is explicit. The
server authorizes the authenticated principal against the exact operation and
tenant/pack resource before any store access or audit mutation.

The resident admin listener maps the certificate-authenticated peer through a
bounded snapshot whose first line is `rule-engine.operator-bindings.v1` and
whose remaining tab-separated rows contain tenant, peer, principal, principal
kind, home tenant, pack prefix, and an explicit comma-separated capability
set. Peers and principals are unique; tenant, pack prefix, principal kind, and
capability must all authorize the exact resource. The version-6 canonical
admin request wire and version-4 response wire are a coordinated-upgrade
boundary: deploy the matching server and CLI together. Mixed versions reject
the request before authorization or mutation. The standalone client exposes pack/operation reads, verified
resumable upload, server-owned distributed stage, bounded operation polling,
forward rollback restaging, and activation preview, drain, explicit straggler
fencing, and atomic flip. `pack.stage`, `pack.activate`, and `pack.rollback`
are separate binding capabilities. `registry.read` is a distinct global
operator capability: it does not inherit authority from a tenant or pack
prefix and exposes only the aggregate maintenance fields described above. The
client pins the configured server URI
SAN and correlates one bounded request/response per mTLS connection.

Durable generation codec v4 records each resident's direct state-schema
attestation. Older generation records are readable for inspection, but
versions 1 through 3 cannot become resident-ready without restaging.

For example:

```powershell
rule_engine_admin upload C:/approved/com.example.cheat.rpack `
  --tenant tenant-a --request-id upload-1042 --config admin.conf

rule_engine_admin stage com.example.cheat `
  sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef 7 `
  --tenant tenant-a --state-namespace state:com.example.cheat `
  --expected-version 0 --request-id stage-1042 `
  --reason "compile approved source on every resident" --config admin.conf

rule_engine_admin stage com.example.cheat `
  sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef 7 `
  --tenant tenant-a --state-namespace state:com.example.cheat `
  --expected-version 0 --request-id stage-1042-apply `
  --operation-id stage-1042 --idempotency-key stage-1042 `
  --apply --wait --config admin.conf

rule_engine_admin rollback com.example.cheat 5 8 --tenant tenant-a `
  --expected-version 12 --request-id rollback-1042 `
  --reason "restore retained generation 5 as forward generation 8" `
  --config admin.conf

rule_engine_admin rollback com.example.cheat 5 8 --tenant tenant-a `
  --expected-version 12 --request-id rollback-1042-apply `
  --operation-id rollback-1042 --idempotency-key rollback-1042 `
  --apply --wait --config admin.conf

rule_engine_admin activate com.example.cheat 7 --tenant tenant-a `
  --expected-version 3 --request-id change-1042 `
  --reason "approved detection rollout" --config admin.conf

rule_engine_admin activate com.example.cheat --tenant tenant-a `
  --phase drain --boundary 92014 --expected-version 3 `
  --operation-id change-1042 --idempotency-key change-1042 `
  --request-id change-1042-drain --apply --config admin.conf
```

Preview does not mutate the pack version. Stage or rollback apply freezes the
eligible serving targets and returns the new resource version; `--wait` follows
the durable operation through `staged` or `failed`. Each activation phase then
uses the updated resource version returned by the previous phase. Rollback is a
forward restage and currently accepts carry state only: the retained and active
state schema must match, and no reset/migration flag can be supplied. Policy
mutation still fails closed with `ADMIN-NOT-IMPLEMENTED`.

At startup, the resident reads every configured trust and execution-policy
file and computes one `activation-policy.v1` bundle identity. Stage records that
identity in both the durable generation and its idempotency fingerprint. Every
target must be running the same bundle before it can report, and active-pack
readiness requires an exact match.

Policy files are therefore deployment inputs, not live-editable configuration.
Replace them atomically and restart the residents as one controlled rollout,
then stage source as a new generation under the new bundle before activation.
Changing comments or whitespace changes the byte identity. A generation written
by control-payload version 1 or 2 has no policy snapshot and must be restaged
before this server version will serve it. A rollback also retains the original
generation's policy identity; if policy has changed, stage the retained source
as an ordinary new generation under the current policy instead.

Use the configured JSON log, security audit, readiness, and Prometheus outputs
for operations. Logs and diagnostics record identities, hashes, limits, and
failure classes, not rule payloads, private keys, connection secrets, or
Sensitive/Secret values.

## 7. Benchmark interpretation

```powershell
rule_engine_benchmark --peers 10000 --format json
```

This validates exact/optimized observable parity and a bounded in-memory
resident coordinator/spool model. The output states whether sockets and
PostgreSQL were exercised. The default 10,000-peer run is not a claim of 10,000
concurrent TLS connections or a live database load test.

## 8. Stop and recovery rules

- Stop admission first, cancel bounded work, then join owned workers; no
  detached task may outlive its owner.
- Never delete an agent spool to fix a reconnect. Restore connectivity and let
  cumulative ACK retire durable records.
- Treat stale fences, semantic-hash disagreement, schema mismatch, runtime-pin
  mismatch, migration failure, or incomplete activation as fail-closed
  readiness failures.
- Replay is diagnostic and dispatch-free. External actions are redriven only
  through a separately authorized outbox operation.
- Do not weaken signer, TLS, schema, or private-runtime validation to recover a
  pack. Repair the artifact or policy and stage a new generation.

The complete known-limit record and its revisit conditions are in
[`LIMITATIONS.md`](LIMITATIONS.md). Current implementation and qualification
status is in [`IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md), and the
exact local evidence/unqualified matrix is in
[`QUALIFICATION.md`](QUALIFICATION.md).
