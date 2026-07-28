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

The pack registry is content addressed. Place each canonical signed archive at
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
service.inbound_credit_bytes
service.inbound_credit_messages
service.inbound_credit_work_attempts
service.inbound_credit_snapshot_chunks
network.require_hard_resolver_bounds
runtime.root
pack.registry_path
bindings.operator_path
schemas.catalog_path
profiles.budget_path
profiles.retention_path
observability.prometheus_endpoint
observability.json_log_path
observability.audit_path
```

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

Current operations must account for two evaluator limits: one VM provider turn
stays on one agent route, and capability/service/state/history host turns fail
closed. Activation does not require a process restart: an atomic flip fences
old sessions, residents verify and compile the new durable active identity, and
new sessions are admitted only after the local scheduler has swapped. See
[L-031](LIMITATIONS.md#l-031--resident-evaluation-supports-agent-fact-and-scan-turns-only).

## 5. Configure the Windows agent

The agent is outbound-only and accepts numeric failover endpoints. It never
receives a predicate, bytecode, or verdict; it enumerates typed subjects and
returns requested facts, scans, inventory observations, or diagnostics.

```text
schema_version = 1
spool_path = C:\ProgramData\RuleEngine\agent\spool.sqlite3
certificate_path = C:\ProgramData\RuleEngine\agent\client.pem
private_key_path = C:\ProgramData\RuleEngine\agent\client-key.pem
ca_path = C:\ProgramData\RuleEngine\agent\ca.pem
server_endpoint = 192.0.2.10:7443
server_endpoint = [2001:db8::10]:7443
server_name = coordinator.example
server_uri = urn:rule-engine:server
server_fingerprint_sha256 = 64_LOWERCASE_HEX_DIGITS
peer_id = peer:example-host
active_generation = 1
```

All filesystem paths are absolute. The TLS chain, DNS name, exact URI SAN, and
SHA-256 leaf fingerprint must agree. Validate before running:

```powershell
rule_engine_agent --config C:/ProgramData/RuleEngine/agent/agent.conf --validate-config
rule_engine_agent --config C:/ProgramData/RuleEngine/agent/agent.conf
```

Accepted results and complete authoritative inventory snapshots are written to
the SQLite spool before first transmission. Reconnect replays unacknowledged
records; cumulative ACK is the deletion boundary. Sequence, generation,
session, request, and fence mismatches are rejected rather than guessed.

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
capability must all authorize the exact resource. The version-5 canonical
request wire and standalone client expose pack/operation reads, verified
resumable upload, server-owned distributed stage, bounded operation polling,
forward rollback restaging, and activation preview, drain, explicit straggler
fencing, and atomic flip. `pack.stage`, `pack.activate`, and `pack.rollback`
are separate binding capabilities. The client pins the configured server URI
SAN and correlates one bounded request/response per mTLS connection.

For example:

```powershell
rule_engine_admin upload C:/approved/com.example.cheat.rpack `
  --tenant tenant-a --request-id upload-1042 --config admin.conf

rule_engine_admin stage com.example.cheat `
  sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef 7 `
  --tenant tenant-a --state-schema sha256:state-v1 `
  --state-namespace state:com.example.cheat `
  --expected-version 0 --request-id stage-1042 `
  --reason "compile approved source on every resident" --config admin.conf

rule_engine_admin stage com.example.cheat `
  sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef 7 `
  --tenant tenant-a --state-schema sha256:state-v1 `
  --state-namespace state:com.example.cheat `
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
