# Python command-line tooling

This component owns the local author and operator entrypoints:

- `rule_engine_pack` canonicalizes source-only packs, signs them through the
  offline file-key adapter, verifies trust, inspects redacted metadata, and
  copies the pinned PEP 561 SDK;
- `rule_engine_check` runs the exact private CPython parser worker and the same
  C++ static compiler and optimizer contracts used by the server; and
- `rule_engine_admin` validates an authenticated endpoint configuration before
  delegating to an injected control-plane transport.

## Build and check are deliberately separate

`rule_engine_pack build` validates the manifest, paths, source index,
dependency closure, archive limits, and any explicitly authorized generator
output. A generator-free pack does not require CPython. Build never imports or
executes a static rule module and never embeds compiled IR.

`rule_engine_check` is the authoritative static-language compile, type, and
optimizer validation path. It requires a staged exact CPython 3.14.6 private
runtime. CPython produces syntax only; C++ owns all accepted language semantics
and executable output.

Unsigned packs and generators are accepted only with the explicit
`--trust-mode development` option. Production verification requires
`--trust-config` and loads OpenSSL only from the configured regular file. The
canonical trust-file format is:

```text
format=1
mode=production
crypto_library=relative/or/absolute/path
signer=sha256:PUBLIC_KEY_DIGEST|64_HEX_PUBLIC_KEY|sorted.pack.prefixes|active
```

`rule_engine_pack sign` requires `--runtime-root` and an explicit absolute
`file:` signer reference. The referenced file contains exactly one raw 32-byte
Ed25519 seed. On Windows it must be a regular local file owned by the caller,
have a protected DACL, and grant access only to the caller, SYSTEM, and
Administrators. The command loads OpenSSL 3 only from the validated exact
private runtime, never copies the key into the archive, never prints the key
reference, refuses to overwrite its output, and reports only the derived key
ID and signature status. `--key-id` can pin the expected derived identity.
`build --signer ...` uses the same adapter after canonical validation.

`rule_engine_pack stubs` verifies the tracked SDK manifest and every declared
file digest, then copies those bytes directly. It does not start Python, import
the SDK, or consult ambient packages.

## Admin boundary

The executable intentionally contains no implicit local administrator and no
unauthenticated fallback. It requires `--config` in this canonical format:

```text
format=1
endpoint=https://control.example/v1
client_certificate=client.pem
client_key=client.key
trust_bundle=trust.pem
actor=operator-identity
```

Relative mTLS paths resolve beside the configuration file. Symlinked or missing
material is rejected. A deployment must inject a real control-plane adapter;
the standalone executable fails with the stable unavailable-transport exit when
none is linked.

The resident server has a separate TLS-only admin listener. Its version-1
canonical length-prefixed application codec is deliberately narrow: pack
snapshot, operation snapshot, and final activation flip. It resolves the mTLS
peer through `rule-engine.operator-bindings.v1` and then calls
`AuthorizedActivationAdmin`; it never trusts an actor string from the request.
The bounded tab-separated binding snapshot is:

```text
rule-engine.operator-bindings.v1
tenant<TAB>peer<TAB>principal<TAB>administrator|automation|pack_signer<TAB>home-tenant<TAB>pack-prefix<TAB>pack.read,operation.read,pack.activate
```

Each peer and principal is unique. Capabilities are named explicitly, tenant
and pack prefix must match, and a `pack_signer` identity is rejected as an
administrator even if the row lists an admin capability.

## Resident service bounds

`rule_engine_server` requires explicit worker count, queued-session count,
application-memory reservation, frame size, messages per session, in-flight
work, session duration, and independent inbound byte/message/work/snapshot
credits. The fixed `std::jthread` pool owns every accepted TLS application
session; overload closes the newly authenticated connection, shutdown requests
cancellation and joins all workers, and no detached thread is used. The
application-memory reservation does not claim to include OS socket buffers,
OpenSSL allocator overhead, or backend-internal caches.

## Current limits

- The worker's process and resource limits contain ordinary failure and abuse;
  they are not a hostile-code sandbox for a trusted generator.
- The standalone admin CLI transport adapter is not linked by this component;
  the resident server's narrow authenticated admin listener is linked as
  described above. The offline file signer is currently implemented only on
  Windows; HSM/KMS/PKCS#11 providers remain deployment integrations.
- The resident listener currently requires mTLS even when development
  configuration permits loopback plaintext; startup fails closed instead of
  dereferencing a missing TLS context. Accept and TLS handshake are serialized
  before bounded worker admission, and an injected agent backend supplies one
  initial work batch per session.
- Archive publication uses a same-directory hard link to provide atomic
  no-clobber behavior. Filesystems without hard-link support fail closed.
- `--watch` coordinates cancellation and publication generations, but a
  platform filesystem event source is not yet linked into the standalone
  executable, and cancellation is observed between compile phases rather than
  terminating an in-flight parser worker.
- The compiler currently exposes richer fact explanations separately from its
  `PackCompiler` result, so check validates the same captured AST through both
  the rich static compiler and the server-facing adapter and rejects any
  semantic-hash divergence.
