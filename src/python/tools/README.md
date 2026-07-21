# Python command-line tooling

This component owns the local author and operator entrypoints:

- `rule_engine_pack` canonicalizes source-only packs, verifies trust, inspects
  redacted metadata, and copies the pinned PEP 561 SDK;
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

## Current limits

- The worker's process and resource limits contain ordinary failure and abuse;
  they are not a hostile-code sandbox for a trusted generator.
- External signing and the authenticated admin transport are integration
  adapters and are not linked by this component.
- `--watch` coordinates cancellation and publication generations, but a
  platform filesystem event source is not yet linked into the standalone
  executable, and cancellation is observed between compile phases rather than
  terminating an in-flight parser worker.
- The compiler currently exposes richer fact explanations separately from its
  `PackCompiler` result, so check validates the same captured AST through both
  the rich static compiler and the server-facing adapter and rejects any
  semantic-hash divergence.
