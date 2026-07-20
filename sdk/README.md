# Rule Engine Python SDK

This directory contains the versioned source artifacts used by pack tooling to
materialize the Python 3.14 authoring environment.

- `rule_engine` is a PEP 561 declaration package. Its runtime module contains
  only fail-closed sentinels so a rule module cannot accidentally acquire
  semantics by being imported by CPython.
- `rule_engine_generator` is the small deterministic runtime made available to
  an already trusted, signed binding generator. It exposes declared input
  aliases and typed binding factories, but no filesystem, network, process,
  clock, environment, or import capabilities.
- `manifest.json` records the exact SDK/API versions and SHA-256 digests used by
  pack staging. `verify_manifest.py` verifies that surface without importing
  either package.

The C++ compiler and VM remain authoritative. These Python artifacts provide
editor types, parse-time declarations, and trusted-generator proposal
serialization only.
