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

## External static qualification

From the repository root, run the exact independently installed tools below.
They read the strict checked-in `pyproject.toml` configuration and do not become
build, runtime, or SDK dependencies:

```powershell
uvx --from pyright==1.1.411 pyright sdk tests/sdk/authoring_surface.py
uvx --from ruff==0.15.22 ruff check sdk tests/sdk/authoring_surface.py
```

The author SDK was qualified on 2026-07-21 with Pyright 1.1.411 and Ruff
0.15.22. Both tools support the SDK's required Python 3.14 syntax; the recorded
qualification result is zero Pyright errors/warnings and all Ruff checks
passing. CPython itself remains pinned separately and exactly to 3.14.6.
