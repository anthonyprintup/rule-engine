# Python Rule Engine Design

This directory is the durable product specification for the Python rule engine. It records the intended architecture, the reasoning behind its boundaries, rejected alternatives, verification criteria, and known limitations. C++ remains the semantic authority; Python is a statically checked authoring language and a short-lived parse/generation dependency only.

## Reading order

1. [`architecture/00-system-context.md`](architecture/00-system-context.md) — ownership, deployment, and end-to-end flows.
2. [`architecture/01-trust-and-threat-model.md`](architecture/01-trust-and-threat-model.md) — explicit source trust and abuse boundaries.
3. [`architecture/02-authoring-language-and-types.md`](architecture/02-authoring-language-and-types.md) — accepted Python surface and typing rules.
4. [`architecture/03-rulepacks-and-python-worker.md`](architecture/03-rulepacks-and-python-worker.md) — signed packs, dependencies, CPython 3.14.6, and deterministic generators.
5. [`architecture/04-compiler-ir-and-vm.md`](architecture/04-compiler-ir-and-vm.md) — compiler stages, verified bytecode, resumable execution, and budgets.
6. [`architecture/05-facts-subjects-and-scanning.md`](architecture/05-facts-subjects-and-scanning.md) — typed recursive identities, lazy facts, and scan plans.
7. [`architecture/06-effects-services-faults-and-replay.md`](architecture/06-effects-services-faults-and-replay.md) — transactional effects, labels, structured async, faults, and replay.
8. [`architecture/07-events-history-state-and-correlation.md`](architecture/07-events-history-state-and-correlation.md) — event time, history, MVCC state, and correlation.
9. [`architecture/08-protocol-storage-and-cluster.md`](architecture/08-protocol-storage-and-cluster.md) — protocol v2, stores, leases, fencing, and active-active coordination.
10. [`architecture/09-activation-operations-and-tooling.md`](architecture/09-activation-operations-and-tooling.md) — atomic activation and operational surfaces.
11. [`architecture/10-verification-and-cutover.md`](architecture/10-verification-and-cutover.md) — qualification and the no-compatibility cutover gate.

The frozen cross-component API expectations are in [`CONTRACTS.md`](CONTRACTS.md). Consolidated design limitations are in [`LIMITATIONS.md`](LIMITATIONS.md). The `decisions/` directory contains the eighteen accepted architecture decision records and their rejected alternatives.

## Status convention

Architecture statements define the target contract. A feature is implemented only when its code and acceptance tests are present; documentation alone is not evidence of completion. Any temporary implementation gap must remain visible in `LIMITATIONS.md` and the repository status documentation until its qualification gate passes.
