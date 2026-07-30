# Python rule authoring tour

This directory is a short-to-complex tour of the Python authoring model. Start
with the four runnable rules in
[`src/authoring_tour/rules.py`](src/authoring_tour/rules.py), then read the
contract examples in number order.

Python source is parsed as data by the pinned CPython 3.14.6 worker. It is never
imported or executed to make a decision. The C++ compiler, verifier, VM, and
resident runtime own all semantics, budgets, effects, and durable commits.

## Two support levels

- **Runnable now:** part of `entry_modules`; the checker lowers it to verified
  bytecode and the C++ VM executes it.
- **Contract example:** intentionally outside `src/`; the SDK defines the
  author-facing shape, but the current checker rejects at least one construct
  until that runtime lane is complete.

This separation is deliberate. Moving a contract file into `src/` does not
enable a feature and must fail closed rather than approximate its behavior.

## Reading path

| Step | File | What it teaches | Status |
|---|---|---|---|
| 1 | `rules.py`: `unsigned_process` | Minimal process rule | Runnable now |
| 2 | `rules.py`: `filtered_process` | Early filters and lazy facts | Runnable now |
| 3 | `rules.py`: `first_unsigned_process` | Peer-scoped scalar state | Runnable now |
| 4 | `rules.py`: `report_unsigned_process` | Typed transactional telemetry | Runnable now |
| 5 | `contract/01_system_event_rule.py` | Validated system events | Contract |
| 6 | `contract/02_scan_and_match_filtering.py` | Exact/text/masked/RE2 patterns and typed match filters | Contract |
| 7 | `contract/03_execution_tracing.py` | Trace annotations and recorder publication | Contract |
| 8 | `contract/04_post_and_session_reporting.py` | Durable posts and session-scoped reporting state | Contract |
| 9 | `contract/05_history_and_correlation.py` | Bounded history and serialized correlation | Contract |
| 10 | `contract/06_service_enrichment.py` | Optional services and structured async | Contract |
| 11 | `contract/07_combined_malware_detection.py` | Filter, scan, enrich, trace, state, emit, and post | Contract |
| 12 | `contract/08_combined_cheat_detection.py` | System-event correlation, trace, event, and review post | Contract |

## Build the runnable pack

From a configured rule-engine installation:

```powershell
rule_engine_pack build . --output authoring-tour.rpack

rule_engine_check `
  --pack authoring-tour.rpack `
  --runtime-root C:/rule-engine/libexec/rule_engine/python/runtime/3.14.6 `
  --trust-mode development
```

The pack is source-only. Production activation additionally requires an
operator-authorized Ed25519 signature and capability/policy bindings.

For a compact explanation of each example and its execution behavior, see
[`docs/python-engine/RULE_EXAMPLES.md`](../../../docs/python-engine/RULE_EXAMPLES.md).
For instruction, suspension, budget, journal, retry, and commit semantics, see
[`docs/python-engine/VM_SEMANTICS.md`](../../../docs/python-engine/VM_SEMANTICS.md).
