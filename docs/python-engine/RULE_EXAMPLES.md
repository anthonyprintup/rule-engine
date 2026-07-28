# Python Rule Examples

This is the short, practical guide to reading and writing rules on the Python
branch. It starts with code that works end to end today, then shows the wider
authoring contract for pattern matches, history, state, correlations, and
effects.

Python is the authoring language, not the runtime. The pinned CPython worker
turns source into bounded syntax data; C++ validates, compiles, verifies, and
executes it. Rule modules are never imported to make a decision.

## Status labels

The examples use two labels:

- **Runnable now** means `rule_engine_check` can lower the shown source to
  verified bytecode and the C++ VM can execute it.
- **Contract example** means the SDK and engine design define the API, but
  source lowering is not complete. The checker rejects it rather than silently
  changing its meaning.

For the exact boundary, see
[`IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md) and
[`LIMITATIONS.md`](LIMITATIONS.md).

## A runnable rule pack

**Runnable now.** A minimal pack has one manifest and one or more modules below
`src/`:

```text
endpoint-rules/
|-- rulepack.toml
`-- src/
    `-- acme/
        `-- endpoint_rules.py
```

`rulepack.toml`:

```toml
format = 1

[pack]
id = "com.acme.endpoint-rules"
version = "1.0.0"
kind = "rules"
engine_api = 1
python = "3.14.6"
entry_modules = ["acme.endpoint_rules"]
budget_profile = "balanced.v1"
policy_profile = "development.v1"

[capabilities]
required = []
optional = []
```

`src/acme/endpoint_rules.py`:

```python
from rule_engine import Model, provider_fact, rule


class Process(Model):
    is_signed: bool = provider_fact(route="process.signer.is_signed")
    thread_count: int = provider_fact(route="process.thread_count")


@rule("com.acme.unsigned-high-thread-count")
def unsigned_high_thread_count(process: Process) -> bool:
    # Cheap, selective filters go first. Because fact reads are lazy, a signed
    # process returns before thread_count is requested.
    signed = process.is_signed
    if signed:
        return False

    thread_count = process.thread_count
    thresholds = [4, 16, 64]
    votes = 0

    for threshold in thresholds:
        if thread_count > threshold:
            votes = votes + 1

    return votes >= 2
```

The rule illustrates four useful habits:

1. Put cheap filters before expensive facts.
2. Save a fact in a local when it will be used more than once.
3. Keep loops over fresh, visibly bounded collections.
4. Return a Boolean verdict; providers never receive the predicate.

Evaluation order is Python's left-to-right order. Reordering the two fact reads
would be an observable semantic change and is not allowed.

## Pattern declarations and match filtering

**Contract example.** These four declarations cover exact bytes, encoded text,
masked bytes, and RE2 regular expressions:

```python
from rule_engine import ScanSpace, pattern, rule


DOS_HEADER = pattern.bytes(
    b"MZ",
    id="com.acme.pattern.dos-header",
)
POWERSHELL_UTF16 = pattern.text(
    "powershell",
    encoding="utf-16-le",
    case="ascii_insensitive",
    id="com.acme.pattern.powershell",
)
FUNCTION_PROLOGUE = pattern.masked(
    "48 8B ?? ?5 A? ??",
    id="com.acme.pattern.function-prologue",
)
URL = pattern.regex(
    r"https?://[^\s]+",
    dialect="re2",
    encoding="utf-8",
    id="com.acme.pattern.url",
)


@rule("com.acme.suspicious-executable-content")
def suspicious_executable_content(memory: ScanSpace) -> bool:
    matches = memory.scan(
        [POWERSHELL_UTF16, FUNCTION_PROLOGUE, URL],
        before=8,
        after=16,
        maximum_matches=64,
    )

    for match in matches:
        # This is a rule-side filter over typed match metadata. The endpoint
        # returns observations; it never evaluates this predicate.
        if match.pattern_id != POWERSHELL_UTF16.id:
            continue
        if "execute" not in match.permissions:
            continue
        if match.length < 10:
            continue
        return True

    return False
```

`MatchSet` is ordered and bounded. Each `Match` exposes:

| Field | Meaning |
|---|---|
| `pattern_id` | Stable ID of the declaration that matched |
| `subject` | Typed subject that was scanned |
| `offset` | Offset within the scan space |
| `absolute_address` | Address when the scan space has one |
| `length` | Matched byte length |
| `permissions` | Read, write, and execute labels |
| `before`, `matched`, `after` | Optional bounded context bytes |

The requested context and match cap are part of the scan request and its
budget. Reaching a configured result limit is a typed failure, not an
unbounded list.

## History filters, correlations, state, and effects

**Contract example.** This compact example shows how the remaining pieces fit
together. It is intentionally a sketch of one flow rather than a production
rule pack:

```python
from datetime import datetime, timedelta

from rule_engine import (
    EventEnvelope,
    EventRecord,
    History,
    State,
    StateKey,
    StateScope,
    correlation,
    schema,
    telemetry,
    transaction,
    wire_field,
)


@schema("com.acme.alert.v1")
class Alert(EventRecord):
    process_id: int = wire_field(id=1)
    reason: str = wire_field(id=2)


ALERT_COUNT = StateKey(
    "com.acme.alert-count",
    int,
    scope=StateScope.PEER,
    default=0,
)


@correlation(
    "com.acme.repeated-alerts",
    group_by=lambda event: event.peer_id,
    order_by="event_time",
    allowed_lateness=timedelta(minutes=5),
)
async def repeated_alerts(
    event: EventEnvelope[Alert],
    history: History,
    state: State,
) -> bool:
    if event.peer_id is None:
        return False

    window = (
        history.events(Alert)
        .peer(event.peer_id)
        .between(datetime(2026, 1, 1), datetime(2026, 1, 2))
        .where(lambda item: item.payload.reason == event.payload.reason)
        .order_by("producer")
        .limit(20)
    )

    if not await window.exists():
        return False

    with transaction() as tx:
        count = state.get(ALERT_COUNT)
        state.set(ALERT_COUNT, 1 if count is None else count + 1)
        telemetry.emit(
            Alert(process_id=event.payload.process_id, reason="repeated-alert")
        )
        tx.commit()

    return True
```

The history chain is declarative and bounded: tenant/peer/time predicates are
eligible for store pushdown, `.where(...)` is still defined by C++ semantics,
and `.limit(...)` is mandatory protection against open-ended reads.

State writes and emitted events are journaled. They become visible only with
the rule result and cursor in one durable commit. A fault, cancellation, or
uncommitted transaction discards them.

The custom-event portion of this example is intentionally strict:
`EventRecord` requires one stable `@schema`, every field needs a unique positive
`wire_field` ID, construction supplies every field by keyword, and
`telemetry.emit(...)` is a standalone statement. Positional/default construction
and using an in-rule `EventReceipt` are not yet supported.

## What is usable today

| Authoring area | Current branch |
|---|---|
| `@rule`, models, and `provider_fact(route="...")` | Runnable now |
| Scalar expressions, branches, calls, and Boolean return | Runnable now |
| Fresh list/tuple/dict values and subscriptions | Runnable now |
| Bounded synchronous `for` loops | Runnable now |
| Closed `try`/`except`/`else`/`finally` subset | Runnable now |
| Pattern declarations, scans, and `MatchSet` filtering | Contract; lowering incomplete |
| History and correlation source | Contract; lowering incomplete |
| State records, transactions, telemetry, and services | Contract; lowering incomplete |
| Ambient/runtime imports, reflection, dynamic code, and native extensions | Deliberately unsupported |

The SDK may expose a contract before its complete lowering exists so authors
can type-check designs without the engine pretending they are executable.

## Build and check

Use the repository-built tools and the checksum-verified private runtime:

```powershell
rule_engine_pack build C:/rules/endpoint-rules `
  --output C:/packs/endpoint-rules.rpack `
  --trust-mode development

rule_engine_check `
  --pack C:/packs/endpoint-rules.rpack `
  --runtime-root C:/runtime/python-3.14.6 `
  --trust-mode development `
  --format text
```

`rule_engine_pack` creates a deterministic source-only archive.
`rule_engine_check` invokes the parser worker and the C++ compiler/verifier. Do
not use a system Python or run the module directly.

For the full language contract, continue with
[`architecture/02-authoring-language-and-types.md`](architecture/02-authoring-language-and-types.md).
For VM behavior, read [`VM_SEMANTICS.md`](VM_SEMANTICS.md).
