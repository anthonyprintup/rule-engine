# Python Rule Examples

This is the shortest path from a one-condition process rule to a composed
detection. The complete, copyable tour lives in
[`examples/python/authoring_tour`](../../examples/python/authoring_tour/README.md).

Python is the authoring language, not the execution runtime. The pinned CPython
worker parses source as data; C++ type-checks, lowers, verifies, budgets, and
executes it. Endpoints return typed facts and observations. They never receive
the rule predicate or make the match decision.

## Read the status labels first

- **Runnable now** — checked-in below the tour's `src/` directory, lowered to
  verified bytecode, and executable by the C++ VM.
- **Contract example** — checked-in below `contract/`, where it documents the
  intended authoring API. The current checker rejects at least one construct
  until that execution lane is implemented.

Contract examples are deliberately not entry modules. Moving one into `src/`
does not enable it, and the engine must never approximate its meaning. See
[`IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md) for the current boundary
and [`VM_SEMANTICS.md`](VM_SEMANTICS.md) for the execution graph, suspension,
budgets, journals, retries, and commits.

## 1. Start with one Boolean decision

**Runnable now.** The smallest useful process rule requests one fact and returns
one verdict:

```python
@rule("com.example.tour.01-unsigned-process")
def unsigned_process(process: Process) -> bool:
    return not process.is_signed
```

`process.is_signed` is a lazy provider fact. C++ requests it only when evaluation
reaches that expression, validates the returned value, resumes the VM, and
retains ownership of the decision.

Full source:
[`src/authoring_tour/rules.py`](../../examples/python/authoring_tour/src/authoring_tour/rules.py).

## 2. Filter before requesting more

**Runnable now.** Put cheap or selective conditions first:

```python
@rule("com.example.tour.02-filtered-process")
def filtered_process(process: Process) -> bool:
    if process.is_signed:
        return False
    return process.thread_count >= 32
```

A signed process returns before `thread_count` is requested. Python's
left-to-right evaluation order is observable and is preserved by the compiler.
This is the basic pattern for process filtering: narrow the population, then
request the next fact.

## 3. Remember a result

**Runnable now.** Scalar peer- or subject-scoped state lets a rule report a
condition only once:

```python
@rule("com.example.tour.03-first-unsigned-process")
def first_unsigned_process(process: Process, state: State) -> bool:
    if process.is_signed:
        return False

    seen = state.get(SEEN_UNSIGNED)
    state.set(SEEN_UNSIGNED, True)
    return seen is None
```

The read and write use a statically declared `StateKey`. Reached writes are
journaled and become visible only with the rule result and cursor in the durable
commit.

## 4. Emit a typed report

**Runnable now.** `telemetry.emit(...)` records an internal typed event in the
same result transaction:

```python
telemetry.emit(
    UnsignedProcessAlert(
        process_id=process.pid,
        creation_time=process.creation_time,
        reason="unsigned-process",
    )
)
return True
```

The event must have a stable `@schema`; each field has a unique positive
`wire_field` ID; construction is by keyword; and `telemetry.emit(...)` is a
standalone statement. In the full source, `severity` is omitted here and the
compiler materializes its declared canonical string default. That default is a
constructor convenience only: `severity` remains present and required in the
wire record, so adding it required the example's new `v2` schema ID. A failed
or cancelled attempt publishes neither the verdict nor the event.

This is different from posting to an external system. External posts use a
durable outbox and remain a contract example below.

## 5. Consume a system event

**Contract example.** A validated observation can become the typed input to a
system-event rule:

```python
@correlation(
    "com.example.system-event.suspicious-process-start",
    group_by=lambda event: (event.peer_id, event.payload.process_id),
)
def suspicious_process_start(event: ObservationEvent[ProcessStart]) -> bool:
    start = event.payload
    if "powershell" not in start.image_path.casefold():
        return False
    return "-encodedcommand" in start.command_line.casefold()
```

This keeps provider collection separate from server-owned filtering. Full
example:
[`01_system_event_rule.py`](../../examples/python/authoring_tour/contract/01_system_event_rule.py).

## 6. Scan, then filter typed matches

**Contract example.** Pattern declarations cover exact bytes, encoded text,
masked bytes, and RE2 regular expressions. A bounded scan returns an ordered
`MatchSet`, and the rule filters typed metadata such as `pattern_id`,
permissions, length, offset, address, and bounded context:

```python
matches = memory.scan(
    [MZ_HEADER, POWERSHELL_UTF16, INJECTOR_PROLOGUE, DOWNLOAD_URL],
    before=8,
    after=16,
    maximum_matches=64,
)
for match in matches:
    if match.pattern_id == POWERSHELL_UTF16.id:
        if "execute" in match.permissions and match.length >= 10:
            return True
return False
```

The endpoint performs only the requested bounded observation; the server owns
the match filter and verdict. Full example:
[`02_scan_and_match_filtering.py`](../../examples/python/authoring_tour/contract/02_scan_and_match_filtering.py).

## 7. Select diagnostic traces

**Contract example.** Trace calls select already captured, bounded flight-
recorder information for publication:

```python
signed = process.is_signed
trace(signed, label="signer-result")
if signed:
    return False

trace.enable()
with trace.scope(enabled=True):
    thread_count = process.thread_count
    trace(thread_count, label="unsigned-thread-count")
    return thread_count >= 32
```

Recording must be armed by pack/operator policy before execution starts.
Rule-side `trace.enable()` cannot retroactively create unbounded history. Full
example:
[`03_execution_tracing.py`](../../examples/python/authoring_tour/contract/03_execution_tracing.py).

## 8. Post a session report

**Contract example.** A `PostSink` creates a durable external-delivery intent,
while session-scoped state records reporting progress:

```python
reports(
    SessionReport(
        session_id=session_id,
        matched_rule="com.example.report.session-match",
        process_id=process_id,
    )
)
state.set(SESSION_REPORT_COUNT, 1 if sent is None else sent + 1)
return True
```

The post is dispatched only from the committed outbox; the rule never performs
ambient network I/O. Queue, dry-run, or suppression policy does not change the
detection verdict. Full example:
[`04_post_and_session_reporting.py`](../../examples/python/authoring_tour/contract/04_post_and_session_reporting.py).

## 9. Correlate bounded history

**Contract example.** History queries must be bounded, and correlation keys
serialize related events:

```python
recent = (
    history.events(UnsignedProcessAlert)
    .peer(event.peer_id)
    .between(
        event.ingest_timestamp - timedelta(minutes=10),
        event.ingest_timestamp,
    )
    .where(lambda item: item.payload.process_id == event.payload.process_id)
    .order_by("producer")
    .limit(20)
)
return await recent.count() >= 3
```

Full example:
[`05_history_and_correlation.py`](../../examples/python/authoring_tour/contract/05_history_and_correlation.py).

## 10. Enrich through an optional service

**Contract example.** Services are typed capabilities, not arbitrary Python
clients. Structured async bounds their lifetime:

```python
if reputation is None:
    return False

async with TaskGroup(on_exit=TaskGroupExit.CANCEL_PENDING) as group:
    lookup = group.start(reputation.lookup(ReputationRequest(sha256=sha256)))
    result = await lookup
    return result.score < 20
```

Full example:
[`06_service_enrichment.py`](../../examples/python/authoring_tour/contract/06_service_enrichment.py).

## 11. Put the stages together

The larger examples are intentionally last:

- **Dummy malware detection — contract example.** Filter signed processes,
  avoid duplicate work with subject state, scan readable memory for a
  reflective-loader pattern, request optional reputation, select trace
  evidence, emit a typed alert, and enqueue a SOC ticket:
  [`07_combined_malware_detection.py`](../../examples/python/authoring_tour/contract/07_combined_malware_detection.py).
- **Dummy cheat detection — contract example.** Consume remote-thread system
  events, group them by protected game process, query a bounded recent window,
  select trace evidence, emit an alert, and enqueue a human-review request:
  [`08_combined_cheat_detection.py`](../../examples/python/authoring_tour/contract/08_combined_cheat_detection.py).

These examples show how the capabilities compose; they do not claim the
unfinished lanes are runnable.

## Build the runnable tour

Use repository-built tools and the checksum-verified private runtime. Do not run
the modules directly or substitute a system Python:

```powershell
rule_engine_pack build examples/python/authoring_tour `
  --output authoring-tour.rpack `
  --trust-mode development

rule_engine_check `
  --pack authoring-tour.rpack `
  --runtime-root C:/rule-engine/libexec/rule_engine/python/runtime/3.14.6 `
  --trust-mode development `
  --format text
```

Continue with the tour's
[`README`](../../examples/python/authoring_tour/README.md), the
[`VM semantics`](VM_SEMANTICS.md), and the full
[`authoring-language contract`](architecture/02-authoring-language-and-types.md).
