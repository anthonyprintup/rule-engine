from rule_engine import (
    EventRecord,
    Identity,
    Model,
    Sensitive,
    State,
    StateKey,
    StateScope,
    provider_fact,
    rule,
    schema,
    telemetry,
    wire_field,
)


class Process(Model):
    """One stable process incarnation on one authenticated endpoint."""

    pid: Identity[int]
    creation_time: Identity[int]
    image_path: Sensitive[str]
    is_signed: bool = provider_fact(route="process.signer.is_signed")
    thread_count: int = provider_fact(route="process.thread_count")


@schema("com.example.unsigned-process-alert.v1")
class UnsignedProcessAlert(EventRecord):
    process_id: int = wire_field(id=1)
    creation_time: int = wire_field(id=2)
    reason: str = wire_field(id=3)


SEEN_UNSIGNED = StateKey(
    "com.example.seen-unsigned",
    bool,
    scope=StateScope.PEER,
)


@rule("com.example.tour.01-unsigned-process")
def unsigned_process(process: Process) -> bool:
    """Example 1: one fact and one Boolean decision."""

    return not process.is_signed


@rule("com.example.tour.02-filtered-process")
def filtered_process(process: Process) -> bool:
    """Example 2: a cheap early filter avoids a later fact request."""

    if process.is_signed:
        return False

    return process.thread_count >= 32


@rule("com.example.tour.03-first-unsigned-process")
def first_unsigned_process(process: Process, state: State) -> bool:
    """Example 3: remember a peer-local result transactionally."""

    if process.is_signed:
        return False

    seen = state.get(SEEN_UNSIGNED)
    state.set(SEEN_UNSIGNED, True)
    return seen is None


@rule("com.example.tour.04-report-unsigned-process")
def report_unsigned_process(process: Process) -> bool:
    """Example 4: publish a typed event in the result transaction."""

    if process.is_signed:
        return False

    telemetry.emit(
        UnsignedProcessAlert(
            process_id=process.pid,
            creation_time=process.creation_time,
            reason="unsigned-process",
        )
    )
    return True
