from datetime import datetime, timedelta

from rule_engine import (
    EventRecord,
    History,
    Identity,
    Model,
    Sensitive,
    Service,
    ServiceCall,
    State,
    StateKey,
    StateRecord,
    StateScope,
    TaskGroup,
    TaskGroupExit,
    WireRecord,
    bind,
    complete,
    correlation,
    finalizer,
    keep,
    on_fault,
    pattern,
    provider_fact,
    rule_template,
    schema,
    telemetry,
    transaction,
    wire_field,
)

type Score = int


class Process(Model):
    pid: Identity[int]
    creation_time: Identity[int]
    image_path: Sensitive[str]
    is_signed: bool = provider_fact(route="process.signer.is_signed")


@schema("com.example.alert.v1")
class Alert(EventRecord):
    process_id: int = wire_field(id=1)
    explanation: str = wire_field(id=2)


@schema("com.example.counter.v1")
class Counter(StateRecord):
    value: int = wire_field(id=1, default=0)


COUNTER = StateKey(
    "com.example.counter",
    Counter,
    scope=StateScope.PEER,
)
MZ = pattern.bytes(b"MZ")
POWERSHELL = pattern.text(
    "powershell",
    encoding="utf-16-le",
    case="ascii_insensitive",
)
PROLOGUE = pattern.masked("48 8B ?? ?5 A? ??")
URL = pattern.regex(r"https?://[^\\s]+", dialect="re2", encoding="utf-8")


class ReputationRequest(WireRecord):
    digest: bytes


class ReputationResponse(WireRecord):
    score: int


class Reputation(Service):
    def lookup(self, request: ReputationRequest) -> ServiceCall[ReputationResponse]: ...


@rule_template("com.example.unsigned")
async def unsigned_process(
    process: Process,
    threshold: int,
    state: State,
    history: History,
    reputation: Reputation | None,
) -> bool:
    with transaction() as tx:
        if process.is_signed:
            return False
        if reputation is not None:
            async with TaskGroup(on_exit=TaskGroupExit.WAIT_PENDING) as group:
                call = reputation.lookup(ReputationRequest())
                result = await group.start(call)
                if result.score < threshold:
                    telemetry.emit(Alert())
                    tx.commit()
                    return True
        return await history.events(Alert).between(
            datetime(2026, 1, 1),
            datetime(2026, 1, 2),
        ).limit(10).exists()


UNSIGNED = bind(
    unsigned_process,
    id="com.example.unsigned.default",
    threshold=50,
)


@correlation(
    "com.example.alert.correlation",
    group_by=lambda event: event.tenant_id,
    allowed_lateness=timedelta(minutes=5),
)
async def correlate_alert(event: Alert, history: History) -> bool:
    return await history.events(Alert).between(
        datetime(2026, 1, 1),
        datetime(2026, 1, 2),
    ).limit(10).exists()


@on_fault(unsigned_process)
async def recover_unsigned(error: object) -> object:
    return complete(False)


@finalizer(unsigned_process)
def finalize_unsigned(result: object) -> object:
    return keep()
