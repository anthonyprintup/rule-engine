"""CONTRACT EXAMPLE: history and correlation execution are not lowered yet."""

from datetime import timedelta

from rule_engine import (
    EventEnvelope,
    EventRecord,
    History,
    correlation,
    schema,
    wire_field,
)


@schema("com.example.unsigned-process-alert.v2")
class UnsignedProcessAlert(EventRecord):
    process_id: int = wire_field(id=1)
    creation_time: int = wire_field(id=2)
    reason: str = wire_field(id=3)
    severity: str = wire_field(id=4, default="medium")


@correlation(
    "com.example.correlation.repeated-unsigned-process",
    group_by=lambda event: (event.peer_id, event.payload.process_id),
    order_by="event_time",
    allowed_lateness=timedelta(minutes=2),
)
async def repeated_unsigned_process(
    event: EventEnvelope[UnsignedProcessAlert],
    history: History,
) -> bool:
    if event.peer_id is None:
        return False

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
