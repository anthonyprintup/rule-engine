"""CONTRACT EXAMPLE: a composed game-cheat detection using system events."""

from datetime import timedelta

from rule_engine import (
    EventRecord,
    History,
    ObservationEvent,
    PostSink,
    WireRecord,
    correlation,
    schema,
    telemetry,
    trace,
    wire_field,
)


@schema("com.example.remote-thread.v1")
class RemoteThreadCreated(WireRecord):
    source_process_id: int = wire_field(id=1)
    target_process_id: int = wire_field(id=2)
    start_address: int = wire_field(id=3)
    target_is_protected_game: bool = wire_field(id=4)


@schema("com.example.cheat-alert.v1")
class CheatAlert(EventRecord):
    source_process_id: int = wire_field(id=1)
    target_process_id: int = wire_field(id=2)
    reason: str = wire_field(id=3)


@schema("com.example.review-request.v1")
class ReviewRequest(WireRecord):
    source_process_id: int = wire_field(id=1)
    target_process_id: int = wire_field(id=2)


@schema("com.example.review-ack.v1")
class ReviewAck(WireRecord):
    case_id: str = wire_field(id=1)


@correlation(
    "com.example.cheat.remote-thread-burst",
    group_by=lambda event: (event.peer_id, event.payload.target_process_id),
    order_by="ingest_time",
    allowed_lateness=timedelta(seconds=30),
    trace_policy="diagnostic.v1",
)
async def remote_thread_burst(
    event: ObservationEvent[RemoteThreadCreated],
    history: History,
    review: PostSink[ReviewRequest, ReviewAck],
) -> bool:
    current = event.payload
    if not current.target_is_protected_game:
        return False
    if event.peer_id is None:
        return False

    recent = (
        history.events(RemoteThreadCreated)
        .peer(event.peer_id)
        .between(
            event.ingest_timestamp - timedelta(minutes=2),
            event.ingest_timestamp,
        )
        .where(
            lambda item: item.payload.target_process_id
            == current.target_process_id
        )
        .limit(16)
    )
    if await recent.count() < 3:
        return False

    trace.enable()
    trace(
        current.source_process_id,
        current.target_process_id,
        current.start_address,
        label="remote-thread-burst",
    )
    telemetry.emit(
        CheatAlert(
            source_process_id=current.source_process_id,
            target_process_id=current.target_process_id,
            reason="repeated-remote-thread-creation",
        )
    )
    review(
        ReviewRequest(
            source_process_id=current.source_process_id,
            target_process_id=current.target_process_id,
        )
    )
    return True
