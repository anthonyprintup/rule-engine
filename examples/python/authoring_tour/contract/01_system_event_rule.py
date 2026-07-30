"""CONTRACT EXAMPLE: typed system-event entrypoints are not lowered yet."""

from rule_engine import ObservationEvent, WireRecord, correlation, schema, wire_field


@schema("com.example.windows.process-start.v1")
class ProcessStart(WireRecord):
    process_id: int = wire_field(id=1)
    parent_process_id: int = wire_field(id=2)
    image_path: str = wire_field(id=3)
    command_line: str = wire_field(id=4)


@correlation(
    "com.example.system-event.suspicious-process-start",
    group_by=lambda event: (event.peer_id, event.payload.process_id),
)
def suspicious_process_start(event: ObservationEvent[ProcessStart]) -> bool:
    """Filter one validated provider event; the endpoint sees no predicate."""

    start = event.payload
    if start.parent_process_id == 0:
        return False
    if "powershell" not in start.image_path.casefold():
        return False
    return "-encodedcommand" in start.command_line.casefold()
