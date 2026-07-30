"""CONTRACT EXAMPLE: post sinks and session-scoped state are not lowered yet."""

from rule_engine import (
    PostSink,
    State,
    StateKey,
    StateScope,
    WireRecord,
    rule,
    schema,
    wire_field,
)


@schema("com.example.session-report.v1")
class SessionReport(WireRecord):
    session_id: str = wire_field(id=1)
    matched_rule: str = wire_field(id=2)
    process_id: int = wire_field(id=3)


@schema("com.example.session-report-ack.v1")
class SessionReportAck(WireRecord):
    accepted: bool = wire_field(id=1)


SESSION_REPORT_COUNT = StateKey(
    "com.example.session-report-count",
    int,
    scope=StateScope.SESSION,
    default=0,
)


@rule("com.example.report.session-match")
def report_session_match(
    session_id: str,
    process_id: int,
    state: State,
    reports: PostSink[SessionReport, SessionReportAck],
) -> bool:
    sent = state.get(SESSION_REPORT_COUNT)
    report = SessionReport(
        session_id=session_id,
        matched_rule="com.example.report.session-match",
        process_id=process_id,
    )
    reports(report)
    state.set(SESSION_REPORT_COUNT, 1 if sent is None else sent + 1)
    # Delivery policy never changes the detection verdict. The durable intent
    # may be queued, dry-run, or suppressed without turning this into NO_MATCH.
    return True
