"""CONTRACT EXAMPLE: trace authoring and publication are not lowered yet."""

from rule_engine import Model, provider_fact, rule, trace


class Process(Model):
    is_signed: bool = provider_fact(route="process.signer.is_signed")
    thread_count: int = provider_fact(route="process.thread_count")


@rule(
    "com.example.trace.unsigned-process",
    trace_policy="diagnostic.v1",
)
def traced_unsigned_process(process: Process) -> bool:
    signed = process.is_signed
    trace(signed, label="signer-result")
    if signed:
        return False

    # An operator/pack policy must arm recording before execution starts.
    # Enabling here selects the already captured bounded history for publication.
    trace.enable()
    with trace.scope(enabled=True):
        thread_count = process.thread_count
        trace(thread_count, label="unsigned-thread-count")
        return thread_count >= 32
