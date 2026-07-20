from rule_engine import Identity, Model, Sensitive, provider_fact, rule


class Process(Model):
    """One stable process incarnation on one authenticated endpoint."""

    pid: Identity[int]
    creation_time: Identity[int]
    image_path: Sensitive[str]
    is_signed: bool = provider_fact(route="process.signer.is_signed")


@rule("com.example.process.unsigned")
def unsigned_process(process: Process) -> bool:
    return not process.is_signed
