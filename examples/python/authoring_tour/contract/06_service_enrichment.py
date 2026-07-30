"""CONTRACT EXAMPLE: services and structured async are not lowered yet."""

from rule_engine import (
    Service,
    ServiceCall,
    TaskGroup,
    TaskGroupExit,
    WireRecord,
    rule,
    schema,
    wire_field,
)


@schema("com.example.reputation-request.v1")
class ReputationRequest(WireRecord):
    sha256: bytes = wire_field(id=1)


@schema("com.example.reputation-response.v1")
class ReputationResponse(WireRecord):
    score: int = wire_field(id=1)
    family: str = wire_field(id=2)


class Reputation(Service):
    def lookup(
        self,
        request: ReputationRequest,
    ) -> ServiceCall[ReputationResponse]: ...


@rule("com.example.service.low-reputation")
async def low_reputation(
    sha256: bytes,
    reputation: Reputation | None,
) -> bool:
    if reputation is None:
        return False

    async with TaskGroup(on_exit=TaskGroupExit.CANCEL_PENDING) as group:
        lookup = group.start(reputation.lookup(ReputationRequest(sha256=sha256)))
        result = await lookup
        return result.score < 20
