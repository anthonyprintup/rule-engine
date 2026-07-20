"""Fail-closed runtime sentinels for the static rule authoring package.

Rule modules are parsed as data and must never be imported by CPython. The
objects here exist only to make an accidental import fail with a precise error
instead of silently supplying a second implementation of rule semantics.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final

SDK_VERSION: Final = "1.0.0"
ENGINE_API: Final = 1
PYTHON_ABI: Final = "3.14.6"


class StaticIntrinsicError(RuntimeError):
    """Raised when a compiler-owned rule intrinsic is executed by CPython."""


def _unavailable(name: str) -> StaticIntrinsicError:
    return StaticIntrinsicError(
        f"rule_engine.{name} is a static compiler intrinsic; "
        "rule modules must be checked/compiled, never imported or executed"
    )


class _StaticOnly:
    def __new__(cls, *args: object, **kwargs: object) -> object:
        raise _unavailable(cls.__name__)


class Model(_StaticOnly):
    pass


class WireRecord(_StaticOnly):
    pass


class EventRecord(WireRecord):
    pass


class StateRecord(WireRecord):
    pass


class _TypeMarker:
    __slots__ = ("_name",)

    def __init__(self, name: str) -> None:
        self._name = name

    def __getitem__(self, item: object) -> object:
        return item

    def __repr__(self) -> str:
        return self._name


Identity = _TypeMarker("Identity")
Public = _TypeMarker("Public")
Internal = _TypeMarker("Internal")
Sensitive = _TypeMarker("Sensitive")
Secret = _TypeMarker("Secret")


def _intrinsic(name: str):
    def unavailable(*args: object, **kwargs: object) -> object:
        raise _unavailable(name)

    unavailable.__name__ = name
    return unavailable


provider_fact = _intrinsic("provider_fact")
wire_field = _intrinsic("wire_field")
schema = _intrinsic("schema")
rule = _intrinsic("rule")
rule_template = _intrinsic("rule_template")
correlation = _intrinsic("correlation")
correlation_template = _intrinsic("correlation_template")
bind = _intrinsic("bind")
state_migration = _intrinsic("state_migration")
transaction = _intrinsic("transaction")
retry_once = _intrinsic("retry_once")
complete = _intrinsic("complete")
abort = _intrinsic("abort")
quarantine = _intrinsic("quarantine")
keep = _intrinsic("keep")
replace = _intrinsic("replace")
finalizer_abort = _intrinsic("finalizer_abort")
on_fault = _intrinsic("on_fault")
on_double_fault = _intrinsic("on_double_fault")
finalizer = _intrinsic("finalizer")


class _IntrinsicObject:
    __slots__ = ("_name",)

    def __init__(self, name: str) -> None:
        object.__setattr__(self, "_name", name)

    def __call__(self, *args: object, **kwargs: object) -> object:
        raise _unavailable(self._name)

    def __getattr__(self, name: str) -> object:
        raise _unavailable(f"{self._name}.{name}")

    def __setattr__(self, name: str, value: object) -> Never:
        raise _unavailable(f"{self._name}.{name}")


pattern = _IntrinsicObject("pattern")
telemetry = _IntrinsicObject("telemetry")
retention = _IntrinsicObject("retention")
trace = _IntrinsicObject("trace")


class FactError(RuntimeError):
    pass


class FactNotFound(FactError):
    pass


class FactUnsupported(FactError):
    pass


class FactAccessDenied(FactError):
    pass


class FactTimedOut(FactError):
    pass


class FactUnavailable(FactError):
    pass


class FactCanceled(FactError):
    pass


class FactMalformed(FactError):
    pass


class FactProtocolViolation(FactError):
    pass


class BoundaryValidationError(RuntimeError):
    pass


class DataPolicyViolation(RuntimeError):
    pass


class ScanResultLimitExceeded(RuntimeError):
    pass


class HistoryError(RuntimeError):
    pass


class HistoryUnavailable(HistoryError):
    pass


class HistoryLimitExceeded(HistoryError):
    pass


class ServiceError(RuntimeError):
    pass


class ServiceUnavailable(ServiceError):
    pass


class ServiceTimedOut(ServiceError):
    pass


class ServiceCanceled(ServiceError):
    pass


class ServiceRejected(ServiceError):
    pass


class ServiceMalformed(ServiceError):
    pass


class FaultedRule(RuntimeError):
    pass


class SoftBudgetExceeded(RuntimeError):
    pass


class StateScope(StrEnum):
    SESSION = "session"
    PEER = "peer"
    SUBJECT = "subject"
    CORRELATION_GROUP = "correlation_group"
    SHARED = "shared"


class PostDisposition(StrEnum):
    QUEUED = "queued"
    DRY_RUN = "dry_run"
    SUPPRESSED = "suppressed"


class TaskGroupExit(StrEnum):
    CANCEL_PENDING = "cancel_pending"
    WAIT_PENDING = "wait_pending"


class FaultKind(StrEnum):
    PYTHON_EXCEPTION = "python_exception"
    ENGINE_EXCEPTION = "engine_exception"
    CONTROL_FAULT = "control_fault"
    INTEGRITY_FAULT = "integrity_fault"


_STATIC_CLASSES = (
    "BoundEntrypoint SubjectKey Pattern Match MatchSet ScanSpace PatternFactory "
    "EventEnvelope ObservationEvent RemovalEvent MatchEvent FaultEvent "
    "ActionDeliveryEvent CaptureResultEvent HistoryQuery History FleetHistory "
    "StateKey State SharedState Transaction PostReceipt PostCapabilities "
    "EventReceipt Telemetry RetentionReceipt RetainReads Retention CaptureReceipt "
    "TraceScope Trace Service ServiceCall TaskHandle TaskGroup Fault FaultChain "
    "FaultContext FinalizerContext FaultDecision RetryOnce Complete Abort Quarantine "
    "FinalizerDecision Keep Replace FinalizerAbort"
).split()

for _class_name in _STATIC_CLASSES:
    globals()[_class_name] = type(_class_name, (_StaticOnly,), {})


def __getattr__(name: str) -> object:
    raise _unavailable(name)


__all__ = [name for name in globals() if not name.startswith("_")]
