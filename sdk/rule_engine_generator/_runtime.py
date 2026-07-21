# pyright: strict, reportPrivateUsage=false, reportUnusedFunction=false
from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import struct
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum, StrEnum
from types import MappingProxyType
from typing import Final, Self, cast

type _LiteralValue = None | bool | float | str | bytes
type _EnumMemberValue = None | bool | int | str

_ID_PATTERN: Final = re.compile(r"[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?\Z")
_ALIAS_PATTERN: Final = re.compile(r"[a-z][a-z0-9_-]{0,62}\Z")
_PARAMETER_PATTERN: Final = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_ARGUMENT_DOMAIN: Final = b"rule-engine-generator-arguments-v1\0"
_OUTPUT_DOMAIN: Final = b"rule-engine-generator-output-v1\0"
_NO_DEFAULT: Final = object()
_BINDING_TOKEN: Final = object()
_CONTEXT_TOKEN: Final = object()


class GeneratorSdkError(RuntimeError):
    pass


class InputAliasError(GeneratorSdkError):
    pass


class InputFormatError(GeneratorSdkError):
    pass


class InputDecodeError(GeneratorSdkError):
    pass


class BindingValidationError(GeneratorSdkError):
    pass


class DuplicateBindingError(GeneratorSdkError):
    pass


class ContextSealedError(GeneratorSdkError):
    pass


class InputFormat(StrEnum):
    BYTES = "bytes"
    UTF8 = "utf8"
    JSON = "json"


@dataclass(frozen=True, slots=True)
class ValueSpec:
    kind: str
    children: tuple[ValueSpec, ...] = ()
    metadata: tuple[object, ...] = ()

    def __post_init__(self) -> None:
        allowed = {
            "none",
            "bool",
            "int",
            "float",
            "str",
            "bytes",
            "list",
            "tuple",
            "dict",
            "set",
            "frozenset",
            "union",
            "literal",
            "enum",
            "record",
        }
        if self.kind not in allowed:
            raise BindingValidationError(f"unsupported value specification: {self.kind}")


NONE: Final = ValueSpec("none")
BOOL: Final = ValueSpec("bool")
INT: Final = ValueSpec("int")
FLOAT: Final = ValueSpec("float")
STR: Final = ValueSpec("str")
BYTES: Final = ValueSpec("bytes")


def list_of(item: ValueSpec, /) -> ValueSpec:
    return ValueSpec("list", (item,))


def tuple_of(*items: ValueSpec, variadic: bool = False) -> ValueSpec:
    if not items:
        raise BindingValidationError("tuple specification requires at least one item type")
    if variadic and len(items) != 1:
        raise BindingValidationError("a variadic tuple has exactly one item type")
    return ValueSpec("tuple", tuple(items), (variadic,))


def dict_of(key: ValueSpec, value: ValueSpec, /) -> ValueSpec:
    return ValueSpec("dict", (key, value))


def set_of(item: ValueSpec, /) -> ValueSpec:
    return ValueSpec("set", (item,))


def frozenset_of(item: ValueSpec, /) -> ValueSpec:
    return ValueSpec("frozenset", (item,))


def union_of(*items: ValueSpec) -> ValueSpec:
    flattened: list[ValueSpec] = []
    for item in items:
        flattened.extend(item.children if item.kind == "union" else (item,))
    if len(flattened) < 2:
        raise BindingValidationError("a union requires at least two alternatives")
    return ValueSpec("union", tuple(flattened))


def optional(item: ValueSpec, /) -> ValueSpec:
    return union_of(NONE, item)


def literal(*values: None | bool | float | str | bytes) -> ValueSpec:
    if not values:
        raise BindingValidationError("a literal specification cannot be empty")
    for value in values:
        _canonical_node(value)
    return ValueSpec("literal", metadata=(tuple(values),))


def enum_of(id: str, members: dict[str, None | bool | int | str], /) -> ValueSpec:
    _validate_stable_id(id, "enum schema ID")
    if not members:
        raise BindingValidationError("an enum specification cannot be empty")
    normalized: list[tuple[str, object]] = []
    for name, value in members.items():
        if not _PARAMETER_PATTERN.fullmatch(name):
            raise BindingValidationError(f"invalid enum member name: {name!r}")
        _canonical_node(value)
        normalized.append((name, value))
    normalized.sort(key=lambda item: item[0])
    return ValueSpec("enum", metadata=(id, tuple(normalized)))


def record_of(id: str, fields: tuple[ParameterSpec, ...] | list[ParameterSpec], /) -> ValueSpec:
    _validate_stable_id(id, "record schema ID")
    normalized = tuple(fields)
    _validate_parameters(normalized)
    return ValueSpec("record", metadata=(id, normalized))


@dataclass(frozen=True, slots=True, init=False)
class ParameterSpec:
    name: str
    value: ValueSpec
    required: bool
    default: object

    def __init__(
        self,
        name: str,
        value: object,
        /,
        *,
        required: bool = True,
        default: object = _NO_DEFAULT,
    ) -> None:
        if not _PARAMETER_PATTERN.fullmatch(name):
            raise BindingValidationError(f"invalid binding parameter name: {name!r}")
        if not isinstance(value, ValueSpec):
            raise BindingValidationError(f"parameter {name!r} has no ValueSpec")
        if required and default is not _NO_DEFAULT:
            raise BindingValidationError(f"required parameter {name!r} cannot have a default")
        if not required and default is _NO_DEFAULT:
            raise BindingValidationError(f"optional parameter {name!r} requires a default")
        if default is not _NO_DEFAULT:
            default = _validate_value(value, default, name)
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "value", value)
        object.__setattr__(self, "required", required)
        object.__setattr__(self, "default", default)


@dataclass(frozen=True, slots=True)
class _EnumValue:
    schema_id: str
    member: str


@dataclass(frozen=True, slots=True)
class _RecordValue:
    schema_id: str
    fields: tuple[tuple[str, object], ...]


class BindingSpec:
    __slots__ = ("_canonical_arguments", "_id", "_template_id")

    def __new__(
        cls,
        token: object = None,
        id: str = "",
        template_id: str = "",
        canonical_arguments: bytes = b"",
    ) -> Self:
        if token is not _BINDING_TOKEN:
            raise BindingValidationError("BindingSpec is opaque; use a generated binding factory")
        return super().__new__(cls)

    def __init__(
        self,
        token: object = None,
        id: str = "",
        template_id: str = "",
        canonical_arguments: bytes = b"",
    ) -> None:
        self._id = id
        self._template_id = template_id
        self._canonical_arguments = canonical_arguments

    def __repr__(self) -> str:
        return f"BindingSpec(id={self._id!r}, template={self._template_id!r})"

    def __setattr__(self, name: str, value: object) -> None:
        if hasattr(self, name):
            raise BindingValidationError("BindingSpec is immutable")
        object.__setattr__(self, name, value)


class BindingFactory:
    __slots__ = ("_by_name", "parameters", "template_id")

    def __init__(self, template_id: str, parameters: tuple[ParameterSpec, ...] | list[ParameterSpec], /) -> None:
        _validate_stable_id(template_id, "template ID")
        normalized = tuple(parameters)
        _validate_parameters(normalized)
        self.template_id = template_id
        self.parameters = normalized
        self._by_name = MappingProxyType({parameter.name: parameter for parameter in normalized})

    def __call__(self, *, id: str, **arguments: object) -> BindingSpec:
        _validate_stable_id(id, "binding ID")
        unknown = sorted(set(arguments) - set(self._by_name))
        if unknown:
            raise BindingValidationError(f"unknown binding argument(s): {', '.join(unknown)}")
        validated: list[tuple[str, object]] = []
        for parameter in self.parameters:
            if parameter.name in arguments:
                raw = arguments[parameter.name]
            elif parameter.required:
                raise BindingValidationError(f"missing binding argument: {parameter.name}")
            else:
                raw = parameter.default
            validated.append((parameter.name, _validate_value(parameter.value, raw, parameter.name)))
        canonical = _ARGUMENT_DOMAIN + _canonical_json_bytes(
            {"$": "arguments", "values": [[name, _canonical_node(value)] for name, value in validated]}
        )
        return BindingSpec(_BINDING_TOKEN, id, self.template_id, canonical)


@dataclass(frozen=True, slots=True)
class _DeclaredInput:
    format: InputFormat
    payload: bytes


@dataclass(frozen=True, slots=True)
class _CanonicalProposal:
    id: str
    template_id: str
    canonical_arguments: bytes


@dataclass(frozen=True, slots=True)
class _GenerationResult:
    proposals: tuple[_CanonicalProposal, ...]
    canonical_bytes: bytes
    sha256: str


class GenerationContext:
    __slots__ = ("_emitted", "_inputs", "_json_cache", "_sealed")

    def __new__(
        cls,
        token: object = None,
        inputs: dict[str, _DeclaredInput] | None = None,
    ) -> Self:
        if token is not _CONTEXT_TOKEN:
            raise GeneratorSdkError("GenerationContext is created only by the private worker")
        return super().__new__(cls)

    def __init__(
        self,
        token: object = None,
        inputs: dict[str, _DeclaredInput] | None = None,
    ) -> None:
        if inputs is None:
            raise GeneratorSdkError("GenerationContext requires private worker inputs")
        self._inputs = MappingProxyType(dict(inputs))
        self._json_cache: dict[str, object] = {}
        self._emitted: dict[str, BindingSpec] = {}
        self._sealed = False

    def bytes(self, name: str) -> bytes:
        return bytes(self._input(name, InputFormat.BYTES).payload)

    def text(self, name: str) -> str:
        payload = self._input(name, InputFormat.UTF8).payload
        try:
            return payload.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise InputDecodeError(f"declared UTF-8 input {name!r} is invalid") from error

    def json(self, name: str) -> object:
        declared = self._input(name, InputFormat.JSON)
        if name not in self._json_cache:
            try:
                text = declared.payload.decode("utf-8", errors="strict")
                value = json.loads(
                    text,
                    object_pairs_hook=_json_object,
                    parse_constant=_reject_json_constant,
                )
            except (UnicodeDecodeError, json.JSONDecodeError, InputDecodeError) as error:
                if isinstance(error, InputDecodeError):
                    raise
                raise InputDecodeError(f"declared JSON input {name!r} is invalid") from error
            self._json_cache[name] = _freeze_json(value)
        return self._json_cache[name]

    def emit(self, binding: object) -> None:
        if self._sealed:
            raise ContextSealedError("generator context is sealed")
        if not isinstance(binding, BindingSpec):
            raise BindingValidationError("ctx.emit accepts only an opaque BindingSpec")
        if binding._id in self._emitted:
            raise DuplicateBindingError(f"duplicate generated binding ID: {binding._id}")
        self._emitted[binding._id] = binding

    def _input(self, name: str, expected: InputFormat) -> _DeclaredInput:
        if self._sealed:
            raise ContextSealedError("generator context is sealed")
        declared = self._inputs.get(name)
        if declared is None:
            raise InputAliasError(f"undeclared generator input alias: {name!r}")
        if declared.format is not expected:
            raise InputFormatError(
                f"generator input {name!r} is {declared.format.value}, not {expected.value}"
            )
        return declared


def _create_generation_context(
    inputs: Mapping[str, tuple[str | InputFormat, object]],
) -> GenerationContext:
    declared: dict[str, _DeclaredInput] = {}
    for name, (raw_format, payload) in inputs.items():
        if not _ALIAS_PATTERN.fullmatch(name):
            raise InputAliasError(f"invalid generator input alias: {name!r}")
        if name in declared:
            raise InputAliasError(f"duplicate generator input alias: {name!r}")
        try:
            input_format = InputFormat(raw_format)
        except ValueError as error:
            raise InputFormatError(f"invalid input format for {name!r}: {raw_format!r}") from error
        if not isinstance(payload, bytes):
            raise InputDecodeError(f"input payload for {name!r} must be bytes")
        declared[name] = _DeclaredInput(input_format, payload)
    return GenerationContext(_CONTEXT_TOKEN, declared)


def _finish_generation(context: object) -> _GenerationResult:
    if not isinstance(context, GenerationContext):
        raise GeneratorSdkError("worker tried to finish an invalid generation context")
    if context._sealed:
        raise ContextSealedError("generator context is already sealed")
    context._sealed = True
    proposals = tuple(
        _CanonicalProposal(binding._id, binding._template_id, binding._canonical_arguments)
        for _, binding in sorted(context._emitted.items())
    )
    output = bytearray(_OUTPUT_DOMAIN)
    output.extend(struct.pack("<I", len(proposals)))
    for proposal in proposals:
        _append_blob(output, proposal.id.encode("utf-8"))
        _append_blob(output, proposal.template_id.encode("utf-8"))
        _append_blob(output, proposal.canonical_arguments)
    canonical = bytes(output)
    return _GenerationResult(proposals, canonical, "sha256:" + hashlib.sha256(canonical).hexdigest())


def _validate_parameters(parameters: tuple[object, ...]) -> None:
    seen: set[str] = set()
    for parameter in parameters:
        if not isinstance(parameter, ParameterSpec):
            raise BindingValidationError("binding parameter table contains a non-ParameterSpec value")
        if parameter.name in seen:
            raise BindingValidationError(f"duplicate binding parameter: {parameter.name}")
        seen.add(parameter.name)


def _validate_stable_id(value: object, label: str) -> None:
    if not isinstance(value, str) or unicodedata.normalize("NFC", value) != value or not _ID_PATTERN.fullmatch(value):
        raise BindingValidationError(f"invalid {label}: {value!r}")


def _validate_value(spec: ValueSpec, value: object, path: str) -> object:
    kind = spec.kind
    if kind == "none":
        if value is None:
            return None
    elif kind == "bool":
        if type(value) is bool:
            return value
    elif kind == "int":
        if type(value) is int:
            return value
    elif kind == "float":
        if type(value) is int:
            return float(value)
        if type(value) is float and math.isfinite(value):
            return value
    elif kind == "str":
        if isinstance(value, str):
            return value
    elif kind == "bytes":
        if isinstance(value, bytes):
            return value
    elif kind == "list":
        if isinstance(value, list):
            values = cast(list[object], value)
            return [_validate_value(spec.children[0], item, f"{path}[]") for item in values]
    elif kind == "tuple":
        if isinstance(value, tuple):
            values = cast(tuple[object, ...], value)
            variadic = cast(bool, spec.metadata[0])
            if variadic:
                return tuple(_validate_value(spec.children[0], item, f"{path}[]") for item in values)
            if len(values) == len(spec.children):
                return tuple(
                    _validate_value(item_spec, item, f"{path}[{index}]")
                    for index, (item_spec, item) in enumerate(zip(spec.children, values, strict=True))
                )
    elif kind == "dict":
        if isinstance(value, dict):
            values = cast(dict[object, object], value)
            return {
                _validate_value(spec.children[0], key, f"{path}.key"): _validate_value(
                    spec.children[1], item, f"{path}[{key!r}]"
                )
                for key, item in values.items()
            }
    elif kind == "set":
        if isinstance(value, set):
            values = cast(set[object], value)
            return {_validate_value(spec.children[0], item, f"{path}[]") for item in values}
    elif kind == "frozenset":
        if isinstance(value, frozenset):
            values = cast(frozenset[object], value)
            return frozenset(_validate_value(spec.children[0], item, f"{path}[]") for item in values)
    elif kind == "union":
        for child in spec.children:
            try:
                return _validate_value(child, value, path)
            except BindingValidationError:
                pass
    elif kind == "literal":
        literal_values = cast(tuple[_LiteralValue, ...], spec.metadata[0])
        for literal_value in literal_values:
            if type(value) is type(literal_value) and value == literal_value:
                return value
    elif kind == "enum":
        schema_id = cast(str, spec.metadata[0])
        members = cast(tuple[tuple[str, _EnumMemberValue], ...], spec.metadata[1])
        member_map = dict(members)
        if isinstance(value, Enum) and value.name in member_map and value.value == member_map[value.name]:
            return _EnumValue(schema_id, value.name)
        for member, member_value in members:
            if type(value) is type(member_value) and value == member_value:
                return _EnumValue(schema_id, member)
    elif kind == "record":
        schema_id = cast(str, spec.metadata[0])
        fields = cast(tuple[ParameterSpec, ...], spec.metadata[1])
        if isinstance(value, dict):
            values = cast(dict[object, object], value)
            expected = {field.name for field in fields}
            if set(values) == expected:
                return _RecordValue(
                    schema_id,
                    tuple(
                        (
                            field.name,
                            _validate_value(
                                field.value,
                                values[field.name],
                                f"{path}.{field.name}",
                            ),
                        )
                        for field in fields
                    ),
                )
    raise BindingValidationError(f"binding argument {path!r} does not match {kind}")


def _canonical_node(value: object) -> object:
    if value is None:
        return {"$": "none"}
    if type(value) is bool:
        return {"$": "bool", "value": value}
    if type(value) is int:
        negative = value < 0
        magnitude = abs(value)
        raw = magnitude.to_bytes((magnitude.bit_length() + 7) // 8, "big")
        return {
            "$": "int",
            "magnitude_be": base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii"),
            "negative": negative,
        }
    if type(value) is float:
        if not math.isfinite(value):
            raise BindingValidationError("non-finite float cannot cross the generator boundary")
        return {"$": "float64", "bits": struct.pack(">d", value).hex()}
    if isinstance(value, str):
        return {"$": "str", "value": value}
    if isinstance(value, bytes):
        return {"$": "bytes", "base64": base64.b64encode(value).decode("ascii")}
    if isinstance(value, _EnumValue):
        return {"$": "enum", "schema": value.schema_id, "member": value.member}
    if isinstance(value, _RecordValue):
        return {
            "$": "record",
            "schema": value.schema_id,
            "fields": [[name, _canonical_node(item)] for name, item in value.fields],
        }
    if isinstance(value, list):
        values = cast(list[object], value)
        return {"$": "list", "items": [_canonical_node(item) for item in values]}
    if isinstance(value, tuple):
        values = cast(tuple[object, ...], value)
        return {"$": "tuple", "items": [_canonical_node(item) for item in values]}
    if isinstance(value, dict):
        values = cast(dict[object, object], value)
        pairs = [(_canonical_node(key), _canonical_node(item)) for key, item in values.items()]
        pairs.sort(key=lambda pair: _canonical_json_bytes(pair[0]))
        return {"$": "dict", "items": [[key, item] for key, item in pairs]}
    if isinstance(value, (set, frozenset)):
        values = cast(set[object] | frozenset[object], value)
        items = [_canonical_node(item) for item in values]
        items.sort(key=_canonical_json_bytes)
        return {"$": "frozenset" if isinstance(value, frozenset) else "set", "items": items}
    raise BindingValidationError(f"value of type {type(value).__name__} is not canonical")


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")


def _json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise InputDecodeError(f"duplicate JSON object key: {name!r}")
        result[name] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise InputDecodeError(f"non-finite JSON number is forbidden: {value}")


def _freeze_json(value: object) -> object:
    if value is None or type(value) in (bool, int, str):
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise InputDecodeError("non-finite JSON number is forbidden")
        return value
    if isinstance(value, list):
        values = cast(list[object], value)
        return tuple(_freeze_json(item) for item in values)
    if isinstance(value, dict):
        values = cast(dict[str, object], value)
        return MappingProxyType({name: _freeze_json(item) for name, item in values.items()})
    raise InputDecodeError(f"unsupported JSON value: {type(value).__name__}")


def _append_blob(output: bytearray, value: bytes) -> None:
    if len(value) > 0xFFFFFFFF:
        raise BindingValidationError("canonical generator field exceeds u32 length")
    output.extend(struct.pack("<I", len(value)))
    output.extend(value)
