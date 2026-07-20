"""One-request CPython 3.14.6 AST and trusted-generator worker.

The parent supplies a reduced environment and a Windows Job Object to contain
failures and ordinary resource abuse. Those controls are availability defenses;
this worker is not a hostile-code sandbox for a malicious trusted signer.
"""

import ast
import base64
import contextlib
import hashlib
import inspect
import io
import json
import os
import struct
import sys
import tokenize
import types
import unicodedata


PROTOCOL = 1
RUNTIME_VERSION = "3.14.6"
RUNTIME_SHA256 = "df901e84a896ff1ee720ad03377e0c8d8c2244fda79808aeeaff6316df1cb75c"
SOURCE_SCHEMA = "rule-engine.source/1"
AST_SCHEMA = "rule-engine.ast/1"
GENERATOR_REQUEST_SCHEMA = "rule-engine.generator-request/1"
BINDINGS_SCHEMA = "rule-engine.bindings/1"
MAXIMUM_FRAME_BYTES = 256 * 1024 * 1024
MAXIMUM_BINDINGS = 100_000


def _read_exact(stream, size):
    chunks = []
    remaining = size
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            raise ValueError("truncated worker frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_frame():
    header = _read_exact(sys.stdin.buffer, 4)
    (size,) = struct.unpack("<I", header)
    if size > MAXIMUM_FRAME_BYTES:
        raise ValueError("worker frame exceeds the protocol bound")
    payload = _read_exact(sys.stdin.buffer, size)
    if sys.stdin.buffer.read(1):
        raise ValueError("worker protocol accepts exactly one request")
    return payload


def _write_frame(payload):
    if len(payload) > MAXIMUM_FRAME_BYTES:
        raise ValueError("worker response exceeds the protocol bound")
    sys.stdout.buffer.write(struct.pack("<I", len(payload)))
    sys.stdout.buffer.write(payload)
    sys.stdout.buffer.flush()


def _strict_base64(value):
    if not isinstance(value, str):
        raise ValueError("base64 value must be a string")
    return base64.b64decode(value, validate=True)


def _tag_string(value):
    encoded = value.encode("utf-8", errors="surrogatepass")
    return {"$": "str", "wtf8_base64": base64.urlsafe_b64encode(encoded).decode("ascii").rstrip("=")}


def _tag_integer(value):
    negative = value < 0
    magnitude = -value if negative else value
    size = (magnitude.bit_length() + 7) // 8
    encoded = magnitude.to_bytes(size, "big") if size else b""
    return {
        "$": "int",
        "negative": negative,
        "magnitude_be": base64.urlsafe_b64encode(encoded).decode("ascii").rstrip("="),
    }


def _tag_float(value):
    return {"$": "float64", "bits": struct.pack(">d", value).hex()}


def _ast_span(node):
    if not hasattr(node, "lineno"):
        return None
    return {
        "col": node.col_offset,
        "end_col": getattr(node, "end_col_offset", None),
        "end_line": getattr(node, "end_lineno", None),
        "line": node.lineno,
    }


def _encode_ast_value(value):
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, ast.AST):
        fields = {}
        for field in value._fields:
            fields[field] = _encode_ast_value(getattr(value, field))
        return {"$": "ast", "kind": type(value).__name__, "fields": fields, "span": _ast_span(value)}
    if isinstance(value, list):
        return [_encode_ast_value(item) for item in value]
    if isinstance(value, str):
        return _tag_string(value)
    if isinstance(value, bytes):
        return {"$": "bytes", "base64": base64.b64encode(value).decode("ascii")}
    if isinstance(value, int):
        return _tag_integer(value)
    if isinstance(value, float):
        return _tag_float(value)
    if value is Ellipsis:
        return {"$": "ellipsis"}
    raise TypeError(f"unsupported AST scalar: {type(value).__name__}")


def _token_table(source_bytes):
    result = []
    for token in tokenize.tokenize(io.BytesIO(source_bytes).readline):
        result.append(
            {
                "end": [token.end[0], token.end[1]],
                "start": [token.start[0], token.start[1]],
                "string": _tag_string(token.string),
                "type": token.type,
            }
        )
    return result


def _parse_payload(source_bytes, source_id):
    source = source_bytes.decode("utf-8", errors="strict")
    if source.startswith("\ufeff") or "\r" in source:
        raise ValueError("source must be canonical UTF-8 without BOM and with LF line endings")
    tree = ast.parse(
        source,
        filename=source_id,
        mode="exec",
        type_comments=True,
        feature_version=(3, 14),
        optimize=0,
    )
    envelope = {
        "ast": _encode_ast_value(tree),
        "format": 1,
        "schema": AST_SCHEMA,
        "tokens": _token_table(source_bytes),
        "worker": {
            "build": "rule-engine-python-worker/1",
            "cache_tag": sys.implementation.cache_tag,
            "python": RUNTIME_VERSION,
            "unicode": unicodedata.unidata_version,
        },
    }
    return json.dumps(envelope, ensure_ascii=True, separators=(",", ":")).encode("utf-8")


def _canonical_generator_value(value):
    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, int):
        return _tag_integer(value)
    if isinstance(value, float):
        return _tag_float(value)
    if isinstance(value, bytes):
        return {"$": "bytes", "base64": base64.b64encode(value).decode("ascii")}
    if isinstance(value, (list, tuple)):
        return [_canonical_generator_value(item) for item in value]
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise TypeError("generator argument maps require string keys")
        return {key: _canonical_generator_value(value[key]) for key in sorted(value)}
    raise TypeError(f"unsupported generator argument: {type(value).__name__}")


class _BindingSpec:
    __slots__ = ("arguments", "binding_id", "template_id")

    def __init__(self, binding_id, template_id, arguments):
        self.binding_id = binding_id
        self.template_id = template_id
        self.arguments = arguments


class _GenerationContext:
    __slots__ = ("_emitted", "_inputs")

    def __init__(self, inputs):
        self._inputs = inputs
        self._emitted = []

    def bytes(self, name):
        value = self._inputs[name]
        if value[0] != "bytes":
            raise TypeError(f"input {name!r} is not declared as bytes")
        return value[1]

    def text(self, name):
        value = self._inputs[name]
        if value[0] != "utf8":
            raise TypeError(f"input {name!r} is not declared as utf8")
        return value[1]

    def json(self, name):
        value = self._inputs[name]
        if value[0] != "json":
            raise TypeError(f"input {name!r} is not declared as json")
        return value[1]

    def emit(self, binding):
        if not isinstance(binding, _BindingSpec):
            raise TypeError("emit accepts only generated BindingSpec objects")
        self._emitted.append(binding)
        if len(self._emitted) > MAXIMUM_BINDINGS:
            raise ValueError("generator binding count exceeds the protocol bound")


def _identifier(value, field):
    if (
        not isinstance(value, str)
        or not value
        or any(ord(character) < 0x21 or ord(character) > 0x7E or character in {'"', "\\"} for character in value)
    ):
        raise ValueError(f"{field} must be a nonempty printable ASCII string")
    return value


def _generator_payload(payload_bytes, source_id):
    request = json.loads(payload_bytes.decode("utf-8", errors="strict"))
    if not isinstance(request, dict) or set(request) != {"callable", "inputs", "module_source_b64", "templates"}:
        raise ValueError("generator request payload fields are invalid")
    canonical = json.dumps(request, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if canonical != payload_bytes:
        raise ValueError("generator request payload is not canonical JSON")
    callable_name = _identifier(request["callable"], "generator callable")
    module_source = _strict_base64(request["module_source_b64"])
    source_text = module_source.decode("utf-8", errors="strict")
    if source_text.startswith("\ufeff") or "\r" in source_text:
        raise ValueError("generator source is not canonical UTF-8/LF text")

    inputs = {}
    previous_name = None
    if not isinstance(request["inputs"], list):
        raise ValueError("generator inputs must be a list")
    for item in request["inputs"]:
        if not isinstance(item, dict) or set(item) != {"data_b64", "format", "name"}:
            raise ValueError("generator input descriptor is invalid")
        name = _identifier(item["name"], "generator input name")
        if previous_name is not None and name <= previous_name:
            raise ValueError("generator inputs must be sorted and duplicate-free")
        previous_name = name
        raw = _strict_base64(item["data_b64"])
        if item["format"] == "bytes":
            value = raw
        elif item["format"] == "utf8":
            value = raw.decode("utf-8", errors="strict")
        elif item["format"] == "json":
            value = json.loads(raw.decode("utf-8", errors="strict"))
        else:
            raise ValueError("generator input format is invalid")
        inputs[name] = (item["format"], value)

    api_module = types.ModuleType("rule_engine_generator")
    bindings_module = types.ModuleType("rule_engine_generator.bindings")
    api_module.GenerationContext = _GenerationContext
    api_module.BindingSpec = _BindingSpec
    api_module.bindings = bindings_module
    previous_factory = None
    if not isinstance(request["templates"], list):
        raise ValueError("generator templates must be a list")
    for item in request["templates"]:
        if not isinstance(item, dict) or set(item) != {"factory", "template_id"}:
            raise ValueError("generator template descriptor is invalid")
        factory_name = _identifier(item["factory"], "generator factory")
        template_id = _identifier(item["template_id"], "generator template ID")
        if previous_factory is not None and factory_name <= previous_factory:
            raise ValueError("generator factories must be sorted and duplicate-free")
        previous_factory = factory_name

        def make_factory(bound_template_id):
            def factory(*, id, **arguments):
                return _BindingSpec(_identifier(id, "binding ID"), bound_template_id, arguments)

            return factory

        factory = make_factory(template_id)
        factory.__name__ = factory_name
        setattr(bindings_module, factory_name, factory)

    sys.modules["rule_engine_generator"] = api_module
    sys.modules["rule_engine_generator.bindings"] = bindings_module
    namespace = {"__builtins__": __builtins__, "__name__": "rule_engine_pack_generator", "__package__": None}
    context = _GenerationContext(inputs)
    diagnostics_stdout = io.StringIO()
    diagnostics_stderr = io.StringIO()
    with contextlib.redirect_stdout(diagnostics_stdout), contextlib.redirect_stderr(diagnostics_stderr):
        exec(compile(source_text, source_id, "exec", dont_inherit=True, optimize=0), namespace)
        entrypoint = namespace.get(callable_name)
        if not inspect.isfunction(entrypoint) or inspect.iscoroutinefunction(entrypoint):
            raise TypeError("generator entrypoint must be one synchronous Python function")
        returned = entrypoint(context)
        if inspect.isawaitable(returned):
            raise TypeError("generator entrypoint returned an awaitable")
        if returned is not None:
            for binding in returned:
                context.emit(binding)
    diagnostics = (diagnostics_stdout.getvalue() + diagnostics_stderr.getvalue()).encode("utf-8", errors="replace")
    if diagnostics:
        sys.stderr.buffer.write(diagnostics[: 64 * 1024])
        sys.stderr.buffer.flush()

    bindings = []
    seen_ids = set()
    for binding in sorted(context._emitted, key=lambda item: item.binding_id):
        if binding.binding_id in seen_ids:
            raise ValueError(f"duplicate generated binding ID: {binding.binding_id}")
        seen_ids.add(binding.binding_id)
        arguments = json.dumps(
            _canonical_generator_value(binding.arguments),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        bindings.append(
            {
                "arguments_b64": base64.b64encode(arguments).decode("ascii"),
                "id": binding.binding_id,
                "template_id": binding.template_id,
            }
        )
    envelope = {"bindings": bindings, "format": 1, "schema": BINDINGS_SCHEMA}
    return json.dumps(envelope, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _response(request, mode, status, schema, payload):
    response = {
        "mode": mode,
        "payload": base64.b64encode(payload).decode("ascii"),
        "payload_schema": schema,
        "protocol": PROTOCOL,
        "request_id": request["request_id"],
        "runtime_sha256": RUNTIME_SHA256,
        "runtime_version": RUNTIME_VERSION,
        "source_digest": request["source_digest"],
        "source_id": request["source_id"],
        "status": status,
    }
    return json.dumps(response, ensure_ascii=True, separators=(",", ":")).encode("utf-8")


def _error_payload(error):
    if isinstance(error, SyntaxError):
        detail = {
            "class": "SyntaxError",
            "end_col": error.end_offset,
            "end_line": error.end_lineno,
            "line": error.lineno,
            "message": error.msg,
            "offset": error.offset,
            "text": error.text,
        }
    else:
        detail = {"class": type(error).__name__, "message": str(error)}
    return json.dumps({"error": detail, "format": 1}, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _arguments():
    mode = None
    protocol = None
    for argument in sys.argv[1:]:
        if argument.startswith("--mode="):
            mode = argument[7:]
        elif argument.startswith("--protocol="):
            protocol = argument[11:]
        else:
            raise ValueError("unknown worker command-line argument")
    if mode not in {"parse", "generate"} or protocol != "1":
        raise ValueError("worker mode or protocol command-line argument is invalid")
    return mode


def main():
    mode = _arguments()
    if sys.version_info[:3] != (3, 14, 6) or sys.flags.isolated != 1 or sys.flags.no_site != 1:
        raise RuntimeError("worker is not running under the exact isolated CPython 3.14.6 runtime")
    request_bytes = _read_frame()
    request = json.loads(request_bytes.decode("utf-8", errors="strict"))
    expected_fields = {
        "hash_seed",
        "mode",
        "payload",
        "payload_schema",
        "protocol",
        "request_id",
        "runtime_sha256",
        "runtime_version",
        "source_digest",
        "source_id",
    }
    if not isinstance(request, dict) or set(request) != expected_fields:
        raise ValueError("worker request fields are invalid")
    if request["protocol"] != PROTOCOL or request["mode"] != mode:
        raise ValueError("worker request protocol or mode mismatch")
    if request["runtime_version"] != RUNTIME_VERSION or request["runtime_sha256"] != RUNTIME_SHA256:
        raise ValueError("worker request runtime identity mismatch")
    if not isinstance(request["hash_seed"], int) or not 0 <= request["hash_seed"] <= 0xFFFFFFFF:
        raise ValueError("worker hash seed is invalid")
    if os.environ.get("PYTHONHASHSEED") != str(request["hash_seed"]):
        raise ValueError("worker hash seed does not match the reduced launch environment")
    for field in ("request_id", "source_digest", "source_id"):
        _identifier(request[field], field)
    payload = _strict_base64(request["payload"])
    expected_digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    if request["source_digest"] != expected_digest:
        raise ValueError("worker payload digest mismatch")

    if mode == "parse":
        expected_request_schema = SOURCE_SCHEMA
        response_schema = AST_SCHEMA
    else:
        expected_request_schema = GENERATOR_REQUEST_SCHEMA
        response_schema = BINDINGS_SCHEMA
    if request["payload_schema"] != expected_request_schema:
        raise ValueError("worker payload schema does not match its mode")

    try:
        if mode == "parse":
            response_payload = _parse_payload(payload, request["source_id"])
        else:
            response_payload = _generator_payload(payload, request["source_id"])
        response = _response(request, mode, "ok", response_schema, response_payload)
    except (MemoryError, RecursionError, SyntaxError, TypeError, ValueError) as error:
        response = _response(request, mode, "rejected", response_schema, _error_payload(error))
    _write_frame(response)


if __name__ == "__main__":
    try:
        main()
    except BaseException as error:
        sys.stderr.write(f"rule-engine worker fatal: {type(error).__name__}: {error}\n")
        sys.stderr.flush()
        raise SystemExit(2)
