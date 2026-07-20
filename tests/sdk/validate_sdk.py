from __future__ import annotations

import ast
import importlib.util
import sys
import unittest
from pathlib import Path

SDK_ROOT = Path(__file__).resolve().parents[2] / "sdk"
sys.path.insert(0, str(SDK_ROOT))

import rule_engine
import rule_engine_generator as generator
from rule_engine_generator import _runtime


class ExactRuntimeTests(unittest.TestCase):
    def test_exact_isolated_runtime(self) -> None:
        self.assertEqual(sys.version_info[:3], (3, 14, 6))
        self.assertEqual(sys.flags.isolated, 1)
        self.assertEqual(sys.flags.no_site, 1)


class StubSurfaceTests(unittest.TestCase):
    def test_all_sources_parse_as_python_314(self) -> None:
        paths = sorted(SDK_ROOT.rglob("*.py")) + sorted(SDK_ROOT.rglob("*.pyi"))
        self.assertTrue(paths)
        for path in paths:
            compile(path.read_text(encoding="utf-8"), str(path), "exec")
        fixture = Path(__file__).with_name("authoring_surface.py")
        compile(fixture.read_text(encoding="utf-8"), str(fixture), "exec")

    def test_root_stub_declares_complete_intrinsic_families(self) -> None:
        tree = ast.parse((SDK_ROOT / "rule_engine" / "__init__.pyi").read_text(encoding="utf-8"))
        names = {
            node.name
            for node in tree.body
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
        }
        required = {
            "Model",
            "WireRecord",
            "EventRecord",
            "StateRecord",
            "provider_fact",
            "wire_field",
            "schema",
            "rule",
            "rule_template",
            "correlation",
            "correlation_template",
            "bind",
            "PatternFactory",
            "MatchSet",
            "History",
            "HistoryQuery",
            "StateKey",
            "State",
            "SharedState",
            "Transaction",
            "PostSink",
            "Telemetry",
            "Retention",
            "PeerCapture",
            "Service",
            "ServiceCall",
            "TaskGroup",
            "on_fault",
            "on_double_fault",
            "finalizer",
            "retry_once",
            "complete",
            "abort",
            "quarantine",
            "keep",
            "replace",
        }
        self.assertEqual(required - names, set())

    def test_runtime_intrinsics_fail_closed(self) -> None:
        calls = (
            lambda: rule_engine.provider_fact(route="process.pid"),
            lambda: rule_engine.rule("com.example.rule"),
            lambda: rule_engine.pattern.bytes(b"MZ"),
            lambda: rule_engine.transaction(),
            lambda: rule_engine.telemetry.emit(object()),
            lambda: rule_engine.TaskGroup(),
        )
        for call in calls:
            with self.assertRaises(rule_engine.StaticIntrinsicError):
                call()

        class Process(rule_engine.Model):
            pid: rule_engine.Identity[int]

        with self.assertRaises(rule_engine.StaticIntrinsicError):
            Process()

    def test_static_runtime_has_no_semantic_backend(self) -> None:
        source = (SDK_ROOT / "rule_engine" / "__init__.py").read_text(encoding="utf-8")
        forbidden = ("subprocess", "socket", "ctypes", "importlib", "eval(", "exec(", "open(")
        self.assertFalse([name for name in forbidden if name in source])


class GeneratorSdkTests(unittest.TestCase):
    @staticmethod
    def context(order: bool = False) -> generator.GenerationContext:
        items = [
            ("groups", ("json", b'[{"id":"com.example.a","threshold":7}]')),
            ("notice", ("utf8", "hello".encode())),
            ("opaque", ("bytes", b"\x00\xff")),
        ]
        if order:
            items.reverse()
        return _runtime._create_generation_context(dict(items))

    @staticmethod
    def factory() -> generator.BindingFactory:
        return generator.BindingFactory(
            "com.example.template",
            (
                generator.ParameterSpec("threshold", generator.INT),
                generator.ParameterSpec("tags", generator.set_of(generator.STR)),
                generator.ParameterSpec(
                    "note",
                    generator.optional(generator.STR),
                    required=False,
                    default=None,
                ),
            ),
        )

    def test_declared_inputs_are_format_checked_and_immutable(self) -> None:
        context = self.context()
        self.assertEqual(context.bytes("opaque"), b"\x00\xff")
        self.assertEqual(context.text("notice"), "hello")
        rows = context.json("groups")
        self.assertIsInstance(rows, tuple)
        with self.assertRaises(TypeError):
            rows[0]["id"] = "changed"
        with self.assertRaises(generator.InputFormatError):
            context.text("opaque")
        with self.assertRaises(generator.InputAliasError):
            context.bytes("missing")

    def test_json_rejects_duplicates_and_nonfinite_values(self) -> None:
        duplicate = _runtime._create_generation_context({"bad": ("json", b'{"x":1,"x":2}')})
        with self.assertRaises(generator.InputDecodeError):
            duplicate.json("bad")
        nonfinite = _runtime._create_generation_context({"bad": ("json", b'{"x":NaN}')})
        with self.assertRaises(generator.InputDecodeError):
            nonfinite.json("bad")

    def test_binding_factory_is_exact_and_binding_is_opaque(self) -> None:
        factory = self.factory()
        binding = factory(id="com.example.binding", threshold=7, tags={"a", "b"})
        self.assertIn("com.example.binding", repr(binding))
        with self.assertRaises(generator.BindingValidationError):
            generator.BindingSpec()
        with self.assertRaises(generator.BindingValidationError):
            factory(id="com.example.binding", threshold=True, tags=set())
        with self.assertRaises(generator.BindingValidationError):
            factory(id="com.example.binding", threshold=7, tags=set(), extra=1)
        with self.assertRaises(generator.BindingValidationError):
            factory(id="Bad ID", threshold=7, tags=set())

    def test_proposals_are_sorted_and_byte_deterministic(self) -> None:
        factory = self.factory()
        first = self.context()
        first.emit(factory(id="com.example.z", threshold=9, tags={"b", "a"}))
        first.emit(factory(id="com.example.a", threshold=7, tags={"a"}))
        first_result = _runtime._finish_generation(first)

        second = self.context(order=True)
        second.emit(factory(id="com.example.a", threshold=7, tags={"a"}))
        second.emit(factory(id="com.example.z", threshold=9, tags={"a", "b"}))
        second_result = _runtime._finish_generation(second)

        self.assertEqual(first_result.canonical_bytes, second_result.canonical_bytes)
        self.assertEqual(first_result.sha256, second_result.sha256)
        self.assertEqual([proposal.id for proposal in first_result.proposals], ["com.example.a", "com.example.z"])
        with self.assertRaises(generator.ContextSealedError):
            first.text("notice")

    def test_duplicate_binding_is_rejected(self) -> None:
        factory = self.factory()
        context = self.context()
        context.emit(factory(id="com.example.same", threshold=1, tags=set()))
        with self.assertRaises(generator.DuplicateBindingError):
            context.emit(factory(id="com.example.same", threshold=2, tags=set()))

    def test_generator_runtime_has_no_ambient_capability_imports(self) -> None:
        tree = ast.parse((SDK_ROOT / "rule_engine_generator" / "_runtime.py").read_text(encoding="utf-8"))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertNotIn(node.func.id, {"open", "eval", "exec", "compile", "__import__"})
        forbidden = {"os", "pathlib", "socket", "subprocess", "ctypes", "importlib", "inspect", "time", "random"}
        self.assertEqual(imported & forbidden, set())
        public = {name for name in dir(generator.GenerationContext) if not name.startswith("_")}
        self.assertEqual(public, {"bytes", "emit", "json", "text"})


class ManifestTests(unittest.TestCase):
    def test_manifest_verifies(self) -> None:
        module_path = SDK_ROOT / "verify_manifest.py"
        spec = importlib.util.spec_from_file_location("sdk_manifest_verifier", module_path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.verify(SDK_ROOT)


if __name__ == "__main__":
    unittest.main(verbosity=2)
