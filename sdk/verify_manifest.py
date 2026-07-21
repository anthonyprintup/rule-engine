from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import TypedDict, cast

_DOMAIN = b"rule-engine-python-sdk-files-v1\0"


class _ManifestFile(TypedDict):
    path: str
    sha256: str
    size: int


def aggregate_digest(files: list[_ManifestFile]) -> str:
    digest = hashlib.sha256()
    digest.update(_DOMAIN)
    for entry in sorted(files, key=lambda item: str(item["path"])):
        digest.update(str(entry["path"]).encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(entry["size"]).encode("ascii"))
        digest.update(b"\0")
        digest.update(str(entry["sha256"]).encode("ascii"))
        digest.update(b"\0")
    return "sha256:" + digest.hexdigest()


def verify(root: Path) -> None:
    manifest_path = root / "manifest.json"
    raw_manifest: object = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(raw_manifest, dict):
        raise RuntimeError("SDK manifest root is not an object")
    manifest = cast(dict[str, object], raw_manifest)
    if manifest.get("format") != 1:
        raise RuntimeError("unsupported SDK manifest format")
    if manifest.get("python") != "3.14.6":
        raise RuntimeError("SDK manifest does not target exact Python 3.14.6")
    raw_files = manifest.get("files")
    if not isinstance(raw_files, list) or not raw_files:
        raise RuntimeError("SDK manifest has no files")
    seen: set[str] = set()
    files: list[_ManifestFile] = []
    for raw_entry in cast(list[object], raw_files):
        if not isinstance(raw_entry, dict):
            raise RuntimeError("invalid SDK file entry")
        entry = cast(dict[str, object], raw_entry)
        relative = entry.get("path")
        if not isinstance(relative, str) or relative in seen or "\\" in relative:
            raise RuntimeError(f"invalid or duplicate SDK path: {relative!r}")
        expected_size = entry.get("size")
        expected_sha256 = entry.get("sha256")
        if type(expected_size) is not int or expected_size < 0:
            raise RuntimeError(f"invalid SDK size: {relative}")
        if (
            not isinstance(expected_sha256, str)
            or len(expected_sha256) != 64
            or any(character not in "0123456789abcdef" for character in expected_sha256)
        ):
            raise RuntimeError(f"invalid SDK SHA-256: {relative}")
        seen.add(relative)
        path = (root / relative).resolve()
        try:
            path.relative_to(root.resolve())
        except ValueError as error:
            raise RuntimeError(f"SDK path escapes root: {relative!r}") from error
        payload = path.read_bytes()
        if len(payload) != expected_size:
            raise RuntimeError(f"SDK size mismatch: {relative}")
        actual = hashlib.sha256(payload).hexdigest()
        if actual != expected_sha256:
            raise RuntimeError(f"SDK SHA-256 mismatch: {relative}")
        files.append(
            {
                "path": relative,
                "sha256": expected_sha256,
                "size": expected_size,
            }
        )
    if aggregate_digest(files) != manifest.get("content_sha256"):
        raise RuntimeError("SDK aggregate SHA-256 mismatch")


def main() -> int:
    root = Path(sys.argv[1]).resolve() if len(sys.argv) == 2 else Path(__file__).resolve().parent
    verify(root)
    print("SDK manifest verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
