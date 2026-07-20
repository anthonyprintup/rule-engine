from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

_DOMAIN = b"rule-engine-python-sdk-files-v1\0"


def aggregate_digest(files: list[dict[str, object]]) -> str:
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
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("format") != 1:
        raise RuntimeError("unsupported SDK manifest format")
    if manifest.get("python") != "3.14.6":
        raise RuntimeError("SDK manifest does not target exact Python 3.14.6")
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        raise RuntimeError("SDK manifest has no files")
    seen: set[str] = set()
    for entry in files:
        if not isinstance(entry, dict):
            raise RuntimeError("invalid SDK file entry")
        relative = entry.get("path")
        if not isinstance(relative, str) or relative in seen or "\\" in relative:
            raise RuntimeError(f"invalid or duplicate SDK path: {relative!r}")
        seen.add(relative)
        path = (root / relative).resolve()
        try:
            path.relative_to(root.resolve())
        except ValueError as error:
            raise RuntimeError(f"SDK path escapes root: {relative!r}") from error
        payload = path.read_bytes()
        if len(payload) != entry.get("size"):
            raise RuntimeError(f"SDK size mismatch: {relative}")
        actual = hashlib.sha256(payload).hexdigest()
        if actual != entry.get("sha256"):
            raise RuntimeError(f"SDK SHA-256 mismatch: {relative}")
    if aggregate_digest(files) != manifest.get("content_sha256"):
        raise RuntimeError("SDK aggregate SHA-256 mismatch")


def main() -> int:
    root = Path(sys.argv[1]).resolve() if len(sys.argv) == 2 else Path(__file__).resolve().parent
    verify(root)
    print("SDK manifest verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
