"""Identify the actual application code, not just a healthy container."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path


def source_fingerprint(code_dir: Path, migrations_dir: Path) -> str:
    digest = hashlib.sha256()
    for label, directory in (("appsecctl", code_dir), ("migrations", migrations_dir)):
        if not directory.is_dir():
            raise RuntimeError("Missing application source directory: " + label)
        files = sorted(p for p in directory.rglob("*")
                       if p.is_file() and "__pycache__" not in p.parts
                       and p.suffix in (".py", ".html", ".js", ".css", ".mako"))
        for path in files:
            digest.update((label + "/" + path.relative_to(directory).as_posix()).encode())
            digest.update(b"\0")
            digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def runtime_info() -> dict[str, str]:
    code_dir = Path(__file__).resolve().parent
    app_dir = code_dir.parent
    stamp = app_dir / ".appsec-build-revision"
    revision = stamp.read_text(encoding="ascii").strip() if stamp.is_file() else "unknown"
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        revision = "unknown"
    migrations = app_dir / "migrations"
    if not migrations.is_dir():  # local checkout / unit tests
        migrations = app_dir.parent / "migrations"
    return {"revision": revision, "source_sha256": source_fingerprint(code_dir, migrations)}


if __name__ == "__main__":
    print(json.dumps(runtime_info()))
