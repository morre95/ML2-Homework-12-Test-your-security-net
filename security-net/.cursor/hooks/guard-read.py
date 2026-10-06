#!/usr/bin/python3
"""Cursor beforeReadFile hook: block reads of secrets and private keys."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _policy import (  # noqa: E402
    audit,
    emit,
    is_secret_path,
    load_policy,
    read_stdin_json,
)


def extract_paths(data: dict[str, Any]) -> list[str]:
    paths: list[str] = []
    for key in ("file_path", "path", "filePath"):
        value = data.get(key)
        if isinstance(value, str) and value:
            paths.append(value)
    tool_input = data.get("tool_input")
    if isinstance(tool_input, dict):
        for key in ("file_path", "path", "filePath"):
            value = tool_input.get(key)
            if isinstance(value, str) and value:
                paths.append(value)
    attachments = data.get("attachments") or []
    if isinstance(attachments, list):
        for item in attachments:
            if isinstance(item, dict):
                for key in ("file_path", "path"):
                    value = item.get(key)
                    if isinstance(value, str) and value:
                        paths.append(value)
            elif isinstance(item, str):
                paths.append(item)
    return paths


def main() -> int:
    data = read_stdin_json()
    cwd = data.get("cwd")
    try:
        policy = load_policy()
    except OSError:
        emit({"permission": "deny", "user_message": "Security-net policy.json could not be loaded."})
        return 0

    for path in extract_paths(data):
        if is_secret_path(path, policy, cwd):
            msg = (
                f"Reading secret file `{path}` is blocked by the security net."
            )
            audit("beforeReadFile", permission="deny", path=path, reason="secret")
            emit({"permission": "deny", "user_message": msg})
            return 0

    emit({"permission": "allow"})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
