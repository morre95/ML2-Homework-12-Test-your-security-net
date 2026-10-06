#!/usr/bin/python3
"""Cursor preToolUse hook: block writes/deletes of security-net files and secrets."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _policy import (  # noqa: E402
    audit,
    emit,
    is_protected_path,
    is_secret_path,
    load_policy,
    read_stdin_json,
)


def extract_paths(tool_input: Any) -> list[str]:
    paths: list[str] = []
    if isinstance(tool_input, dict):
        for key in ("path", "file_path", "target_file", "filePath"):
            value = tool_input.get(key)
            if isinstance(value, str) and value:
                paths.append(value)
        extra = tool_input.get("paths")
        if isinstance(extra, list):
            paths.extend(p for p in extra if isinstance(p, str) and p)
    elif isinstance(tool_input, str) and tool_input:
        paths.append(tool_input)
    return paths


def main() -> int:
    data = read_stdin_json()
    tool = data.get("tool_name") or ""
    cwd = data.get("cwd")
    tool_input = data.get("tool_input") or {}
    try:
        policy = load_policy()
    except OSError:
        emit(
            {
                "permission": "deny",
                "user_message": "Security-net policy.json could not be loaded.",
                "agent_message": "The security net failed closed because policy.json is unreadable.",
            }
        )
        return 0

    for path in extract_paths(tool_input):
        if is_protected_path(path, policy, cwd):
            msg = (
                f"{tool} is not allowed to modify security-net file `{path}`. "
                "Ask the user to change hooks/policy outside the agent."
            )
            audit("preToolUse", permission="deny", tool=tool, path=path, reason="protected")
            emit(
                {
                    "permission": "deny",
                    "user_message": msg,
                    "agent_message": msg,
                }
            )
            return 0
        if is_secret_path(path, policy, cwd):
            msg = (
                f"{tool} is not allowed to modify secret file `{path}`."
            )
            audit("preToolUse", permission="deny", tool=tool, path=path, reason="secret")
            emit(
                {
                    "permission": "deny",
                    "user_message": msg,
                    "agent_message": msg,
                }
            )
            return 0

    emit({"permission": "allow"})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
