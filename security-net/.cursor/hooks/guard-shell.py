#!/usr/bin/python3
"""Cursor beforeShellExecution hook: gate dangerous and history-rewriting commands."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _classify import classify_command, decision_to_payload  # noqa: E402
from _policy import audit, emit, load_policy, read_stdin_json  # noqa: E402


def main() -> int:
    data = read_stdin_json()
    command = data.get("command") or ""
    cwd = data.get("cwd") or None
    workspace_roots = data.get("workspace_roots") or []
    if isinstance(workspace_roots, str):
        workspace_roots = [workspace_roots]

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

    decision = classify_command(command, cwd, policy, workspace_roots)
    if decision.permission != "allow":
        audit(
            "beforeShellExecution",
            permission=decision.permission,
            rule_id=decision.rule_id,
            tool=decision.tool,
            command=command,
            cwd=cwd,
            reason=decision.reason,
        )
    emit(decision_to_payload(decision))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
