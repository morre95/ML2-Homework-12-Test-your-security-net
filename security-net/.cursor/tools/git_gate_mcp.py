#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "mcp",
# ]
# ///
"""Gated git/deploy tools. Cursor hooks force user approval before these run."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

HOOKS_DIR = Path(__file__).resolve().parent.parent / "hooks"
sys.path.insert(0, str(HOOKS_DIR))

from _classify import classify_command  # noqa: E402
from _policy import is_protected_branch, load_policy, tool_name  # noqa: E402

try:
    from mcp.server.fastmcp import FastMCP as _Server
except ImportError:  # mcp Python SDK v2
    from mcp.server import MCPServer as _Server

mcp = _Server("git-gate")


def _project_dir() -> Path:
    env = os.environ.get("CURSOR_PROJECT_DIR") or os.environ.get("CLAUDE_PROJECT_DIR")
    if env:
        return Path(env)
    # .cursor/tools/thisfile.py -> repo root
    return Path(__file__).resolve().parent.parent.parent


def _run(args: list[str], cwd: Path, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _format_proc(proc: subprocess.CompletedProcess[str]) -> str:
    parts = []
    if proc.stdout:
        parts.append(proc.stdout.rstrip())
    if proc.stderr:
        parts.append(proc.stderr.rstrip())
    parts.append(f"(exit {proc.returncode})")
    return "\n".join(p for p in parts if p)


@mcp.tool()
def show_policy() -> str:
    """Return the active security-net policy (protected branches, prod hosts, tools)."""
    policy = load_policy()
    return json.dumps(policy, indent=2, ensure_ascii=False)


@mcp.tool()
def push_protected_branch(
    branch: str,
    justification: str,
    remote: str = "origin",
    force: bool = False,
) -> str:
    """Push the current HEAD to a protected branch after listing commits that would be published.

    Use this instead of `git push` when the destination is main/master/dev/develop/production
    or a release/* branch. The security-net hook will still ask the user to approve this call.
    """
    if not justification.strip():
        raise ValueError("justification is required so the user knows why this push should happen.")

    policy = load_policy()
    if not is_protected_branch(branch, policy):
        raise ValueError(
            f"`{branch}` is not a protected branch. Use regular `git push` for feature branches. "
            f"Protected: {policy.get('protected_branches')} plus {policy.get('protected_branch_globs')}."
        )

    cwd = _project_dir()
    ahead = _run(
        ["git", "log", "--oneline", f"{remote}/{branch}..HEAD"],
        cwd=cwd,
        timeout=20,
    )
    if ahead.returncode != 0:
        # remote ref may not exist yet
        ahead_text = (
            f"Could not list commits vs {remote}/{branch} "
            f"(the remote ref may not exist yet):\n{ahead.stderr.strip()}"
        )
    else:
        commits = ahead.stdout.strip() or "(no commits ahead — fast-forward empty or already pushed)"
        ahead_text = f"Commits that would be pushed ({remote}/{branch}..HEAD):\n{commits}"

    push_args = ["git", "push"]
    if force:
        push_args.append("--force-with-lease")
    push_args.extend([remote, f"HEAD:{branch}"])

    proc = _run(push_args, cwd=cwd, timeout=120)
    result = _format_proc(proc)
    if proc.returncode != 0:
        raise RuntimeError(
            f"Push failed.\nJustification: {justification}\n{ahead_text}\n\n{result}"
        )
    return f"Pushed HEAD to {remote}/{branch}.\nJustification: {justification}\n{ahead_text}\n\n{result}"


@mcp.tool()
def run_gated_command(command: str, justification: str) -> str:
    """Run a command that the security net otherwise denies (deploy, force-push, service control, publish).

    Hard-denied commands (rm -rf /, prod SSH, terraform destroy, hook tampering, …) are still refused.
    History-rewriting git commands are not run here — use the Shell tool so the user gets an ask prompt.
    """
    if not justification.strip():
        raise ValueError("justification is required so the user knows why this command should run.")
    if not command.strip():
        raise ValueError("command is required.")

    policy = load_policy()
    cwd = _project_dir()
    decision = classify_command(command, str(cwd), policy, [str(cwd)])

    if decision.permission == "deny" and not decision.tool:
        raise PermissionError(
            f"Refused: {decision.reason or 'hard-denied by the security net'} "
            f"(rule {decision.rule_id}). git-gate will not run this command."
        )
    if decision.permission == "ask":
        raise PermissionError(
            "This command is in the 'ask' category (history rewrite, ssh, sudo, …). "
            "Use the Shell tool instead so Cursor prompts the user directly."
        )
    if decision.permission == "allow":
        raise PermissionError(
            "This command is not gated. Run it with the Shell tool; git-gate is only for "
            "protected-branch pushes, deploys, service control, and publishes."
        )

    expected = {
        tool_name(policy, "run_gated_command"),
        tool_name(policy, "push_protected_branch"),
    }
    if decision.tool not in expected:
        raise PermissionError(
            f"Refused: classified as {decision.rule_id} / tool={decision.tool}."
        )

    try:
        args = shlex.split(command)
        proc = subprocess.run(
            args,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
    except ValueError:
        proc = subprocess.run(
            command,
            cwd=str(cwd),
            shell=True,
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )

    result = _format_proc(proc)
    header = (
        f"Ran gated command (rule {decision.rule_id}).\n"
        f"Justification: {justification}\n"
        f"Command: {command}\n"
    )
    if proc.returncode != 0:
        raise RuntimeError(header + result)
    return header + result


if __name__ == "__main__":
    mcp.run()
