#!/usr/bin/python3
"""Shared policy loading, path matching, and JSON I/O for security-net hooks."""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

HOOKS_DIR = Path(__file__).resolve().parent
DEFAULT_POLICY_PATH = HOOKS_DIR / "policy.json"
LOG_DIR = HOOKS_DIR / "logs"

RANK = {"allow": 0, "ask": 1, "deny": 3}


def policy_path() -> Path:
    override = os.environ.get("GIT_GATE_POLICY")
    if override:
        return Path(override)
    return DEFAULT_POLICY_PATH


def load_policy() -> dict[str, Any]:
    path = policy_path()
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def read_stdin_json() -> dict[str, Any]:
    raw = sys.stdin.read()
    if not raw.strip():
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def emit(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload, ensure_ascii=False))
    sys.stdout.flush()


def audit(event: str, **fields: Any) -> None:
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event,
            **fields,
        }
        with (LOG_DIR / "audit.log").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        pass


def session_log(event: str, **fields: Any) -> None:
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event,
            **fields,
        }
        with (LOG_DIR / "sessions.log").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        pass


def expand_path(path: str, cwd: str | None = None) -> str:
    expanded = os.path.expandvars(os.path.expanduser(path))
    if not os.path.isabs(expanded):
        base = cwd or os.getcwd()
        expanded = os.path.join(base, expanded)
    return os.path.normpath(expanded)


def is_protected_branch(branch: str, policy: dict[str, Any]) -> bool:
    name = (branch or "").strip()
    if not name:
        return False
    for prefix in ("refs/heads/", "refs/tags/", "refs/remotes/origin/", "origin/"):
        if name.startswith(prefix):
            name = name[len(prefix) :]
            break
    if name in set(policy.get("protected_branches") or []):
        return True
    for glob in policy.get("protected_branch_globs") or []:
        if fnmatch(name, glob):
            return True
    return False


def is_prod_host(host: str, policy: dict[str, Any]) -> bool:
    host = (host or "").strip().lower().strip("[]")
    if not host:
        return False
    if ":" in host and not host.startswith("["):
        host = host.rsplit(":", 1)[0]
    for sub in policy.get("prod_host_substrings") or []:
        if sub.lower() in host:
            return True
    for glob in policy.get("prod_host_globs") or []:
        if fnmatch(host, glob.lower()):
            return True
    return False


def _home() -> str:
    return os.path.expanduser("~")


def is_protected_path(path: str, policy: dict[str, Any], cwd: str | None = None) -> bool:
    raw = path or ""
    resolved = expand_path(raw, cwd)
    lowered = resolved.replace("\\", "/").lower()
    original = raw.replace("\\", "/").lower()

    for sub in policy.get("protected_path_substrings") or []:
        needle = sub.lower()
        if needle in lowered or needle in original:
            return True

    home = _home().replace("\\", "/")
    for rel in policy.get("protected_user_relpaths") or []:
        target = f"{home}/{rel}".replace("\\", "/").lower()
        if lowered == target.rstrip("/") or lowered.startswith(target):
            return True
        if original.endswith(rel.lower()) or rel.lower() in original:
            if ".cursor/" in original or str(Path.home()) in raw:
                return True
    return False


def is_secret_path(path: str, policy: dict[str, Any], cwd: str | None = None) -> bool:
    raw = (path or "").replace("\\", "/")
    resolved = expand_path(path or "", cwd).replace("\\", "/")
    name = Path(resolved).name
    if name.endswith(".pub") and not policy.get("secret_read_allow_pubkeys", False):
        if name.startswith("id_"):
            return False
    candidates = [raw, resolved, name, raw.lstrip("./")]
    globs = policy.get("secret_path_globs") or []
    for candidate in candidates:
        lowered = candidate
        for glob in globs:
            g = glob.replace("\\", "/")
            if fnmatch(lowered, g) or fnmatch(lowered.lower(), g.lower()):
                if g.endswith(".pub"):
                    continue
                return True
            # also match basename against the last glob segment
            last = g.split("/")[-1]
            if last.startswith("id_") and fnmatch(name, last):
                if name.endswith(".pub"):
                    return False
                return True
            if last in {".env", ".netrc"} and name == last:
                return True
            if last.startswith(".env") and fnmatch(name, last):
                return True
            if last in {"credentials.json", "secrets.yaml", "secrets.yml"} and name == last:
                return True
            if last.startswith("*.") and fnmatch(name, last):
                if name.endswith(".pub"):
                    return False
                return True
    if name in {".env", ".netrc"} or name.startswith(".env."):
        return True
    if name in {"credentials.json", "credentials"} and ".aws" in resolved:
        return True
    if "/.ssh/" in resolved and name.startswith("id_") and not name.endswith(".pub"):
        return True
    if "/.aws/credentials" in resolved:
        return True
    if Path(resolved).suffix.lower() in {".pem", ".key"}:
        return True
    return False


def tool_name(policy: dict[str, Any], key: str) -> str:
    tools = policy.get("tools") or {}
    return str(tools.get(key) or key)
