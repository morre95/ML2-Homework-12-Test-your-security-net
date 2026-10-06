#!/usr/bin/env python3
"""Run the cases in cases.yaml against the hooks in <project>/.cursor/hooks.json.

The hooks are found through the hook configuration, not through hard-coded
paths: for each case the script picks every hook registered for the case's
event whose matcher matches, runs its command from the project root with the
configured timeout, and turns the result into the decision Cursor would make.
"""

import argparse
import json
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

import yaml

HOOKS_CONFIG = Path(".cursor") / "hooks.json"
DEFAULT_TIMEOUT = 30
RANK = {"allow": 0, "ask": 1, "deny": 2}
PREVIEW_CHARS = 60


def load_cases(path):
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def load_hooks(project):
    config = project / HOOKS_CONFIG
    return json.loads(config.read_text(encoding="utf-8")).get("hooks", {})


def substitute(value, project):
    if isinstance(value, str):
        return value.replace("{project}", str(project)).replace("{home}", str(Path.home()))
    if isinstance(value, list):
        return [substitute(v, project) for v in value]
    if isinstance(value, dict):
        return {k: substitute(v, project) for k, v in value.items()}
    return value


def matcher_target(event, payload):
    """The value Cursor tests a hook's matcher against, per event."""
    if event in {"beforeShellExecution", "afterShellExecution"}:
        return payload.get("command") or ""
    if event == "beforeReadFile":
        return "Read"
    if event == "afterFileEdit":
        return "Write"
    return payload.get("tool_name") or ""


def matches(hook, target):
    pattern = hook.get("matcher")
    if not pattern or pattern == "*":
        return True
    return re.search(pattern, target) is not None


def build_stdin(case, event, project):
    """Return (stdin text, parsed payload). raw_stdin is sent as-is."""
    payload = substitute(case.get("input", {}), project)
    if "raw_stdin" in case:
        return substitute(case["raw_stdin"], project), payload
    full = {
        "hook_event_name": event,
        "workspace_roots": [str(project)],
        "cwd": str(project),
        **payload,
    }
    return json.dumps(full), full


def effective_permission(event, hook, rc, stdout, timed_out):
    """Map one hook run to Cursor's decision. Returns (permission, output, problem)."""
    fail_closed = bool(hook.get("failClosed"))
    if timed_out:
        return ("deny" if fail_closed else "allow"), {}, "timeout"
    if rc == 2:
        return "deny", {}, ""
    if rc != 0:
        return ("deny" if fail_closed else "allow"), {}, f"exit {rc}"
    try:
        output = json.loads(stdout)
    except json.JSONDecodeError:
        return "deny", {}, "ogiltig JSON på stdout"
    permission = output.get("permission") if isinstance(output, dict) else None
    if permission not in RANK:
        return "deny", {}, "svar utan giltig permission"
    if event == "preToolUse" and permission == "ask":
        permission = "allow"
    return permission, output, ""


def run_hook(hook, event, stdin, project):
    timeout = hook.get("timeout", DEFAULT_TIMEOUT)
    start = time.perf_counter()
    try:
        proc = subprocess.run(
            hook["command"],
            shell=True,
            cwd=project,
            input=stdin,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        rc, stdout, stderr, timed_out = proc.returncode, proc.stdout, proc.stderr, False
    except subprocess.TimeoutExpired:
        rc, stdout, stderr, timed_out = None, "", "", True
    ms = (time.perf_counter() - start) * 1000
    permission, output, problem = effective_permission(event, hook, rc, stdout, timed_out)
    if not problem and "Traceback" in stderr:
        problem = "Traceback på stderr"
    return {
        "command": hook["command"],
        "ms": ms,
        "permission": permission,
        "reason": " ".join(
            str(output.get(k, "")) for k in ("user_message", "agent_message")
        ).strip(),
        "problem": problem,
    }


CHECKS = {
    "decision": lambda r, v: (r["decision"] == v, f"fick {r['decision']}, väntade {v}"),
    "has_reason": lambda r, v: (bool(r["reason"]), "tomt skäl"),
    "reason_contains": lambda r, v: (v.lower() in r["reason"].lower(), f"skälet saknar '{v}'"),
    "max_ms": lambda r, v: (r["ms"] <= v, f"{r['ms']:.0f} ms > {v} ms"),
    "no_crash": lambda r, v: (not r["problems"], "krasch: " + "; ".join(r["problems"])),
}


def run_case(case, hooks, project):
    """Run one case once. Returns dict with decision, reason, ms, hooks, failures."""
    event = case["event"]
    stdin, payload = build_stdin(case, event, project)
    target = matcher_target(event, payload)
    selected = [h for h in hooks.get(event, []) if matches(h, target)]
    runs = [run_hook(h, event, stdin, project) for h in selected]

    decision = max((r["permission"] for r in runs), key=RANK.get, default="allow")
    result = {
        "decision": decision,
        "reason": " ".join(r["reason"] for r in runs if r["permission"] == decision).strip(),
        "ms": sum(r["ms"] for r in runs),
        "hooks": [Path(r["command"]).name for r in runs],
        "problems": [f"{Path(r['command']).name}: {r['problem']}" for r in runs if r["problem"]],
    }
    failures = []
    if not selected:
        failures.append(f"ingen hook i hooks.json matchar {event}")
    for check in case["checks"]:
        passed, reason = CHECKS[check["type"]](result, check.get("value"))
        if not passed:
            failures.append(reason)
    result["failures"] = failures
    return result


def call_preview(case):
    data = case.get("input", {})
    tool_input = data.get("tool_input")
    if "raw_stdin" in case:
        text = f"stdin: {case['raw_stdin']}"
    elif "mcp_server_name" in data:
        text = f"{data['mcp_server_name']} {data.get('tool_name', '')} {tool_input or ''}"
    elif "command" in data:
        text = data["command"]
    elif isinstance(tool_input, dict):
        text = f"{data.get('tool_name', '')} {tool_input.get('path', '')}"
    else:
        text = data.get("file_path", "")
    text = text.replace("{project}/", "").replace("{home}", "~")
    flat = " ".join(str(text).split())
    flat = flat[:PREVIEW_CHARS] + ("…" if len(flat) > PREVIEW_CHARS else "")
    return flat.replace("|", "\\|")


def summarize(case, runs):
    """Collapse repeated runs of one case into a table row."""
    passes = sum(1 for r in runs if not r["failures"])
    failed_run = next((r for r in runs if r["failures"]), runs[-1])
    if passes == len(runs):
        verdict = "PASS"
    elif passes == 0:
        verdict = "FAIL"
    else:
        verdict = "OSTABIL"
    expected = next((c["value"] for c in case["checks"] if c["type"] == "decision"), "–")
    return {
        "id": case["id"],
        "kategori": case["kategori"],
        "call": call_preview(case),
        "expected": expected,
        "got": failed_run["decision"],
        "verdict": verdict,
        "passes": f"{passes}/{len(runs)}",
        "ms": max(r["ms"] for r in runs),
        "hooks": ", ".join(failed_run["hooks"]) or "–",
        "reason": "; ".join(failed_run["failures"]).replace("|", "\\|"),
    }


def format_table(rows):
    lines = [
        "| id | kategori | anrop | väntat | fick | utfall | pass | max ms | hook | orsak |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for row in rows:
        lines.append(
            f"| {row['id']} | {row['kategori']} | `{row['call']}` | {row['expected']} "
            f"| {row['got']} | **{row['verdict']}** | {row['passes']} | {row['ms']:.0f} "
            f"| {row['hooks']} | {row['reason']} |"
        )
    return "\n".join(lines)


def format_hooks(hooks, events):
    lines = []
    for event in events:
        for hook in hooks.get(event, []):
            extras = [f"timeout {hook.get('timeout', DEFAULT_TIMEOUT)} s"]
            if hook.get("matcher"):
                extras.insert(0, f"matcher `{hook['matcher']}`")
            if hook.get("failClosed"):
                extras.append("failClosed")
            lines.append(f"  - `{event}` → `{hook['command']}` ({', '.join(extras)})")
    return "\n".join(lines)


def net_version(project):
    def git(*args):
        out = subprocess.run(["git", *args], capture_output=True, text=True, cwd=project)
        return out.stdout.strip()

    commit = git("log", "-1", "--format=%h", "--", ".")
    dirty = git("status", "--porcelain", "--", ".")
    return f"`{commit}`" + (" + ej incheckade ändringar" if dirty else "")


def format_report(rows, title, repeat, project, hooks, events):
    failed = sum(1 for row in rows if row["verdict"] != "PASS")
    return (
        f"## {title}\n\n"
        f"- Datum: {datetime.now().isoformat(timespec='seconds')}\n"
        f"- Hook-konfiguration: `{project.name}/{HOOKS_CONFIG}`, nätets commit: "
        f"{net_version(project)}, upprepningar per fall: {repeat}\n"
        f"- Hookar som kördes:\n{format_hooks(hooks, events)}\n"
        f"- **{failed} av {len(rows)} fall föll**\n\n"
        f"{format_table(rows)}\n\n"
    )


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", default="security-net", help="project root with .cursor/hooks.json")
    parser.add_argument("--cases", default="cases.yaml")
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--report", help="append a markdown section to this file")
    parser.add_argument("--title", default="Körning")
    return parser.parse_args()


def main():
    args = parse_args()
    project = Path(args.project).resolve()
    if not (project / HOOKS_CONFIG).is_file():
        sys.exit(f"Hittar ingen {HOOKS_CONFIG} under {project}")
    hooks = load_hooks(project)
    cases = load_cases(args.cases)

    rows = []
    for case in cases:
        runs = [run_case(case, hooks, project) for _ in range(args.repeat)]
        rows.append(summarize(case, runs))
        print(f"{rows[-1]['verdict']:8} {case['id']}", file=sys.stderr)

    events = list(dict.fromkeys(case["event"] for case in cases))
    report = format_report(rows, args.title, args.repeat, project, hooks, events)
    print(report)
    if args.report:
        with open(args.report, "a", encoding="utf-8") as fh:
            fh.write(report)
    sys.exit(1 if any(row["verdict"] != "PASS" for row in rows) else 0)


if __name__ == "__main__":
    main()
