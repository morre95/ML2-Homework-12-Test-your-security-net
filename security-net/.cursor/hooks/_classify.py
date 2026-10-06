#!/usr/bin/python3
"""Classify shell commands for the security-net beforeShellExecution hook."""

from __future__ import annotations

import os
import re
import shlex
import subprocess
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Iterable

from _policy import is_prod_host, is_protected_branch, is_protected_path, tool_name

WRAPPERS = {
    "sudo",
    "doas",
    "pkexec",
    "env",
    "nohup",
    "time",
    "command",
    "nice",
    "ionice",
    "timeout",
    "stdbuf",
    "script",
    "watch",
    "chronic",
}

WRAPPERS_WITH_ARG = {
    "timeout": 1,
    "nice": 0,
    "ionice": 0,
    "stdbuf": 0,
    "sudo": 0,
    "doas": 0,
    "pkexec": 0,
    "env": 0,
    "command": 0,
}

PRIVILEGE = {"sudo", "doas", "pkexec", "su"}

SYSTEM_RM_TARGETS = {
    "/",
    "/bin",
    "/boot",
    "/dev",
    "/etc",
    "/home",
    "/lib",
    "/lib64",
    "/opt",
    "/proc",
    "/root",
    "/run",
    "/sbin",
    "/sys",
    "/usr",
    "/var",
}

GIT_GLOBAL_FLAGS_WITH_ARG = {
    "-C",
    "--git-dir",
    "--work-tree",
    "-c",
    "--namespace",
    "--config-env",
    "--super-prefix",
    "--list-cmds",
}

PUSH_FLAGS_WITH_ARG = {
    "-u",
    "--set-upstream",
    "-o",
    "--push-option",
    "--signed",
    "--receive-pack",
    "--exec",
    "--repo",
    "--recurse-submodules",
}

SSH_FAMILY = {"ssh", "scp", "sftp", "rsync"}

DEPLOY_PREFIXES = {
    "kubectl": {"apply", "rollout", "delete", "scale", "exec", "cordon", "drain"},
    "helm": {"install", "upgrade", "rollback", "uninstall", "delete"},
    "terraform": {"apply"},
    "tofu": {"apply"},
    "ansible-playbook": {"*"},
    "fly": {"deploy"},
    "flyctl": {"deploy"},
    "vercel": {"*"},
    "heroku": {"*"},
    "cap": {"deploy"},
    "capistrano": {"deploy"},
}

PUBLISH_COMMANDS = {
    ("npm", "publish"),
    ("npx", "publish"),
    ("pnpm", "publish"),
    ("yarn", "publish"),
    ("twine", "upload"),
    ("uv", "publish"),
    ("cargo", "publish"),
}

PIPE_TO_SHELL_RE = re.compile(
    r"(curl|wget|fetch|httpie|http)\b[^|;\n]*\|\s*(?:sudo\s+)?(?:ba)?sh\b",
    re.IGNORECASE,
)
BASE64_TO_SHELL_RE = re.compile(
    r"base64\b[^|;\n]*-d[^|;\n]*\|\s*(?:sudo\s+)?(?:ba)?sh\b",
    re.IGNORECASE,
)
REDIRECT_DEVICE_RE = re.compile(r"(?:>>?|tee(?:\s+-a)?)\s+/dev/sd[a-z]\d*", re.IGNORECASE)

HISTORY_SAFE_FLAGS = {"--abort", "--continue", "--skip", "--quit"}


@dataclass(frozen=True)
class Decision:
    permission: str  # allow | ask | deny
    reason: str = ""
    rule_id: str = ""
    tool: str | None = None
    user_message: str = ""
    agent_message: str = ""

    @property
    def rank(self) -> int:
        if self.permission == "deny":
            return 3
        if self.permission == "ask":
            return 1
        return 0


ALLOW = Decision("allow")


def deny(rule_id: str, reason: str) -> Decision:
    return Decision(
        permission="deny",
        reason=reason,
        rule_id=rule_id,
        user_message=reason,
        agent_message=(
            f"Blocked by the security net ({rule_id}). {reason} "
            "This action cannot be performed via Shell or via git-gate."
        ),
    )


def gated(rule_id: str, reason: str, tool: str) -> Decision:
    return Decision(
        permission="deny",
        reason=reason,
        rule_id=rule_id,
        tool=tool,
        user_message=reason,
        agent_message=(
            f"Blocked by the security net ({rule_id}). {reason} "
            f"Call the git-gate MCP tool `{tool}` with a justification. "
            "The user must approve that tool call."
        ),
    )


def ask(rule_id: str, reason: str) -> Decision:
    return Decision(
        permission="ask",
        reason=reason,
        rule_id=rule_id,
        user_message=reason,
        agent_message=(
            f"The security net requires user confirmation ({rule_id}): {reason}"
        ),
    )


def stricter(a: Decision, b: Decision) -> Decision:
    if a.rank > b.rank:
        return a
    if b.rank > a.rank:
        return b
    # same rank: prefer a decision that points at a tool
    if b.tool and not a.tool:
        return b
    return a


def basename(token: str) -> str:
    return Path(token).name


def split_segments(command: str) -> list[str]:
    segments: list[str] = []
    buf: list[str] = []
    quote: str | None = None
    i = 0
    n = len(command)
    while i < n:
        c = command[i]
        if quote:
            buf.append(c)
            if c == quote and (i == 0 or command[i - 1] != "\\"):
                quote = None
            i += 1
            continue
        if c in {"'", '"', "`"}:
            quote = c
            buf.append(c)
            i += 1
            continue
        if command.startswith("&&", i) or command.startswith("||", i):
            seg = "".join(buf).strip()
            if seg:
                segments.append(seg)
            buf = []
            i += 2
            continue
        if c in {";", "|", "\n"}:
            seg = "".join(buf).strip()
            if seg:
                segments.append(seg)
            buf = []
            i += 1
            continue
        # background separator, but not 2>&1 / &>/dev/null / 1>/file
        if c == "&":
            prev = command[i - 1] if i else ""
            nxt = command[i + 1] if i + 1 < n else ""
            if prev not in {">", "<", "1", "2"} and nxt not in {">", "<"}:
                seg = "".join(buf).strip()
                if seg:
                    segments.append(seg)
                buf = []
                i += 1
                continue
        buf.append(c)
        i += 1
    seg = "".join(buf).strip()
    if seg:
        segments.append(seg)
    return segments


def tokenize(segment: str) -> list[str]:
    cleaned = segment.strip()
    if not cleaned:
        return []
    try:
        return shlex.split(cleaned, posix=True)
    except ValueError:
        return cleaned.split()


def strip_wrappers(tokens: list[str]) -> tuple[list[str], bool]:
    """Return (inner tokens, used_privilege)."""
    used_priv = False
    i = 0
    n = len(tokens)
    while i < n:
        cmd = basename(tokens[i])
        if cmd in PRIVILEGE:
            used_priv = True
        if cmd not in WRAPPERS:
            break
        i += 1
        while i < n:
            tok = tokens[i]
            if cmd in {"env"} and "=" in tok and not tok.startswith("-"):
                i += 1
                continue
            if tok in {"--"}:
                i += 1
                break
            if tok.startswith("-"):
                flag = tok.split("=", 1)[0]
                # sudo -u user / timeout 10 / nice -n 5
                if cmd == "sudo" and flag in {"-u", "-g", "-C", "-p", "-H"} and "=" not in tok:
                    i += 2
                    continue
                if cmd == "timeout" and not tok.startswith("-"):
                    break
                if cmd in {"timeout", "nice", "ionice"} and flag in {
                    "-n",
                    "-c",
                    "-t",
                    "-p",
                    "-s",
                    "-k",
                }:
                    i += 2
                    continue
                i += 1
                continue
            if cmd == "timeout" and re.fullmatch(r"\d+(?:\.\d+)?[smhd]?", tok):
                i += 1
                continue
            break
    return tokens[i:], used_priv


def current_git_branch(cwd: str | None) -> str:
    try:
        proc = subprocess.run(
            ["git", "symbolic-ref", "--short", "HEAD"],
            cwd=cwd or None,
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    if proc.returncode != 0:
        return ""
    return proc.stdout.strip()


def parse_git(tokens: list[str]) -> tuple[str | None, list[str]]:
    i = 1
    n = len(tokens)
    while i < n:
        tok = tokens[i]
        if tok in GIT_GLOBAL_FLAGS_WITH_ARG:
            i += 2
            continue
        if tok.startswith("--git-dir=") or tok.startswith("--work-tree="):
            i += 1
            continue
        if tok.startswith("-c") and tok != "-c":
            i += 1
            continue
        if tok.startswith("-") and tok not in {"--"}:
            i += 1
            continue
        break
    if i >= n:
        return None, []
    return tokens[i], tokens[i + 1 :]


def normalize_ref(ref: str) -> str:
    name = ref.lstrip("+")
    for prefix in ("refs/heads/", "refs/tags/", "refs/remotes/origin/", "origin/"):
        if name.startswith(prefix):
            return name[len(prefix) :]
    return name


def parse_push(args: list[str]) -> tuple[bool, bool, bool, list[str]]:
    """Returns force, delete, all_or_mirror, dest_refs."""
    force = False
    delete = False
    all_or_mirror = False
    positionals: list[str] = []
    i = 0
    n = len(args)
    while i < n:
        a = args[i]
        if a in {"-f", "--force"} or a.startswith("--force-with-lease"):
            force = True
            i += 1
            continue
        if a in {"-d", "--delete"}:
            delete = True
            i += 1
            continue
        if a in {"--all", "--mirror", "--tags"}:
            if a != "--tags":
                all_or_mirror = True
            i += 1
            continue
        if a.startswith("-"):
            name = a.split("=", 1)[0]
            if name in PUSH_FLAGS_WITH_ARG and "=" not in a:
                i += 2
                continue
            i += 1
            continue
        positionals.append(a)
        i += 1

    dests: list[str] = []
    refspecs = positionals[1:] if positionals else []
    for spec in refspecs:
        raw = spec.lstrip("+")
        if ":" in raw:
            src, dst = raw.split(":", 1)
            if src == "":
                delete = True
            dests.append(normalize_ref(dst or src))
        else:
            dests.append(normalize_ref(raw))
    return force, delete, all_or_mirror, dests


def extract_host_from_tokens(cmd: str, tokens: list[str]) -> str | None:
    skip_next = False
    ssh_flags_with_arg = {
        "-b",
        "-c",
        "-D",
        "-E",
        "-e",
        "-F",
        "-I",
        "-i",
        "-J",
        "-L",
        "-l",
        "-m",
        "-O",
        "-o",
        "-p",
        "-Q",
        "-R",
        "-S",
        "-W",
        "-w",
    }
    scp_flags_with_arg = ssh_flags_with_arg | {"-P", "-c", "-i", "-l", "-o", "-F", "-J"}
    rsync_flags_with_arg = {"-e", "--rsh", "--port", "-M"}
    flags = ssh_flags_with_arg if cmd in {"ssh", "sftp"} else scp_flags_with_arg
    if cmd == "rsync":
        flags = rsync_flags_with_arg
    for tok in tokens[1:]:
        if skip_next:
            skip_next = False
            continue
        if tok.startswith("-"):
            name = tok.split("=", 1)[0]
            if name in flags and "=" not in tok:
                skip_next = True
            continue
        candidate = tok
        if cmd == "rsync" and ":" not in candidate and "@" not in candidate:
            continue
        if "@" in candidate:
            candidate = candidate.split("@", 1)[1]
        candidate = candidate.split(":", 1)[0]
        candidate = candidate.strip("[]")
        if candidate and candidate not in {".", ".."} and not candidate.startswith("/"):
            return candidate
        if cmd in {"scp", "rsync"}:
            continue
        return candidate
    return None


def looks_like_remote_host(host: str | None) -> bool:
    if not host:
        return False
    if host in {"localhost", "127.0.0.1", "::1"}:
        return False
    return True


def in_workspace(path: str, cwd: str | None, workspace_roots: list[str]) -> bool:
    resolved = os.path.normpath(os.path.expanduser(os.path.expandvars(path)))
    if not os.path.isabs(resolved):
        resolved = os.path.normpath(os.path.join(cwd or os.getcwd(), resolved))
    roots = list(workspace_roots or [])
    if cwd:
        roots.append(cwd)
    for root in roots:
        root_n = os.path.normpath(os.path.expanduser(root))
        if resolved == root_n or resolved.startswith(root_n + os.sep):
            return True
    return False


def classify_rm(
    tokens: list[str],
    cwd: str | None,
    workspace_roots: list[str],
) -> Decision:
    flags = ""
    paths: list[str] = []
    i = 1
    while i < len(tokens):
        tok = tokens[i]
        if tok == "--":
            paths.extend(tokens[i + 1 :])
            break
        if tok.startswith("-") and tok != "-":
            flags += tok.lstrip("-")
            i += 1
            continue
        paths.append(tok)
        i += 1
    recursive = "r" in flags.lower()
    force = "f" in flags.lower()
    if not recursive:
        return ALLOW

    home = os.path.realpath(os.path.expanduser("~"))
    for raw in paths:
        expanded = os.path.expanduser(os.path.expandvars(raw))
        if not os.path.isabs(expanded):
            expanded = os.path.join(cwd or os.getcwd(), expanded)
        normalized = os.path.normpath(expanded)
        real = os.path.realpath(normalized) if os.path.exists(normalized) else normalized
        if real in SYSTEM_RM_TARGETS or normalized in SYSTEM_RM_TARGETS:
            return deny("rm-root-or-home", "Recursive delete of a system path is blocked.")
        if real in {home, home + "/"} or normalized in {home, os.path.expanduser("~")}:
            return deny("rm-root-or-home", "Recursive delete of $HOME is blocked.")
        if raw in {"/", "/*", "~", "~/", "$HOME", "$HOME/", "${HOME}", "${HOME}/"}:
            return deny("rm-root-or-home", "Recursive delete of root or home is blocked.")
        if recursive and force and not in_workspace(normalized, cwd, workspace_roots):
            return ask(
                "rm-outside-workspace",
                f"Recursive delete outside the workspace requires confirmation: {raw}",
            )
        if recursive and not in_workspace(normalized, cwd, workspace_roots):
            return ask(
                "rm-outside-workspace",
                f"Recursive delete outside the workspace requires confirmation: {raw}",
            )
    return ALLOW


def classify_git(tokens: list[str], cwd: str | None, policy: dict[str, Any]) -> Decision:
    sub, args = parse_git(tokens)
    if not sub:
        return ALLOW

    if sub == "push":
        force, delete, all_or_mirror, dests = parse_push(args)
        push_tool = tool_name(policy, "push_protected_branch")
        gated_tool = tool_name(policy, "run_gated_command")
        if force or delete:
            return gated(
                "force-or-delete-push",
                "Force-push and remote branch deletion must be approved via git-gate.",
                gated_tool,
            )
        if all_or_mirror:
            return gated(
                "push-protected-branch",
                "git push --all/--mirror can update protected branches; use push_protected_branch.",
                push_tool,
            )
        if not dests:
            branch = current_git_branch(cwd)
            dests = [branch] if branch else []
            if not dests:
                return gated(
                    "push-protected-branch",
                    "Bare git push could update a protected branch; use push_protected_branch.",
                    push_tool,
                )
        for dest in dests:
            if dest in {"HEAD", ""}:
                dest = current_git_branch(cwd)
            if is_protected_branch(dest, policy):
                return gated(
                    "push-protected-branch",
                    f"Pushing to protected branch `{dest}` is blocked. "
                    f"Use MCP tool `{push_tool}`.",
                    push_tool,
                )
        return ALLOW

    if sub == "config":
        joined = " ".join(args)
        if re.search(r"core\.hooksPath", joined, re.IGNORECASE):
            return deny(
                "tamper-security-net",
                "Changing git core.hooksPath is blocked.",
            )

    if sub == "rebase":
        if any(a in HISTORY_SAFE_FLAGS for a in args):
            return ALLOW
        return ask(
            "git-history-rewrite",
            "git rebase rewrites history and needs confirmation.",
        )

    if sub == "reset":
        if any(a in {"--hard", "--merge"} for a in args):
            return ask(
                "git-history-rewrite",
                "git reset --hard/--merge discards work and needs confirmation.",
            )
        return ALLOW

    if sub == "commit":
        if any(a == "--amend" or a.startswith("--amend=") for a in args):
            return ask(
                "git-history-rewrite",
                "git commit --amend rewrites the last commit and needs confirmation.",
            )
        return ALLOW

    if sub in {"filter-branch", "filter-repo"}:
        return ask(
            "git-history-rewrite",
            f"git {sub} rewrites history and needs confirmation.",
        )

    if sub == "reflog":
        if args and args[0] in {"expire", "delete"}:
            return ask(
                "git-history-rewrite",
                "git reflog expire/delete needs confirmation.",
            )
        return ALLOW

    if sub == "gc":
        if any(a == "--prune" or a.startswith("--prune=") for a in args):
            return ask(
                "git-history-rewrite",
                "git gc --prune needs confirmation.",
            )
        return ALLOW

    if sub == "branch":
        if "-D" in args or any(a.startswith("-D") for a in args):
            return ask(
                "git-history-rewrite",
                "git branch -D force-deletes a branch and needs confirmation.",
            )
        return ALLOW

    if sub == "tag":
        if "-d" in args or "--delete" in args:
            return ask(
                "git-history-rewrite",
                "git tag -d needs confirmation.",
            )
        return ALLOW

    if sub == "checkout":
        if "--" in args:
            paths = args[args.index("--") + 1 :]
            if any(p in {".", "-A", "--all"} for p in paths):
                return ask(
                    "git-history-rewrite",
                    "git checkout -- . discards uncommitted work and needs confirmation.",
                )
        return ALLOW

    if sub == "restore":
        paths = [a for a in args if not a.startswith("-")]
        if any(p in {".", "-A"} for p in paths) or "--all" in args or "-W" in args:
            return ask(
                "git-history-rewrite",
                "git restore . discards uncommitted work and needs confirmation.",
            )
        return ALLOW

    if sub == "clean":
        if any(a == "-f" or a.startswith("-f") or a == "--force" or (a.startswith("-") and "f" in a[1:]) for a in args):
            return ask(
                "git-history-rewrite",
                "git clean -f deletes untracked files and needs confirmation.",
            )
        return ALLOW

    if sub == "stash":
        if args and args[0] in {"drop", "clear"}:
            return ask(
                "git-history-rewrite",
                "git stash drop/clear needs confirmation.",
            )
        return ALLOW

    if sub == "update-ref":
        if "-d" in args or "--delete" in args:
            return ask(
                "git-history-rewrite",
                "git update-ref -d needs confirmation.",
            )
        return ALLOW

    return ALLOW


def classify_service(cmd: str, tokens: list[str], policy: dict[str, Any]) -> Decision:
    tool = tool_name(policy, "run_gated_command")
    if cmd == "systemctl":
        verbs = {"stop", "disable", "mask", "restart", "kill", "reload"}
        for tok in tokens[1:]:
            if tok in verbs:
                return gated(
                    "service-control",
                    f"systemctl {tok} must be approved via run_gated_command.",
                    tool,
                )
        return ALLOW
    if cmd == "docker":
        # docker compose down / docker stop / rm / kill / system prune
        rest = [basename(t) for t in tokens[1:] if not t.startswith("-")]
        if not rest:
            return ALLOW
        if rest[0] in {"compose", "stack"} and "down" in rest:
            return gated(
                "service-control",
                "docker compose down must be approved via run_gated_command.",
                tool,
            )
        if rest[0] in {"stop", "rm", "kill"}:
            return gated(
                "service-control",
                f"docker {rest[0]} must be approved via run_gated_command.",
                tool,
            )
        if rest[0] == "system" and "prune" in rest:
            return gated(
                "service-control",
                "docker system prune must be approved via run_gated_command.",
                tool,
            )
        return ALLOW
    if cmd in {"docker-compose", "podman-compose"}:
        rest = [t for t in tokens[1:] if not t.startswith("-")]
        if rest and rest[0] == "down":
            return gated(
                "service-control",
                f"{cmd} down must be approved via run_gated_command.",
                tool,
            )
    if cmd == "podman" and len(tokens) > 1 and basename(tokens[1]) in {"stop", "rm", "kill"}:
        return gated(
            "service-control",
            f"podman {basename(tokens[1])} must be approved via run_gated_command.",
            tool,
        )
    return ALLOW


def classify_deploy(cmd: str, tokens: list[str], policy: dict[str, Any]) -> Decision:
    tool = tool_name(policy, "run_gated_command")
    rest = [t for t in tokens[1:] if t != "--"]
    verbs = [t for t in rest if not t.startswith("-")]

    if cmd in {"kubectl"}:
        if verbs:
            v = verbs[0]
            if v == "delete" and any(x in {"namespace", "ns"} for x in verbs[1:2] + rest):
                if "namespace" in rest or "ns" in rest:
                    return deny(
                        "kubectl-delete-ns",
                        "Deleting Kubernetes namespaces is blocked.",
                    )
            if v in DEPLOY_PREFIXES["kubectl"]:
                return gated(
                    "deploy",
                    f"kubectl {v} must be approved via run_gated_command.",
                    tool,
                )
        return ALLOW

    if cmd in {"terraform", "tofu"}:
        if verbs and verbs[0] == "destroy":
            return deny("terraform-destroy", f"{cmd} destroy is blocked.")
        if verbs and verbs[0] == "apply":
            return gated(
                "deploy",
                f"{cmd} apply must be approved via run_gated_command.",
                tool,
            )
        return ALLOW

    if cmd in {"helm"}:
        if verbs and verbs[0] in DEPLOY_PREFIXES["helm"]:
            return gated(
                "deploy",
                f"helm {verbs[0]} must be approved via run_gated_command.",
                tool,
            )
        return ALLOW

    if cmd in {"fly", "flyctl"}:
        if verbs and verbs[0] == "deploy":
            return gated("deploy", f"{cmd} deploy must be approved via run_gated_command.", tool)
        return ALLOW

    if cmd == "vercel":
        if "--prod" in rest or (verbs and verbs[0] == "deploy"):
            return gated("deploy", "vercel --prod/deploy must be approved via run_gated_command.", tool)
        return ALLOW

    if cmd == "ansible-playbook":
        return gated(
            "deploy",
            "ansible-playbook must be approved via run_gated_command.",
            tool,
        )

    if cmd == "heroku":
        if verbs and verbs[0] in {"create", "destroy", "ps:scale", "releases:rollback"} or any(
            t.startswith("deploy") for t in rest
        ):
            return gated("deploy", "heroku deploy/scale must be approved via run_gated_command.", tool)
        return ALLOW

    return ALLOW


def classify_publish(cmd: str, tokens: list[str], policy: dict[str, Any]) -> Decision:
    tool = tool_name(policy, "run_gated_command")
    rest = [basename(t) for t in tokens]
    pairs = [(rest[0], rest[1])] if len(rest) > 1 else []
    if tuple(rest[:2]) in PUBLISH_COMMANDS or (cmd, rest[1] if len(rest) > 1 else "") in PUBLISH_COMMANDS:
        return gated(
            "publish",
            f"{' '.join(rest[:2])} must be approved via run_gated_command.",
            tool,
        )
    if cmd == "gh":
        # gh repo delete / gh release create|delete / gh pr merge
        if len(tokens) >= 3 and tokens[1] == "repo" and tokens[2] == "delete":
            return deny("gh-repo-delete", "gh repo delete is blocked.")
        if len(tokens) >= 3 and tokens[1] == "release" and tokens[2] in {"create", "delete"}:
            return gated(
                "publish",
                f"gh release {tokens[2]} must be approved via run_gated_command.",
                tool,
            )
        if len(tokens) >= 3 and tokens[1] == "pr" and tokens[2] == "merge":
            return gated(
                "publish",
                "gh pr merge must be approved via run_gated_command.",
                tool,
            )
    if cmd == "uv" and len(tokens) > 1 and tokens[1] == "publish":
        return gated("publish", "uv publish must be approved via run_gated_command.", tool)
    if cmd == "twine" and len(tokens) > 1 and tokens[1] == "upload":
        return gated("publish", "twine upload must be approved via run_gated_command.", tool)
    if cmd == "cargo" and len(tokens) > 1 and tokens[1] == "publish":
        return gated("publish", "cargo publish must be approved via run_gated_command.", tool)
    if cmd in {"npm", "pnpm", "yarn", "npx"} and "publish" in tokens[1:]:
        return gated("publish", f"{cmd} publish must be approved via run_gated_command.", tool)
    return ALLOW


def classify_full_string(command: str) -> Decision:
    if PIPE_TO_SHELL_RE.search(command):
        return deny("pipe-to-shell", "Piping curl/wget/fetch into a shell is blocked.")
    if BASE64_TO_SHELL_RE.search(command):
        return deny("base64-to-shell", "Decoding base64 into a shell is blocked.")
    if REDIRECT_DEVICE_RE.search(command):
        return deny("redirect-block-device", "Redirecting onto a block device is blocked.")
    return ALLOW


def classify_segment(
    tokens: list[str],
    cwd: str | None,
    policy: dict[str, Any],
    workspace_roots: list[str],
) -> Decision:
    if not tokens:
        return ALLOW
    inner, used_priv = strip_wrappers(tokens)
    if not inner:
        if used_priv:
            return ask("privilege-escalation", "sudo/su/doas/pkexec requires confirmation.")
        return ALLOW

    cmd = basename(inner[0])
    decision = ALLOW

    if cmd in {"mkfs", "mkfs.ext4", "mkfs.xfs", "mkfs.btrfs", "mkfs.vfat", "mkswap"}:
        decision = deny("mkfs", "Formatting disks is blocked.")
    elif cmd == "dd":
        joined = " ".join(inner)
        if re.search(r"\bof=/dev/", joined):
            decision = deny("dd-device", "Writing raw devices with dd is blocked.")
    elif cmd == "shred":
        decision = deny("shred", "shred is blocked.")
    elif cmd == "chmod":
        joined = " ".join(inner)
        if re.search(r"-R\b.*\b777\b", joined) or re.search(r"\b777\b.*-R\b", joined):
            if any(p in {"/", "/*"} for p in inner[1:]):
                decision = deny("chmod-777-root", "chmod -R 777 on / is blocked.")
    elif cmd in {"shutdown", "reboot", "poweroff", "halt", "telinit"}:
        decision = deny("shutdown", "shutdown/reboot/poweroff is blocked.")
    elif cmd == "kill":
        joined = inner[1:]
        if "-9" in joined and "-1" in joined:
            decision = deny("kill-all", "kill -9 -1 is blocked.")
    elif cmd == "rm":
        decision = classify_rm(inner, cwd, workspace_roots)
    elif cmd == "git":
        decision = classify_git(inner, cwd, policy)
    elif cmd in SSH_FAMILY:
        host = extract_host_from_tokens(cmd, inner)
        if is_prod_host(host or "", policy):
            decision = deny(
                "prod-ssh",
                f"{cmd} to production host `{host}` is blocked.",
            )
        elif looks_like_remote_host(host):
            decision = ask(
                "remote-ssh",
                f"{cmd} to `{host}` requires confirmation.",
            )
    elif cmd in {"eval"}:
        decision = ask("eval-or-shell-c", "eval can hide a dangerous command.")
    elif cmd in {"bash", "sh", "zsh", "ksh", "fish"}:
        if "-c" in inner:
            idx = inner.index("-c")
            nested = ALLOW
            if idx + 1 < len(inner):
                nested = classify_command(inner[idx + 1], cwd, policy, workspace_roots)
            shell_c = ask(
                "eval-or-shell-c",
                f"{cmd} -c can hide a dangerous command and needs confirmation.",
            )
            decision = stricter(nested, shell_c)
    elif cmd == "su":
        decision = ask("privilege-escalation", "su requires confirmation.")
    else:
        decision = classify_service(cmd, inner, policy)
        if decision.permission == "allow":
            decision = classify_deploy(cmd, inner, policy)
        if decision.permission == "allow":
            decision = classify_publish(cmd, inner, policy)

    # tamper with security net via rm/mv/sed/chmod/tee on protected paths
    if decision.permission != "deny" or decision.rule_id != "tamper-security-net":
        if cmd in {"rm", "mv", "sed", "chmod", "chown", "tee", "truncate", "unlink", "ln"}:
            for tok in inner[1:]:
                if tok.startswith("-"):
                    continue
                if is_protected_path(tok, policy, cwd):
                    decision = deny(
                        "tamper-security-net",
                        "Modifying security-net files is blocked.",
                    )
                    break
        joined_inner = " ".join(inner)
        if re.search(r"core\.hooksPath", joined_inner):
            decision = deny(
                "tamper-security-net",
                "Changing git core.hooksPath is blocked.",
            )

    if used_priv and cmd not in PRIVILEGE:
        decision = stricter(
            decision,
            ask("privilege-escalation", "sudo/su/doas/pkexec requires confirmation."),
        )
    elif cmd in PRIVILEGE:
        decision = stricter(
            decision,
            ask("privilege-escalation", "sudo/su/doas/pkexec requires confirmation."),
        )
    return decision


def classify_command(
    command: str,
    cwd: str | None,
    policy: dict[str, Any],
    workspace_roots: Iterable[str] | None = None,
) -> Decision:
    roots = [r for r in (workspace_roots or []) if r]
    best = classify_full_string(command)
    segments = split_segments(command) or [command]
    for segment in segments:
        tokens = tokenize(segment)
        best = stricter(best, classify_segment(tokens, cwd, policy, roots))
        # also classify without splitting quotes-stripped inner of bash -c already handled
    return best


def decision_to_payload(decision: Decision) -> dict[str, Any]:
    payload: dict[str, Any] = {"permission": decision.permission}
    if decision.user_message:
        payload["user_message"] = decision.user_message
    if decision.agent_message:
        payload["agent_message"] = decision.agent_message
    return payload
