#!/usr/bin/env bash
# =============================================================================
# Cursor Hook: sessionStart — inject project + security-net context
# Inspired by https://github.com/Aedelon/claude-code-blueprint/blob/main/hooks/scripts/session-start.sh
# =============================================================================
set -euo pipefail

export PATH="${HOME}/.local/bin:/usr/bin:/bin:${PATH}"

HOOKS_DIR="$(cd "$(dirname "$0")" && pwd)"
POLICY_FILE="${HOOKS_DIR}/policy.json"
LOG_DIR="${HOOKS_DIR}/logs"
mkdir -p "$LOG_DIR"

input=$(cat)

cwd=$(echo "$input" | jq -r '.workspace_roots[0] // .cwd // empty')
if [ -z "$cwd" ]; then
    cwd="$(pwd)"
fi
cd "$cwd" 2>/dev/null || true

composer_mode=$(echo "$input" | jq -r '.composer_mode // empty')
session_id=$(echo "$input" | jq -r '.session_id // .conversation_id // empty')
is_bg=$(echo "$input" | jq -r '.is_background_agent // false')

context="SECURITY NET is active (session $(date '+%Y-%m-%d %H:%M:%S'))."

if [ -f package.json ]; then
    name=$(jq -r '.name // "project"' package.json 2>/dev/null || echo "project")
    if jq -e '.dependencies.next // .devDependencies.next' package.json >/dev/null 2>&1; then
        context="$context Project: $name (Next.js)."
    elif jq -e '.dependencies["react-native"] // .dependencies.expo' package.json >/dev/null 2>&1; then
        context="$context Project: $name (React Native)."
    else
        context="$context Project: $name (Node.js)."
    fi
elif [ -f pyproject.toml ]; then
    name=$(grep -E '^name\s*=' pyproject.toml 2>/dev/null | head -1 | sed 's/.*"\([^"]*\)".*/\1/' || echo "project")
    context="$context Project: ${name:-project} (Python)."
elif [ -f Cargo.toml ]; then
    name=$(grep -E '^name\s*=' Cargo.toml 2>/dev/null | head -1 | sed 's/.*"\([^"]*\)".*/\1/' || echo "project")
    context="$context Project: ${name:-project} (Rust)."
elif [ -f go.mod ]; then
    context="$context Project: Go."
fi

branch=""
uncommitted="0"
if git rev-parse --git-dir >/dev/null 2>&1; then
    branch=$(git branch --show-current 2>/dev/null || echo "detached")
    uncommitted=$(git status --short 2>/dev/null | wc -l | tr -d ' ')
    if [ "$uncommitted" -gt 0 ]; then
        context="$context Git: branch ${branch} (${uncommitted} uncommitted files)."
    else
        context="$context Git: branch ${branch}."
    fi
fi

protected="main, master, dev, develop, production, release/*"
if [ -f "$POLICY_FILE" ]; then
    protected=$(jq -r '
        ((.protected_branches // []) + (.protected_branch_globs // [])) | join(", ")
    ' "$POLICY_FILE" 2>/dev/null || echo "$protected")
fi

context="$context Protected branches: ${protected}."
context="$context Do NOT git push to a protected branch via Shell; call MCP tool push_protected_branch(branch, justification)."
context="$context Force-push, deploy, service stop/restart, and publish go through MCP tool run_gated_command(command, justification)."
context="$context Git history rewrites (rebase, reset --hard, commit --amend, filter-repo, clean -f, …) require user confirmation."
context="$context Production SSH, rm -rf of /, hook tampering, terraform destroy, and similar are hard-denied."
context="$context Use show_policy() to inspect the live policy. After file edits, format + LSP diagnostics are injected automatically."
if [ -n "$composer_mode" ]; then
    context="$context composer_mode=${composer_mode}."
fi

jq -n \
    --arg ts "$(date -Iseconds)" \
    --arg sid "$session_id" \
    --arg cwd "$cwd" \
    --arg branch "$branch" \
    --arg uncommitted "$uncommitted" \
    --arg mode "$composer_mode" \
    --argjson bg "$is_bg" \
    '{ts:$ts, event:"sessionStart", session_id:$sid, cwd:$cwd, branch:$branch, uncommitted:($uncommitted|tonumber), composer_mode:$mode, is_background_agent:$bg}' \
    >> "${LOG_DIR}/sessions.log"

escaped=$(jq -n --arg c "$context" '$c')
# additional_context at top level (Cursor sessionStart)
jq -n --arg c "$context" '{additional_context:$c}'

exit 0
