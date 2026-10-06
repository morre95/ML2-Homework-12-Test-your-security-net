#!/usr/bin/env bash
# =============================================================================
# Cursor Hook: sessionEnd — log duration and remind about uncommitted files
# Inspired by https://github.com/Aedelon/claude-code-blueprint/blob/main/hooks/scripts/session-end.sh
# =============================================================================
set -euo pipefail

export PATH="${HOME}/.local/bin:/usr/bin:/bin:${PATH}"

HOOKS_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG_DIR="${HOOKS_DIR}/logs"
mkdir -p "$LOG_DIR"

input=$(cat)

reason=$(echo "$input" | jq -r '.reason // "unknown"')
duration_ms=$(echo "$input" | jq -r '.duration_ms // 0')
session_id=$(echo "$input" | jq -r '.session_id // .conversation_id // empty')
cwd=$(echo "$input" | jq -r '.workspace_roots[0] // .cwd // empty')
if [ -z "$cwd" ]; then
    cwd="$(pwd)"
fi
cd "$cwd" 2>/dev/null || true

uncommitted=0
if git rev-parse --git-dir >/dev/null 2>&1; then
    uncommitted=$(git status --short 2>/dev/null | wc -l | tr -d ' ')
fi

jq -n \
    --arg ts "$(date -Iseconds)" \
    --arg sid "$session_id" \
    --arg reason "$reason" \
    --arg cwd "$cwd" \
    --argjson duration "$duration_ms" \
    --argjson uncommitted "$uncommitted" \
    '{ts:$ts, event:"sessionEnd", session_id:$sid, reason:$reason, cwd:$cwd, duration_ms:$duration, uncommitted:$uncommitted}' \
    >> "${LOG_DIR}/sessions.log"

if [ "$uncommitted" -gt 0 ] && command -v notify-send >/dev/null 2>&1; then
    notify-send \
        "Cursor-session slut" \
        "${uncommitted} uncommitted fil(er). Reason: ${reason}" \
        >/dev/null 2>&1 || true
fi

exit 0
