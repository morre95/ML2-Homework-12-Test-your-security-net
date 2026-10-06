#!/usr/bin/env bash
# =============================================================================
# Cursor Hook: postToolUse — LSP / diagnostics after Write/StrReplace/Edit
# =============================================================================
set -euo pipefail

export PATH="${HOME}/.local/bin:/usr/bin:/bin:${PATH}"

input=$(cat)

tool=$(echo "$input" | jq -r '.tool_name // empty')
cwd=$(echo "$input" | jq -r '.cwd // empty')

file_path=$(echo "$input" | jq -r '
    .tool_input.path
    // .tool_input.file_path
    // .tool_input.target_file
    // .file_path
    // empty
')

if [ -z "$file_path" ] || [ ! -f "$file_path" ]; then
    echo '{}'
    exit 0
fi

if [ -n "$cwd" ] && [ -d "$cwd" ]; then
    cd "$cwd" || true
elif [ -n "${CURSOR_PROJECT_DIR:-}" ] && [ -d "${CURSOR_PROJECT_DIR}" ]; then
    cd "$CURSOR_PROJECT_DIR" || true
fi

diag_file="$(mktemp)"
trap 'rm -f "$diag_file"' EXIT

run_ruff_check() {
    local out
    if command -v ruff >/dev/null 2>&1; then
        out=$(ruff check --output-format json "$file_path" 2>/dev/null || true)
    elif command -v uvx >/dev/null 2>&1; then
        out=$(uvx ruff check --output-format json "$file_path" 2>/dev/null || true)
    else
        return
    fi
    echo "$out" | jq -r '
        if type=="array" then
            .[] | "\(.filename // "file"):\(.location.row // 0):\(.location.column // 0) \(.severity // "warning") [\(.code // "ruff")] \(.message // "")"
        else empty end
    ' 2>/dev/null >> "$diag_file" || true
}

run_basedpyright() {
    local out
    if command -v basedpyright >/dev/null 2>&1; then
        out=$(basedpyright --outputjson "$file_path" 2>/dev/null || true)
    elif command -v pyright >/dev/null 2>&1; then
        out=$(pyright --outputjson "$file_path" 2>/dev/null || true)
    elif command -v uvx >/dev/null 2>&1; then
        out=$(uvx basedpyright --outputjson "$file_path" 2>/dev/null || true)
    else
        return
    fi
    echo "$out" | jq -r '
        (.generalDiagnostics // .diagnostics // [])[]
        | "\(.file // .uri // "file"):\(.range.start.line + 1):\(.range.start.character + 1) \(.severity // "error") \(.message // "")"
    ' 2>/dev/null >> "$diag_file" || true
}

run_tsc() {
    if [ ! -f tsconfig.json ]; then
        return
    fi
    if command -v npx >/dev/null 2>&1; then
        npx --no-install tsc --noEmit --pretty false --pretty false 2>/dev/null \
            | grep -F "$file_path" \
            | head -n 40 >> "$diag_file" || true
    fi
}

case "$file_path" in
    *.py)
        run_ruff_check
        run_basedpyright
        ;;
    *.ts|*.tsx)
        run_tsc
        ;;
    *)
        echo '{}'
        exit 0
        ;;
esac

if [ ! -s "$diag_file" ]; then
    echo '{}'
    exit 0
fi

# cap injected context
lines=$(head -n 40 "$diag_file")
count=$(printf '%s\n' "$lines" | grep -c . || true)
context=$(printf 'LSP diagnostics after %s of %s (%s issue(s)):\n%s\nFix these if they were introduced by the last edit.' \
    "$tool" "$file_path" "$count" "$lines")

jq -n --arg c "$context" '{additional_context:$c}'
exit 0
