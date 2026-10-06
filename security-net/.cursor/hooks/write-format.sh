#!/usr/bin/env bash
# =============================================================================
# Cursor Hook: afterFileEdit — auto-format written files
# Inspired by https://github.com/Aedelon/claude-code-blueprint/blob/main/hooks/scripts/write-format.sh
# =============================================================================
set -euo pipefail

export PATH="${HOME}/.local/bin:/usr/bin:/bin:${PATH}"

input=$(cat)
file_path=$(echo "$input" | jq -r '.file_path // .path // empty')

if [ -z "$file_path" ] || [ ! -f "$file_path" ]; then
    exit 0
fi

run_ruff() {
    if command -v ruff >/dev/null 2>&1; then
        ruff format --quiet "$file_path" >/dev/null 2>&1 || true
    elif command -v uvx >/dev/null 2>&1; then
        uvx ruff format --quiet "$file_path" >/dev/null 2>&1 || true
    fi
}

run_prettier() {
    local dir
    dir="$(dirname "$file_path")"
    if [ -x "${CURSOR_PROJECT_DIR:-}/node_modules/.bin/prettier" ]; then
        "${CURSOR_PROJECT_DIR}/node_modules/.bin/prettier" --write "$file_path" >/dev/null 2>&1 || true
        return
    fi
    if command -v prettier >/dev/null 2>&1; then
        prettier --write "$file_path" >/dev/null 2>&1 || true
        return
    fi
    if command -v npx >/dev/null 2>&1; then
        # only if the project already depends on prettier
        if [ -f "${CURSOR_PROJECT_DIR:-}/package.json" ] && grep -q '"prettier"' "${CURSOR_PROJECT_DIR}/package.json" 2>/dev/null; then
            npx --no-install prettier --write "$file_path" >/dev/null 2>&1 || true
        fi
    fi
}

case "$file_path" in
    *.py)
        run_ruff
        ;;
    *.ts|*.tsx|*.js|*.jsx|*.mjs|*.cjs|*.json|*.md)
        run_prettier
        ;;
esac

exit 0
