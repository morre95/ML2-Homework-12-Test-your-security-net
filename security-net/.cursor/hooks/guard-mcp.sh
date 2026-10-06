#!/usr/bin/env bash
# =============================================================================
# Cursor Hook: beforeMCPExecution — force user approval for git-gate tools
# =============================================================================
set -euo pipefail

export PATH="${HOME}/.local/bin:/usr/bin:/bin:${PATH}"

input=$(cat)

server=$(echo "$input" | jq -r '.mcp_server_name // empty')
if [ "$server" != "git-gate" ]; then
    echo '{"permission":"allow"}'
    exit 0
fi

tool=$(echo "$input" | jq -r '.tool_name // empty')
input_type=$(echo "$input" | jq -r '.tool_input | type')

if [ "$input_type" = "string" ]; then
    raw=$(echo "$input" | jq -r '.tool_input')
    if echo "$raw" | jq -e . >/dev/null 2>&1; then
        args_json="$raw"
    else
        args_json=$(jq -n --arg raw "$raw" '{raw:$raw}')
    fi
else
    args_json=$(echo "$input" | jq -c '.tool_input // {}')
fi

justification=$(echo "$args_json" | jq -r '.justification // empty')
summary=$(echo "$args_json" | jq -c '.')

user_message="git-gate tool \`${tool}\` requires your approval."
if [ -n "$justification" ]; then
    user_message="${user_message} Justification: ${justification}"
fi
user_message="${user_message} Args: ${summary}"

agent_message="The security net is asking the user to approve git-gate tool \`${tool}\`. Do not retry via Shell."

jq -n \
    --arg um "$user_message" \
    --arg am "$agent_message" \
    '{permission:"ask", user_message:$um, agent_message:$am}'

exit 0
