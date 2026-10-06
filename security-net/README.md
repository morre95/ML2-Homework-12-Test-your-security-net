# Agent Security Net

Projektnivå-säkerhetsnät för Cursor-agenten. Hooks spärrar farliga tool-calls, tvingar dig in i loopen för git-historik, och ger agenten specialbyggda MCP-verktyg för det som annars är förbjudet (push till `main`/`dev`, deploy, tjänstestyrning).

## Arkitektur

```
Agent  --git push origin main-->  guard-shell.py  --deny-->  agenten
Agent  --push_protected_branch-->  guard-mcp.sh   --ask-->   du
Du     --allow----------------->  git-gate MCP            --git push-->  remote
```

All policy ligger i [`.cursor/hooks/policy.json`](.cursor/hooks/policy.json). Ändra den filen om du vill skydda fler brancher, lägga till prod-hosts eller justera hemlighetsmönster.

## Vad som spärras

### Hard deny (går inte via git-gate heller)

- `rm -rf /`, `$HOME` och systemkataloger
- `mkfs`, `dd of=/dev/…`, `shred`, `chmod -R 777 /`
- `curl|wget … | sh`, `base64 -d | sh`
- SSH/SCP/RSYNC mot värdar som matchar `prod` / `production` / `*.prod.*`
- `shutdown` / `reboot` / `poweroff`, `kill -9 -1`
- `gh repo delete`, `terraform destroy`, `kubectl delete namespace`
- Ändring av själva säkerhetsnätet (`.cursor/hooks*`, `.cursor/mcp.json`, `git config core.hooksPath`)
- Läs/skriv av hemligheter (`.env`, `~/.ssh/id_*`, `~/.aws/credentials`, `*.pem`, …)

### Gated (deny i Shell, tillåtet via MCP efter ditt OK)

| Situation | MCP-verktyg |
| --- | --- |
| `git push` till `main`/`master`/`dev`/`develop`/`production`/`release/*` (även bar `git push` när aktuell branch är skyddad) | `push_protected_branch` |
| Force-push, `git push --delete` | `run_gated_command` |
| Deploy (`kubectl apply/rollout`, `terraform apply`, `helm install/upgrade`, `fly deploy`, `vercel --prod`, `ansible-playbook`, …) | `run_gated_command` |
| Tjänster (`systemctl stop/disable/mask/restart`, `docker stop/rm/kill/system prune`, `docker compose down`) | `run_gated_command` |
| Publicering (`npm publish`, `twine upload`, `uv publish`, `cargo publish`, `gh release create/delete`, `gh pr merge`) | `run_gated_command` |

### Ask (ett klick i Cursor)

Git-kommandon som skriver om historik eller kastar arbete: `rebase`, `reset --hard/--merge`, `commit --amend`, `filter-branch`/`filter-repo`, `reflog expire/delete`, `gc --prune`, `branch -D`, `tag -d`, `checkout -- .`, `restore .`, `clean -f`, `stash drop/clear`, `update-ref -d`.

Även `sudo`/`su`/`doas`, `rm -r` utanför workspace, SSH till icke-prod, `eval` och `bash -c`.

## MCP-servern `git-gate`

Definierad i [`.cursor/mcp.json`](.cursor/mcp.json), implementerad i [`.cursor/tools/git_gate_mcp.py`](.cursor/tools/git_gate_mcp.py).

Hooken [`guard-mcp.sh`](.cursor/hooks/guard-mcp.sh) sätter alltid `permission: "ask"` för den servern, så auto-run inte kan kringgå dig.

1. Agenten försöker `git push origin main` → Shell-hooken nekar och pekar på `push_protected_branch`.
2. Agenten anropar `push_protected_branch(branch="main", justification="…")`.
3. Du får ett godkännande-kort med justification och args.
4. Vid allow kör servern `git log origin/main..HEAD` och därefter `git push`.

`show_policy` är read-only men går samma ask-väg så du ser när agenten läser reglerna.

## Övriga hooks

| Event | Script | Roll |
| --- | --- | --- |
| `sessionStart` | `session-start.sh` | Injectar projekttyp, branch, uncommitted + policy i agentkontexten |
| `sessionEnd` | `session-end.sh` | Loggar duration; `notify-send` om det finns uncommitted filer |
| `afterFileEdit` | `write-format.sh` | `ruff format` (PATH eller `uvx`) / Prettier om projektet har det |
| `postToolUse` | `lsp-check.sh` | basedpyright + ruff (Python) eller `tsc --noEmit` (TS) som `additional_context` |
| `preToolUse` | `guard-tools.py` | Write/Edit/Delete får inte röra hooks eller hemligheter |
| `beforeReadFile` | `guard-read.py` | Blockerar läsning av nycklar och `.env` |

Inspiration: [session-start.sh](https://github.com/Aedelon/claude-code-blueprint/blob/main/hooks/scripts/session-start.sh), [session-end.sh](https://github.com/Aedelon/claude-code-blueprint/blob/main/hooks/scripts/session-end.sh), [write-format.sh](https://github.com/Aedelon/claude-code-blueprint/blob/main/hooks/scripts/write-format.sh).

## Filer

```
.cursor/hooks.json
.cursor/mcp.json
.cursor/hooks/policy.json
.cursor/hooks/guard-shell.py
.cursor/hooks/guard-tools.py
.cursor/hooks/guard-read.py
.cursor/hooks/guard-mcp.sh
.cursor/hooks/session-start.sh
.cursor/hooks/session-end.sh
.cursor/hooks/write-format.sh
.cursor/hooks/lsp-check.sh
.cursor/tools/git_gate_mcp.py
```

Auditloggar skrivs till `.cursor/hooks/logs/` (gitignored).

## Krav

- `jq`, `python3`, `git`
- `uv` för MCP-servern (`~/.local/bin/uv`)
- valfritt: `ruff`, `basedpyright` (annars `uvx`), `notify-send`

Cursor laddar om `hooks.json` vid sparning. Om en hook inte syns: öppna **Cursor Settings → Hooks** och starta om fönstret.

## Testa lokalt

```bash
echo '{"command":"git push origin main","cwd":"'"$PWD"'"}' \
  | .cursor/hooks/guard-shell.py
# → permission: deny, pekar på push_protected_branch

echo '{"mcp_server_name":"git-gate","tool_name":"push_protected_branch","tool_input":"{\"branch\":\"main\",\"justification\":\"release\"}"}' \
  | .cursor/hooks/guard-mcp.sh
# → permission: ask
```
