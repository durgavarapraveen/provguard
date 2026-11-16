# provguard

A runtime firewall for AI coding agents. It tracks where context comes from and blocks dangerous tool calls that untrusted content drives.

> **Status: week 3.** provguard labels what each session reads (untrusted, sensitive), parses every Bash/PowerShell command into sink classes (EGRESS, PERSIST, DESTROY, EXEC_REMOTE, OPAQUE) and logs them, and blocks one thing: agent changes to hook settings or provguard's own files. The main policy (blocking exfiltration) comes in week 4.

See [DESIGN.md](DESIGN.md) for the threat model, design and MVP plan.

## Build

Requires Go 1.22 or later.

```bash
go build -o bin/provguard ./cmd/provguard
```

## Install the hooks (Claude Code)

`init` shows the change first. It writes only with `--yes`, and it backs up your settings file.

```bash
bin/provguard init
```

```bash
bin/provguard init --yes
```

Remove the hooks:

```bash
bin/provguard uninstall --yes
```

## What it does now

| Event | Action |
|---|---|
| PreToolUse | **Self-protection:** denies agent writes (Write, Edit, Bash, PowerShell) that change `hooks` or `disableAllHooks` in any `.claude/settings*.json`, any write to `~/.provguard/`, and agent runs of `provguard init/uninstall`. |
| PostToolUse | Labels the result. **Untrusted:** web fetch/search, `curl`/`wget`/`gh issue view`-style commands, third-party MCP servers, vendor dirs, repos of untrusted owners, output of subagents that read untrusted content. **Sensitive:** `.env`, SSH keys, cloud credentials, env dumps, tokens found in output. |
| UserPromptSubmit | Marks the session sensitive if the prompt contains a token. |
| SessionStart | Deletes session files older than 7 days. |

## Files

| Path | Content |
|---|---|
| `~/.provguard/audit/YYYY-MM-DD.jsonl` | One redacted line per hook call |
| `~/.provguard/sessions/<id>.json` | Per-session labels, untrusted URLs/hosts, secret fingerprints (HMAC) |
| `~/.provguard/key` | Per-install HMAC key for fingerprints |
| `~/.provguard/config.json` | Optional config (below) |

Set `PROVGUARD_HOME` to change the location.

## Config

`~/.provguard/config.json` (all keys optional):

```json
{
  "self_protect": true,
  "trusted_repo_owners": ["your-github-user"],
  "trusted_mcp_servers": ["github"],
  "trust_sdk_mcp_servers": true,
  "allowed_hosts": ["docs.python.org"]
}
```

- `trusted_repo_owners`: files in git repos whose origin owner is not listed are untrusted. Empty list turns the check off.
- `trust_sdk_mcp_servers`: trust in-process MCP servers that the host app provides.

An agent cannot edit this file, because self-protection blocks it. Edit it yourself.

## Safety rules for this tool

- **Fail open.** If provguard has an error, the agent continues with its normal permission flow. provguard never returns "allow"; it only denies.
- **No raw secrets on disk.** Tool inputs are redacted. Tool outputs are stored as size and SHA-256 only. Secrets are stored as HMAC fingerprints only.

## Shell analysis

Bash commands are parsed with [mvdan.cc/sh](https://github.com/mvdan/sh). provguard walks pipes, lists, subshells, `$(...)`, `<(...)`, here-documents, functions and control flow; resolves variables assigned in the same command; and looks inside wrappers (`sudo`, `env`, `timeout`, `xargs`, `bash -c`, `pwsh -Command`, `cmd /c`, `python -c`, `node -e`, `find -exec`). PowerShell uses a tokenizer heuristic (no Go parser exists): quotes, `$(...)`, `(...)`, script blocks, pipelines, redirects, aliases and named parameters.

Each Bash/PowerShell call's sinks are written to the audit log, e.g. `"sinks": ["EGRESS:curl->https://example.com"]`. Self-protection uses the resolved write targets, so text inside a commit message no longer triggers it.

## Known gaps

- Values known only at run time (environment variables, command output) cannot be resolved. Writes to such paths are blocked only when the command also names protected files; code that provguard cannot read (`eval`, `python -c`, encoded commands) is blocked only when its text names protected files.
- The PowerShell analysis is a heuristic, not a full parser.
- The provguard binary itself is not protected from replacement yet (week 7).

## License

Apache-2.0.
