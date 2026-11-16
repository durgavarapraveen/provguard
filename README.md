# provguard

A runtime firewall for AI coding agents. It tracks where context comes from and blocks dangerous tool calls that untrusted content drives.

> **Status: week 7 (hardening done).** provguard labels what each session reads (untrusted, sensitive), parses every Bash/PowerShell command into sink classes, and applies a policy that can block exfiltration. The default profile is `audit`: it logs what it *would* block and blocks nothing except attempts to turn provguard off.

## Policy

Rules, first match wins:

| # | Situation | Decision |
|---|---|---|
| 1 | The call contains a secret this session has seen (plain, base64, hex or URL-encoded) | deny |
| 2 | EGRESS while the session has read both untrusted content and secrets (the "lethal trifecta") | deny |
| 3 | EGRESS to a URL or host taken from untrusted content | ask |
| 4 | PERSIST, EXEC_REMOTE or OPAQUE while the session is untrusted | ask |
| 5 | DESTROY (`rm -rf`, `git push --force`, …) | ask |
| 6 | Anything else | no decision (normal Claude Code permissions) |

Besides Bash and PowerShell, the policy also covers WebFetch (EGRESS when the URL carries data), Write/Edit to persistence paths (CI, git hooks, shell startup files, agent config), and third-party MCP tools whose names suggest writing (`create_*`, `send_*`, `post_*`, …).

Profiles, set with `"profile"` in `config.json`:

- `audit` (default): never blocks; the audit log records `"would": "deny"` or `"ask"`.
- `balanced`: the table above.
- `strict`: every "ask" becomes "deny".

## Benchmark

14 attack cases modeled on public incidents and on bypasses of provguard itself, plus 31 normal coding tasks. In replay mode, `balanced` blocks 10 attacks and asks on 4 (none missed), with 0 false positives in 86 normal tool calls. Details, method and caveats: [docs/BENCHMARK.md](docs/BENCHMARK.md).

**Set your trusted repo owners.** Several quiet-by-default behaviors (reads of your own repos, pushes to your own remotes, sessions started in someone else's repo) need this in `~/.provguard/config.json`:

```json
{ "trusted_repo_owners": ["your-github-user", "your-org"] }
```

```bash
provguard bench
```

## Commands for you

```bash
provguard explain latest
```

Shows why a session is untrusted or sensitive and every policy hit.

```bash
provguard reset latest --yes
```

Clears a session's untrusted label after you have checked it. Secret fingerprints stay. Agents cannot run `reset`, `init` or `uninstall`; self-protection blocks them.

See [DESIGN.md](DESIGN.md) for the threat model, design and MVP plan.

## Where it works

| Where you use Claude | Protected by provguard? |
|---|---|
| Claude Code CLI | Yes |
| Claude desktop app, Code tab | Yes (verified live) |
| VS Code / JetBrains with Claude Code | Likely, because they use the same `~/.claude/settings.json`. Not tested yet. |
| Claude desktop app, Chat with MCP servers | No. Chat does not run Claude Code hooks. Needs the planned MCP proxy (v0.3). |
| Cursor, Gemini CLI | Not yet. Adapters are planned for v0.2. |

`provguard bench --live` starts the Claude Code CLI (`claude -p`), which has its own login, separate from the desktop app. Run `claude` and then `/login` in a terminal first.

## Build

Requires Go 1.22 or later.

```bash
go build -o bin/provguard ./cmd/provguard
```

## Install the hooks (Claude Code)

`init` shows the change first. It writes only with `--yes`, and it backs up your settings file. It copies the binary to `~/.provguard/bin/` and points the hooks there, so an agent cannot replace the program its hooks run. In the `strict` profile it also makes the PreToolUse hook fail closed.

Before you open a repo you did not write, check it:

```bash
provguard doctor path/to/repo
```

`doctor` checks that provguard's hooks are installed and protected, and reports repo settings that turn hooks off, repo hooks, `.mcp.json` servers, and risky text in `CLAUDE.md` / `AGENTS.md` / `.cursorrules`. It exits 1 on a HIGH finding.

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
  "profile": "audit",
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
- The binary is protected only when installed by `provguard init` (not with `--no-copy`).
- `ConfigChange` handling and `onFailure: block` follow the Claude Code docs but are not yet verified live.

## License

Apache-2.0.
