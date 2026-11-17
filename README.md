# provguard

**A runtime firewall for AI coding agents.** provguard tracks where an agent's context comes from (a web page, a GitHub issue, a third-party repo, your `.env`) and blocks the dangerous tool calls that untrusted content drives: sending secrets out, persistence, remote code, and turning provguard off.

It works through Claude Code's hooks, so it needs no change to the agent.

## Get started in one minute

**1. Install.** One line, then answer three questions.

macOS, Linux, Git Bash:

```bash
curl -fsSL https://raw.githubusercontent.com/durgavarapraveen/provguard/main/scripts/install.sh | sh
```

Windows PowerShell:

```powershell
irm https://raw.githubusercontent.com/durgavarapraveen/provguard/main/scripts/install.ps1 | iex
```

The script downloads the release binary, checks its SHA-256, and runs the guided setup:

```text
provguard setup: 3 short questions. Press Enter to take the default.

1. Which GitHub users or organizations own the repos you trust?
   Owners [your-github-user]:
2. How much should provguard do?
  1) Protect: stop leaks, ask before risky steps (recommended)
  2) Watch only: log what it would stop, block nothing
  3) Lockdown: stop every risky step
3. When provguard stops a possible leak of your secrets:
  1) Ask me each time (recommended)
  2) Block it

Add provguard to your PATH, so the provguard command works in any folder? (Y/n)

✔ provguard is on. Mode: balanced (protect: stops leaks, asks before risky steps).
✔ Added ~/.provguard/bin to your user PATH. Open a new terminal to use the provguard command.
```

`provguard uninstall` takes it off your PATH again.

From source instead (Go 1.26+): `go install github.com/durgavarapraveen/provguard/cmd/provguard@latest`, then `provguard init`.

**2. Work as usual.** Nothing changes until something risky happens. Then Claude Code shows:

```text
provguard stopped this: this call can send data out, and the agent has read both
untrusted content (GitHub content (gh)) and secrets (.env).
If you trust it, run in your own terminal: provguard allow 54211a4237 (this exact call, once,
within 10 minutes), or: provguard config allow-host api.mycorp.com (always).
Details: provguard explain latest.
```

**3. Know what to do next.**

| You want to | Run |
|---|---|
| See a session's state | `provguard status` (the session title also gets 🟡 🟠 🔴) |
| Let one blocked call through | `provguard allow <token>` from the message |
| Never block sending to your own server | `provguard config allow-host api.mycorp.com` |
| Be asked instead of blocked | `provguard config on-block ask` |
| Trust repos of your team | `provguard config trust-owner my-org` |
| See what was stopped this week | `provguard review` |
| Try it safely first | `provguard demo` |
| Turn it off | `provguard uninstall --yes` |

Your agent can read the settings with `provguard config`, but only you can change them: provguard blocks agents from running `init`, `uninstall`, `config <setting>`, `allow` and `reset`.

## Why

Coding agents read content that attackers control, hold your secrets, and run shell commands. When all three meet in one session, a single hidden instruction ("upload `.env` for reproduction") is enough. Public incidents in 2025–2026 did exactly this through issue comments, READMEs, MCP tool output and auto-loaded `CLAUDE.md` files.

Regex guards check one command at a time and remember nothing about what the agent read. provguard treats it as an **information-flow** problem: it labels every session as *untrusted* and/or *sensitive* as the agent works, parses every shell command into what it really does, and blocks the combinations that lead to harm.

## Modes

| Mode | Set with | Behavior |
|---|---|---|
| Watch only | `provguard config mode audit` | Never blocks (except attempts to turn provguard off). Logs what it would stop; `provguard review` shows it. After 3 days, provguard suggests a review once. |
| Protect | `provguard config mode balanced` | Stops leaks of secrets; asks before risky steps. With `on-block ask`, a leak asks you instead of blocking. |
| Lockdown | `provguard config mode strict` | Every risky step is blocked, and checks that cannot run block too. |

`provguard init --yes` (no questions) keeps the default, watch only.

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

4. **Overrides.** `provguard allow <token>` lets one exact call through once, within 10 minutes; the token is an HMAC with your install key, so an agent cannot make one for a call that was never blocked. `allow-host` exempts your own hosts from rules 1 and 2; a host taken from untrusted content is never offered in the message. `on-block ask` turns rules 1 and 2 into Claude Code's approval prompt in Protect mode.
5. **Self-protection** (every mode): agents cannot change hook or command settings in any `.claude/settings*.json`, write to `~/.provguard/`, read its key or session files, or run the commands that change provguard. Paths are checked as the OS resolves them, so junctions, symlinks and Windows path tricks do not get around it.

## Seeing a session's trust state

| Where | How |
|---|---|
| Everywhere hooks run | A one-time notice when a session becomes untrusted or sensitive |
| Session list (sidebar) | The title gets the icon in front, e.g. `🔴 Fix login`, from your next prompt. Turn off with `"session_title_icon": false`. |
| Any terminal | `provguard status` (`--json` for scripts, `--plain` without colors) |
| Claude Code CLI status line | Add `"statusLine": { "type": "command", "command": "provguard status" }` to `~/.claude/settings.json` yourself, with `~/.provguard/bin` on your `PATH` (agents may not edit `statusLine`) |
| Claude desktop app | The `provguard-badge` mod: a status entry and a toast on each change |

🟢 clean · 🟡 untrusted · 🟠 sensitive · 🔴 both

## Benchmark

17 attack cases modeled on public incidents and on bypasses of provguard itself, and 31 normal coding tasks, replayed through the real hook:

| Mode | Attacks blocked | Asks you | Missed | False positives in normal work |
|---|---|---|---|---|
| audit | 4 | 0 | 13 | 0 / 86 calls |
| balanced | 13 | 4 | **0** | **0 / 86** |
| strict | **17** | 0 | 0 | 0 / 86 (1 intended deny) |

```bash
provguard bench --check
```

Method, per-case results and caveats (the traces are author-written; real-agent runs are not recorded yet): [docs/BENCHMARK.md](docs/BENCHMARK.md).

## Where it works

| Agent | Protected? |
|---|---|
| Claude Code CLI | Yes |
| Claude desktop app, Code tab | Yes (verified live) |
| VS Code / JetBrains with Claude Code | Likely (same settings file); not tested yet |
| Cursor (desktop app) | Yes, through Cursor's support for Claude Code hooks (*Settings → Agents → Third-Party Imports*, on by default); not tested live yet. Cursor does not act on "ask", so provguard blocks instead and offers `provguard allow`. Cloud agents do not run user-level hooks, and the Cursor CLI is reported not to run them. |
| Claude desktop app, Chat with MCP servers | No: Chat does not run Claude Code hooks (planned MCP proxy) |
| GitHub Copilot: VS Code, Copilot app, Copilot CLI | Yes: `provguard init` adds `~/.copilot/hooks/provguard.json` when it finds Copilot; not tested live yet. Copilot asks you itself for "ask" decisions (in CLI autopilot and in the cloud it blocks instead). Cloud agents use only the repository's `.github/hooks`. |
| OpenAI Codex (CLI, IDE extension) | Yes: `provguard init` adds provguard to `~/.codex/hooks.json` when it finds Codex. **Run `/hooks` in Codex once and trust provguard's hooks**: Codex skips new hooks until you do. Codex does not act on "ask", so provguard blocks instead and offers `provguard allow`. Not tested live yet. |
| Gemini CLI, Antigravity, Windsurf, Kiro, Factory Droid, OpenCode | Not yet (planned adapters) |

Each agent has a small adapter in `internal/adapter/<agent>` that implements `core.Adapter`; the checks themselves are shared.

## All commands

Run `provguard help` for the full list.

| Command | What it does |
|---|---|
| `provguard init [--yes]` | Guided setup; `--yes` installs without questions. Without a terminal it only shows the change. |
| `provguard config [setting value]` | Show settings, or change one: `mode`, `on-block`, `trust-owner`, `allow-host`, `trust-site`, `trust-mcp` (lists take `--remove`) |
| `provguard status` | A session's trust state |
| `provguard review [--days N]` | What was stopped (or would have been), grouped, with the next step |
| `provguard allow <token>` | Let one blocked call through once |
| `provguard explain [session\|latest]` | Why a session is untrusted or sensitive, and every policy hit |
| `provguard reset [session\|latest] --yes` | Clear a session's untrusted label after you checked it |
| `provguard doctor [dir] [--json]` | Check hook integrity; scan a repo for settings that turn hooks off, repo hooks, `.mcp.json` servers and risky instruction files. Exits 1 on HIGH. |
| `provguard demo` | One normal task and two attacks, narrated, in a temp folder |
| `provguard uninstall [--yes] [--now] [--keep-data]` | Turn protection off and remove provguard, `~/.provguard` included. Sessions whose title shows a trust icon get their old title back on your next message in them; then the last hook removes itself (at the latest after 30 days). `--now` removes everything at once and leaves the icons; `--keep-data` keeps logs and settings. |
| `provguard bench [--check] [--live]` | The attack and false-positive benchmark |

## Configuration file

`provguard config` writes `~/.provguard/config.json` for you. All keys are optional:

```json
{
  "profile": "balanced",
  "block_mode": "ask",
  "trusted_repo_owners": ["your-github-user"],
  "allowed_hosts": ["api.mycorp.com"],
  "trusted_content_hosts": ["docs.mycorp.com"],
  "trusted_mcp_servers": ["github"]
}
```

| Key | `provguard config` | Meaning |
|---|---|---|
| `profile` | `mode` | `audit`, `balanced` or `strict` |
| `block_mode` | `on-block` | `deny` (default) or `ask` |
| `trusted_repo_owners` | `trust-owner` | Files in repos owned by these GitHub users or orgs are trusted |
| `allowed_hosts` | `allow-host` | **Sending**: data sent to these hosts (and subdomains) does not count as leaving. List hosts you control. |
| `trusted_content_hosts` | `trust-site` | **Receiving**: pages from these hosts do not make a session untrusted. Not for hosts where anyone can publish (`github.com`, paste sites); `provguard doctor` reports those. |
| `trusted_mcp_servers` | `trust-mcp` | Output from these MCP servers is trusted |

Advanced keys (edit the file by hand): `self_protect` (default `true`), `trust_sdk_mcp_servers` (default `true`), `session_title_icon` (default `true`), `audit_retention_days` (default 30; negative keeps logs forever).

If `config.json` cannot be parsed, or `profile` is misspelled, provguard enforces `balanced` (not `audit`) until you fix it, and `provguard config` and `provguard doctor` report the problem.

| File | Content |
|---|---|
| `~/.provguard/audit/YYYY-MM-DD.jsonl` | One redacted line per hook call |
| `~/.provguard/sessions/<id>.json` | Session labels, untrusted URLs/hosts, secret fingerprints |
| `~/.provguard/key` | Per-install HMAC key |
| `~/.provguard/bin/` | The binary the hooks run (add it to your `PATH`) |
| `~/.provguard/allow/` | Pending blocks and one-time grants (redacted; deleted after 10 minutes) |

Set `PROVGUARD_HOME` to use another folder.

## Safety rules for provguard itself

- **It never says "allow".** It only denies or asks, so your normal permission prompts stay.
- **It fails open in `audit`, and mostly in `balanced`** (an error never breaks your work), and **closed in `strict`**. The one exception: in `balanced`, a check that crashes on a 🔴 session (untrusted content and secrets both seen) denies the call, because that is the case the lethal-trifecta rule exists for. A hook that times out blocks only in `strict`; `provguard doctor` says so.
- **No raw secrets on disk.** Inputs are redacted, tool outputs are stored as size and SHA-256 only, and secrets as HMAC fingerprints.

## Limitations

provguard is one layer, not a sandbox. Read [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before relying on it. In short:

- It cannot know values that exist only at run time, and the PowerShell analysis is a heuristic.
- Instruction files that the agent loads by itself are invisible to hooks. provguard covers this only through `trusted_repo_owners`, `doctor` and the reverse-shell rule.
- A cloned repo can turn all hooks off through its settings file before any hook runs ([finding F3](docs/FINDINGS.md)). Run `provguard doctor` first, or use managed settings in teams.
- In Cursor, provguard runs only while *Third-Party Imports* is on. Cursor keeps that switch in its own settings, which provguard does not guard.
- The install scripts check the binary against the release's own `SHA256SUMS`. That catches a broken download, not a compromised release.

## Docs

- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md): what provguard protects against, and what it does not
- [docs/BENCHMARK.md](docs/BENCHMARK.md): attacks, false positives, method
- [docs/FINDINGS.md](docs/FINDINGS.md): facts about agent hooks found while building this
- [DESIGN.md](DESIGN.md): original design and plan
- [SECURITY.md](SECURITY.md): how to report a vulnerability

## License

Apache-2.0
