# provguard

[![CI](https://github.com/durgavarapraveen/provguard/actions/workflows/ci.yml/badge.svg)](https://github.com/durgavarapraveen/provguard/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/durgavarapraveen/provguard)](https://github.com/durgavarapraveen/provguard/releases/latest)
[![License](https://img.shields.io/github/license/durgavarapraveen/provguard)](LICENSE)
[![Go](https://img.shields.io/github/go-mod/go-version/durgavarapraveen/provguard)](go.mod)

**A runtime firewall for AI coding agents.** An agent that reads untrusted content (a web page, a GitHub issue, a cloned repo) and also holds your secrets can be turned against you by one hidden instruction. provguard tracks where the agent's context came from and stops the tool calls that untrusted content drives: sending secrets out, lasting changes, remote code, destructive commands, and turning provguard off.

- **10 agents, one install:** Claude Code, Cursor, GitHub Copilot, OpenAI Codex, Gemini CLI, Devin, Kiro, Factory Droid, OpenCode and Antigravity. provguard uses each agent's own hooks; the agent needs no change.
- **Local and private:** one Go binary on Windows, macOS and Linux. Nothing leaves your computer, and secrets are kept only as HMAC fingerprints.
- **Measured:** in Protect mode it blocks 13 of the 17 benchmark attacks and asks you about the other 4, with 0 false positives in 86 normal calls. See [Benchmark](#benchmark).

<p align="center"><img src="docs/demo.svg" width="860" alt="provguard blocks an agent that read .env and a poisoned GitHub issue from sending .env to an attacker, and blocks an attempt to turn provguard off, while normal work runs"></p>
<p align="center"><sub>Shortened output of <code>provguard demo</code>, which replays these calls through the real hook in a temp folder.</sub></p>

## Get started in one minute

**1. Install.** One line, then answer a few questions.

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

Which coding agents should provguard protect?
  all) Claude Code and every agent found below
  1) Claude Code (also Cursor and Devin)  (found)
  2) GitHub Copilot (VS Code, Copilot app, Copilot CLI)
  3) OpenAI Codex  (found)
  ...
  10) Antigravity (app, CLI and IDE)  (found)
Type all, or numbers separated by commas [all]: 1,3,10

✔ provguard is on. Mode: balanced (protect: stops leaks, asks before risky steps).
✔ Added ~/.provguard/bin to your user PATH. Open a new terminal to use the provguard command.
```

`provguard uninstall` takes it off your PATH again.

Downloading a binary from the [Releases page](https://github.com/durgavarapraveen/provguard/releases) by hand instead? The asset is named `provguard_<version>_<os>_<arch>`, so it is a file, not yet a `provguard` command. Run it once by its own name to install itself:

```powershell
.\provguard_<version>_windows_amd64.exe init --yes
```

`init --yes` asks nothing. It copies the binary to `~/.provguard/bin`, points the hooks there, and puts that folder on your PATH; `--no-path` skips the PATH change. **Then open a new terminal.** A terminal keeps the PATH it had when it started, and a terminal inside an editor keeps the editor's, so `provguard` stays "not recognized" in windows that were already open. `provguard doctor` tells you when that is what is happening.

From source instead (Go 1.26+): `go install github.com/durgavarapraveen/provguard/cmd/provguard@latest`, then `provguard init`.

Releases after v0.5.1 carry signed build provenance (Sigstore); v0.5.1 and older do not. To check that a binary was built from this repository by its release workflow, run `gh attestation verify <file> --repo durgavarapraveen/provguard`.

**2. Work as usual.** Nothing changes until something risky happens. Then your agent shows:

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
| See what provguard would do with a command | `provguard check "terraform destroy"` |
| Check that each agent's hook works | `provguard doctor --live` |
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

`provguard init --yes` (no questions) keeps the default, watch only, and puts provguard on your PATH (`--no-path` skips that).

## How it works

1. **Labels (PostToolUse).** Each tool result marks the session:
   - **untrusted:** web fetch/search, `curl`/`wget`/`gh issue view` and similar, third-party MCP servers, vendored dependencies, repos of untrusted owners, subagents that read untrusted content, and sessions started in an untrusted repo;
   - **sensitive:** `.env`, SSH keys, cloud credentials, environment dumps, tokens in output or in your prompt, and the files in your `sensitive_paths`. Secrets are kept only as HMAC fingerprints;
   - **hidden text:** any tool output that hides text from you (invisible Unicode tag characters, characters that reorder text, runs of zero-width characters, or an HTML comment or invisible element with instructions to an AI). The session becomes untrusted even if the file comes from a trusted repo, and rules 3 and 4 below block instead of ask.
2. **Sinks (PreToolUse).** Every Bash and PowerShell command is parsed (Bash with [mvdan.cc/sh](https://github.com/mvdan/sh), PowerShell with a tokenizer) through pipes, subshells, `$(…)`, heredocs, variables and wrappers such as `sudo`, `bash -c`, `python -c`. Each action gets a class: `EGRESS`, `PERSIST`, `DESTROY`, `EXEC_REMOTE` or `OPAQUE`. WebFetch, Write/Edit, MCP write tools and MCP terminal tools are covered too.
3. **Policy.** First match wins:

| # | Situation | Decision |
|---|---|---|
| 1 | The call contains a secret this session has seen (plain, base64, hex, URL-encoded, in a DNS name) | deny |
| 1c | Data goes to a host in `blocked_hosts` | deny |
| 2 | Data can leave while the session is both untrusted and sensitive (the "lethal trifecta") | deny |
| 2b | Your rules, the repo's rules, and the rule packs you turned on | ask or deny, as the rule says |
| 3 | Data goes to a host or URL taken from untrusted content | ask |
| 4 | Lasting change, remote code or unreadable code after untrusted input | ask |
| 5 | Reverse shell, or risky deletion: outside the project, history rewrites on shared branches, remote deletes, `terraform destroy`, cluster-wide `kubectl delete`, `helm uninstall`, cloud deletes (`aws … delete-*`, `gcloud … delete`), container volumes, `DROP TABLE` / `TRUNCATE` / `DELETE` without `WHERE`, `FLUSHALL`, writing a disk with `dd` | ask |
| 6 | Anything else | no decision (normal Claude Code permissions) |

4. **Overrides.** `provguard allow <token>` lets one exact call through once, within 10 minutes; the token is an HMAC with your install key, so an agent cannot make one for a call that was never blocked. `allow-host` exempts your own hosts from rules 1 and 2; a host taken from untrusted content is never offered in the message. `on-block ask` turns rules 1 and 2 into Claude Code's approval prompt in Protect mode.
5. **Self-protection** (every mode): agents cannot change hook or command settings in any `.claude/settings*.json`, write to `~/.provguard/`, read its key or session files, or run the commands that change provguard. Paths are checked as the OS resolves them, so junctions, symlinks and Windows path tricks do not get around it.

## Seeing a session's trust state

| State | Meaning |
|---|---|
| (no icon) | Clean |
| 🟡 untrusted | The agent read content you do not control: web pages, web searches, GitHub issues, `curl` output, repos or MCP servers you have not marked as trusted |
| 🟠 sensitive | The agent read secrets: `.env`, keys, tokens |
| 🔴 both | Both of the above: the riskiest state |
| ⚪ not tracked | No provguard hook has seen this session (`provguard status` only): it may have run without provguard |

| Where | How |
|---|---|
| Any terminal, every agent | `provguard status` shows the latest session's state, `provguard explain latest` shows why, and `provguard review` counts the states of recent sessions |
| Claude Code session list | The title gets the icon in front, e.g. `🔴 Fix login`, from your next prompt. The app owns its titles, so the icon changes only when you send a message in that session, and it is not added to a session that was renamed (by you, or by a tool). Turn off with `"session_title_icon": false`. |
| Claude Code CLI status line | Add `"statusLine": { "type": "command", "command": "provguard status" }` to `~/.claude/settings.json` yourself, with `~/.provguard/bin` on your `PATH` (agents may not edit `statusLine`) |
| A notice in the chat | provguard sends a one-time notice when a state changes, but not every agent shows it: see below |

**Which agents show the notice.** When provguard blocks or asks, every agent gets provguard's reason, and the call stops or waits for you. The one-time notice about a state change is different: an agent shows it only if its hooks can send a message to the user.

| Agent | Shows the notice | Title icon | Source |
|---|---|---|---|
| Claude Code CLI | Yes (`systemMessage`) | Yes | Claude Code hook docs |
| Claude desktop app, Code tab | Through the agent: the app did not show `systemMessage` in our live test, so provguard also gives the notice to the agent and asks it to tell you. Not yet tested live in the app. | Yes | Live test (notice); hook docs (agent context) |
| OpenAI Codex | Yes, as a warning | No | Codex hook docs |
| Gemini CLI | Yes | No | Gemini CLI hook docs |
| Factory Droid | Yes, as a hook warning | No | Droid hook docs |
| Cursor, Devin, GitHub Copilot, Kiro, OpenCode, Antigravity | No: their hooks have no message channel to the user | No | Each agent's hook docs; Antigravity also in a live test |

Where the notice is not shown, run `provguard explain latest` to see a session's state and the reason for it.

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
| Gemini CLI | Yes: `provguard init` adds provguard to `~/.gemini/settings.json` when it finds Gemini CLI. Gemini CLI hooks can only allow or deny, so provguard blocks where it would ask, and offers `provguard allow`. Not tested live yet. |
| Devin Desktop (formerly Windsurf) and Devin CLI | Yes, through Devin's support for Claude Code hooks (`read_config_from.claude`, on by default); provguard guards that switch. Devin hooks can only approve or block, so provguard blocks where it would ask. Not tested live yet. |
| Kiro (IDE and CLI V3) | Yes: `provguard init` adds `~/.kiro/hooks/provguard.json` when it finds Kiro. Kiro blocks a tool call only on a hook's non-zero exit, which provguard uses; it has no "ask", so provguard blocks there and offers `provguard allow`. Not tested live yet. |
| Factory Droid (CLI and IDE) | Yes: `provguard init` adds hooks to `~/.factory/hooks.json` when it finds Droid, keeping other hooks there. Droid's "ask" does not prompt, so provguard blocks there and offers `provguard allow`; self-protection covers `.factory` hooks and settings. Not tested live yet. |
| OpenCode | Yes: `provguard init` adds a small plugin, `~/.config/opencode/plugins/provguard.js`, when it finds OpenCode (V1 and V2 plugin APIs). The plugin blocks a tool call by throwing an error with provguard's reason; it has no "ask", so provguard blocks there and offers `provguard allow`. Self-protection covers OpenCode plugin folders and `opencode.json`. A repository's own `opencode.json` can still list `"-provguard"` to turn the plugin off. Not tested live yet. |
| Antigravity (app, CLI and IDE) | Yes: `provguard init` adds a `provguard` entry to `~/.gemini/config/hooks.json` when it finds Antigravity, keeping other entries. provguard's "ask" uses `force_ask`, so a cached "Always Allow" cannot skip it. Antigravity's PostToolUse does not include tool output, so provguard labels by the tool and its arguments only (no secret scan of output). Self-protection covers `~/.gemini/config/hooks.json` and `.agents/hooks.json`. Hooks may not run with `--dangerously-skip-permissions` (reported by a third-party guide, not confirmed). Not tested live yet. |

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
| `provguard reset [session|latest] [--source N] --yes` | Clear a session's untrusted label after you checked it. Without `--yes` it lists the untrusted sources, numbered; `--source N` clears only that one, and the label goes with the last source. |\|latest] --yes` | Clear a session's untrusted label after you checked it |
| `provguard check [--untrusted] [--secrets] "<command>"` | What provguard would do with a shell command, and why, without running it. Exit code 0 when allowed, 1 when it would ask or block. `--json` for scripts. |
| `provguard doctor --live` | Send a test write to a protected file through each installed agent's hook and check that provguard blocks it in that agent's reply format |
| `provguard doctor [dir] [--json]` | Check hook integrity; scan a repo for settings that turn hooks off, repo hooks, `.mcp.json` servers and risky instruction files. Exits 1 on HIGH. |
| `provguard demo` | One normal task and two attacks, narrated, in a temp folder |
| `provguard uninstall [--yes] [--now] [--keep-data]` | Turn protection off and remove provguard, `~/.provguard` included. Sessions whose title shows a trust icon get their old title back on your next message in them; then the last hook removes itself (at the latest after 30 days). Both forms list the sessions whose title still shows an icon. `--now` removes everything at once, and those titles keep their icon until you rename them yourself; run it without `--yes` first to see the list. `--keep-data` keeps logs and settings. |
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

### Your own rules

Add rules, rule packs, sensitive files and blocked hosts in `config.json`:

```json
{
  "rules": [
    {"name": "prod-apply", "command": "kubectl apply", "match": "--context[ =]prod", "action": "deny", "reason": "production changes go through CI"},
    {"name": "deploy", "command": "make deploy", "action": "ask"},
    {"name": "merge", "tool": "mcp__github__merge_*", "action": "ask"}
  ],
  "packs": ["terraform", "kubernetes", "aws", "gcloud", "azure"],
  "sensitive_paths": ["*.tfvars", "secrets/*"],
  "blocked_hosts": ["pastebin.com"]
}
```

- **`command`:** the words a shell command contains, in this order, starting with its name. Flags and other words can come between them, and `*` matches one word (`aws create-*`).
- **`match`:** a regular expression on the whole command line.
- **`tool`:** a pattern on the tool name, for tools that are not shell commands, such as MCP tools.
- **Combining parts:** a rule matches when every part it sets matches.
- **`action`:** `ask` or `deny`. The mode still applies: Watch only logs, and Lockdown blocks asks.
- **Packs** ask before changes to shared infrastructure: `terraform apply`/`import`/`state`, `kubectl apply`/`create`/`patch`/`delete`, `helm install`/`upgrade`, and cloud `create`/`update`/`deploy`/IAM commands.
- **Order:** these rules come after the built-in blocks, so they can add checks but never hide a leak.

Try a rule with `provguard check "<command>"`.

### Team policy in a repo

Commit `.provguard/policy.json` to a repository to give everyone who works in it the same extra checks:

```json
{
  "mode": "balanced",
  "rules": [{"name": "deploy", "command": "make deploy", "action": "ask"}],
  "packs": ["terraform"],
  "sensitive_paths": ["*.tfvars"],
  "blocked_hosts": ["paste.example.com"]
}
```

- **It can only make provguard stricter.** `mode` raises the mode, never lowers it. The lists are added to yours. Keys that would weaken a check (`allowed_hosts`, trusted owners or sites) are not read, because a cloned repository is untrusted.
- **Where it applies:** commands run in the repository or its subfolders.
- **Agents cannot change or remove it:** self-protection covers every `.provguard` folder.
- **`provguard doctor`** reports a repo's policy when it scans the repo.

### Advanced keys

Edit the file by hand: `self_protect` (default `true`), `trust_sdk_mcp_servers` (default `true`), `session_title_icon` (default `true`), `audit_retention_days` (default 30; negative keeps logs forever).

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
- Instruction files that the agent loads by itself are invisible to hooks. At session start provguard checks the ones in the repo root and working folder for hidden text and strong signs of an attack; files that load later, and subtler injections, are not caught. `trusted_repo_owners` and `doctor` add to this.
- A cloned repo can turn all hooks off through its settings file before any hook runs ([finding F3](docs/FINDINGS.md)). provguard warns when an agent clones such a repo; run `provguard doctor` on a repo you cloned yourself, or use managed settings in teams.
- In Cursor, provguard runs only while *Third-Party Imports* is on. Cursor keeps that switch in its own settings, which provguard does not guard.
- The install scripts check the binary against the release's own `SHA256SUMS`, which catches a broken download, not a compromised release. For releases after v0.5.1 they also check the signed build provenance (`gh attestation verify`) when the GitHub CLI is installed and signed in, and refuse to install a binary that fails it. Without `gh` they say the check was skipped.

## Docs

- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md): what provguard protects against, and what it does not
- [docs/BENCHMARK.md](docs/BENCHMARK.md): attacks, false positives, method
- [docs/FINDINGS.md](docs/FINDINGS.md): facts about agent hooks found while building this
- [SECURITY.md](SECURITY.md): how to report a vulnerability

## License

Apache-2.0
