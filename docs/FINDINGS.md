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

## Open — live tests still to run
- [x] F3: project `disableAllHooks: true` against user-level provguard hooks.
- [x] F5: canary phrase in `additionalContext` reaches the model.
- [x] Record real payloads for Bash, PowerShell, Read, Write, Edit, WebFetch, one MCP tool (F7).
- [ ] F3 follow-up: does the workspace trust dialog show `disableAllHooks` or repo hooks when a repo is first opened?
- [ ] Headless `claude -p` runs (blocked: CLI login expired on this machine).
- [x] Hook latency p50/p95 over 100 calls (M1). Repeat inside a real Claude Code session.
