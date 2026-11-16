# Changelog

## Unreleased

### Added
- `provguard allow <token>`: the user lets one blocked call through once (same session, tool and text; 10 minutes). Tokens are HMACs with the install key; agents cannot run the command.
- `allowed_hosts` now also exempts data sent to those hosts from the egress rules.
- `"block_mode": "ask"` turns `balanced` denies into an approval prompt.
- Session title icon and `provguard status` for the trust state; `provguard-badge` desktop mod (status entry and toasts).

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
