# Changelog

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

### Known limitations
- See docs/THREAT_MODEL.md. Real-agent benchmark runs, `ConfigChange` and `onFailure: block` are not yet verified live.
