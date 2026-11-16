# Threat model

## What provguard is

A deterministic check that runs **outside the model**, on every tool call of a coding agent, through the agent's hook API. A prompt injection can change what the model *wants* to do. It cannot change what the hook *decides*.

## Assets

1. **Secrets** the agent can reach: `.env` files, SSH keys, cloud credentials, tokens in environment variables and tool output.
2. **The user's machine and repos:** shell startup files, git hooks, CI workflows, agent settings, branches and history.
3. **provguard itself:** its hooks, binary, config, keys and logs.

## Attacker

Someone who controls content that the agent reads, but not the user, the agent binary or the operating system:

- issue and PR text and comments, including hidden HTML comments;
- web pages fetched by the agent;
- files in third-party repos and dependencies (READMEs, docs, `CLAUDE.md`, `AGENTS.md`);
- output of third-party MCP servers;
- repo-level agent config (`.claude/settings.json`, `.mcp.json`).

## Attacker goals and coverage

| Goal | Example | provguard response |
|---|---|---|
| Exfiltrate secrets | `curl -d @.env`, `python -c` sockets, base64 or hex in URLs, DNS names | Deny when a seen secret appears in the call, or when an untrusted *and* sensitive session sends data out |
| Send data to an attacker host | `curl https://injected-host/…` | Ask when the host came from untrusted content |
| Persistence | `~/.bashrc`, `.git/hooks/`, `.github/workflows/`, `crontab`, `git remote add` | Ask after untrusted input |
| Remote code | `curl … \| sh`, named package installs, `npx` | Ask after untrusted input |
| Remote control | reverse shells over `/dev/tcp` | Always ask |
| Destruction | `rm -rf` outside the project, force-push to `main`, `gh repo delete` | Ask |
| Turn provguard off | edit hook settings, `disableAllHooks`, replace the binary, run `uninstall` | Deny in every profile |

## Out of scope

- **A malicious user**, or an attacker with code execution outside the agent. provguard runs with the user's rights.
- **A compromised agent binary or OS.**
- **Harmful code the agent writes that a human later merges.** provguard checks actions, not code quality.
- **Attacks that need no tool call**, for example the model lying to the user in chat.
- **Kernel-level isolation.** Use a sandbox or container as well; provguard complements it.

## Known weaknesses

1. **Repo settings can turn hooks off before any hook runs.** A cloned repo with `"disableAllHooks": true` in `.claude/settings.json` disables user-level hooks, provguard included ([F3](FINDINGS.md)). Mitigation: run `provguard doctor` before opening a repo, and use managed settings (`allowManagedHooksOnly`) in teams.
2. **Auto-loaded instruction files are invisible to hooks.** `CLAUDE.md` and `AGENTS.md` enter the context without a tool call. provguard marks the session untrusted when it starts in a repo whose owner is not in `trusted_repo_owners`. Without that setting, it cannot tell your repos from others'.
3. **Static analysis has limits.** Values known only at run time cannot be resolved, and the PowerShell analysis is a heuristic. Unreadable code (`eval`, encoded commands, `python -c` writes) is treated as OPAQUE and asks after untrusted input.
4. **Fail open by default.** In `audit` and `balanced`, a crashed or timed-out hook lets the call run. Only `strict` fails closed.
5. **Taint is coarse.** Once a session is untrusted it stays untrusted, so long sessions can ask more often. `provguard reset` clears it after the user checks.
6. **Secret matching is exact.** A secret split across commands, or transformed in ways other than base64, hex or URL encoding, is not matched.
7. **Coverage depends on the agent's hook API.** Claude Code is supported. Desktop Chat with MCP servers is not (no hooks).

## Trust anchors

- provguard's hooks are installed at user scope, and the binary lives in `~/.provguard/bin/`. Both are protected from agent writes.
- Configuration is written by the user only.
- Decisions are deterministic and logged with their reason in `~/.provguard/audit/`.
