# Security policy

provguard is a security tool, so bypasses of it are security bugs.

## Report a vulnerability

Please use GitHub's private vulnerability reporting: open the **Security** tab of this repository and choose **Report a vulnerability**. Do not open a public issue for a bypass.

Useful details:

- the agent and version (for example Claude Code 2.1.x), the OS and the provguard version (`provguard version`);
- the tool call or command that gets through, and the profile (`audit`, `balanced` or `strict`);
- whether it needs a special repo, page or MCP server.

You will get an answer within 7 days. Confirmed bypasses get a fix, a regression case in `bench/attacks/`, and credit in the release notes if you want it.

## In scope

- Agent actions that should be denied or asked under [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) but are allowed.
- Ways for an agent to turn provguard off, change its config, or replace its binary.
- Raw secrets written to provguard's logs or session files.

## Out of scope

The "out of scope" and "known weaknesses" items in the threat model, unless you find a way around a documented mitigation.
