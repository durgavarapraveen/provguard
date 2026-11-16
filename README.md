# provguard

A runtime firewall for AI coding agents. It tracks where context comes from and blocks dangerous tool calls that untrusted content drives.

> **Status: week 1, log-only.** provguard records every tool call. It does not block anything yet.

See [DESIGN.md](DESIGN.md) for the threat model, design and MVP plan.

## Build

Requires Go 1.22 or later.

```bash
go build -o bin/provguard ./cmd/provguard
```

## Install the hooks (Claude Code)

`init` shows the change first. It writes only with `--yes`, and it backs up your settings file.

```bash
bin/provguard init
```

```bash
bin/provguard init --yes
```

Remove the hooks:

```bash
bin/provguard uninstall --yes
```

## Audit log

provguard writes one JSON line per hook call to `~/.provguard/audit/YYYY-MM-DD.jsonl`. It redacts secrets before it writes. Set `PROVGUARD_HOME` to change the location.

## Safety rules for this tool

- **Fail open.** If provguard has an error, the agent continues with its normal permission flow. In log-only mode provguard never returns a decision.
- **No raw secrets on disk.** Tool inputs are redacted. Tool outputs are stored as size and SHA-256 only.

## License

Apache-2.0.
