# Contributing to provguard

Thank you for helping. provguard is a security tool, so every change has two goals: stop more attacks, and do not get in the way of normal work.

## Report a problem

- **A way around provguard (a bypass)** is a security bug. Report it privately: **Security** tab → **Report a vulnerability**. See [SECURITY.md](SECURITY.md). Do not open a public issue.
- **A false alarm** (provguard blocked or asked about normal work): open a *False positive* issue with the output of `provguard check "<command>"` or `provguard explain latest`.
- **Other bugs and ideas:** open an issue with the template that fits.

## Set up

You need Go 1.26 or later. provguard has one dependency, the shell parser `mvdan.cc/sh`, so there is nothing else to install.

```bash
git clone https://github.com/durgavarapraveen/provguard
cd provguard
go build ./cmd/provguard
go test ./...
```

Before you open a pull request, run the same checks as CI:

```bash
go vet ./...
go test ./...
go run ./cmd/provguard bench --check
```

`bench --check` replays 17 attacks and 31 normal tasks through the real hook. It fails when an attack gets through or a normal task gets a false alarm.

To test a full install in a throwaway home folder (your own setup is not touched):

```bash
scripts/release.sh 0.0.0-dev
PROVGUARD_DIST=dist sh scripts/e2e.sh 0.0.0-dev          # Linux, macOS
```

```powershell
$env:PROVGUARD_DIST = 'dist'; powershell -File scripts\e2e.ps1 -Version 0.0.0-dev   # Windows
```

## How the code is organized

| Folder | What it does |
|---|---|
| `cmd/provguard` | The command line: `hook`, `init`, `check`, `doctor`, `review` and the rest |
| `internal/adapter` | One package per coding agent. Each implements `core.Adapter`: recognize the agent's payload, convert it to an `event.Event`, write the agent's reply format, and build a `Probe` for `doctor --live` |
| `internal/label` | Marks a session untrusted or sensitive from tool results, and finds hidden text |
| `internal/shell` | Parses Bash and PowerShell commands into sinks: `EGRESS`, `PERSIST`, `DESTROY`, `EXEC_REMOTE`, `OPAQUE` |
| `internal/policy` | Decides allow, ask or deny; user rules and rule packs |
| `internal/protect` | Self-protection: agents cannot turn provguard off |
| `internal/config` | The config file and repository policies |
| `bench` | The attack and normal-work benchmark |

### Add support for a coding agent

1. Add a package under `internal/adapter/<agent>` that implements `core.Adapter`, with a link to the agent's hook documentation in the package comment.
2. Register it in `internal/adapter/adapter.go`, and, if it has its own hook file, add it to `otherAgents` in `cmd/provguard/agents.go`.
3. Protect the agent's hook files in `internal/protect/protect.go`.
4. Add tests: the adapter's own tests, and an end-to-end test in `cmd/provguard/<agent>_test.go`. `TestProbesRoundTrip` and `TestDoctorLiveBlocksInEveryAgent` cover the new adapter automatically.
5. Add a row to "Where it works" in the README and an entry to the CHANGELOG.

## Pull requests

- Keep each pull request to one change, with tests.
- A new block or ask needs a case that shows it, and must keep `bench --check` passing. A rule that adds false alarms will not be merged, however good the attack it stops.
- Do not add dependencies without asking in an issue first.
- Write comments that explain why the code works as it does, not its history.
- User-facing text uses short, plain sentences.

## Releases

Maintainers release by pushing a tag `vX.Y.Z` after the CHANGELOG has a section for it. The release workflow builds the binaries, signs their build provenance, and publishes the GitHub release.

After the release is published, update the package managers:

1. Download the release's `SHA256SUMS`.
2. Run `scripts/packaging.sh X.Y.Z path/to/SHA256SUMS`. It writes `bucket/provguard.json` (Scoop), `packaging/homebrew/provguard.rb` and `packaging/winget/X.Y.Z/`.
3. Commit the files to `main`. Scoop users get the update from the `bucket` folder.
4. Copy `packaging/homebrew/provguard.rb` to `Formula/provguard.rb` in the tap repository `durgavarapraveen/homebrew-provguard`.
5. Send `packaging/winget/X.Y.Z/` to [microsoft/winget-pkgs](https://github.com/microsoft/winget-pkgs) as `manifests/d/DurgavaraPraveen/Provguard/X.Y.Z/` (for example with `wingetcreate submit`).

## Code of conduct

Everyone who takes part follows the [code of conduct](CODE_OF_CONDUCT.md).
