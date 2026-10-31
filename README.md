# mcp-warden

**Find risky MCP servers before they find you.** A single, dependency-free Go
binary that audits the MCP servers configured in Claude Desktop, Claude Code,
Cursor, VS Code, Cline, Windsurf and Gemini CLI, and alerts you when a server
changes after you approved it.

[中文说明](README.zh-CN.md)

## Why

MCP servers run with your permissions and their tool descriptions are read by
the model as instructions. In 2026 the ecosystem has tens of thousands of
servers, registries that verify *existence* but not *trustworthiness*,
typosquatted packages, and clients that never re-validate a server after the
first approval. `mcp-warden` gives individual developers a fast, local, open
check, and gives teams a CI gate.

## Install

Download a prebuilt binary for Linux, macOS or Windows (amd64/arm64) from
[Releases](https://github.com/ELOATS/mcp-warden/releases) and verify it against
`checksums.txt`, or build it with Go 1.22+:

```sh
go install github.com/ELOATS/mcp-warden/cmd/mcp-warden@latest
# or from a checkout
go build ./cmd/mcp-warden
```

Maintainers: pushing a tag such as `v0.1.0` runs the tests and publishes a
release via GoReleaser (`.goreleaser.yaml`, `.github/workflows/release.yml`).

## Usage

```sh
mcp-warden list                       # what is configured, where
mcp-warden scan                       # static audit of every config (runs nothing)
mcp-warden scan --probe               # also start/connect to servers and inspect their tools
mcp-warden pin --probe                # record a trusted baseline (~/.mcp-warden/lock.json)
mcp-warden diff                       # what changed since the baseline? (exit 1 on changes)
mcp-warden watch                      # re-check every hour, notify on new changes
```

Useful flags: `--project DIR`, `--project-only` (skip user configs),
`--config FILE` (repeatable), `--json`, `--fail-on high`, `--show info`,
`--timeout 30s`, `--lock FILE`.

> `--probe` launches each enabled server's command exactly as your MCP client
> would (including `npx`/`uvx` downloads). Static `scan`, `list` and a
> config-only `pin` never execute anything.

### Continuous monitoring (`watch`)

`watch` re-runs `diff` against your baseline and alerts only on changes it has
not reported before. A failed delivery is retried on the next check.

```sh
mcp-warden pin --probe                                # 1. accept the current state
mcp-warden watch --interval 30m                       # 2. desktop notifications
mcp-warden watch --webhook "$MCP_WARDEN_WEBHOOK"      #    …and/or chat
```

Webhook format is detected from the URL: Slack, Discord, Feishu/Lark,
DingTalk, WeCom, otherwise generic JSON (`--webhook-format` overrides it).
Keep the URL in `MCP_WARDEN_WEBHOOK` rather than in shell history.
Desktop notifications use `osascript` (macOS), `notify-send` (Linux) or
PowerShell (Windows). After you review a change, run `pin` again to accept it.

For a scheduler, use `--once`. It runs one check, alerts, and exits 1 if open
changes remain:

```sh
# cron (Linux/macOS): hourly
17 * * * * /usr/local/bin/mcp-warden watch --once >> ~/.mcp-warden/watch.log 2>&1

# systemd user timer: ~/.config/systemd/user/mcp-warden.service
#   [Service]
#   Type=oneshot
#   ExecStart=%h/go/bin/mcp-warden watch --once
# ~/.config/systemd/user/mcp-warden.timer
#   [Timer]
#   OnCalendar=hourly
#   Persistent=true
#   [Install]
#   WantedBy=timers.target
systemctl --user enable --now mcp-warden.timer
```

On macOS, a launchd agent with `StartInterval` 3600 running
`mcp-warden watch --once` does the same job.

### CI gate (GitHub Actions)

```yaml
- uses: actions/setup-go@v5
  with: { go-version: "1.22" }
- run: go install github.com/ELOATS/mcp-warden/cmd/mcp-warden@latest
- run: mcp-warden scan --project-only --fail-on high
```

## What it checks

| Rule | Severity | What it catches |
|------|----------|-----------------|
| `SHELL-PIPE-EXEC` | critical | `curl … \| sh` style launchers |
| `TOOL-POISONING` | critical/high/medium | tool descriptions or schemas that override instructions, hide actions from the user, use `<IMPORTANT>`-style tags, or reference `~/.ssh`, `.aws/credentials`, MCP configs … |
| `HIDDEN-UNICODE` | high | zero-width, bidi and Unicode tag characters in tool definitions |
| `TOOL-DEFINITION-CHANGED` | high | (diff) a tool's description/schema changed after pinning: the rug-pull pattern |
| `CONFIG-CHANGED` | high | (diff) command/args/env/url/headers changed since pinning |
| `PLAINTEXT-SECRET` | high/medium | literal tokens (GitHub, Anthropic, OpenAI, Slack, AWS, Stripe …) in env, args or headers |
| `POSSIBLE-TYPOSQUAT` | high | package/image one or two edits away from a popular MCP server |
| `BROAD-FS-ACCESS`, `HOST-ROOT-MOUNT` | high | `/`, `~` or home passed to a server or mounted into a container |
| `DOCKER-PRIVILEGED`, `DOCKER-SOCKET`, `DOCKER-CAPABILITY` | high | container escapes to the host |
| `INSECURE-TRANSPORT`, `SECRET-IN-URL`, `CREDENTIAL-IN-URL` | high | plain-http remotes, keys in URLs |
| `UNPINNED-PACKAGE`, `UNPINNED-IMAGE` | medium | `npx -y pkg`, `uvx pkg`, `image:latest`: every launch can pull a new release |
| `CAP-EXEC` | medium | server exposes command/code execution tools |
| `LETHAL-TRIFECTA` | medium | one client mixes web-fetching tools with local-data/exec tools |
| `TOOL-NAME-COLLISION`, `CROSS-TOOL-REFERENCE` | medium | tool shadowing across servers |
| `NEW-SERVER`, `TOOL-ADDED` | medium | (diff) things added after pinning |
| `SHELL-WRAPPER`, `CREDENTIAL-IN-ARGS`, `HOST-PID` | medium | opaque launchers, DB passwords in args |
| `LEGACY-SSE`, `HOST-NETWORK`, `PROBE-FAILED`, … | low/info | hygiene |

The lockfile never stores secrets: env values and headers are hashed, args
and URLs are redacted.

## Exit codes

`0` ok · `1` findings at or above `--fail-on` (default: `none` for scan,
`medium` for diff) · `2` usage or runtime error.

## Layout

```
cmd/mcp-warden        CLI
internal/config       config discovery for each client (JSONC-tolerant)
internal/audit        static rules, tool-definition rules, cross-server rules
internal/probe        MCP client: stdio + Streamable HTTP, initialize + tools/list
internal/lockfile     fingerprints, baseline, diff
internal/report       text / JSON output
internal/testserver   scripted MCP server used by the tests
```

## Roadmap

- prompts & resources inspection, OAuth-aware remote probing
- signed allowlist policy for teams (`mcp-warden.policy.json`), SARIF output
- live package metadata (publish age, maintainer changes, download counts)

## License

Apache License 2.0. See [LICENSE](LICENSE).
