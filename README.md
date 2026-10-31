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

```sh
go install github.com/ELOATS/mcp-warden/cmd/mcp-warden@latest
# or from a checkout
cd mcp-warden && go build ./cmd/mcp-warden
```

## Usage

```sh
mcp-warden list                       # what is configured, where
mcp-warden scan                       # static audit of every config (runs nothing)
mcp-warden scan --probe               # also start/connect to servers and inspect their tools
mcp-warden pin --probe                # record a trusted baseline (~/.mcp-warden/lock.json)
mcp-warden diff                       # what changed since the baseline? (exit 1 on changes)
```

Useful flags: `--project DIR`, `--project-only` (skip user configs),
`--config FILE` (repeatable), `--json`, `--fail-on high`, `--show info`,
`--timeout 30s`, `--lock FILE`.

> `--probe` launches each enabled server's command exactly as your MCP client
> would (including `npx`/`uvx` downloads). Static `scan`, `list` and a
> config-only `pin` never execute anything.

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

- `watch` mode / scheduled diff with desktop or Slack notification
- prompts & resources inspection, OAuth-aware remote probing
- signed allowlist policy for teams (`mcp-warden.policy.json`), SARIF output
- live package metadata (publish age, maintainer changes, download counts)
