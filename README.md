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
mcp-warden scan                       # audit every config + npm/PyPI metadata (starts nothing)
mcp-warden scan --probe               # also start/connect to servers and inspect their tools
mcp-warden scan --offline             # no network at all
mcp-warden pin --probe                # record a trusted baseline (~/.mcp-warden/lock.json)
mcp-warden diff                       # what changed since the baseline? (exit 1 on changes)
mcp-warden watch                      # re-check every hour, notify on new changes
```

The default report is compact: a rule that fires on three or more servers is
listed once under *common issues*, servers without other problems collapse
into one line, and the worst problems come first. `--verbose` (`-v`) prints
every finding with its evidence and fix.

Useful flags: `--project DIR`, `--project-only` (skip user configs),
`--config FILE` (repeatable), `--format text|json|sarif`, `--fail-on high`,
`--show info`, `--policy FILE`, `--timeout 30s`, `--lock FILE`.

> `--probe` launches each enabled server's command exactly as your MCP client
> would (including `npx`/`uvx` downloads). Without it, `scan`, `list` and
> `pin` never execute anything; `scan` only makes read-only metadata requests
> to npm and PyPI, which `--offline` (or `MCP_WARDEN_OFFLINE=1`) turns off.

### Registry checks (on by default)

Looks up the npm or PyPI metadata of every package a server is launched from
(read-only HTTP requests; nothing is downloaded or executed) and flags:

- packages npm removed as malware (`0.0.1-security` placeholders), and packages
  or versions that do not exist (typos, dependency confusion, deleted packages)
- **provenance dropped**: a release without provenance after CI-published
  releases that had it, which is the trace of a stolen publish token
- **new publisher**: a release by an account that never published the package
  before (skipped for npm trusted publishing, where the publisher is CI)
- releases younger than the cooldown (`--cooldown 7` days) and packages
  younger than 30 days
- `preinstall`/`install`/`postinstall` scripts, yanked and deprecated versions,
  missing source repository links and very low weekly downloads

Unpinned packages are evaluated at the version they currently resolve to. If
a registry cannot be reached, its checks are skipped after the first failure
with a single warning, so offline machines are not slowed down. Use
`--npm-registry https://registry.npmmirror.com` (or `MCP_WARDEN_NPM_REGISTRY`)
for a mirror and `--pypi-url` for a PyPI-compatible index with the JSON API.

### Continuous monitoring (`watch`)

```sh
mcp-warden watch --install                                # check hourly in the background
mcp-warden watch --install --probe --webhook "$HOOK_URL"  # also watch tool definitions, alert in chat
mcp-warden watch --uninstall
```

`--install` registers a per-user job with the system scheduler (launchd on
macOS, a systemd user timer on Linux, Task Scheduler on Windows) that runs
`mcp-warden watch --once` with your flags every `--interval` (default 1h).
Relative paths are made absolute and your current `PATH` is kept so `npx`
and `uvx` are found. The webhook URL is not written into the job definition;
it is stored in `~/.mcp-warden/webhook` with 0600 permissions. Output goes to
`~/.mcp-warden/watch.log`.

The first run trusts the current state as the baseline, so there is nothing
to set up beforehand; after that, only changes that were not reported before
trigger an alert, and a failed delivery is retried on the next check. To
accept a change, run `mcp-warden pin` (with `--probe` if you watch tools).

Alerts go to the desktop (`osascript`, `notify-send` or PowerShell) and/or a
webhook. The webhook format is detected from the URL: Slack, Discord,
Feishu/Lark, DingTalk, WeCom, otherwise generic JSON (`--webhook-format`
overrides it). Without `--install`, `watch` runs in the foreground, and
`--once` runs a single check for your own scheduler (exit 1 while changes
remain open).

### Team policy (`mcp-warden.policy.json`)

Commit a policy to the repository to decide which MCP servers your team may
run. It is picked up automatically from the project root (then
`~/.mcp-warden/policy.json`); `--policy FILE` and `--no-policy` override that.

```sh
mcp-warden policy init --project-only   # allow exactly what is configured today
```

```jsonc
{
  "version": 1,
  "allow": {                                   // if any list is set, everything else is POLICY-NOT-ALLOWED (high)
    "npm":     ["@modelcontextprotocol/*@*", "@your-org/*"],   // name or name@version, * and ? globs
    "pypi":    ["mcp-server-fetch==*"],
    "docker":  ["ghcr.io/github/github-mcp-server@sha256:*"],
    "remote":  ["https://mcp.your-org.com/*"],
    "command": ["/opt/your-org/bin/*"]
  },
  "deny":   { "npm": ["*desktop-commander*"] },                 // POLICY-DENIED (critical)
  "ignore": [                                                   // reason is required; expires is optional
    { "rule": "CAP-EXEC", "server": "sandbox-shell", "reason": "runs in a throwaway VM", "expires": "2027-01-31" }
  ],
  "severity": { "UNPINNED-PACKAGE": "high" }                    // tighten (or relax) any rule
}
```

Allow/deny lists are enforced by `scan`; ignores and severity overrides apply to
`scan`, `diff` and `watch`. Unknown keys, unknown rule IDs and ignores without
a reason are errors, so a typo cannot silently weaken the policy, and expired
ignores stop applying. `mcp-warden rules` lists every rule ID.

### CI gate and GitHub code scanning

```yaml
name: mcp-warden
on: [push, pull_request]
permissions:
  contents: read
  security-events: write   # upload SARIF
jobs:
  mcp:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: stable }
      - run: go install github.com/ELOATS/mcp-warden/cmd/mcp-warden@latest
      - run: mcp-warden scan --project-only --format sarif > mcp-warden.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: mcp-warden.sarif, category: mcp-warden }
      - run: mcp-warden scan --project-only --fail-on high   # fail the build
```

Findings show up under **Security → Code scanning** and as annotations on the
exact line of `.mcp.json`, `.cursor/mcp.json` or `.vscode/mcp.json` in pull
requests.

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
| `POLICY-DENIED`, `POLICY-NOT-ALLOWED` | critical/high | server violates the team policy |
| `REGISTRY-MALWARE-REMOVED` | critical | (registry) npm removed the package as malware |
| `REGISTRY-NOT-FOUND`, `REGISTRY-UNPUBLISHED`, `VERSION-NOT-FOUND`, `PROVENANCE-DROPPED` | high | (registry) missing packages, stolen-token pattern |
| `NEW-PUBLISHER`, `INSTALL-SCRIPTS`, `VERSION-TOO-NEW`, `PACKAGE-TOO-NEW`, `YANKED-VERSION` | medium | (registry) takeover and fresh-release risk |
| `DEPRECATED-VERSION`, `NO-SOURCE-REPO`, `LOW-DOWNLOADS` | low | (registry) maintenance and adoption signals |
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
internal/registry     npm / PyPI metadata checks
internal/policy       team policy: allow/deny lists, ignores, severity overrides
internal/notify       desktop and webhook notifications for watch
internal/report       text / JSON / SARIF output
internal/testserver   scripted MCP server used by the tests
```

## Roadmap

- prompts & resources inspection, OAuth-aware remote probing
- central policy distribution and signed policies for organisations
- on-disk cache for registry metadata; Docker image registry checks

## License

Apache License 2.0. See [LICENSE](LICENSE).
