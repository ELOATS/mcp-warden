package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"regexp"
	"runtime/debug"
	"sort"
	"strings"
)

type flagDoc struct{ arg, text string }

// flagDocs documents every flag once; commands pick the ones that apply.
var flagDocs = map[string]flagDoc{
	"project":        {"DIR", `project directory with .mcp.json, .cursor/, .vscode/ (default ".")`},
	"project-only":   {"", "skip user-level configs (use this in CI)"},
	"config":         {"FILE", "extra config file to read (repeatable)"},
	"probe":          {"", "start/connect to each enabled server and inspect its tools"},
	"timeout":        {"DUR", "per-server probe timeout (default 20s)"},
	"registry":       {"", "check npm/PyPI metadata (on by default; see --offline)"},
	"offline":        {"", "skip npm/PyPI metadata lookups (env MCP_WARDEN_OFFLINE=1)"},
	"cooldown":       {"DAYS", "flag versions younger than this (default 7)"},
	"npm-registry":   {"URL", "npm registry or mirror, e.g. https://registry.npmmirror.com (env MCP_WARDEN_NPM_REGISTRY)"},
	"pypi-url":       {"URL", "PyPI-compatible index with the JSON API (env MCP_WARDEN_PYPI_URL)"},
	"policy":         {"FILE", "team policy (default ./mcp-warden.policy.json, then ~/.mcp-warden/policy.json)"},
	"no-policy":      {"", "ignore any policy file"},
	"format":         {"FMT", "output format: text, json or sarif"},
	"json":           {"", "shorthand for --format json"},
	"fail-on":        {"SEV", "exit 1 if a finding is at or above SEV (info|low|medium|high|critical|none)"},
	"show":           {"SEV", "lowest severity printed in text output (default low)"},
	"verbose":        {"", "show evidence and fixes for every finding, without grouping (also -v)"},
	"no-color":       {"", "disable colours (also honours NO_COLOR)"},
	"lock":           {"FILE", "baseline lockfile (default ~/.mcp-warden/lock.json, or ./mcp-warden.lock.json with --project-only)"},
	"interval":       {"DUR", "time between checks (default 1h, minimum 1m)"},
	"once":           {"", "run one check and exit (for cron, launchd, systemd)"},
	"notify":         {"MODE", "desktop (default) or none"},
	"webhook":        {"URL", "also post alerts here (env MCP_WARDEN_WEBHOOK)"},
	"webhook-format": {"F", "auto|slack|discord|feishu|dingtalk|wecom|json (default auto)"},
	"state":          {"FILE", "where already-alerted changes are remembered"},
	"install":        {"", "install a per-user scheduled job (launchd, systemd timer or Task Scheduler) running these flags every --interval"},
	"uninstall":      {"", "remove the scheduled job"},
	"apply":          {"", "write the changes (default: preview only); each file is backed up next to it"},
	"secrets":        {"", "also move literal env secrets into ~/.mcp-warden/secrets.env (Claude Code, Gemini CLI)"},
	"server":         {"NAME", "only fix these servers (glob, repeatable)"},
	"output":         {"FILE", "where to write the policy (default ./mcp-warden.policy.json)"},
	"force":          {"", "overwrite an existing policy file"},
}

type command struct {
	name, args, summary string
	flags               []string
	examples            []string
}

var commands = []command{
	{name: "scan", summary: "audit MCP server configs and their npm/PyPI packages; --probe inspects live tools",
		flags: []string{"project", "project-only", "config", "probe", "timeout", "offline", "cooldown", "npm-registry", "pypi-url",
			"policy", "no-policy", "format", "json", "fail-on", "show", "verbose", "no-color"},
		examples: []string{
			"mcp-warden scan                                  # configs + npm/PyPI metadata; starts nothing",
			"mcp-warden scan --probe                          # also inspect live tool definitions",
			"mcp-warden scan --offline                        # no network at all",
			"mcp-warden scan --project-only --fail-on high    # CI gate",
			"mcp-warden scan --format sarif > mcp.sarif       # GitHub code scanning"}},
	{name: "fix", summary: "pin unpinned npx/uvx packages to a vetted release (and, with --secrets, move secrets out); previews unless --apply",
		flags: []string{"apply", "secrets", "server", "project", "project-only", "config", "cooldown", "offline", "npm-registry", "pypi-url"},
		examples: []string{
			"mcp-warden fix                      # show what would change",
			"mcp-warden fix --apply              # write it (each file is backed up first)",
			"mcp-warden fix --secrets --apply    # also move literal secrets to ~/.mcp-warden/secrets.env"}},
	{name: "list", summary: "list the MCP servers configured for this user and project",
		flags: []string{"project", "project-only", "config", "json"}},
	{name: "pin", summary: "record a trusted baseline of configs (and, with --probe, tool definitions)",
		flags:    []string{"project", "project-only", "config", "probe", "timeout", "lock", "json"},
		examples: []string{"mcp-warden pin --probe"}},
	{name: "diff", summary: "report everything that changed since the baseline (rug pulls, new servers, edited configs)",
		flags:    []string{"project", "project-only", "config", "probe", "timeout", "lock", "policy", "no-policy", "format", "json", "fail-on", "no-color"},
		examples: []string{"mcp-warden diff", "mcp-warden diff --format sarif > drift.sarif"}},
	{name: "watch", summary: "re-run diff on a schedule and alert on new changes (desktop or webhook)",
		flags: []string{"install", "uninstall", "interval", "once", "notify", "webhook", "webhook-format", "state", "fail-on",
			"project", "project-only", "config", "probe", "timeout", "lock", "policy", "no-policy"},
		examples: []string{
			"mcp-warden watch --install                         # check hourly in the background",
			`mcp-warden watch --install --probe --webhook "$FEISHU_HOOK"`,
			"mcp-warden watch --interval 30m                    # run in the foreground",
			"mcp-warden watch --uninstall"}},
	{name: "policy", args: "init", summary: "write a team policy that allows exactly what is configured now",
		flags:    []string{"project", "project-only", "config", "output", "force"},
		examples: []string{"mcp-warden policy init --project-only && git add mcp-warden.policy.json"}},
	{name: "rules", summary: "list every rule with its description", flags: []string{"json"}},
	{name: "version", summary: "print the version"},
}

func lookupCommand(name string) (command, bool) {
	for _, c := range commands {
		if c.name == name {
			return c, true
		}
	}
	return command{}, false
}

func overview() string {
	var b strings.Builder
	b.WriteString("mcp-warden — find risky MCP servers before they find you.\n\nUsage: mcp-warden <command> [flags]\n\nCommands:\n")
	for _, c := range commands {
		fmt.Fprintf(&b, "  %-13s %s\n", strings.TrimSpace(c.name+" "+c.args), c.summary)
	}
	b.WriteString(`
Start with:  mcp-warden scan          (add --probe to inspect live tools)
Run 'mcp-warden <command> -h' for the flags of a command.

Exit codes: 0 ok, 1 findings at/above --fail-on, 2 usage or runtime error.
--probe runs each server's command exactly as your MCP client would.
`)
	return b.String()
}

func commandHelp(name string) string {
	c, ok := lookupCommand(name)
	if !ok {
		return overview()
	}
	var b strings.Builder
	usage := "mcp-warden " + strings.TrimSpace(c.name+" "+c.args)
	if len(c.flags) > 0 {
		usage += " [flags]"
	}
	fmt.Fprintf(&b, "%s\n\n  %s\n", usage, c.summary)
	if len(c.flags) > 0 {
		b.WriteString("\nFlags:\n")
		for _, f := range c.flags {
			d := flagDocs[f]
			left := "--" + f
			if d.arg != "" {
				left += " " + d.arg
			}
			fmt.Fprintf(&b, "  %-22s %s\n", left, d.text)
		}
	}
	if len(c.examples) > 0 {
		b.WriteString("\nExamples:\n")
		for _, e := range c.examples {
			fmt.Fprintf(&b, "  %s\n", e)
		}
	}
	return b.String()
}

// parseArgs parses flags. It prints help for -h (exit 0) and a one-line
// error with a suggestion for mistakes (exit 2); ok=false means return code.
func parseArgs(fs *flag.FlagSet, o *opts, args []string, stdout, stderr io.Writer) (int, bool) {
	cmd := strings.Fields(fs.Name())[0]
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	err := parse(fs, o, args)
	if err == nil {
		return 0, true
	}
	if errors.Is(err, flag.ErrHelp) {
		fmt.Fprint(stdout, commandHelp(cmd))
		return 0, false
	}
	msg := err.Error()
	const undefined = "flag provided but not defined: -"
	if strings.HasPrefix(msg, undefined) {
		name := strings.TrimLeft(strings.TrimPrefix(msg, undefined), "-")
		msg = "unknown flag --" + name
		if s := suggestFlag(fs, name); s != "" {
			msg += " (did you mean --" + s + "?)"
		}
	}
	fmt.Fprintf(stderr, "error: %s\nRun 'mcp-warden %s -h' for usage.\n", msg, cmd)
	return 2, false
}

func suggestFlag(fs *flag.FlagSet, name string) string {
	var names []string
	fs.VisitAll(func(f *flag.Flag) { names = append(names, f.Name) })
	sort.Strings(names)
	best, bestD := "", 3
	for _, n := range names {
		if strings.HasPrefix(n, name) && len(name) >= 3 {
			return n
		}
		if d := editDistance(name, n); d < bestD {
			best, bestD = n, d
		}
	}
	return best
}

func suggestCommand(name string) string {
	best, bestD := "", 3
	for _, c := range commands {
		if d := editDistance(name, c.name); d < bestD {
			best, bestD = c.name, d
		}
	}
	return best
}

func editDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}

var pseudoVersionRe = regexp.MustCompile(`^v?\d+\.\d+\.\d+-(?:0\.)?\d{14}-([0-9a-f]{12})`)

// buildVersion turns Go build metadata into a readable version: a release
// ("0.3.0"), or "dev (abc1234)" / "dev (abc1234, modified)" for local builds.
func buildVersion(bi *debug.BuildInfo) string {
	v := bi.Main.Version
	if v != "" && v != "(devel)" && !pseudoVersionRe.MatchString(v) && !strings.Contains(v, "+dirty") {
		return strings.TrimPrefix(v, "v")
	}
	rev, modified := "", false
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}
	if rev == "" {
		if m := pseudoVersionRe.FindStringSubmatch(v); m != nil {
			rev = m[1]
		}
	}
	if rev == "" {
		return "dev"
	}
	if len(rev) > 7 {
		rev = rev[:7]
	}
	if modified || strings.Contains(v, "+dirty") {
		return "dev (" + rev + ", modified)"
	}
	return "dev (" + rev + ")"
}
