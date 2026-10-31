// Command mcp-warden audits the MCP servers configured on this machine.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/ELOATS/mcp-warden/internal/audit"
	"github.com/ELOATS/mcp-warden/internal/config"
	"github.com/ELOATS/mcp-warden/internal/lockfile"
	"github.com/ELOATS/mcp-warden/internal/probe"
	"github.com/ELOATS/mcp-warden/internal/report"
)

// version is set at release time with -ldflags "-X main.version=1.2.3".
// For `go install ...@vX.Y.Z` builds it falls back to the module version.
var version = "dev"

func init() {
	if version != "dev" {
		return
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		version = strings.TrimPrefix(bi.Main.Version, "v")
	}
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

const usageText = `mcp-warden — find risky MCP servers before they find you.

Usage:
  mcp-warden list   [flags]   list MCP servers configured for this user/project
  mcp-warden scan   [flags]   audit configs; add --probe to inspect live tool definitions
  mcp-warden pin    [flags]   record a trusted baseline (lockfile)
  mcp-warden diff   [flags]   report anything that changed since the baseline
  mcp-warden version

Common flags:
  --project DIR       project directory to scan for .mcp.json, .cursor/, .vscode/ (default ".")
  --project-only      skip user-level configs (handy in CI)
  --config FILE       extra config file to read (repeatable)
  --probe             start/connect to each enabled server and list its tools
  --timeout DUR       per-server probe timeout (default 20s)
  --json              machine-readable output
  --fail-on SEV       exit 1 if a finding is at or above SEV: info|low|medium|high|critical|none
  --show SEV          lowest severity printed in text output (default low)
  --lock FILE         lockfile path for pin/diff

Exit codes: 0 ok, 1 findings at/above --fail-on, 2 usage or runtime error.
Probing runs each server's command exactly as your MCP client would; only probe configs you would launch anyway.
`

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usageText)
		return 2
	}
	probe.ClientVersion = version
	switch args[0] {
	case "list":
		return cmdList(args[1:], stdout, stderr)
	case "scan":
		return cmdScan(args[1:], stdout, stderr)
	case "pin":
		return cmdPin(args[1:], stdout, stderr)
	case "diff":
		return cmdDiff(args[1:], stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, "mcp-warden "+version)
		return 0
	case "help", "--help", "-h":
		fmt.Fprint(stdout, usageText)
		return 0
	}
	fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usageText)
	return 2
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

type opts struct {
	project     string
	projectOnly bool
	configs     multiFlag
	probe       bool
	timeout     time.Duration
	json        bool
	noColor     bool
	failOn      string
	show        string
	lock        string

	probeSet bool
}

func newFlags(name string, stderr io.Writer, defaultFailOn string) (*flag.FlagSet, *opts) {
	o := &opts{}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usageText) }
	fs.StringVar(&o.project, "project", ".", "")
	fs.BoolVar(&o.projectOnly, "project-only", false, "")
	fs.Var(&o.configs, "config", "")
	fs.BoolVar(&o.probe, "probe", false, "")
	fs.DurationVar(&o.timeout, "timeout", 20*time.Second, "")
	fs.BoolVar(&o.json, "json", false, "")
	fs.BoolVar(&o.noColor, "no-color", false, "")
	fs.StringVar(&o.failOn, "fail-on", defaultFailOn, "")
	fs.StringVar(&o.show, "show", "low", "")
	fs.StringVar(&o.lock, "lock", "", "")
	return fs, o
}

func parse(fs *flag.FlagSet, o *opts, args []string) error {
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "probe" {
			o.probeSet = true
		}
	})
	return nil
}

func (o *opts) discover() (config.Env, config.Result, error) {
	env, err := config.DefaultEnv(o.project)
	if err != nil {
		return env, config.Result{}, err
	}
	env.SkipUser = o.projectOnly
	return env, config.Discover(env, o.configs), nil
}

func (o *opts) styler(w io.Writer) report.Styler {
	if o.noColor {
		return report.Styler{}
	}
	return report.AutoColor(w)
}

func (o *opts) lockPath(env config.Env) string {
	if o.lock != "" {
		return o.lock
	}
	if o.projectOnly {
		return filepath.Join(env.ProjectDir, "mcp-warden.lock.json")
	}
	return filepath.Join(env.Home, ".mcp-warden", "lock.json")
}

func failThreshold(v string) (audit.Severity, bool, error) {
	if v == "" || strings.EqualFold(v, "none") {
		return 0, false, nil
	}
	s, err := audit.ParseSeverity(v)
	return s, true, err
}

// probeAll probes every enabled server, at most 4 at a time, and probes
// identical definitions (same server shared by several clients) only once.
func probeAll(servers []config.Server, env config.Env, timeout time.Duration, stderr io.Writer) map[string]*probe.Result {
	fmt.Fprintln(stderr, "probing: launching/connecting to each enabled server the way your MCP client would…")
	type job struct {
		key string
		s   config.Server
	}
	byKey := map[string]*probe.Result{}
	var jobs []job
	for _, s := range servers {
		if s.Disabled {
			continue
		}
		key := lockfile.ConfigHashes(s).Config
		if _, ok := byKey[key]; ok {
			continue
		}
		byKey[key] = nil
		jobs = append(jobs, job{key, s})
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	for _, j := range jobs {
		wg.Add(1)
		go func(j job) {
			defer wg.Done()
			sem <- struct{}{}
			r := probe.Probe(context.Background(), j.s, probe.Options{Timeout: timeout, Dir: env.ProjectDir})
			<-sem
			mu.Lock()
			byKey[j.key] = &r
			mu.Unlock()
		}(j)
	}
	wg.Wait()
	out := map[string]*probe.Result{}
	for _, s := range servers {
		if r := byKey[lockfile.ConfigHashes(s).Config]; r != nil && !s.Disabled {
			out[s.ID()] = r
		}
	}
	return out
}

func cmdList(args []string, stdout, stderr io.Writer) int {
	fs, o := newFlags("list", stderr, "none")
	if err := parse(fs, o, args); err != nil {
		return 2
	}
	_, res, err := o.discover()
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	if o.json {
		_ = report.WriteJSON(stdout, res)
		return 0
	}
	for _, w := range res.Warnings {
		fmt.Fprintln(stderr, "warning:", w)
	}
	if len(res.Servers) == 0 {
		fmt.Fprintln(stdout, "No MCP servers found.")
		return 0
	}
	for _, s := range res.Servers {
		dis := ""
		if s.Disabled {
			dis = " (disabled)"
		}
		fmt.Fprintf(stdout, "%-14s %-24s %-6s %s%s\n    %s\n", s.Client, s.Name, s.Transport, s.Location, dis, audit.Describe(s))
	}
	return 0
}

type analysis struct {
	env    config.Env
	res    config.Result
	probes map[string]*probe.Result
}

func (o *opts) analyze(stderr io.Writer, doProbe bool) (analysis, error) {
	env, res, err := o.discover()
	if err != nil {
		return analysis{}, err
	}
	a := analysis{env: env, res: res}
	if doProbe && len(res.Servers) > 0 {
		a.probes = probeAll(res.Servers, env, o.timeout, stderr)
	}
	return a, nil
}

func (a analysis) report() report.Report {
	var views []report.ServerView
	var findings []audit.Finding
	var withTools []audit.ServerTools
	for _, s := range a.res.Servers {
		f := audit.StaticChecks(s, audit.Options{Home: a.env.Home})
		v := report.ServerView{ID: s.ID(), Client: s.Client, Name: s.Name, Location: s.Location,
			Transport: s.Transport, Launch: audit.Describe(s), Disabled: s.Disabled}
		if pr := a.probes[s.ID()]; pr != nil {
			v.Probe = pr
			switch pr.Status {
			case "ok":
				f = append(f, audit.ToolChecks(s, pr.Tools)...)
				v.Capabilities = audit.ServerCapabilities(pr.Tools)
				withTools = append(withTools, audit.ServerTools{Server: s, Tools: pr.Tools})
			case "auth-required":
				f = append(f, audit.Finding{Rule: "PROBE-AUTH-REQUIRED", Severity: audit.Info, Server: s.ID(),
					Message: "server requires authentication, so its tools were not inspected", Evidence: pr.Error})
			case "skipped":
				f = append(f, audit.Finding{Rule: "PROBE-SKIPPED", Severity: audit.Info, Server: s.ID(), Message: pr.Error})
			default:
				f = append(f, audit.Finding{Rule: "PROBE-FAILED", Severity: audit.Low, Server: s.ID(),
					Message: "could not list tools", Evidence: pr.Error})
			}
		}
		findings = append(findings, f...)
		views = append(views, v)
	}
	findings = append(findings, audit.CrossChecks(withTools)...)
	return report.New("mcp-warden "+version, a.res.Files, a.res.Warnings, views, findings)
}

func (a analysis) snapshots() []lockfile.Snapshot {
	out := make([]lockfile.Snapshot, 0, len(a.res.Servers))
	for _, s := range a.res.Servers {
		out = append(out, lockfile.Snapshot{Server: s, Probe: a.probes[s.ID()]})
	}
	return out
}

func cmdScan(args []string, stdout, stderr io.Writer) int {
	fs, o := newFlags("scan", stderr, "none")
	if err := parse(fs, o, args); err != nil {
		return 2
	}
	threshold, failing, err := failThreshold(o.failOn)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	show, err := audit.ParseSeverity(o.show)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	a, err := o.analyze(stderr, o.probe)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	rep := a.report()
	if o.json {
		_ = report.WriteJSON(stdout, rep)
	} else {
		report.WriteText(stdout, rep, o.styler(stdout), show)
		if !o.probe && len(rep.Servers) > 0 {
			fmt.Fprintln(stdout, "Tip: add --probe to inspect the tools each server actually exposes.")
		}
	}
	if failing && audit.CountAtLeast(rep.All(), threshold) > 0 {
		return 1
	}
	return 0
}

func cmdPin(args []string, stdout, stderr io.Writer) int {
	fs, o := newFlags("pin", stderr, "none")
	if err := parse(fs, o, args); err != nil {
		return 2
	}
	a, err := o.analyze(stderr, o.probe)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	lf := lockfile.Build("mcp-warden "+version, a.snapshots())
	path := o.lockPath(a.env)
	if err := lockfile.Save(path, lf); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	probed := 0
	for _, e := range lf.Servers {
		if e.Probed {
			probed++
		}
	}
	if o.json {
		_ = report.WriteJSON(stdout, map[string]any{"lockfile": path, "servers": len(lf.Servers), "withTools": probed})
		return 0
	}
	fmt.Fprintf(stdout, "Pinned %d server(s) (%d with tool fingerprints) → %s\n", len(lf.Servers), probed, path)
	for id, e := range lf.Servers {
		if !e.Probed && o.probe {
			if pr := a.probes[id]; pr != nil {
				fmt.Fprintf(stdout, "  %s: tools not fingerprinted (%s)\n", id, pr.Status)
			}
		}
	}
	if !o.probe {
		fmt.Fprintln(stdout, "Config-only baseline. Add --probe to also fingerprint tool definitions (catches server-side rug pulls).")
	}
	return 0
}

func cmdDiff(args []string, stdout, stderr io.Writer) int {
	flags, o := newFlags("diff", stderr, "medium")
	if err := parse(flags, o, args); err != nil {
		return 2
	}
	threshold, failing, err := failThreshold(o.failOn)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	env, err := config.DefaultEnv(o.project)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	path := o.lockPath(env)
	base, err := lockfile.Load(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			fmt.Fprintf(stderr, "no baseline at %s; run `mcp-warden pin --probe` first\n", path)
		} else {
			fmt.Fprintln(stderr, "error:", err)
		}
		return 2
	}
	doProbe := o.probe
	if !o.probeSet {
		doProbe = base.HasProbed() // compare tools automatically if the baseline has them
	}
	a, err := o.analyze(stderr, doProbe)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	cur := lockfile.Build("mcp-warden "+version, a.snapshots())
	findings := lockfile.Diff(base, cur)
	if o.json {
		_ = report.WriteJSON(stdout, map[string]any{
			"lockfile": path, "pinnedAt": base.GeneratedAt, "findings": nonNil(findings), "summary": audit.Summary(findings)})
	} else {
		report.WriteDiffText(stdout, "mcp-warden "+version, path, findings, o.styler(stdout))
	}
	if failing && audit.CountAtLeast(findings, threshold) > 0 {
		return 1
	}
	return 0
}

func nonNil(f []audit.Finding) []audit.Finding {
	if f == nil {
		return []audit.Finding{}
	}
	return f
}
