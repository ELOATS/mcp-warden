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
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ELOATS/mcp-warden/internal/audit"
	"github.com/ELOATS/mcp-warden/internal/config"
	"github.com/ELOATS/mcp-warden/internal/lockfile"
	"github.com/ELOATS/mcp-warden/internal/notify"
	"github.com/ELOATS/mcp-warden/internal/policy"
	"github.com/ELOATS/mcp-warden/internal/probe"
	"github.com/ELOATS/mcp-warden/internal/registry"
	"github.com/ELOATS/mcp-warden/internal/report"
)

// version is set at release time with -ldflags "-X main.version=1.2.3".
// For `go install ...@vX.Y.Z` builds it falls back to the module version.
var version = "dev"

func init() {
	if version != "dev" {
		return
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		version = buildVersion(bi)
	}
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, overview())
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
	case "watch":
		return cmdWatch(args[1:], stdout, stderr)
	case "policy":
		return cmdPolicy(args[1:], stdout, stderr)
	case "rules":
		return cmdRules(args[1:], stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, "mcp-warden "+version)
		return 0
	case "help", "--help", "-h":
		if len(args) > 1 {
			fmt.Fprint(stdout, commandHelp(args[1]))
		} else {
			fmt.Fprint(stdout, overview())
		}
		return 0
	}
	msg := fmt.Sprintf("error: unknown command %q", args[0])
	if s := suggestCommand(args[0]); s != "" {
		msg += fmt.Sprintf(" (did you mean %q?)", s)
	}
	fmt.Fprintln(stderr, msg+"\nRun 'mcp-warden help' for the list of commands.")
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
	format      string
	policyPath  string
	noPolicy    bool

	probeSet bool
}

func newFlags(name string, stderr io.Writer, defaultFailOn string) (*flag.FlagSet, *opts) {
	o := &opts{}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
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
	fs.StringVar(&o.format, "format", "text", "")
	fs.StringVar(&o.policyPath, "policy", "", "")
	fs.BoolVar(&o.noPolicy, "no-policy", false, "")
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
	if o.json {
		o.format = "json"
	}
	switch o.format {
	case "text", "json", "sarif":
	default:
		return fmt.Errorf("--format must be text, json or sarif, got %q", o.format)
	}
	o.json = o.format == "json"
	return nil
}

// loadPolicy returns the policy in effect, or nil if there is none.
func (o *opts) loadPolicy(env config.Env) (*policy.Policy, error) {
	if o.noPolicy {
		return nil, nil
	}
	path := o.policyPath
	if path == "" {
		path = policy.Find(env.ProjectDir, env.Home)
		if path == "" {
			return nil, nil
		}
	}
	return policy.Load(path)
}

func (o *opts) discover() (config.Env, config.Result, error) {
	env, err := config.DefaultEnv(o.project)
	if err != nil {
		return env, config.Result{}, err
	}
	env.SkipUser = o.projectOnly
	return env, config.Discover(env, o.configs), nil
}

func (o *opts) styler(w io.Writer) report.Styler { return report.ForWriter(w, o.noColor) }

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
	if code, ok := parseArgs(fs, o, args, stdout, stderr); !ok {
		return code
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
	env      config.Env
	res      config.Result
	probes   map[string]*probe.Result
	registry []audit.Finding
}

// checkRegistries looks up npm/PyPI metadata for every enabled server.
func (a *analysis) checkRegistries(c *registry.Client, stderr io.Writer) {
	fmt.Fprintln(stderr, "registry: fetching npm/PyPI metadata…")
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)
	for _, s := range a.res.Servers {
		if s.Disabled {
			continue
		}
		wg.Add(1)
		go func(s config.Server) {
			defer wg.Done()
			sem <- struct{}{}
			fs := c.Check(context.Background(), s)
			<-sem
			mu.Lock()
			a.registry = append(a.registry, fs...)
			mu.Unlock()
		}(s)
	}
	wg.Wait()
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

func (a analysis) report(pol *policy.Policy) report.Report {
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
	findings = append(findings, a.registry...)
	warnings := a.res.Warnings
	suppressed := 0
	if pol != nil {
		findings = append(findings, pol.Check(a.res.Servers)...)
		r := pol.Apply(findings, time.Now())
		findings, suppressed = r.Findings, len(r.Suppressed)
		warnings = append(warnings, r.Warnings...)
	}
	rep := report.New("mcp-warden "+version, a.res.Files, warnings, views, findings)
	if pol != nil {
		rep.Policy, rep.Suppressed = pol.Path, suppressed
	}
	return rep
}

// locator maps finding Server IDs to config-file locations for SARIF.
func (a analysis) locator() (func(string) (report.Location, bool), report.Location) {
	byID := map[string]report.Location{}
	byClient := map[string]report.Location{}
	fallback := report.Location{URI: ".mcp.json", Line: 1}
	for i, s := range a.res.Servers {
		loc := report.Location{URI: sarifURI(s), Line: findLine(s.Source, s.Name)}
		byID[s.ID()] = loc
		if _, ok := byClient["client:"+s.Client]; !ok {
			byClient["client:"+s.Client] = loc
		}
		if i == 0 {
			fallback = report.Location{URI: loc.URI, Line: 1}
		}
	}
	return func(id string) (report.Location, bool) {
		if l, ok := byID[id]; ok {
			return l, true
		}
		if l, ok := byClient[id]; ok {
			return l, true
		}
		// A server that no longer exists (diff): use the location in its ID.
		if i := strings.Index(id, " @ "); i >= 0 {
			loc := id[i+3:]
			if j := strings.Index(loc, "#"); j >= 0 {
				loc = loc[:j]
			}
			if !strings.HasPrefix(loc, "~") && !filepath.IsAbs(loc) {
				return report.Location{URI: loc, Line: 1}, true
			}
		}
		return report.Location{}, false
	}, fallback
}

// sarifURI is project-relative for project configs (so code scanning can
// annotate them) and a file:// URI for user-level configs.
func sarifURI(s config.Server) string {
	if s.Scope != "user" && !strings.HasPrefix(s.Location, "~") && !filepath.IsAbs(s.Location) {
		return s.Location
	}
	p := filepath.ToSlash(s.Source)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p // Windows drive paths
	}
	return "file://" + p
}

// findLine returns the 1-based line where server name is defined, or 1.
func findLine(path, name string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return 1
	}
	re := regexp.MustCompile(`"` + regexp.QuoteMeta(name) + `"\s*:`)
	for i, line := range strings.Split(string(b), "\n") {
		if re.MatchString(line) {
			return i + 1
		}
	}
	return 1
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
	useRegistry := fs.Bool("registry", true, "")
	offline := fs.Bool("offline", false, "")
	verbose := fs.Bool("verbose", false, "")
	fs.BoolVar(verbose, "v", false, "")
	npmURL := fs.String("npm-registry", envOr("MCP_WARDEN_NPM_REGISTRY", registry.DefaultNPM), "")
	pypiURL := fs.String("pypi-url", envOr("MCP_WARDEN_PYPI_URL", registry.DefaultPyPI), "")
	cooldown := fs.Int("cooldown", 7, "")
	if code, ok := parseArgs(fs, o, args, stdout, stderr); !ok {
		return code
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
	if *cooldown < 0 {
		fmt.Fprintln(stderr, "error: --cooldown must be >= 0 days")
		return 2
	}
	a, err := o.analyze(stderr, o.probe)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	// Registry lookups are read-only, so they are on by default. --offline
	// (or MCP_WARDEN_OFFLINE=1) turns them off; an explicit --registry wins
	// over the environment variable.
	registrySet := false
	fs.Visit(func(f *flag.Flag) { registrySet = registrySet || f.Name == "registry" })
	if !registrySet && truthy(os.Getenv("MCP_WARDEN_OFFLINE")) {
		*useRegistry = false
	}
	if *offline {
		*useRegistry = false
	}
	if *useRegistry {
		rc := registry.New("mcp-warden/" + version + " (+https://github.com/ELOATS/mcp-warden)")
		rc.NPM, rc.PyPI = *npmURL, *pypiURL
		if *npmURL != registry.DefaultNPM {
			rc.NPMDownloads = "" // mirrors do not serve the download-count API
		}
		rc.Cooldown = time.Duration(*cooldown) * 24 * time.Hour
		a.checkRegistries(rc, stderr)
		for host, err := range rc.Unreachable() {
			a.res.Warnings = append(a.res.Warnings, fmt.Sprintf(
				"could not reach %s (%v); its registry checks were skipped. Use --offline to skip them on purpose.", host, err))
		}
	}
	pol, err := o.loadPolicy(a.env)
	if err != nil {
		fmt.Fprintln(stderr, "error: policy:", err)
		return 2
	}
	rep := a.report(pol)
	switch o.format {
	case "json":
		_ = report.WriteJSON(stdout, rep)
	case "sarif":
		locate, fallback := a.locator()
		if err := report.WriteSARIF(stdout, version, rep.All(), locate, fallback); err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 2
		}
	default:
		report.WriteText(stdout, rep, o.styler(stdout), report.TextOptions{MinShown: show, Verbose: *verbose})
		if len(rep.Servers) > 0 && !o.probe {
			fmt.Fprintln(stdout, "Tip: add --probe to also inspect the tools each server exposes (this starts the servers).")
		}
	}
	if failing && audit.CountAtLeast(rep.All(), threshold) > 0 {
		return 1
	}
	return 0
}

func cmdPin(args []string, stdout, stderr io.Writer) int {
	fs, o := newFlags("pin", stderr, "none")
	if code, ok := parseArgs(fs, o, args, stdout, stderr); !ok {
		return code
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

// errNoBaseline is returned by computeDiff when no lockfile exists yet.
var errNoBaseline = errors.New("no baseline")

// computeDiff loads the baseline and compares the current state against it.
// Tools are probed automatically when the baseline has tool fingerprints,
// unless --probe was given explicitly.
type diffResult struct {
	path       string
	base       lockfile.File
	findings   []audit.Finding
	analysis   analysis
	policy     string
	suppressed int
	warnings   []string
}

func (o *opts) computeDiff(probeLog io.Writer) (diffResult, error) {
	var d diffResult
	env, err := config.DefaultEnv(o.project)
	if err != nil {
		return d, err
	}
	pol, err := o.loadPolicy(env)
	if err != nil {
		return d, fmt.Errorf("policy: %w", err)
	}
	d.path = o.lockPath(env)
	d.base, err = lockfile.Load(d.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return d, fmt.Errorf("%w at %s; run `mcp-warden pin --probe` first", errNoBaseline, d.path)
		}
		return d, err
	}
	doProbe := o.probe
	if !o.probeSet {
		doProbe = d.base.HasProbed()
	}
	d.analysis, err = o.analyze(probeLog, doProbe)
	if err != nil {
		return d, err
	}
	cur := lockfile.Build("mcp-warden "+version, d.analysis.snapshots())
	d.findings = lockfile.Diff(d.base, cur)
	if pol != nil {
		r := pol.Apply(d.findings, time.Now())
		d.findings, d.suppressed, d.warnings, d.policy = r.Findings, len(r.Suppressed), r.Warnings, pol.Path
	}
	return d, nil
}

func cmdDiff(args []string, stdout, stderr io.Writer) int {
	flags, o := newFlags("diff", stderr, "medium")
	if code, ok := parseArgs(flags, o, args, stdout, stderr); !ok {
		return code
	}
	threshold, failing, err := failThreshold(o.failOn)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	d, err := o.computeDiff(stderr)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	findings := d.findings
	for _, w := range d.warnings {
		fmt.Fprintln(stderr, "warning:", w)
	}
	switch o.format {
	case "json":
		out := map[string]any{"lockfile": d.path, "pinnedAt": d.base.GeneratedAt, "findings": nonNil(findings), "summary": audit.Summary(findings)}
		if d.policy != "" {
			out["policy"], out["suppressed"] = d.policy, d.suppressed
		}
		_ = report.WriteJSON(stdout, out)
	case "sarif":
		locate, fallback := d.analysis.locator()
		if err := report.WriteSARIF(stdout, version, findings, locate, fallback); err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 2
		}
	default:
		report.WriteDiffText(stdout, "mcp-warden "+version, d.path, findings, o.styler(stdout))
		if d.suppressed > 0 {
			fmt.Fprintf(stdout, "%d change(s) suppressed by ignore rules in %s\n", d.suppressed, d.policy)
		}
	}
	if failing && audit.CountAtLeast(findings, threshold) > 0 {
		return 1
	}
	return 0
}

func cmdWatch(args []string, stdout, stderr io.Writer) int {
	flags, o := newFlags("watch", stderr, "medium")
	interval := flags.Duration("interval", time.Hour, "")
	once := flags.Bool("once", false, "")
	desktop := flags.String("notify", "desktop", "")
	webhook := flags.String("webhook", os.Getenv("MCP_WARDEN_WEBHOOK"), "")
	webhookFormat := flags.String("webhook-format", notify.FormatAuto, "")
	statePath := flags.String("state", "", "")
	install := flags.Bool("install", false, "")
	uninstall := flags.Bool("uninstall", false, "")
	if code, ok := parseArgs(flags, o, args, stdout, stderr); !ok {
		return code
	}
	env, err := config.DefaultEnv(o.project)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	if *uninstall {
		in, err := newInstaller(env.Home, env.ConfigDir, stdout)
		if err == nil {
			err = in.uninstall()
		}
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 2
		}
		return 0
	}
	if *webhook == "" { // stored by --install, outside the job definition
		if b, err := os.ReadFile(webhookFile(env.Home)); err == nil {
			*webhook = strings.TrimSpace(string(b))
		}
	}
	threshold, failing, err := failThreshold(o.failOn)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	if !failing {
		threshold = audit.Info // --fail-on none: alert on everything
	}
	if *interval < time.Minute && !*once {
		fmt.Fprintln(stderr, "error: --interval must be at least 1m")
		return 2
	}
	var notifiers []notify.Notifier
	switch *desktop {
	case "desktop":
		notifiers = append(notifiers, notify.Desktop{})
	case "none":
	default:
		fmt.Fprintf(stderr, "error: --notify must be desktop or none, got %q\n", *desktop)
		return 2
	}
	if *webhook != "" {
		if !contains(notify.Formats, *webhookFormat) {
			fmt.Fprintf(stderr, "error: --webhook-format must be one of %s\n", strings.Join(notify.Formats, ", "))
			return 2
		}
		notifiers = append(notifiers, notify.Webhook{URL: *webhook, Format: *webhookFormat})
	}
	if *statePath == "" {
		*statePath = filepath.Join(filepath.Dir(o.lockPath(env)), "watch-state.json")
	}
	if err := o.ensureBaseline(env, stdout, stderr); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	if *install {
		sched, err := scheduledArgs(args, o.project)
		if err == nil {
			var in installer
			if in, err = newInstaller(env.Home, env.ConfigDir, stdout); err == nil {
				err = in.install(sched, *interval, *webhook)
			}
		}
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 2
		}
		return 0
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// tick runs one check. It returns the number of findings at/above the
	// threshold, and a fatal error only when watching cannot continue.
	tick := func() (int, error) {
		d, err := o.computeDiff(io.Discard)
		findings := d.findings
		if err != nil {
			if errors.Is(err, errNoBaseline) {
				return 0, err
			}
			fmt.Fprintf(stderr, "%s check failed: %v\n", stamp(), err)
			return 0, nil
		}
		var relevant []audit.Finding
		for _, f := range findings {
			if f.Severity >= threshold {
				relevant = append(relevant, f)
			}
		}
		state, err := notify.LoadState(*statePath)
		if err != nil {
			fmt.Fprintf(stderr, "%s cannot read state: %v\n", stamp(), err)
		}
		fresh := state.New(relevant)
		if len(fresh) == 0 {
			fmt.Fprintf(stdout, "%s ok: %d open change(s), nothing new\n", stamp(), len(relevant))
			state.Sync(relevant, nil, time.Now())
			_ = state.Save(*statePath)
			return len(relevant), nil
		}
		msg := notify.Compose(fresh)
		fmt.Fprintf(stdout, "%s %s\n%s\n", stamp(), msg.Title, msg.Body)
		delivered := len(notifiers) == 0
		for _, n := range notifiers {
			if err := n.Notify(ctx, msg); err != nil {
				fmt.Fprintf(stderr, "%s %s notification failed: %v\n", stamp(), n.Name(), err)
				continue
			}
			delivered = true
		}
		if delivered { // otherwise keep them "new" and retry next tick
			state.Sync(relevant, fresh, time.Now())
		} else {
			state.Sync(relevant, nil, time.Now())
		}
		if err := state.Save(*statePath); err != nil {
			fmt.Fprintf(stderr, "%s cannot save state: %v\n", stamp(), err)
		}
		return len(relevant), nil
	}

	open, err := tick()
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	if *once {
		if failing && open > 0 {
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "%s watching every %s (Ctrl-C to stop)\n", stamp(), *interval)
	t := time.NewTicker(*interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			fmt.Fprintf(stdout, "%s stopped\n", stamp())
			return 0
		case <-t.C:
			if _, err := tick(); err != nil {
				fmt.Fprintln(stderr, "error:", err)
				return 2
			}
		}
	}
}

func cmdPolicy(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "init" {
		fmt.Fprint(stderr, commandHelp("policy"))
		return 2
	}
	flags, o := newFlags("policy init", stderr, "none")
	output := flags.String("output", "", "")
	force := flags.Bool("force", false, "")
	if code, ok := parseArgs(flags, o, args[1:], stdout, stderr); !ok {
		return code
	}
	env, res, err := o.discover()
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	path := *output
	if path == "" {
		path = filepath.Join(env.ProjectDir, policy.FileName)
	}
	p := policy.Init(res.Servers)
	if err := p.Save(path, *force); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	n := len(p.Allow.NPM) + len(p.Allow.PyPI) + len(p.Allow.Docker) + len(p.Allow.Remote) + len(p.Allow.Command)
	fmt.Fprintf(stdout, "Wrote %s with %d allow pattern(s) from %d configured server(s).\n", path, n, len(res.Servers))
	fmt.Fprintln(stdout, "Review it, loosen patterns where you want (e.g. \"@your-org/*\"), and commit it.")
	if !o.projectOnly {
		fmt.Fprintln(stdout, "Note: includes user-level configs too; use --project-only for a repository policy.")
	}
	return 0
}

func cmdRules(args []string, stdout, stderr io.Writer) int {
	flags, o := newFlags("rules", stderr, "none")
	if code, ok := parseArgs(flags, o, args, stdout, stderr); !ok {
		return code
	}
	rules := audit.Rules()
	if o.json {
		_ = report.WriteJSON(stdout, rules)
		return 0
	}
	for _, r := range rules {
		fmt.Fprintf(stdout, "%-24s %s\n", r.ID, r.Title)
		if r.Help != "" {
			fmt.Fprintf(stdout, "%-24s %s\n", "", r.Help)
		}
	}
	return 0
}

func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// ensureBaseline pins the current state when no baseline exists yet, so
// `watch` works out of the box instead of failing on its first run.
func (o *opts) ensureBaseline(env config.Env, stdout, stderr io.Writer) error {
	path := o.lockPath(env)
	if _, err := os.Stat(path); err == nil || !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	a, err := o.analyze(stderr, o.probe)
	if err != nil {
		return err
	}
	lf := lockfile.Build("mcp-warden "+version, a.snapshots())
	if err := lockfile.Save(path, lf); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "%s no baseline yet: trusted the current %s → %s\n", stamp(), pluralize(len(lf.Servers), "server"), path)
	if !o.probe {
		fmt.Fprintln(stdout, "    (configs only; add --probe to also watch tool definitions for rug pulls)")
	}
	return nil
}

func pluralize(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

func stamp() string { return time.Now().Format("2006-01-02 15:04:05") }

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func nonNil(f []audit.Finding) []audit.Finding {
	if f == nil {
		return []audit.Finding{}
	}
	return f
}
