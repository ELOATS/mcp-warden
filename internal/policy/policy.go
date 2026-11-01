// Package policy implements team policy files (mcp-warden.policy.json):
// allow/deny lists for what MCP servers may run, documented ignores, and
// severity overrides.
package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ELOATS/mcp-warden/internal/audit"
	"github.com/ELOATS/mcp-warden/internal/config"
)

// FileName is the conventional policy file name at a project root.
const FileName = "mcp-warden.policy.json"

// Policy is a parsed policy file.
type Policy struct {
	Version  int                       `json:"version"`
	Allow    Lists                     `json:"allow,omitempty"`
	Deny     Lists                     `json:"deny,omitempty"`
	Ignore   []Ignore                  `json:"ignore,omitempty"`
	Severity map[string]audit.Severity `json:"severity,omitempty"`

	Path string `json:"-"`
}

// Lists holds glob patterns per launch kind. Package patterns are
// "name" (any version) or "name@version", where both parts may use * and ?.
type Lists struct {
	NPM     []string `json:"npm,omitempty"`
	PyPI    []string `json:"pypi,omitempty"`
	Docker  []string `json:"docker,omitempty"`  // image or image@sha256:… / image:tag
	Remote  []string `json:"remote,omitempty"`  // URL patterns
	Command []string `json:"command,omitempty"` // full command lines of local servers
}

func (l Lists) empty() bool {
	return len(l.NPM)+len(l.PyPI)+len(l.Docker)+len(l.Remote)+len(l.Command) == 0
}

func (l Lists) of(kind string) []string {
	switch kind {
	case "npm":
		return l.NPM
	case "pypi":
		return l.PyPI
	case "docker":
		return l.Docker
	case "remote":
		return l.Remote
	}
	return l.Command
}

// Ignore suppresses matching findings. A reason is mandatory so that every
// exception is documented; Expires (YYYY-MM-DD) makes it lapse automatically.
type Ignore struct {
	Rule    string `json:"rule"`
	Server  string `json:"server,omitempty"` // glob on the server name or full ID
	Tool    string `json:"tool,omitempty"`
	Reason  string `json:"reason"`
	Expires string `json:"expires,omitempty"`
}

// Find returns the policy file to use: the project's, else the user's, else "".
func Find(projectDir, home string) string {
	for _, p := range []string{filepath.Join(projectDir, FileName), filepath.Join(home, ".mcp-warden", "policy.json")} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// Load reads and validates a policy file. Unknown fields are errors, so a
// typo cannot silently disable a rule.
func Load(path string) (*Policy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(config.StripJSONC(b)))
	dec.DisallowUnknownFields()
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	p.Path = path
	if err := p.validate(); err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	return &p, nil
}

func (p *Policy) validate() error {
	if p.Version != 1 {
		return fmt.Errorf("unsupported policy version %d (want 1)", p.Version)
	}
	var errs []string
	for i, ig := range p.Ignore {
		if ig.Rule == "" {
			errs = append(errs, fmt.Sprintf("ignore[%d]: rule is required", i))
		}
		if strings.TrimSpace(ig.Reason) == "" {
			errs = append(errs, fmt.Sprintf("ignore[%d] (%s): reason is required", i, ig.Rule))
		}
		if ig.Expires != "" {
			if _, err := time.Parse("2006-01-02", ig.Expires); err != nil {
				errs = append(errs, fmt.Sprintf("ignore[%d] (%s): expires must be YYYY-MM-DD", i, ig.Rule))
			}
		}
		if !strings.ContainsAny(ig.Rule, "*?") && !audit.Known(ig.Rule) {
			errs = append(errs, fmt.Sprintf("ignore[%d]: unknown rule %q", i, ig.Rule))
		}
	}
	for id := range p.Severity {
		if !audit.Known(id) {
			errs = append(errs, fmt.Sprintf("severity: unknown rule %q", id))
		}
	}
	if len(errs) > 0 {
		sort.Strings(errs)
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// Target is what a server runs, normalised for matching.
type Target struct {
	Kind    string // npm | pypi | docker | remote | command
	Name    string
	Version string
}

func (t Target) String() string {
	if t.Version == "" {
		return t.Kind + ":" + t.Name
	}
	return t.Kind + ":" + t.Name + "@" + t.Version
}

// TargetOf classifies a server's launch target.
func TargetOf(s config.Server) Target {
	if s.Transport == "http" || s.Transport == "sse" {
		return Target{Kind: "remote", Name: s.URL}
	}
	l := audit.ParseLaunch(s.Command, s.Args)
	switch l.Runner {
	case "npx":
		return Target{Kind: "npm", Name: l.Package, Version: l.Version}
	case "uvx":
		return Target{Kind: "pypi", Name: l.Package, Version: l.Version}
	case "docker":
		return Target{Kind: "docker", Name: l.Package, Version: l.Version}
	}
	return Target{Kind: "command", Name: strings.TrimSpace(s.Command + " " + strings.Join(s.Args, " "))}
}

// Matches reports whether pattern (from list kind) matches t.
func Matches(pattern string, t Target) bool {
	if t.Kind == "remote" || t.Kind == "command" {
		return Glob(pattern, t.Name)
	}
	name, ver := splitPattern(t.Kind, pattern)
	if !Glob(name, t.Name) {
		return false
	}
	return ver == "" || Glob(ver, t.Version)
}

func splitPattern(kind, p string) (name, version string) {
	switch kind {
	case "pypi":
		if i := strings.Index(p, "=="); i > 0 {
			return p[:i], p[i+2:]
		}
	case "docker":
		if i := strings.Index(p, "@"); i > 0 {
			return p[:i], p[i+1:]
		}
		if c := strings.LastIndex(p, ":"); c > strings.LastIndex(p, "/") {
			return p[:c], p[c+1:]
		}
		return p, ""
	}
	start := 0
	if strings.HasPrefix(p, "@") { // npm scope
		start = 1
	}
	if i := strings.Index(p[start:], "@"); i >= 0 {
		return p[:start+i], p[start+i+1:]
	}
	return p, ""
}

// Check evaluates the allow/deny lists against configured servers.
func (p *Policy) Check(servers []config.Server) []audit.Finding {
	var out []audit.Finding
	for _, s := range servers {
		if s.Disabled {
			continue
		}
		t := TargetOf(s)
		if pat, ok := firstMatch(p.Deny.of(t.Kind), t); ok {
			out = append(out, audit.Finding{Rule: "POLICY-DENIED", Severity: audit.Critical, Server: s.ID(),
				Message:  fmt.Sprintf("matches deny rule %q in the team policy", pat),
				Evidence: redactTarget(t), Fix: "Remove this server; it is explicitly forbidden by " + p.Path + "."})
			continue
		}
		if p.Allow.empty() {
			continue
		}
		if _, ok := firstMatch(p.Allow.of(t.Kind), t); !ok {
			out = append(out, audit.Finding{Rule: "POLICY-NOT-ALLOWED", Severity: audit.High, Server: s.ID(),
				Message:  "is not on the team allowlist",
				Evidence: redactTarget(t),
				Fix:      fmt.Sprintf("Remove it, or add a reviewed pattern under allow.%s in %s.", t.Kind, p.Path)})
		}
	}
	return out
}

func firstMatch(patterns []string, t Target) (string, bool) {
	for _, pat := range patterns {
		if Matches(pat, t) {
			return pat, true
		}
	}
	return "", false
}

func redactTarget(t Target) string {
	switch t.Kind {
	case "remote":
		t.Name = audit.RedactURL(t.Name)
	case "command":
		t.Name = strings.Join(audit.RedactArgs(strings.Fields(t.Name)), " ")
	}
	return t.String()
}

// Result of applying ignores and overrides.
type Result struct {
	Findings   []audit.Finding
	Suppressed []audit.Finding
	Warnings   []string
}

// Apply applies severity overrides, then ignores. Expired ignores no longer
// suppress anything and produce a warning instead.
func (p *Policy) Apply(findings []audit.Finding, now time.Time) Result {
	var r Result
	warned := map[int]bool{}
	today := now.Format("2006-01-02")
	for _, f := range findings {
		if sev, ok := p.Severity[f.Rule]; ok {
			f.Severity = sev
		}
		suppressed := false
		for i, ig := range p.Ignore {
			if !ig.matches(f) {
				continue
			}
			if ig.Expires != "" && ig.Expires < today {
				if !warned[i] {
					warned[i] = true
					r.Warnings = append(r.Warnings, fmt.Sprintf("policy ignore for %s (%s) expired on %s and no longer applies", ig.Rule, ig.Reason, ig.Expires))
				}
				continue
			}
			suppressed = true
			break
		}
		if suppressed {
			r.Suppressed = append(r.Suppressed, f)
		} else {
			r.Findings = append(r.Findings, f)
		}
	}
	return r
}

func (ig Ignore) matches(f audit.Finding) bool {
	if !Glob(ig.Rule, f.Rule) {
		return false
	}
	if ig.Server != "" && !Glob(ig.Server, f.Server) && !Glob(ig.Server, serverName(f.Server)) {
		return false
	}
	if ig.Tool != "" && !Glob(ig.Tool, f.Tool) {
		return false
	}
	return true
}

// serverName extracts "name" from an ID like "client/name @ location#project".
func serverName(id string) string {
	i := strings.Index(id, "/")
	j := strings.Index(id, " @ ")
	if i < 0 || j < i {
		return id
	}
	return id[i+1 : j]
}

// Init builds an allowlist that admits exactly what is configured today.
func Init(servers []config.Server) *Policy {
	set := map[string]map[string]bool{}
	add := func(kind, v string) {
		if set[kind] == nil {
			set[kind] = map[string]bool{}
		}
		set[kind][v] = true
	}
	for _, s := range servers {
		if s.Disabled {
			continue
		}
		t := TargetOf(s)
		switch t.Kind {
		case "remote":
			if i := strings.IndexAny(t.Name, "?#"); i >= 0 {
				// Never copy query-string secrets into a committed file.
				t.Name = t.Name[:i] + "?*"
			}
			add("remote", t.Name)
		case "command":
			// Secret-bearing arguments become wildcards so the pattern still
			// matches without writing the secret into the policy file.
			words := append([]string{s.Command}, s.Args...)
			red := audit.RedactArgs(words)
			for i := range words {
				if red[i] != words[i] {
					words[i] = "*"
				}
			}
			add("command", strings.Join(words, " "))
		case "pypi":
			if t.Version != "" && !strings.ContainsAny(t.Version, "<>~!*,") {
				add("pypi", t.Name+"=="+t.Version)
			} else {
				add("pypi", t.Name)
			}
		default:
			if t.Version != "" {
				add(t.Kind, t.Name+"@"+t.Version)
			} else {
				add(t.Kind, t.Name)
			}
		}
	}
	list := func(kind string) []string {
		var out []string
		for v := range set[kind] {
			out = append(out, v)
		}
		sort.Strings(out)
		return out
	}
	return &Policy{Version: 1, Allow: Lists{
		NPM: list("npm"), PyPI: list("pypi"), Docker: list("docker"), Remote: list("remote"), Command: list("command"),
	}}
}

// Save writes the policy as indented JSON, refusing to overwrite unless force.
func (p *Policy) Save(path string, force bool) error {
	if !force {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("%s already exists (use --force to overwrite)", path)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// Glob matches s against a pattern where * matches any run of characters
// (including '/') and ? matches exactly one.
func Glob(pattern, s string) bool {
	p, r := []rune(pattern), []rune(s)
	pi, si, star, mark := 0, 0, -1, 0
	for si < len(r) {
		switch {
		case pi < len(p) && (p[pi] == '?' || p[pi] == r[si]):
			pi++
			si++
		case pi < len(p) && p[pi] == '*':
			star, mark = pi, si
			pi++
		case star >= 0:
			pi = star + 1
			mark++
			si = mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}
