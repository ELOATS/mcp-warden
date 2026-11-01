// Package fix plans and applies safe, mechanical fixes to MCP configs:
// pinning npx/uvx packages to a vetted version and (opt-in) moving literal
// secrets into an env file. Edits are surgical (see jsonedit), verified
// before writing, written atomically, and every touched file is backed up.
package fix

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ELOATS/mcp-warden/internal/audit"
	"github.com/ELOATS/mcp-warden/internal/config"
	"github.com/ELOATS/mcp-warden/internal/jsonedit"
	"github.com/ELOATS/mcp-warden/internal/policy"
	"github.com/ELOATS/mcp-warden/internal/registry"
)

// Change is one planned edit of a string value in a config file.
type Change struct {
	Server config.Server
	Field  string   // human label, e.g. "args[1]" or "env.GITHUB_TOKEN"
	Path   []string // JSON path of the value
	Old    string   // display value (secrets masked)
	New    string   // display value
	Note   string

	oldRaw, newRaw string
	secret         *secretMove
}

type secretMove struct{ name, value string }

// Skip explains why a finding could not be fixed automatically.
type Skip struct {
	Server config.Server
	What   string
	Reason string
}

// Plan is the set of changes for all files.
type Plan struct {
	Changes []Change
	Skips   []Skip
}

// Files returns the config files the plan touches, in a stable order.
func (p Plan) Files() []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range p.Changes {
		if !seen[c.Server.Source] {
			seen[c.Server.Source] = true
			out = append(out, c.Server.Source)
		}
	}
	sort.Strings(out)
	return out
}

// Options for Build.
type Options struct {
	Registry    *registry.Client // nil: pinning is skipped
	Secrets     bool             // also move literal env secrets into SecretsFile
	SecretsFile string
	Servers     []string // only these server names (globs); empty = all
}

// secretClients expand ${VAR} in env values and inherit the environment of
// the shell that starts them. GUI clients started from a dock or start menu
// often do not, so secrets are not moved for them automatically.
var secretClients = map[string]bool{"claude-code": true, "gemini-cli": true}

// Build computes the plan. It reads nothing from disk except the secrets
// file (to avoid name clashes) and queries the registries for pins.
func Build(ctx context.Context, servers []config.Server, opt Options) Plan {
	var p Plan
	var pins []pinJob
	for _, s := range servers {
		if !selected(s.Name, opt.Servers) {
			continue
		}
		if s.Disabled {
			continue
		}
		if s.Transport == "stdio" {
			if job, skip, ok := pinFor(s); ok {
				pins = append(pins, job)
			} else if skip != nil {
				p.Skips = append(p.Skips, *skip)
			}
		}
		if keys := audit.SecretEnvKeys(s); len(keys) > 0 {
			switch {
			case !opt.Secrets:
				p.Skips = append(p.Skips, Skip{s, "secrets in env (" + strings.Join(keys, ", ") + ")",
					"not moved by default; re-run with --secrets"})
			case !secretClients[s.Client]:
				p.Skips = append(p.Skips, Skip{s, "secrets in env (" + strings.Join(keys, ", ") + ")",
					s.Client + " may not pass your shell's variables to servers; move them by hand (see `mcp-warden scan -v`)"})
			default:
				for _, k := range keys {
					v := s.Env[k]
					p.Changes = append(p.Changes, Change{
						Server: s, Field: "env." + k, Path: append(append([]string(nil), s.Path...), "env", k),
						Old: audit.Redact(v), oldRaw: v, secret: &secretMove{name: k, value: v},
					})
				}
			}
		}
	}
	p.Changes = append(p.Changes, resolvePins(ctx, pins, opt.Registry, &p.Skips)...)
	assignSecretNames(p.Changes, opt.SecretsFile)
	sort.SliceStable(p.Changes, func(i, j int) bool {
		a, b := p.Changes[i], p.Changes[j]
		if a.Server.Source != b.Server.Source {
			return a.Server.Source < b.Server.Source
		}
		return a.Server.Name < b.Server.Name
	})
	return p
}

func selected(name string, globs []string) bool {
	if len(globs) == 0 {
		return true
	}
	for _, g := range globs {
		if policy.Glob(g, name) {
			return true
		}
	}
	return false
}

type pinJob struct {
	server config.Server
	eco    string
	pkg    string
	argIdx int
	prefix string
	base   string // spec without prefix and without @latest
	oldRaw string
}

func pinFor(s config.Server) (pinJob, *Skip, bool) {
	l := audit.ParseLaunch(s.Command, s.Args)
	if l.Runner != "npx" && l.Runner != "uvx" || l.Pinned {
		return pinJob{}, nil, false
	}
	what := "unpinned " + l.Package
	switch {
	case !l.HasSpec || l.SpecIndex >= len(s.Args):
		return pinJob{}, &Skip{s, what, "could not locate the package argument"}, false
	case strings.HasPrefix(l.Package, "git+") || strings.Contains(l.Package, "://") || strings.Contains(l.Package, ":"):
		return pinJob{}, &Skip{s, what, "installed from git or a URL; pin a commit by hand"}, false
	case l.Version != "" && l.Version != "latest":
		return pinJob{}, &Skip{s, what, fmt.Sprintf("uses the version constraint %q; pin it by hand", l.Version)}, false
	}
	raw := s.Args[l.SpecIndex]
	base := strings.TrimSuffix(strings.TrimPrefix(raw, l.SpecPrefix), "@latest")
	eco := "npm"
	if l.Runner == "uvx" {
		eco = "pypi"
	}
	return pinJob{server: s, eco: eco, pkg: l.Package, argIdx: l.SpecIndex, prefix: l.SpecPrefix, base: base, oldRaw: raw}, nil, true
}

func resolvePins(ctx context.Context, jobs []pinJob, rc *registry.Client, skips *[]Skip) []Change {
	type result struct {
		cand registry.Candidate
		err  error
	}
	results := map[string]*result{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)
	for _, j := range jobs {
		key := j.eco + ":" + j.pkg
		if _, ok := results[key]; ok || rc == nil {
			continue
		}
		results[key] = &result{}
		wg.Add(1)
		go func(key, eco, pkg string) {
			defer wg.Done()
			sem <- struct{}{}
			c, err := rc.PinCandidate(ctx, eco, pkg)
			<-sem
			mu.Lock()
			results[key].cand, results[key].err = c, err
			mu.Unlock()
		}(key, j.eco, j.pkg)
	}
	wg.Wait()

	var out []Change
	for _, j := range jobs {
		what := "unpinned " + j.pkg
		if rc == nil {
			*skips = append(*skips, Skip{j.server, what, "registry lookups are off (--offline)"})
			continue
		}
		r := results[j.eco+":"+j.pkg]
		if r.err != nil {
			*skips = append(*skips, Skip{j.server, what, r.err.Error()})
			continue
		}
		spec := j.base + "@" + r.cand.Version
		if j.eco == "pypi" {
			spec = j.base + "==" + r.cand.Version
		}
		newRaw := j.prefix + spec
		note := fmt.Sprintf("the latest release, published %s", r.cand.Published.Format("2006-01-02"))
		if r.cand.Version != r.cand.Latest {
			note = fmt.Sprintf("latest %s is only %s old; %s (published %s) is the newest release older than %s",
				r.cand.Latest, days(r.cand.LatestAge), r.cand.Version, r.cand.Published.Format("2006-01-02"), days(rc.Cooldown))
		}
		out = append(out, Change{
			Server: j.server, Field: "args[" + strconv.Itoa(j.argIdx) + "]",
			Path: append(append([]string(nil), j.server.Path...), "args", strconv.Itoa(j.argIdx)),
			Old:  j.oldRaw, New: newRaw, Note: note, oldRaw: j.oldRaw, newRaw: newRaw,
		})
	}
	return out
}

func days(d time.Duration) string {
	if d < 48*time.Hour {
		return fmt.Sprintf("%d hours", int(d.Hours()))
	}
	return fmt.Sprintf("%d days", int(d.Hours()/24))
}

var nonIdent = regexp.MustCompile(`[^A-Z0-9_]+`)

// assignSecretNames picks the variable name for each moved secret, adding a
// server suffix when the same name already holds a different value.
func assignSecretNames(changes []Change, secretsFile string) {
	taken, _ := readEnvFile(secretsFile)
	if taken == nil {
		taken = map[string]string{}
	}
	for i := range changes {
		m := changes[i].secret
		if m == nil {
			continue
		}
		name := m.name
		suffix := strings.Trim(nonIdent.ReplaceAllString(strings.ToUpper(changes[i].Server.Name), "_"), "_")
		for n := 1; ; n++ {
			if v, ok := taken[name]; !ok || v == m.value {
				break
			}
			name = m.name + "_" + suffix
			if n > 1 {
				name += "_" + strconv.Itoa(n)
			}
		}
		taken[name] = m.value
		m.name = name
		changes[i].newRaw = "${" + name + "}"
		changes[i].New = changes[i].newRaw
		changes[i].Note = "value moved to " + secretsFile
	}
}

// ---------------------------------------------------------------- apply

// Result describes one written file.
type Result struct {
	File    string
	Backup  string
	Changes int
}

// ErrChanged means a config file no longer matches what was planned.
var ErrChanged = errors.New("config changed since the plan was made; re-run mcp-warden fix")

// Apply verifies every edit, then writes the secrets file and each config
// atomically, keeping a backup of every config it touches. Nothing is
// written unless all files verify.
func (p Plan) Apply(secretsFile string, now time.Time) ([]Result, error) {
	type pending struct {
		path    string
		mode    os.FileMode
		orig    []byte
		updated []byte
		n       int
	}
	var todo []pending
	secrets := map[string]string{}
	for _, file := range p.Files() {
		orig, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		fi, err := os.Stat(file)
		if err != nil {
			return nil, err
		}
		idx, err := jsonedit.Strings(orig)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", file, err)
		}
		var edits []jsonedit.Edit
		var mine []Change
		for _, c := range p.Changes {
			if c.Server.Source != file {
				continue
			}
			span, ok := idx[jsonedit.Key(c.Path...)]
			if !ok {
				return nil, fmt.Errorf("%s: %s of %q: %w", file, c.Field, c.Server.Name, ErrChanged)
			}
			if cur, err := jsonedit.Value(orig, span); err != nil || cur != c.oldRaw {
				return nil, fmt.Errorf("%s: %s of %q: %w", file, c.Field, c.Server.Name, ErrChanged)
			}
			edits = append(edits, jsonedit.Edit{Span: span, Value: c.newRaw})
			mine = append(mine, c)
			if c.secret != nil {
				secrets[c.secret.name] = c.secret.value
			}
		}
		updated, err := jsonedit.Apply(orig, edits)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", file, err)
		}
		// Verify: still parses, and every edited value reads back as planned.
		after, err := jsonedit.Strings(updated)
		if err != nil {
			return nil, fmt.Errorf("%s: edited file would not parse (%v); nothing was written", file, err)
		}
		for _, c := range mine {
			span, ok := after[jsonedit.Key(c.Path...)]
			if v, err := jsonedit.Value(updated, span); !ok || err != nil || v != c.newRaw {
				return nil, fmt.Errorf("%s: verification of %s failed; nothing was written", file, c.Field)
			}
		}
		todo = append(todo, pending{file, fi.Mode().Perm(), orig, updated, len(mine)})
	}

	if len(secrets) > 0 { // before the configs, so references never dangle
		if err := mergeEnvFile(secretsFile, secrets); err != nil {
			return nil, err
		}
	}
	var results []Result
	stamp := now.Format("20060102-150405")
	for _, t := range todo {
		backup := t.path + ".mcp-warden-" + stamp + ".bak"
		if err := os.WriteFile(backup, t.orig, t.mode); err != nil {
			return results, fmt.Errorf("backup %s: %v (config not modified)", backup, err)
		}
		if err := writeAtomic(t.path, t.updated, t.mode); err != nil {
			return results, err
		}
		results = append(results, Result{File: t.path, Backup: backup, Changes: t.n})
	}
	return results, nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".mcp-warden-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// ---------------------------------------------------------------- env file

var envLineRe = regexp.MustCompile(`^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$`)

func readEnvFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		m := envLineRe.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		out[m[1]] = unquote(m[2])
	}
	return out, sc.Err()
}

func unquote(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && v[0] == '\'' && v[len(v)-1] == '\'' {
		return strings.ReplaceAll(v[1:len(v)-1], `'\''`, `'`)
	}
	return v
}

func shellQuote(v string) string { return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'" }

func mergeEnvFile(path string, add map[string]string) error {
	existing, err := readEnvFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	var b strings.Builder
	if len(existing) == 0 {
		b.WriteString("# Secrets moved out of MCP configs by mcp-warden fix.\n# Load them in your shell profile:  source " + path + "\n")
	} else {
		data, _ := os.ReadFile(path)
		b.Write(data)
		if len(data) > 0 && data[len(data)-1] != '\n' {
			b.WriteByte('\n')
		}
	}
	names := make([]string, 0, len(add))
	for k := range add {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		if v, ok := existing[k]; ok && v == add[k] {
			continue
		}
		fmt.Fprintf(&b, "export %s=%s\n", k, shellQuote(add[k]))
	}
	if err := writeAtomic(path, []byte(b.String()), 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}
