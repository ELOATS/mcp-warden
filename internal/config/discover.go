// Package config discovers MCP server definitions in the configuration files
// of popular MCP clients and normalises them into a single Server type.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Server is one MCP server entry from one client's config file.
type Server struct {
	Name      string            `json:"name"`
	Client    string            `json:"client"`
	Scope     string            `json:"scope"`    // user | project | explicit
	Source    string            `json:"source"`   // absolute path of the config file
	Location  string            `json:"location"` // portable display path (~/... or project-relative)
	Project   string            `json:"project,omitempty"`
	Transport string            `json:"transport"` // stdio | http | sse | unknown
	Command   string            `json:"command,omitempty"`
	Args      []string          `json:"args,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
	URL       string            `json:"url,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
	Disabled  bool              `json:"disabled,omitempty"`
	// Path is the JSON path of this server's object inside Source (e.g.
	// ["mcpServers", "github"]), used by `fix` to edit it in place.
	Path []string `json:"-"`
}

// ID is a stable, machine-portable identifier used in reports and lockfiles.
func (s Server) ID() string {
	id := s.Client + "/" + s.Name + " @ " + s.Location
	if s.Project != "" {
		id += "#" + s.Project
	}
	return id
}

// Env describes where to look for config files.
type Env struct {
	Home       string
	ConfigDir  string // per-OS user config dir (os.UserConfigDir)
	ProjectDir string
	SkipUser   bool // only scan project-level configs (useful in CI)
}

// DefaultEnv builds an Env for the current user.
func DefaultEnv(projectDir string) (Env, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Env{}, err
	}
	cfg, err := os.UserConfigDir()
	if err != nil {
		cfg = filepath.Join(home, ".config")
	}
	abs, err := filepath.Abs(projectDir)
	if err != nil {
		return Env{}, err
	}
	return Env{Home: home, ConfigDir: cfg, ProjectDir: abs}, nil
}

// ClientNames are the MCP clients whose configs are discovered.
var ClientNames = []string{"Claude Desktop", "Claude Code", "Cursor", "VS Code", "Cline", "Windsurf", "Gemini CLI"}

type kind int

const (
	kindMCPServers     kind = iota // {"mcpServers": {...}}
	kindServers                    // {"servers": {...}}            (VS Code mcp.json)
	kindVSCodeSettings             // {"mcp": {"servers": {...}}}   (VS Code settings.json)
	kindClaudeCode                 // ~/.claude.json: top-level + per-project mcpServers
	kindAuto                       // explicit --config file: try all shapes
)

type source struct {
	client string
	path   string
	scope  string
	kind   kind
}

func sources(e Env) []source {
	var s []source
	if !e.SkipUser {
		s = append(s,
			source{"claude-desktop", filepath.Join(e.ConfigDir, "Claude", "claude_desktop_config.json"), "user", kindMCPServers},
			source{"claude-code", filepath.Join(e.Home, ".claude.json"), "user", kindClaudeCode},
			source{"cursor", filepath.Join(e.Home, ".cursor", "mcp.json"), "user", kindMCPServers},
			source{"windsurf", filepath.Join(e.Home, ".codeium", "windsurf", "mcp_config.json"), "user", kindMCPServers},
			source{"gemini-cli", filepath.Join(e.Home, ".gemini", "settings.json"), "user", kindMCPServers},
		)
		for _, flavor := range []string{"Code", "Code - Insiders"} {
			user := filepath.Join(e.ConfigDir, flavor, "User")
			s = append(s,
				source{"vscode", filepath.Join(user, "mcp.json"), "user", kindServers},
				source{"vscode", filepath.Join(user, "settings.json"), "user", kindVSCodeSettings},
				source{"cline", filepath.Join(user, "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"), "user", kindMCPServers},
			)
		}
	}
	if e.ProjectDir != "" {
		p := e.ProjectDir
		s = append(s,
			source{"claude-code", filepath.Join(p, ".mcp.json"), "project", kindMCPServers},
			source{"cursor", filepath.Join(p, ".cursor", "mcp.json"), "project", kindMCPServers},
			source{"vscode", filepath.Join(p, ".vscode", "mcp.json"), "project", kindServers},
			source{"gemini-cli", filepath.Join(p, ".gemini", "settings.json"), "project", kindMCPServers},
		)
	}
	return s
}

// Result of a discovery run.
type Result struct {
	Servers  []Server
	Files    []string // config files that were found and parsed
	Warnings []string
}

// Discover reads every known config location plus any explicit files.
func Discover(e Env, explicit []string) Result {
	var r Result
	srcs := sources(e)
	for _, p := range explicit {
		abs, err := filepath.Abs(p)
		if err != nil {
			abs = p
		}
		srcs = append(srcs, source{"explicit", abs, "explicit", kindAuto})
	}
	seen := map[string]bool{}
	for _, src := range srcs {
		if seen[src.path] {
			continue
		}
		seen[src.path] = true
		data, err := os.ReadFile(src.path)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) || src.scope == "explicit" {
				r.Warnings = append(r.Warnings, fmt.Sprintf("%s: %v", src.path, err))
			}
			continue
		}
		servers, warns, err := parse(src, data, e)
		r.Warnings = append(r.Warnings, warns...)
		if err != nil {
			r.Warnings = append(r.Warnings, err.Error())
			continue
		}
		r.Files = append(r.Files, src.path)
		r.Servers = append(r.Servers, servers...)
	}
	return r
}

func parse(src source, data []byte, e Env) ([]Server, []string, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(StripJSONC(data), &top); err != nil {
		return nil, nil, fmt.Errorf("%s: invalid JSON: %v", src.path, err)
	}
	loc := displayPath(src, e)
	var out []Server
	var warns []string
	add := func(block json.RawMessage, project string, prefix ...string) {
		ss, w := parseBlock(block, src, loc, project, prefix)
		out = append(out, ss...)
		warns = append(warns, w...)
	}
	vscodeSettings := func() {
		var m map[string]json.RawMessage
		if raw, ok := top["mcp"]; ok && json.Unmarshal(raw, &m) == nil {
			add(m["servers"], "", "mcp", "servers")
		}
	}
	switch src.kind {
	case kindMCPServers:
		add(top["mcpServers"], "", "mcpServers")
	case kindServers:
		add(top["servers"], "", "servers")
	case kindVSCodeSettings:
		vscodeSettings()
	case kindClaudeCode:
		add(top["mcpServers"], "", "mcpServers")
		if raw, ok := top["projects"]; ok {
			var projects map[string]struct {
				MCPServers json.RawMessage `json:"mcpServers"`
			}
			if err := json.Unmarshal(raw, &projects); err == nil {
				for _, k := range sortedKeys(projects) {
					add(projects[k].MCPServers, k, "projects", k, "mcpServers")
				}
			}
		}
	case kindAuto:
		add(top["mcpServers"], "", "mcpServers")
		add(top["servers"], "", "servers")
		vscodeSettings()
	}
	return out, warns, nil
}

type rawServer struct {
	Type      string         `json:"type"`
	Transport string         `json:"transport"`
	Command   string         `json:"command"`
	Args      []any          `json:"args"`
	Env       map[string]any `json:"env"`
	URL       string         `json:"url"`
	ServerURL string         `json:"serverUrl"` // Windsurf
	HTTPURL   string         `json:"httpUrl"`   // Gemini CLI
	Headers   map[string]any `json:"headers"`
	Disabled  bool           `json:"disabled"`
}

func parseBlock(block json.RawMessage, src source, loc, project string, prefix []string) ([]Server, []string) {
	if len(block) == 0 || string(block) == "null" {
		return nil, nil
	}
	var entries map[string]json.RawMessage
	if err := json.Unmarshal(block, &entries); err != nil {
		return nil, []string{fmt.Sprintf("%s: unexpected server list shape: %v", src.path, err)}
	}
	var out []Server
	var warns []string
	for _, name := range sortedKeys(entries) {
		var r rawServer
		if err := json.Unmarshal(entries[name], &r); err != nil {
			warns = append(warns, fmt.Sprintf("%s: server %q: %v", src.path, name, err))
			continue
		}
		u := firstNonEmpty(r.HTTPURL, r.URL, r.ServerURL)
		s := Server{
			Name:      name,
			Client:    src.client,
			Scope:     src.scope,
			Source:    src.path,
			Location:  loc,
			Project:   project,
			Transport: transportOf(r, u),
			Command:   r.Command,
			Args:      stringSlice(r.Args),
			Env:       stringMap(r.Env),
			URL:       u,
			Headers:   stringMap(r.Headers),
			Disabled:  r.Disabled,
			Path:      append(append([]string(nil), prefix...), name),
		}
		if project != "" {
			s.Scope = "local"
		}
		out = append(out, s)
	}
	return out, warns
}

func transportOf(r rawServer, url string) string {
	t := strings.ToLower(r.Type)
	if t == "" {
		t = strings.ToLower(r.Transport)
	}
	switch t {
	case "stdio":
		return "stdio"
	case "sse":
		return "sse"
	case "http", "streamable-http", "streamablehttp", "streamable_http":
		return "http"
	}
	if r.Command != "" {
		return "stdio"
	}
	if r.HTTPURL != "" {
		return "http"
	}
	if url != "" {
		if strings.HasSuffix(strings.TrimRight(url, "/"), "/sse") {
			return "sse"
		}
		return "http"
	}
	return "unknown"
}

func displayPath(src source, e Env) string {
	if src.scope != "user" && e.ProjectDir != "" {
		if rel, ok := under(e.ProjectDir, src.path); ok {
			return rel
		}
	}
	if e.Home != "" {
		if rel, ok := under(e.Home, src.path); ok {
			return "~/" + rel
		}
	}
	return filepath.ToSlash(src.path)
}

func under(base, p string) (string, bool) {
	rel, err := filepath.Rel(base, p)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return filepath.ToSlash(rel), true
}

var refRe = regexp.MustCompile(`\$\{(env:)?([A-Za-z_][A-Za-z0-9_]*)(:-([^}]*))?\}`)

// Expand resolves ${VAR}, ${VAR:-default} and VS Code style ${env:VAR}
// references. Unknown references are left untouched.
func Expand(s string, lookup func(string) (string, bool)) string {
	return refRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := refRe.FindStringSubmatch(m)
		if v, ok := lookup(sub[2]); ok {
			return v
		}
		if sub[3] != "" {
			return sub[4]
		}
		return m
	})
}

func stringSlice(in []any) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = scalar(v)
	}
	return out
}

func stringMap(in map[string]any) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = scalar(v)
	}
	return out
}

func scalar(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return ""
	default:
		b, _ := json.Marshal(t)
		return string(b)
	}
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
