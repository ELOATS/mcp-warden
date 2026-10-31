package config

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoverAllClients(t *testing.T) {
	home, cfg, proj := t.TempDir(), t.TempDir(), t.TempDir()
	write(t, filepath.Join(cfg, "Claude", "claude_desktop_config.json"),
		`{"mcpServers":{"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/"]}}}`)
	write(t, filepath.Join(home, ".claude.json"), `{
		"mcpServers": {"remote": {"type": "http", "url": "https://mcp.example.com/mcp", "headers": {"Authorization": "Bearer ${TOKEN}"}}},
		"projects": {"/work/app": {"mcpServers": {"pg": {"command": "uvx", "args": ["mcp-server-postgres"], "env": {"PORT": 5432}}}}}
	}`)
	write(t, filepath.Join(home, ".cursor", "mcp.json"), `{"mcpServers":{"legacy":{"url":"https://x.example.com/sse"}}}`)
	write(t, filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"), `{"mcpServers":{"ws":{"serverUrl":"https://ws.example.com/mcp"}}}`)
	write(t, filepath.Join(cfg, "Code", "User", "settings.json"), `{
		// VS Code settings allow comments
		"editor.fontSize": 14,
		"mcp": { "servers": { "gh": { "type": "stdio", "command": "docker", "args": ["run", "-i", "ghcr.io/github/github-mcp-server"], }, }, },
	}`)
	write(t, filepath.Join(proj, ".mcp.json"), `{"mcpServers":{"local":{"command":"node","args":["server.js"]}}}`)
	write(t, filepath.Join(proj, ".vscode", "mcp.json"), `{"servers":{"time":{"command":"uvx","args":["mcp-server-time"]}}}`)
	write(t, filepath.Join(proj, ".cursor", "mcp.json"), `{not json`)

	res := Discover(Env{Home: home, ConfigDir: cfg, ProjectDir: proj}, nil)

	got := map[string]Server{}
	for _, s := range res.Servers {
		got[s.Client+"/"+s.Name] = s
	}
	want := map[string]string{ // id -> transport
		"claude-desktop/fs": "stdio", "claude-code/remote": "http", "claude-code/pg": "stdio",
		"cursor/legacy": "sse", "windsurf/ws": "http", "vscode/gh": "stdio",
		"claude-code/local": "stdio", "vscode/time": "stdio",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d servers %v, want %d", len(got), keysOf(got), len(want))
	}
	for id, tr := range want {
		s, ok := got[id]
		if !ok {
			t.Errorf("missing %s", id)
			continue
		}
		if s.Transport != tr {
			t.Errorf("%s transport = %s, want %s", id, s.Transport, tr)
		}
	}
	if pg := got["claude-code/pg"]; pg.Project != "/work/app" || pg.Env["PORT"] != "5432" || pg.Scope != "local" {
		t.Errorf("pg = %+v", pg)
	}
	if l := got["claude-code/local"]; l.Location != ".mcp.json" || l.Scope != "project" {
		t.Errorf("project location = %q scope %q", l.Location, l.Scope)
	}
	if c := got["cursor/legacy"]; c.Location != "~/.cursor/mcp.json" {
		t.Errorf("user location = %q", c.Location)
	}
	if len(res.Warnings) != 1 {
		t.Errorf("want 1 warning for the broken file, got %v", res.Warnings)
	}
}

func TestSkipUserAndExplicit(t *testing.T) {
	home, proj := t.TempDir(), t.TempDir()
	write(t, filepath.Join(home, ".cursor", "mcp.json"), `{"mcpServers":{"a":{"command":"x"}}}`)
	extra := filepath.Join(t.TempDir(), "custom.json")
	write(t, extra, `{"servers":{"b":{"command":"y"}}}`)
	res := Discover(Env{Home: home, ConfigDir: home, ProjectDir: proj, SkipUser: true}, []string{extra})
	if len(res.Servers) != 1 || res.Servers[0].Name != "b" || res.Servers[0].Client != "explicit" {
		t.Fatalf("got %+v", res.Servers)
	}
}

func TestStripJSONC(t *testing.T) {
	in := `{
  // comment with "quotes"
  "a": "http://not-a-comment", /* block
  comment */ "b": [1, 2,],
  "c": "trailing, }",
}`
	want := map[string]bool{`"http://not-a-comment"`: true}
	out := string(StripJSONC([]byte(in)))
	for k := range want {
		if !contains(out, k) {
			t.Errorf("lost %s in %s", k, out)
		}
	}
	if contains(out, "comment with") || contains(out, "block") || contains(out, "2,]") {
		t.Errorf("not stripped: %s", out)
	}
	if !contains(out, `"trailing, }"`) {
		t.Errorf("string content modified: %s", out)
	}
}

func TestExpand(t *testing.T) {
	env := map[string]string{"TOKEN": "abc"}
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	cases := map[string]string{
		"Bearer ${TOKEN}":  "Bearer abc",
		"${env:TOKEN}":     "abc",
		"${MISSING:-dflt}": "dflt",
		"${MISSING}":       "${MISSING}",
		"${input:apiKey}":  "${input:apiKey}",
		"plain":            "plain",
	}
	for in, want := range cases {
		if got := Expand(in, lookup); got != want {
			t.Errorf("Expand(%q) = %q, want %q", in, got, want)
		}
	}
}

func contains(s, sub string) bool { return len(sub) == 0 || indexOf(s, sub) >= 0 }

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func keysOf(m map[string]Server) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
