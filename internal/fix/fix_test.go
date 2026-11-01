package fix

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ELOATS/mcp-warden/internal/audit"
	"github.com/ELOATS/mcp-warden/internal/config"
	"github.com/ELOATS/mcp-warden/internal/registry"
)

var now = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

func ago(d int) string { return now.AddDate(0, 0, -d).Format(time.RFC3339) }

func fakeRegistry(t *testing.T) *registry.Client {
	t.Helper()
	docs := map[string]any{
		"/@acme%2Fsrv": map[string]any{
			"dist-tags": map[string]string{"latest": "2.1.0"},
			"time":      map[string]string{"created": ago(400), "1.9.0": ago(200), "2.0.0": ago(30), "2.1.0": ago(2), "2.0.1-beta": ago(20)},
			"versions":  map[string]any{"1.9.0": map[string]any{}, "2.0.0": map[string]any{}, "2.1.0": map[string]any{}, "2.0.1-beta": map[string]any{}},
		},
		"/old-mcp": map[string]any{
			"dist-tags": map[string]string{"latest": "1.0.0"},
			"time":      map[string]string{"created": ago(900), "1.0.0": ago(800)},
			"versions":  map[string]any{"1.0.0": map[string]any{}},
		},
		"/pypi/mcp-server-fetch/json": map[string]any{
			"info":     map[string]any{"version": "2026.10.28"},
			"releases": map[string]any{"2026.10.28": []map[string]any{{"upload_time_iso_8601": ago(3)}}, "2025.9.1": []map[string]any{{"upload_time_iso_8601": ago(60)}}},
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d, ok := docs[r.URL.EscapedPath()]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(d)
	}))
	t.Cleanup(srv.Close)
	c := registry.New("mcp-warden/test")
	c.NPM, c.PyPI, c.NPMDownloads = srv.URL, srv.URL, ""
	c.Now = func() time.Time { return now }
	return c
}

const projectCfg = `{
  "mcpServers": {
    "srv":    { "command": "npx", "args": ["-y", "@acme/srv"], "env": { "GITHUB_TOKEN": "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" } },
    "latest": { "command": "npx", "args": ["-y", "old-mcp@latest"] },
    "fetch":  { "command": "uvx", "args": ["mcp-server-fetch"] },
    "ranged": { "command": "npx", "args": ["-y", "old-mcp@^1.0"] },
    "pinned": { "command": "npx", "args": ["-y", "old-mcp@1.0.0"] },
    "ghost":  { "command": "npx", "args": ["-y", "no-such-mcp"] }
  }
}
`

// cursor is a GUI client: its secret must not be moved automatically.
const cursorCfg = `{
  // comments survive
  "mcpServers": {
    "srv": { "command": "npx", "args": ["-y", "@acme/srv"], "env": {"API_KEY": "sk-cursorcursorcursorcursor"} },
  },
}
`

type fixture struct {
	project, home, projectFile, cursorFile, secrets string
	servers                                         []config.Server
}

func setup(t *testing.T) fixture {
	t.Helper()
	f := fixture{project: t.TempDir(), home: t.TempDir()}
	f.projectFile = filepath.Join(f.project, ".mcp.json")
	f.cursorFile = filepath.Join(f.home, ".cursor", "mcp.json")
	f.secrets = filepath.Join(f.home, ".mcp-warden", "secrets.env")
	_ = os.MkdirAll(filepath.Dir(f.cursorFile), 0o755)
	if err := os.WriteFile(f.projectFile, []byte(projectCfg), 0o640); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(f.cursorFile, []byte(cursorCfg), 0o600)
	res := config.Discover(config.Env{Home: f.home, ConfigDir: filepath.Join(f.home, ".config"), ProjectDir: f.project}, nil)
	if len(res.Warnings) > 0 {
		t.Fatalf("discover: %v", res.Warnings)
	}
	f.servers = res.Servers
	return f
}

func changesByServer(p Plan) map[string]Change {
	m := map[string]Change{}
	for _, c := range p.Changes {
		m[c.Server.Client+"/"+c.Server.Name+"/"+c.Field] = c
	}
	return m
}

func skipsByServer(p Plan) map[string]string {
	m := map[string]string{}
	for _, s := range p.Skips {
		m[s.Server.Client+"/"+s.Server.Name] += s.Reason + ";"
	}
	return m
}

func TestPlan(t *testing.T) {
	f := setup(t)
	p := Build(context.Background(), f.servers, Options{Registry: fakeRegistry(t), SecretsFile: f.secrets})
	ch := changesByServer(p)
	want := map[string]string{
		"claude-code/srv/args[1]":    "@acme/srv@2.0.0", // 2.1.0 is 2 days old, 2.0.1-beta is a prerelease
		"claude-code/latest/args[1]": "old-mcp@1.0.0",   // @latest is replaced
		"claude-code/fetch/args[0]":  "mcp-server-fetch==2025.9.1",
		"cursor/srv/args[1]":         "@acme/srv@2.0.0",
	}
	if len(ch) != len(want) {
		t.Errorf("got %d changes, want %d: %v", len(ch), len(want), ch)
	}
	for k, v := range want {
		if ch[k].New != v {
			t.Errorf("%s: %q, want %q", k, ch[k].New, v)
		}
	}
	if !strings.Contains(ch["claude-code/srv/args[1]"].Note, "2.1.0 is only 2 days old; 2.0.0 (published") {
		t.Errorf("note: %q", ch["claude-code/srv/args[1]"].Note)
	}
	sk := skipsByServer(p)
	for k, want := range map[string]string{
		"claude-code/ranged": "version constraint",
		"claude-code/ghost":  "does not exist",
		"claude-code/srv":    "--secrets",
	} {
		if !strings.Contains(sk[k], want) {
			t.Errorf("skip %s: %q, want %q", k, sk[k], want)
		}
	}
	if _, ok := sk["claude-code/pinned"]; ok {
		t.Error("already pinned server reported")
	}

	off := Build(context.Background(), f.servers, Options{SecretsFile: f.secrets})
	if len(off.Changes) != 0 || !strings.Contains(skipsByServer(off)["claude-code/srv"], "--offline") {
		t.Errorf("offline plan: %+v", off)
	}
	only := Build(context.Background(), f.servers, Options{Registry: fakeRegistry(t), Servers: []string{"fe*"}})
	if len(only.Changes) != 1 || only.Changes[0].Server.Name != "fetch" {
		t.Errorf("--server filter: %+v", only.Changes)
	}
}

func TestApply(t *testing.T) {
	f := setup(t)
	origProject, _ := os.ReadFile(f.projectFile)
	origCursor, _ := os.ReadFile(f.cursorFile)
	p := Build(context.Background(), f.servers, Options{Registry: fakeRegistry(t), Secrets: true, SecretsFile: f.secrets})

	sk := skipsByServer(p)
	if !strings.Contains(sk["cursor/srv"], "by hand") {
		t.Errorf("GUI client secret must be skipped: %q", sk["cursor/srv"])
	}
	results, err := p.Apply(f.secrets, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("results: %+v", results)
	}

	// Only the planned values changed; formatting and comments are intact.
	got, _ := os.ReadFile(f.projectFile)
	want := string(origProject)
	for old, nw := range map[string]string{
		`"@acme/srv"`: `"@acme/srv@2.0.0"`, `"old-mcp@latest"`: `"old-mcp@1.0.0"`, `"mcp-server-fetch"`: `"mcp-server-fetch==2025.9.1"`,
		`"ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`: `"${GITHUB_TOKEN}"`,
	} {
		want = strings.Replace(want, old, nw, 1)
	}
	if string(got) != want {
		t.Errorf("project config:\n got %s\nwant %s", got, want)
	}
	gotCursor, _ := os.ReadFile(f.cursorFile)
	if string(gotCursor) != strings.Replace(string(origCursor), `"@acme/srv"`, `"@acme/srv@2.0.0"`, 1) {
		t.Errorf("cursor config:\n%s", gotCursor)
	}

	// Backups hold the originals; permissions are preserved.
	for _, r := range results {
		b, err := os.ReadFile(r.Backup)
		orig := origProject
		if r.File == f.cursorFile {
			orig = origCursor
		}
		if err != nil || string(b) != string(orig) {
			t.Errorf("backup %s: %v", r.Backup, err)
		}
	}
	if fi, _ := os.Stat(f.projectFile); fi.Mode().Perm() != 0o640 {
		t.Errorf("mode changed to %v", fi.Mode().Perm())
	}

	// The secret lives in a 0600 env file and nowhere in the config.
	fi, err := os.Stat(f.secrets)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("secrets file: %v %v", err, fi)
	}
	env, _ := readEnvFile(f.secrets)
	if env["GITHUB_TOKEN"] != "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Errorf("secrets file: %v", env)
	}

	// Re-scanning: pins hold and the moved secret is no longer a finding.
	res := config.Discover(config.Env{Home: f.home, ConfigDir: filepath.Join(f.home, ".config"), ProjectDir: f.project}, nil)
	for _, s := range res.Servers {
		for _, fd := range audit.StaticChecks(s, audit.Options{}) {
			if s.Client == "claude-code" && fd.Rule == "PLAINTEXT-SECRET" {
				t.Errorf("secret still in config: %+v", fd)
			}
			if fd.Rule == "UNPINNED-PACKAGE" && s.Name != "ranged" && s.Name != "ghost" {
				t.Errorf("%s/%s still unpinned", s.Client, s.Name)
			}
		}
	}
}

func TestApplyRefusesStalePlan(t *testing.T) {
	f := setup(t)
	p := Build(context.Background(), f.servers, Options{Registry: fakeRegistry(t)})
	edited := strings.Replace(projectCfg, `"mcp-server-fetch"`, `"mcp-server-fetch==1.0.0"`, 1)
	_ = os.WriteFile(f.projectFile, []byte(edited), 0o640)
	if _, err := p.Apply(f.secrets, now); !errors.Is(err, ErrChanged) {
		t.Fatalf("stale plan applied: %v", err)
	}
	if got, _ := os.ReadFile(f.projectFile); string(got) != edited {
		t.Error("file modified despite stale plan")
	}
	matches, _ := filepath.Glob(filepath.Join(f.project, "*.bak"))
	cm, _ := filepath.Glob(filepath.Join(filepath.Dir(f.cursorFile), "*.bak"))
	if len(matches)+len(cm) != 0 {
		t.Errorf("backups written for an aborted apply: %v %v", matches, cm)
	}
}

func TestSecretNameClash(t *testing.T) {
	f := setup(t)
	_ = os.MkdirAll(filepath.Dir(f.secrets), 0o700)
	_ = os.WriteFile(f.secrets, []byte("export GITHUB_TOKEN='something-else'\n"), 0o600)
	p := Build(context.Background(), f.servers, Options{Registry: fakeRegistry(t), Secrets: true, SecretsFile: f.secrets})
	c := changesByServer(p)["claude-code/srv/env.GITHUB_TOKEN"]
	if c.New != "${GITHUB_TOKEN_SRV}" {
		t.Fatalf("clashing name: %q", c.New)
	}
	if _, err := p.Apply(f.secrets, now); err != nil {
		t.Fatal(err)
	}
	env, _ := readEnvFile(f.secrets)
	if env["GITHUB_TOKEN"] != "something-else" || !strings.HasPrefix(env["GITHUB_TOKEN_SRV"], "ghp_") {
		t.Errorf("existing secret clobbered: %v", env)
	}
}

func TestShellQuoteRoundTrip(t *testing.T) {
	for _, v := range []string{"plain", "it's", `a"b$c\d`, "x y'z'"} {
		if got := unquote(shellQuote(v)); got != v {
			t.Errorf("round trip %q -> %q", v, got)
		}
	}
}
