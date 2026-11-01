package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ELOATS/mcp-warden/internal/testserver"
)

func TestMain(m *testing.M) {
	testserver.MaybeRun()
	os.Exit(m.Run())
}

// setup creates an isolated HOME and a project whose .mcp.json launches this
// test binary as a fake MCP server. The returned file switches its tool set.
func setup(t *testing.T) (project, stateFile string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("NO_COLOR", "1")
	t.Setenv("MCP_WARDEN_OFFLINE", "1") // never hit real registries from tests
	project = t.TempDir()
	stateFile = filepath.Join(t.TempDir(), "mode")
	if err := os.WriteFile(stateFile, []byte("clean"), 0o644); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cfg := map[string]any{"mcpServers": map[string]any{
		"fake": map[string]any{"command": exe, "env": map[string]string{
			testserver.EnvMode: "clean", testserver.EnvStateFile: stateFile}},
		"gh": map[string]any{"command": "npx", "args": []string{"-y", "@modelcontextprotocol/server-github"},
			"env": map[string]string{"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_" + strings.Repeat("a", 36)}, "disabled": true},
	}}
	b, _ := json.Marshal(cfg)
	if err := os.WriteFile(filepath.Join(project, ".mcp.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	return project, stateFile
}

func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestScanAndRugPull(t *testing.T) {
	project, state := setup(t)

	code, out, errOut := runCLI(t, "scan", "--project", project, "--probe", "--fail-on", "high")
	if code != 1 { // the literal GitHub token is HIGH
		t.Fatalf("scan exit %d\n%s\n%s", code, out, errOut)
	}
	for _, want := range []string{"PLAINTEXT-SECRET", "UNPINNED-PACKAGE", "2 tools", "LETHAL-TRIFECTA"} {
		if !strings.Contains(out, want) {
			t.Errorf("scan output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, strings.Repeat("a", 36)) {
		t.Error("scan output leaks the token")
	}

	code, out, _ = runCLI(t, "scan", "--project", project, "--probe", "--json")
	if code != 0 {
		t.Fatalf("json scan exit %d", code)
	}
	var rep struct {
		Servers []struct {
			Name  string `json:"name"`
			Probe *struct {
				Status string `json:"status"`
			} `json:"probe"`
		} `json:"servers"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil || len(rep.Servers) != 2 {
		t.Fatalf("bad json (%v): %s", err, out)
	}

	lock := filepath.Join(t.TempDir(), "lock.json")
	if code, out, errOut := runCLI(t, "pin", "--project", project, "--project-only", "--probe", "--lock", lock); code != 0 {
		t.Fatalf("pin exit %d: %s %s", code, out, errOut)
	}
	if code, out, _ := runCLI(t, "diff", "--project", project, "--project-only", "--lock", lock); code != 0 || !strings.Contains(out, "No changes") {
		t.Fatalf("clean diff exit %d:\n%s", code, out)
	}

	// The server now ships a poisoned tool description; config is unchanged.
	if err := os.WriteFile(state, []byte("poisoned"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, _ = runCLI(t, "diff", "--project", project, "--project-only", "--lock", lock)
	if code != 1 || !strings.Contains(out, "TOOL-DEFINITION-CHANGED") || strings.Contains(out, "CONFIG-CHANGED") {
		t.Fatalf("rug pull not detected (exit %d):\n%s", code, out)
	}
	code, out, _ = runCLI(t, "scan", "--project", project, "--project-only", "--probe")
	if !strings.Contains(out, "TOOL-POISONING") || !strings.Contains(out, "HIDDEN-UNICODE") {
		t.Fatalf("poisoned tool not flagged by scan:\n%s", out)
	}
}

func TestUsageErrors(t *testing.T) {
	if code, _, _ := runCLI(t); code != 2 {
		t.Errorf("no args: %d", code)
	}
	if code, _, _ := runCLI(t, "bogus"); code != 2 {
		t.Errorf("unknown command: %d", code)
	}
	if code, _, _ := runCLI(t, "scan", "--fail-on", "severe"); code != 2 {
		t.Errorf("bad severity: %d", code)
	}
	project, _ := setup(t)
	if code, _, errOut := runCLI(t, "diff", "--project", project, "--lock", filepath.Join(t.TempDir(), "none.json")); code != 2 || !strings.Contains(errOut, "pin") {
		t.Errorf("missing lockfile: %d %s", code, errOut)
	}
	if code, out, _ := runCLI(t, "version"); code != 0 || !strings.Contains(out, version) {
		t.Errorf("version: %d %s", code, out)
	}
}

func TestWatchOnceAlertsOnceAndRetries(t *testing.T) {
	project, state := setup(t)
	dir := t.TempDir()
	lock := filepath.Join(dir, "lock.json")
	if code, out, errOut := runCLI(t, "pin", "--project", project, "--project-only", "--probe", "--lock", lock); code != 0 {
		t.Fatalf("pin: %d %s %s", code, out, errOut)
	}

	var hits []string
	fail := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		b, _ := io.ReadAll(r.Body)
		hits = append(hits, string(b))
	}))
	defer srv.Close()
	watch := func() (int, string, string) {
		return runCLI(t, "watch", "--once", "--project", project, "--project-only", "--lock", lock,
			"--notify", "none", "--webhook", srv.URL, "--webhook-format", "json")
	}

	if code, out, _ := watch(); code != 0 || len(hits) != 0 || !strings.Contains(out, "nothing new") {
		t.Fatalf("clean watch: code %d hits %d\n%s", code, len(hits), out)
	}

	if err := os.WriteFile(state, []byte("poisoned"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Delivery fails: nothing is marked as alerted, so the next run retries.
	fail = true
	if code, _, errOut := watch(); code != 1 || !strings.Contains(errOut, "notification failed") {
		t.Fatalf("failing webhook: code %d\n%s", code, errOut)
	}
	fail = false
	if code, _, _ := watch(); code != 1 || len(hits) != 1 || !strings.Contains(hits[0], "TOOL-DEFINITION-CHANGED") {
		t.Fatalf("rug pull alert: code %d hits %v", code, hits)
	}
	// Same change again: still failing the check (exit 1) but no repeat alert.
	if code, out, _ := watch(); code != 1 || len(hits) != 1 || !strings.Contains(out, "nothing new") {
		t.Fatalf("duplicate alert: code %d hits %d\n%s", code, len(hits), out)
	}
	// Accepting the change (re-pin) clears it.
	runCLI(t, "pin", "--project", project, "--project-only", "--probe", "--lock", lock)
	if code, _, _ := watch(); code != 0 || len(hits) != 1 {
		t.Fatalf("after re-pin: code %d hits %d", code, len(hits))
	}
}

func TestWatchFlagErrors(t *testing.T) {
	_, _ = setup(t)
	lock := filepath.Join(t.TempDir(), "missing.json")
	cases := [][]string{
		{"watch", "--interval", "5s", "--lock", lock},
		{"watch", "--notify", "carrier-pigeon", "--lock", lock},
		{"watch", "--once", "--webhook", "https://x", "--webhook-format", "fax", "--lock", lock},
	}
	for _, c := range cases {
		if code, _, _ := runCLI(t, c...); code != 2 {
			t.Errorf("%v: exit %d, want 2", c, code)
		}
	}
}

func TestPolicyLifecycle(t *testing.T) {
	project, _ := setup(t)
	// Generate a policy from the current project setup and commit-style use it.
	if code, out, errOut := runCLI(t, "policy", "init", "--project", project, "--project-only"); code != 0 || !strings.Contains(out, "allow pattern") {
		t.Fatalf("policy init: %d %s %s", code, out, errOut)
	}
	if code, _, errOut := runCLI(t, "policy", "init", "--project", project, "--project-only"); code != 2 || !strings.Contains(errOut, "--force") {
		t.Fatalf("policy init overwrote: %d %s", code, errOut)
	}
	code, out, _ := runCLI(t, "scan", "--project", project, "--project-only")
	if code != 0 || !strings.Contains(out, "policy: ") || strings.Contains(out, "POLICY-") {
		t.Fatalf("scan with generated policy: %d\n%s", code, out)
	}

	// A new, unreviewed server is rejected by the allowlist.
	cfgPath := filepath.Join(project, ".mcp.json")
	var cfg map[string]map[string]any
	b, _ := os.ReadFile(cfgPath)
	_ = json.Unmarshal(b, &cfg)
	cfg["mcpServers"]["sneaky"] = map[string]any{"command": "npx", "args": []string{"-y", "totally-legit-mcp@1.0.0"}}
	b, _ = json.Marshal(cfg)
	_ = os.WriteFile(cfgPath, b, 0o644)
	code, out, _ = runCLI(t, "scan", "--project", project, "--project-only", "--fail-on", "high")
	if code != 1 || !strings.Contains(out, "POLICY-NOT-ALLOWED") {
		t.Fatalf("unlisted server not rejected: %d\n%s", code, out)
	}

	// Documented ignores suppress findings; severity overrides apply.
	pol := `{"version": 1,
	  "deny": {"npm": ["totally-legit-*"]},
	  "ignore": [{"rule": "UNPINNED-PACKAGE", "server": "gh", "reason": "disabled server"},
	             {"rule": "PLAINTEXT-SECRET", "reason": "fixture token"}],
	  "severity": {"LOCAL-SCRIPT": "high"}}`
	polPath := filepath.Join(t.TempDir(), "p.json")
	_ = os.WriteFile(polPath, []byte(pol), 0o644)
	code, out, _ = runCLI(t, "scan", "--project", project, "--project-only", "--policy", polPath, "--format", "json")
	var rep struct {
		Policy     string `json:"policy"`
		Suppressed int    `json:"suppressed"`
		Summary    map[string]int
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	if rep.Policy != polPath || rep.Suppressed < 2 || rep.Summary["critical"] != 1 {
		t.Errorf("policy apply: %+v\n%s", rep, out)
	}
	if strings.Contains(out, `"rule": "PLAINTEXT-SECRET"`) {
		t.Error("ignored rule still reported")
	}

	// Broken policies are hard errors, never silently skipped.
	_ = os.WriteFile(polPath, []byte(`{"version": 1, "ignroe": []}`), 0o644)
	if code, _, errOut := runCLI(t, "scan", "--project", project, "--policy", polPath); code != 2 || !strings.Contains(errOut, "policy") {
		t.Errorf("invalid policy: %d %s", code, errOut)
	}
	if code, _, _ := runCLI(t, "scan", "--project", project, "--policy", polPath, "--no-policy"); code != 0 {
		t.Errorf("--no-policy did not skip the policy: %d", code)
	}
}

func TestSARIF(t *testing.T) {
	project, _ := setup(t)
	code, out, errOut := runCLI(t, "scan", "--project", project, "--project-only", "--format", "sarif")
	if code != 0 {
		t.Fatalf("sarif scan: %d %s", code, errOut)
	}
	var log struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID         string         `json:"id"`
						Properties map[string]any `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				RuleIndex int    `json:"ruleIndex"`
				Level     string `json:"level"`
				Message   struct{ Text string }
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI       string `json:"uri"`
							URIBaseID string `json:"uriBaseId"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &log); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if log.Version != "2.1.0" || len(log.Runs) != 1 || log.Runs[0].Tool.Driver.Name != "mcp-warden" {
		t.Fatalf("bad SARIF envelope: %+v", log)
	}
	run := log.Runs[0]
	cfg, _ := os.ReadFile(filepath.Join(project, ".mcp.json"))
	ghLine := 0
	for i, l := range strings.Split(string(cfg), "\n") {
		if strings.Contains(l, `"gh":`) {
			ghLine = i + 1
		}
	}
	found := false
	for _, r := range run.Results {
		if run.Tool.Driver.Rules[r.RuleIndex].ID != r.RuleID {
			t.Errorf("ruleIndex mismatch for %s", r.RuleID)
		}
		loc := r.Locations[0].PhysicalLocation
		if loc.ArtifactLocation.URI != ".mcp.json" || loc.ArtifactLocation.URIBaseID != "%SRCROOT%" {
			t.Errorf("location not project-relative: %+v", loc)
		}
		if r.PartialFingerprints["mcpWarden/v1"] == "" {
			t.Error("missing fingerprint")
		}
		if r.RuleID == "PLAINTEXT-SECRET" {
			found = true
			if r.Level != "error" || loc.Region.StartLine != ghLine {
				t.Errorf("PLAINTEXT-SECRET: level %s line %d (want error, %d)", r.Level, loc.Region.StartLine, ghLine)
			}
			if strings.Contains(r.Message.Text, strings.Repeat("a", 36)) {
				t.Error("SARIF leaks the token")
			}
		}
	}
	if !found {
		t.Error("PLAINTEXT-SECRET missing from SARIF")
	}
	for _, rule := range run.Tool.Driver.Rules {
		if rule.Properties["security-severity"] == nil {
			t.Errorf("rule %s lacks security-severity", rule.ID)
		}
	}
	if code, _, _ := runCLI(t, "scan", "--format", "xml"); code != 2 {
		t.Errorf("bad --format accepted: %d", code)
	}
	if code, out, _ := runCLI(t, "rules"); code != 0 || !strings.Contains(out, "TOOL-POISONING") {
		t.Errorf("rules: %d", code)
	}
}

func TestScanRegistry(t *testing.T) {
	project, _ := setup(t)
	now := time.Now().UTC()
	reg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.EscapedPath() {
		case "/@modelcontextprotocol%2Fserver-github":
			// The fixture's gh server floats to latest, which was published an hour ago.
			_ = json.NewEncoder(w).Encode(map[string]any{
				"dist-tags": map[string]string{"latest": "9.0.0"},
				"time": map[string]string{"created": now.AddDate(-1, 0, 0).Format(time.RFC3339),
					"9.0.0": now.Add(-time.Hour).Format(time.RFC3339)},
				"versions":   map[string]any{"9.0.0": map[string]any{}},
				"repository": "github:modelcontextprotocol/servers",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer reg.Close()
	// The fixture's gh server is disabled; enable it for this test.
	cfgPath := filepath.Join(project, ".mcp.json")
	b, _ := os.ReadFile(cfgPath)
	_ = os.WriteFile(cfgPath, bytes.Replace(b, []byte(`"disabled":true`), []byte(`"disabled":false`), 1), 0o644)

	code, out, errOut := runCLI(t, "scan", "--project", project, "--project-only", "--registry",
		"--npm-registry", reg.URL, "--pypi-url", reg.URL, "--format", "json")
	if code != 0 {
		t.Fatalf("scan --registry: %d %s", code, errOut)
	}
	if !strings.Contains(out, `"VERSION-TOO-NEW"`) {
		t.Errorf("registry findings missing:\n%s", out)
	}
	if code, _, _ := runCLI(t, "scan", "--project", project, "--cooldown", "-1"); code != 2 {
		t.Errorf("negative cooldown accepted: %d", code)
	}
}

func TestHelpAndErrors(t *testing.T) {
	code, out, _ := runCLI(t, "scan", "-h")
	if code != 0 || !strings.Contains(out, "--offline") || strings.Contains(out, "--webhook") || !strings.Contains(out, "Examples:") {
		t.Errorf("scan -h: %d\n%s", code, out)
	}
	if _, out, _ := runCLI(t, "watch", "--help"); !strings.Contains(out, "--webhook-format") || strings.Contains(out, "--offline") {
		t.Errorf("watch --help:\n%s", out)
	}
	if _, out, _ := runCLI(t, "help", "diff"); !strings.HasPrefix(out, "mcp-warden diff") {
		t.Errorf("help diff:\n%s", out)
	}
	code, out, errOut := runCLI(t, "scan", "--prob")
	if code != 2 || out != "" || strings.Count(errOut, "\n") != 2 || !strings.Contains(errOut, "did you mean --probe?") {
		t.Errorf("typo flag should be a 2-line hint: %d %q", code, errOut)
	}
	if _, _, errOut := runCLI(t, "sacn"); !strings.Contains(errOut, `did you mean "scan"?`) {
		t.Errorf("typo command: %q", errOut)
	}
	if _, _, errOut := runCLI(t, "scan", "--regsitry"); !strings.Contains(errOut, "--registry") {
		t.Errorf("transposed letters: %q", errOut)
	}
	for _, c := range commands { // every documented flag exists in the docs table
		for _, f := range c.flags {
			if _, ok := flagDocs[f]; !ok {
				t.Errorf("%s: flag %s has no documentation", c.name, f)
			}
		}
	}
}

func TestBuildVersion(t *testing.T) {
	cases := []struct {
		main     string
		settings map[string]string
		want     string
	}{
		{"v0.3.0", nil, "0.3.0"},
		{"v0.2.1-0.20261101015411-d04663a68c04", nil, "dev (d04663a)"},
		{"v0.2.1-0.20261101015411-d04663a68c04+dirty", nil, "dev (d04663a, modified)"},
		{"(devel)", map[string]string{"vcs.revision": "abcdef1234567", "vcs.modified": "true"}, "dev (abcdef1, modified)"},
		{"(devel)", nil, "dev"},
	}
	for _, c := range cases {
		bi := &debug.BuildInfo{Main: debug.Module{Version: c.main}}
		for k, v := range c.settings {
			bi.Settings = append(bi.Settings, debug.BuildSetting{Key: k, Value: v})
		}
		if got := buildVersion(bi); got != c.want {
			t.Errorf("buildVersion(%q) = %q, want %q", c.main, got, c.want)
		}
	}
}

func TestRegistryOnByDefault(t *testing.T) {
	project, _ := setup(t)
	var hits int32
	reg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		http.NotFound(w, r)
	}))
	defer reg.Close()
	cfgPath := filepath.Join(project, ".mcp.json")
	b, _ := os.ReadFile(cfgPath)
	_ = os.WriteFile(cfgPath, bytes.Replace(b, []byte(`"disabled":true`), []byte(`"disabled":false`), 1), 0o644)

	t.Setenv("MCP_WARDEN_OFFLINE", "")
	t.Setenv("MCP_WARDEN_NPM_REGISTRY", reg.URL)
	if _, out, _ := runCLI(t, "scan", "--project", project, "--project-only"); !strings.Contains(out, "REGISTRY-NOT-FOUND") {
		t.Fatalf("registry checks should run by default:\n%s", out)
	}
	n := atomic.LoadInt32(&hits)
	if _, out, _ := runCLI(t, "scan", "--project", project, "--project-only", "--offline"); strings.Contains(out, "REGISTRY-") || atomic.LoadInt32(&hits) != n {
		t.Errorf("--offline still queried the registry")
	}
	t.Setenv("MCP_WARDEN_OFFLINE", "1")
	runCLI(t, "scan", "--project", project, "--project-only")
	if atomic.LoadInt32(&hits) != n {
		t.Errorf("MCP_WARDEN_OFFLINE=1 still queried the registry")
	}
	// Unreachable registry: one warning, scan still succeeds quickly.
	t.Setenv("MCP_WARDEN_OFFLINE", "")
	t.Setenv("MCP_WARDEN_NPM_REGISTRY", "http://127.0.0.1:1")
	code, out, _ := runCLI(t, "scan", "--project", project, "--project-only")
	if code != 0 || strings.Count(out, "could not reach 127.0.0.1:1") != 1 {
		t.Errorf("unreachable registry: %d\n%s", code, out)
	}
}

func TestWatchCreatesBaselineOnFirstRun(t *testing.T) {
	project, _ := setup(t)
	lock := filepath.Join(t.TempDir(), "lock.json")
	code, out, errOut := runCLI(t, "watch", "--once", "--project", project, "--project-only", "--lock", lock, "--notify", "none")
	if code != 0 || !strings.Contains(out, "no baseline yet: trusted the current 2 servers") {
		t.Fatalf("first run: %d\n%s%s", code, out, errOut)
	}
	if _, err := os.Stat(lock); err != nil {
		t.Fatalf("baseline not written: %v", err)
	}
	if _, out, _ := runCLI(t, "watch", "--once", "--project", project, "--project-only", "--lock", lock, "--notify", "none"); strings.Contains(out, "no baseline yet") {
		t.Errorf("second run re-pinned:\n%s", out)
	}
}

func TestFixCommand(t *testing.T) {
	project, _ := setup(t)
	now := time.Now().UTC()
	reg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != "/demo-mcp" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"dist-tags": map[string]string{"latest": "1.1.0"},
			"time":      map[string]string{"1.0.0": now.AddDate(0, 0, -90).Format(time.RFC3339), "1.1.0": now.Add(-time.Hour).Format(time.RFC3339)},
			"versions":  map[string]any{"1.0.0": map[string]any{}, "1.1.0": map[string]any{}},
		})
	}))
	defer reg.Close()
	cfg := filepath.Join(project, "extra.json")
	orig := `{"mcpServers": {"demo": {"command": "npx", "args": ["-y", "demo-mcp"]}}}`
	_ = os.WriteFile(cfg, []byte(orig), 0o644)
	t.Setenv("MCP_WARDEN_OFFLINE", "")
	t.Setenv("MCP_WARDEN_NPM_REGISTRY", reg.URL)
	base := []string{"fix", "--project", project, "--project-only", "--config", cfg, "--server", "demo"}

	code, out, errOut := runCLI(t, base...)
	if code != 0 || !strings.Contains(out, "demo-mcp  →  demo-mcp@1.0.0") || !strings.Contains(out, "preview") {
		t.Fatalf("preview: %d\n%s%s", code, out, errOut)
	}
	if b, _ := os.ReadFile(cfg); string(b) != orig {
		t.Fatal("preview modified the file")
	}
	code, out, errOut = runCLI(t, append(base, "--apply")...)
	if code != 0 || !strings.Contains(out, "1 change written") {
		t.Fatalf("apply: %d\n%s%s", code, out, errOut)
	}
	if b, _ := os.ReadFile(cfg); string(b) != strings.Replace(orig, `"demo-mcp"`, `"demo-mcp@1.0.0"`, 1) {
		t.Errorf("applied file:\n%s", b)
	}
	if _, out, _ := runCLI(t, base...); !strings.Contains(out, "Nothing to change") {
		t.Errorf("second run should be a no-op:\n%s", out)
	}
	cfg2 := filepath.Join(project, "extra2.json")
	_ = os.WriteFile(cfg2, []byte(`{"mcpServers": {"other": {"command": "npx", "args": ["-y", "demo-mcp"]}}}`), 0o644)
	code, out, _ = runCLI(t, "fix", "--project", project, "--project-only", "--config", cfg2, "--offline", "--apply")
	if code != 0 || !strings.Contains(out, "registry lookups are off (--offline)") || !strings.Contains(out, "Nothing to change") {
		t.Errorf("offline fix: %d\n%s", code, out)
	}
}
