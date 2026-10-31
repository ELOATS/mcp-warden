package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	for _, want := range []string{"PLAINTEXT-SECRET", "UNPINNED-PACKAGE", "2 tool(s)", "LETHAL-TRIFECTA"} {
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
	project, _ := setup(t)
	lock := filepath.Join(t.TempDir(), "missing.json")
	cases := [][]string{
		{"watch", "--interval", "5s", "--lock", lock},
		{"watch", "--notify", "carrier-pigeon", "--lock", lock},
		{"watch", "--once", "--webhook", "https://x", "--webhook-format", "fax", "--lock", lock},
		{"watch", "--once", "--project", project, "--lock", lock}, // no baseline yet
	}
	for _, c := range cases {
		if code, _, _ := runCLI(t, c...); code != 2 {
			t.Errorf("%v: exit %d, want 2", c, code)
		}
	}
}
