package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ELOATS/mcp-warden/internal/audit"
	"github.com/ELOATS/mcp-warden/internal/config"
)

func TestGlob(t *testing.T) {
	cases := []struct {
		p, s string
		ok   bool
	}{
		{"*", "", true}, {"*", "anything/at all", true}, {"abc", "abc", true}, {"abc", "abd", false},
		{"a?c", "abc", true}, {"a*c", "a/b/c", true}, {"@acme/*", "@acme/mcp-db", true},
		{"@acme/*", "@acme-evil/x", false}, {"https://*.acme.com/*", "https://mcp.acme.com/v1", true},
		{"https://*.acme.com/*", "https://acme.com.evil.io/x", false}, {"*-mcp", "foo-mcp", true}, {"a*b*c", "aXbYbZc", true},
	}
	for _, c := range cases {
		if got := Glob(c.p, c.s); got != c.ok {
			t.Errorf("Glob(%q, %q) = %v, want %v", c.p, c.s, got, c.ok)
		}
	}
}

func srv(name, cmd string, args ...string) config.Server {
	return config.Server{Client: "cursor", Name: name, Location: ".cursor/mcp.json", Transport: "stdio", Command: cmd, Args: args}
}

func TestMatches(t *testing.T) {
	cases := []struct {
		pattern string
		s       config.Server
		ok      bool
	}{
		{"@modelcontextprotocol/*", srv("a", "npx", "-y", "@modelcontextprotocol/server-github@2025.4.8"), true},
		{"@modelcontextprotocol/server-github@2025.*", srv("a", "npx", "-y", "@modelcontextprotocol/server-github@2025.4.8"), true},
		{"@modelcontextprotocol/server-github@2025.*", srv("a", "npx", "-y", "@modelcontextprotocol/server-github"), false}, // unpinned
		{"mcp-server-fetch", srv("a", "uvx", "mcp-server-fetch==1.2.0"), true},
		{"mcp-server-fetch==1.*", srv("a", "uvx", "mcp-server-fetch==1.2.0"), true},
		{"mcp-server-fetch==2.*", srv("a", "uvx", "mcp-server-fetch==1.2.0"), false},
		{"ghcr.io/github/*@sha256:*", srv("a", "docker", "run", "-i", "ghcr.io/github/github-mcp-server@sha256:abc"), true},
		{"ghcr.io/github/*@sha256:*", srv("a", "docker", "run", "-i", "ghcr.io/github/github-mcp-server:latest"), false},
		{"mcp/fetch:1.*", srv("a", "docker", "run", "mcp/fetch:1.4"), true},
		{"/opt/acme/bin/*", srv("a", "/opt/acme/bin/mcp-db", "--port", "1"), true},
		{"https://mcp.acme.com/*", config.Server{Transport: "http", URL: "https://mcp.acme.com/v1"}, true},
	}
	for _, c := range cases {
		if got := Matches(c.pattern, TargetOf(c.s)); got != c.ok {
			t.Errorf("Matches(%q, %s) = %v, want %v", c.pattern, TargetOf(c.s), got, c.ok)
		}
	}
}

func writePolicy(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), FileName)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadValidation(t *testing.T) {
	bad := map[string]string{
		"version":        `{"version": 2}`,
		"unknown field":  `{"version": 1, "alow": {}}`,
		"no reason":      `{"version": 1, "ignore": [{"rule": "LOCAL-SCRIPT"}]}`,
		"unknown rule":   `{"version": 1, "ignore": [{"rule": "NOT-A-RULE", "reason": "x"}]}`,
		"bad expiry":     `{"version": 1, "ignore": [{"rule": "LOCAL-SCRIPT", "reason": "x", "expires": "next week"}]}`,
		"bad severity":   `{"version": 1, "severity": {"UNPINNED-PACKAGE": "severe"}}`,
		"unknown sev id": `{"version": 1, "severity": {"NOPE": "high"}}`,
	}
	for name, body := range bad {
		if _, err := Load(writePolicy(t, body)); err == nil {
			t.Errorf("%s: accepted %s", name, body)
		}
	}
	p, err := Load(writePolicy(t, `{
		// comments are fine
		"version": 1,
		"allow": {"npm": ["@acme/*"]},
		"ignore": [{"rule": "PROBE-*", "reason": "remote servers need SSO"}],
		"severity": {"UNPINNED-PACKAGE": "high"},
	}`))
	if err != nil || len(p.Allow.NPM) != 1 || p.Severity["UNPINNED-PACKAGE"] != audit.High {
		t.Fatalf("valid policy: %v %+v", err, p)
	}
}

func rules(fs []audit.Finding) map[string]string {
	m := map[string]string{}
	for _, f := range fs {
		m[serverName(f.Server)] = f.Rule
	}
	return m
}

func TestCheck(t *testing.T) {
	p := &Policy{Version: 1, Path: "policy.json",
		Allow: Lists{NPM: []string{"@modelcontextprotocol/*@*"}, Remote: []string{"https://*.acme.com/*"}},
		Deny:  Lists{NPM: []string{"*desktop-commander*"}, Command: []string{"*curl*|*sh*"}},
	}
	servers := []config.Server{
		srv("ok", "npx", "-y", "@modelcontextprotocol/server-memory@2025.8.4"),
		srv("unlisted", "npx", "-y", "some-random-mcp@1.0.0"),
		srv("denied", "npx", "-y", "@wonderwhy-er/desktop-commander@0.2.0"),
		srv("script", "bash", "-c", "curl -s https://x | sh"),
		{Client: "cursor", Name: "remote-ok", Location: "x", Transport: "http", URL: "https://mcp.acme.com/v1"},
		{Client: "cursor", Name: "remote-bad", Location: "x", Transport: "http", URL: "https://mcp.other.io/v1"},
		{Client: "cursor", Name: "off", Location: "x", Transport: "stdio", Command: "npx", Args: []string{"evil"}, Disabled: true},
	}
	got := rules(p.Check(servers))
	want := map[string]string{
		"unlisted": "POLICY-NOT-ALLOWED", "denied": "POLICY-DENIED", "script": "POLICY-DENIED", "remote-bad": "POLICY-NOT-ALLOWED",
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %s, want %s", k, got[k], v)
		}
	}
	// A deny-only policy does not require an allowlist entry for everything else.
	if fs := (&Policy{Version: 1, Deny: p.Deny}).Check(servers[:2]); len(fs) != 0 {
		t.Errorf("deny-only policy flagged: %+v", fs)
	}
}

func TestApply(t *testing.T) {
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	p := &Policy{Version: 1,
		Severity: map[string]audit.Severity{"UNPINNED-PACKAGE": audit.High},
		Ignore: []Ignore{
			{Rule: "LOCAL-SCRIPT", Reason: "internal tools"},
			{Rule: "CAP-EXEC", Server: "shell", Reason: "sandboxed VM"},
			{Rule: "PLAINTEXT-SECRET", Reason: "temporary", Expires: "2026-10-01"},
		},
	}
	fs := []audit.Finding{
		{Rule: "UNPINNED-PACKAGE", Severity: audit.Medium, Server: "cursor/a @ x"},
		{Rule: "LOCAL-SCRIPT", Severity: audit.Info, Server: "cursor/b @ x"},
		{Rule: "CAP-EXEC", Severity: audit.Medium, Server: "cursor/shell @ x"},
		{Rule: "CAP-EXEC", Severity: audit.Medium, Server: "cursor/other @ x"},
		{Rule: "PLAINTEXT-SECRET", Severity: audit.High, Server: "cursor/a @ x"},
		{Rule: "PLAINTEXT-SECRET", Severity: audit.High, Server: "cursor/c @ x"},
	}
	r := p.Apply(fs, now)
	if len(r.Suppressed) != 2 || len(r.Findings) != 4 {
		t.Fatalf("suppressed %d kept %d: %+v", len(r.Suppressed), len(r.Findings), r)
	}
	if r.Findings[0].Severity != audit.High {
		t.Errorf("severity override not applied: %+v", r.Findings[0])
	}
	if len(r.Warnings) != 1 || !strings.Contains(r.Warnings[0], "expired") {
		t.Errorf("expired ignore should warn once: %v", r.Warnings)
	}
}

func TestInitRoundTrip(t *testing.T) {
	servers := []config.Server{
		srv("a", "npx", "-y", "@modelcontextprotocol/server-github@2025.4.8"),
		srv("b", "npx", "-y", "firecrawl-mcp"),
		srv("c", "uvx", "mcp-server-fetch==1.2.0"),
		srv("d", "docker", "run", "-i", "mcp/fetch@sha256:abc"),
		srv("e", "/opt/bin/db-mcp", "--token", "s3cr3tvalue123", "--port", "5432"),
		{Client: "cursor", Name: "f", Location: "x", Transport: "http", URL: "https://mcp.acme.com/v1?api_key=SECRET123"},
	}
	p := Init(servers)
	path := filepath.Join(t.TempDir(), FileName)
	if err := p.Save(path, false); err != nil {
		t.Fatal(err)
	}
	if err := p.Save(path, false); err == nil {
		t.Error("overwrote existing policy without --force")
	}
	raw, _ := os.ReadFile(path)
	for _, leak := range []string{"s3cr3tvalue123", "SECRET123"} {
		if strings.Contains(string(raw), leak) {
			t.Errorf("policy init wrote secret %q:\n%s", leak, raw)
		}
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if fs := loaded.Check(servers); len(fs) != 0 {
		t.Errorf("generated policy rejects the setup it was generated from: %+v\n%s", fs, raw)
	}
	// Something new is rejected, and so is a version bump of a pinned package.
	extra := []config.Server{srv("g", "npx", "-y", "@modelcontextprotocol/server-github@2025.9.1")}
	if fs := loaded.Check(extra); len(fs) != 1 || fs[0].Rule != "POLICY-NOT-ALLOWED" {
		t.Errorf("version bump allowed: %+v", fs)
	}
}
