package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ELOATS/mcp-warden/internal/audit"
	"github.com/ELOATS/mcp-warden/internal/config"
)

var now = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

func ts(daysAgo int) string {
	return now.Add(-time.Duration(daysAgo) * 24 * time.Hour).Format(time.RFC3339)
}

type npmV = map[string]any

func npmDocJSON(created int, versions map[string]int, publishers map[string]string, latest string, extra map[string]npmV) map[string]any {
	times := map[string]any{"created": ts(created), "modified": ts(0)}
	vs := map[string]any{}
	for v, d := range versions {
		times[v] = ts(d)
		meta := npmV{"version": v, "_npmUser": map[string]string{"name": publishers[v]}}
		for k, val := range extra[v] {
			meta[k] = val
		}
		vs[v] = meta
	}
	return map[string]any{"name": "x", "dist-tags": map[string]string{"latest": latest}, "time": times, "versions": vs,
		"repository": map[string]string{"type": "git", "url": "git+https://github.com/acme/x.git"}}
}

func fakeRegistry(t *testing.T) (*httptest.Server, *int32) {
	var hits int32
	docs := map[string]any{
		// Healthy, established package.
		"/@acme%2Fgood": npmDocJSON(400, map[string]int{"1.0.0": 300, "1.1.0": 200, "1.2.0": 100},
			map[string]string{"1.0.0": "alice", "1.1.0": "alice", "1.2.0": "alice"}, "1.2.0", nil),
		// Hijack pattern: new publisher, fresh release, postinstall script.
		"/hijacked": npmDocJSON(800, map[string]int{"2.0.0": 400, "2.1.0": 300, "2.2.0": 200, "2.3.0": 1},
			map[string]string{"2.0.0": "bob", "2.1.0": "bob", "2.2.0": "carol", "2.3.0": "mallory"}, "2.3.0",
			map[string]npmV{"2.3.0": {"scripts": map[string]string{"postinstall": "node ./setup.js"}}}),
		// Brand-new package, deprecated, no repo.
		"/fresh-mcp": func() map[string]any {
			d := npmDocJSON(3, map[string]int{"0.1.0": 3}, map[string]string{"0.1.0": "eve"}, "0.1.0",
				map[string]npmV{"0.1.0": {"deprecated": "use fresh-mcp2"}})
			delete(d, "repository")
			return d
		}(),
		// CI-published with provenance, then a manual release without it.
		"/ci-pkg": npmDocJSON(500, map[string]int{"1.0.0": 300, "1.1.0": 200, "1.2.0": 30},
			map[string]string{"1.0.0": "GitHub Actions", "1.1.0": "GitHub Actions", "1.2.0": "maintainer"}, "1.2.0",
			map[string]npmV{"1.0.0": {"dist": map[string]any{"attestations": map[string]any{"url": "x"}}},
				"1.1.0": {"dist": map[string]any{"attestations": map[string]any{"url": "x"}}}}),
		// Human releases, then a move to trusted publishing: not suspicious.
		"/ci-switch": npmDocJSON(500, map[string]int{"1.0.0": 300, "1.1.0": 200, "1.2.0": 100, "2.0.0": 30},
			map[string]string{"1.0.0": "alice", "1.1.0": "alice", "1.2.0": "alice", "2.0.0": "GitHub Actions"}, "2.0.0",
			map[string]npmV{"2.0.0": {"_npmUser": map[string]any{"name": "GitHub Actions", "trustedPublisher": map[string]string{"id": "github"}},
				"scripts": map[string]string{"prepare": "npm run build"}}}),
		"/downloads/point/last-week/ci-pkg":       map[string]int{"downloads": 9000},
		"/downloads/point/last-week/ci-switch":    map[string]int{"downloads": 9000},
		"/evil-mcp":                               map[string]any{"name": "evil-mcp", "dist-tags": map[string]string{"latest": "0.0.1-security"}, "versions": map[string]any{"0.0.1-security": map[string]any{}}},
		"/gone-mcp":                               map[string]any{"name": "gone-mcp", "time": map[string]any{"unpublished": map[string]any{"time": ts(5)}}},
		"/downloads/point/last-week/@acme%2Fgood": map[string]int{"downloads": 50000},
		"/downloads/point/last-week/hijacked":     map[string]int{"downloads": 20000},
		"/downloads/point/last-week/fresh-mcp":    map[string]int{"downloads": 12},
		"/pypi/mcp-server-fetch/json": map[string]any{
			"info": map[string]any{"name": "mcp-server-fetch", "version": "1.3.0",
				"project_urls": map[string]string{"Source": "https://github.com/modelcontextprotocol/servers"}},
			"releases": map[string]any{
				"1.0.0": []map[string]any{{"upload_time_iso_8601": ts(300)}},
				"1.2.0": []map[string]any{{"upload_time_iso_8601": ts(100), "yanked": true, "yanked_reason": "broken build"}},
				"1.3.0": []map[string]any{{"upload_time_iso_8601": ts(2)}},
			}},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if ua := r.Header.Get("User-Agent"); !strings.HasPrefix(ua, "mcp-warden") {
			t.Errorf("missing User-Agent: %q", ua)
		}
		d, ok := docs[r.URL.EscapedPath()]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(d)
	}))
	return srv, &hits
}

func client(srv *httptest.Server) *Client {
	c := New("mcp-warden/test")
	c.NPM, c.NPMDownloads, c.PyPI = srv.URL, srv.URL, srv.URL
	c.Now = func() time.Time { return now }
	return c
}

func npx(spec string) config.Server {
	return config.Server{Client: "cursor", Name: "s", Location: "x", Transport: "stdio", Command: "npx", Args: []string{"-y", spec}}
}

func uvx(spec string) config.Server {
	return config.Server{Client: "cursor", Name: "s", Location: "x", Transport: "stdio", Command: "uvx", Args: []string{spec}}
}

func ruleSet(fs []audit.Finding) map[string]audit.Severity {
	m := map[string]audit.Severity{}
	for _, f := range fs {
		m[f.Rule] = f.Severity
	}
	return m
}

func TestNPM(t *testing.T) {
	srv, _ := fakeRegistry(t)
	defer srv.Close()
	c := client(srv)
	ctx := context.Background()
	cases := []struct {
		spec   string
		want   []string
		forbid []string
	}{
		{"@acme/good@1.2.0", nil, []string{"VERSION-TOO-NEW", "NEW-PUBLISHER", "LOW-DOWNLOADS", "NO-SOURCE-REPO", "INSTALL-SCRIPTS"}},
		{"@acme/good@9.9.9", []string{"VERSION-NOT-FOUND"}, nil},
		{"hijacked", []string{"NEW-PUBLISHER", "VERSION-TOO-NEW", "INSTALL-SCRIPTS"}, []string{"PACKAGE-TOO-NEW"}},
		{"hijacked@2.2.0", nil, []string{"NEW-PUBLISHER", "VERSION-TOO-NEW", "INSTALL-SCRIPTS"}},
		{"fresh-mcp@0.1.0", []string{"PACKAGE-TOO-NEW", "VERSION-TOO-NEW", "DEPRECATED-VERSION", "NO-SOURCE-REPO", "LOW-DOWNLOADS"}, []string{"NEW-PUBLISHER"}},
		{"ci-pkg", []string{"PROVENANCE-DROPPED"}, []string{"NEW-PUBLISHER"}},
		{"ci-pkg@1.1.0", nil, []string{"PROVENANCE-DROPPED", "NEW-PUBLISHER"}},
		{"ci-switch", nil, []string{"NEW-PUBLISHER", "PROVENANCE-DROPPED", "INSTALL-SCRIPTS"}},
		{"evil-mcp", []string{"REGISTRY-MALWARE-REMOVED"}, nil},
		{"gone-mcp", []string{"REGISTRY-UNPUBLISHED"}, nil},
		{"does-not-exist-mcp", []string{"REGISTRY-NOT-FOUND"}, nil},
	}
	for _, tc := range cases {
		got := ruleSet(c.Check(ctx, npx(tc.spec)))
		for _, r := range tc.want {
			if _, ok := got[r]; !ok {
				t.Errorf("%s: missing %s in %v", tc.spec, r, got)
			}
		}
		for _, r := range tc.forbid {
			if _, ok := got[r]; ok {
				t.Errorf("%s: unexpected %s in %v", tc.spec, r, got)
			}
		}
	}
	if got := ruleSet(c.Check(ctx, npx("evil-mcp"))); got["REGISTRY-MALWARE-REMOVED"] != audit.Critical {
		t.Errorf("malware placeholder must be critical: %v", got)
	}
}

func TestPyPI(t *testing.T) {
	srv, _ := fakeRegistry(t)
	defer srv.Close()
	c := client(srv)
	ctx := context.Background()
	if got := ruleSet(c.Check(ctx, uvx("mcp-server-fetch"))); len(got) != 1 || got["VERSION-TOO-NEW"] == 0 {
		t.Errorf("unpinned resolves to fresh 1.3.0: %v", got)
	}
	if got := ruleSet(c.Check(ctx, uvx("mcp-server-fetch==1.0.0"))); len(got) != 0 {
		t.Errorf("old pinned version should be clean: %v", got)
	}
	if got := ruleSet(c.Check(ctx, uvx("MCP_Server.Fetch==1.2.0"))); got["YANKED-VERSION"] == 0 {
		t.Errorf("name normalisation / yanked: %v", got)
	}
	if got := ruleSet(c.Check(ctx, uvx("mcp-server-fetch==0.0.1"))); got["VERSION-NOT-FOUND"] == 0 {
		t.Errorf("missing version: %v", got)
	}
	if got := ruleSet(c.Check(ctx, uvx("mcp-server-ftech"))); got["REGISTRY-NOT-FOUND"] == 0 {
		t.Errorf("missing project: %v", got)
	}
}

func TestCachingAndScope(t *testing.T) {
	srv, hits := fakeRegistry(t)
	defer srv.Close()
	c := client(srv)
	ctx := context.Background()
	a, b := npx("@acme/good@1.2.0"), npx("@acme/good@1.2.0")
	b.Client, b.Name = "vscode", "other"
	fa, fb := c.Check(ctx, a), c.Check(ctx, b)
	if n := atomic.LoadInt32(hits); n != 2 { // doc + downloads, once
		t.Errorf("expected 2 requests for a shared package, got %d", n)
	}
	_ = fa
	for _, f := range fb {
		if f.Server != b.ID() {
			t.Errorf("cached finding not re-attributed: %s", f.Server)
		}
	}
	// Not registry-backed: nothing fetched.
	before := atomic.LoadInt32(hits)
	for _, s := range []config.Server{
		{Transport: "http", URL: "https://x"},
		{Transport: "stdio", Command: "node", Args: []string{"server.js"}},
		npx("github:acme/repo"),
		uvx("git+https://github.com/a/b@" + strings.Repeat("a", 40)),
	} {
		if fs := c.Check(ctx, s); fs != nil {
			t.Errorf("%+v: unexpected findings %v", s, fs)
		}
	}
	if atomic.LoadInt32(hits) != before {
		t.Error("non-registry servers triggered requests")
	}
}

func TestUnreachableFailsFast(t *testing.T) {
	var hits int32
	pypi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		http.Error(w, "boom", http.StatusBadGateway)
	}))
	defer pypi.Close()
	c := New("mcp-warden/test")
	c.NPM, c.NPMDownloads, c.PyPI = "http://127.0.0.1:1", "", pypi.URL
	ctx := context.Background()
	start := time.Now()
	for i := 0; i < 20; i++ {
		if fs := c.Check(ctx, npx(fmt.Sprintf("pkg-%d@1.0.0", i))); len(fs) != 0 {
			t.Fatalf("offline npm should yield no per-package findings: %v", fs)
		}
	}
	if time.Since(start) > 3*time.Second {
		t.Errorf("circuit breaker did not short-circuit: %s", time.Since(start))
	}
	if down := c.Unreachable(); len(down) != 1 || down["127.0.0.1:1"] == nil {
		t.Errorf("Unreachable() = %v", down)
	}
	// A reachable registry answering with an error status is reported per package and not tripped.
	for i := 0; i < 2; i++ {
		got := ruleSet(c.Check(ctx, uvx(fmt.Sprintf("p%d==1.0", i))))
		if got["REGISTRY-UNREACHABLE"] != audit.Info {
			t.Errorf("HTTP 502: %v", got)
		}
	}
	if atomic.LoadInt32(&hits) != 2 {
		t.Errorf("HTTP errors must not trip the breaker: %d requests", hits)
	}
}

func TestCooldownSeverity(t *testing.T) {
	srv, _ := fakeRegistry(t)
	defer srv.Close()
	c := client(srv)
	ctx := context.Background()
	if got := ruleSet(c.Check(ctx, npx("fresh-mcp@0.1.0")))["VERSION-TOO-NEW"]; got != audit.Medium {
		t.Errorf("pinned fresh version: %s, want medium", got)
	}
	if got := ruleSet(c.Check(ctx, uvx("mcp-server-fetch")))["VERSION-TOO-NEW"]; got != audit.Low {
		t.Errorf("unpinned fresh latest: %s, want low (UNPINNED-PACKAGE carries the fix)", got)
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.10.0", "1.9.2", 1}, {"2025.10.1", "2025.9.30", 1}, {"1.2", "1.2.0", 0}, {"0.0.84", "0.0.9", 1}, {"1.0.0", "1.0.0", 0}, {"2.0.0", "10.0.0", -1},
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%s, %s) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestPinCandidate(t *testing.T) {
	srv, _ := fakeRegistry(t)
	defer srv.Close()
	c := client(srv)
	ctx := context.Background()

	// Latest (1.2.0, 100 days old) is old enough.
	if got, err := c.PinCandidate(ctx, "npm", "@acme/good"); err != nil || got.Version != "1.2.0" || got.Latest != "1.2.0" {
		t.Errorf("good: %+v %v", got, err)
	}
	// Latest 2.3.0 is 1 day old: pick the newest older release.
	if got, err := c.PinCandidate(ctx, "npm", "hijacked"); err != nil || got.Version != "2.2.0" || got.Latest != "2.3.0" {
		t.Errorf("hijacked: %+v %v", got, err)
	}
	// Only release is 3 days old and deprecated: nothing to pin, and the reason says why.
	if _, err := c.PinCandidate(ctx, "npm", "fresh-mcp"); err == nil || !strings.Contains(err.Error(), "deprecated") {
		t.Errorf("fresh-mcp: %v", err)
	}
	// Brand-new but healthy package: "not old enough yet".
	c.Cooldown = 1000 * 24 * time.Hour
	if _, err := c.PinCandidate(ctx, "npm", "@acme/good"); err == nil || !strings.Contains(err.Error(), "older than") {
		t.Errorf("cooldown message: %v", err)
	}
	c.Cooldown = 7 * 24 * time.Hour
	if _, err := c.PinCandidate(ctx, "npm", "evil-mcp"); err == nil || !strings.Contains(err.Error(), "malware") {
		t.Errorf("malware package must not be pinned: %v", err)
	}
	if _, err := c.PinCandidate(ctx, "npm", "nope-mcp"); err == nil {
		t.Error("missing package pinned")
	}
	// PyPI: 1.3.0 is 2 days old, 1.2.0 is yanked, so 1.0.0.
	if got, err := c.PinCandidate(ctx, "pypi", "mcp_server.fetch"); err != nil || got.Version != "1.0.0" || got.Latest != "1.3.0" {
		t.Errorf("pypi: %+v %v", got, err)
	}
}

func TestDeprecationGrading(t *testing.T) {
	cases := []struct {
		msg  string
		sev  audit.Severity
		fix  string
		text string
	}{
		// Real messages from the registry (November 2026).
		{"Archived and unmaintained; no security guarantees. See https://github.com/modelcontextprotocol/servers-archived", audit.Medium, "maintained alternative", "no longer maintained"},
		{"Package no longer supported. Contact Support at https://www.npmjs.com/support for more info.", audit.Medium, "maintained alternative", "no longer maintained"},
		{"This package has moved to @browserbasehq/mcp", audit.Low, "@browserbasehq/mcp", "moved to @browserbasehq/mcp"},
		{"renamed to `fresh-mcp2`.", audit.Low, "fresh-mcp2", "moved to fresh-mcp2"},
		{"use fresh-mcp2 instead", audit.Low, "", "deprecated on npm"},
	}
	for _, c := range cases {
		f := deprecatedFinding("x@1", c.msg)
		if f.Severity != c.sev || !strings.Contains(f.Fix, c.fix) || !strings.Contains(f.Message, c.text) {
			t.Errorf("%q -> %s %q / %q", c.msg, f.Severity, f.Message, f.Fix)
		}
	}
}

func TestOnCodeHost(t *testing.T) {
	yes := []string{"https://github.com/cloudflare/mcp-server-cloudflare", "https://github.com/a/b/issues",
		"git+https://gitlab.com/a/b.git", "git@github.com:a/b.git", "https://www.github.com/a", "https://gist.github.com/x"}
	no := []string{"", "https://modelcontextprotocol.io", "https://github.com.evil.io/a/b", "https://notgithub.com/a", "not a url"}
	for _, u := range yes {
		if !onCodeHost(u) {
			t.Errorf("onCodeHost(%q) = false", u)
		}
	}
	for _, u := range no {
		if onCodeHost(u) {
			t.Errorf("onCodeHost(%q) = true", u)
		}
	}
}

func TestNPMSourceFromHomepageOrBugs(t *testing.T) {
	mk := func(extra map[string]any) npmDoc {
		b, _ := json.Marshal(extra)
		var d npmDoc
		_ = json.Unmarshal(b, &d)
		return d
	}
	ver := npmVersion{}
	if !npmHasSource(mk(map[string]any{"homepage": "https://github.com/cloudflare/mcp-server-cloudflare"}), ver) {
		t.Error("homepage on GitHub should count as a source link")
	}
	if !npmHasSource(mk(map[string]any{"homepage": "https://modelcontextprotocol.io", "bugs": map[string]string{"url": "https://github.com/modelcontextprotocol/servers/issues"}}), ver) {
		t.Error("issue tracker on GitHub should count as a source link")
	}
	if !npmHasSource(mk(map[string]any{"bugs": "https://gitlab.com/a/b/-/issues"}), ver) {
		t.Error("string-form bugs URL")
	}
	if npmHasSource(mk(map[string]any{"homepage": "https://example.com"}), ver) {
		t.Error("a non-code-host homepage is not a source link")
	}
}
