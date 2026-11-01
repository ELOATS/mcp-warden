// Package registry checks npm and PyPI metadata for the packages that MCP
// servers are launched from: missing or malware-removed packages, very new
// packages and versions, publisher changes, install scripts, yanked or
// deprecated versions, missing source links and very low adoption.
package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ELOATS/mcp-warden/internal/audit"
	"github.com/ELOATS/mcp-warden/internal/config"
)

// Defaults for the public registries.
const (
	DefaultNPM          = "https://registry.npmjs.org"
	DefaultNPMDownloads = "https://api.npmjs.org"
	DefaultPyPI         = "https://pypi.org"
)

// Client queries registries. The zero value is not usable; use New.
type Client struct {
	HTTP         *http.Client
	NPM          string // registry base URL (npmjs.org or a mirror such as registry.npmmirror.com)
	NPMDownloads string // download-count API base; "" disables the LOW-DOWNLOADS check
	PyPI         string
	UserAgent    string
	Now          func() time.Time

	Cooldown      time.Duration // versions younger than this are VERSION-TOO-NEW
	NewPackageAge time.Duration // packages younger than this are PACKAGE-TOO-NEW
	MinDownloads  int           // weekly npm downloads below this are LOW-DOWNLOADS

	mu    sync.Mutex
	cache map[string]*entry
}

type entry struct {
	once sync.Once
	fs   []audit.Finding // findings with Server unset
}

// New returns a client with sensible defaults.
func New(userAgent string) *Client {
	return &Client{
		HTTP: &http.Client{Timeout: 15 * time.Second}, NPM: DefaultNPM, NPMDownloads: DefaultNPMDownloads, PyPI: DefaultPyPI,
		UserAgent: userAgent, Now: time.Now,
		Cooldown: 7 * 24 * time.Hour, NewPackageAge: 30 * 24 * time.Hour, MinDownloads: 100,
	}
}

// Check returns registry findings for one server (nil for servers that are
// not launched from npm or PyPI). Results are cached per package@version, so
// the same package used by several clients is fetched once.
func (c *Client) Check(ctx context.Context, s config.Server) []audit.Finding {
	if s.Transport != "stdio" {
		return nil
	}
	l := audit.ParseLaunch(s.Command, s.Args)
	var eco string
	switch l.Runner {
	case "npx":
		eco = "npm"
	case "uvx":
		eco = "pypi"
	default:
		return nil
	}
	if l.Package == "" || strings.Contains(l.Package, "://") || strings.HasPrefix(l.Package, "git+") ||
		strings.HasPrefix(l.Package, ".") || strings.HasPrefix(l.Package, "/") || strings.Contains(l.Package, ":") {
		return nil // URLs, git and local paths have no registry metadata
	}
	key := eco + ":" + l.Package + "@" + l.Version
	c.mu.Lock()
	if c.cache == nil {
		c.cache = map[string]*entry{}
	}
	e, ok := c.cache[key]
	if !ok {
		e = &entry{}
		c.cache[key] = e
	}
	c.mu.Unlock()
	e.once.Do(func() {
		if eco == "npm" {
			e.fs = c.checkNPM(ctx, l.Package, l.Version, l.Pinned)
		} else {
			e.fs = c.checkPyPI(ctx, l.Package, l.Version, l.Pinned)
		}
	})
	out := make([]audit.Finding, len(e.fs))
	for i, f := range e.fs {
		f.Server = s.ID()
		out[i] = f
	}
	return out
}

var errNotFound = errors.New("not found")

func (c *Client) getJSON(ctx context.Context, rawURL string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return errNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, hostOf(rawURL))
	}
	// Full npm documents of popular packages can be several MB.
	return json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(v)
}

func hostOf(raw string) string {
	if u, err := url.Parse(raw); err == nil {
		return u.Host
	}
	return raw
}

func unreachable(eco, pkg string, err error) []audit.Finding {
	return []audit.Finding{{Rule: "REGISTRY-UNREACHABLE", Severity: audit.Info,
		Message: fmt.Sprintf("could not fetch %s metadata for %s", eco, pkg), Evidence: err.Error()}}
}

// ---------------------------------------------------------------- npm

type npmDoc struct {
	Name       string                     `json:"name"`
	DistTags   map[string]string          `json:"dist-tags"`
	Time       map[string]json.RawMessage `json:"time"`
	Versions   map[string]npmVersion      `json:"versions"`
	Repository json.RawMessage            `json:"repository"`
}

type npmVersion struct {
	Deprecated json.RawMessage   `json:"deprecated"`
	Scripts    map[string]string `json:"scripts"`
	NPMUser    *struct {
		Name             string          `json:"name"`
		TrustedPublisher json.RawMessage `json:"trustedPublisher"`
	} `json:"_npmUser"`
	Dist struct {
		Attestations json.RawMessage `json:"attestations"`
	} `json:"dist"`
	Repository json.RawMessage `json:"repository"`
}

// provenance reports whether the version was published from CI with npm
// trusted publishing or carries signed provenance attestations.
func (v npmVersion) provenance() bool {
	if len(v.Dist.Attestations) > 0 && string(v.Dist.Attestations) != "null" {
		return true
	}
	return v.NPMUser != nil && len(v.NPMUser.TrustedPublisher) > 0 && string(v.NPMUser.TrustedPublisher) != "null"
}

func (d npmDoc) published(v string) (time.Time, bool) {
	raw, ok := d.Time[v]
	if !ok {
		return time.Time{}, false
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s)
	return t, err == nil
}

func npmPath(pkg string) string {
	// Scoped names keep the @ and encode the slash: @scope%2Fname.
	return strings.ReplaceAll(url.PathEscape(pkg), "%40", "@")
}

func (c *Client) checkNPM(ctx context.Context, pkg, version string, pinned bool) []audit.Finding {
	var doc npmDoc
	err := c.getJSON(ctx, strings.TrimRight(c.NPM, "/")+"/"+npmPath(pkg), &doc)
	if errors.Is(err, errNotFound) {
		return []audit.Finding{{Rule: "REGISTRY-NOT-FOUND", Severity: audit.High,
			Message:  fmt.Sprintf("npm package %s does not exist (typo, dependency confusion, or removed for malware)", pkg),
			Evidence: pkg, Fix: "Do not run it. Check the exact package name with the server's maintainers."}}
	}
	if err != nil {
		return unreachable("npm", pkg, err)
	}
	if _, gone := doc.Time["unpublished"]; gone && len(doc.Versions) == 0 {
		return []audit.Finding{{Rule: "REGISTRY-UNPUBLISHED", Severity: audit.High,
			Message: fmt.Sprintf("npm package %s has been unpublished", pkg), Evidence: pkg,
			Fix: "Remove the server; anyone could republish this name later."}}
	}
	latest := doc.DistTags["latest"]
	if strings.HasSuffix(latest, "-security") {
		return []audit.Finding{{Rule: "REGISTRY-MALWARE-REMOVED", Severity: audit.Critical,
			Message:  fmt.Sprintf("npm replaced %s with a security placeholder (%s): it was removed as malicious", pkg, latest),
			Evidence: pkg + "@" + latest,
			Fix:      "Remove the server immediately and treat the machine as possibly compromised: rotate credentials it could reach."}}
	}

	resolved, note := version, ""
	if !pinned {
		resolved, note = latest, " (currently resolves to latest)"
		if version != "" && version != "latest" {
			if t, ok := doc.DistTags[version]; ok { // a dist-tag such as "next"
				resolved = t
			}
		}
	}
	var out []audit.Finding
	ver, ok := doc.Versions[resolved]
	if !ok {
		return append(out, audit.Finding{Rule: "VERSION-NOT-FOUND", Severity: audit.High,
			Message:  fmt.Sprintf("version %s of %s does not exist on npm", resolved, pkg),
			Evidence: pkg + "@" + resolved, Fix: "Pin a version that exists."})
	}
	id := pkg + "@" + resolved

	now := c.Now()
	if created, ok := doc.published("created"); ok && now.Sub(created) < c.NewPackageAge {
		out = append(out, audit.Finding{Rule: "PACKAGE-TOO-NEW", Severity: audit.Medium,
			Message:  fmt.Sprintf("npm package was created %s ago", age(now.Sub(created))),
			Evidence: pkg + " created " + created.Format("2006-01-02"),
			Fix:      "New packages have no track record; review the source before trusting it."})
	}
	if pub, ok := doc.published(resolved); ok && now.Sub(pub) < c.Cooldown {
		out = append(out, audit.Finding{Rule: "VERSION-TOO-NEW", Severity: audit.Medium,
			Message:  fmt.Sprintf("version %s was published %s ago%s", resolved, age(now.Sub(pub)), note),
			Evidence: id + " published " + pub.Format("2006-01-02 15:04"),
			Fix:      fmt.Sprintf("Compromised releases are usually caught within days. Pin a version older than %s.", age(c.Cooldown))})
	}
	if prev, ok := previousVersion(doc, resolved); ok && doc.Versions[prev].provenance() && !ver.provenance() {
		out = append(out, audit.Finding{Rule: "PROVENANCE-DROPPED", Severity: audit.High,
			Message:  fmt.Sprintf("version %s has no provenance, but the previous release %s was published from CI with provenance", resolved, prev),
			Evidence: id,
			Fix:      "A manual publish after CI-only releases is how stolen npm tokens are used. Stay on " + prev + " until the maintainers confirm this release."})
	} else if f, ok := npmPublisherChange(doc, resolved); ok && !ver.provenance() {
		f.Evidence = id + ": " + f.Evidence
		out = append(out, f)
	}
	var hooks []string
	// "prepare" is not listed: npm runs it for git/local installs, not for
	// registry tarballs, which is what npx downloads.
	for _, k := range []string{"preinstall", "install", "postinstall"} {
		if v := ver.Scripts[k]; v != "" {
			hooks = append(hooks, k+": "+clip(v, 80))
		}
	}
	if len(hooks) > 0 {
		out = append(out, audit.Finding{Rule: "INSTALL-SCRIPTS", Severity: audit.Medium,
			Message:  "package runs install scripts, so code executes as soon as npx downloads it",
			Evidence: id + " " + strings.Join(hooks, "; "),
			Fix:      "Review the scripts, or run with npm_config_ignore_scripts=true if the server works without them."})
	}
	if msg := deprecation(ver.Deprecated); msg != "" {
		out = append(out, audit.Finding{Rule: "DEPRECATED-VERSION", Severity: audit.Low,
			Message: "this version is deprecated on npm", Evidence: id + ": " + clip(msg, 160)})
	}
	if !hasRepo(doc.Repository) && !hasRepo(ver.Repository) {
		out = append(out, audit.Finding{Rule: "NO-SOURCE-REPO", Severity: audit.Low,
			Message: "package metadata links no source repository, so the published code cannot be compared with its source", Evidence: id})
	}
	if c.NPMDownloads != "" && c.MinDownloads > 0 {
		var dl struct {
			Downloads int `json:"downloads"`
		}
		if err := c.getJSON(ctx, strings.TrimRight(c.NPMDownloads, "/")+"/downloads/point/last-week/"+npmPath(pkg), &dl); err == nil && dl.Downloads < c.MinDownloads {
			out = append(out, audit.Finding{Rule: "LOW-DOWNLOADS", Severity: audit.Low,
				Message:  fmt.Sprintf("only %d npm downloads last week", dl.Downloads),
				Evidence: pkg, Fix: "Rarely used packages get little scrutiny; typosquats look exactly like this."})
		}
	}
	return out
}

// previousVersion returns the version published immediately before v.
func previousVersion(doc npmDoc, v string) (string, bool) {
	at, ok := doc.published(v)
	if !ok {
		return "", false
	}
	best, bestT := "", time.Time{}
	for other := range doc.Versions {
		t, ok := doc.published(other)
		if !ok || !t.Before(at) || strings.Contains(other, "-") { // skip prereleases
			continue
		}
		if t.After(bestT) {
			best, bestT = other, t
		}
	}
	return best, best != ""
}

// npmPublisherChange flags a version published by an account that never
// published an earlier version of the package.
func npmPublisherChange(doc npmDoc, resolved string) (audit.Finding, bool) {
	cur := doc.Versions[resolved].NPMUser
	if cur == nil || cur.Name == "" {
		return audit.Finding{}, false
	}
	pubAt, ok := doc.published(resolved)
	if !ok {
		return audit.Finding{}, false
	}
	prior := map[string]bool{}
	earlier := 0
	for v, meta := range doc.Versions {
		t, ok := doc.published(v)
		if !ok || !t.Before(pubAt) || meta.NPMUser == nil {
			continue
		}
		earlier++
		prior[meta.NPMUser.Name] = true
	}
	if earlier < 3 || prior[cur.Name] {
		return audit.Finding{}, false
	}
	names := make([]string, 0, len(prior))
	for n := range prior {
		names = append(names, n)
	}
	sort.Strings(names)
	return audit.Finding{Rule: "NEW-PUBLISHER", Severity: audit.Medium,
		Message:  fmt.Sprintf("version was published by %q, who never published any of the %d earlier versions", cur.Name, earlier),
		Evidence: "previous publishers: " + strings.Join(names, ", "),
		Fix:      "A first release by a new account is how hijacked packages look. Confirm the handover with the project before upgrading."}, true
}

func deprecation(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var b bool
	if json.Unmarshal(raw, &b) == nil && b {
		return "deprecated"
	}
	return ""
}

func hasRepo(raw json.RawMessage) bool {
	if len(raw) == 0 || string(raw) == "null" {
		return false
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return strings.TrimSpace(s) != ""
	}
	var o struct {
		URL string `json:"url"`
	}
	return json.Unmarshal(raw, &o) == nil && strings.TrimSpace(o.URL) != ""
}

// ---------------------------------------------------------------- PyPI

type pypiFile struct {
	UploadTime string `json:"upload_time_iso_8601"`
	Yanked     bool   `json:"yanked"`
	Reason     string `json:"yanked_reason"`
}

type pypiDoc struct {
	Info struct {
		Name        string            `json:"name"`
		Version     string            `json:"version"`
		HomePage    string            `json:"home_page"`
		ProjectURLs map[string]string `json:"project_urls"`
	} `json:"info"`
	Releases map[string][]pypiFile `json:"releases"`
}

var pypiNormRe = regexp.MustCompile(`[-_.]+`)

func pypiName(n string) string { return strings.ToLower(pypiNormRe.ReplaceAllString(n, "-")) }

func (c *Client) checkPyPI(ctx context.Context, pkg, version string, pinned bool) []audit.Finding {
	var doc pypiDoc
	err := c.getJSON(ctx, strings.TrimRight(c.PyPI, "/")+"/pypi/"+url.PathEscape(pypiName(pkg))+"/json", &doc)
	if errors.Is(err, errNotFound) {
		return []audit.Finding{{Rule: "REGISTRY-NOT-FOUND", Severity: audit.High,
			Message:  fmt.Sprintf("PyPI project %s does not exist (typo, dependency confusion, or removed/quarantined)", pkg),
			Evidence: pkg, Fix: "Do not run it. Check the exact project name with the server's maintainers."}}
	}
	if err != nil {
		return unreachable("PyPI", pkg, err)
	}
	resolved, note := version, ""
	if !pinned {
		resolved, note = doc.Info.Version, " (currently resolves to latest)"
	}
	files, ok := doc.Releases[resolved]
	if !ok {
		return []audit.Finding{{Rule: "VERSION-NOT-FOUND", Severity: audit.High,
			Message:  fmt.Sprintf("version %s of %s does not exist on PyPI", resolved, pkg),
			Evidence: pkg + "==" + resolved, Fix: "Pin a version that exists."}}
	}
	id := pkg + "==" + resolved
	var out []audit.Finding
	now := c.Now()

	var first time.Time
	for _, fs := range doc.Releases {
		for _, f := range fs {
			if t, err := time.Parse(time.RFC3339, f.UploadTime); err == nil && (first.IsZero() || t.Before(first)) {
				first = t
			}
		}
	}
	if !first.IsZero() && now.Sub(first) < c.NewPackageAge {
		out = append(out, audit.Finding{Rule: "PACKAGE-TOO-NEW", Severity: audit.Medium,
			Message:  fmt.Sprintf("PyPI project was created %s ago", age(now.Sub(first))),
			Evidence: pkg + " first upload " + first.Format("2006-01-02"),
			Fix:      "New projects have no track record; review the source before trusting it."})
	}
	var newest time.Time
	yanked, reason := len(files) > 0, ""
	for _, f := range files {
		if t, err := time.Parse(time.RFC3339, f.UploadTime); err == nil && t.After(newest) {
			newest = t
		}
		if !f.Yanked {
			yanked = false
		} else if f.Reason != "" {
			reason = f.Reason
		}
	}
	if !newest.IsZero() && now.Sub(newest) < c.Cooldown {
		out = append(out, audit.Finding{Rule: "VERSION-TOO-NEW", Severity: audit.Medium,
			Message:  fmt.Sprintf("version %s was published %s ago%s", resolved, age(now.Sub(newest)), note),
			Evidence: id + " published " + newest.Format("2006-01-02 15:04"),
			Fix:      fmt.Sprintf("Compromised releases are usually caught within days. Pin a version older than %s.", age(c.Cooldown))})
	}
	if yanked {
		ev := id
		if reason != "" {
			ev += ": " + clip(reason, 160)
		}
		out = append(out, audit.Finding{Rule: "YANKED-VERSION", Severity: audit.Medium,
			Message: "this version was yanked by its maintainers", Evidence: ev, Fix: "Pin a version that has not been yanked."})
	}
	if !pypiHasSource(doc) {
		out = append(out, audit.Finding{Rule: "NO-SOURCE-REPO", Severity: audit.Low,
			Message: "project metadata links no source repository, so the published code cannot be compared with its source", Evidence: id})
	}
	return out
}

func pypiHasSource(doc pypiDoc) bool {
	hosts := []string{"github.com", "gitlab.com", "bitbucket.org", "codeberg.org", "sr.ht", "gitee.com"}
	check := func(u string) bool {
		for _, h := range hosts {
			if strings.Contains(strings.ToLower(u), h) {
				return true
			}
		}
		return false
	}
	for k, v := range doc.Info.ProjectURLs {
		lk := strings.ToLower(k)
		if strings.Contains(lk, "source") || strings.Contains(lk, "repo") || strings.Contains(lk, "code") || check(v) {
			return true
		}
	}
	return check(doc.Info.HomePage)
}

// ---------------------------------------------------------------- helpers

func age(d time.Duration) string {
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	}
	return fmt.Sprintf("%d days", int(d.Hours()/24))
}

func clip(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
