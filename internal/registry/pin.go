package registry

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Candidate is the version `fix` proposes to pin.
type Candidate struct {
	Version   string
	Published time.Time
	Latest    string        // current latest release
	LatestAge time.Duration // how old the latest release is
}

// PinCandidate picks the newest stable release that is older than the
// cooldown: not a prerelease, not deprecated (npm) or yanked (PyPI). eco is
// "npm" or "pypi".
func (c *Client) PinCandidate(ctx context.Context, eco, pkg string) (Candidate, error) {
	switch eco {
	case "npm":
		return c.npmCandidate(ctx, pkg)
	case "pypi":
		return c.pypiCandidate(ctx, pkg)
	}
	return Candidate{}, fmt.Errorf("unsupported ecosystem %q", eco)
}

func (c *Client) npmCandidate(ctx context.Context, pkg string) (Candidate, error) {
	var doc npmDoc
	skipped, err := c.fetch(ctx, c.NPM, strings.TrimRight(c.NPM, "/")+"/"+npmPath(pkg), &doc)
	switch {
	case skipped:
		return Candidate{}, errors.New("npm registry is unreachable")
	case errors.Is(err, errNotFound):
		return Candidate{}, errors.New("package does not exist on npm; check the name instead of pinning")
	case err != nil:
		return Candidate{}, err
	}
	latest := doc.DistTags["latest"]
	if strings.HasSuffix(latest, "-security") {
		return Candidate{}, errors.New("npm removed this package as malware; remove the server instead")
	}
	now := c.Now()
	cutoff := now.Add(-c.Cooldown)
	var best Candidate
	stable, deprecated := 0, 0
	for v, meta := range doc.Versions {
		if strings.ContainsAny(v, "-+") {
			continue
		}
		stable++
		if deprecation(meta.Deprecated) != "" {
			deprecated++
			continue
		}
		t, ok := doc.published(v)
		if !ok || t.After(cutoff) {
			continue
		}
		if best.Version == "" || compareVersions(v, best.Version) > 0 {
			best = Candidate{Version: v, Published: t}
		}
	}
	if best.Version == "" {
		if stable > 0 && deprecated == stable {
			return Candidate{}, errors.New("every release is deprecated (the package is no longer maintained); replace this server")
		}
		return Candidate{}, fmt.Errorf("no stable release is older than %s yet; try again later or pin by hand", age(c.Cooldown))
	}
	best.Latest = latest
	if t, ok := doc.published(latest); ok {
		best.LatestAge = now.Sub(t)
	}
	return best, nil
}

var pyPreRe = regexp.MustCompile(`(?i)(a|alpha|b|beta|c|rc|pre|preview|dev)\d*`)

func (c *Client) pypiCandidate(ctx context.Context, pkg string) (Candidate, error) {
	var doc pypiDoc
	skipped, err := c.fetch(ctx, c.PyPI, strings.TrimRight(c.PyPI, "/")+"/pypi/"+url.PathEscape(pypiName(pkg))+"/json", &doc)
	switch {
	case skipped:
		return Candidate{}, errors.New("PyPI is unreachable")
	case errors.Is(err, errNotFound):
		return Candidate{}, errors.New("project does not exist on PyPI; check the name instead of pinning")
	case err != nil:
		return Candidate{}, err
	}
	now := c.Now()
	cutoff := now.Add(-c.Cooldown)
	newest := func(v string) (time.Time, bool) {
		var t time.Time
		usable := false
		for _, f := range doc.Releases[v] {
			if !f.Yanked {
				usable = true
			}
			if ft, err := time.Parse(time.RFC3339, f.UploadTime); err == nil && ft.After(t) {
				t = ft
			}
		}
		return t, usable && !t.IsZero()
	}
	var best Candidate
	stable, yanked := 0, 0
	for v := range doc.Releases {
		if pyPreRe.MatchString(strings.ReplaceAll(strings.ToLower(v), "post", "")) {
			continue
		}
		stable++
		t, ok := newest(v)
		if !ok && !t.IsZero() {
			yanked++
		}
		if !ok || t.After(cutoff) {
			continue
		}
		if best.Version == "" || compareVersions(v, best.Version) > 0 {
			best = Candidate{Version: v, Published: t}
		}
	}
	if best.Version == "" {
		if stable > 0 && yanked == stable {
			return Candidate{}, errors.New("every release has been yanked; replace this server")
		}
		return Candidate{}, fmt.Errorf("no stable release is older than %s yet; try again later or pin by hand", age(c.Cooldown))
	}
	best.Latest = doc.Info.Version
	if t, ok := newest(doc.Info.Version); ok {
		best.LatestAge = now.Sub(t)
	}
	return best, nil
}

// compareVersions compares dotted versions numerically segment by segment
// ("1.10.0" > "1.9.2", "2025.10.1" > "2025.9.30"); non-numeric tails compare
// as strings.
func compareVersions(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < max(len(as), len(bs)); i++ {
		var x, y string
		if i < len(as) {
			x = as[i]
		}
		if i < len(bs) {
			y = bs[i]
		}
		xn, xr := leadingInt(x)
		yn, yr := leadingInt(y)
		if xn != yn {
			if xn < yn {
				return -1
			}
			return 1
		}
		if xr != yr {
			return strings.Compare(xr, yr)
		}
	}
	return 0
}

func leadingInt(s string) (int, string) {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	n, _ := strconv.Atoi(s[:i])
	return n, s[i:]
}
