package audit

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

var secretPatterns = []struct {
	name string
	re   *regexp.Regexp
}{
	{"GitHub token", regexp.MustCompile(`\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}`)},
	{"GitHub token", regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{30,}`)},
	{"Anthropic API key", regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_\-]{20,}`)},
	{"OpenAI-style API key", regexp.MustCompile(`\bsk-(proj-)?[A-Za-z0-9_\-]{20,}`)},
	{"Slack token", regexp.MustCompile(`\bxox[abposr]-[A-Za-z0-9\-]{10,}`)},
	{"AWS access key ID", regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{"Google API key", regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}`)},
	{"GitLab token", regexp.MustCompile(`\bglpat-[A-Za-z0-9_\-]{20,}`)},
	{"Stripe live key", regexp.MustCompile(`\b(sk|rk)_live_[0-9A-Za-z]{20,}`)},
	{"npm token", regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`)},
	{"Hugging Face token", regexp.MustCompile(`\bhf_[A-Za-z0-9]{30,}`)},
	{"private key", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
}

// credURLRe matches scheme://user:password@ in connection strings.
var credURLRe = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.\-]*)://([^:/@\s]+):([^@/\s]+)@`)

// secretKind returns a human name if v contains a known credential format.
func secretKind(v string) string {
	for _, p := range secretPatterns {
		if p.re.MatchString(v) {
			return p.name
		}
	}
	return ""
}

var sensitiveWords = []string{
	"TOKEN", "SECRET", "PASSWORD", "PASSWD", "API_KEY", "APIKEY", "ACCESS_KEY",
	"PRIVATE_KEY", "AUTHORIZATION", "COOKIE", "SESSION_KEY", "CLIENT_SECRET",
}

// sensitiveKey reports whether an env var, header or flag name suggests a credential.
func sensitiveKey(k string) bool {
	u := strings.ToUpper(strings.ReplaceAll(k, "-", "_"))
	for _, w := range sensitiveWords {
		if strings.Contains(u, w) {
			return true
		}
	}
	return false
}

// isRef reports whether v is a reference to a secret stored elsewhere rather
// than the secret itself.
func isRef(v string) bool {
	return strings.Contains(v, "${") || strings.HasPrefix(v, "$") || strings.Contains(v, "{env:") ||
		strings.HasPrefix(v, "op://") || strings.HasPrefix(v, "keychain:")
}

func looksLikePlainValue(v string) bool {
	switch strings.ToLower(v) {
	case "", "true", "false", "yes", "no", "none", "null":
		return true
	}
	return strings.HasPrefix(v, "/") || strings.HasPrefix(v, "~") || strings.HasPrefix(v, "./") ||
		strings.Contains(v, "\\") || strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://")
}

func redact(v string) string {
	if len(v) <= 8 {
		return "****"
	}
	return fmt.Sprintf("%s…(%d chars)", v[:4], len(v))
}

// RedactArgs masks credentials in a command line so it is safe to print or store.
func RedactArgs(args []string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = a
		if isRef(a) {
			continue
		}
		if secretKind(a) != "" {
			out[i] = redact(a)
			continue
		}
		if k, v, ok := strings.Cut(a, "="); ok && strings.HasPrefix(k, "-") && sensitiveKey(k) && v != "" {
			out[i] = k + "=" + redact(v)
			continue
		}
		if i > 0 && strings.HasPrefix(args[i-1], "-") && !strings.Contains(args[i-1], "=") &&
			sensitiveKey(args[i-1]) && !strings.HasPrefix(a, "-") {
			out[i] = redact(a)
			continue
		}
		if credURLRe.MatchString(a) {
			out[i] = credURLRe.ReplaceAllString(a, "$1://$2:****@")
		}
	}
	return out
}

// RedactURL masks passwords and credential-like query parameters.
func RedactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	if u.User != nil {
		if _, ok := u.User.Password(); ok {
			u.User = url.UserPassword(u.User.Username(), "****")
		}
	}
	q := u.Query()
	changed := false
	for k := range q {
		if sensitiveKey(k) || strings.EqualFold(k, "key") {
			q.Set(k, "REDACTED")
			changed = true
		}
	}
	if changed {
		u.RawQuery = q.Encode()
	}
	return u.String()
}
