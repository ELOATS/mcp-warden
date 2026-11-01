package audit

import (
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/ELOATS/mcp-warden/internal/config"
)

// Options tune the static checks.
type Options struct {
	Home string // user's home directory, used to spot over-broad file access
}

var pipeExecRe = regexp.MustCompile(`(?i)\b(curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b[^|;&]*\|\s*(sudo\s+)?(sh|bash|zsh|python3?|node|iex|invoke-expression)\b`)

// StaticChecks inspects a server's configuration without running it.
func StaticChecks(s config.Server, opt Options) []Finding {
	var out []Finding
	add := func(f Finding) {
		f.Server = s.ID()
		out = append(out, f)
	}
	switch s.Transport {
	case "stdio":
		checkLaunch(s, opt, add)
	case "http", "sse":
		checkURL(s.URL, add)
		if s.Transport == "sse" {
			add(Finding{Rule: "LEGACY-SSE", Severity: Low,
				Message: "uses the deprecated HTTP+SSE transport",
				Fix:     "Switch to the server's Streamable HTTP endpoint if it offers one."})
		}
		add(Finding{Rule: "REMOTE-SERVER", Severity: Info,
			Message: "remote server: its code and tool definitions can change at any time without a local update",
			Fix:     "Run `mcp-warden pin --probe` once, then `mcp-warden diff` regularly to catch drift."})
	default:
		add(Finding{Rule: "UNKNOWN-TRANSPORT", Severity: Low,
			Message: "could not determine how this server is started (no command or url)"})
	}
	checkSecrets(s, add)
	return out
}

func checkLaunch(s config.Server, opt Options, add func(Finding)) {
	l := ParseLaunch(s.Command, s.Args)
	switch l.Runner {
	case "shell":
		if pipeExecRe.MatchString(l.Script) {
			add(Finding{Rule: "SHELL-PIPE-EXEC", Severity: Critical,
				Message:  "downloads a script and executes it on every launch",
				Evidence: truncate(l.Script, 160),
				Fix:      "Never run an MCP server from a downloaded script; install a pinned package instead."})
		} else {
			add(Finding{Rule: "SHELL-WRAPPER", Severity: Medium,
				Message:  "started through an inline shell script, which hides what actually runs",
				Evidence: truncate(strings.Join(RedactArgs([]string{l.Script}), ""), 160),
				Fix:      "Call the server binary directly so its provenance can be audited."})
		}
	case "npx", "uvx":
		if l.Package == "" {
			add(Finding{Rule: "UNKNOWN-PACKAGE", Severity: Low, Message: "could not determine which package is executed"})
			break
		}
		checkTyposquat(l.Package, add)
		if !l.Pinned {
			ver := l.Runner + " fetches the latest version"
			if l.Version != "" {
				ver = fmt.Sprintf("%s resolves %q", l.Runner, l.Version)
			}
			example := l.Package + "@<exact-version>"
			if l.Runner == "uvx" {
				example = l.Package + "==<exact-version>"
			}
			add(Finding{Rule: "UNPINNED-PACKAGE", Severity: Medium,
				Message: fmt.Sprintf("not pinned (%s): every launch can install a new, possibly compromised, release", ver),
				Fix:     "Pin an exact version, e.g. " + example + ", or run `mcp-warden fix` to pick a vetted one."})
		}
		if l.Package == "mcp-remote" {
			for _, a := range l.Rest {
				if strings.HasPrefix(a, "http://") || strings.HasPrefix(a, "https://") {
					checkURL(a, add)
					break
				}
			}
		}
	case "docker":
		checkTyposquat(l.Package, add)
		if !l.Pinned {
			sev, why := Low, fmt.Sprintf("tag %q is mutable", l.Version)
			if l.Version == "" || l.Version == "latest" {
				sev, why = Medium, "no tag / :latest"
			}
			add(Finding{Rule: "UNPINNED-IMAGE", Severity: sev,
				Message: fmt.Sprintf("image %s is not pinned by digest (%s)", l.Package, why),
				Fix:     "Pin the image by digest: " + l.Package + "@sha256:<digest>."})
		}
		checkDockerFlags(l.Docker, opt, add)
	case "local":
		add(Finding{Rule: "LOCAL-SCRIPT", Severity: Info,
			Message: fmt.Sprintf("runs a local script (%s); its provenance cannot be verified automatically", l.Package)})
	}
	for _, a := range s.Args {
		if isBroadPath(a, opt.Home) {
			add(Finding{Rule: "BROAD-FS-ACCESS", Severity: High,
				Message:  fmt.Sprintf("is given access to %q, i.e. the whole disk or home directory", a),
				Evidence: a,
				Fix:      "Grant only the project directories the server actually needs."})
		}
	}
}

func checkTyposquat(pkg string, add func(Finding)) {
	if near, ok := nearestKnown(pkg); ok {
		add(Finding{Rule: "POSSIBLE-TYPOSQUAT", Severity: High,
			Message:  fmt.Sprintf("%q is one or two characters away from the popular %q", pkg, near),
			Evidence: pkg,
			Fix:      fmt.Sprintf("Check the publisher. Did you mean %q?", near)})
	}
}

func checkDockerFlags(flags []string, opt Options, add func(Finding)) {
	for _, f := range flags {
		k, v, _ := strings.Cut(f, "=")
		switch {
		case k == "--privileged":
			add(Finding{Rule: "DOCKER-PRIVILEGED", Severity: High,
				Message: "container runs with --privileged (effectively root on the host)",
				Fix:     "Remove --privileged."})
		case strings.Contains(v, "docker.sock"):
			add(Finding{Rule: "DOCKER-SOCKET", Severity: High,
				Message: "mounts the Docker socket, which grants control over the host", Evidence: f,
				Fix: "Do not mount /var/run/docker.sock into MCP servers."})
		case (k == "-v" || k == "--volume") && hostSide(v) != "":
			if isBroadPath(hostSide(v), opt.Home) {
				add(Finding{Rule: "HOST-ROOT-MOUNT", Severity: High,
					Message: "mounts the host root or home directory into the container", Evidence: f,
					Fix: "Mount only the directories the server needs, read-only (:ro) where possible."})
			}
		case k == "--mount" && (strings.Contains(v, "source=/,") || strings.Contains(v, "src=/,") ||
			strings.HasSuffix(v, "source=/") || strings.HasSuffix(v, "src=/")):
			add(Finding{Rule: "HOST-ROOT-MOUNT", Severity: High,
				Message: "mounts the host root into the container", Evidence: f,
				Fix: "Mount only the directories the server needs."})
		case (k == "--network" || k == "--net") && v == "host":
			add(Finding{Rule: "HOST-NETWORK", Severity: Low,
				Message: "container shares the host network namespace", Evidence: f})
		case k == "--pid" && v == "host":
			add(Finding{Rule: "HOST-PID", Severity: Medium,
				Message: "container can see and signal host processes", Evidence: f})
		case k == "--cap-add" && (strings.EqualFold(v, "ALL") || strings.EqualFold(v, "SYS_ADMIN")):
			add(Finding{Rule: "DOCKER-CAPABILITY", Severity: High,
				Message: "container is granted " + v + " capabilities", Evidence: f})
		}
	}
}

func hostSide(volume string) string {
	if i := strings.Index(volume, ":"); i > 0 {
		// Windows drive letters ("C:\...:/data") are not handled; good enough for an MVP.
		return volume[:i]
	}
	return ""
}

var driveRootRe = regexp.MustCompile(`^[A-Za-z]:[\\/]?$`)

func isBroadPath(p, home string) bool {
	switch p {
	case "/", "~", "~/", "$HOME", "${HOME}":
		return true
	}
	if driveRootRe.MatchString(p) {
		return true
	}
	if home != "" && strings.HasPrefix(p, "/") && filepath.Clean(p) == filepath.Clean(home) {
		return true
	}
	return false
}

func checkURL(raw string, add func(Finding)) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		if isRef(raw) {
			return
		}
		add(Finding{Rule: "INVALID-URL", Severity: Low, Message: "server URL could not be parsed", Evidence: raw})
		return
	}
	if u.Scheme == "http" && !isLoopback(u.Hostname()) {
		add(Finding{Rule: "INSECURE-TRANSPORT", Severity: High,
			Message:  "talks to a remote server over plain http://: traffic and credentials can be read or altered",
			Evidence: RedactURL(raw), Fix: "Use https://."})
	}
	if u.User != nil {
		if p, ok := u.User.Password(); ok && !isRef(p) {
			add(Finding{Rule: "CREDENTIAL-IN-URL", Severity: High,
				Message: "URL embeds a password", Evidence: RedactURL(raw),
				Fix: "Move the credential into a header that references an environment variable."})
		}
	}
	for k, vs := range u.Query() {
		if (sensitiveKey(k) || strings.EqualFold(k, "key")) && len(vs) > 0 && !isRef(vs[0]) && vs[0] != "" {
			add(Finding{Rule: "SECRET-IN-URL", Severity: High,
				Message: fmt.Sprintf("URL query parameter %q carries a credential", k), Evidence: RedactURL(raw),
				Fix: "Pass credentials in a header that references an environment variable; URLs end up in logs."})
		}
	}
}

func isLoopback(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

const secretFix = "Keep the value in your shell environment or a secret manager and reference it as ${NAME}; rotate it if this file was ever shared, synced or committed."

func checkSecrets(s config.Server, add func(Finding)) {
	for _, k := range sortedKeys(s.Env) {
		v := s.Env[k]
		if isRef(v) {
			continue
		}
		if kind := secretKind(v); kind != "" {
			add(Finding{Rule: "PLAINTEXT-SECRET", Severity: High,
				Message: fmt.Sprintf("env %s contains a literal %s", k, kind), Evidence: redact(v), Fix: secretFix})
		} else if sensitiveKey(k) && len(v) >= 8 && !looksLikePlainValue(v) {
			add(Finding{Rule: "PLAINTEXT-SECRET", Severity: Medium,
				Message: fmt.Sprintf("env %s looks like a credential stored in plain text", k), Evidence: redact(v), Fix: secretFix})
		}
	}
	for i, a := range s.Args {
		if isRef(a) {
			continue
		}
		if kind := secretKind(a); kind != "" {
			add(Finding{Rule: "PLAINTEXT-SECRET", Severity: High,
				Message:  fmt.Sprintf("argument %d contains a literal %s (visible in process lists)", i, kind),
				Evidence: redact(a), Fix: secretFix})
			continue
		}
		if k, v, ok := strings.Cut(a, "="); ok && strings.HasPrefix(k, "-") && sensitiveKey(k) && len(v) >= 8 && !isRef(v) {
			add(Finding{Rule: "PLAINTEXT-SECRET", Severity: High,
				Message:  fmt.Sprintf("flag %s is given a literal credential (visible in process lists)", k),
				Evidence: k + "=" + redact(v), Fix: secretFix})
			continue
		}
		if i > 0 && strings.HasPrefix(s.Args[i-1], "-") && !strings.Contains(s.Args[i-1], "=") &&
			sensitiveKey(s.Args[i-1]) && !strings.HasPrefix(a, "-") && len(a) >= 8 {
			add(Finding{Rule: "PLAINTEXT-SECRET", Severity: High,
				Message:  fmt.Sprintf("flag %s is given a literal credential (visible in process lists)", s.Args[i-1]),
				Evidence: redact(a), Fix: secretFix})
			continue
		}
		if m := credURLRe.FindStringSubmatch(a); m != nil && !isRef(m[3]) {
			add(Finding{Rule: "CREDENTIAL-IN-ARGS", Severity: Medium,
				Message:  fmt.Sprintf("argument %d is a connection string with an embedded password", i),
				Evidence: credURLRe.ReplaceAllString(a, "$1://$2:****@"), Fix: secretFix})
		}
	}
	for _, k := range sortedKeys(s.Headers) {
		v := s.Headers[k]
		if isRef(v) {
			continue
		}
		bare := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(v, "Bearer "), "Basic "))
		if secretKind(v) != "" || ((strings.EqualFold(k, "authorization") || sensitiveKey(k)) && len(bare) >= 8) {
			add(Finding{Rule: "PLAINTEXT-SECRET", Severity: High,
				Message: fmt.Sprintf("header %s contains a literal credential", k), Evidence: redact(bare), Fix: secretFix})
		}
	}
}

// SecretEnvKeys lists env vars of s whose values are literal credentials,
// using the same rules as the PLAINTEXT-SECRET finding.
func SecretEnvKeys(s config.Server) []string {
	var out []string
	for _, k := range sortedKeys(s.Env) {
		if literalSecretEnv(k, s.Env[k]) {
			out = append(out, k)
		}
	}
	return out
}

// Describe returns a short, redacted, human-readable launch description.
func Describe(s config.Server) string {
	switch s.Transport {
	case "stdio":
		return truncate(strings.TrimSpace(s.Command+" "+strings.Join(RedactArgs(s.Args), " ")), 120)
	case "http", "sse":
		return s.Transport + " " + RedactURL(s.URL)
	}
	return s.Transport
}

func truncate(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
