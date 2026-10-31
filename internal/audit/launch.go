package audit

import (
	"regexp"
	"strings"
)

// Launch describes how a stdio server is started, as far as can be inferred
// from its command line.
type Launch struct {
	Runner  string   // npx | uvx | docker | shell | local | binary
	Package string   // npm/PyPI package, docker image, or script path
	Version string   // version / tag / digest / git rev, if any
	Pinned  bool     // exact version or immutable digest
	Script  string   // inline script for shell wrappers
	Docker  []string // docker run flags, normalised to "--flag=value"
	Rest    []string // arguments passed on to the server itself
}

// ParseLaunch infers the launcher from a command and its arguments.
func ParseLaunch(command string, args []string) Launch {
	base := normBase(command)
	switch {
	case base == "cmd" && len(args) >= 2 && strings.EqualFold(args[0], "/c"):
		return ParseLaunch(args[1], args[2:])
	case isShell(base):
		for i, a := range args {
			if a == "-c" || a == "-lc" || a == "-ic" || strings.EqualFold(a, "-command") || strings.EqualFold(a, "-c") {
				if i+1 < len(args) {
					return Launch{Runner: "shell", Script: strings.Join(args[i+1:], " ")}
				}
			}
		}
		if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
			return Launch{Runner: "local", Package: args[0], Rest: args[1:]}
		}
		return Launch{Runner: "shell", Script: strings.Join(args, " ")}
	case base == "npx" || base == "bunx":
		return parseNode(args)
	case base == "npm" && len(args) > 0 && args[0] == "exec":
		return parseNode(args[1:])
	case (base == "pnpm" || base == "yarn") && len(args) > 0 && args[0] == "dlx":
		return parseNode(args[1:])
	case base == "uvx":
		return parsePy(args)
	case base == "uv" && len(args) >= 2 && args[0] == "tool" && args[1] == "run":
		return parsePy(args[2:])
	case base == "pipx" && len(args) >= 1 && args[0] == "run":
		return parsePy(args[1:])
	case (base == "docker" || base == "podman") && len(args) > 0 && args[0] == "run":
		return parseDocker(args[1:])
	case isInterpreter(base):
		for i, a := range args {
			if a == "-m" && i+1 < len(args) {
				return Launch{Runner: "local", Package: "python -m " + args[i+1], Rest: args[i+2:]}
			}
			if !strings.HasPrefix(a, "-") && a != "run" {
				return Launch{Runner: "local", Package: a, Rest: args[i+1:]}
			}
		}
		return Launch{Runner: "local", Package: command}
	}
	return Launch{Runner: "binary", Package: command, Rest: args}
}

func normBase(command string) string {
	c := strings.ReplaceAll(command, "\\", "/")
	if i := strings.LastIndex(c, "/"); i >= 0 {
		c = c[i+1:]
	}
	c = strings.ToLower(c)
	for _, ext := range []string{".exe", ".cmd", ".bat", ".ps1"} {
		c = strings.TrimSuffix(c, ext)
	}
	return c
}

func isShell(b string) bool {
	switch b {
	case "sh", "bash", "zsh", "dash", "fish", "pwsh", "powershell":
		return true
	}
	return false
}

func isInterpreter(b string) bool {
	switch b {
	case "node", "python", "python3", "deno", "bun", "ruby", "java", "php", "perl", "tsx", "ts-node":
		return true
	}
	return false
}

func parseNode(args []string) Launch {
	l := Launch{Runner: "npx"}
	var spec string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
		case strings.HasPrefix(a, "--package="):
			spec = strings.TrimPrefix(a, "--package=")
		case a == "-p" || a == "--package":
			if i+1 < len(args) {
				i++
				spec = args[i]
			}
		case strings.HasPrefix(a, "-"):
			// boolean flag such as -y / --yes / --quiet
		default:
			if spec == "" {
				spec = a
			}
			l.Rest = args[i+1:]
			i = len(args)
		}
	}
	l.Package, l.Version = splitNodeSpec(spec)
	l.Pinned = exactVersion(l.Version)
	return l
}

func splitNodeSpec(spec string) (name, version string) {
	if strings.HasPrefix(spec, "@") {
		if i := strings.Index(spec[1:], "@"); i >= 0 {
			return spec[:i+1], spec[i+2:]
		}
		return spec, ""
	}
	if strings.Contains(spec, "://") || strings.Contains(spec, ":") {
		return spec, "" // git/URL/github: specs are treated as unpinned
	}
	if i := strings.Index(spec, "@"); i > 0 {
		return spec[:i], spec[i+1:]
	}
	return spec, ""
}

var (
	exactVersionRe = regexp.MustCompile(`^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]+)?$`)
	gitSHARe       = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

func exactVersion(v string) bool { return exactVersionRe.MatchString(v) }

func parsePy(args []string) Launch {
	l := Launch{Runner: "uvx"}
	var from, first string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--from" || a == "--with" || a == "--python" || a == "-p" || a == "--index-url" ||
			a == "--index" || a == "--spec" || a == "--extra-index-url":
			if i+1 < len(args) {
				i++
				if a == "--from" || a == "--spec" {
					from = args[i]
				}
			}
		case strings.HasPrefix(a, "--from="):
			from = strings.TrimPrefix(a, "--from=")
		case strings.HasPrefix(a, "-"):
		default:
			first = a
			l.Rest = args[i+1:]
			i = len(args)
		}
	}
	spec := from
	if spec == "" {
		spec = first
	}
	l.Package, l.Version, l.Pinned = splitPySpec(spec)
	return l
}

func splitPySpec(spec string) (name, version string, pinned bool) {
	spec = strings.TrimSpace(spec)
	if strings.HasPrefix(spec, "git+") {
		scheme := strings.Index(spec, "://")
		if i := strings.LastIndex(spec, "@"); i > scheme {
			return spec[:i], spec[i+1:], gitSHARe.MatchString(spec[i+1:])
		}
		return spec, "", false
	}
	switch {
	case strings.Contains(spec, "=="):
		i := strings.Index(spec, "==")
		name, version = spec[:i], spec[i+2:]
		pinned = version != "" && !strings.ContainsAny(version, "*,")
	case strings.ContainsAny(spec, "<>~!"):
		i := strings.IndexAny(spec, "<>~!")
		name, version = spec[:i], spec[i:]
	case strings.LastIndex(spec, "@") > 0:
		i := strings.LastIndex(spec, "@")
		name, version = spec[:i], spec[i+1:]
		pinned = exactVersion(version)
	default:
		name = spec
	}
	if j := strings.Index(name, "["); j > 0 {
		name = name[:j]
	}
	return strings.TrimSpace(name), version, pinned
}

var dockerValueFlags = map[string]bool{
	"-e": true, "--env": true, "-v": true, "--volume": true, "-p": true, "--publish": true,
	"--name": true, "--network": true, "--net": true, "-w": true, "--workdir": true,
	"-u": true, "--user": true, "--entrypoint": true, "--env-file": true, "--mount": true,
	"-l": true, "--label": true, "--platform": true, "-m": true, "--memory": true,
	"--cpus": true, "--add-host": true, "--cap-add": true, "--cap-drop": true,
	"--device": true, "--security-opt": true, "--pid": true, "--ipc": true, "-h": true,
	"--hostname": true, "--restart": true, "--runtime": true, "--gpus": true, "--pull": true,
	"--log-driver": true, "--tmpfs": true, "--ulimit": true, "--shm-size": true, "--userns": true,
}

func parseDocker(args []string) Launch {
	l := Launch{Runner: "docker"}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			switch {
			case strings.Contains(a, "="):
				l.Docker = append(l.Docker, a)
			case dockerValueFlags[a] && i+1 < len(args):
				l.Docker = append(l.Docker, a+"="+args[i+1])
				i++
			default:
				l.Docker = append(l.Docker, a)
			}
			continue
		}
		l.Package = a
		l.Rest = args[i+1:]
		break
	}
	l.Package, l.Version, l.Pinned = splitImage(l.Package)
	return l
}

func splitImage(img string) (name, version string, pinned bool) {
	if i := strings.Index(img, "@sha256:"); i >= 0 {
		return img[:i], img[i+1:], true
	}
	slash := strings.LastIndex(img, "/")
	if c := strings.LastIndex(img, ":"); c > slash {
		return img[:c], img[c+1:], false
	}
	return img, "", false
}
