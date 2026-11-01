package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	serviceLabel = "io.github.eloats.mcp-warden" // launchd label
	serviceName  = "mcp-warden"                  // systemd unit / Windows task name
)

// installer writes and registers a per-user scheduled job that runs
// `mcp-warden watch --once` with the user's flags. Everything that touches
// the OS is injectable so all three platforms can be tested anywhere.
type installer struct {
	goos      string
	home      string
	configDir string // XDG config dir on Linux
	exe       string
	env       func(string) string
	run       func(name string, args ...string) error
	lookPath  func(string) (string, error)
	out       io.Writer
}

func newInstaller(home, configDir string, out io.Writer) (installer, error) {
	exe, err := os.Executable()
	if err != nil {
		return installer{}, err
	}
	if p, err := filepath.EvalSymlinks(exe); err == nil {
		exe = p
	}
	if strings.Contains(exe, "go-build") || strings.HasPrefix(exe, os.TempDir()) {
		return installer{}, fmt.Errorf("%s looks like a temporary build (go run); install mcp-warden first, e.g. with go install or a release binary", exe)
	}
	return installer{
		goos: goos(), home: home, configDir: configDir, exe: exe, env: os.Getenv,
		run: func(name string, args ...string) error {
			out, err := exec.Command(name, args...).CombinedOutput()
			if err != nil {
				return fmt.Errorf("%s %s: %v %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
			}
			return nil
		},
		lookPath: exec.LookPath, out: out,
	}, nil
}

func (in installer) stateDir() string { return filepath.Join(in.home, ".mcp-warden") }
func (in installer) logPath() string  { return filepath.Join(in.stateDir(), "watch.log") }

// webhookFile holds the webhook URL outside the (world-readable) job definition.
func webhookFile(home string) string { return filepath.Join(home, ".mcp-warden", "webhook") }

func (in installer) paths() []string {
	switch in.goos {
	case "darwin":
		return []string{filepath.Join(in.home, "Library", "LaunchAgents", serviceLabel+".plist")}
	case "windows":
		return []string{filepath.Join(in.stateDir(), "watch.cmd")}
	default:
		dir := filepath.Join(in.configDir, "systemd", "user")
		return []string{filepath.Join(dir, serviceName+".service"), filepath.Join(dir, serviceName+".timer")}
	}
}

func (in installer) install(args []string, interval time.Duration, webhook string) error {
	if err := os.MkdirAll(in.stateDir(), 0o700); err != nil {
		return err
	}
	if webhook != "" {
		if err := os.WriteFile(webhookFile(in.home), []byte(webhook+"\n"), 0o600); err != nil {
			return err
		}
	}
	argv := append([]string{in.exe, "watch", "--once"}, args...)
	var err error
	switch in.goos {
	case "darwin":
		err = in.installLaunchd(argv, interval)
	case "windows":
		err = in.installSchtasks(argv, interval)
	case "linux":
		err = in.installSystemd(argv, interval)
	default:
		err = fmt.Errorf("--install is not supported on %s; schedule `%s` with your system's scheduler", in.goos, strings.Join(argv, " "))
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(in.out, "Installed: mcp-warden now checks every %s.\n", interval)
	for _, p := range in.paths() {
		fmt.Fprintf(in.out, "  job:     %s\n", p)
	}
	fmt.Fprintf(in.out, "  command: %s\n", strings.Join(argv, " "))
	fmt.Fprintf(in.out, "  log:     %s\n", in.logPath())
	if webhook != "" {
		fmt.Fprintf(in.out, "  webhook: stored in %s (readable only by you)\n", webhookFile(in.home))
	}
	fmt.Fprintln(in.out, "Remove it with: mcp-warden watch --uninstall")
	return nil
}

func (in installer) uninstall() error {
	var errs []string
	switch in.goos {
	case "darwin":
		_ = in.run("launchctl", "bootout", "gui/"+strconv.Itoa(os.Getuid())+"/"+serviceLabel)
	case "windows":
		if err := in.run("schtasks", "/Delete", "/F", "/TN", serviceName); err != nil {
			errs = append(errs, err.Error())
		}
	case "linux":
		_ = in.run("systemctl", "--user", "disable", "--now", serviceName+".timer")
	}
	removed := 0
	for _, p := range append(in.paths(), webhookFile(in.home)) {
		if err := os.Remove(p); err == nil {
			removed++
			fmt.Fprintf(in.out, "removed %s\n", p)
		} else if !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err.Error())
		}
	}
	if in.goos == "linux" && removed > 0 {
		_ = in.run("systemctl", "--user", "daemon-reload")
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	if removed == 0 {
		fmt.Fprintln(in.out, "Nothing to remove: mcp-warden watch was not installed.")
	} else {
		fmt.Fprintln(in.out, "Uninstalled. Baseline and logs in "+in.stateDir()+" were kept.")
	}
	return nil
}

// ---------------------------------------------------------------- macOS

func xmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;").Replace(s)
}

func (in installer) installLaunchd(argv []string, interval time.Duration) error {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>` + serviceLabel + `</string>
  <key>ProgramArguments</key>
  <array>
`)
	for _, a := range argv {
		fmt.Fprintf(&b, "    <string>%s</string>\n", xmlEscape(a))
	}
	fmt.Fprintf(&b, `  </array>
  <key>StartInterval</key><integer>%d</integer>
  <key>RunAtLoad</key><true/>
  <key>StandardOutPath</key><string>%s</string>
  <key>StandardErrorPath</key><string>%s</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key><string>%s</string>
  </dict>
</dict>
</plist>
`, int(interval.Seconds()), xmlEscape(in.logPath()), xmlEscape(in.logPath()), xmlEscape(in.env("PATH")))
	path := in.paths()[0]
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		return err
	}
	domain := "gui/" + strconv.Itoa(os.Getuid())
	_ = in.run("launchctl", "bootout", domain+"/"+serviceLabel) // replace an older install
	return in.run("launchctl", "bootstrap", domain, path)
}

// ---------------------------------------------------------------- Linux

// systemdQuote quotes one ExecStart word (systemd.service(5) quoting).
func systemdQuote(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\"'\\$%;") {
		return s
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `$`, `$$`, `%`, `%%`)
	return `"` + r.Replace(s) + `"`
}

func (in installer) installSystemd(argv []string, interval time.Duration) error {
	if _, err := in.lookPath("systemctl"); err != nil {
		return fmt.Errorf("systemctl not found; add this to `crontab -e` instead:\n  */%d * * * * %s >> %s 2>&1",
			max(1, int(interval.Minutes())%60), strings.Join(argv, " "), in.logPath())
	}
	words := make([]string, len(argv))
	for i, a := range argv {
		words[i] = systemdQuote(a)
	}
	log := systemdQuote(in.logPath())
	env := "Environment=" + systemdQuote("PATH="+in.env("PATH")) + "\n"
	if bus := in.env("DBUS_SESSION_BUS_ADDRESS"); bus != "" { // needed for notify-send
		env += "Environment=" + systemdQuote("DBUS_SESSION_BUS_ADDRESS="+bus) + "\n"
	}
	service := fmt.Sprintf(`[Unit]
Description=mcp-warden: alert on MCP server changes

[Service]
Type=oneshot
ExecStart=%s
%sStandardOutput=append:%s
StandardError=append:%s
`, strings.Join(words, " "), env, strings.Trim(log, `"`), strings.Trim(log, `"`))
	timer := fmt.Sprintf(`[Unit]
Description=Run mcp-warden every %s

[Timer]
OnBootSec=5min
OnUnitActiveSec=%ds
Unit=%s.service

[Install]
WantedBy=timers.target
`, interval, int(interval.Seconds()), serviceName)
	p := in.paths()
	if err := os.MkdirAll(filepath.Dir(p[0]), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(p[0], []byte(service), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(p[1], []byte(timer), 0o644); err != nil {
		return err
	}
	if err := in.run("systemctl", "--user", "daemon-reload"); err != nil {
		return err
	}
	return in.run("systemctl", "--user", "enable", "--now", serviceName+".timer")
}

// ---------------------------------------------------------------- Windows

func cmdQuote(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t&|<>^\"%") {
		return s
	}
	return `"` + strings.ReplaceAll(strings.ReplaceAll(s, `"`, `""`), "%", "%%") + `"`
}

func (in installer) installSchtasks(argv []string, interval time.Duration) error {
	// schtasks /TR is limited to 261 characters, so the command lives in a
	// small wrapper script.
	words := make([]string, len(argv))
	for i, a := range argv {
		words[i] = cmdQuote(a)
	}
	script := "@echo off\r\n" + strings.Join(words, " ") + " >> " + cmdQuote(in.logPath()) + " 2>&1\r\n"
	path := in.paths()[0]
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		return err
	}
	sched, mod := "MINUTE", int(interval.Minutes())
	switch {
	case mod >= 24*60:
		sched, mod = "DAILY", mod/(24*60)
	case mod >= 60 && mod%60 == 0:
		sched, mod = "HOURLY", mod/60
	case mod > 1439:
		sched, mod = "HOURLY", mod/60
	}
	return in.run("schtasks", "/Create", "/F", "/TN", serviceName, "/SC", sched, "/MO", strconv.Itoa(max(1, mod)), "/TR", cmdQuote(path))
}

// ---------------------------------------------------------------- args

// scheduledArgs returns the flags to bake into the scheduled command: the
// user's flags minus install-only ones, with paths made absolute (the job
// does not run in the current directory). The webhook URL is never copied;
// it is stored separately (see webhookFile).
func scheduledArgs(args []string, project string) ([]string, error) {
	drop := map[string]bool{"install": true, "uninstall": true, "once": true}
	dropValue := map[string]bool{"interval": true, "webhook": true}
	pathValue := map[string]bool{"project": true, "config": true, "lock": true, "policy": true, "state": true}
	var out []string
	sawProject := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		name, val, hasVal := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if !strings.HasPrefix(a, "-") {
			out = append(out, a)
			continue
		}
		takesValue := dropValue[name] || pathValue[name] || name == "timeout" || name == "fail-on" ||
			name == "notify" || name == "webhook-format"
		if takesValue && !hasVal && i+1 < len(args) {
			i++
			val, hasVal = args[i], true
		}
		switch {
		case drop[name] || dropValue[name]:
			continue
		case pathValue[name]:
			abs, err := filepath.Abs(val)
			if err != nil {
				return nil, err
			}
			sawProject = sawProject || name == "project"
			out = append(out, "--"+name, abs)
		case hasVal:
			out = append(out, "--"+name, val)
		default:
			out = append(out, "--"+name)
		}
	}
	if !sawProject {
		abs, err := filepath.Abs(project)
		if err != nil {
			return nil, err
		}
		out = append([]string{"--project", abs}, out...)
	}
	return out, nil
}
