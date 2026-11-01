package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fakeInstaller(t *testing.T, goos string) (installer, *[]string, *bytes.Buffer) {
	t.Helper()
	home := t.TempDir()
	var cmds []string
	var out bytes.Buffer
	return installer{
		goos: goos, home: home, configDir: filepath.Join(home, ".config"), exe: "/opt/bin/mcp-warden",
		env: func(k string) string {
			return map[string]string{"PATH": "/opt/homebrew/bin:/usr/bin", "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus"}[k]
		},
		run: func(name string, args ...string) error {
			cmds = append(cmds, name+" "+strings.Join(args, " "))
			return nil
		},
		lookPath: func(string) (string, error) { return "/usr/bin/systemctl", nil },
		out:      &out,
	}, &cmds, &out
}

const secretHook = "https://open.feishu.cn/open-apis/bot/v2/hook/SECRET-TOKEN"

func readAll(t *testing.T, paths []string) string {
	t.Helper()
	var b strings.Builder
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("missing job file: %v", err)
		}
		b.Write(data)
	}
	return b.String()
}

func TestInstallPerPlatform(t *testing.T) {
	args := []string{"--project", "/work/app", "--probe"}
	cases := map[string][]string{
		"darwin":  {"<string>/opt/bin/mcp-warden</string>", "<string>--once</string>", "<string>--probe</string>", "<integer>1800</integer>", "/opt/homebrew/bin"},
		"linux":   {"ExecStart=/opt/bin/mcp-warden watch --once --project /work/app --probe", "OnUnitActiveSec=1800s", "PATH=/opt/homebrew/bin", "DBUS_SESSION_BUS_ADDRESS", "WantedBy=timers.target"},
		"windows": {"/opt/bin/mcp-warden watch --once --project /work/app --probe >> ", "2>&1"},
	}
	wantCmds := map[string][]string{
		"darwin":  {"launchctl bootstrap gui/"},
		"linux":   {"systemctl --user daemon-reload", "systemctl --user enable --now mcp-warden.timer"},
		"windows": {"schtasks /Create /F /TN mcp-warden /SC MINUTE /MO 30 /TR "},
	}
	for goos, wants := range cases {
		in, cmds, out := fakeInstaller(t, goos)
		if err := in.install(args, 30*time.Minute, secretHook); err != nil {
			t.Fatalf("%s: %v", goos, err)
		}
		job := readAll(t, in.paths())
		for _, w := range wants {
			if !strings.Contains(job, w) {
				t.Errorf("%s: job file lacks %q:\n%s", goos, w, job)
			}
		}
		if strings.Contains(job, "SECRET-TOKEN") || strings.Contains(strings.Join(*cmds, " "), "SECRET-TOKEN") || strings.Contains(out.String(), "SECRET-TOKEN") {
			t.Errorf("%s: webhook secret leaked into the job, commands or output", goos)
		}
		fi, err := os.Stat(webhookFile(in.home))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: webhook file must exist with 0600: %v %v", goos, err, fi)
		}
		for _, w := range wantCmds[goos] {
			found := false
			for _, c := range *cmds {
				found = found || strings.HasPrefix(c, w)
			}
			if !found {
				t.Errorf("%s: missing command %q in %q", goos, w, *cmds)
			}
		}

		*cmds = nil
		out.Reset()
		if err := in.uninstall(); err != nil {
			t.Fatalf("%s uninstall: %v", goos, err)
		}
		for _, p := range append(in.paths(), webhookFile(in.home)) {
			if _, err := os.Stat(p); err == nil {
				t.Errorf("%s: %s not removed", goos, p)
			}
		}
		if err := in.uninstall(); err != nil || !strings.Contains(out.String(), "Nothing to remove") {
			t.Errorf("%s: second uninstall: %v %q", goos, err, out.String())
		}
	}
}

func TestInstallQuotingAndIntervals(t *testing.T) {
	in, cmds, _ := fakeInstaller(t, "linux")
	if err := in.install([]string{"--project", "/My Projects/app 100%"}, time.Hour, ""); err != nil {
		t.Fatal(err)
	}
	if job := readAll(t, in.paths()); !strings.Contains(job, `"/My Projects/app 100%%"`) {
		t.Errorf("systemd quoting:\n%s", job)
	}
	if _, err := os.Stat(webhookFile(in.home)); err == nil {
		t.Error("webhook file written although no webhook was given")
	}
	_ = cmds

	win, wcmds, _ := fakeInstaller(t, "windows")
	_ = win.install(nil, 2*time.Hour, "")
	_ = win.install(nil, 48*time.Hour, "")
	all := strings.Join(*wcmds, "\n")
	if !strings.Contains(all, "/SC HOURLY /MO 2") || !strings.Contains(all, "/SC DAILY /MO 2") {
		t.Errorf("windows schedules: %s", all)
	}

	mac, _, _ := fakeInstaller(t, "darwin")
	_ = mac.install([]string{"--policy", "/a&b/<p>.json"}, time.Hour, "")
	if job := readAll(t, mac.paths()); !strings.Contains(job, "/a&amp;b/&lt;p&gt;.json") {
		t.Errorf("plist escaping:\n%s", job)
	}

	none, _, _ := fakeInstaller(t, "linux")
	none.lookPath = func(string) (string, error) { return "", os.ErrNotExist }
	if err := none.install(nil, time.Hour, ""); err == nil || !strings.Contains(err.Error(), "crontab") {
		t.Errorf("missing systemctl should suggest cron: %v", err)
	}
}

func TestScheduledArgs(t *testing.T) {
	wd, _ := os.Getwd()
	got, err := scheduledArgs([]string{"--install", "--interval", "30m", "--webhook=https://x/SECRET", "--probe",
		"--lock", "rel/lock.json", "--fail-on", "high", "--once", "-notify", "none"}, ".")
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(got, " ")
	want := "--project " + wd + " --probe --lock " + filepath.Join(wd, "rel/lock.json") + " --fail-on high --notify none"
	if joined != want {
		t.Errorf("scheduledArgs:\n got %s\nwant %s", joined, want)
	}
}
