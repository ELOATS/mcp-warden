package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ELOATS/mcp-warden/internal/audit"
)

var sample = []audit.Finding{
	{Rule: "TOOL-DEFINITION-CHANGED", Severity: audit.High, Server: "cursor/gh @ ~/.cursor/mcp.json", Tool: "create_issue",
		Message: "tool definition changed", Evidence: "before: a | after: b"},
	{Rule: "NEW-SERVER", Severity: audit.Medium, Server: "cursor/x @ ~/.cursor/mcp.json", Message: "server was added"},
}

func TestDetectFormat(t *testing.T) {
	cases := map[string]string{
		"https://hooks.slack.com/services/T/B/x":                   FormatSlack,
		"https://discord.com/api/webhooks/1/abc":                   FormatDiscord,
		"https://open.feishu.cn/open-apis/bot/v2/hook/abc":         FormatFeishu,
		"https://open.larksuite.com/open-apis/bot/v2/hook/abc":     FormatFeishu,
		"https://oapi.dingtalk.com/robot/send?access_token=abc":    FormatDingTalk,
		"https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=abc": FormatWeCom,
		"https://example.com/hooks/mcp":                            FormatJSON,
		"https://discord.com/channels/1":                           FormatJSON,
	}
	for u, want := range cases {
		if got := DetectFormat(u); got != want {
			t.Errorf("DetectFormat(%s) = %s, want %s", u, got, want)
		}
	}
}

func TestPayloads(t *testing.T) {
	m := Compose(append([]audit.Finding{}, sample...))
	check := func(format, path string) {
		t.Helper()
		b, err := Webhook{URL: "https://example.com", Format: format}.Payload(m)
		if err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		var v map[string]any
		if err := json.Unmarshal(b, &v); err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		var cur any = v
		for _, k := range strings.Split(path, ".") {
			cur = cur.(map[string]any)[k]
		}
		s, _ := cur.(string)
		if !strings.Contains(s, "TOOL-DEFINITION-CHANGED") || !strings.Contains(s, "highest HIGH") {
			t.Errorf("%s: %s = %q", format, path, s)
		}
	}
	check(FormatSlack, "text")
	check(FormatDiscord, "content")
	check(FormatFeishu, "content.text")
	check(FormatDingTalk, "text.content")
	check(FormatWeCom, "text.content")
	check(FormatJSON, "text")
	if _, err := (Webhook{URL: "x", Format: "carrier-pigeon"}).Payload(m); err == nil {
		t.Error("unknown format accepted")
	}
}

func TestWebhookDelivery(t *testing.T) {
	var got []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		switch r.URL.Path {
		case "/fail":
			w.WriteHeader(http.StatusInternalServerError)
		case "/feishu-error":
			_, _ = w.Write([]byte(`{"code":19021,"msg":"sign match fail"}`))
		case "/dingtalk-ok":
			_, _ = w.Write([]byte(`{"errcode":0,"errmsg":"ok"}`))
		}
	}))
	defer srv.Close()
	m := Compose(append([]audit.Finding{}, sample...))
	ctx := context.Background()
	if err := (Webhook{URL: srv.URL + "/ok", Format: FormatJSON}).Notify(ctx, m); err != nil {
		t.Fatal(err)
	}
	var v struct {
		Findings []audit.Finding `json:"findings"`
	}
	if json.Unmarshal(got, &v) != nil || len(v.Findings) != 2 {
		t.Errorf("generic payload: %s", got)
	}
	if err := (Webhook{URL: srv.URL + "/dingtalk-ok", Format: FormatDingTalk}).Notify(ctx, m); err != nil {
		t.Errorf("errcode 0 treated as failure: %v", err)
	}
	if err := (Webhook{URL: srv.URL + "/fail"}).Notify(ctx, m); err == nil {
		t.Error("HTTP 500 not reported")
	}
	if err := (Webhook{URL: srv.URL + "/feishu-error", Format: FormatFeishu}).Notify(ctx, m); err == nil || !strings.Contains(err.Error(), "19021") {
		t.Errorf("body-level error not reported: %v", err)
	}
	secret := "http://127.0.0.1:1/hook/SUPERSECRET"
	if err := (Webhook{URL: secret}).Notify(ctx, m); err == nil || strings.Contains(err.Error(), "SUPERSECRET") {
		t.Errorf("connection error leaks webhook secret: %v", err)
	}
}

func TestDesktopCommandsDoNotInterpolate(t *testing.T) {
	evil := `"; rm -rf ~ #'$(whoami)`
	for _, goos := range []string{"darwin", "linux", "windows"} {
		name, args, env, err := Desktop{GOOS: goos}.Command("title", evil)
		if err != nil {
			t.Fatalf("%s: %v", goos, err)
		}
		script := strings.Join(args, " ")
		if goos == "windows" {
			if strings.Contains(script, evil) || !contains(env, "MCP_WARDEN_BODY="+evil) {
				t.Errorf("windows: body must travel via env only: %v %v", args, env)
			}
			continue
		}
		if args[len(args)-1] != evil || name == "" {
			t.Errorf("%s: body must be its own argv entry: %q", goos, args)
		}
	}
	if _, _, _, err := (Desktop{GOOS: "plan9"}).Command("t", "b"); err == nil {
		t.Error("unsupported OS accepted")
	}
	var ran string
	d := Desktop{GOOS: "linux", run: func(_ context.Context, name string, _, _ []string) error { ran = name; return nil }}
	if err := d.Notify(context.Background(), Message{Title: "t", Body: "b"}); err != nil || ran != "notify-send" {
		t.Errorf("Notify ran %q, err %v", ran, err)
	}
}

func TestState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s", "state.json")
	s, err := LoadState(path)
	if err != nil || len(s.New(sample)) != 2 {
		t.Fatalf("fresh state: %v", err)
	}
	s.Sync(sample, sample[:1], time.Now())
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	s, _ = LoadState(path)
	if n := s.New(sample); len(n) != 1 || n[0].Rule != "NEW-SERVER" {
		t.Fatalf("after alerting one: %+v", n)
	}
	// The alerted finding disappears (re-pinned) and later comes back: alert again.
	s.Sync(sample[1:], nil, time.Now())
	if n := s.New(sample); len(n) != 2 {
		t.Errorf("resolved finding not forgotten: %+v", n)
	}
}

func TestComposeTruncates(t *testing.T) {
	var many []audit.Finding
	for i := 0; i < 20; i++ {
		many = append(many, audit.Finding{Rule: "TOOL-ADDED", Severity: audit.Medium, Server: "s", Tool: strings.Repeat("t", i+1)})
	}
	m := Compose(many)
	if !strings.Contains(m.Body, "and 12 more") || !strings.Contains(m.Title, "20 new") {
		t.Errorf("compose: %s\n%s", m.Title, m.Body)
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
