// Package notify delivers alerts to the desktop or to chat webhooks
// (Slack, Discord, Feishu/Lark, DingTalk, WeCom or generic JSON).
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/ELOATS/mcp-warden/internal/audit"
)

// Message is one alert.
type Message struct {
	Title    string
	Body     string // multi-line plain text
	Findings []audit.Finding
}

// Notifier sends a Message somewhere.
type Notifier interface {
	Name() string
	Notify(ctx context.Context, m Message) error
}

// ---------------------------------------------------------------- desktop

// Desktop shows a native notification using the OS's built-in tooling.
type Desktop struct {
	GOOS string // defaults to runtime.GOOS; overridable for tests
	run  func(ctx context.Context, name string, args, env []string) error
}

func (d Desktop) Name() string { return "desktop" }

// Command returns the program, arguments and extra environment used to show
// a notification. Title and body are passed as arguments or environment
// variables, never spliced into a script, so they cannot inject code.
func (d Desktop) Command(title, body string) (string, []string, []string, error) {
	goos := d.GOOS
	if goos == "" {
		goos = runtime.GOOS
	}
	switch goos {
	case "darwin":
		return "osascript", []string{
			"-e", "on run argv",
			"-e", "display notification (item 2 of argv) with title (item 1 of argv)",
			"-e", "end run",
			title, body,
		}, nil, nil
	case "windows":
		script := "Add-Type -AssemblyName System.Windows.Forms; Add-Type -AssemblyName System.Drawing; " +
			"$n = New-Object System.Windows.Forms.NotifyIcon; $n.Icon = [System.Drawing.SystemIcons]::Warning; " +
			"$n.Visible = $true; $n.ShowBalloonTip(10000, $env:MCP_WARDEN_TITLE, $env:MCP_WARDEN_BODY, 'Warning'); " +
			"Start-Sleep -Seconds 6; $n.Dispose()"
		return "powershell", []string{"-NoProfile", "-NonInteractive", "-Command", script},
			[]string{"MCP_WARDEN_TITLE=" + title, "MCP_WARDEN_BODY=" + body}, nil
	case "linux", "freebsd", "openbsd", "netbsd":
		return "notify-send", []string{"--urgency=critical", "--app-name=mcp-warden", title, body}, nil, nil
	}
	return "", nil, nil, fmt.Errorf("desktop notifications are not supported on %s", goos)
}

func (d Desktop) Notify(ctx context.Context, m Message) error {
	name, args, env, err := d.Command(m.Title, clip(m.Body, 400))
	if err != nil {
		return err
	}
	run := d.run
	if run == nil {
		run = runCommand
	}
	return run(ctx, name, args, env)
}

func runCommand(ctx context.Context, name string, args, env []string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), env...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %v %s", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ---------------------------------------------------------------- webhook

// Webhook formats.
const (
	FormatAuto     = "auto"
	FormatSlack    = "slack"
	FormatDiscord  = "discord"
	FormatFeishu   = "feishu"
	FormatDingTalk = "dingtalk"
	FormatWeCom    = "wecom"
	FormatJSON     = "json"
)

// Formats lists the accepted --webhook-format values.
var Formats = []string{FormatAuto, FormatSlack, FormatDiscord, FormatFeishu, FormatDingTalk, FormatWeCom, FormatJSON}

// DetectFormat guesses the payload format from the webhook host.
func DetectFormat(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return FormatJSON
	}
	h := strings.ToLower(u.Hostname())
	switch {
	case h == "hooks.slack.com":
		return FormatSlack
	case (h == "discord.com" || h == "discordapp.com") && strings.HasPrefix(u.Path, "/api/webhooks/"):
		return FormatDiscord
	case h == "open.feishu.cn" || h == "open.larksuite.com":
		return FormatFeishu
	case h == "oapi.dingtalk.com":
		return FormatDingTalk
	case h == "qyapi.weixin.qq.com":
		return FormatWeCom
	}
	return FormatJSON
}

// Webhook posts the alert as JSON.
type Webhook struct {
	URL    string
	Format string
	Client *http.Client
}

func (w Webhook) Name() string { return "webhook (" + w.format() + ")" }

func (w Webhook) format() string {
	if w.Format == "" || w.Format == FormatAuto {
		return DetectFormat(w.URL)
	}
	return w.Format
}

// Payload builds the request body for the configured format.
func (w Webhook) Payload(m Message) ([]byte, error) {
	text := m.Title + "\n" + m.Body
	var v any
	switch w.format() {
	case FormatSlack:
		v = map[string]any{"text": clip(text, 3500)}
	case FormatDiscord:
		v = map[string]any{"content": clip(text, 1900), "username": "mcp-warden"}
	case FormatFeishu:
		v = map[string]any{"msg_type": "text", "content": map[string]any{"text": clip(text, 3500)}}
	case FormatDingTalk, FormatWeCom:
		v = map[string]any{"msgtype": "text", "text": map[string]any{"content": clip(text, 1800)}}
	case FormatJSON:
		fs := m.Findings
		if fs == nil {
			fs = []audit.Finding{}
		}
		v = map[string]any{"source": "mcp-warden", "title": m.Title, "text": text, "findings": fs}
	default:
		return nil, fmt.Errorf("unknown webhook format %q", w.Format)
	}
	return json.Marshal(v)
}

func (w Webhook) Notify(ctx context.Context, m Message) error {
	body, err := w.Payload(m)
	if err != nil {
		return err
	}
	client := w.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return errors.New(redactURLError(err.Error(), w.URL))
	}
	defer resp.Body.Close()
	reply, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(reply)))
	}
	// Feishu, DingTalk and WeCom answer 200 with an error code in the body.
	var r struct {
		Code    *int   `json:"code"`
		ErrCode *int   `json:"errcode"`
		Msg     string `json:"msg"`
		ErrMsg  string `json:"errmsg"`
	}
	if json.Unmarshal(reply, &r) == nil {
		if r.Code != nil && *r.Code != 0 {
			return fmt.Errorf("webhook rejected the message: code %d %s", *r.Code, r.Msg)
		}
		if r.ErrCode != nil && *r.ErrCode != 0 {
			return fmt.Errorf("webhook rejected the message: errcode %d %s", *r.ErrCode, r.ErrMsg)
		}
	}
	return nil
}

// Webhook URLs embed their secret; keep it out of error messages and logs.
func redactURLError(msg, raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return strings.ReplaceAll(msg, raw, "<webhook>")
	}
	return strings.ReplaceAll(msg, raw, u.Scheme+"://"+u.Host+"/…")
}

// ---------------------------------------------------------------- message

// Compose turns findings into a short alert.
func Compose(findings []audit.Finding) Message {
	audit.Sort(findings)
	top := audit.Info
	for _, f := range findings {
		if f.Severity > top {
			top = f.Severity
		}
	}
	title := fmt.Sprintf("mcp-warden: %d new MCP change(s), highest %s", len(findings), strings.ToUpper(top.String()))
	var b strings.Builder
	for i, f := range findings {
		if i == 8 {
			fmt.Fprintf(&b, "…and %d more. Run `mcp-warden diff` for details.\n", len(findings)-i)
			break
		}
		subject := f.Server
		if f.Tool != "" {
			subject += " · tool " + f.Tool
		}
		fmt.Fprintf(&b, "[%s] %s: %s (%s)\n", strings.ToUpper(f.Severity.String()), f.Rule, f.Message, subject)
	}
	return Message{Title: title, Body: strings.TrimRight(b.String(), "\n"), Findings: findings}
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
