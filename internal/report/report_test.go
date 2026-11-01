package report

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/ELOATS/mcp-warden/internal/audit"
)

func TestLinesWrap(t *testing.T) {
	text := "npx fetches the latest version: every launch can install a new, possibly compromised, release"
	ls := lines(text, 40, 20, 11)
	if len(ls) < 3 {
		t.Fatalf("expected wrapping, got %q", ls)
	}
	if 20+utf8.RuneCountInString(ls[0]) > 40 {
		t.Errorf("first line too long: %q", ls[0])
	}
	for _, l := range ls[1:] {
		if 11+utf8.RuneCountInString(l) > 40 {
			t.Errorf("continuation too long: %q", l)
		}
	}
	if strings.Join(ls, " ") != text {
		t.Errorf("words lost: %q", ls)
	}
	if ls := lines(text, 0, 20, 11); len(ls) != 1 {
		t.Errorf("width 0 must not wrap: %q", ls)
	}
	long := strings.Repeat("x", 80) // unbreakable tokens are kept whole
	if ls := lines("a "+long, 40, 0, 4); len(ls) != 2 || ls[1] != long {
		t.Errorf("long token: %q", ls)
	}
}

func TestTextLayout(t *testing.T) {
	fs := []audit.Finding{
		{Rule: "PLAINTEXT-SECRET", Severity: audit.High, Server: "s",
			Message:  "env GITHUB_TOKEN contains a literal GitHub token that is long enough to wrap around",
			Evidence: "ghp_…(40 chars)", Fix: "Keep the value in your shell environment or a secret manager and reference it as ${NAME}."},
		{Rule: "LOCAL-SCRIPT", Severity: audit.Info, Server: "s", Message: "runs a local script"},
	}
	r := New("mcp-warden test", []string{"f"}, nil, []ServerView{{ID: "s", Name: "srv", Client: "cursor", Location: ".cursor/mcp.json"}}, fs)
	var b bytes.Buffer
	WriteText(&b, r, Styler{Width: 60}, audit.Low)
	out := b.String()
	for _, l := range strings.Split(out, "\n") {
		if n := utf8.RuneCountInString(l); n > 60 {
			t.Errorf("line exceeds width (%d): %q", n, l)
		}
	}
	for _, want := range []string{"1 config file, 1 server", "Summary: 1 high, 1 info", "1 finding below low not shown", "           fix: Keep"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "LOCAL-SCRIPT") {
		t.Error("info finding shown despite --show low")
	}

	b.Reset()
	WriteText(&b, New("mcp-warden test", nil, nil, nil, nil), Styler{}, audit.Low)
	if !strings.Contains(b.String(), "Claude Desktop") || strings.Contains(b.String(), "Summary") {
		t.Errorf("empty state:\n%s", b.String())
	}
	b.Reset()
	WriteText(&b, New("t", []string{"f"}, nil, []ServerView{{ID: "s", Name: "srv"}}, nil), Styler{}, audit.Low)
	if !strings.Contains(b.String(), "no issues found") {
		t.Errorf("clean summary:\n%s", b.String())
	}
}
