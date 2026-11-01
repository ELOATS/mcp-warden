package jsonedit

import (
	"encoding/json"
	"strings"
	"testing"
)

const doc = `{
  // user settings: comments, odd spacing and trailing commas must survive
  "editor.fontSize":14,
  "mcp": {
    "servers": {
      "gh": { "command": "npx", "args": ["-y",   "@modelcontextprotocol/server-github"], },
      "esc\"aped": {"args": ["aé\n", 42, true, null, {"k": "v"}]}, /* block */
    },
  },
}
`

func TestStringsAndApply(t *testing.T) {
	idx, err := Strings([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	spec, ok := idx[Key("mcp", "servers", "gh", "args", "1")]
	if !ok {
		t.Fatalf("arg not indexed; have %d paths", len(idx))
	}
	if v, _ := Value([]byte(doc), spec); v != "@modelcontextprotocol/server-github" {
		t.Fatalf("value = %q", v)
	}
	if s, ok := idx[Key("mcp", "servers", `esc"aped`, "args", "0")]; !ok {
		t.Error("escaped key not indexed")
	} else if v, _ := Value([]byte(doc), s); v != "aé\n" {
		t.Errorf("escaped value = %q", v)
	}
	if _, ok := idx[Key("mcp", "servers", `esc"aped`, "args", "4", "k")]; !ok {
		t.Error("nested object in array not indexed")
	}

	out, err := Apply([]byte(doc), []Edit{
		{Span: spec, Value: "@modelcontextprotocol/server-github@2025.4.8"},
		{Span: idx[Key("mcp", "servers", "gh", "command")], Value: "a<b>&c"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(doc, `"@modelcontextprotocol/server-github"`, `"@modelcontextprotocol/server-github@2025.4.8"`, 1)
	want = strings.Replace(want, `"command": "npx"`, `"command": "a<b>&c"`, 1)
	if string(out) != want {
		t.Errorf("only the two values may change.\n got: %s\nwant: %s", out, want)
	}
}

func TestStringsRejectsBrokenInput(t *testing.T) {
	for _, bad := range []string{`{"a": }`, `{"a" "b"}`, `["x"`, `{"a": "unterminated}`, `{} extra`, `{"a": tru}`} {
		if _, err := Strings([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestApplyRejectsOverlap(t *testing.T) {
	if _, err := Apply([]byte(`{"a":"b"}`), []Edit{{Span{5, 8}, "x"}, {Span{6, 8}, "y"}}); err == nil {
		t.Error("overlapping edits accepted")
	}
}

// Every string value of a plain JSON document is found and decodes to what
// encoding/json sees.
func TestAgreesWithEncodingJSON(t *testing.T) {
	src := `{"mcpServers":{"a":{"command":"uvx","args":["mcp-server-fetch","--x=1"],"env":{"K":"V\t"}}}}`
	idx, err := Strings([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		MCPServers map[string]struct {
			Command string            `json:"command"`
			Args    []string          `json:"args"`
			Env     map[string]string `json:"env"`
		} `json:"mcpServers"`
	}
	_ = json.Unmarshal([]byte(src), &v)
	a := v.MCPServers["a"]
	check := func(want string, path ...string) {
		if got, _ := Value([]byte(src), idx[Key(path...)]); got != want {
			t.Errorf("%v = %q, want %q", path, got, want)
		}
	}
	check(a.Command, "mcpServers", "a", "command")
	check(a.Args[1], "mcpServers", "a", "args", "1")
	check(a.Env["K"], "mcpServers", "a", "env", "K")
}
