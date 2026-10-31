package audit

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/ELOATS/mcp-warden/internal/config"
	"github.com/ELOATS/mcp-warden/internal/probe"
)

var poisonRules = []struct {
	re   *regexp.Regexp
	sev  Severity
	what string
}{
	{regexp.MustCompile(`(?i)ignore\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier|preceding)\s+(instructions|prompts|rules|messages)`),
		Critical, "tries to override the model's prior instructions"},
	{regexp.MustCompile(`(?i)(do\s+not|don't|never)\s+(tell|inform|mention|reveal|notify|alert)\s+(this\s+to\s+)?(the\s+)?user`),
		Critical, "asks the model to hide what it does from the user"},
	{regexp.MustCompile(`(?i)without\s+(telling|informing|notifying|alerting)\s+(the\s+)?user`),
		Critical, "asks the model to act without the user's knowledge"},
	{regexp.MustCompile(`(?i)<\s*/?\s*(important|system|instructions?|secret|hidden)\s*>`),
		High, "contains instruction-style markup aimed at the model"},
	{regexp.MustCompile(`(?i)(~/\.ssh|id_rsa|id_ed25519|\.aws/credentials|\.npmrc|\.netrc|\.pgpass|\.git-credentials|claude_desktop_config|\.cursor/mcp\.json|private[\s_-]?key)`),
		High, "references credential files or private keys"},
	{regexp.MustCompile(`(?i)(before|prior\s+to)\s+(using|calling|invoking|running)\s+(this|any|the)\s+(tool|function)`),
		Medium, "tells the model what to do before calling tools"},
	{regexp.MustCompile(`(?i)(you\s+must|always)\s+(also\s+)?(send|forward|bcc|cc|copy|upload|post)\b`),
		Medium, "instructs the model to send data somewhere"},
}

const poisonFix = "Do not use this server until the text is explained. Tool descriptions are read by the model as instructions; report it to the maintainer and the registry."

// ToolChecks inspects the tool definitions a single server exposes.
func ToolChecks(s config.Server, tools []probe.Tool) []Finding {
	var out []Finding
	id := s.ID()
	var execTools, destructive []string
	for _, t := range tools {
		text := toolText(t)
		for _, r := range poisonRules {
			if loc := r.re.FindStringIndex(text); loc != nil {
				out = append(out, Finding{Rule: "TOOL-POISONING", Severity: r.sev, Server: id, Tool: t.Name,
					Message:  "tool description " + r.what,
					Evidence: snippet(text, loc[0], loc[1]), Fix: poisonFix})
			}
		}
		if hidden := hiddenRunes(text); len(hidden) > 0 {
			out = append(out, Finding{Rule: "HIDDEN-UNICODE", Severity: High, Server: id, Tool: t.Name,
				Message:  fmt.Sprintf("tool definition contains %d invisible/bidi control character(s) that can hide instructions from humans", len(hidden)),
				Evidence: strings.Join(uniq(hidden), " "), Fix: poisonFix})
		}
		if n := len([]rune(t.Description)); n > 4000 {
			out = append(out, Finding{Rule: "OVERSIZED-DESCRIPTION", Severity: Low, Server: id, Tool: t.Name,
				Message: fmt.Sprintf("description is %d characters long; long descriptions are a common place to bury instructions", n)})
		}
		caps := ToolCapabilities(t)
		if caps["exec"] {
			execTools = append(execTools, t.Name)
		}
		if caps["destructive"] {
			destructive = append(destructive, t.Name)
		}
	}
	if len(execTools) > 0 {
		out = append(out, Finding{Rule: "CAP-EXEC", Severity: Medium, Server: id,
			Message:  "can run arbitrary commands or code",
			Evidence: strings.Join(execTools, ", "),
			Fix:      "Keep per-call approval on for these tools; never auto-approve them."})
	}
	if len(destructive) > 0 {
		out = append(out, Finding{Rule: "CAP-DESTRUCTIVE", Severity: Low, Server: id,
			Message:  "declares destructive tools",
			Evidence: strings.Join(destructive, ", ")})
	}
	return out
}

// ServerTools pairs a server with the tools it exposed during a probe.
type ServerTools struct {
	Server config.Server
	Tools  []probe.Tool
}

// CrossChecks looks for dangerous combinations across servers of one client.
func CrossChecks(all []ServerTools) []Finding {
	byClient := map[string][]ServerTools{}
	for _, st := range all {
		if st.Server.Disabled {
			continue
		}
		byClient[st.Server.Client] = append(byClient[st.Server.Client], st)
	}
	var out []Finding
	for _, client := range sortedKeys(byClient) {
		group := byClient[client]
		scope := "client:" + client

		// 1. Tool name collisions (the model may call the wrong server).
		owners := map[string][]string{}
		for _, st := range group {
			for _, t := range st.Tools {
				owners[t.Name] = appendUniq(owners[t.Name], st.Server.Name)
			}
		}
		for _, name := range sortedKeys(owners) {
			if len(owners[name]) > 1 {
				out = append(out, Finding{Rule: "TOOL-NAME-COLLISION", Severity: Medium, Server: scope, Tool: name,
					Message:  fmt.Sprintf("tool %q is exposed by %d servers", name, len(owners[name])),
					Evidence: strings.Join(owners[name], ", "),
					Fix:      "Disable or rename one of them; a malicious server can shadow a trusted tool this way."})
			}
		}

		// 2. Descriptions that talk about other servers' tools (tool shadowing).
		for _, a := range group {
			for _, b := range group {
				if a.Server.ID() == b.Server.ID() {
					continue
				}
				for _, t := range a.Tools {
					for _, other := range b.Tools {
						n := other.Name
						if len(n) < 6 || !strings.ContainsAny(n, "_-") {
							continue
						}
						re := regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(n) + `\b`)
						if loc := re.FindStringIndex(t.Description); loc != nil {
							out = append(out, Finding{Rule: "CROSS-TOOL-REFERENCE", Severity: Medium, Server: a.Server.ID(), Tool: t.Name,
								Message:  fmt.Sprintf("description refers to tool %q of server %q", n, b.Server.Name),
								Evidence: snippet(t.Description, loc[0], loc[1]),
								Fix:      "A tool should not give instructions about another server's tools; this is a known shadowing attack."})
						}
					}
				}
			}
		}

		// 3. The "lethal trifecta": untrusted input + private data + a way out.
		var net, priv []string
		for _, st := range group {
			caps := ServerCapabilities(st.Tools)
			if contains(caps, "network") {
				net = append(net, st.Server.Name)
			}
			if contains(caps, "fs-read") || contains(caps, "exec") {
				priv = append(priv, st.Server.Name)
			}
		}
		if len(net) > 0 && len(priv) > 0 {
			out = append(out, Finding{Rule: "LETHAL-TRIFECTA", Severity: Medium, Server: scope,
				Message: "this client combines tools that fetch untrusted content with tools that read local data or run commands",
				Evidence: fmt.Sprintf("network: %s | local data/exec: %s",
					strings.Join(uniq(net), ", "), strings.Join(uniq(priv), ", ")),
				Fix: "Injected text from the web can make the model read secrets and send them out. Keep approvals on, or split these servers into separate profiles."})
		}
	}
	return out
}

var capRules = []struct {
	cap   string
	words []string
}{
	{"exec", []string{"exec", "execute", "shell", "bash", "terminal", "command", "run_command", "run_code", "eval", "spawn", "subprocess", "powershell", "run_script"}},
	{"fs-write", []string{"write", "edit", "create_file", "delete", "remove", "move", "rename", "mkdir", "create_directory", "patch", "upload", "save", "append"}},
	{"fs-read", []string{"read", "cat", "list_directory", "list_files", "get_file", "search_files", "file_contents", "tree", "directory_tree", "read_file"}},
	{"network", []string{"fetch", "http", "request", "browse", "navigate", "url", "download", "scrape", "crawl", "web", "curl"}},
	{"send", []string{"send", "email", "message", "post", "publish", "comment", "notify", "tweet", "create_issue", "create_pull_request", "push"}},
}

// ToolCapabilities classifies a tool by its name and annotations.
func ToolCapabilities(t probe.Tool) map[string]bool {
	norm, toks := tokens(t.Name)
	caps := map[string]bool{}
	for _, r := range capRules {
		for _, w := range r.words {
			if strings.Contains(w, "_") {
				if strings.Contains("_"+norm+"_", "_"+w+"_") {
					caps[r.cap] = true
				}
				continue
			}
			for _, tok := range toks {
				if tok == w {
					caps[r.cap] = true
				}
			}
		}
	}
	var ann struct {
		DestructiveHint *bool `json:"destructiveHint"`
		OpenWorldHint   *bool `json:"openWorldHint"`
	}
	if len(t.Annotations) > 0 && json.Unmarshal(t.Annotations, &ann) == nil {
		if ann.DestructiveHint != nil && *ann.DestructiveHint {
			caps["destructive"] = true
		}
		if ann.OpenWorldHint != nil && *ann.OpenWorldHint {
			caps["network"] = true
		}
	}
	return caps
}

// ServerCapabilities is the sorted union of all tool capabilities.
func ServerCapabilities(tools []probe.Tool) []string {
	set := map[string]bool{}
	for _, t := range tools {
		for c := range ToolCapabilities(t) {
			set[c] = true
		}
	}
	return sortedKeys(set)
}

func tokens(name string) (string, []string) {
	var b strings.Builder
	prevLower := false
	for _, r := range name {
		switch {
		case r == '-' || r == '.' || r == ' ' || r == '/' || r == '_':
			b.WriteByte('_')
			prevLower = false
		case unicode.IsUpper(r):
			if prevLower {
				b.WriteByte('_')
			}
			b.WriteRune(unicode.ToLower(r))
			prevLower = false
		default:
			b.WriteRune(r)
			prevLower = unicode.IsLower(r) || unicode.IsDigit(r)
		}
	}
	norm := b.String()
	return norm, strings.FieldsFunc(norm, func(r rune) bool { return r == '_' })
}

// toolText concatenates every human/model-readable string in a tool definition.
func toolText(t probe.Tool) string {
	parts := []string{t.Name, t.Title, t.Description}
	var v any
	if len(t.InputSchema) > 0 && json.Unmarshal(t.InputSchema, &v) == nil {
		walkStrings(v, &parts)
	}
	return strings.Join(parts, "\n")
}

func walkStrings(v any, out *[]string) {
	switch x := v.(type) {
	case string:
		*out = append(*out, x)
	case []any:
		for _, e := range x {
			walkStrings(e, out)
		}
	case map[string]any:
		for _, k := range sortedKeys(x) {
			*out = append(*out, k)
			walkStrings(x[k], out)
		}
	}
}

func isHidden(r rune) bool {
	return (r >= 0x200B && r <= 0x200F) || (r >= 0x202A && r <= 0x202E) ||
		(r >= 0x2060 && r <= 0x2064) || (r >= 0x2066 && r <= 0x2069) ||
		r == 0xFEFF || r == 0x00AD || (r >= 0xE0000 && r <= 0xE007F)
}

func hiddenRunes(s string) []string {
	var out []string
	for _, r := range s {
		if isHidden(r) {
			out = append(out, fmt.Sprintf("U+%04X", r))
		}
	}
	return out
}

func snippet(text string, start, end int) string {
	from, to := start-60, end+60
	if from < 0 {
		from = 0
	}
	if to > len(text) {
		to = len(text)
	}
	s := strings.ToValidUTF8(text[from:to], "")
	var b strings.Builder
	for _, r := range s {
		if isHidden(r) {
			fmt.Fprintf(&b, "<U+%04X>", r)
			continue
		}
		b.WriteRune(r)
	}
	out := strings.Join(strings.Fields(b.String()), " ")
	if from > 0 {
		out = "…" + out
	}
	if to < len(text) {
		out += "…"
	}
	return out
}

func uniq(in []string) []string {
	var out []string
	for _, s := range in {
		out = appendUniq(out, s)
	}
	sort.Strings(out)
	return out
}

func appendUniq(list []string, s string) []string {
	if contains(list, s) {
		return list
	}
	return append(list, s)
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
