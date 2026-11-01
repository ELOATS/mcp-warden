// Package report renders scan and diff results as text or JSON.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/ELOATS/mcp-warden/internal/audit"
	"github.com/ELOATS/mcp-warden/internal/config"
	"github.com/ELOATS/mcp-warden/internal/probe"
)

// ServerView is one server as shown in a report.
type ServerView struct {
	ID           string          `json:"id"`
	Client       string          `json:"client"`
	Name         string          `json:"name"`
	Location     string          `json:"location"`
	Transport    string          `json:"transport"`
	Launch       string          `json:"launch"`
	Disabled     bool            `json:"disabled,omitempty"`
	Probe        *probe.Result   `json:"probe,omitempty"`
	Capabilities []string        `json:"capabilities,omitempty"`
	Findings     []audit.Finding `json:"findings"`
}

// Report is the result of a scan.
type Report struct {
	Generator  string          `json:"generator"`
	Files      []string        `json:"files"`
	Warnings   []string        `json:"warnings,omitempty"`
	Policy     string          `json:"policy,omitempty"`     // policy file in effect
	Suppressed int             `json:"suppressed,omitempty"` // findings hidden by policy ignores
	Servers    []ServerView    `json:"servers"`
	Global     []audit.Finding `json:"global,omitempty"`
	Summary    map[string]int  `json:"summary"`
}

// New distributes findings to their servers.
func New(generator string, files, warnings []string, servers []ServerView, findings []audit.Finding) Report {
	idx := map[string]int{}
	for i := range servers {
		idx[servers[i].ID] = i
		servers[i].Findings = []audit.Finding{}
	}
	r := Report{Generator: generator, Files: files, Warnings: warnings, Summary: audit.Summary(findings)}
	if r.Files == nil {
		r.Files = []string{}
	}
	for _, f := range findings {
		if i, ok := idx[f.Server]; ok {
			servers[i].Findings = append(servers[i].Findings, f)
		} else {
			r.Global = append(r.Global, f)
		}
	}
	for i := range servers {
		audit.Sort(servers[i].Findings)
	}
	audit.Sort(r.Global)
	r.Servers = servers
	if r.Servers == nil {
		r.Servers = []ServerView{}
	}
	return r
}

// All returns every finding in the report.
func (r Report) All() []audit.Finding {
	out := append([]audit.Finding{}, r.Global...)
	for _, s := range r.Servers {
		out = append(out, s.Findings...)
	}
	return out
}

// WriteJSON writes v as indented JSON.
func WriteJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// Styler adds optional ANSI colour and word wrapping.
type Styler struct {
	On    bool // ANSI colour
	Width int  // wrap text at this column; 0 disables wrapping
}

// AutoColor enables colour when w is a terminal and NO_COLOR is unset.
func AutoColor(w io.Writer) Styler { return ForWriter(w, false) }

// ForWriter picks colour and wrapping for w: both only apply to terminals,
// so piped or redirected output stays one finding line per line (grep-able).
func ForWriter(w io.Writer, noColor bool) Styler {
	f, ok := w.(*os.File)
	if !ok {
		return Styler{}
	}
	fi, err := f.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return Styler{}
	}
	return Styler{On: !noColor && os.Getenv("NO_COLOR") == "", Width: terminalWidth(f)}
}

func terminalWidth(f *os.File) int {
	if c, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && c >= 40 {
		return min(c, 120)
	}
	if c := ttyColumns(f); c >= 40 {
		return min(c, 120)
	}
	return 100
}

func (s Styler) wrap(code, text string) string {
	if !s.On {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}

func (s Styler) Bold(t string) string { return s.wrap("1", t) }
func (s Styler) Dim(t string) string  { return s.wrap("2", t) }

func (s Styler) Sev(sev audit.Severity) string {
	label := fmt.Sprintf("%-8s", strings.ToUpper(sev.String()))
	switch sev {
	case audit.Critical:
		return s.wrap("1;35", label)
	case audit.High:
		return s.wrap("1;31", label)
	case audit.Medium:
		return s.wrap("33", label)
	case audit.Low:
		return s.wrap("36", label)
	}
	return s.wrap("2", label)
}

// lines word-wraps text to width (0 = no wrapping), with the first line
// starting at column first and the rest indented by indent spaces.
func lines(text string, width, first, indent int) []string {
	words := strings.Fields(text)
	if width <= 0 || len(words) == 0 {
		return []string{strings.Join(words, " ")}
	}
	var out []string
	cur, col := "", first
	for _, word := range words {
		n := utf8.RuneCountInString(word)
		switch {
		case cur == "":
			cur, col = word, col+n
		case col+1+n > width:
			out = append(out, cur)
			cur, col = word, indent+n
		default:
			cur, col = cur+" "+word, col+1+n
		}
	}
	return append(out, cur)
}

const findingIndent = 11 // "  " + 8-char severity + " "

func writeBlock(w io.Writer, st Styler, prefix, label, text string, start int) {
	if label != "" {
		text = label + " " + text
	}
	ls := lines(text, st.Width, start, findingIndent)
	for i, l := range ls {
		if label != "" && i == 0 {
			l = st.Dim(label) + strings.TrimPrefix(l, label)
		}
		if i == 0 {
			fmt.Fprintf(w, "%s%s\n", prefix, l)
		} else {
			fmt.Fprintf(w, "%s%s\n", strings.Repeat(" ", findingIndent), l)
		}
	}
}

// WriteText renders a scan report for humans.
func WriteText(w io.Writer, r Report, st Styler, minShown audit.Severity) {
	fmt.Fprintf(w, "%s — %s, %s\n", st.Bold(r.Generator), plural(len(r.Files), "config file"), plural(len(r.Servers), "server"))
	if r.Policy != "" {
		fmt.Fprintf(w, "%s %s (%s suppressed by ignore rules)\n", st.Dim("policy:"), r.Policy, plural(r.Suppressed, "finding"))
	}
	for _, warn := range r.Warnings {
		writeBlock(w, st, "", "warning:", warn, 0)
	}
	if len(r.Servers) == 0 {
		fmt.Fprintf(w, "\nNo MCP servers found. Looked in the user and project configs of %s.\n", strings.Join(config.ClientNames, ", "))
		fmt.Fprintln(w, "Use --project DIR for another project, or --config FILE for a config elsewhere.")
		return
	}
	hidden := 0
	for _, s := range r.Servers {
		fmt.Fprintln(w)
		status := ""
		if s.Disabled {
			status = st.Dim(" (disabled)")
		}
		fmt.Fprintf(w, "● %s%s  %s\n", st.Bold(s.Name), status, st.Dim(s.Client+" · "+s.Location+projectSuffix(s.ID)))
		fmt.Fprintf(w, "  %s\n", st.Dim(s.Launch))
		if p := s.Probe; p != nil {
			switch p.Status {
			case "ok":
				info := plural(len(p.Tools), "tool")
				if p.ServerName != "" {
					info += fmt.Sprintf(" · reports %s %s", p.ServerName, p.ServerVersion)
				}
				if len(s.Capabilities) > 0 {
					info += " · capabilities: " + strings.Join(s.Capabilities, ", ")
				}
				writeBlock(w, st, "  ", "", info, 2)
			default:
				fmt.Fprintf(w, "  probe: %s\n", p.Status)
			}
		}
		hidden += writeFindings(w, s.Findings, st, minShown)
	}
	if len(r.Global) > 0 {
		fmt.Fprintf(w, "\n%s\n", st.Bold("● across servers"))
		hidden += writeFindings(w, r.Global, st, minShown)
	}
	fmt.Fprintln(w)
	writeSummary(w, r.Summary, st)
	if hidden > 0 {
		fmt.Fprintln(w, st.Dim(fmt.Sprintf("%s below %s not shown (--show info to see all).", plural(hidden, "finding"), minShown)))
	}
}

// WriteDiffText renders diff findings grouped by server.
func WriteDiffText(w io.Writer, generator, lockPath string, findings []audit.Finding, st Styler) {
	fmt.Fprintf(w, "%s — comparing against %s\n", st.Bold(generator), lockPath)
	if len(findings) == 0 {
		fmt.Fprintln(w, "\nNo changes since the baseline was pinned. ✓")
		return
	}
	groups := map[string][]audit.Finding{}
	var order []string
	for _, f := range findings {
		if _, ok := groups[f.Server]; !ok {
			order = append(order, f.Server)
		}
		groups[f.Server] = append(groups[f.Server], f)
	}
	for _, id := range order {
		fmt.Fprintf(w, "\n● %s\n", st.Bold(id))
		audit.Sort(groups[id])
		writeFindings(w, groups[id], st, audit.Info)
	}
	fmt.Fprintln(w)
	writeSummary(w, audit.Summary(findings), st)
}

// writeFindings prints findings at or above minShown and returns how many
// were skipped.
func writeFindings(w io.Writer, fs []audit.Finding, st Styler, minShown audit.Severity) int {
	hidden := 0
	for _, f := range fs {
		if f.Severity < minShown {
			hidden++
			continue
		}
		subject := ""
		if f.Tool != "" {
			subject = "tool " + f.Tool + ": "
		}
		head := fmt.Sprintf("  %s %s  ", st.Sev(f.Severity), st.Bold(f.Rule))
		start := findingIndent + len(f.Rule) + 2
		ls := lines(subject+f.Message, st.Width, start, findingIndent)
		fmt.Fprintf(w, "%s%s\n", head, ls[0])
		for _, l := range ls[1:] {
			fmt.Fprintf(w, "%s%s\n", strings.Repeat(" ", findingIndent), l)
		}
		if f.Evidence != "" {
			writeBlock(w, st, strings.Repeat(" ", findingIndent), "evidence:", f.Evidence, findingIndent)
		}
		if f.Fix != "" {
			writeBlock(w, st, strings.Repeat(" ", findingIndent), "fix:", f.Fix, findingIndent)
		}
	}
	return hidden
}

func writeSummary(w io.Writer, sum map[string]int, st Styler) {
	var parts []string
	for _, sev := range []audit.Severity{audit.Critical, audit.High, audit.Medium, audit.Low, audit.Info} {
		if n := sum[sev.String()]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sev))
		}
	}
	if len(parts) == 0 {
		fmt.Fprintf(w, "%s no issues found ✓\n", st.Bold("Summary:"))
		return
	}
	fmt.Fprintf(w, "%s %s\n", st.Bold("Summary:"), strings.Join(parts, ", "))
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

func projectSuffix(id string) string {
	if i := strings.LastIndex(id, "#"); i >= 0 {
		return " · project " + id[i+1:]
	}
	return ""
}
