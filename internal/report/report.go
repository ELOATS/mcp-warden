// Package report renders scan and diff results as text or JSON.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ELOATS/mcp-warden/internal/audit"
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
	Generator string          `json:"generator"`
	Files     []string        `json:"files"`
	Warnings  []string        `json:"warnings,omitempty"`
	Servers   []ServerView    `json:"servers"`
	Global    []audit.Finding `json:"global,omitempty"`
	Summary   map[string]int  `json:"summary"`
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

// Styler adds optional ANSI colour.
type Styler struct{ On bool }

// AutoColor enables colour when w is a terminal and NO_COLOR is unset.
func AutoColor(w io.Writer) Styler {
	if os.Getenv("NO_COLOR") != "" {
		return Styler{}
	}
	f, ok := w.(*os.File)
	if !ok {
		return Styler{}
	}
	fi, err := f.Stat()
	return Styler{On: err == nil && fi.Mode()&os.ModeCharDevice != 0}
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

// WriteText renders a scan report for humans.
func WriteText(w io.Writer, r Report, st Styler, minShown audit.Severity) {
	fmt.Fprintf(w, "%s — %d config file(s), %d server(s)\n", st.Bold(r.Generator), len(r.Files), len(r.Servers))
	for _, warn := range r.Warnings {
		fmt.Fprintf(w, "%s %s\n", st.Dim("warning:"), warn)
	}
	if len(r.Servers) == 0 {
		fmt.Fprintln(w, "\nNo MCP servers found. Use --config <file> to point at a config explicitly.")
	}
	for _, s := range r.Servers {
		fmt.Fprintln(w)
		status := ""
		if s.Disabled {
			status = st.Dim(" (disabled)")
		}
		fmt.Fprintf(w, "● %s%s  %s\n", st.Bold(s.Name), status, st.Dim("["+s.Client+" · "+s.Location+projectSuffix(s.ID)+"]"))
		fmt.Fprintf(w, "  %s\n", st.Dim(s.Launch))
		if p := s.Probe; p != nil {
			switch p.Status {
			case "ok":
				info := fmt.Sprintf("%d tool(s)", len(p.Tools))
				if p.ServerName != "" {
					info += fmt.Sprintf(" · reports %s %s", p.ServerName, p.ServerVersion)
				}
				if len(s.Capabilities) > 0 {
					info += " · capabilities: " + strings.Join(s.Capabilities, ", ")
				}
				fmt.Fprintf(w, "  %s\n", info)
			default:
				fmt.Fprintf(w, "  probe: %s\n", p.Status)
			}
		}
		writeFindings(w, s.Findings, st, minShown)
	}
	if len(r.Global) > 0 {
		fmt.Fprintf(w, "\n%s\n", st.Bold("● cross-server"))
		writeFindings(w, r.Global, st, minShown)
	}
	fmt.Fprintln(w)
	writeSummary(w, r.Summary, st)
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

func writeFindings(w io.Writer, fs []audit.Finding, st Styler, minShown audit.Severity) {
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
		fmt.Fprintf(w, "  %s %-24s %s%s\n", st.Sev(f.Severity), f.Rule, subject, f.Message)
		if f.Evidence != "" {
			fmt.Fprintf(w, "  %8s %-24s %s %s\n", "", "", st.Dim("evidence:"), f.Evidence)
		}
		if f.Fix != "" {
			fmt.Fprintf(w, "  %8s %-24s %s %s\n", "", "", st.Dim("fix:"), f.Fix)
		}
	}
	if hidden > 0 {
		fmt.Fprintf(w, "  %s\n", st.Dim(fmt.Sprintf("(%d lower-severity finding(s) hidden; use --show info)", hidden)))
	}
}

func writeSummary(w io.Writer, sum map[string]int, st Styler) {
	parts := []string{}
	for _, sev := range []audit.Severity{audit.Critical, audit.High, audit.Medium, audit.Low, audit.Info} {
		parts = append(parts, fmt.Sprintf("%d %s", sum[sev.String()], sev))
	}
	fmt.Fprintf(w, "%s %s\n", st.Bold("Summary:"), strings.Join(parts, ", "))
}

func projectSuffix(id string) string {
	if i := strings.LastIndex(id, "#"); i >= 0 {
		return " · project " + id[i+1:]
	}
	return ""
}
