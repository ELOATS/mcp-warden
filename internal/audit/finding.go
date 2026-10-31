// Package audit holds the security rules: static checks on server
// configuration and dynamic checks on the tool definitions a server exposes.
package audit

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Severity of a finding. Ordered so that comparisons work.
type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

var severityNames = []string{"info", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if s < 0 || int(s) >= len(severityNames) {
		return "unknown"
	}
	return severityNames[s]
}

// ParseSeverity parses a severity name (case-insensitive).
func ParseSeverity(v string) (Severity, error) {
	for i, n := range severityNames {
		if strings.EqualFold(v, n) {
			return Severity(i), nil
		}
	}
	return Info, fmt.Errorf("unknown severity %q (want one of %s)", v, strings.Join(severityNames, ", "))
}

func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

func (s *Severity) UnmarshalJSON(b []byte) error {
	var v string
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	p, err := ParseSeverity(v)
	if err != nil {
		return err
	}
	*s = p
	return nil
}

// Finding is a single issue reported to the user.
type Finding struct {
	Rule     string   `json:"rule"`
	Severity Severity `json:"severity"`
	// Server is the config.Server ID the finding belongs to, or
	// "client:<name>" for findings that span several servers of one client.
	Server   string `json:"server"`
	Tool     string `json:"tool,omitempty"`
	Message  string `json:"message"`
	Evidence string `json:"evidence,omitempty"`
	Fix      string `json:"fix,omitempty"`
}

// Sort orders findings by severity (highest first), then server, rule, tool.
func Sort(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.Server != b.Server {
			return a.Server < b.Server
		}
		if a.Rule != b.Rule {
			return a.Rule < b.Rule
		}
		return a.Tool < b.Tool
	})
}

// CountAtLeast returns how many findings are at or above min.
func CountAtLeast(fs []Finding, min Severity) int {
	n := 0
	for _, f := range fs {
		if f.Severity >= min {
			n++
		}
	}
	return n
}

// Summary counts findings per severity name.
func Summary(fs []Finding) map[string]int {
	m := map[string]int{}
	for _, n := range severityNames {
		m[n] = 0
	}
	for _, f := range fs {
		m[f.Severity.String()]++
	}
	return m
}
