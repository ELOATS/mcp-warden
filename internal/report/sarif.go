package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/ELOATS/mcp-warden/internal/audit"
)

// Location of a finding in a config file. URI is either relative to the
// project root (so GitHub code scanning can annotate it) or a file:// URI.
type Location struct {
	URI  string
	Line int
}

// Relative reports whether the URI is project-relative.
func (l Location) Relative() bool { return l.URI != "" && !strings.Contains(l.URI, "://") }

const sarifSchema = "https://json.schemastore.org/sarif-2.1.0.json"

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifRule struct {
	ID                   string         `json:"id"`
	Name                 string         `json:"name"`
	ShortDescription     sarifText      `json:"shortDescription"`
	FullDescription      sarifText      `json:"fullDescription"`
	Help                 sarifText      `json:"help"`
	DefaultConfiguration map[string]any `json:"defaultConfiguration"`
	Properties           map[string]any `json:"properties"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

func sarifLevel(s audit.Severity) string {
	switch {
	case s >= audit.High:
		return "error"
	case s == audit.Medium:
		return "warning"
	}
	return "note"
}

// GitHub code scanning maps security-severity to critical (>=9), high (>=7),
// medium (>=4) and low.
func securitySeverity(s audit.Severity) string {
	return map[audit.Severity]string{
		audit.Critical: "9.5", audit.High: "8.0", audit.Medium: "5.5", audit.Low: "3.0", audit.Info: "1.0",
	}[s]
}

// WriteSARIF renders findings as a SARIF 2.1.0 log. locate maps a finding's
// Server field to a file location; findings it cannot place are anchored to
// fallback (e.g. the first config file scanned).
func WriteSARIF(w io.Writer, version string, findings []audit.Finding, locate func(server string) (Location, bool), fallback Location) error {
	fs := append([]audit.Finding{}, findings...)
	audit.Sort(fs)

	maxSev := map[string]audit.Severity{}
	for _, f := range fs {
		if s, ok := maxSev[f.Rule]; !ok || f.Severity > s {
			maxSev[f.Rule] = f.Severity
		}
	}
	ids := make([]string, 0, len(maxSev))
	for id := range maxSev {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	index := map[string]int{}
	rules := make([]sarifRule, 0, len(ids))
	for i, id := range ids {
		info := audit.Rule(id)
		help := info.Help
		if help == "" {
			help = info.Title
		}
		index[id] = i
		rules = append(rules, sarifRule{
			ID: id, Name: ruleName(id),
			ShortDescription:     sarifText{info.Title},
			FullDescription:      sarifText{help},
			Help:                 sarifText{help},
			DefaultConfiguration: map[string]any{"level": sarifLevel(maxSev[id])},
			Properties: map[string]any{
				"security-severity": securitySeverity(maxSev[id]),
				"tags":              []string{"security", "mcp"},
				"precision":         "high",
			},
		})
	}

	results := make([]sarifResult, 0, len(fs))
	for _, f := range fs {
		loc, ok := locate(f.Server)
		if !ok {
			loc = fallback
		}
		art := sarifArtifact{URI: loc.URI}
		if loc.Relative() {
			art.URIBaseID = "%SRCROOT%"
		}
		var region *sarifRegion
		if loc.Line > 0 {
			region = &sarifRegion{StartLine: loc.Line}
		}
		results = append(results, sarifResult{
			RuleID: f.Rule, RuleIndex: index[f.Rule], Level: sarifLevel(f.Severity),
			Message:             sarifText{resultText(f)},
			Locations:           []sarifLocation{{PhysicalLocation: sarifPhysical{ArtifactLocation: art, Region: region}}},
			PartialFingerprints: map[string]string{"mcpWarden/v1": audit.Fingerprint(f)},
			Properties:          map[string]any{"severity": f.Severity.String(), "server": f.Server},
		})
	}

	log := sarifLog{Schema: sarifSchema, Version: "2.1.0", Runs: []sarifRun{{
		Tool: sarifTool{Driver: sarifDriver{
			Name: "mcp-warden", Version: version,
			InformationURI: "https://github.com/ELOATS/mcp-warden", Rules: rules,
		}},
		Results: results,
	}}}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func resultText(f audit.Finding) string {
	var b strings.Builder
	name := f.Server
	if i := strings.Index(name, " @ "); i > 0 {
		name = name[:i]
	}
	fmt.Fprintf(&b, "%s: ", name)
	if f.Tool != "" {
		fmt.Fprintf(&b, "tool %s ", f.Tool)
	}
	b.WriteString(f.Message)
	if f.Evidence != "" {
		fmt.Fprintf(&b, " (evidence: %s)", f.Evidence)
	}
	if f.Fix != "" {
		fmt.Fprintf(&b, ". Fix: %s", f.Fix)
	}
	return b.String()
}

// ruleName turns TOOL-POISONING into ToolPoisoning (SARIF rule names are
// conventionally PascalCase identifiers).
func ruleName(id string) string {
	var b strings.Builder
	for _, part := range strings.Split(strings.ToLower(id), "-") {
		if part == "" {
			continue
		}
		b.WriteString(strings.ToUpper(part[:1]) + part[1:])
	}
	return b.String()
}
