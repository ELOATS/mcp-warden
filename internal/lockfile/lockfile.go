// Package lockfile records a trusted baseline of MCP server configs and tool
// definitions, and diffs the current state against it to catch "rug pulls":
// servers whose config or tool descriptions change after you approved them.
package lockfile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ELOATS/mcp-warden/internal/audit"
	"github.com/ELOATS/mcp-warden/internal/config"
	"github.com/ELOATS/mcp-warden/internal/probe"
)

const formatVersion = 1

// File is the on-disk lockfile.
type File struct {
	Version     int              `json:"version"`
	Generator   string           `json:"generator"`
	GeneratedAt time.Time        `json:"generatedAt"`
	Servers     map[string]Entry `json:"servers"`
}

// Entry is the pinned state of one server. Secrets are never stored: env
// values and headers are kept only as hashes, args and URLs are redacted.
type Entry struct {
	Client        string               `json:"client"`
	Name          string               `json:"name"`
	Location      string               `json:"location"`
	Project       string               `json:"project,omitempty"`
	Transport     string               `json:"transport"`
	Command       string               `json:"command,omitempty"`
	Args          []string             `json:"args,omitempty"`
	URL           string               `json:"url,omitempty"`
	EnvKeys       []string             `json:"envKeys,omitempty"`
	HeaderKeys    []string             `json:"headerKeys,omitempty"`
	Hashes        Hashes               `json:"hashes"`
	Probed        bool                 `json:"probed"`
	ServerName    string               `json:"serverName,omitempty"`
	ServerVersion string               `json:"serverVersion,omitempty"`
	ToolsHash     string               `json:"toolsHash,omitempty"`
	Tools         map[string]ToolEntry `json:"tools,omitempty"`
}

// Hashes of each config field, so a diff can say exactly what changed.
type Hashes struct {
	Config  string `json:"config"`
	Command string `json:"command"`
	Args    string `json:"args"`
	Env     string `json:"env"`
	URL     string `json:"url"`
	Headers string `json:"headers"`
}

// ToolEntry is the fingerprint of one tool definition.
type ToolEntry struct {
	Hash        string `json:"hash"`
	SchemaHash  string `json:"schemaHash"`
	Description string `json:"description,omitempty"`
}

// Snapshot is one server plus (optionally) its probe result.
type Snapshot struct {
	Server config.Server
	Probe  *probe.Result
}

// Build creates a lockfile from snapshots.
func Build(generator string, snaps []Snapshot) File {
	f := File{Version: formatVersion, Generator: generator, GeneratedAt: time.Now().UTC(), Servers: map[string]Entry{}}
	for _, sn := range snaps {
		s := sn.Server
		e := Entry{
			Client: s.Client, Name: s.Name, Location: s.Location, Project: s.Project,
			Transport: s.Transport, Command: s.Command, Args: audit.RedactArgs(s.Args),
			EnvKeys: keys(s.Env), HeaderKeys: keys(s.Headers), Hashes: ConfigHashes(s),
		}
		if s.URL != "" {
			e.URL = audit.RedactURL(s.URL)
		}
		if sn.Probe != nil && sn.Probe.Status == "ok" {
			e.Probed = true
			e.ServerName, e.ServerVersion = sn.Probe.ServerName, sn.Probe.ServerVersion
			e.Tools = map[string]ToolEntry{}
			var all []string
			for _, t := range sn.Probe.Tools {
				te := ToolEntry{Hash: ToolHash(t), SchemaHash: hash(canonical(t.InputSchema), canonical(t.Annotations)), Description: t.Description}
				e.Tools[t.Name] = te
				all = append(all, t.Name+"="+te.Hash)
			}
			sort.Strings(all)
			e.ToolsHash = hash(all...)
		}
		f.Servers[s.ID()] = e
	}
	return f
}

// ConfigHashes fingerprints every field of a server definition.
func ConfigHashes(s config.Server) Hashes {
	h := Hashes{
		Command: hash(s.Transport, s.Command),
		Args:    hash(s.Args...),
		Env:     hash(pairs(s.Env)...),
		URL:     hash(s.URL),
		Headers: hash(pairs(s.Headers)...),
	}
	h.Config = hash(h.Command, h.Args, h.Env, h.URL, h.Headers)
	return h
}

// ToolHash fingerprints a tool definition (name, title, description, schema, annotations).
func ToolHash(t probe.Tool) string {
	return hash(t.Name, t.Title, t.Description, canonical(t.InputSchema), canonical(t.Annotations))
}

// Load reads a lockfile.
func Load(path string) (File, error) {
	var f File
	b, err := os.ReadFile(path)
	if err != nil {
		return f, err
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return f, fmt.Errorf("%s: %w", path, err)
	}
	if f.Version != formatVersion {
		return f, fmt.Errorf("%s: unsupported lockfile version %d", path, f.Version)
	}
	if f.Servers == nil {
		f.Servers = map[string]Entry{}
	}
	return f, nil
}

// Save writes a lockfile (0600, it describes your local setup).
func Save(path string, f File) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

// HasProbed reports whether any entry carries tool fingerprints.
func (f File) HasProbed() bool {
	for _, e := range f.Servers {
		if e.Probed {
			return true
		}
	}
	return false
}

// Diff compares the current state against the baseline.
func Diff(base, cur File) []audit.Finding {
	ids := map[string]bool{}
	for k := range base.Servers {
		ids[k] = true
	}
	for k := range cur.Servers {
		ids[k] = true
	}
	var out []audit.Finding
	for _, id := range sortedKeys(ids) {
		o, inOld := base.Servers[id]
		n, inNew := cur.Servers[id]
		switch {
		case !inOld:
			out = append(out, audit.Finding{Rule: "NEW-SERVER", Severity: audit.Medium, Server: id,
				Message:  "server was added after the baseline was pinned",
				Evidence: describe(n),
				Fix:      "Review it (`mcp-warden scan --probe`), then run `mcp-warden pin` to accept it."})
		case !inNew:
			out = append(out, audit.Finding{Rule: "REMOVED-SERVER", Severity: audit.Info, Server: id,
				Message: "server from the baseline is no longer configured"})
		default:
			out = append(out, diffEntry(id, o, n)...)
		}
	}
	return out
}

func diffEntry(id string, o, n Entry) []audit.Finding {
	var out []audit.Finding
	if o.Hashes.Config != n.Hashes.Config {
		var what []string
		if o.Hashes.Command != n.Hashes.Command {
			what = append(what, fmt.Sprintf("command: %s %s → %s %s", o.Transport, o.Command, n.Transport, n.Command))
		}
		if o.Hashes.Args != n.Hashes.Args {
			what = append(what, fmt.Sprintf("args: %s → %s", strings.Join(o.Args, " "), strings.Join(n.Args, " ")))
		}
		if o.Hashes.URL != n.Hashes.URL {
			what = append(what, fmt.Sprintf("url: %s → %s", o.URL, n.URL))
		}
		if o.Hashes.Env != n.Hashes.Env {
			what = append(what, "env: "+keyChange(o.EnvKeys, n.EnvKeys))
		}
		if o.Hashes.Headers != n.Hashes.Headers {
			what = append(what, "headers: "+keyChange(o.HeaderKeys, n.HeaderKeys))
		}
		out = append(out, audit.Finding{Rule: "CONFIG-CHANGED", Severity: audit.High, Server: id,
			Message:  "server configuration changed since it was pinned",
			Evidence: strings.Join(what, "; "),
			Fix:      "If you did not make this change, find out what did (an installer, an extension, a synced dotfile). Re-pin once reviewed."})
	}
	switch {
	case o.Probed && n.Probed:
		if o.ServerVersion != n.ServerVersion {
			out = append(out, audit.Finding{Rule: "SERVER-VERSION-CHANGED", Severity: audit.Info, Server: id,
				Message: fmt.Sprintf("server reports version %q (was %q)", n.ServerVersion, o.ServerVersion)})
		}
		if o.ToolsHash != n.ToolsHash {
			out = append(out, diffTools(id, o.Tools, n.Tools)...)
		}
	case o.Probed && !n.Probed:
		out = append(out, audit.Finding{Rule: "TOOLS-NOT-VERIFIED", Severity: audit.Low, Server: id,
			Message: "baseline has tool fingerprints, but this run could not list the server's tools",
			Fix:     "Run with --probe, and check that the server starts."})
	}
	return out
}

func diffTools(id string, old, cur map[string]ToolEntry) []audit.Finding {
	names := map[string]bool{}
	for k := range old {
		names[k] = true
	}
	for k := range cur {
		names[k] = true
	}
	var out []audit.Finding
	for _, name := range sortedKeys(names) {
		o, inOld := old[name]
		n, inNew := cur[name]
		switch {
		case !inOld:
			out = append(out, audit.Finding{Rule: "TOOL-ADDED", Severity: audit.Medium, Server: id, Tool: name,
				Message: "server exposes a new tool", Evidence: clip(n.Description),
				Fix: "Review the new tool, then re-pin."})
		case !inNew:
			out = append(out, audit.Finding{Rule: "TOOL-REMOVED", Severity: audit.Low, Server: id, Tool: name,
				Message: "tool is no longer exposed"})
		case o.Hash != n.Hash:
			ev := "input schema or annotations changed"
			if o.Description != n.Description {
				ev = fmt.Sprintf("before: %q | after: %q", clip(o.Description), clip(n.Description))
			}
			out = append(out, audit.Finding{Rule: "TOOL-DEFINITION-CHANGED", Severity: audit.High, Server: id, Tool: name,
				Message:  "tool definition changed after it was approved (rug-pull pattern)",
				Evidence: ev,
				Fix:      "Read the new definition before using the server again; re-pin only if the change is expected."})
		}
	}
	return out
}

func describe(e Entry) string {
	if e.Transport == "stdio" {
		return strings.TrimSpace(e.Command + " " + strings.Join(e.Args, " "))
	}
	return e.Transport + " " + e.URL
}

func keyChange(o, n []string) string {
	oset, nset := map[string]bool{}, map[string]bool{}
	for _, k := range o {
		oset[k] = true
	}
	for _, k := range n {
		nset[k] = true
	}
	var parts []string
	for _, k := range n {
		if !oset[k] {
			parts = append(parts, "+"+k)
		}
	}
	for _, k := range o {
		if !nset[k] {
			parts = append(parts, "-"+k)
		}
	}
	if len(parts) == 0 {
		return "values changed"
	}
	return strings.Join(parts, " ")
}

func clip(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	r := []rune(s)
	if len(r) > 240 {
		return string(r[:239]) + "…"
	}
	return s
}

func canonical(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return string(raw)
	}
	b, _ := json.Marshal(v) // map keys are sorted by encoding/json
	return string(b)
}

func hash(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func pairs(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for _, k := range keys(m) {
		out = append(out, k+"="+m[k])
	}
	return out
}

func keys(m map[string]string) []string {
	if len(m) == 0 {
		return nil
	}
	return sortedKeys(m)
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
