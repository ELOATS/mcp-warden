package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ELOATS/mcp-warden/internal/fix"
	"github.com/ELOATS/mcp-warden/internal/registry"
)

func cmdFix(args []string, stdout, stderr io.Writer) int {
	flags, o := newFlags("fix", stderr, "none")
	apply := flags.Bool("apply", false, "")
	secrets := flags.Bool("secrets", false, "")
	var only multiFlag
	flags.Var(&only, "server", "")
	offline := flags.Bool("offline", false, "")
	npmURL := flags.String("npm-registry", envOr("MCP_WARDEN_NPM_REGISTRY", registry.DefaultNPM), "")
	pypiURL := flags.String("pypi-url", envOr("MCP_WARDEN_PYPI_URL", registry.DefaultPyPI), "")
	cooldown := flags.Int("cooldown", 7, "")
	if code, ok := parseArgs(flags, o, args, stdout, stderr); !ok {
		return code
	}
	if *cooldown < 0 {
		fmt.Fprintln(stderr, "error: --cooldown must be >= 0 days")
		return 2
	}
	env, res, err := o.discover()
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	for _, w := range res.Warnings {
		fmt.Fprintln(stderr, "warning:", w)
	}
	var rc *registry.Client
	if !*offline && !truthy(os.Getenv("MCP_WARDEN_OFFLINE")) {
		rc = registry.New("mcp-warden/" + version + " (+https://github.com/ELOATS/mcp-warden)")
		rc.NPM, rc.PyPI, rc.NPMDownloads = *npmURL, *pypiURL, ""
		rc.Cooldown = time.Duration(*cooldown) * 24 * time.Hour
	}
	secretsFile := filepath.Join(env.Home, ".mcp-warden", "secrets.env")
	plan := fix.Build(context.Background(), res.Servers, fix.Options{
		Registry: rc, Secrets: *secrets, SecretsFile: secretsFile, Servers: only})
	if rc != nil {
		for host, err := range rc.Unreachable() {
			fmt.Fprintf(stderr, "warning: could not reach %s (%v)\n", host, err)
		}
	}

	st := o.styler(stdout)
	files := plan.Files()
	mode := "preview; nothing written"
	if *apply {
		mode = "applying"
	}
	fmt.Fprintf(stdout, "%s — %s in %s (%s)\n", st.Bold("mcp-warden fix"),
		pluralize(len(plan.Changes), "change"), pluralize(len(files), "file"), mode)
	if len(res.Servers) == 0 {
		fmt.Fprintln(stdout, "\nNo MCP servers found.")
		return 0
	}
	home := env.Home + string(filepath.Separator)
	pretty := func(p string) string {
		if rel, err := filepath.Rel(env.ProjectDir, p); err == nil && !strings.HasPrefix(rel, "..") {
			return rel
		}
		if strings.HasPrefix(p, home) {
			return "~/" + filepath.ToSlash(strings.TrimPrefix(p, home))
		}
		return p
	}
	for _, file := range files {
		fmt.Fprintf(stdout, "\n%s\n", st.Bold(pretty(file)))
		if filepath.Base(file) == ".claude.json" && *apply {
			fmt.Fprintln(stdout, st.Dim("  note: Claude Code rewrites this file while it runs; quit it first or the change may be lost"))
		}
		for _, c := range plan.Changes {
			if c.Server.Source != file {
				continue
			}
			name := c.Server.Name
			if c.Server.Project != "" {
				name += " (" + c.Server.Project + ")"
			}
			fmt.Fprintf(stdout, "  %-14s %-18s %s  →  %s\n", name, c.Field, c.Old, c.New)
			if c.Note != "" {
				fmt.Fprintf(stdout, "  %-14s %-18s %s\n", "", "", st.Dim(c.Note))
			}
		}
	}
	if len(plan.Skips) > 0 {
		fmt.Fprintf(stdout, "\n%s\n", st.Bold("Not fixed automatically:"))
		for _, s := range plan.Skips {
			fmt.Fprintf(stdout, "  %-14s %s: %s\n", s.Server.Name, s.What, s.Reason)
		}
	}
	if len(plan.Changes) == 0 {
		fmt.Fprintln(stdout, "\nNothing to change automatically.")
		return 0
	}
	if !*apply {
		fmt.Fprintln(stdout, "\nApply with: mcp-warden fix --apply   (each file is backed up next to it first)")
		return 0
	}

	results, err := plan.Apply(secretsFile, time.Now())
	for _, r := range results {
		fmt.Fprintf(stdout, "\n✓ %s: %s written\n  backup: %s", pretty(r.File), pluralize(r.Changes, "change"), r.Backup)
	}
	if len(results) > 0 {
		fmt.Fprintln(stdout)
	}
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	moved := false
	for _, c := range plan.Changes {
		moved = moved || strings.HasPrefix(c.Field, "env.")
	}
	if moved {
		fmt.Fprintf(stdout, "\nSecrets were moved to %s (readable only by you). Load them in the shell you start your MCP client from:\n", pretty(secretsFile))
		fmt.Fprintf(stdout, "    echo 'source %s' >> ~/.zshrc    # or ~/.bashrc\n", pretty(secretsFile))
		fmt.Fprintln(stdout, "Rotate these credentials if the config was ever shared, synced or committed.")
	}
	fmt.Fprintln(stdout, "\nNext: restart your MCP clients. If you use diff/watch, accept the new config with: mcp-warden pin")
	return 0
}
