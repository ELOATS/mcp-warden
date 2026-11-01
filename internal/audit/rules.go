package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
)

// RuleInfo documents a rule for SARIF output and `mcp-warden rules`.
type RuleInfo struct {
	ID    string
	Title string
	Help  string
}

var catalog = map[string]RuleInfo{}

func rule(id, title, help string) { catalog[id] = RuleInfo{ID: id, Title: title, Help: help} }

func init() {
	// Launch & supply chain
	rule("SHELL-PIPE-EXEC", "Server is launched by piping a download into a shell",
		"`curl … | sh` runs whatever the remote host serves on every launch. Install a pinned package instead.")
	rule("SHELL-WRAPPER", "Server is launched through an inline shell script",
		"An inline script hides what actually runs and defeats provenance checks. Invoke the server binary directly.")
	rule("POSSIBLE-TYPOSQUAT", "Package name is a near-miss of a popular MCP server",
		"Typosquatted packages copy a well-known server's behaviour plus a payload. Verify the publisher and the exact name.")
	rule("UNPINNED-PACKAGE", "npx/uvx package is not pinned to an exact version",
		"Floating versions install whatever was published last, so a compromised release reaches you automatically.")
	rule("UNPINNED-IMAGE", "Container image is not pinned by digest",
		"Tags are mutable. Pin images as name@sha256:<digest>.")
	rule("UNKNOWN-PACKAGE", "Could not determine which package is executed", "")
	rule("LOCAL-SCRIPT", "Server runs a local script", "Local scripts cannot be verified against a registry; review them like any other code you run.")
	rule("UNKNOWN-TRANSPORT", "Server has neither a command nor a URL", "")
	// Permissions
	rule("BROAD-FS-ACCESS", "Server is given the whole disk or home directory",
		"Grant only the directories the server needs; the model can be steered into reading anything it can reach.")
	rule("HOST-ROOT-MOUNT", "Container mounts the host root or home directory", "Mount only what is needed, read-only where possible.")
	rule("DOCKER-PRIVILEGED", "Container runs with --privileged", "A privileged container is effectively root on the host.")
	rule("DOCKER-SOCKET", "Container mounts the Docker socket", "Access to docker.sock is equivalent to root on the host.")
	rule("DOCKER-CAPABILITY", "Container is granted ALL or SYS_ADMIN capabilities", "")
	rule("HOST-NETWORK", "Container shares the host network", "")
	rule("HOST-PID", "Container shares the host PID namespace", "")
	// Secrets & transport
	rule("PLAINTEXT-SECRET", "Credential stored in plain text in an MCP config",
		"MCP configs are synced, shared and committed. Reference secrets as ${VAR} and rotate any that were exposed.")
	rule("CREDENTIAL-IN-ARGS", "Connection string with an embedded password", "Arguments are visible in process listings and logs.")
	rule("CREDENTIAL-IN-URL", "Server URL embeds a password", "")
	rule("SECRET-IN-URL", "Server URL carries a credential in its query string", "URLs end up in logs and proxies; use a header that references an environment variable.")
	rule("INSECURE-TRANSPORT", "Remote server reached over plain HTTP", "Traffic, tool definitions and credentials can be read or altered in transit. Use HTTPS.")
	rule("INVALID-URL", "Server URL could not be parsed", "")
	rule("LEGACY-SSE", "Server uses the deprecated HTTP+SSE transport", "")
	rule("REMOTE-SERVER", "Remote server: definitions can change server-side", "Pin with `mcp-warden pin --probe` and run `mcp-warden diff`/`watch` to detect drift.")
	// Tool definitions
	rule("TOOL-POISONING", "Tool definition contains instructions aimed at the model",
		"Tool descriptions are read by the model as instructions. Text that overrides prior instructions, hides actions from the user or references credentials is a prompt-injection attack.")
	rule("HIDDEN-UNICODE", "Tool definition contains invisible or bidi control characters", "Invisible characters can hide instructions from human reviewers.")
	rule("OVERSIZED-DESCRIPTION", "Tool description is unusually long", "")
	rule("CAP-EXEC", "Server can run arbitrary commands or code", "Keep per-call approval on for these tools.")
	rule("CAP-DESTRUCTIVE", "Server declares destructive tools", "")
	rule("TOOL-NAME-COLLISION", "Several servers expose the same tool name", "A malicious server can shadow a trusted tool this way.")
	rule("CROSS-TOOL-REFERENCE", "Tool description refers to another server's tool", "A known tool-shadowing technique: one server rewrites how the model uses another.")
	rule("LETHAL-TRIFECTA", "Client mixes web-fetching tools with local-data or exec tools",
		"Untrusted content can instruct the model to read private data with one tool and exfiltrate it with another.")
	// Probing
	rule("PROBE-FAILED", "Server could not be probed", "")
	rule("PROBE-AUTH-REQUIRED", "Server requires authentication to be probed", "")
	rule("PROBE-SKIPPED", "Server was not probed", "")
	// Baseline drift
	rule("CONFIG-CHANGED", "Server configuration changed since it was pinned", "If you did not make this change, find out what did before using the server again.")
	rule("TOOL-DEFINITION-CHANGED", "Tool definition changed after it was approved",
		"A server that changes its tool descriptions after approval (a rug pull) can turn a trusted tool malicious.")
	rule("TOOL-ADDED", "Server exposes a new tool since it was pinned", "")
	rule("TOOL-REMOVED", "Tool is no longer exposed", "")
	rule("NEW-SERVER", "Server was added after the baseline was pinned", "")
	rule("REMOVED-SERVER", "Pinned server is no longer configured", "")
	rule("SERVER-VERSION-CHANGED", "Server reports a different version", "")
	rule("TOOLS-NOT-VERIFIED", "Tool fingerprints could not be compared", "")
	// Policy
	rule("POLICY-DENIED", "Server matches a deny rule in the team policy", "")
	rule("POLICY-NOT-ALLOWED", "Server is not on the team policy allowlist", "Add it to the policy after review, or remove it.")
}

// Rule returns the catalog entry for id (a stub entry if unknown).
func Rule(id string) RuleInfo {
	if r, ok := catalog[id]; ok {
		return r
	}
	return RuleInfo{ID: id, Title: id}
}

// Rules returns every documented rule, sorted by ID.
func Rules() []RuleInfo {
	out := make([]RuleInfo, 0, len(catalog))
	for _, r := range catalog {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Fingerprint identifies a finding stably across runs.
func Fingerprint(f Finding) string {
	h := sha256.Sum256([]byte(f.Server + "\x00" + f.Rule + "\x00" + f.Tool + "\x00" + f.Evidence))
	return hex.EncodeToString(h[:12])
}

// Known reports whether id is a documented rule.
func Known(id string) bool {
	_, ok := catalog[id]
	return ok
}
