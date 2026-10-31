// Package probe connects to an MCP server the same way a client would,
// performs the initialize handshake and lists the tools it exposes.
package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"time"

	"github.com/ELOATS/mcp-warden/internal/config"
)

// ClientVersion is reported in clientInfo during initialize.
var ClientVersion = "dev"

const clientProtocolVersion = "2025-06-18"

// ErrAuthRequired is returned when a remote server rejects an unauthenticated probe.
var ErrAuthRequired = errors.New("server requires authentication")

// Tool is a tool definition as returned by tools/list.
type Tool struct {
	Name        string          `json:"name"`
	Title       string          `json:"title,omitempty"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
	Annotations json.RawMessage `json:"annotations,omitempty"`
}

// Result of probing one server.
type Result struct {
	Status          string `json:"status"` // ok | error | auth-required | skipped
	Error           string `json:"error,omitempty"`
	ServerName      string `json:"serverName,omitempty"`
	ServerVersion   string `json:"serverVersion,omitempty"`
	ProtocolVersion string `json:"protocolVersion,omitempty"`
	Tools           []Tool `json:"tools,omitempty"`
}

// Options for Probe.
type Options struct {
	Timeout   time.Duration
	Dir       string // working directory for stdio servers
	LookupEnv func(string) (string, bool)
}

type transport interface {
	call(ctx context.Context, method string, params any) (json.RawMessage, error)
	notify(ctx context.Context, method string, params any) error
	close()
}

// Probe starts or connects to the server and lists its tools.
func Probe(ctx context.Context, s config.Server, opt Options) Result {
	if opt.Timeout <= 0 {
		opt.Timeout = 20 * time.Second
	}
	if opt.LookupEnv == nil {
		opt.LookupEnv = os.LookupEnv
	}
	ctx, cancel := context.WithTimeout(ctx, opt.Timeout)
	defer cancel()

	var t transport
	switch s.Transport {
	case "stdio":
		st, err := startStdio(s, opt)
		if err != nil {
			return Result{Status: "error", Error: err.Error()}
		}
		t = st
	case "http":
		t = newHTTP(s, opt)
	case "sse":
		return Result{Status: "skipped", Error: "legacy SSE transport is not probed"}
	default:
		return Result{Status: "skipped", Error: "unknown transport"}
	}
	defer t.close()

	res, err := session(ctx, t)
	if err != nil {
		if errors.Is(err, ErrAuthRequired) {
			return Result{Status: "auth-required", Error: err.Error()}
		}
		if ctx.Err() != nil {
			err = fmt.Errorf("timed out after %s: %w", opt.Timeout, err)
		}
		if st, ok := t.(*stdioTransport); ok {
			if tail := st.stderr.String(); tail != "" {
				err = fmt.Errorf("%w; stderr: %s", err, tail)
			}
		}
		return Result{Status: "error", Error: err.Error()}
	}
	res.Status = "ok"
	return res
}

func session(ctx context.Context, t transport) (Result, error) {
	raw, err := t.call(ctx, "initialize", map[string]any{
		"protocolVersion": clientProtocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "mcp-warden", "version": ClientVersion},
	})
	if err != nil {
		return Result{}, fmt.Errorf("initialize: %w", err)
	}
	var init struct {
		ProtocolVersion string                     `json:"protocolVersion"`
		Capabilities    map[string]json.RawMessage `json:"capabilities"`
		ServerInfo      struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"serverInfo"`
	}
	if err := json.Unmarshal(raw, &init); err != nil {
		return Result{}, fmt.Errorf("initialize: bad result: %w", err)
	}
	r := Result{ServerName: init.ServerInfo.Name, ServerVersion: init.ServerInfo.Version, ProtocolVersion: init.ProtocolVersion}
	if ht, ok := t.(*httpTransport); ok {
		ht.protocolVersion = init.ProtocolVersion
	}
	if err := t.notify(ctx, "notifications/initialized", nil); err != nil {
		return r, fmt.Errorf("initialized notification: %w", err)
	}
	_, declaresTools := init.Capabilities["tools"]
	cursor := ""
	for page := 0; page < 100; page++ {
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		raw, err := t.call(ctx, "tools/list", params)
		if err != nil {
			if !declaresTools && page == 0 {
				return r, nil // server has no tools
			}
			return r, fmt.Errorf("tools/list: %w", err)
		}
		var lst struct {
			Tools      []Tool `json:"tools"`
			NextCursor string `json:"nextCursor"`
		}
		if err := json.Unmarshal(raw, &lst); err != nil {
			return r, fmt.Errorf("tools/list: bad result: %w", err)
		}
		r.Tools = append(r.Tools, lst.Tools...)
		if lst.NextCursor == "" || lst.NextCursor == cursor {
			break
		}
		cursor = lst.NextCursor
	}
	sort.SliceStable(r.Tools, func(i, j int) bool { return r.Tools[i].Name < r.Tools[j].Name })
	return r, nil
}

// --- JSON-RPC plumbing shared by both transports ---

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      *int   `json:"id,omitempty"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcMessage struct {
	ID     json.RawMessage `json:"id,omitempty"`
	Method string          `json:"method,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *rpcError) Error() string { return fmt.Sprintf("server error %d: %s", e.Code, e.Message) }

func idMatches(raw json.RawMessage, id int) bool {
	s := string(bytes.TrimSpace(raw))
	return s == strconv.Itoa(id) || s == strconv.Quote(strconv.Itoa(id))
}

func expandAll(in []string, lookup func(string) (string, bool)) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = config.Expand(s, lookup)
	}
	return out
}
