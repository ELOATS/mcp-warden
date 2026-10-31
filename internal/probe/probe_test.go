package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ELOATS/mcp-warden/internal/config"
	"github.com/ELOATS/mcp-warden/internal/testserver"
)

func TestMain(m *testing.M) {
	testserver.MaybeRun()
	os.Exit(m.Run())
}

func self(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return exe
}

func TestProbeStdio(t *testing.T) {
	s := config.Server{Transport: "stdio", Command: self(t), Env: map[string]string{testserver.EnvMode: "${MODE}"}}
	r := Probe(context.Background(), s, Options{Timeout: 10 * time.Second,
		LookupEnv: func(k string) (string, bool) { return "poisoned", k == "MODE" }})
	if r.Status != "ok" {
		t.Fatalf("status %s: %s", r.Status, r.Error)
	}
	if r.ServerName != "fake" || r.ServerVersion != "1.0.0" {
		t.Errorf("serverInfo = %s %s", r.ServerName, r.ServerVersion)
	}
	if len(r.Tools) != 2 || r.Tools[0].Name != "fetch_url" || r.Tools[1].Name != "read_file" {
		t.Fatalf("tools = %+v", r.Tools)
	}
	if !strings.Contains(r.Tools[1].Description, "id_rsa") {
		t.Errorf("env expansion did not select the poisoned tool set: %q", r.Tools[1].Description)
	}
}

func TestProbeStdioFailures(t *testing.T) {
	r := Probe(context.Background(), config.Server{Transport: "stdio", Command: "/nonexistent/mcp-server"}, Options{Timeout: 5 * time.Second})
	if r.Status != "error" {
		t.Errorf("missing binary: status %s", r.Status)
	}
	// A process that exits immediately without speaking MCP.
	r = Probe(context.Background(), config.Server{Transport: "stdio", Command: "sh", Args: []string{"-c", "echo boom >&2; exit 3"}},
		Options{Timeout: 5 * time.Second})
	if r.Status != "error" || !strings.Contains(r.Error, "boom") {
		t.Errorf("early exit: %+v", r)
	}
	// A process that never answers must time out rather than hang.
	start := time.Now()
	r = Probe(context.Background(), config.Server{Transport: "stdio", Command: "sleep", Args: []string{"30"}},
		Options{Timeout: 500 * time.Millisecond})
	if r.Status != "error" || time.Since(start) > 5*time.Second {
		t.Errorf("hang: %+v after %s", r, time.Since(start))
	}
}

// fakeHTTP implements just enough of Streamable HTTP for the probe.
func fakeHTTP(t *testing.T, sse bool, requireAuth string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requireAuth != "" && r.Header.Get("Authorization") != requireAuth {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodDelete {
			return
		}
		var m struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&m)
		var result any
		switch m.Method {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "sess-1")
			result = map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{"tools": map[string]any{}},
				"serverInfo": map[string]any{"name": "remote", "version": "2.0"}}
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
			return
		case "tools/list":
			if r.Header.Get("Mcp-Session-Id") != "sess-1" {
				t.Errorf("session id not sent")
			}
			result = map[string]any{"tools": testserver.Tools("clean")}
		}
		msg, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": result})
		if sse {
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprintf(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{}}\n\n")
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", msg)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(msg)
	}))
}

func TestProbeHTTP(t *testing.T) {
	for _, sse := range []bool{false, true} {
		srv := fakeHTTP(t, sse, "Bearer s3cret")
		s := config.Server{Transport: "http", URL: srv.URL, Headers: map[string]string{"Authorization": "Bearer ${TOK}"}}
		r := Probe(context.Background(), s, Options{Timeout: 5 * time.Second,
			LookupEnv: func(k string) (string, bool) { return "s3cret", k == "TOK" }})
		if r.Status != "ok" || len(r.Tools) != 2 || r.ServerName != "remote" {
			t.Errorf("sse=%v: %+v", sse, r)
		}
		// Without the token the server must be reported as auth-required.
		s.Headers = nil
		if r := Probe(context.Background(), s, Options{Timeout: 5 * time.Second}); r.Status != "auth-required" {
			t.Errorf("sse=%v no auth: %+v", sse, r)
		}
		srv.Close()
	}
}
