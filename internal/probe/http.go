package probe

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ELOATS/mcp-warden/internal/config"
)

// httpTransport implements the Streamable HTTP transport (single POST per
// message; responses may be plain JSON or an SSE stream).
type httpTransport struct {
	url             string
	headers         map[string]string
	client          *http.Client
	sessionID       string
	protocolVersion string
	nextID          int
}

func newHTTP(s config.Server, opt Options) *httpTransport {
	h := map[string]string{}
	for k, v := range s.Headers {
		h[k] = config.Expand(v, opt.LookupEnv)
	}
	return &httpTransport{
		url:     config.Expand(s.URL, opt.LookupEnv),
		headers: h,
		client:  &http.Client{Timeout: opt.Timeout},
	}
}

func (h *httpTransport) post(ctx context.Context, body any) (*http.Response, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.url, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	for k, v := range h.headers {
		req.Header.Set(k, v)
	}
	if h.sessionID != "" {
		req.Header.Set("Mcp-Session-Id", h.sessionID)
	}
	if h.protocolVersion != "" {
		req.Header.Set("MCP-Protocol-Version", h.protocolVersion)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		resp.Body.Close()
		return nil, fmt.Errorf("%w (HTTP %d)", ErrAuthRequired, resp.StatusCode)
	}
	if resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		resp.Body.Close()
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		h.sessionID = sid
	}
	return resp, nil
}

func (h *httpTransport) call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	h.nextID++
	id := h.nextID
	resp, err := h.post(ctx, rpcRequest{JSONRPC: "2.0", ID: &id, Method: method, Params: params})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body := io.LimitReader(resp.Body, 32<<20)
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		return readSSE(body, id)
	}
	data, err := io.ReadAll(body)
	if err != nil {
		return nil, err
	}
	data = bytes.TrimSpace(data)
	var msgs []rpcMessage
	if len(data) > 0 && data[0] == '[' {
		err = json.Unmarshal(data, &msgs)
	} else {
		var m rpcMessage
		err = json.Unmarshal(data, &m)
		msgs = []rpcMessage{m}
	}
	if err != nil {
		return nil, fmt.Errorf("bad JSON response: %w", err)
	}
	for _, m := range msgs {
		if m.Method == "" && idMatches(m.ID, id) {
			if m.Error != nil {
				return nil, m.Error
			}
			return m.Result, nil
		}
	}
	return nil, errors.New("response did not contain a reply to our request")
}

func readSSE(r io.Reader, id int) (json.RawMessage, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 32*1024*1024)
	var data strings.Builder
	flush := func() (json.RawMessage, bool, error) {
		if data.Len() == 0 {
			return nil, false, nil
		}
		var m rpcMessage
		err := json.Unmarshal([]byte(data.String()), &m)
		data.Reset()
		if err != nil || m.Method != "" || !idMatches(m.ID, id) {
			return nil, false, nil
		}
		if m.Error != nil {
			return nil, true, m.Error
		}
		return m.Result, true, nil
	}
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			if res, ok, err := flush(); ok {
				return res, err
			}
			continue
		}
		if strings.HasPrefix(line, "data:") {
			if data.Len() > 0 {
				data.WriteByte('\n')
			}
			data.WriteString(strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	if res, ok, err := flush(); ok {
		return res, err
	}
	return nil, errors.New("event stream ended without a reply")
}

func (h *httpTransport) notify(ctx context.Context, method string, params any) error {
	resp, err := h.post(ctx, rpcRequest{JSONRPC: "2.0", Method: method, Params: params})
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	return nil
}

func (h *httpTransport) close() {
	if h.sessionID == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, h.url, nil)
	if err != nil {
		return
	}
	req.Header.Set("Mcp-Session-Id", h.sessionID)
	for k, v := range h.headers {
		req.Header.Set(k, v)
	}
	if resp, err := h.client.Do(req); err == nil {
		resp.Body.Close()
	}
}
