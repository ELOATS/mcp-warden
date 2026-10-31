package probe

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/ELOATS/mcp-warden/internal/config"
)

type stdioTransport struct {
	cmd       *exec.Cmd
	stdin     io.WriteCloser
	msgs      chan rpcMessage
	done      chan struct{} // closed when stdout reaches EOF
	closed    chan struct{} // closed by close()
	closeOnce sync.Once
	stderr    *tailBuffer
	nextID    int
}

func startStdio(s config.Server, opt Options) (*stdioTransport, error) {
	if s.Command == "" {
		return nil, errors.New("no command configured")
	}
	cmd := exec.Command(config.Expand(s.Command, opt.LookupEnv), expandAll(s.Args, opt.LookupEnv)...)
	cmd.Env = os.Environ()
	for k, v := range s.Env {
		cmd.Env = append(cmd.Env, k+"="+config.Expand(v, opt.LookupEnv))
	}
	cmd.Dir = opt.Dir
	cmd.WaitDelay = time.Second
	setProcessGroup(cmd)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	tb := &tailBuffer{max: 1024}
	cmd.Stderr = tb
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s: %w", s.Command, err)
	}
	t := &stdioTransport{
		cmd: cmd, stdin: stdin, stderr: tb,
		msgs: make(chan rpcMessage, 64), done: make(chan struct{}), closed: make(chan struct{}),
	}
	go t.readLoop(stdout)
	return t, nil
}

func (t *stdioTransport) readLoop(r io.Reader) {
	defer close(t.done)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 32*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue // tolerate servers that print logs to stdout
		}
		var m rpcMessage
		if json.Unmarshal(line, &m) != nil {
			continue
		}
		select {
		case t.msgs <- m:
		case <-t.closed:
			return
		}
	}
}

func (t *stdioTransport) send(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = t.stdin.Write(append(b, '\n'))
	return err
}

func (t *stdioTransport) notify(_ context.Context, method string, params any) error {
	return t.send(rpcRequest{JSONRPC: "2.0", Method: method, Params: params})
}

func (t *stdioTransport) call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	t.nextID++
	id := t.nextID
	if err := t.send(rpcRequest{JSONRPC: "2.0", ID: &id, Method: method, Params: params}); err != nil {
		return nil, fmt.Errorf("write to server: %w", err)
	}
	handle := func(m rpcMessage) (json.RawMessage, bool, error) {
		if m.Method != "" {
			t.answerServerRequest(m)
			return nil, false, nil
		}
		if !idMatches(m.ID, id) {
			return nil, false, nil
		}
		if m.Error != nil {
			return nil, true, m.Error
		}
		return m.Result, true, nil
	}
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case m := <-t.msgs:
			if res, ok, err := handle(m); ok {
				return res, err
			}
		case <-t.done:
			for { // drain anything read before EOF
				select {
				case m := <-t.msgs:
					if res, ok, err := handle(m); ok {
						return res, err
					}
				default:
					return nil, errors.New("server exited before responding")
				}
			}
		}
	}
}

// answerServerRequest replies to server-initiated requests so the server is
// not left waiting. We advertise no client capabilities, so only ping is valid.
func (t *stdioTransport) answerServerRequest(m rpcMessage) {
	if len(m.ID) == 0 {
		return // notification
	}
	if m.Method == "ping" {
		_ = t.send(rpcResponse{JSONRPC: "2.0", ID: m.ID, Result: map[string]any{}})
		return
	}
	_ = t.send(rpcResponse{JSONRPC: "2.0", ID: m.ID, Error: &rpcError{Code: -32601, Message: "method not supported by mcp-warden"}})
}

func (t *stdioTransport) close() {
	t.closeOnce.Do(func() {
		close(t.closed)
		_ = t.stdin.Close()
		exited := make(chan struct{})
		go func() { _ = t.cmd.Wait(); close(exited) }()
		select {
		case <-exited:
		case <-time.After(500 * time.Millisecond):
		}
		killProcess(t.cmd) // also reaps grandchildren (npx -> node, uvx -> python)
		<-exited
	})
}

// tailBuffer keeps the last max bytes written to it.
type tailBuffer struct {
	mu  sync.Mutex
	buf []byte
	max int
}

func (b *tailBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	if len(b.buf) > b.max {
		b.buf = b.buf[len(b.buf)-b.max:]
	}
	return len(p), nil
}

func (b *tailBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return strings.Join(strings.Fields(string(b.buf)), " ")
}
