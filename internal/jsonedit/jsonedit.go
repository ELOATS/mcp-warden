// Package jsonedit makes surgical edits to JSON and JSONC documents: it
// locates string values by path and replaces just those bytes, so comments,
// key order, indentation and everything else in the file stay untouched.
package jsonedit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Span is the byte range of a string value, including its quotes.
type Span struct{ Start, End int }

// Key joins a path (object keys and decimal array indices) into a map key.
func Key(path ...string) string { return strings.Join(path, "\x00") }

// Strings indexes every string value in a JSON/JSONC document by its path.
func Strings(data []byte) (map[string]Span, error) {
	p := &parser{b: data, out: map[string]Span{}}
	if err := p.value(nil); err != nil {
		return nil, err
	}
	p.ws()
	if p.i != len(p.b) {
		return nil, p.errorf("unexpected data after the top-level value")
	}
	return p.out, nil
}

// Value decodes the string at span.
func Value(data []byte, s Span) (string, error) {
	var v string
	err := json.Unmarshal(data[s.Start:s.End], &v)
	return v, err
}

// Edit replaces the string at Span with Value (encoded as a JSON string).
type Edit struct {
	Span  Span
	Value string
}

// Apply returns a copy of data with the edits applied.
func Apply(data []byte, edits []Edit) ([]byte, error) {
	es := append([]Edit(nil), edits...)
	sort.Slice(es, func(i, j int) bool { return es[i].Span.Start > es[j].Span.Start })
	out := append([]byte(nil), data...)
	prev := len(data) + 1
	for _, e := range es {
		if e.Span.Start < 0 || e.Span.End > len(data) || e.Span.Start >= e.Span.End || e.Span.End > prev {
			return nil, errors.New("overlapping or invalid edit")
		}
		prev = e.Span.Start
		enc, err := encode(e.Value)
		if err != nil {
			return nil, err
		}
		out = append(out[:e.Span.Start], append(enc, out[e.Span.End:]...)...)
	}
	return out, nil
}

func encode(s string) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // keep <, > and & readable in config files
	if err := enc.Encode(s); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

type parser struct {
	b   []byte
	i   int
	out map[string]Span
}

func (p *parser) errorf(format string, a ...any) error {
	line := 1 + bytes.Count(p.b[:min(p.i, len(p.b))], []byte("\n"))
	return fmt.Errorf("line %d: %s", line, fmt.Sprintf(format, a...))
}

// ws skips whitespace and // or /* */ comments.
func (p *parser) ws() {
	for p.i < len(p.b) {
		switch c := p.b[p.i]; {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			p.i++
		case c == '/' && p.i+1 < len(p.b) && p.b[p.i+1] == '/':
			for p.i < len(p.b) && p.b[p.i] != '\n' {
				p.i++
			}
		case c == '/' && p.i+1 < len(p.b) && p.b[p.i+1] == '*':
			end := bytes.Index(p.b[p.i+2:], []byte("*/"))
			if end < 0 {
				p.i = len(p.b)
				return
			}
			p.i += end + 4
		default:
			return
		}
	}
}

func child(path []string, k string) []string {
	out := make([]string, len(path)+1)
	copy(out, path)
	out[len(path)] = k
	return out
}

func (p *parser) value(path []string) error {
	p.ws()
	if p.i >= len(p.b) {
		return p.errorf("unexpected end of input")
	}
	switch p.b[p.i] {
	case '{':
		return p.object(path)
	case '[':
		return p.array(path)
	case '"':
		start := p.i
		if _, err := p.str(); err != nil {
			return err
		}
		p.out[Key(path...)] = Span{start, p.i}
		return nil
	}
	start := p.i
	for p.i < len(p.b) && !strings.ContainsRune(",}] \t\r\n/", rune(p.b[p.i])) {
		p.i++
	}
	tok := string(p.b[start:p.i])
	if tok != "true" && tok != "false" && tok != "null" {
		if _, err := strconv.ParseFloat(tok, 64); err != nil {
			return p.errorf("invalid value %q", tok)
		}
	}
	return nil
}

func (p *parser) str() (string, error) {
	start := p.i
	p.i++
	for p.i < len(p.b) {
		switch p.b[p.i] {
		case '\\':
			p.i += 2
			continue
		case '"':
			p.i++
			var s string
			if err := json.Unmarshal(p.b[start:p.i], &s); err != nil {
				return "", p.errorf("invalid string: %v", err)
			}
			return s, nil
		}
		p.i++
	}
	return "", p.errorf("unterminated string")
}

func (p *parser) object(path []string) error {
	p.i++ // {
	for {
		p.ws()
		if p.i < len(p.b) && p.b[p.i] == '}' {
			p.i++
			return nil
		}
		if p.i >= len(p.b) || p.b[p.i] != '"' {
			return p.errorf("expected an object key")
		}
		key, err := p.str()
		if err != nil {
			return err
		}
		p.ws()
		if p.i >= len(p.b) || p.b[p.i] != ':' {
			return p.errorf("expected ':' after key %q", key)
		}
		p.i++
		if err := p.value(child(path, key)); err != nil {
			return err
		}
		p.ws()
		if p.i < len(p.b) && p.b[p.i] == ',' {
			p.i++
			continue
		}
		if p.i < len(p.b) && p.b[p.i] == '}' {
			p.i++
			return nil
		}
		return p.errorf("expected ',' or '}'")
	}
}

func (p *parser) array(path []string) error {
	p.i++ // [
	for n := 0; ; n++ {
		p.ws()
		if p.i < len(p.b) && p.b[p.i] == ']' {
			p.i++
			return nil
		}
		if err := p.value(child(path, strconv.Itoa(n))); err != nil {
			return err
		}
		p.ws()
		if p.i < len(p.b) && p.b[p.i] == ',' {
			p.i++
			continue
		}
		if p.i < len(p.b) && p.b[p.i] == ']' {
			p.i++
			return nil
		}
		return p.errorf("expected ',' or ']'")
	}
}
