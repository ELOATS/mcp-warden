package notify

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/ELOATS/mcp-warden/internal/audit"
)

// State remembers which findings were already alerted so that watch does
// not repeat itself every interval.
type State struct {
	Alerted map[string]time.Time `json:"alerted"`
}

// Key identifies a finding across runs.
func Key(f audit.Finding) string {
	h := sha256.Sum256([]byte(f.Server + "\x00" + f.Rule + "\x00" + f.Tool + "\x00" + f.Evidence))
	return hex.EncodeToString(h[:12])
}

// LoadState reads the state file; a missing file is an empty state.
func LoadState(path string) (State, error) {
	s := State{Alerted: map[string]time.Time{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return State{Alerted: map[string]time.Time{}}, nil // corrupt state: start over rather than fail
	}
	if s.Alerted == nil {
		s.Alerted = map[string]time.Time{}
	}
	return s, nil
}

// Save writes the state file.
func (s State) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

// New returns the findings that have not been alerted yet.
func (s State) New(findings []audit.Finding) []audit.Finding {
	var out []audit.Finding
	for _, f := range findings {
		if _, ok := s.Alerted[Key(f)]; !ok {
			out = append(out, f)
		}
	}
	return out
}

// Sync records alerted findings and forgets ones that are gone (for
// example after a re-pin), so they alert again if they ever come back.
func (s *State) Sync(current, alerted []audit.Finding, now time.Time) {
	live := map[string]bool{}
	for _, f := range current {
		live[Key(f)] = true
	}
	for k := range s.Alerted {
		if !live[k] {
			delete(s.Alerted, k)
		}
	}
	for _, f := range alerted {
		s.Alerted[Key(f)] = now
	}
}
