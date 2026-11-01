package audit

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every rule ID emitted anywhere in the code base must be documented.
func TestEveryRuleIsDocumented(t *testing.T) {
	re := regexp.MustCompile(`Rule:\s+"([A-Z][A-Z-]+)"`)
	root := filepath.Join("..", "..")
	seen := 0
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, m := range re.FindAllStringSubmatch(string(b), -1) {
			seen++
			if _, ok := catalog[m[1]]; !ok {
				t.Errorf("%s: rule %s is not in the catalog (rules.go)", p, m[1])
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if seen < 40 {
		t.Fatalf("found only %d rule references; is the walk rooted correctly?", seen)
	}
}
