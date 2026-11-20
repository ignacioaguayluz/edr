package detection

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"
)

type ruleFile struct {
	Rules []Rule `yaml:"rules"`
}

// LoadDir loads and validates every *.yaml / *.yml rule file in dir,
// including every document of multi-document files. A missing directory,
// a directory without rules, unknown YAML keys, invalid rules and duplicate
// IDs are errors, so a typo fails loudly at startup instead of leaving the
// agent running with rules that never fire.
func LoadDir(dir string) ([]Rule, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("rules directory: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("rules directory: %s is not a directory", dir)
	}

	var paths []string
	for _, pat := range []string{"*.yaml", "*.yml"} {
		m, err := filepath.Glob(filepath.Join(dir, pat))
		if err != nil {
			return nil, err
		}
		paths = append(paths, m...)
	}
	sort.Strings(paths)

	seen := map[string]string{}
	var rules []Rule
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		for {
			var rf ruleFile
			if err := dec.Decode(&rf); err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return nil, fmt.Errorf("%s: %w", p, err)
			}
			for _, r := range rf.Rules {
				if err := r.Validate(); err != nil {
					return nil, fmt.Errorf("%s: %w", p, err)
				}
				if prev, dup := seen[r.ID]; dup {
					return nil, fmt.Errorf("%s: duplicate rule id %s (first defined in %s)", p, r.ID, prev)
				}
				seen[r.ID] = p
				rules = append(rules, r)
			}
		}
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("no rules found in %s (*.yaml, *.yml)", dir)
	}
	return rules, nil
}
