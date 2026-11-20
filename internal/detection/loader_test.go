package detection

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeRules(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const validRule = `
rules:
  - id: EDR-1
    title: miner
    severity: critical
    kind: process_exec
    action: kill
    match:
      - field: process.comm
        in: [xmrig]
`

func TestLoadDirReadsYAMLFilesAndIgnoresOthers(t *testing.T) {
	dir := writeRules(t, map[string]string{"a.yaml": validRule, "notes.txt": "not yaml: ["})
	rules, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].ID != "EDR-1" || rules[0].Action != ActionKill || rules[0].Severity != SeverityCritical {
		t.Fatalf("unexpected rules: %+v", rules)
	}
}

func TestLoadDirRejectsInvalidRules(t *testing.T) {
	cases := map[string]string{
		"missing id":       "rules:\n  - severity: low\n    match: [{field: process.comm, equals: x}]\n",
		"bad severity":     "rules:\n  - id: X\n    severity: huge\n    match: [{field: process.comm, equals: x}]\n",
		"unknown field":    "rules:\n  - id: X\n    severity: low\n    match: [{field: process.name, equals: x}]\n",
		"no operator":      "rules:\n  - id: X\n    severity: low\n    match: [{field: process.comm}]\n",
		"two operators":    "rules:\n  - id: X\n    severity: low\n    match: [{field: process.comm, equals: x, contains: y}]\n",
		"no conditions":    "rules:\n  - id: X\n    severity: low\n",
		"bad kind":         "rules:\n  - id: X\n    severity: low\n    kind: proc\n    match: [{field: process.comm, equals: x}]\n",
		"bad action":       "rules:\n  - id: X\n    severity: low\n    action: nuke\n    match: [{field: process.comm, equals: x}]\n",
		"unknown yaml key": "rules:\n  - id: X\n    severity: low\n    sevrity: low\n    match: [{field: process.comm, equals: x}]\n",
	}
	for name, body := range cases {
		if _, err := LoadDir(writeRules(t, map[string]string{"r.yaml": body})); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestLoadDirRejectsDuplicateIDsAcrossFiles(t *testing.T) {
	_, err := LoadDir(writeRules(t, map[string]string{"a.yaml": validRule, "b.yml": validRule}))
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("want duplicate id error, got %v", err)
	}
}

func TestShippedRulesAreValid(t *testing.T) {
	rules, err := LoadDir("../../rules")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) == 0 {
		t.Fatal("no shipped rules")
	}
}
