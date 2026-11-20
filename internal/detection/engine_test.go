package detection

import (
	"testing"
	"time"

	"edr/internal/telemetry"
)

func ptr(s string) *string { return &s }

func execEvent(comm, exe, parent string) telemetry.Event {
	return telemetry.Event{
		Time:    time.Unix(100, 0),
		Kind:    telemetry.KindProcessExec,
		Process: telemetry.Process{PID: 42, Comm: comm, Exe: exe, ParentComm: parent},
	}
}

func TestConditionOperators(t *testing.T) {
	ev := execEvent("xmrig", "/tmp/x/xmrig", "bash")
	cases := []struct {
		name string
		c    Condition
		want bool
	}{
		{"equals hit", Condition{Field: "process.comm", Equals: ptr("xmrig")}, true},
		{"equals miss", Condition{Field: "process.comm", Equals: ptr("xmri")}, false},
		{"contains", Condition{Field: "process.exe", Contains: ptr("/x/")}, true},
		{"startswith", Condition{Field: "process.exe", StartsWith: ptr("/tmp/")}, true},
		{"startswith miss", Condition{Field: "process.exe", StartsWith: ptr("/usr/")}, false},
		{"endswith", Condition{Field: "process.exe", EndsWith: ptr("/xmrig")}, true},
		{"in hit", Condition{Field: "process.comm", In: []string{"minerd", "xmrig"}}, true},
		{"in miss", Condition{Field: "process.comm", In: []string{"minerd"}}, false},
		{"absent field never matches", Condition{Field: "file.path", Contains: ptr("")}, false},
	}
	for _, tc := range cases {
		if got := tc.c.matches(ev); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}

func TestEngineEmitsAlertOnlyWhenKindAndAllConditionsMatch(t *testing.T) {
	rule := Rule{
		ID: "R1", Title: "shell from web server", Severity: SeverityHigh, Action: ActionKill,
		Kind: telemetry.KindProcessExec,
		Match: []Condition{
			{Field: "process.comm", In: []string{"sh", "bash"}},
			{Field: "process.parent_comm", Equals: ptr("nginx")},
		},
	}
	eng := NewEngine([]Rule{rule})

	hit := execEvent("bash", "/bin/bash", "nginx")
	alerts := eng.Evaluate(hit)
	if len(alerts) != 1 {
		t.Fatalf("want 1 alert, got %d", len(alerts))
	}
	a := alerts[0]
	if a.RuleID != "R1" || a.Title != rule.Title || a.Severity != SeverityHigh || a.Action != ActionKill || a.Event.Process.PID != 42 || !a.Time.Equal(hit.Time) {
		t.Fatalf("unexpected alert: %+v", a)
	}

	if n := len(eng.Evaluate(execEvent("bash", "/bin/bash", "sshd"))); n != 0 {
		t.Errorf("partial match produced %d alerts", n)
	}
	other := hit
	other.Kind = telemetry.KindFileOpen
	if n := len(eng.Evaluate(other)); n != 0 {
		t.Errorf("wrong kind produced %d alerts", n)
	}
}

func TestEngineRuleWithoutKindMatchesAnyKind(t *testing.T) {
	eng := NewEngine([]Rule{{ID: "R", Severity: SeverityLow, Match: []Condition{{Field: "process.comm", Equals: ptr("nc")}}}})
	ev := execEvent("nc", "", "")
	ev.Kind = telemetry.KindNetConnect
	if n := len(eng.Evaluate(ev)); n != 1 {
		t.Fatalf("want 1 alert, got %d", n)
	}
}
