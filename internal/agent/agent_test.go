package agent

import (
	"context"
	"testing"

	"edr/internal/detection"
	"edr/internal/telemetry"
)

type record struct {
	typ  string
	data any
}

type memSink struct{ records []record }

func (m *memSink) Write(t string, d any) error {
	m.records = append(m.records, record{t, d})
	return nil
}

type fakeResponder struct{ got []detection.Alert }

func (f *fakeResponder) Respond(a detection.Alert) *detection.ResponseOutcome {
	f.got = append(f.got, a)
	if a.Action != detection.ActionKill {
		return nil
	}
	return &detection.ResponseOutcome{Action: a.Action, Status: "killed"}
}

func ptr(s string) *string { return &s }

func newAgent(rules []detection.Rule, emit bool) (*Agent, *memSink, *fakeResponder) {
	sink, resp := &memSink{}, &fakeResponder{}
	a := New(detection.NewEngine(rules), resp, sink, Options{EmitEvents: emit})
	a.procExe = func(pid uint32) string { return "/proc-resolved/exe" }
	a.procComm = func(pid uint32) string {
		if pid == 1 {
			return "systemd"
		}
		return ""
	}
	return a, sink, resp
}

func exec(pid, ppid uint32, comm, exe string) telemetry.Event {
	return telemetry.Event{Kind: telemetry.KindProcessExec, Process: telemetry.Process{PID: pid, PPID: ppid, Comm: comm, Exe: exe, Args: []string{exe}}}
}

func alerts(s *memSink) []detection.Alert {
	var out []detection.Alert
	for _, r := range s.records {
		if r.typ == "alert" {
			out = append(out, r.data.(detection.Alert))
		}
	}
	return out
}

func TestExecIsEnrichedWithParentFromTableThenProcfs(t *testing.T) {
	rule := detection.Rule{ID: "WEB", Severity: detection.SeverityHigh, Action: detection.ActionKill, Kind: telemetry.KindProcessExec,
		Match: []detection.Condition{{Field: "process.parent_comm", Equals: ptr("nginx")}}}
	a, sink, _ := newAgent([]detection.Rule{rule}, false)

	a.Handle(exec(100, 1, "nginx", "/usr/sbin/nginx"))
	a.Handle(exec(200, 100, "bash", "/bin/bash"))

	got := alerts(sink)
	if len(got) != 1 || got[0].Event.Process.PID != 200 || got[0].Event.Process.ParentComm != "nginx" {
		t.Fatalf("alerts = %+v", got)
	}
	if got[0].Response == nil || got[0].Response.Status != "killed" {
		t.Fatalf("response not recorded: %+v", got[0].Response)
	}
	if p, _ := a.procs.get(100); p.ParentComm != "systemd" {
		t.Errorf("procfs parent fallback not applied: %+v", p)
	}
}

func TestRelativeExeIsResolvedFromProcfs(t *testing.T) {
	a, _, _ := newAgent(nil, false)
	a.Handle(exec(300, 1, "x", "./x"))
	if p, _ := a.procs.get(300); p.Exe != "/proc-resolved/exe" {
		t.Fatalf("exe = %q", p.Exe)
	}
}

func TestNonExecEventsInheritProcessContextAndExitForgets(t *testing.T) {
	rule := detection.Rule{ID: "TMP-NET", Severity: detection.SeverityLow, Kind: telemetry.KindNetConnect,
		Match: []detection.Condition{{Field: "process.exe", StartsWith: ptr("/tmp/")}}}
	a, sink, resp := newAgent([]detection.Rule{rule}, false)

	a.Handle(exec(400, 1, "dropper", "/tmp/dropper"))
	conn := telemetry.Event{Kind: telemetry.KindNetConnect, Process: telemetry.Process{PID: 400, PPID: 1, Comm: "dropper"}, Network: &telemetry.Network{DstPort: 80}}
	a.Handle(conn)
	if got := alerts(sink); len(got) != 1 || got[0].Event.Process.Args[0] != "/tmp/dropper" {
		t.Fatalf("alerts = %+v", got)
	}
	if len(resp.got) != 1 {
		t.Fatalf("responder called %d times", len(resp.got))
	}

	a.Handle(telemetry.Event{Kind: telemetry.KindProcessExit, Process: telemetry.Process{PID: 400}})
	if _, ok := a.procs.get(400); ok {
		t.Fatal("exited process still tracked")
	}
}

func TestEventsAreOnlyEmittedWhenEnabled(t *testing.T) {
	for _, emit := range []bool{false, true} {
		a, sink, _ := newAgent(nil, emit)
		a.Handle(exec(1, 0, "init", "/sbin/init"))
		if got := len(sink.records); (got == 1) != emit {
			t.Errorf("emit=%v: %d records", emit, got)
		}
	}
}

func TestProcessTableIsBounded(t *testing.T) {
	tbl := newProcessTable(2)
	tbl.put(telemetry.Process{PID: 1})
	tbl.put(telemetry.Process{PID: 2})
	tbl.put(telemetry.Process{PID: 3})
	if _, ok := tbl.get(3); ok {
		t.Fatal("table grew past its limit")
	}
	tbl.put(telemetry.Process{PID: 2, Comm: "updated"})
	if p, _ := tbl.get(2); p.Comm != "updated" {
		t.Fatal("existing entry not updated when full")
	}
}

type sliceSource []telemetry.Event

func (s sliceSource) Run(ctx context.Context, out chan<- telemetry.Event) error {
	for _, ev := range s {
		out <- ev
	}
	return nil
}

func TestRunDrainsSourceUntilItStops(t *testing.T) {
	a, sink, _ := newAgent(nil, true)
	err := a.Run(context.Background(), sliceSource{exec(1, 0, "a", "/a"), exec(2, 0, "b", "/b")})
	if err != nil || len(sink.records) != 2 {
		t.Fatalf("err=%v records=%d", err, len(sink.records))
	}
}
