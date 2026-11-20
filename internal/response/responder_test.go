package response

import (
	"errors"
	"syscall"
	"testing"

	"edr/internal/detection"
	"edr/internal/telemetry"
)

type killCall struct {
	pid   uint32
	start uint64
}

type fakeKill struct {
	calls []killCall
	err   error
}

func (f *fakeKill) kill(pid uint32, startBootNS uint64) error {
	f.calls = append(f.calls, killCall{pid, startBootNS})
	return f.err
}

func alert(action detection.Action, pid uint32, start uint64) detection.Alert {
	return detection.Alert{RuleID: "R", Action: action, Event: telemetry.Event{
		Process: telemetry.Process{PID: pid, StartBootNS: start},
	}}
}

func TestRespond(t *testing.T) {
	cases := []struct {
		name       string
		action     detection.Action
		pid        uint32
		start      uint64
		dryRun     bool
		killErr    error
		wantStatus string
		wantErr    string
		wantKills  int
	}{
		{"alert only does nothing", detection.ActionAlert, 500, 9, false, nil, "", "", 0},
		{"kill", detection.ActionKill, 500, 9, false, nil, StatusKilled, "", 1},
		{"dry run", detection.ActionKill, 500, 9, true, nil, StatusDryRun, "", 0},
		{"protect init", detection.ActionKill, 1, 9, false, nil, StatusSkipped, "protected process", 0},
		{"protect pid 0", detection.ActionKill, 0, 9, false, nil, StatusSkipped, "protected process", 0},
		{"protect self", detection.ActionKill, 77, 9, false, nil, StatusSkipped, "protected process", 0},
		{"unknown identity fails closed", detection.ActionKill, 500, 0, false, nil, StatusSkipped, "process identity unknown", 0},
		{"already gone", detection.ActionKill, 500, 9, false, syscall.ESRCH, StatusGone, "", 1},
		{"pid reused", detection.ActionKill, 500, 9, false, errPIDReused, StatusGone, "pid reused by another process", 1},
		{"kill fails", detection.ActionKill, 500, 9, false, errors.New("boom"), StatusFailed, "boom", 1},
	}
	for _, tc := range cases {
		fk := &fakeKill{err: tc.killErr}
		r := &Responder{DryRun: tc.dryRun, SelfPID: 77, kill: fk.kill}
		out := r.Respond(alert(tc.action, tc.pid, tc.start))
		if tc.wantStatus == "" {
			if out != nil {
				t.Errorf("%s: want nil outcome, got %+v", tc.name, out)
			}
		} else if out == nil || out.Status != tc.wantStatus || out.Error != tc.wantErr || out.Action != detection.ActionKill {
			t.Errorf("%s: got %+v, want status %q err %q", tc.name, out, tc.wantStatus, tc.wantErr)
		}
		if len(fk.calls) != tc.wantKills {
			t.Errorf("%s: kill calls %v", tc.name, fk.calls)
		}
		if tc.wantKills == 1 && (fk.calls[0] != killCall{tc.pid, tc.start}) {
			t.Errorf("%s: kill called with %+v", tc.name, fk.calls[0])
		}
	}
}
