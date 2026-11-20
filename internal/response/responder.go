// Package response executes the actions requested by matching rules.
package response

import (
	"errors"
	"syscall"

	"edr/internal/detection"
)

// Outcome statuses.
const (
	StatusKilled  = "killed"
	StatusDryRun  = "dry_run"
	StatusSkipped = "skipped" // protected target or unknown process identity
	StatusGone    = "gone"    // process exited (or its pid was reused) before we acted
	StatusFailed  = "failed"
)

// errPIDReused means the pid now belongs to a different process instance
// than the one that triggered the alert; no signal was sent.
var errPIDReused = errors.New("pid reused by another process")

// Responder applies rule actions to the offending process.
//
// Kills target a process instance, not a bare PID: the kill function
// receives the pid and the start time reported by the kernel, and must only
// signal a process whose start time matches (see pidfdKill).
type Responder struct {
	DryRun  bool
	SelfPID int
	kill    func(pid uint32, startBootNS uint64) error
}

// Respond executes the alert's action. It returns nil when the action
// requires no response (plain alerts).
func (r *Responder) Respond(a detection.Alert) *detection.ResponseOutcome {
	if a.Action != detection.ActionKill {
		return nil
	}
	out := &detection.ResponseOutcome{Action: detection.ActionKill}
	p := a.Event.Process
	switch {
	case p.PID <= 1 || int(p.PID) == r.SelfPID:
		out.Status, out.Error = StatusSkipped, "protected process"
	case p.StartBootNS == 0:
		out.Status, out.Error = StatusSkipped, "process identity unknown"
	case r.DryRun:
		out.Status = StatusDryRun
	default:
		err := r.kill(p.PID, p.StartBootNS)
		switch {
		case err == nil:
			out.Status = StatusKilled
		case errors.Is(err, syscall.ESRCH):
			out.Status = StatusGone
		case errors.Is(err, errPIDReused):
			out.Status, out.Error = StatusGone, err.Error()
		default:
			out.Status, out.Error = StatusFailed, err.Error()
		}
	}
	return out
}
