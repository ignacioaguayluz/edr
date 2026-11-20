// Package response executes the actions requested by matching rules.
package response

import (
	"errors"
	"os"
	"syscall"

	"edr/internal/detection"
)

// Outcome statuses.
const (
	StatusKilled  = "killed"
	StatusDryRun  = "dry_run"
	StatusSkipped = "skipped" // target is protected (pid 0/1 or the agent itself)
	StatusGone    = "gone"    // process exited before we could act
	StatusFailed  = "failed"
)

// Responder applies rule actions to the offending process.
//
// Known limitation: kill targets a PID, so a PID reused between detection
// and response could hit the wrong process. The window is microseconds for
// exec-time detections; pidfd-based targeting would close it.
type Responder struct {
	DryRun  bool
	SelfPID int
	kill    func(pid int, sig syscall.Signal) error
}

// New returns a Responder that sends real signals.
func New(dryRun bool) *Responder {
	return &Responder{DryRun: dryRun, SelfPID: os.Getpid(), kill: syscall.Kill}
}

// Respond executes the alert's action. It returns nil when the action
// requires no response (plain alerts).
func (r *Responder) Respond(a detection.Alert) *detection.ResponseOutcome {
	if a.Action != detection.ActionKill {
		return nil
	}
	out := &detection.ResponseOutcome{Action: detection.ActionKill}
	pid := int(a.Event.Process.PID)
	switch {
	case pid <= 1 || pid == r.SelfPID:
		out.Status, out.Error = StatusSkipped, "protected process"
	case r.DryRun:
		out.Status = StatusDryRun
	default:
		err := r.kill(pid, syscall.SIGKILL)
		switch {
		case err == nil:
			out.Status = StatusKilled
		case errors.Is(err, syscall.ESRCH):
			out.Status = StatusGone
		default:
			out.Status, out.Error = StatusFailed, err.Error()
		}
	}
	return out
}
