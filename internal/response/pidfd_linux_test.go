//go:build linux

package response

import (
	"errors"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

func startSleeper(t *testing.T) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	return cmd
}

func waitStatus(t *testing.T, cmd *exec.Cmd) syscall.WaitStatus {
	t.Helper()
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("process did not exit")
	}
	return cmd.ProcessState.Sys().(syscall.WaitStatus)
}

func TestPidfdKillTerminatesMatchingInstance(t *testing.T) {
	cmd := startSleeper(t)
	pid := uint32(cmd.Process.Pid)
	ticks, err := procStartTicks(pid)
	if err != nil {
		t.Fatal(err)
	}
	if err := pidfdKill(pid, ticks*nsPerTick); err != nil {
		t.Fatalf("pidfdKill: %v", err)
	}
	if ws := waitStatus(t, cmd); !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
		t.Fatalf("want SIGKILL, got %v", ws)
	}
}

func TestPidfdKillSparesProcessWithDifferentStartTime(t *testing.T) {
	cmd := startSleeper(t)
	pid := uint32(cmd.Process.Pid)
	ticks, err := procStartTicks(pid)
	if err != nil {
		t.Fatal(err)
	}
	// Simulates an event from an earlier process that held the same pid.
	err = pidfdKill(pid, (ticks-1)*nsPerTick)
	if !errors.Is(err, errPIDReused) {
		t.Fatalf("want errPIDReused, got %v", err)
	}
	if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("spared process is not alive: %v", err)
	}
}

func TestPidfdKillReportsMissingProcessAsESRCH(t *testing.T) {
	// PID_MAX_LIMIT is 2^22, so this pid is never assigned. A reaped child's
	// pid would be flaky: another process may reuse it before pidfd_open.
	const neverAssigned = 1<<22 + 1
	if err := pidfdKill(neverAssigned, 1); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("want ESRCH, got %v", err)
	}
}

func TestProcStartTicksHandlesCommWithSpacesAndParens(t *testing.T) {
	stat := "123 (a) b) c) S 1 123 123 0 -1 4194560 100 0 0 0 0 0 0 0 20 0 1 0 98765 1000 10"
	ticks, err := parseStartTicks(stat)
	if err != nil || ticks != 98765 {
		t.Fatalf("got %d, %v", ticks, err)
	}
	if _, err := parseStartTicks("garbage"); err == nil {
		t.Fatal("garbage accepted")
	}
}
