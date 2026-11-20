//go:build e2e && linux

package e2e

import (
	"context"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"edr/internal/detection"
	"edr/internal/response"
	"edr/internal/sensor/ebpf"
	"edr/internal/telemetry"
)

const probeEnv = "EDR_IDENTITY_PROBE_HELPER"

// TestMain lets the test binary re-exec itself as a helper that opens a file
// from a non-leader thread and then execs /bin/sleep from that same thread
// (the kernel de_thread path).
func TestMain(m *testing.M) {
	if os.Getenv(probeEnv) == "1" {
		runtime.LockOSThread()
		done := make(chan struct{})
		go func() {
			runtime.LockOSThread()
			if unix.Gettid() == unix.Getpid() {
				os.Exit(3)
			}
			if f, _ := os.Open(os.Args[1]); f != nil {
				f.Close()
			}
			time.Sleep(200 * time.Millisecond)
			_ = syscall.Exec("/bin/sleep", []string{"sleep", "10"}, nil)
			close(done)
		}()
		<-done
		os.Exit(4)
	}
	os.Exit(m.Run())
}

func procTicks(t *testing.T, pid uint32) uint64 {
	t.Helper()
	b, err := os.ReadFile("/proc/" + strconv.Itoa(int(pid)) + "/stat")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	f := strings.Fields(s[strings.LastIndexByte(s, ')')+1:])
	v, err := strconv.ParseUint(f[19], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// The kernel start time on events must match /proc for events raised by a
// non-leader thread and for an exec performed by one, and the pidfd
// responder must then kill that exact process.
func TestStartTimeMatchesProcForThreadAndDeThreadExec(t *testing.T) {
	sensor, err := ebpf.Open(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("open sensor: %v", err)
	}
	defer sensor.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	events := make(chan telemetry.Event, 4096)
	go sensor.Run(ctx, events)

	marker := t.TempDir() + "/identity-marker"
	if err := os.WriteFile(marker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(self, marker)
	cmd.Env = append(os.Environ(), probeEnv+"=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := uint32(cmd.Process.Pid)
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })

	var openEv, execEv *telemetry.Event
	for openEv == nil || execEv == nil {
		select {
		case ev := <-events:
			if ev.Process.PID != pid {
				continue
			}
			e := ev
			if ev.Kind == telemetry.KindFileOpen && ev.File.Path == marker {
				openEv = &e
			}
			if ev.Kind == telemetry.KindProcessExec && strings.HasSuffix(ev.Process.Exe, "sleep") {
				execEv = &e
			}
		case <-ctx.Done():
			t.Fatalf("missing events: open=%v exec=%v", openEv != nil, execEv != nil)
		}
	}
	ticks := procTicks(t, pid)
	for name, ev := range map[string]*telemetry.Event{"open(thread)": openEv, "exec(de_thread)": execEv} {
		if ev.Process.StartBootNS == 0 || ev.Process.StartBootNS/10_000_000 != ticks {
			t.Errorf("%s: start %d ns, /proc says %d ticks", name, ev.Process.StartBootNS, ticks)
		}
	}

	out := response.New(false).Respond(detection.Alert{RuleID: "P", Action: detection.ActionKill, Event: *execEv})
	if out == nil || out.Status != response.StatusKilled {
		t.Fatalf("respond: %+v", out)
	}
	_ = cmd.Wait()
	if ws := cmd.ProcessState.Sys().(syscall.WaitStatus); !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
		t.Fatalf("want SIGKILL, got %v", ws)
	}
}
