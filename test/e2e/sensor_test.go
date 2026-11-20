//go:build e2e && linux

// Package e2e exercises the real eBPF sensor against the running kernel.
// Run as root with --pid=host: `make e2e`.
package e2e

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"edr/internal/sensor/ebpf"
	"edr/internal/telemetry"
)

func TestSensorCapturesExecOpenConnectExit(t *testing.T) {
	sensor, err := ebpf.Open(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("open sensor: %v", err)
	}
	defer sensor.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	events := make(chan telemetry.Event, 4096)
	go sensor.Run(ctx, events)

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	marker := filepath.Join(t.TempDir(), "edr-marker")
	if err := os.WriteFile(marker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	// All activity happens in a child: the agent's own pid is filtered in-kernel.
	script := fmt.Sprintf("cat %s >/dev/null; exec 3<>/dev/tcp/127.0.0.1/%d; exit 7", marker, port)
	cmd := exec.Command("/bin/bash", "-c", script)
	_ = cmd.Run()
	child := uint32(cmd.Process.Pid)

	var sawExec, sawOpen, sawConnect, sawExit bool
	for !(sawExec && sawOpen && sawConnect && sawExit) {
		select {
		case ev := <-events:
			switch {
			case ev.Kind == telemetry.KindProcessExec && ev.Process.PID == child:
				sawExec = ev.Process.Exe == "/bin/bash" && slices.Contains(ev.Process.Args, "-c") && ev.Process.StartBootNS > 0
			case ev.Kind == telemetry.KindFileOpen && ev.File.Path == marker && ev.Process.Comm == "cat":
				sawOpen = true
			case ev.Kind == telemetry.KindNetConnect && ev.Process.PID == child:
				sawConnect = ev.Network.DstIP == "127.0.0.1" && int(ev.Network.DstPort) == port
			case ev.Kind == telemetry.KindProcessExit && ev.Process.PID == child:
				sawExit = ev.Process.ExitCode != nil && *ev.Process.ExitCode == 7
			}
		case <-ctx.Done():
			t.Fatalf("timeout: exec=%v open=%v connect=%v exit=%v", sawExec, sawOpen, sawConnect, sawExit)
		}
	}
}

func TestSensorIgnoresAgentOwnActivity(t *testing.T) {
	sensor, err := ebpf.Open(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("open sensor: %v", err)
	}
	defer sensor.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	events := make(chan telemetry.Event, 4096)
	runErr := make(chan error, 1)
	go func() { runErr <- sensor.Run(ctx, events) }()

	self := uint32(os.Getpid())
	path := filepath.Join(t.TempDir(), "self-open")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// Positive controls: a child opens the same path before and after the
	// agent does. The ring buffer preserves submission order, so any event
	// for the agent's own opens would arrive before the second marker.
	childOpen := func() uint32 {
		cmd := exec.Command("/bin/cat", path)
		if err := cmd.Run(); err != nil {
			t.Fatalf("child open: %v", err)
		}
		return uint32(cmd.Process.Pid)
	}
	before := childOpen()
	for i := 0; i < 20; i++ {
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
	}
	after := childOpen()

	sawBefore := false
	for {
		select {
		case ev := <-events:
			if ev.Process.PID == self {
				t.Fatalf("agent observed its own activity: %+v", ev)
			}
			if ev.Kind != telemetry.KindFileOpen || ev.File.Path != path {
				continue
			}
			switch ev.Process.PID {
			case before:
				sawBefore = true
			case after:
				if !sawBefore {
					t.Fatal("second control marker arrived without the first")
				}
				return
			}
		case err := <-runErr:
			t.Fatalf("sensor stopped early: %v", err)
		case <-ctx.Done():
			t.Fatalf("timeout waiting for control markers (before seen: %v)", sawBefore)
		}
	}
}

func TestSensorCountsRingBufferDrops(t *testing.T) {
	sensor, err := ebpf.Open(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("open sensor: %v", err)
	}
	defer sensor.Close()

	// Nobody reads the ring buffer, so a flood of opens must overflow it.
	flood := exec.Command("/bin/bash", "-c", "for i in $(seq 1 60000); do : < /etc/hostname; done")
	if err := flood.Run(); err != nil {
		t.Fatalf("flood: %v", err)
	}
	dropped, err := sensor.Dropped()
	if err != nil {
		t.Fatal(err)
	}
	if dropped == 0 {
		t.Fatal("ring buffer overflowed but no drops were counted")
	}
	t.Logf("dropped %d events", dropped)
}
