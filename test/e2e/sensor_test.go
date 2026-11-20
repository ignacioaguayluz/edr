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
				sawExec = ev.Process.Exe == "/bin/bash" && slices.Contains(ev.Process.Args, "-c")
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

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	events := make(chan telemetry.Event, 4096)
	go sensor.Run(ctx, events)

	self := uint32(os.Getpid())
	path := filepath.Join(t.TempDir(), "self-open")
	for i := 0; i < 20; i++ {
		f, _ := os.Create(path)
		f.Close()
	}
	for {
		select {
		case ev := <-events:
			if ev.Process.PID == self {
				t.Fatalf("agent observed its own activity: %+v", ev)
			}
		case <-ctx.Done():
			return
		}
	}
}
